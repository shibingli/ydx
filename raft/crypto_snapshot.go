package raft

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"os"
	"sync"

	"github.com/shibingli/ydx/errs"
)

const (
	// snapshotVersionEncrypted adds AEAD-encrypted, independently authenticated
	// chunks to the snapshot file format. | snapshotVersionEncrypted 在快照文件格式
	// 中增加逐块独立认证的 AEAD 加密。
	snapshotVersionEncrypted = byte(3)
	// encryptedSnapshotBaseHeader is the version 3 header without the
	// configuration bytes: magic, version, index, term, conf length, data length,
	// CRC, flags, key ID, suite, salt, chunk size and SHA-256. |
	// encryptedSnapshotBaseHeader 是不含配置字节的版本 3 头部：魔数、版本、索引、
	// 任期、配置长度、数据长度、CRC、标志、密钥 ID、套件、salt、分块大小与 SHA-256。
	encryptedSnapshotBaseHeader = 99
	// snapshotChunkHeaderSize is the plaintext and ciphertext length prefix. |
	// snapshotChunkHeaderSize 是明文与密文长度前缀的长度。
	snapshotChunkHeaderSize = 8
)

// snapshotCrypto describes the encrypted layout of one file-backed snapshot. It
// is immutable after creation except for the lazily derived AEAD. |
// snapshotCrypto 描述一个文件快照的加密布局；除惰性派生的 AEAD 外，创建后不可变。
type snapshotCrypto struct {
	cipher     *dataCipher
	aead       cipher.AEAD
	err        error
	prefixHash [sha256.Size]byte
	index      uint64
	term       uint64
	dataLen    int64
	headerLen  int64
	chunkSize  int
	keyID      uint32
	suite      EncryptionSuite
	salt       [streamSaltSize]byte
	once       sync.Once
}

// chunkAEAD derives and caches the per-file AEAD. | chunkAEAD 派生并缓存每个文件
// 专用的 AEAD。
func (c *snapshotCrypto) chunkAEAD() (cipher.AEAD, error) {
	c.once.Do(func() {
		if c.cipher == nil {
			c.err = errs.Detail(ErrInvalidConfig, "encrypted snapshot requires encryption keys | 加密快照需要加密密钥")
			return
		}
		key, ok := c.cipher.ring.keys[c.keyID]
		if !ok {
			c.err = errs.Detail(ErrKeyNotFound,
				"snapshot key ID %[1]d is not in the ring | 快照密钥 ID %[1]d 不在密钥环中", c.keyID)
			return
		}
		if key.suite != c.suite {
			c.err = errs.Detail(ErrCorrupt,
				"snapshot key %d suite %s does not match header suite %s | 快照密钥 %d 套件 %s 与头部套件 %s 不匹配",
				c.keyID, key.suite, c.suite, c.keyID, key.suite, c.suite)
			return
		}
		c.aead, c.err = key.deriveAEAD(c.salt[:], infoSnapshot)
	})
	return c.aead, c.err
}

// headerDigest returns the digest of the header bytes bound into every chunk
// AAD. It covers the magic, version, index, term, key ID, suite, flags, salt,
// chunk size and configuration, so tampering with any of them fails
// authentication without copying a potentially large configuration per chunk.
// | headerDigest 返回绑定进每个分块 AAD 的头部摘要，覆盖魔数、版本、索引、任期、
// 密钥 ID、套件、标志、salt、分块大小与配置；篡改其中任何一项都会认证失败，且无需
// 为每个分块复制可能很大的配置。
func (c *snapshotCrypto) headerDigest() []byte {
	return c.prefixHash[:]
}

// snapshotPrefix builds the authenticated snapshot header prefix. |
// snapshotPrefix 构建参与认证的快照头部前缀。
func snapshotPrefix(index, term uint64, keyID uint32, suite EncryptionSuite,
	flags byte, salt [streamSaltSize]byte, chunkSize int, conf []byte) []byte {
	prefix := make([]byte, 0, 55+len(conf))
	prefix = append(prefix, snapshotMagic...)
	prefix = append(prefix, snapshotVersionEncrypted)
	prefix = binary.LittleEndian.AppendUint64(prefix, index)
	prefix = binary.LittleEndian.AppendUint64(prefix, term)
	prefix = binary.LittleEndian.AppendUint32(prefix, keyID)
	prefix = append(prefix, byte(suite), flags)
	prefix = append(prefix, salt[:]...)
	prefix = binary.LittleEndian.AppendUint32(prefix, uint32(chunkSize))
	prefix = binary.LittleEndian.AppendUint32(prefix, uint32(len(conf)))
	return append(prefix, conf...)
}

// snapshotPrefixHash returns the SHA-256 of the authenticated header prefix. |
// snapshotPrefixHash 返回参与认证的头部前缀的 SHA-256。
func snapshotPrefixHash(index, term uint64, keyID uint32, suite EncryptionSuite,
	flags byte, salt [streamSaltSize]byte, chunkSize int, conf []byte) [sha256.Size]byte {
	return sha256.Sum256(snapshotPrefix(index, term, keyID, suite, flags, salt, chunkSize, conf))
}

// snapshotChecksumFlag maps the checksum selection onto the header flags byte.
// | snapshotChecksumFlag 把校验选择映射为头部标志字节。
func snapshotChecksumFlag(useSHA bool) byte {
	if useSHA {
		return snapshotFlagSHA256
	}
	return 0
}

// encryptedSnapshotHeaderSize returns the version 3 header length. |
// encryptedSnapshotHeaderSize 返回版本 3 头部长度。
func encryptedSnapshotHeaderSize(confLen int) int {
	return encryptedSnapshotBaseHeader + confLen
}

// encodeEncryptedSnapshotHeader serializes a version 3 header. The SHA-256 field
// is zeroed when useSHA is false. | encodeEncryptedSnapshotHeader 序列化版本 3
// 头部；useSHA 为假时 SHA-256 字段置零。
func encodeEncryptedSnapshotHeader(dst []byte, conf []byte, index, term, dataLen uint64, crc uint32,
	sum []byte, useSHA bool, keyID uint32, suite EncryptionSuite, salt [streamSaltSize]byte, chunkSize int) []byte {
	flags := snapshotChecksumFlag(useSHA)
	dst = append(dst, snapshotMagic...)
	dst = append(dst, snapshotVersionEncrypted)
	dst = binary.LittleEndian.AppendUint64(dst, index)
	dst = binary.LittleEndian.AppendUint64(dst, term)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(conf)))
	dst = append(dst, conf...)
	dst = binary.LittleEndian.AppendUint64(dst, dataLen)
	dst = binary.LittleEndian.AppendUint32(dst, crc)
	dst = append(dst, flags)
	dst = binary.LittleEndian.AppendUint32(dst, keyID)
	dst = append(dst, byte(suite))
	dst = append(dst, salt[:]...)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(chunkSize))
	if useSHA {
		dst = append(dst, sum...)
	} else {
		dst = append(dst, make([]byte, 32)...)
	}
	return dst
}

// snapshotSealWriter buffers plaintext into fixed-size chunks and seals each one
// into the snapshot file. | snapshotSealWriter 把明文缓存为固定大小分块并逐块封装
// 写入快照文件。
type snapshotSealWriter struct {
	w         io.Writer
	aead      cipher.AEAD
	err       error
	buf       []byte
	prefix    []byte
	chunkSize int
	index     uint32
	salt      [streamSaltSize]byte
	closed    bool
}

// newSnapshotSealWriter creates a chunk writer for one snapshot file. |
// newSnapshotSealWriter 为一个快照文件创建分块写入器。
func newSnapshotSealWriter(w io.Writer, meta *snapshotCrypto) (*snapshotSealWriter, error) {
	aead, err := meta.chunkAEAD()
	if err != nil {
		return nil, err
	}
	return &snapshotSealWriter{
		w:         w,
		aead:      aead,
		prefix:    meta.headerDigest(),
		salt:      meta.salt,
		chunkSize: meta.chunkSize,
	}, nil
}

// Write buffers plaintext until one chunk is full. | Write 缓存明文直到一个分块
// 填满。
func (w *snapshotSealWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errs.Detail(ErrStorage, "snapshot image is closed | 快照镜像已关闭")
	}
	written := 0
	for len(p) > 0 {
		if len(w.buf) == w.chunkSize {
			if err := w.writeChunk(w.buf, false, 0); err != nil {
				w.err = err
				return written, err
			}
			w.buf = w.buf[:0]
		}
		n := w.chunkSize - len(w.buf)
		if n > len(p) {
			n = len(p)
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		written += n
	}
	return written, nil
}

// Close flushes the final data chunk and writes the authenticated end marker
// carrying the plaintext length. | Close 刷新最后一个数据分块，并写出携带明文长度的
// 认证结束标记。
func (w *snapshotSealWriter) Close(dataLen uint64) error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if len(w.buf) > 0 {
		if err := w.writeChunk(w.buf, false, 0); err != nil {
			w.err = err
			return err
		}
		w.buf = w.buf[:0]
	}
	if err := w.writeChunk(nil, true, dataLen); err != nil {
		w.err = err
		return err
	}
	return nil
}

// writeChunk seals and writes one chunk. | writeChunk 封装并写出一个分块。
func (w *snapshotSealWriter) writeChunk(plain []byte, final bool, dataLen uint64) error {
	if w.index == math.MaxUint32 {
		return errs.Detail(ErrTooLarge, "snapshot chunk index overflow | 快照分块序号溢出")
	}
	nonce := streamNonce(w.salt, w.index)
	aad := snapshotChunkAAD(nil, w.prefix, w.index, len(plain), final, dataLen)
	record := make([]byte, snapshotChunkHeaderSize, snapshotChunkHeaderSize+len(plain)+encryptionTagSize)
	binary.LittleEndian.PutUint32(record[0:4], uint32(len(plain)))
	binary.LittleEndian.PutUint32(record[4:8], uint32(len(plain)+encryptionTagSize))
	record = w.aead.Seal(record, nonce[:], plain, aad)
	if err := writeFull(w.w, record); err != nil {
		return err
	}
	w.index++
	return nil
}

// snapshotChunkAAD binds the header digest, chunk index, length, final flag and,
// for the end marker, the plaintext length. | snapshotChunkAAD 绑定头部摘要、
// 分块序号、长度与结束标志；结束标记还会绑定明文总长度。
func snapshotChunkAAD(dst, prefix []byte, index uint32, plainLen int, final bool, dataLen uint64) []byte {
	dst = append(dst, prefix...)
	dst = binary.LittleEndian.AppendUint32(dst, index)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(plainLen))
	if final {
		dst = append(dst, 1)
		return binary.LittleEndian.AppendUint64(dst, dataLen)
	}
	return append(dst, 0)
}

// decryptSnapshotPayload reads and authenticates every chunk of a version 3
// image. The file offset must already point at the first chunk. |
// decryptSnapshotPayload 读取并认证版本 3 镜像的每个分块；文件偏移必须已指向第一个
// 分块。
func decryptSnapshotPayload(f *os.File, size int64, meta *snapshotCrypto) ([]byte, error) {
	aead, err := meta.chunkAEAD()
	if err != nil {
		return nil, err
	}
	dataLen := meta.dataLen
	if dataLen < 0 || uint64(dataLen) > uint64(size) {
		return nil, errs.Detail(ErrCorrupt, "snapshot data length %d | 快照数据长度 %d 非法", dataLen, dataLen)
	}
	if uint64(dataLen) > uint64(math.MaxInt) {
		return nil, errs.Detail(ErrCorrupt, "snapshot data length %d | 快照数据长度 %d 溢出", dataLen, dataLen)
	}
	chunks := uint64(0)
	if dataLen > 0 {
		chunks = (uint64(dataLen) + uint64(meta.chunkSize) - 1) / uint64(meta.chunkSize)
	}
	if chunks > math.MaxUint32 {
		return nil, errs.Detail(ErrCorrupt, "snapshot chunk count %d | 快照分块数量 %d 溢出", chunks, chunks)
	}
	expected := uint64(meta.headerLen) + uint64(dataLen) +
		chunks*uint64(snapshotChunkHeaderSize+encryptionTagSize) +
		uint64(snapshotChunkHeaderSize+encryptionTagSize)
	if uint64(size) != expected {
		return nil, errs.Detail(ErrCorrupt,
			"encrypted snapshot size %d, want %d | 加密快照长度 %d，期望 %d", size, expected, size, expected)
	}
	payload := make([]byte, int(dataLen))
	offset := 0
	var index uint32
	for offset < len(payload) {
		plainLen := meta.chunkSize
		if remaining := len(payload) - offset; remaining < plainLen {
			plainLen = remaining
		}
		plain, err := readSnapshotChunk(f, meta, aead, index, plainLen, false, 0)
		if err != nil {
			return nil, err
		}
		copy(payload[offset:], plain)
		offset += plainLen
		index++
	}
	if _, err := readSnapshotChunk(f, meta, aead, index, 0, true, uint64(dataLen)); err != nil {
		return nil, err
	}
	return payload, nil
}

// readSnapshotChunk reads and authenticates one chunk record. | readSnapshotChunk
// 读取并认证一条分块记录。
func readSnapshotChunk(f io.Reader, meta *snapshotCrypto, aead cipher.AEAD,
	index uint32, wantPlain int, final bool, dataLen uint64) ([]byte, error) {
	var header [snapshotChunkHeaderSize]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return nil, errs.WrapDetail(err, ErrCorrupt, "short snapshot chunk | 快照分块过短")
	}
	plainLen := binary.LittleEndian.Uint32(header[0:4])
	cipherLen := binary.LittleEndian.Uint32(header[4:8])
	if int(plainLen) != wantPlain || cipherLen != plainLen+encryptionTagSize {
		return nil, errs.Detail(ErrCorrupt,
			"snapshot chunk lengths %d/%d, want %d | 快照分块长度 %d/%d，期望 %d",
			plainLen, cipherLen, wantPlain, plainLen, cipherLen, wantPlain)
	}
	sealed := make([]byte, cipherLen)
	if _, err := io.ReadFull(f, sealed); err != nil {
		return nil, errs.WrapDetail(err, ErrCorrupt, "short snapshot chunk | 快照分块过短")
	}
	nonce := streamNonce(meta.salt, index)
	aad := snapshotChunkAAD(nil, meta.headerDigest(), index, wantPlain, final, dataLen)
	plain, err := aead.Open(nil, nonce[:], sealed, aad)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCorrupt, "snapshot chunk authentication failed | 快照分块认证失败")
	}
	return plain, nil
}

// readSnapshotRange decrypts a plaintext range from a version 3 image for chunked
// transport without scanning the whole file. | readSnapshotRange 为分块传输解密版本 3
// 镜像中的一段明文，无需扫描整个文件。
func readSnapshotRange(snap *Snapshot, offset, size uint64) ([]byte, error) {
	meta := snap.crypto
	if meta == nil {
		return nil, errs.Detail(ErrCorrupt, "nil snapshot crypto metadata | 快照加密元数据为空")
	}
	total := uint64(meta.dataLen)
	if offset > total || size > total-offset {
		return nil, errs.Detail(ErrCorrupt, "snapshot range beyond payload | 快照范围越界")
	}
	out := make([]byte, int(size))
	if size == 0 {
		return out, nil
	}
	aead, err := meta.chunkAEAD()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(snap.file)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	defer f.Close()
	chunkSize := uint64(meta.chunkSize)
	first := offset / chunkSize
	last := (offset + size - 1) / chunkSize
	if last > math.MaxUint32 {
		return nil, errs.Detail(ErrCorrupt, "snapshot chunk index %d | 快照分块序号 %d 溢出", last, last)
	}
	for index := first; index <= last; index++ {
		chunkStart := index * chunkSize
		plainLen := chunkSize
		if remaining := total - chunkStart; remaining < plainLen {
			plainLen = remaining
		}
		fileOffset := uint64(meta.headerLen) + index*uint64(snapshotChunkHeaderSize+encryptionTagSize) + chunkStart
		var header [snapshotChunkHeaderSize]byte
		if _, err := f.ReadAt(header[:], int64(fileOffset)); err != nil {
			return nil, errs.WrapDetail(err, ErrCorrupt, "short snapshot chunk | 快照分块过短")
		}
		gotPlain := binary.LittleEndian.Uint32(header[0:4])
		gotCipher := binary.LittleEndian.Uint32(header[4:8])
		if uint64(gotPlain) != plainLen || uint64(gotCipher) != plainLen+encryptionTagSize {
			return nil, errs.Detail(ErrCorrupt,
				"snapshot chunk lengths %d/%d | 快照分块长度 %d/%d", gotPlain, gotCipher, gotPlain, gotCipher)
		}
		sealed := make([]byte, gotCipher)
		if _, err := f.ReadAt(sealed, int64(fileOffset)+snapshotChunkHeaderSize); err != nil {
			return nil, errs.WrapDetail(err, ErrCorrupt, "short snapshot chunk | 快照分块过短")
		}
		nonce := streamNonce(meta.salt, uint32(index))
		aad := snapshotChunkAAD(nil, meta.headerDigest(), uint32(index), int(plainLen), false, 0)
		plain, err := aead.Open(nil, nonce[:], sealed, aad)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrCorrupt, "snapshot chunk authentication failed | 快照分块认证失败")
		}
		start := offset
		if chunkStart > start {
			start = chunkStart
		}
		end := offset + size
		if chunkEnd := chunkStart + plainLen; chunkEnd < end {
			end = chunkEnd
		}
		copy(out[start-offset:end-offset], plain[start-chunkStart:end-chunkStart])
	}
	return out, nil
}

// readEncryptedSnapshot parses the version 3 encryption trailer, decrypts the
// payload and verifies the checksums. The file offset must point at the flags
// byte after the plaintext length and CRC. | readEncryptedSnapshot 解析版本 3 加密
// 尾部、解密负载并校验校验和；文件偏移必须指向明文长度与 CRC 之后的标志字节。
func readEncryptedSnapshot(path string, f *os.File, info os.FileInfo, conf ConfState,
	confData []byte, confLen int, index, term, dataLen uint64, wantCRC uint32,
	cipher *dataCipher) (*Snapshot, error) {
	var flags [1]byte
	if _, err := io.ReadFull(f, flags[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot flags %[1]s | 快照标志过短 %[1]s", path)
	}
	if flags[0]&^snapshotFlagSHA256 != 0 {
		return nil, errs.Detail(ErrCorrupt, "snapshot checksum flags %[1]d | 快照校验标志 %[1]d", flags[0])
	}
	hasSHA := flags[0]&snapshotFlagSHA256 != 0
	var enc [4 + 1 + streamSaltSize + 4]byte
	if _, err := io.ReadFull(f, enc[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot encryption header %[1]s | 快照加密头部过短 %[1]s", path)
	}
	keyID := binary.LittleEndian.Uint32(enc[0:4])
	suite := EncryptionSuite(enc[4])
	if !suite.valid() {
		return nil, errs.Detail(ErrCorrupt, "snapshot suite %[1]d | 快照套件 %[1]d", enc[4])
	}
	var salt [streamSaltSize]byte
	copy(salt[:], enc[5:21])
	chunkSize := int(binary.LittleEndian.Uint32(enc[21:25]))
	if chunkSize <= 0 || chunkSize > maxEncryptionChunkSize {
		return nil, errs.Detail(ErrCorrupt, "snapshot chunk size %[1]d | 快照分块大小 %[1]d", chunkSize)
	}
	var wantSum [32]byte
	if _, err := io.ReadFull(f, wantSum[:]); err != nil {
		return nil, errs.Detail(ErrCorrupt, "short snapshot SHA-256 %[1]s | 快照 SHA-256 过短 %[1]s", path)
	}
	headerLen := int64(encryptedSnapshotHeaderSize(confLen))
	if headerLen > info.Size() || dataLen > uint64(info.Size()) || dataLen > math.MaxInt64 {
		return nil, errs.Detail(ErrCorrupt, "snapshot data length %[1]d | 快照数据长度 %[1]d", dataLen)
	}
	if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != headerLen {
		return nil, errs.Detail(ErrCorrupt, "snapshot header position %d, want %d | 快照头部位置 %d，期望 %d",
			pos, headerLen, pos, headerLen)
	}
	meta := &snapshotCrypto{
		cipher:     cipher,
		keyID:      keyID,
		suite:      suite,
		salt:       salt,
		chunkSize:  chunkSize,
		index:      index,
		term:       term,
		dataLen:    int64(dataLen),
		headerLen:  headerLen,
		prefixHash: snapshotPrefixHash(index, term, keyID, suite, flags[0], salt, chunkSize, confData),
	}
	payload, err := decryptSnapshotPayload(f, info.Size(), meta)
	if err != nil {
		return nil, err
	}
	if crc32.Checksum(payload, castagnoli) != wantCRC {
		return nil, errs.Detail(ErrCorrupt, "snapshot CRC mismatch %[1]s | 快照 CRC 不匹配 %[1]s", path)
	}
	if hasSHA {
		sum := sha256.Sum256(payload)
		if !bytes.Equal(sum[:], wantSum[:]) {
			return nil, errs.Detail(ErrCorrupt, "snapshot SHA-256 mismatch %[1]s | 快照 SHA-256 不匹配 %[1]s", path)
		}
	}
	if index == 0 || term == 0 {
		return nil, errs.Detail(ErrCorrupt, "snapshot index=%[1]d term=%[2]d | 快照索引=%[1]d 任期=%[2]d", index, term)
	}
	return &Snapshot{Index: index, Term: term, ConfState: conf, Data: payload, crypto: meta}, nil
}

// snapshotSalt fills a fresh per-file salt. | snapshotSalt 生成新的每文件 salt。
func snapshotSalt() ([streamSaltSize]byte, error) {
	var salt [streamSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return salt, errs.Wrap(err, ErrRandom)
	}
	return salt, nil
}
