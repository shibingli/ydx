package raft

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"

	"github.com/shibingli/ydx/errs"
)

const (
	// streamMagic prefixes every streaming ciphertext. | streamMagic 是每个流式
	// 密文的前缀魔数。
	streamMagic = "YDRSTR01"
	// streamVersion is the current streaming format version. | streamVersion 是当前
	// 流式格式版本。
	streamVersion = byte(1)
	// streamHeaderSize is magic, version, key ID, suite, salt and chunk size. |
	// streamHeaderSize 是魔数、版本、密钥 ID、套件、salt 与分块大小的长度。
	streamHeaderSize = 8 + 1 + 4 + 1 + 16 + 4
	// streamChunkHeaderSize is the plaintext and ciphertext length prefix. |
	// streamChunkHeaderSize 是明文与密文长度前缀的长度。
	streamChunkHeaderSize = 8
	// streamSaltSize is the per-stream HKDF salt and nonce prefix length. |
	// streamSaltSize 是每个流的 HKDF salt 与 nonce 前缀长度。
	streamSaltSize = 16
	// streamFinalChunk is the final-marker flag bound into the AEAD. |
	// streamFinalChunk 是绑定进 AEAD 的结束标记标志。
	streamFinalChunk = byte(1)
)

// EncryptWriter seals plaintext written to it as a sequence of independently
// authenticated chunks. Close writes the final marker and must be called to
// produce a complete stream. The writer is not safe for concurrent use. |
// EncryptWriter 把写入的明文封装为逐块独立认证的密文流。必须调用 Close 写入结束
// 标记才能得到完整流；该写入器不支持并发使用。
type EncryptWriter struct {
	w         io.Writer
	aead      cipher.AEAD
	err       error
	buf       []byte
	userAAD   []byte
	chunkSize int
	index     uint32
	header    [streamHeaderSize]byte
	salt      [streamSaltSize]byte
	closed    bool
}

// NewEncryptWriter starts a streaming ciphertext. The header is written
// immediately. aad is authenticated for every chunk and is not stored. The
// caller must flush any buffered underlying writer after Close. |
// NewEncryptWriter 开始一个流式密文并立即写出头部。aad 会参与每个分块的认证且
// 不会被存储。Close 之后调用方必须刷新可能带缓冲的底层写入器。
func (e *Encryptor) NewEncryptWriter(w io.Writer, aad []byte) (io.WriteCloser, error) {
	if e == nil || e.active == nil {
		return nil, errs.Detail(ErrInvalidKey, "nil encryptor | 加密器为空")
	}
	if w == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil stream writer | 流写入器为空")
	}
	writer := &EncryptWriter{w: w, chunkSize: e.chunkSize}
	if _, err := rand.Read(writer.salt[:]); err != nil {
		return nil, errs.Wrap(err, ErrRandom)
	}
	aead, err := e.active.deriveAEAD(writer.salt[:], infoStream)
	if err != nil {
		return nil, err
	}
	writer.aead = aead
	writer.userAAD = append([]byte(nil), aad...)
	copy(writer.header[:8], streamMagic)
	writer.header[8] = streamVersion
	binary.LittleEndian.PutUint32(writer.header[9:13], e.active.id)
	writer.header[13] = byte(e.active.suite)
	copy(writer.header[14:30], writer.salt[:])
	binary.LittleEndian.PutUint32(writer.header[30:34], uint32(e.chunkSize))
	if err := writeFull(w, writer.header[:]); err != nil {
		return nil, err
	}
	return writer, nil
}

// Write buffers plaintext until one chunk is full and seals it. After an error
// the writer is unusable. | Write 缓存明文直到一个分块填满后封装；出错后写入器
// 不可再用。
func (w *EncryptWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errs.Detail(ErrInvalidConfig, "write after close | 关闭后写入")
	}
	written := 0
	for len(p) > 0 {
		if len(w.buf) == w.chunkSize {
			if err := w.flushChunk(); err != nil {
				w.err = err
				return written, err
			}
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

// Close flushes the final partial chunk and writes the authenticated end marker.
// | Close 刷新最后一个不完整分块并写入认证结束标记。
func (w *EncryptWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if err := w.flushChunk(); err != nil {
		w.err = err
		return err
	}
	if err := w.writeChunk(nil, true); err != nil {
		w.err = err
		return err
	}
	return nil
}

// flushChunk seals buffered plaintext as one data chunk. | flushChunk 将缓存的明文
// 封装为一个数据分块。
func (w *EncryptWriter) flushChunk() error {
	if len(w.buf) == 0 {
		return nil
	}
	if err := w.writeChunk(w.buf, false); err != nil {
		return err
	}
	w.buf = w.buf[:0]
	return nil
}

// writeChunk seals and writes one chunk, including the final marker when final
// is set. | writeChunk 封装并写出一个分块；final 为真时写出结束标记。
func (w *EncryptWriter) writeChunk(plain []byte, final bool) error {
	if w.index == math.MaxUint32 {
		return errs.Detail(ErrTooLarge, "stream chunk index overflow | 流分块序号溢出")
	}
	nonce := streamNonce(w.salt, w.index)
	aad := streamChunkAAD(nil, w.header[:], w.index, len(plain), final, w.userAAD)
	record := make([]byte, streamChunkHeaderSize, streamChunkHeaderSize+len(plain)+encryptionTagSize)
	binary.LittleEndian.PutUint32(record[0:4], uint32(len(plain)))
	binary.LittleEndian.PutUint32(record[4:8], uint32(len(plain)+encryptionTagSize))
	record = w.aead.Seal(record, nonce[:], plain, aad)
	if err := writeFull(w.w, record); err != nil {
		return err
	}
	w.index++
	return nil
}

// DecryptReader verifies and decrypts a stream produced by NewEncryptWriter. It
// returns io.EOF only after the authenticated end marker. The reader is not safe
// for concurrent use. | DecryptReader 校验并解密 NewEncryptWriter 生成的流；只有
// 通过认证的结束标记之后才返回 io.EOF。该读取器不支持并发使用。
type DecryptReader struct {
	r         io.Reader
	aead      cipher.AEAD
	err       error
	buf       []byte
	userAAD   []byte
	chunkSize int
	index     uint32
	header    [streamHeaderSize]byte
	salt      [streamSaltSize]byte
	done      bool
}

// NewDecryptReader parses and authenticates the stream header. aad must match
// the value passed to NewEncryptWriter. | NewDecryptReader 解析并认证流头部；
// aad 必须与 NewEncryptWriter 传入的值一致。
func (e *Encryptor) NewDecryptReader(r io.Reader, aad []byte) (io.Reader, error) {
	if e == nil || e.ring == nil {
		return nil, errs.Detail(ErrInvalidKey, "nil encryptor | 加密器为空")
	}
	if r == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil stream reader | 流读取器为空")
	}
	reader := &DecryptReader{r: r, userAAD: append([]byte(nil), aad...)}
	if _, err := io.ReadFull(r, reader.header[:]); err != nil {
		return nil, errs.WrapDetail(err, ErrAuth, "short stream header | 流头部过短")
	}
	if string(reader.header[:8]) != streamMagic {
		return nil, errs.Detail(ErrAuth, "bad stream magic | 流魔数错误")
	}
	if reader.header[8] != streamVersion {
		return nil, errs.Detail(ErrAuth, "unsupported stream version %d | 流版本 %d 不受支持",
			reader.header[8], reader.header[8])
	}
	keyID := binary.LittleEndian.Uint32(reader.header[9:13])
	suite := EncryptionSuite(reader.header[13])
	if !suite.valid() {
		return nil, errs.Detail(ErrAuth, "unknown suite %d | 未知套件 %d", reader.header[13], reader.header[13])
	}
	key, ok := e.ring.keys[keyID]
	if !ok {
		return nil, errs.Detail(ErrKeyNotFound, "key ID %[1]d is not in the ring | 密钥 ID %[1]d 不在密钥环中", keyID)
	}
	if key.suite != suite {
		return nil, errs.Detail(ErrAuth, "key %d suite differs from stream suite | 密钥 %d 套件与流套件不一致", keyID, keyID)
	}
	copy(reader.salt[:], reader.header[14:30])
	chunkSize := int(binary.LittleEndian.Uint32(reader.header[30:34]))
	if chunkSize <= 0 || chunkSize > maxEncryptionChunkSize {
		return nil, errs.Detail(ErrAuth, "stream chunk size %d | 流分块大小 %d", chunkSize, chunkSize)
	}
	reader.chunkSize = chunkSize
	aead, err := key.deriveAEAD(reader.salt[:], infoStream)
	if err != nil {
		return nil, err
	}
	reader.aead = aead
	return reader, nil
}

// Read returns decrypted plaintext. | Read 返回解密后的明文。
func (r *DecryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.nextChunk(); err != nil {
			if err == io.EOF {
				return 0, io.EOF
			}
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// nextChunk reads one chunk or the final marker. | nextChunk 读取一个分块或结束标记。
func (r *DecryptReader) nextChunk() error {
	if r.index == math.MaxUint32 {
		return errs.Detail(ErrTooLarge, "stream chunk index overflow | 流分块序号溢出")
	}
	var prefix [streamChunkHeaderSize]byte
	if _, err := io.ReadFull(r.r, prefix[:]); err != nil {
		return errs.WrapDetail(err, ErrAuth, "stream ended before final marker | 流在结束标记前终止")
	}
	plainLen := binary.LittleEndian.Uint32(prefix[0:4])
	cipherLen := binary.LittleEndian.Uint32(prefix[4:8])
	if plainLen == 0 {
		if cipherLen != encryptionTagSize {
			return errs.Detail(ErrAuth, "bad final marker length %d | 结束标记长度 %d 非法", cipherLen, cipherLen)
		}
		sealed := make([]byte, cipherLen)
		if _, err := io.ReadFull(r.r, sealed); err != nil {
			return errs.WrapDetail(err, ErrAuth, "short final marker | 结束标记过短")
		}
		nonce := streamNonce(r.salt, r.index)
		aad := streamChunkAAD(nil, r.header[:], r.index, 0, true, r.userAAD)
		if _, err := r.aead.Open(nil, nonce[:], sealed, aad); err != nil {
			return errs.Wrap(err, ErrAuth)
		}
		var extra [1]byte
		if n, err := io.ReadFull(r.r, extra[:]); n != 0 {
			return errs.Detail(ErrAuth, "trailing data after final marker | 结束标记后存在多余数据")
		} else if err != nil && err != io.EOF {
			return err
		}
		r.done = true
		return io.EOF
	}
	if plainLen > uint32(r.chunkSize) || cipherLen != plainLen+encryptionTagSize {
		return errs.Detail(ErrAuth,
			"invalid chunk lengths %d/%d | 分块长度 %d/%d 非法",
			plainLen, cipherLen, plainLen, cipherLen)
	}
	sealed := make([]byte, cipherLen)
	if _, err := io.ReadFull(r.r, sealed); err != nil {
		return errs.WrapDetail(err, ErrAuth, "short chunk | 分块过短")
	}
	nonce := streamNonce(r.salt, r.index)
	aad := streamChunkAAD(nil, r.header[:], r.index, int(plainLen), false, r.userAAD)
	plain, err := r.aead.Open(nil, nonce[:], sealed, aad)
	if err != nil {
		return errs.Wrap(err, ErrAuth)
	}
	r.buf = plain
	r.index++
	return nil
}

// streamNonce builds the deterministic nonce for a chunk index. | streamNonce
// 为分块序号构建确定性 nonce。
func streamNonce(salt [streamSaltSize]byte, index uint32) [encryptionNonceSize]byte {
	var nonce [encryptionNonceSize]byte
	copy(nonce[:8], salt[:8])
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce
}

// streamChunkAAD binds the header, chunk index, lengths, final flag and caller
// data into one additional-data buffer. | streamChunkAAD 把头部、分块序号、长度、
// 结束标志与调用方数据绑定为一个附加数据缓冲区。
func streamChunkAAD(dst, header []byte, index uint32, plainLen int, final bool, user []byte) []byte {
	dst = append(dst, header...)
	dst = binary.LittleEndian.AppendUint32(dst, index)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(plainLen))
	if final {
		dst = append(dst, streamFinalChunk)
	} else {
		dst = append(dst, 0)
	}
	return append(dst, user...)
}
