package wal

import (
	"encoding/binary"
	"hash/crc32"
	"math"

	"github.com/shibingli/ydx/errs"
)

// On-disk record flags and codec identifiers. | 磁盘记录标志与压缩算法标识。
const (
	recordFlagEncrypted  uint16 = 1 << 0
	recordFlagCompressed uint16 = 1 << 1
	recordFlagDedupRef   uint16 = 1 << 2
	recordFlagCommitMark uint16 = 1 << 3
	recordLowerFlagMask         = recordFlagEncrypted | recordFlagCompressed | recordFlagDedupRef | recordFlagCommitMark
	recordUserFlagShift         = 4
	recordUserFlagMask          = 0x0FFF

	cipherNone   byte = 0
	cipherAESGCM byte = 1
	cipherSM4GCM byte = 2

	codecNone       byte = 0
	codecFlate      byte = 1
	codecZstd       byte = 2
	codecReservedLo byte = 3
	codecReservedHi byte = 127
	codecUserLo     byte = 128
	codecUserHi     byte = 254
	codecTxnControl byte = 255

	markerPayloadSize    = 28
	txnControlBaseSize   = 56
	txnKeyDigestSize     = 32
	dedupRefBlockSize    = 48
	commitMarkerOverhead = recordHeaderSize + markerPayloadSize
)

// castagnoli is the CRC32C table used by every WAL structure. | castagnoli 是全部 WAL 结构使用的 CRC32C 表。
var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// recordHeader is the decoded fixed record header. | recordHeader 是解码后的定长记录头。
type recordHeader struct {
	size      uint32
	lsn       uint64
	timestamp int64
	txnID     uint64
	keyLen    uint32
	dataLen   uint32
	flags     uint16
	cipher    byte
	codec     byte
	keyID     uint32
	headerLen int
}

// recordOffset fields. | 记录头字段偏移。
const (
	recOffCRC       = 0
	recOffSize      = 4
	recOffLSN       = 8
	recOffTimestamp = 16
	recOffTxnID     = 24
	recOffKeyLen    = 32
	recOffDataLen   = 36
	recOffFlags     = 40
	recOffCipher    = 42
	recOffCodec     = 43
	recOffKeyID     = 44
	recOffNonce     = 48
)

// markerOffset fields. | 提交标记字段偏移。
const (
	markerOffCommittedEnd = 0
	markerOffLastLSN      = 8
	markerOffRecordCount  = 16
	markerOffSegmentCRC   = 24
)

// txnControlOffset fields. | 事务控制记录字段偏移。
const (
	txnOffKind         = 0
	txnOffHashAlg      = 1
	txnOffReserved     = 2
	txnOffCommitSeq    = 8
	txnOffFirstLSN     = 16
	txnOffLastLSN      = 24
	txnOffRecordCount  = 32
	txnOffBytes        = 40
	txnOffWriteKeyNum  = 48
	txnOffReserved2    = 52
	txnOffWriteKeyBase = 56
)

// txnKindCommit is the only transaction control kind written by v1. | txnKindCommit 是 v1 写入的唯一事务控制类型。
const txnKindCommit byte = 1

// encodeRecordHeader fills the fixed 48-byte header. | encodeRecordHeader 填充固定 48 字节记录头。
func encodeRecordHeader(dst []byte, size uint32, lsn uint64, timestamp int64, txnID uint64,
	keyLen, dataLen uint32, flags uint16, cipher, codec byte, keyID uint32) {
	binary.LittleEndian.PutUint32(dst[recOffSize:], size)
	binary.LittleEndian.PutUint64(dst[recOffLSN:], lsn)
	binary.LittleEndian.PutUint64(dst[recOffTimestamp:], uint64(timestamp))
	binary.LittleEndian.PutUint64(dst[recOffTxnID:], txnID)
	binary.LittleEndian.PutUint32(dst[recOffKeyLen:], keyLen)
	binary.LittleEndian.PutUint32(dst[recOffDataLen:], dataLen)
	binary.LittleEndian.PutUint16(dst[recOffFlags:], flags)
	dst[recOffCipher] = cipher
	dst[recOffCodec] = codec
	binary.LittleEndian.PutUint32(dst[recOffKeyID:], keyID)
}

// parseRecordHeader decodes the fixed header and validates structural lengths. | parseRecordHeader
// 解码定长头并校验结构长度。
func parseRecordHeader(h []byte) (recordHeader, error) {
	if len(h) < recordHeaderSize {
		return recordHeader{}, errs.Detail(ErrCorrupt, "record header has %[1]d bytes | 记录头仅 %[1]d 字节", len(h))
	}
	var rh recordHeader
	rh.size = binary.LittleEndian.Uint32(h[recOffSize:])
	rh.lsn = binary.LittleEndian.Uint64(h[recOffLSN:])
	rh.timestamp = int64(binary.LittleEndian.Uint64(h[recOffTimestamp:]))
	rh.txnID = binary.LittleEndian.Uint64(h[recOffTxnID:])
	rh.keyLen = binary.LittleEndian.Uint32(h[recOffKeyLen:])
	rh.dataLen = binary.LittleEndian.Uint32(h[recOffDataLen:])
	rh.flags = binary.LittleEndian.Uint16(h[recOffFlags:])
	rh.cipher = h[recOffCipher]
	rh.codec = h[recOffCodec]
	rh.keyID = binary.LittleEndian.Uint32(h[recOffKeyID:])

	switch rh.cipher {
	case cipherNone:
		rh.headerLen = recordHeaderSize
	case cipherAESGCM, cipherSM4GCM:
		rh.headerLen = recordHeaderSizeEncrypted
	default:
		return recordHeader{}, errs.Detail(ErrCorrupt, "unknown cipher %[1]d | 未知密码套件 %[1]d", rh.cipher)
	}
	if (rh.flags&recordFlagEncrypted != 0) != (rh.cipher != cipherNone) {
		return recordHeader{}, errs.Detail(ErrCorrupt, "encrypted flag and cipher disagree | 加密标志与密码套件不一致")
	}
	if rh.size < uint32(rh.headerLen) {
		return recordHeader{}, errs.Detail(ErrCorrupt, "record size %[1]d is below header size %[2]d | 记录大小 %[1]d 小于头长度 %[2]d", rh.size, rh.headerLen)
	}
	if rh.size > formatHardLimit {
		return recordHeader{}, errs.Detail(ErrTooLarge, "record size %[1]d exceeds the 1 GiB format limit | 记录大小 %[1]d 超过 1 GiB 格式上限", rh.size)
	}
	if uint64(rh.keyLen)+uint64(rh.dataLen) > formatHardLimit {
		return recordHeader{}, errs.Detail(ErrTooLarge, "keyLen+dataLen exceeds the 1 GiB format limit | keyLen+dataLen 超过 1 GiB 格式上限")
	}
	return rh, nil
}

// validateRecordHeader checks the format state machine that every reader and
// Verify must execute. | validateRecordHeader 校验所有读取路径与 Verify 都必须执行的格式状态机。
func validateRecordHeader(rh recordHeader) error {
	if rh.flags&recordFlagCompressed != 0 && rh.codec == codecNone {
		return errs.Detail(ErrCorrupt, "compressed flag with codec 0 | 压缩标志对应 codec 0")
	}
	if rh.codec >= codecReservedLo && rh.codec <= codecReservedHi {
		return errs.Detail(ErrCorrupt, "reserved codec %[1]d | 保留 codec %[1]d", rh.codec)
	}
	if rh.flags&recordFlagCompressed == 0 && rh.codec != codecNone && rh.codec != codecTxnControl {
		return errs.Detail(ErrCorrupt, "codec %[1]d without compressed flag | codec %[1]d 未置压缩标志", rh.codec)
	}
	if rh.flags&recordFlagDedupRef != 0 {
		if rh.flags&recordFlagCompressed != 0 || rh.codec != codecNone {
			return errs.Detail(ErrCorrupt, "dedup reference cannot be compressed | 去重引用不得压缩")
		}
		// Dedup references never belong to a transaction; this preserves the
		// v1 on-disk format and read compatibility with v0.1.0. Transaction
		// records are stored as ordinary records and can still be dedup targets
		// for later non-transaction records. | 去重引用不属于事务，保持 v1 磁盘
		// 格式与 v0.1.0 的读取兼容；事务记录按普通记录存储，仍可作为之后非事务
		// 记录的去重目标。
		if rh.lsn == 0 || rh.txnID != 0 {
			return errs.Detail(ErrCorrupt, "dedup reference has lsn 0 or a transaction | 去重引用的 lsn 为 0 或带事务")
		}
	}
	if rh.flags&recordFlagCommitMark != 0 {
		if rh.lsn != 0 || rh.txnID != 0 || rh.keyLen != 0 || rh.dataLen != 0 ||
			rh.flags&(recordFlagCompressed|recordFlagDedupRef) != 0 || rh.codec != codecNone ||
			rh.flags>>recordUserFlagShift != 0 {
			return errs.Detail(ErrCorrupt, "malformed commit marker | 提交标记格式非法")
		}
	}
	if rh.codec == codecTxnControl {
		if rh.txnID == 0 || rh.lsn != 0 || rh.keyLen != 0 || rh.dataLen != 0 ||
			rh.flags&(recordFlagCompressed|recordFlagDedupRef|recordFlagCommitMark) != 0 ||
			rh.flags>>recordUserFlagShift != 0 {
			return errs.Detail(ErrCorrupt, "malformed transaction control record | 事务控制记录格式非法")
		}
	}
	if rh.codec != codecTxnControl && rh.flags&recordFlagCommitMark == 0 {
		if rh.lsn == 0 {
			return errs.Detail(ErrCorrupt, "user record has lsn 0 | 用户记录 lsn 为 0")
		}
	}
	return nil
}

// plainPayloadLen returns the payload length after removing the AEAD tag. | plainPayloadLen
// 返回去掉 AEAD tag 后的负载长度。
func plainPayloadLen(rh recordHeader) int {
	n := int(rh.size) - rh.headerLen
	if rh.cipher != cipherNone {
		n -= aeadTagSize
	}
	return n
}

// validatePayloadLength checks the payload shape implied by the flags. | validatePayloadLength
// 校验标志位决定的负载形态。
func validatePayloadLength(rh recordHeader) error {
	payload := plainPayloadLen(rh)
	switch {
	case rh.codec == codecTxnControl:
		if payload < txnControlBaseSize || (payload-txnControlBaseSize)%txnKeyDigestSize != 0 {
			return errs.Detail(ErrCorrupt, "bad transaction control payload length %[1]d | 事务控制负载长度 %[1]d 非法", payload)
		}
	case rh.flags&recordFlagCommitMark != 0:
		if payload != markerPayloadSize {
			return errs.Detail(ErrCorrupt, "bad commit marker payload length %[1]d | 提交标记负载长度 %[1]d 非法", payload)
		}
	case rh.flags&recordFlagDedupRef != 0:
		want := int(rh.keyLen) + dedupRefBlockSize
		if payload != want {
			return errs.Detail(ErrDedupCorrupt, "dedup reference payload %[1]d, want %[2]d | 去重引用负载 %[1]d，期望 %[2]d", payload, want)
		}
	case rh.flags&recordFlagCompressed == 0:
		want := int(rh.keyLen) + int(rh.dataLen)
		if payload != want {
			return errs.Detail(ErrCorrupt, "record payload %[1]d, want %[2]d | 记录负载 %[1]d，期望 %[2]d", payload, want)
		}
	}
	return nil
}

// recordCRC computes the CRC of a complete record in place. | recordCRC 就地计算整条记录的 CRC。
func recordCRC(record []byte) uint32 {
	return crc32.Checksum(record[recOffSize:], castagnoli)
}

// fillRecordCRC computes and stores the record CRC. | fillRecordCRC 计算并写入记录 CRC。
func fillRecordCRC(record []byte) {
	binary.LittleEndian.PutUint32(record[recOffCRC:], recordCRC(record))
}

// appendCRC updates a running CRC with one slice. | appendCRC 用一段字节更新累计 CRC。
func appendCRC(crc uint32, p []byte) uint32 { return crc32.Update(crc, castagnoli, p) }

// checksum returns the CRC of a byte slice. | checksum 返回字节切片的 CRC。
func checksum(p []byte) uint32 { return crc32.Checksum(p, castagnoli) }

// encodeCommitMarkerPayload encodes the 28-byte marker payload. | encodeCommitMarkerPayload 编码 28 字节标记负载。
func encodeCommitMarkerPayload(committedEnd, lastLSN, recordCount uint64, segmentCRC uint32) []byte {
	buf := make([]byte, markerPayloadSize)
	return encodeCommitMarkerPayloadInto(buf, committedEnd, lastLSN, recordCount, segmentCRC)
}

// encodeCommitMarkerPayloadInto fills a caller buffer with the marker payload. | encodeCommitMarkerPayloadInto
// 用标记负载填充调用方缓冲。
func encodeCommitMarkerPayloadInto(buf []byte, committedEnd, lastLSN, recordCount uint64, segmentCRC uint32) []byte {
	buf = buf[:markerPayloadSize]
	binary.LittleEndian.PutUint64(buf[markerOffCommittedEnd:], committedEnd)
	binary.LittleEndian.PutUint64(buf[markerOffLastLSN:], lastLSN)
	binary.LittleEndian.PutUint64(buf[markerOffRecordCount:], recordCount)
	binary.LittleEndian.PutUint32(buf[markerOffSegmentCRC:], segmentCRC)
	return buf
}

// commitMarker is the decoded commit-marker payload. | commitMarker 是解码后的提交标记负载。
type commitMarker struct {
	committedEnd uint64
	lastLSN      uint64
	recordCount  uint64
	segmentCRC   uint32
}

// parseCommitMarkerPayload decodes the marker payload. | parseCommitMarkerPayload 解码标记负载。
func parseCommitMarkerPayload(p []byte) (commitMarker, error) {
	if len(p) != markerPayloadSize {
		return commitMarker{}, errs.Detail(ErrCorrupt, "commit marker payload has %[1]d bytes | 提交标记负载为 %[1]d 字节", len(p))
	}
	return commitMarker{
		committedEnd: binary.LittleEndian.Uint64(p[markerOffCommittedEnd:]),
		lastLSN:      binary.LittleEndian.Uint64(p[markerOffLastLSN:]),
		recordCount:  binary.LittleEndian.Uint64(p[markerOffRecordCount:]),
		segmentCRC:   binary.LittleEndian.Uint32(p[markerOffSegmentCRC:]),
	}, nil
}

// txnControl is the decoded transaction control payload. | txnControl 是解码后的事务控制负载。
type txnControl struct {
	writeKeys   [][txnKeyDigestSize]byte
	commitSeq   uint64
	firstLSN    uint64
	lastLSN     uint64
	recordCount uint64
	bytes       uint64
	kind        byte
	hashAlg     byte
}

// encodeTxnControlPayload encodes a transaction control payload. | encodeTxnControlPayload 编码事务控制负载。
func encodeTxnControlPayload(tc txnControl) []byte {
	buf := make([]byte, txnControlBaseSize+len(tc.writeKeys)*txnKeyDigestSize)
	buf[txnOffKind] = tc.kind
	buf[txnOffHashAlg] = tc.hashAlg
	binary.LittleEndian.PutUint64(buf[txnOffCommitSeq:], tc.commitSeq)
	binary.LittleEndian.PutUint64(buf[txnOffFirstLSN:], tc.firstLSN)
	binary.LittleEndian.PutUint64(buf[txnOffLastLSN:], tc.lastLSN)
	binary.LittleEndian.PutUint64(buf[txnOffRecordCount:], tc.recordCount)
	binary.LittleEndian.PutUint64(buf[txnOffBytes:], tc.bytes)
	binary.LittleEndian.PutUint32(buf[txnOffWriteKeyNum:], uint32(len(tc.writeKeys)))
	for i, key := range tc.writeKeys {
		copy(buf[txnOffWriteKeyBase+i*txnKeyDigestSize:], key[:])
	}
	return buf
}

// parseTxnControlPayload decodes and validates a transaction control payload. | parseTxnControlPayload
// 解码并校验事务控制负载。
func parseTxnControlPayload(p []byte) (txnControl, error) {
	if len(p) < txnControlBaseSize || (len(p)-txnControlBaseSize)%txnKeyDigestSize != 0 {
		return txnControl{}, errs.Detail(ErrCorrupt, "bad transaction control payload length %[1]d | 事务控制负载长度 %[1]d 非法", len(p))
	}
	n := int(binary.LittleEndian.Uint32(p[txnOffWriteKeyNum:]))
	if n < 0 || txnControlBaseSize+n*txnKeyDigestSize != len(p) {
		return txnControl{}, errs.Detail(ErrCorrupt, "transaction write-key count %[1]d does not match payload | 事务写键数量 %[1]d 与负载不匹配", n)
	}
	tc := txnControl{
		kind:        p[txnOffKind],
		hashAlg:     p[txnOffHashAlg],
		commitSeq:   binary.LittleEndian.Uint64(p[txnOffCommitSeq:]),
		firstLSN:    binary.LittleEndian.Uint64(p[txnOffFirstLSN:]),
		lastLSN:     binary.LittleEndian.Uint64(p[txnOffLastLSN:]),
		recordCount: binary.LittleEndian.Uint64(p[txnOffRecordCount:]),
		bytes:       binary.LittleEndian.Uint64(p[txnOffBytes:]),
		writeKeys:   make([][txnKeyDigestSize]byte, n),
	}
	for i := range tc.writeKeys {
		copy(tc.writeKeys[i][:], p[txnOffWriteKeyBase+i*txnKeyDigestSize:])
	}
	if tc.kind != txnKindCommit {
		return txnControl{}, errs.Detail(ErrCorrupt, "unknown transaction control kind %[1]d | 未知事务控制类型 %[1]d", tc.kind)
	}
	if tc.hashAlg > byte(HashSM3) {
		return txnControl{}, errs.Detail(ErrCorrupt, "unknown transaction hash algorithm %[1]d | 未知事务哈希算法 %[1]d", tc.hashAlg)
	}
	if tc.recordCount == 0 {
		if tc.firstLSN != 0 || tc.lastLSN != 0 || tc.bytes != 0 {
			return txnControl{}, errs.Detail(ErrCorrupt, "empty transaction control has non-zero statistics | 空事务控制记录的统计非零")
		}
	} else if tc.firstLSN == 0 || tc.lastLSN < tc.firstLSN {
		return txnControl{}, errs.Detail(ErrCorrupt, "transaction control LSN range is invalid | 事务控制 LSN 区间非法")
	}
	return tc, nil
}

// dedupRef is the decoded content-dedup reference block. | dedupRef 是解码后的内容去重引用块。
type dedupRef struct {
	offset  uint64
	hashAlg byte
	digest  [txnKeyDigestSize]byte
}

// encodeDedupRefPayload builds key || ref in one buffer. | encodeDedupRefPayload 在一个缓冲中构建 key || ref。
func encodeDedupRefPayload(key []byte, ref dedupRef) []byte {
	buf := make([]byte, len(key)+dedupRefBlockSize)
	copy(buf, key)
	off := len(key)
	binary.LittleEndian.PutUint64(buf[off:], ref.offset)
	buf[off+8] = ref.hashAlg
	copy(buf[off+16:], ref.digest[:])
	return buf
}

// parseDedupRefPayload decodes the reference block after a key. | parseDedupRefPayload 解码 Key 之后的引用块。
func parseDedupRefPayload(p []byte, keyLen int) ([]byte, dedupRef, error) {
	if keyLen < 0 || len(p) != keyLen+dedupRefBlockSize {
		return nil, dedupRef{}, errs.Detail(ErrDedupCorrupt, "bad dedup reference payload length %[1]d | 去重引用负载长度 %[1]d 非法", len(p))
	}
	key := p[:keyLen]
	off := keyLen
	ref := dedupRef{offset: binary.LittleEndian.Uint64(p[off:]), hashAlg: p[off+8]}
	copy(ref.digest[:], p[off+16:])
	if ref.hashAlg > byte(HashSM3) {
		return nil, dedupRef{}, errs.Detail(ErrDedupCorrupt, "unknown dedup hash algorithm %[1]d | 未知去重哈希算法 %[1]d", ref.hashAlg)
	}
	for _, b := range p[off+9 : off+16] {
		if b != 0 {
			return nil, dedupRef{}, errs.Detail(ErrDedupCorrupt, "dedup reference reserved bytes are non-zero | 去重引用保留字节非零")
		}
	}
	return key, ref, nil
}

// buildAAD returns walID || segmentSeq || recordOffset || header[4:headerLen]. | buildAAD
// 返回 walID || 段序号 || 记录偏移 || 头[4:headerLen]。
func buildAAD(dst []byte, walID [16]byte, seq uint64, off int64, header []byte) []byte {
	need := 16 + 8 + 8 + len(header)
	if cap(dst) < need {
		dst = make([]byte, need)
	} else {
		dst = dst[:need]
	}
	copy(dst, walID[:])
	binary.LittleEndian.PutUint64(dst[16:], seq)
	binary.LittleEndian.PutUint64(dst[24:], uint64(off))
	copy(dst[32:], header)
	return dst
}

// recordHeaderFlags converts caller flags into the on-disk upper bits. | recordHeaderFlags
// 把调用方标志转换为磁盘头部的上半部分。
func recordHeaderFlags(flags uint16) uint16 {
	return (flags & recordUserFlagMask) << recordUserFlagShift
}

// recordVisibleFlags converts on-disk flags back to the caller view. | recordVisibleFlags
// 把磁盘标志转换回调用方视图。
func recordVisibleFlags(flags uint16) uint16 {
	return (flags >> recordUserFlagShift) & recordUserFlagMask
}

// payloadLengthFor returns the plaintext payload length for an unencrypted
// record. | payloadLengthFor 返回未加密记录的明文字节长度。
func payloadLengthFor(size uint32, headerLen int) int {
	return int(size) - headerLen
}

// addSizes returns a+b, reporting overflow. | addSizes 返回 a+b，并报告溢出。
func addSizes(a, b int) (int, bool) {
	if a < 0 || b < 0 || a > math.MaxInt-b {
		return 0, false
	}
	return a + b, true
}
