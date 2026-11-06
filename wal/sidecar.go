package wal

import (
	"encoding/binary"
	"os"
	"sort"

	"github.com/shibingli/ydx/errs"
)

// Sidecar (.idx) layout constants. | 侧车 (.idx) 布局常量。
const (
	sidecarMagic      = "YDXIDX01"
	sidecarVersion    = uint16(1)
	sidecarHeaderSize = uint32(120)
	sidecarTrailer    = 4
	sidecarEntrySize  = 24

	sidecarFlagKeyIndex   = uint16(1 << 0)
	sidecarFlagCheckpoint = uint16(1 << 1)
	sidecarKnownFlags     = sidecarFlagKeyIndex | sidecarFlagCheckpoint

	maxSidecarBytes = int64(formatHardLimit)
)

// Sidecar header offsets. | 侧车头字段偏移。
const (
	idxOffMagic        = 0
	idxOffVersion      = 8
	idxOffFlags        = 10
	idxOffHeaderSize   = 12
	idxOffSeq          = 16
	idxOffBaseLSN      = 24
	idxOffLastLSN      = 32
	idxOffRecordCount  = 40
	idxOffSegmentBytes = 48
	idxOffMinTime      = 56
	idxOffMaxTime      = 64
	idxOffSegmentCRC   = 72
	idxOffSparseCount  = 76
	idxOffKeyCount     = 80
	idxOffDedupRefs    = 88
	idxOffCompressed   = 92
	idxOffWalID        = 96
	idxOffCommitSeq    = 112
)

// sidecar is the decoded .idx file. | sidecar 是解码后的 .idx 文件。
type sidecar struct {
	seq          uint64
	baseLSN      uint64
	lastLSN      uint64
	recordCount  uint64
	segmentBytes uint64
	minTime      int64
	maxTime      int64
	segmentCRC   uint32
	dedupRefs    uint32
	compressed   uint32
	walID        [16]byte
	commitSeq    uint64
	checkpoint   bool
	hasKeyIndex  bool
	sparse       []sparseEntry
	keyIndex     map[string][]uint64
	keyOrder     []string
}

// encodeSidecar encodes one .idx file. | encodeSidecar 编码一个 .idx 文件。
func encodeSidecar(s *sidecar) []byte {
	if s.hasKeyIndex {
		s.keyOrder = s.sortedKeys()
	} else {
		s.keyOrder = nil
	}
	sparseCount := len(s.sparse)
	keyCount := len(s.keyOrder)
	size := int(sidecarHeaderSize) + sparseCount*sidecarEntrySize + sidecarTrailer
	for _, k := range s.keyOrder {
		size += 4 + len(k) + 4 + len(s.keyIndex[k])*8
	}
	buf := make([]byte, int(sidecarHeaderSize), size)
	copy(buf[idxOffMagic:], sidecarMagic)
	binary.LittleEndian.PutUint16(buf[idxOffVersion:], sidecarVersion)
	var flags uint16
	if s.hasKeyIndex {
		flags |= sidecarFlagKeyIndex
	}
	if s.checkpoint {
		flags |= sidecarFlagCheckpoint
	}
	binary.LittleEndian.PutUint16(buf[idxOffFlags:], flags)
	binary.LittleEndian.PutUint32(buf[idxOffHeaderSize:], sidecarHeaderSize)
	binary.LittleEndian.PutUint64(buf[idxOffSeq:], s.seq)
	binary.LittleEndian.PutUint64(buf[idxOffBaseLSN:], s.baseLSN)
	binary.LittleEndian.PutUint64(buf[idxOffLastLSN:], s.lastLSN)
	binary.LittleEndian.PutUint64(buf[idxOffRecordCount:], s.recordCount)
	binary.LittleEndian.PutUint64(buf[idxOffSegmentBytes:], s.segmentBytes)
	binary.LittleEndian.PutUint64(buf[idxOffMinTime:], uint64(s.minTime))
	binary.LittleEndian.PutUint64(buf[idxOffMaxTime:], uint64(s.maxTime))
	binary.LittleEndian.PutUint32(buf[idxOffSegmentCRC:], s.segmentCRC)
	binary.LittleEndian.PutUint32(buf[idxOffSparseCount:], uint32(sparseCount))
	binary.LittleEndian.PutUint64(buf[idxOffKeyCount:], uint64(keyCount))
	binary.LittleEndian.PutUint32(buf[idxOffDedupRefs:], s.dedupRefs)
	binary.LittleEndian.PutUint32(buf[idxOffCompressed:], s.compressed)
	copy(buf[idxOffWalID:], s.walID[:])
	binary.LittleEndian.PutUint64(buf[idxOffCommitSeq:], s.commitSeq)
	for _, sp := range s.sparse {
		var entry [sidecarEntrySize]byte
		binary.LittleEndian.PutUint64(entry[0:], sp.lsn)
		binary.LittleEndian.PutUint64(entry[8:], uint64(sp.offset))
		binary.LittleEndian.PutUint64(entry[16:], uint64(sp.timestamp))
		buf = append(buf, entry[:]...)
	}
	for _, k := range s.keyOrder {
		lsns := s.keyIndex[k]
		var hdr [8]byte
		binary.LittleEndian.PutUint32(hdr[0:], uint32(len(k)))
		binary.LittleEndian.PutUint32(hdr[4:], uint32(len(lsns)))
		buf = append(buf, hdr[:]...)
		buf = append(buf, k...)
		for _, lsn := range lsns {
			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], lsn)
			buf = append(buf, b[:]...)
		}
	}
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], checksum(buf))
	return append(buf, crc[:]...)
}

// decodeSidecar decodes and validates one .idx file. Section sizes are checked
// before any allocation or map construction. | decodeSidecar 解码并校验一个 .idx
// 文件；在任何分配或 map 构建之前校验各段长度。
func decodeSidecar(data []byte) (*sidecar, error) {
	if len(data) < int(sidecarHeaderSize)+sidecarTrailer {
		return nil, errs.Detail(ErrCorrupt, "sidecar is only %[1]d bytes | 侧车仅 %[1]d 字节", len(data))
	}
	if string(data[idxOffMagic:idxOffMagic+8]) != sidecarMagic {
		return nil, errs.Detail(ErrCorrupt, "bad sidecar magic | 侧车 magic 非法")
	}
	if binary.LittleEndian.Uint16(data[idxOffVersion:]) != sidecarVersion ||
		binary.LittleEndian.Uint32(data[idxOffHeaderSize:]) != sidecarHeaderSize {
		return nil, errs.Detail(ErrUnsupported, "unsupported sidecar version/layout | 不支持的侧车版本/布局")
	}
	flags := binary.LittleEndian.Uint16(data[idxOffFlags:])
	if flags&^sidecarKnownFlags != 0 {
		return nil, errs.Detail(ErrUnsupported, "unknown sidecar flags 0x%[1]04x | 未知侧车 flags 0x%[1]04x", flags)
	}
	body := data[:len(data)-sidecarTrailer]
	if got, want := binary.LittleEndian.Uint32(data[len(data)-sidecarTrailer:]), checksum(body); got != want {
		return nil, errs.Detail(ErrCorrupt, "sidecar CRC mismatch | 侧车 CRC 不匹配")
	}
	s := &sidecar{
		seq:          binary.LittleEndian.Uint64(data[idxOffSeq:]),
		baseLSN:      binary.LittleEndian.Uint64(data[idxOffBaseLSN:]),
		lastLSN:      binary.LittleEndian.Uint64(data[idxOffLastLSN:]),
		recordCount:  binary.LittleEndian.Uint64(data[idxOffRecordCount:]),
		segmentBytes: binary.LittleEndian.Uint64(data[idxOffSegmentBytes:]),
		minTime:      int64(binary.LittleEndian.Uint64(data[idxOffMinTime:])),
		maxTime:      int64(binary.LittleEndian.Uint64(data[idxOffMaxTime:])),
		segmentCRC:   binary.LittleEndian.Uint32(data[idxOffSegmentCRC:]),
		dedupRefs:    binary.LittleEndian.Uint32(data[idxOffDedupRefs:]),
		compressed:   binary.LittleEndian.Uint32(data[idxOffCompressed:]),
		commitSeq:    binary.LittleEndian.Uint64(data[idxOffCommitSeq:]),
		checkpoint:   flags&sidecarFlagCheckpoint != 0,
		hasKeyIndex:  flags&sidecarFlagKeyIndex != 0,
	}
	copy(s.walID[:], data[idxOffWalID:])
	if s.seq == 0 || s.baseLSN == 0 || s.segmentBytes < uint64(segmentHeaderSize) || s.walID == ([16]byte{}) {
		return nil, errs.Detail(ErrCorrupt, "sidecar has invalid seq/baseLSN/segmentBytes/walID | 侧车的 seq/baseLSN/segmentBytes/walID 非法")
	}
	if s.lastLSN < s.baseLSN-1 {
		return nil, errs.Detail(ErrCorrupt, "sidecar lastLSN %[1]d is below baseLSN-1 | 侧车 lastLSN %[1]d 小于 baseLSN-1", s.lastLSN)
	}
	sparseCount := int(binary.LittleEndian.Uint32(data[idxOffSparseCount:]))
	keyCount := binary.LittleEndian.Uint64(data[idxOffKeyCount:])
	off := int(sidecarHeaderSize)
	if sparseCount < 0 || sparseCount > (len(body)-off)/sidecarEntrySize {
		return nil, errs.Detail(ErrCorrupt, "sidecar sparse count %[1]d exceeds the file | 侧车稀疏计数 %[1]d 超出文件范围", sparseCount)
	}
	if keyCount > uint64(len(body)-off)/8 {
		return nil, errs.Detail(ErrCorrupt, "sidecar key count %[1]d exceeds the file | 侧车 Key 计数 %[1]d 超出文件范围", keyCount)
	}
	s.sparse = make([]sparseEntry, 0, sparseCount)
	var prevOffset int64 = -1
	var prevLSN uint64
	for i := 0; i < sparseCount; i++ {
		p := body[off : off+sidecarEntrySize]
		off += sidecarEntrySize
		sp := sparseEntry{
			lsn:       binary.LittleEndian.Uint64(p[0:]),
			offset:    int64(binary.LittleEndian.Uint64(p[8:])),
			timestamp: int64(binary.LittleEndian.Uint64(p[16:])),
		}
		if sp.offset < int64(segmentHeaderSize) || sp.offset >= int64(s.segmentBytes) {
			return nil, errs.Detail(ErrCorrupt, "sparse offset %[1]d is outside the segment | 稀疏偏移 %[1]d 超出分段范围", sp.offset)
		}
		if sp.offset <= prevOffset || (i > 0 && sp.lsn <= prevLSN) {
			return nil, errs.Detail(ErrCorrupt, "sparse index is not strictly increasing | 稀疏索引未严格递增")
		}
		if len(s.sparse) == 0 && sp.lsn != s.baseLSN {
			return nil, errs.Detail(ErrCorrupt, "first sparse LSN %[1]d is not baseLSN %[2]d | 首个稀疏 LSN %[1]d 不是 baseLSN %[2]d", sp.lsn, s.baseLSN)
		}
		if sp.lsn < s.baseLSN || sp.lsn > s.lastLSN {
			return nil, errs.Detail(ErrCorrupt, "sparse LSN %[1]d is outside [baseLSN,lastLSN] | 稀疏 LSN %[1]d 超出 [baseLSN,lastLSN]", sp.lsn)
		}
		prevOffset, prevLSN = sp.offset, sp.lsn
		s.sparse = append(s.sparse, sp)
	}
	if s.hasKeyIndex {
		s.keyIndex = make(map[string][]uint64, int(keyCount))
		var prevKey string
		for i := uint64(0); i < keyCount; i++ {
			if off+8 > len(body) {
				return nil, errs.Detail(ErrCorrupt, "truncated sidecar key header | 侧车 Key 头被截断")
			}
			keyLen := int(binary.LittleEndian.Uint32(body[off:]))
			count := int(binary.LittleEndian.Uint32(body[off+4:]))
			off += 8
			if keyLen < 0 || count < 0 || keyLen > len(body)-off || count > (len(body)-off-keyLen)/8 {
				return nil, errs.Detail(ErrCorrupt, "sidecar key entry exceeds the file | 侧车 Key 条目超出文件范围")
			}
			key := string(body[off : off+keyLen])
			off += keyLen
			if i > 0 && key <= prevKey {
				return nil, errs.Detail(ErrCorrupt, "sidecar keys are not strictly sorted | 侧车 Key 未严格排序")
			}
			prevKey = key
			lsns := make([]uint64, count)
			var prev uint64
			for j := 0; j < count; j++ {
				lsn := binary.LittleEndian.Uint64(body[off:])
				off += 8
				if lsn < s.baseLSN || lsn > s.lastLSN || (j > 0 && lsn <= prev) {
					return nil, errs.Detail(ErrCorrupt, "sidecar key LSN is invalid | 侧车 Key LSN 非法")
				}
				prev = lsn
				lsns[j] = lsn
			}
			s.keyIndex[key] = lsns
			s.keyOrder = append(s.keyOrder, key)
		}
	}
	if off != len(body) {
		return nil, errs.Detail(ErrCorrupt, "sidecar has %[1]d trailing bytes | 侧车有 %[1]d 个多余字节", len(body)-off)
	}
	return s, nil
}

// loadSidecar reads and decodes one .idx file. | loadSidecar 读取并解码一个 .idx 文件。
func loadSidecar(path string) (*sidecar, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSidecarBytes {
		return nil, errs.Detail(ErrTooLarge, "sidecar %[1]s has %[2]d bytes | 侧车 %[1]s 有 %[2]d 字节", path, info.Size())
	}
	data := make([]byte, info.Size())
	if err := readAtFull(f, data, 0); err != nil {
		return nil, err
	}
	return decodeSidecar(data)
}

// sortedKeys returns the key order used by encodeSidecar. | sortedKeys 返回 encodeSidecar 使用的键顺序。
func (s *sidecar) sortedKeys() []string {
	keys := make([]string, 0, len(s.keyIndex))
	for k := range s.keyIndex {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
