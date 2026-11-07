package wal

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Segment format constants. | 分段格式常量。
const (
	segmentMagic      = "YDXWAL01"
	segmentVersion    = uint16(1)
	segmentHeaderSize = uint32(64)
	segmentCRCOffset  = 60
)

// Segment header offsets. | 分段头字段偏移。
const (
	segOffMagic       = 0
	segOffVersion     = 8
	segOffFlags       = 10
	segOffHeaderSize  = 12
	segOffSeq         = 16
	segOffBaseLSN     = 24
	segOffCreatedNano = 32
	segOffWalID       = 40
	segOffReserved    = 56
	segOffCRC         = 60
)

// segmentState is the lifecycle of a segment. | segmentState 是分段的生命周期状态。
type segmentState uint32

const (
	// segmentActive accepts new records. | segmentActive 可接受新记录。
	segmentActive segmentState = iota
	// segmentSealing is immutable but its full sidecar is being written. | segmentSealing 已不可写但完整侧车仍在写入。
	segmentSealing
	// segmentSealed is immutable and has a complete sidecar (or was recovered). | segmentSealed 已不可变且具有完整侧车（或已恢复）。
	segmentSealed
)

// segmentHeader is the decoded 64-byte segment header. | segmentHeader 是解码后的 64 字节分段头。
type segmentHeader struct {
	seq         uint64
	baseLSN     uint64
	createdNano int64
	walID       [16]byte
	flags       uint16
}

// encodeSegmentHeader fills a 64-byte header. | encodeSegmentHeader 填充 64 字节分段头。
func encodeSegmentHeader(dst []byte, h segmentHeader) {
	for i := range dst[:segmentHeaderSize] {
		dst[i] = 0
	}
	copy(dst[segOffMagic:], segmentMagic)
	binary.LittleEndian.PutUint16(dst[segOffVersion:], segmentVersion)
	binary.LittleEndian.PutUint16(dst[segOffFlags:], h.flags)
	binary.LittleEndian.PutUint32(dst[segOffHeaderSize:], segmentHeaderSize)
	binary.LittleEndian.PutUint64(dst[segOffSeq:], h.seq)
	binary.LittleEndian.PutUint64(dst[segOffBaseLSN:], h.baseLSN)
	binary.LittleEndian.PutUint64(dst[segOffCreatedNano:], uint64(h.createdNano))
	copy(dst[segOffWalID:], h.walID[:])
	binary.LittleEndian.PutUint32(dst[segOffCRC:], checksum(dst[:segmentCRCOffset]))
}

// decodeSegmentHeader decodes and validates a 64-byte header. | decodeSegmentHeader
// 解码并校验 64 字节分段头。
func decodeSegmentHeader(p []byte) (segmentHeader, error) {
	if len(p) < int(segmentHeaderSize) {
		return segmentHeader{}, errs.Detail(ErrCorrupt, "segment header has %[1]d bytes | 分段头仅 %[1]d 字节", len(p))
	}
	if string(p[segOffMagic:segOffMagic+8]) != segmentMagic {
		return segmentHeader{}, errs.Detail(ErrCorrupt, "bad segment magic | 分段 magic 非法")
	}
	version := binary.LittleEndian.Uint16(p[segOffVersion:])
	headerSize := binary.LittleEndian.Uint32(p[segOffHeaderSize:])
	if version != segmentVersion || headerSize != segmentHeaderSize {
		return segmentHeader{}, errs.Detail(ErrUnsupported, "segment version %[1]d header %[2]d | 分段版本 %[1]d 头长度 %[2]d",
			version, headerSize)
	}
	if got, want := binary.LittleEndian.Uint32(p[segOffCRC:]), checksum(p[:segmentCRCOffset]); got != want {
		return segmentHeader{}, errs.Detail(ErrCorrupt, "segment header CRC mismatch | 分段头 CRC 不匹配")
	}
	var h segmentHeader
	h.flags = binary.LittleEndian.Uint16(p[segOffFlags:])
	h.seq = binary.LittleEndian.Uint64(p[segOffSeq:])
	h.baseLSN = binary.LittleEndian.Uint64(p[segOffBaseLSN:])
	h.createdNano = int64(binary.LittleEndian.Uint64(p[segOffCreatedNano:]))
	copy(h.walID[:], p[segOffWalID:])
	if h.seq == 0 || h.baseLSN == 0 {
		return segmentHeader{}, errs.Detail(ErrCorrupt, "segment seq/baseLSN is zero | 分段 seq/baseLSN 为零")
	}
	if h.walID == ([16]byte{}) {
		return segmentHeader{}, errs.Detail(ErrCorrupt, "segment walID is zero | 分段 walID 为零")
	}
	return h, nil
}

// sparseEntry is one sparse-index point. | sparseEntry 是一个稀疏索引点。
type sparseEntry struct {
	lsn       uint64
	offset    int64
	timestamp int64
}

// segment is one .wal file plus its in-memory summary and index. | segment 是一个 .wal 文件及其内存摘要与索引。
type segment struct {
	f        *os.File
	keyIndex map[string][]uint64
	path     string
	idxPath  string
	bakPath  string

	sparse      []sparseEntry
	offsets     []uint64
	seq         uint64
	baseLSN     uint64
	lastLSN     uint64
	recordCount uint64
	size        int64
	minTime     int64
	maxTime     int64
	commitSeq   uint64
	createdNano int64
	refs        atomic.Int64
	indexGen    uint64

	metaMu sync.RWMutex

	checkpointMu sync.Mutex
	// indexMu serializes lazy full-index rebuilds for a sealed segment. |
	// indexMu 串行化封段的按需完整索引重建。
	indexMu    sync.Mutex
	crc        uint32
	idxCRC     uint32
	dedupRefs  uint32
	compressed uint32
	state      atomic.Uint32
	validated  atomic.Bool

	walID [16]byte

	missing          bool
	retired          bool
	sparseLoaded     bool
	sparseComplete   bool
	denseLoaded      bool
	keyIndexLoaded   bool
	keyIndexComplete bool
	keyIndexOverflow bool
}

// newSegmentSummary builds a segment with no loaded index. | newSegmentSummary 构建一个未加载索引的分段摘要。
func newSegmentSummary(seq, baseLSN, lastLSN uint64, size int64, walID [16]byte, dir string) *segment {
	base := joinPathName(dir, zeroPad20(seq))
	return &segment{
		seq:     seq,
		baseLSN: baseLSN,
		lastLSN: lastLSN,
		size:    size,
		walID:   walID,
		path:    base + ".wal",
		idxPath: base + ".idx",
		bakPath: base + ".bak",
	}
}

// zeroPad20 formats a uint64 as exactly 20 decimal digits. | zeroPad20 把 uint64
// 格式化为恰好 20 位十进制数字。
func zeroPad20(v uint64) string {
	var b [20]byte
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = '0' + byte(v%10)
		v /= 10
	}
	return string(b[:])
}

// joinPathName joins dir and name without cleaning the path. | joinPathName 不经
// 路径清理地拼接目录与文件名。
func joinPathName(dir, name string) string {
	if dir == "" {
		return name
	}
	if os.IsPathSeparator(dir[len(dir)-1]) {
		return dir + name
	}
	return dir + string(filepath.Separator) + name
}

// segmentPath returns <seq>.wal. | segmentPath 返回 <seq>.wal。
func segmentPath(dir string, seq uint64) string {
	return joinPathName(dir, zeroPad20(seq)) + ".wal"
}

// sidecarPath returns <seq>.idx. | sidecarPath 返回 <seq>.idx。
func sidecarPath(dir string, seq uint64) string {
	return joinPathName(dir, zeroPad20(seq)) + ".idx"
}

// backupPath returns <seq>.bak. | backupPath 返回 <seq>.bak。
func backupPath(dir string, seq uint64) string {
	return joinPathName(dir, zeroPad20(seq)) + ".bak"
}

// createSegmentFile creates an O_EXCL segment and writes its header. | createSegmentFile
// 以 O_EXCL 创建分段并写入段头。
func createSegmentFile(dir string, seq, baseLSN uint64, walID [16]byte, mode os.FileMode, preallocate int64) (*segment, error) {
	s := newSegmentSummary(seq, baseLSN, baseLSN-1, int64(segmentHeaderSize), walID, dir)
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, mode)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrStorage, "create segment %s | 创建分段 %s 失败", s.path, s.path)
	}
	h := segmentHeader{seq: seq, baseLSN: baseLSN, createdNano: time.Now().UnixNano(), walID: walID}
	var hdr [segmentHeaderSize]byte
	encodeSegmentHeader(hdr[:], h)
	if err := writeFullAt(f, hdr[:], 0); err != nil {
		_ = f.Close()
		_ = os.Remove(s.path)
		return nil, errs.WrapDetail(err, ErrStorage, "write segment header %s | 写入分段头 %s 失败", s.path, s.path)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(s.path)
		return nil, errs.WrapDetail(err, ErrStorage, "sync segment header %s | 同步分段头 %s 失败", s.path, s.path)
	}
	if err := syncDir(dir); err != nil {
		_ = f.Close()
		_ = os.Remove(s.path)
		return nil, errs.WrapDetail(err, ErrStorage, "sync segment directory %s | 同步分段目录 %s 失败", dir, dir)
	}
	if preallocate > 0 {
		_ = preallocateFile(f, int64(segmentHeaderSize), preallocate)
	}
	s.f = f
	s.createdNano = h.createdNano
	s.validated.Store(true)
	// A freshly created segment has empty, hence complete, indexes. | 新建分段
	// 的索引为空，因此是完整的。
	s.sparseComplete = true
	s.keyIndexComplete = true
	s.state.Store(uint32(segmentActive))
	return s, nil
}

// openSegmentFile opens an existing segment for writing. | openSegmentFile 打开已存在分段用于写入。
func openSegmentFile(dir string, seq uint64, walID [16]byte, mode os.FileMode) (*segment, segmentHeader, error) {
	path := segmentPath(dir, seq)
	f, err := os.OpenFile(path, os.O_RDWR, mode)
	if err != nil {
		return nil, segmentHeader{}, errs.WrapDetail(err, ErrStorage, "open segment %s | 打开分段 %s 失败", path, path)
	}
	var hdr [segmentHeaderSize]byte
	if err := readFullAt(f, hdr[:], 0); err != nil {
		_ = f.Close()
		return nil, segmentHeader{}, errs.WrapDetail(err, ErrStorage, "read segment header %s | 读取分段头 %s 失败", path, path)
	}
	h, err := decodeSegmentHeader(hdr[:])
	if err != nil {
		_ = f.Close()
		return nil, segmentHeader{}, err
	}
	if h.seq != seq {
		_ = f.Close()
		return nil, segmentHeader{}, errs.Detail(ErrCorrupt, "segment file %[1]s has seq %[2]d | 分段文件 %[1]s 的 seq 为 %[2]d", path, h.seq)
	}
	if h.walID != walID {
		_ = f.Close()
		return nil, segmentHeader{}, errs.Detail(ErrCorrupt, "segment %s walID does not match META | 分段 %s 的 walID 与 META 不一致", path, path)
	}
	size, err := fileSize(f)
	if err != nil {
		_ = f.Close()
		return nil, segmentHeader{}, errs.Wrap(err, ErrStorage)
	}
	s := newSegmentSummary(seq, h.baseLSN, h.baseLSN-1, size, walID, dir)
	s.f = f
	s.createdNano = h.createdNano
	s.validated.Store(true)
	return s, h, nil
}

// validateSegmentIdentity checks a lazily opened segment's header. MANIFEST
// fast-path opens defer this check to the first read; a renamed or replaced
// file must not pass silently. | validateSegmentIdentity 校验延迟打开分段的
// 段头；MANIFEST 快速路径把该检查推迟到首次读取，重命名或替换的文件不得静默
// 通过。
func validateSegmentIdentity(seg *segment, f *os.File) error {
	if seg.validated.Load() {
		return nil
	}
	var hdr [segmentHeaderSize]byte
	if err := readFullAt(f, hdr[:], 0); err != nil {
		return wrapStorage("read segment header", err)
	}
	h, err := decodeSegmentHeader(hdr[:])
	if err != nil {
		return err
	}
	if h.seq != seg.seq || h.walID != seg.walID {
		return errs.Detail(ErrCorrupt, "segment %d header identity mismatch | 分段 %d 段头身份不匹配", seg.seq, seg.seq)
	}
	seg.validated.Store(true)
	return nil
}

// readSegmentHeaderFile reads a segment header without keeping the file open. | readSegmentHeaderFile
// 读取分段头而不保留文件句柄。
func readSegmentHeaderFile(path string) (segmentHeader, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return segmentHeader{}, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return segmentHeader{}, 0, err
	}
	var hdr [segmentHeaderSize]byte
	if err := readFullAt(f, hdr[:], 0); err != nil {
		return segmentHeader{}, info.Size(), err
	}
	h, err := decodeSegmentHeader(hdr[:])
	if err != nil {
		return segmentHeader{}, info.Size(), err
	}
	return h, info.Size(), nil
}

// setState atomically changes the segment lifecycle state. | setState 原子改变分段生命周期状态。
func (s *segment) setState(st segmentState) { s.state.Store(uint32(st)) }

// currentState returns the lifecycle state. | currentState 返回生命周期状态。
func (s *segment) currentState() segmentState { return segmentState(s.state.Load()) }

// retain increments the segment reference count. | retain 增加分段引用计数。
func (s *segment) retain() { s.refs.Add(1) }

// release decrements the reference count and wakes the cleaner at zero when a
// deletion is actually pending. Ordinary read leases never touch the cleaner
// channel. | release 减少引用计数，仅在确实有删除待处理时才唤醒 cleaner；普通
// 读租约不会触碰 cleaner 通道。
func (s *segment) release(w *WAL) {
	if s.refs.Add(-1) == 0 {
		w.notifyCleanerIfPending()
	}
}

// notifyCleanerIfPending wakes the cleaner only while it has queued or active
// work. | notifyCleanerIfPending 仅在 cleaner 有排队或在途工作时唤醒它。
func (w *WAL) notifyCleanerIfPending() {
	w.cleanerMu.Lock()
	pending := len(w.cleanerQ) > 0 || w.cleanerBusy
	w.cleanerMu.Unlock()
	if pending {
		w.notifyCleaner()
	}
}

// cloneSummary returns a copy of the segment summary without rebuilding its
// path strings. | cloneSummary 复制分段摘要，不重建路径字符串。
func (s *segment) cloneSummary() *segment {
	s.metaMu.RLock()
	c := &segment{
		seq: s.seq, baseLSN: s.baseLSN, lastLSN: s.lastLSN, recordCount: s.recordCount,
		size: s.size, minTime: s.minTime, maxTime: s.maxTime, crc: s.crc,
		idxCRC: s.idxCRC, commitSeq: s.commitSeq, createdNano: s.createdNano, walID: s.walID,
		missing: s.missing, retired: s.retired, dedupRefs: s.dedupRefs, compressed: s.compressed,
		path: s.path, idxPath: s.idxPath, bakPath: s.bakPath,
	}
	s.metaMu.RUnlock()
	c.state.Store(s.state.Load())
	c.validated.Store(s.validated.Load())
	return c
}

// summarySnapshot returns a copy of the mutable summary fields. | summarySnapshot
// 返回可变摘要字段的副本。
func (s *segment) summarySnapshot() (lastLSN, recordCount uint64, size int64, minTime, maxTime int64, crc, idxCRC uint32, commitSeq uint64) {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return s.lastLSN, s.recordCount, s.size, s.minTime, s.maxTime, s.crc, s.idxCRC, s.commitSeq
}

// addSparseLocked appends a sparse entry when the interval is reached. | addSparseLocked
// 在达到间隔时追加一个稀疏索引条目。
func (s *segment) addSparseLocked(lsn uint64, offset int64, timestamp int64, intervalBytes int, intervalRecords int) {
	if len(s.sparse) == 0 {
		s.sparse = append(s.sparse, sparseEntry{lsn: lsn, offset: offset, timestamp: timestamp})
		return
	}
	last := s.sparse[len(s.sparse)-1]
	if offset-last.offset >= int64(intervalBytes) || lsn-last.lsn >= uint64(intervalRecords) {
		s.sparse = append(s.sparse, sparseEntry{lsn: lsn, offset: offset, timestamp: timestamp})
	}
}

// addKeyLocked records one key occurrence. | addKeyLocked 记录一次 Key 出现。
func (s *segment) addKeyLocked(key []byte, lsn uint64, maxEntries, maxKeyBytes int, overflow *bool) {
	if s.keyIndex == nil {
		s.keyIndex = make(map[string][]uint64)
	}
	if len(key) > maxKeyBytes || len(s.keyIndex) >= maxEntries {
		s.keyIndexOverflow = true
		if overflow != nil {
			*overflow = true
		}
		return
	}
	k := string(key)
	s.keyIndex[k] = append(s.keyIndex[k], lsn)
}

// closeWriter closes the writer-side file handle. | closeWriter 关闭写侧文件句柄。
func (s *segment) closeWriter() {
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
}

// setSummary replaces the summary fields. | setSummary 替换摘要字段。
func (s *segment) setSummary(baseLSN, lastLSN, recordCount uint64, size int64, minTime, maxTime int64, crc, idxCRC uint32, commitSeq uint64) {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	s.baseLSN = baseLSN
	s.lastLSN = lastLSN
	s.recordCount = recordCount
	s.size = size
	s.minTime = minTime
	s.maxTime = maxTime
	s.crc = crc
	s.idxCRC = idxCRC
	s.commitSeq = commitSeq
}
