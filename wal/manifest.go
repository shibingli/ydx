package wal

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// Manifest format constants. | MANIFEST 格式常量。
const (
	manifestMagic      = "YDXMAN01"
	manifestVersion    = uint16(1)
	manifestHeaderSize = uint32(120)
	manifestCRCOffset  = 116

	manifestKindSegment    = byte(1)
	manifestKindRetire     = byte(2)
	manifestKindCheckpoint = byte(3)
	manifestKindTruncate   = byte(4)
	manifestKindCreated    = byte(5)
)

// Manifest record offsets. | MANIFEST 记录字段偏移。
const (
	mfOffMagic        = 0
	mfOffVersion      = 8
	mfOffKind         = 10
	mfOffFlags        = 11
	mfOffHeaderSize   = 12
	mfOffSeq          = 16
	mfOffBaseLSN      = 24
	mfOffLastLSN      = 32
	mfOffSegmentBytes = 40
	mfOffRecordCount  = 48
	mfOffMinTime      = 56
	mfOffMaxTime      = 64
	mfOffSegmentCRC   = 72
	mfOffIdxCRC       = 76
	mfOffWalID        = 80
	mfOffCreatedNano  = 96
	mfOffCommitSeq    = 104
	mfOffReserved     = 112
	mfOffCRC          = 116
)

// manifestRecord is one 120-byte manifest entry. | manifestRecord 是一条 120 字节 MANIFEST 记录。
type manifestRecord struct {
	kind         byte
	seq          uint64
	baseLSN      uint64
	lastLSN      uint64
	segmentBytes uint64
	recordCount  uint64
	minTime      int64
	maxTime      int64
	segmentCRC   uint32
	idxCRC       uint32
	walID        [16]byte
	createdNano  int64
	commitSeq    uint64
}

// encodeManifestRecord fills one 120-byte record. | encodeManifestRecord 填充一条 120 字节记录。
func encodeManifestRecord(dst []byte, r manifestRecord) {
	for i := range dst[:manifestHeaderSize] {
		dst[i] = 0
	}
	copy(dst[mfOffMagic:], manifestMagic)
	binary.LittleEndian.PutUint16(dst[mfOffVersion:], manifestVersion)
	dst[mfOffKind] = r.kind
	binary.LittleEndian.PutUint32(dst[mfOffHeaderSize:], manifestHeaderSize)
	binary.LittleEndian.PutUint64(dst[mfOffSeq:], r.seq)
	binary.LittleEndian.PutUint64(dst[mfOffBaseLSN:], r.baseLSN)
	binary.LittleEndian.PutUint64(dst[mfOffLastLSN:], r.lastLSN)
	binary.LittleEndian.PutUint64(dst[mfOffSegmentBytes:], r.segmentBytes)
	binary.LittleEndian.PutUint64(dst[mfOffRecordCount:], r.recordCount)
	binary.LittleEndian.PutUint64(dst[mfOffMinTime:], uint64(r.minTime))
	binary.LittleEndian.PutUint64(dst[mfOffMaxTime:], uint64(r.maxTime))
	binary.LittleEndian.PutUint32(dst[mfOffSegmentCRC:], r.segmentCRC)
	binary.LittleEndian.PutUint32(dst[mfOffIdxCRC:], r.idxCRC)
	copy(dst[mfOffWalID:], r.walID[:])
	binary.LittleEndian.PutUint64(dst[mfOffCreatedNano:], uint64(r.createdNano))
	binary.LittleEndian.PutUint64(dst[mfOffCommitSeq:], r.commitSeq)
	binary.LittleEndian.PutUint32(dst[mfOffCRC:], checksum(dst[:manifestCRCOffset]))
}

// decodeManifestRecord decodes and validates one record. | decodeManifestRecord 解码并校验一条记录。
func decodeManifestRecord(p []byte) (manifestRecord, error) {
	if len(p) < int(manifestHeaderSize) {
		return manifestRecord{}, errs.Detail(ErrCorrupt, "manifest record has %[1]d bytes | MANIFEST 记录仅 %[1]d 字节", len(p))
	}
	if string(p[mfOffMagic:mfOffMagic+8]) != manifestMagic {
		return manifestRecord{}, errs.Detail(ErrCorrupt, "bad manifest magic | MANIFEST magic 非法")
	}
	if binary.LittleEndian.Uint16(p[mfOffVersion:]) != manifestVersion ||
		binary.LittleEndian.Uint32(p[mfOffHeaderSize:]) != manifestHeaderSize {
		return manifestRecord{}, errs.Detail(ErrUnsupported, "unsupported manifest version/layout | 不支持的 MANIFEST 版本/布局")
	}
	if got, want := binary.LittleEndian.Uint32(p[mfOffCRC:]), checksum(p[:manifestCRCOffset]); got != want {
		return manifestRecord{}, errs.Detail(ErrCorrupt, "manifest record CRC mismatch | MANIFEST 记录 CRC 不匹配")
	}
	r := manifestRecord{
		kind:         p[mfOffKind],
		seq:          binary.LittleEndian.Uint64(p[mfOffSeq:]),
		baseLSN:      binary.LittleEndian.Uint64(p[mfOffBaseLSN:]),
		lastLSN:      binary.LittleEndian.Uint64(p[mfOffLastLSN:]),
		segmentBytes: binary.LittleEndian.Uint64(p[mfOffSegmentBytes:]),
		recordCount:  binary.LittleEndian.Uint64(p[mfOffRecordCount:]),
		minTime:      int64(binary.LittleEndian.Uint64(p[mfOffMinTime:])),
		maxTime:      int64(binary.LittleEndian.Uint64(p[mfOffMaxTime:])),
		segmentCRC:   binary.LittleEndian.Uint32(p[mfOffSegmentCRC:]),
		idxCRC:       binary.LittleEndian.Uint32(p[mfOffIdxCRC:]),
		createdNano:  int64(binary.LittleEndian.Uint64(p[mfOffCreatedNano:])),
		commitSeq:    binary.LittleEndian.Uint64(p[mfOffCommitSeq:]),
	}
	copy(r.walID[:], p[mfOffWalID:])
	switch r.kind {
	case manifestKindSegment, manifestKindRetire, manifestKindCheckpoint, manifestKindTruncate, manifestKindCreated:
	default:
		return manifestRecord{}, errs.Detail(ErrCorrupt, "unknown manifest kind %[1]d | 未知 MANIFEST 类型 %[1]d", r.kind)
	}
	if r.walID == ([16]byte{}) {
		return manifestRecord{}, errs.Detail(ErrCorrupt, "manifest walID is zero | MANIFEST walID 为零")
	}
	if r.kind != manifestKindTruncate && r.seq == 0 {
		return manifestRecord{}, errs.Detail(ErrCorrupt, "manifest segment record has seq 0 | MANIFEST 分段记录 seq 为 0")
	}
	if r.kind == manifestKindTruncate && r.baseLSN == 0 {
		return manifestRecord{}, errs.Detail(ErrCorrupt, "manifest truncate watermark has baseLSN 0 | MANIFEST 截断水位 baseLSN 为 0")
	}
	return r, nil
}

// manifestData is the in-memory segment directory built from the manifest. | manifestData
// 是从 MANIFEST 构建的内存段目录。
type manifestData struct {
	segments map[uint64]*segment
	retired  map[uint64]bool
	// retireFloor is the highest retired sequence. Retirement is prefix
	// monotonic (truncation/retention always removes the oldest segments), so
	// compaction may keep only this one kind=2 record and replay must treat
	// every sequence at or below it as retired. Without this floor, a compacted
	// shard would resurrect older segments whose files were already deleted. |
	// retireFloor 是最高退休序号。退休按前缀单调（截断/保留总是从最旧段开始），
	// 因此压缩可以只保留这一条 kind=2 记录，回放必须把所有小于等于它的序号都
	// 视为退休；否则压缩后的分片会让文件已删除的旧段复活。
	retireFloor   uint64
	maxSeq        uint64
	maxCreatedSeq uint64
	firstLSN      uint64
	commitSeq     uint64
	walID         [16]byte
	walIDSet      bool
}

// retired reports whether seq was retired, including the compacted floor. |
// retired 返回 seq 是否已退休，包含压缩后的水位。
func (d *manifestData) retiredAt(seq uint64) bool {
	return seq <= d.retireFloor || d.retired[seq]
}

// retiredSet is the recovery view of retirement: an explicit set plus the
// prefix-monotonic floor. | retiredSet 是恢复侧的退休视图：显式集合加上
// 前缀单调水位。
type retiredSet struct {
	m     map[uint64]bool
	floor uint64
}

// newRetiredSet returns an empty retirement set. | newRetiredSet 返回空退休集合。
func newRetiredSet() *retiredSet {
	return &retiredSet{m: make(map[uint64]bool)}
}

// has reports whether seq is retired. | has 返回 seq 是否已退休。
func (r *retiredSet) has(seq uint64) bool {
	if r == nil {
		return false
	}
	return seq <= r.floor || r.m[seq]
}

// mark records one retired sequence, advancing the floor when possible. | mark
// 记录一个退休序号，并在可能时推进水位。
func (r *retiredSet) mark(seq uint64) {
	if r == nil {
		return
	}
	if r.m == nil {
		r.m = make(map[uint64]bool)
	}
	r.m[seq] = true
	if seq > r.floor {
		r.floor = seq
	}
}

// union merges another retirement set. | union 合并另一个退休集合。
func (r *retiredSet) union(other *retiredSet) {
	if r == nil || other == nil {
		return
	}
	if other.floor > r.floor {
		r.floor = other.floor
	}
	for seq := range other.m {
		r.mark(seq)
	}
}

// seqs returns explicit sequences at or above the floor, sorted ascending. |
// seqs 返回水位及以上的显式序号（升序）。
func (r *retiredSet) seqs() []uint64 {
	if r == nil {
		return nil
	}
	out := make([]uint64, 0, len(r.m))
	for seq := range r.m {
		if seq > r.floor {
			out = append(out, seq)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// newManifestData returns empty data. | newManifestData 返回空数据。
func newManifestData() manifestData {
	return manifestData{segments: make(map[uint64]*segment), retired: make(map[uint64]bool)}
}

// apply merges one record into the in-memory directory. | apply 把一条记录合并进内存目录。
func (d *manifestData) apply(r manifestRecord, dir string) error {
	if r.walID != ([16]byte{}) {
		if !d.walIDSet {
			d.walID = r.walID
			d.walIDSet = true
		} else if d.walID != r.walID {
			return errs.Detail(ErrCorrupt, "manifest walID changed | MANIFEST walID 改变")
		}
	}
	if r.seq > d.maxSeq {
		d.maxSeq = r.seq
	}
	switch r.kind {
	case manifestKindTruncate:
		if r.baseLSN > d.firstLSN {
			d.firstLSN = r.baseLSN
		}
		if r.commitSeq > d.commitSeq {
			d.commitSeq = r.commitSeq
		}
		return nil
	case manifestKindRetire:
		d.retired[r.seq] = true
		if r.seq > d.retireFloor {
			d.retireFloor = r.seq
		}
		return nil
	case manifestKindCreated:
		if r.seq > d.maxCreatedSeq {
			d.maxCreatedSeq = r.seq
		}
		if _, ok := d.segments[r.seq]; !ok {
			s := newSegmentSummary(r.seq, r.baseLSN, r.baseLSN-1, int64(segmentHeaderSize), r.walID, dir)
			s.createdNano = r.createdNano
			d.segments[r.seq] = s
		}
		return nil
	case manifestKindSegment, manifestKindCheckpoint:
		if r.seq > d.maxCreatedSeq {
			d.maxCreatedSeq = r.seq
		}
		s, ok := d.segments[r.seq]
		if !ok {
			s = newSegmentSummary(r.seq, r.baseLSN, r.baseLSN-1, int64(r.segmentBytes), r.walID, dir)
			d.segments[r.seq] = s
		}
		// A stale checkpoint must never regress a later full description. | 陈旧检查点不得回退更晚的完整描述。
		if r.segmentBytes < uint64(s.size) || r.lastLSN < s.lastLSN || r.commitSeq < s.commitSeq {
			return nil
		}
		s.metaMu.Lock()
		s.baseLSN = r.baseLSN
		s.lastLSN = r.lastLSN
		s.recordCount = r.recordCount
		s.size = int64(r.segmentBytes)
		s.minTime = r.minTime
		s.maxTime = r.maxTime
		s.crc = r.segmentCRC
		s.idxCRC = r.idxCRC
		s.commitSeq = r.commitSeq
		s.createdNano = r.createdNano
		s.metaMu.Unlock()
		if r.kind == manifestKindSegment {
			s.setState(segmentSealed)
		}
		if r.commitSeq > d.commitSeq {
			d.commitSeq = r.commitSeq
		}
	}
	return nil
}

// manifestShardName returns %08d.mf. | manifestShardName 返回 %08d.mf。
func manifestShardName(index int) string { return fmt.Sprintf("%08d.mf", index) }

// parseManifestShardIndex parses an 8-digit .mf shard name without fmt. |
// parseManifestShardIndex 不经过 fmt 解析 8 位数字的 .mf 分片名。
func parseManifestShardIndex(name string) (int, bool) {
	if len(name) != 11 || name[8:] != ".mf" {
		return 0, false
	}
	idx := 0
	for i := 0; i < 8; i++ {
		c := name[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		idx = idx*10 + int(c-'0')
	}
	return idx, true
}

// manifest is the append-only sharded segment directory. | manifest 是只追加的分片段目录。
type manifest struct {
	// poisoned records an unrecoverable MANIFEST sync failure. Appends stop and
	// Close never compacts a poisoned manifest. | poisoned 记录不可恢复的
	// MANIFEST 同步失败；其后停止追加，Close 不再压缩。
	poisoned error

	file         *os.File
	dir          string
	total        []int
	data         manifestData
	shardRecords int
	compactRatio float64
	current      int
	offset       int64
	count        int

	summaryMu sync.RWMutex

	appendMu sync.Mutex
	fileMode os.FileMode

	enabled bool
	// stale records whether any retire/checkpoint/truncate record exists, which
	// is what makes a Close-time compaction worth its I/O. | stale 表示是否存在
	// 退休/检查点/截断记录，即 Close 时压缩是否值得 I/O。
	stale bool
}

// openManifest loads all shards. A missing or empty manifest is not an error;
// the caller falls back to a directory scan and may rebuild it. | openManifest
// 加载全部 shard；MANIFEST 缺失或为空不是错误，调用方回退目录扫描并可重建。
func openManifest(dir string, enabled bool, shardRecords int, ratio float64, fileMode os.FileMode, readOnly bool) (*manifest, bool, bool, error) {
	m := &manifest{
		dir:          filepath.Join(dir, "manifest"),
		enabled:      enabled,
		shardRecords: shardRecords,
		compactRatio: ratio,
		fileMode:     fileMode,
		data:         newManifestData(),
	}
	if !enabled {
		return m, false, false, nil
	}
	if _, err := os.Stat(filepath.Join(m.dir, ".rebuild")); err == nil {
		return m, false, true, nil
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return m, false, false, nil
		}
		return nil, false, false, errs.WrapDetail(err, ErrStorage, "read manifest directory | 读取 MANIFEST 目录失败")
	}
	var names []string
	maxIndex := -1
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tmp") {
			// A leftover atomic-write temp file is never a live shard. Remove it
			// opportunistically; no other writer can be active under the directory
			// lock. | 原子写残留的临时文件不是存活 shard；目录锁保证没有其它写入者，
			// 可直接清理。
			if !readOnly {
				_ = os.Remove(filepath.Join(m.dir, e.Name()))
			}
			continue
		}
		idx, ok := parseManifestShardIndex(e.Name())
		if e.IsDir() || !ok {
			continue
		}
		names = append(names, e.Name())
		if idx > maxIndex {
			maxIndex = idx
		}
	}
	if len(names) == 0 {
		return m, false, false, nil
	}
	sort.Strings(names)
	// Shards are created contiguously from index 0 and only a full rewrite (which
	// is guarded by .rebuild) removes them. A missing index means the directory
	// is damaged; reading around it would silently drop records from that shard. |
	// shard 从 0 开始连续创建，只有受 .rebuild 保护的整体重写才会删除；缺失索引
	// 说明目录损坏，绕过它读取会静默丢失该分片的记录。
	for i, name := range names {
		idx, _ := parseManifestShardIndex(name)
		if idx != i {
			return m, true, true, nil
		}
	}
	corrupt := false
	validRecords := 0
	validEnds := make([]int64, 0, len(names))
	shardBytes := make([]int64, 0, len(names))
	for _, name := range names {
		path := filepath.Join(m.dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false, false, errs.WrapDetail(err, ErrStorage, "read %s | 读取 %s 失败", path, path)
		}
		shardBytes = append(shardBytes, int64(len(data)))
		validInShard := 0
		off := 0
		for ; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
			r, err := decodeManifestRecord(data[off : off+int(manifestHeaderSize)])
			if err != nil {
				// A valid record after the invalid one means middle corruption; a
				// pure tail is an append that was never confirmed. | 无效记录之后仍有
				// 有效记录说明中间损坏；单纯的尾部是未确认的追加。
				if hasValidManifestAfter(data, off+int(manifestHeaderSize)) {
					corrupt = true
				}
				break
			}
			if err := m.data.apply(r, dir); err != nil {
				return nil, false, false, err
			}
			if r.kind == manifestKindRetire || r.kind == manifestKindCheckpoint || r.kind == manifestKindTruncate {
				m.stale = true
			}
			validInShard++
			validRecords++
		}
		m.total = append(m.total, validInShard)
		validEnds = append(validEnds, int64(off))
		if corrupt {
			break
		}
	}
	// A manifest directory with shards but no CRC-valid record is damaged, not
	// an empty manifest. Treating it as empty would silently discard the
	// directory's high-water evidence. | 有分片但没有任何 CRC 有效记录的
	// MANIFEST 属于损坏而非空 MANIFEST；把它当空会静默丢失高水位证据。
	if !corrupt && validRecords == 0 {
		corrupt = true
	}
	if corrupt {
		return m, true, true, nil
	}
	if !readOnly {
		// Discard an unconfirmed tail so a later append cannot place valid
		// records after an invalid one (which would look like middle
		// corruption). | 丢弃未确认尾部，避免后续追加把有效记录写在无效记录
		// 之后（否则会被判为中间损坏）。
		for i, end := range validEnds {
			if end >= shardBytes[i] {
				continue
			}
			path := filepath.Join(m.dir, names[i])
			f, err := os.OpenFile(path, os.O_RDWR, fileMode)
			if err != nil {
				return nil, false, false, errs.WrapDetail(err, ErrStorage, "open manifest shard for truncate | 打开待截断 MANIFEST 分片失败")
			}
			if err := f.Truncate(end); err != nil {
				_ = f.Close()
				return nil, false, false, wrapStorage("truncate manifest shard", err)
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				return nil, false, false, wrapStorage("sync truncated manifest shard", err)
			}
			if err := f.Close(); err != nil {
				return nil, false, false, wrapStorage("close truncated manifest shard", err)
			}
		}
	}
	m.current = maxIndex
	return m, true, false, nil
}

// hasValidManifestAfter searches for a valid record after off. | hasValidManifestAfter
// 在 off 之后搜索一条有效记录。
func hasValidManifestAfter(data []byte, off int) bool {
	for ; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
		if _, err := decodeManifestRecord(data[off : off+int(manifestHeaderSize)]); err == nil {
			return true
		}
	}
	return false
}

// append writes and synchronizes one record, applying it to memory. | append
// 写入并同步一条记录，然后应用到内存。
func (m *manifest) append(r manifestRecord) error {
	if !m.enabled {
		return nil
	}
	m.appendMu.Lock()
	defer m.appendMu.Unlock()
	if m.poisoned != nil {
		return m.poisoned
	}
	if m.file == nil {
		if err := m.openCurrentLocked(); err != nil {
			return err
		}
	}
	if m.count >= m.shardRecords {
		_ = m.closeCurrentLocked()
		m.current++
		if err := m.openCurrentLocked(); err != nil {
			return err
		}
	}
	var rec [manifestHeaderSize]byte
	encodeManifestRecord(rec[:], r)
	good := m.offset
	if err := writeFullAt(m.file, rec[:], good); err != nil {
		werr := wrapStorage("manifest write", err)
		if terr := m.file.Truncate(good); terr != nil {
			m.poisoned = werr
			return werr
		}
		if serr := m.file.Sync(); serr != nil {
			m.poisoned = werr
			return werr
		}
		return werr
	}
	if err := syncMetaFile(m.file); err != nil {
		// An fsync failure is unrecoverable: the on-disk state is unknown, so
		// stop appending instead of rolling back and continuing. | fsync 失败
		// 不可恢复：磁盘状态未知，停止追加，不能回退后继续。
		m.poisoned = wrapStorage("manifest sync", err)
		return m.poisoned
	}
	m.offset += int64(manifestHeaderSize)
	m.count++
	if r.kind == manifestKindRetire || r.kind == manifestKindCheckpoint || r.kind == manifestKindTruncate {
		m.stale = true
	}
	m.summaryMu.Lock()
	err := m.data.apply(r, filepath.Dir(m.dir))
	m.summaryMu.Unlock()
	return err
}

// openCurrentLocked opens or creates the current shard. | openCurrentLocked 打开或创建当前 shard。
func (m *manifest) openCurrentLocked() error {
	if err := ensureDir(m.dir, 0o700); err != nil {
		return err
	}
	name := manifestShardName(m.current)
	path := filepath.Join(m.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, m.fileMode)
	if err != nil {
		return wrapStorage("open manifest shard", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return wrapStorage("stat manifest shard", err)
	}
	if rem := info.Size() % int64(manifestHeaderSize); rem != 0 {
		// A failed append truncates back to goodOffset; if the process died before
		// that, discard the unconfirmed tail here. | 失败追加会回退到 goodOffset；
		// 若进程在此之前崩溃，这里丢弃未确认的尾部。
		good := info.Size() - rem
		if err := f.Truncate(good); err != nil {
			_ = f.Close()
			return wrapStorage("truncate manifest shard", err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return wrapStorage("sync truncated manifest shard", err)
		}
		info, err = f.Stat()
		if err != nil {
			_ = f.Close()
			return wrapStorage("stat manifest shard", err)
		}
	}
	m.file = f
	m.offset = info.Size()
	m.count = int(info.Size() / int64(manifestHeaderSize))
	if len(m.total) <= m.current {
		m.total = append(m.total, m.count)
	} else {
		m.total[m.current] = m.count
	}
	if info.Size() == 0 {
		if err := syncDir(m.dir); err != nil {
			return wrapStorage("sync manifest directory", err)
		}
	}
	return nil
}

// closeCurrentLocked closes the current shard and compacts it if needed. | closeCurrentLocked
// 关闭当前 shard，并在需要时压缩。
func (m *manifest) closeCurrentLocked() error {
	if m.file == nil {
		return nil
	}
	if err := m.file.Close(); err != nil {
		m.file = nil
		return wrapStorage("close manifest shard", err)
	}
	m.file = nil
	idx := m.current
	if ratio := m.staleRatio(idx); ratio >= m.compactRatio {
		_ = m.compactShardLocked(idx)
	}
	return nil
}

// staleRatio estimates the stale ratio of a closed shard. | staleRatio 估算已关闭 shard 的陈旧比例。
func (m *manifest) staleRatio(index int) float64 {
	path := filepath.Join(m.dir, manifestShardName(index))
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return 0
	}
	total := len(data) / int(manifestHeaderSize)
	if total == 0 {
		return 0
	}
	live := m.liveRecordCount(index, data)
	return 1 - float64(live)/float64(total)
}

// liveRecordCount counts records that a compaction would keep. | liveRecordCount
// 统计压缩后会保留的记录数。
func (m *manifest) liveRecordCount(index int, data []byte) int {
	seen := make(map[string]bool)
	var maxRetire, maxCreated uint64
	var lastTruncate int
	for off := 0; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
		r, err := decodeManifestRecord(data[off : off+int(manifestHeaderSize)])
		if err != nil {
			break
		}
		switch r.kind {
		case manifestKindSegment, manifestKindCheckpoint:
			seen[fmt.Sprintf("%d/%d", r.seq, r.kind)] = true
		case manifestKindRetire:
			if r.seq > maxRetire {
				maxRetire = r.seq
			}
		case manifestKindCreated:
			if r.seq > maxCreated {
				maxCreated = r.seq
			}
		case manifestKindTruncate:
			lastTruncate = off
		}
	}
	n := len(seen)
	if maxRetire != 0 {
		n++
	}
	if maxCreated != 0 {
		n++
	}
	if lastTruncate != 0 {
		n++
	}
	return n
}

// compactShardLocked rewrites one closed shard with only live records. | compactShardLocked
// 只保留 live 记录重写一个已关闭 shard。
func (m *manifest) compactShardLocked(index int) error {
	path := filepath.Join(m.dir, manifestShardName(index))
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	latest := make(map[string]int)
	latestTruncate := -1
	var maxRetire, maxCreated int = -1, -1
	var retireSeq, createdSeq uint64
	type parsed struct {
		rec manifestRecord
		off int
	}
	var records []parsed
	for off := 0; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
		r, err := decodeManifestRecord(data[off : off+int(manifestHeaderSize)])
		if err != nil {
			return err
		}
		records = append(records, parsed{rec: r, off: off})
		switch r.kind {
		case manifestKindSegment, manifestKindCheckpoint:
			latest[fmt.Sprintf("%d/%d", r.seq, r.kind)] = len(records) - 1
		case manifestKindRetire:
			if r.seq > retireSeq {
				retireSeq = r.seq
				maxRetire = len(records) - 1
			}
		case manifestKindCreated:
			if r.seq > createdSeq {
				createdSeq = r.seq
				maxCreated = len(records) - 1
			}
		case manifestKindTruncate:
			latestTruncate = len(records) - 1
		}
	}
	keep := make(map[int]bool)
	for _, i := range latest {
		keep[i] = true
	}
	if maxRetire >= 0 {
		keep[maxRetire] = true
	}
	if maxCreated >= 0 {
		keep[maxCreated] = true
	}
	if latestTruncate >= 0 {
		keep[latestTruncate] = true
	}
	out := make([]byte, 0, len(keep)*int(manifestHeaderSize))
	for i, rec := range records {
		if keep[i] {
			var b [manifestHeaderSize]byte
			encodeManifestRecord(b[:], rec.rec)
			out = append(out, b[:]...)
		}
	}
	if len(out) == len(data) {
		return nil
	}
	return writeFileAtomic(path, out, m.fileMode)
}

// poisonErr returns the unrecoverable sync failure, if any. | poisonErr 返回
// 不可恢复的同步失败。
func (m *manifest) poisonErr() error {
	m.appendMu.Lock()
	defer m.appendMu.Unlock()
	return m.poisoned
}

// closeHandle releases the current shard without compacting. It is used when
// Open fails and the directory must not be mutated. | closeHandle 关闭当前 shard
// 且不压缩；用于 Open 失败、不得修改目录的场景。
func (m *manifest) closeHandle() {
	if m == nil {
		return
	}
	m.appendMu.Lock()
	if m.file != nil {
		_ = m.file.Close()
		m.file = nil
	}
	m.appendMu.Unlock()
}

// close closes the current shard and compacts every shard. | close 关闭当前 shard 并压缩全部 shard。
func (m *manifest) close() error {
	if !m.enabled {
		return nil
	}
	m.appendMu.Lock()
	defer m.appendMu.Unlock()
	var first error
	if m.file != nil {
		if err := m.file.Close(); err != nil && first == nil {
			first = err
		}
		m.file = nil
	}
	if m.poisoned != nil {
		return first
	}
	if !m.stale {
		// No retire/checkpoint/truncate records: compaction would rewrite every
		// shard unchanged, so skip the I/O on clean shutdown. | 没有退休/检查点/
		// 截断记录时，压缩只会原样重写每个分片；干净关闭跳过该 I/O。
		return first
	}
	entries, err := os.ReadDir(m.dir)
	if err == nil {
		for _, e := range entries {
			idx, ok := parseManifestShardIndex(e.Name())
			if e.IsDir() || !ok {
				continue
			}
			if err := m.compactShardLocked(idx); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// rewrite rebuilds the manifest directory from the in-memory data. | rewrite
// 从内存数据重建 MANIFEST 目录。
func (m *manifest) rewrite(data manifestData) error {
	if !m.enabled {
		return nil
	}
	m.appendMu.Lock()
	defer m.appendMu.Unlock()
	if m.file != nil {
		_ = m.file.Close()
		m.file = nil
	}
	seqs := make([]uint64, 0, len(data.segments))
	for seq := range data.segments {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var records []manifestRecord
	// Retirement is prefix monotonic, so one watermark record replaces every
	// per-segment kind=2 record. This keeps a rewritten manifest small even
	// after millions of segments were truncated. | 退休按前缀单调，因此一条水位
	// 记录即可替代所有逐段 kind=2 记录；即使截断过百万段，重写后的 MANIFEST
	// 也保持紧凑。
	retireFloor := data.retireFloor
	for seq := range data.retired {
		if seq > retireFloor {
			retireFloor = seq
		}
	}
	if retireFloor > 0 {
		records = append(records, manifestRecord{kind: manifestKindRetire, seq: retireFloor, walID: data.walID})
	}
	for _, seq := range seqs {
		s := data.segments[seq]
		baseLSN := s.baseLSN
		walID := s.walID
		created := s.createdNano
		if s.currentState() == segmentSealed || s.recordCount > 0 || s.size > int64(segmentHeaderSize) {
			records = append(records, manifestRecord{
				kind: manifestKindSegment, seq: seq, baseLSN: baseLSN, lastLSN: s.lastLSN,
				segmentBytes: uint64(s.size), recordCount: s.recordCount, minTime: s.minTime,
				maxTime: s.maxTime, segmentCRC: s.crc, idxCRC: s.idxCRC, walID: walID,
				createdNano: created, commitSeq: s.commitSeq,
			})
		} else {
			records = append(records, manifestRecord{
				kind: manifestKindCreated, seq: seq, baseLSN: baseLSN, lastLSN: baseLSN - 1,
				segmentBytes: uint64(segmentHeaderSize), walID: walID, createdNano: created,
			})
		}
	}
	if data.firstLSN > 1 {
		// firstLSN == 1 is the default and needs no persisted truncate
		// watermark; writing one would make every clean manifest stale. |
		// firstLSN == 1 是默认值，无需持久化截断水位；写入会让每个干净
		// MANIFEST 被误判为存在陈旧记录。
		records = append(records, manifestRecord{kind: manifestKindTruncate, baseLSN: data.firstLSN, commitSeq: data.commitSeq, walID: data.walID})
	}
	if len(records) == 0 {
		_ = os.Remove(filepath.Join(m.dir, ".rebuild"))
		// An empty rebuild must also remove stale shards; otherwise a corrupt or
		// obsolete shard survives forever for an empty WAL and every Open keeps
		// falling back to a directory scan. | 空重建也必须删除陈旧 shard，否则空
		// WAL 上损坏/过期的 shard 会永久残留，每次 Open 都回退目录扫描。
		if entries, err := os.ReadDir(m.dir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && filepath.Ext(e.Name()) == ".mf" {
					_ = os.Remove(filepath.Join(m.dir, e.Name()))
				}
			}
		}
		m.current = 0
		m.offset = 0
		m.count = 0
		m.total = nil
		m.stale = false
		m.summaryMu.Lock()
		m.data = data
		m.summaryMu.Unlock()
		if _, err := os.Stat(m.dir); err == nil {
			return syncDir(m.dir)
		}
		return nil
	}
	if err := ensureDir(m.dir, 0o700); err != nil {
		return err
	}
	marker := filepath.Join(m.dir, ".rebuild")
	if err := writeFileAtomic(marker, nil, m.fileMode); err != nil {
		return err
	}
	// Remove old shards, then write new ones. The .rebuild marker makes a crash fall back to readdir. | 删除旧 shard 后写新 shard；崩溃时 .rebuild 标记使下次回退 readdir。
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".mf" {
			_ = os.Remove(filepath.Join(m.dir, e.Name()))
		}
	}
	for i := 0; i*m.shardRecords < len(records); i++ {
		end := (i + 1) * m.shardRecords
		if end > len(records) {
			end = len(records)
		}
		var buf []byte
		for _, r := range records[i*m.shardRecords : end] {
			var b [manifestHeaderSize]byte
			encodeManifestRecord(b[:], r)
			buf = append(buf, b[:]...)
		}
		if err := writeFileAtomic(filepath.Join(m.dir, manifestShardName(i)), buf, m.fileMode); err != nil {
			return err
		}
	}
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncDir(m.dir); err != nil {
		return err
	}
	m.current = 0
	m.offset = 0
	m.count = 0
	m.total = nil
	m.stale = false
	m.summaryMu.Lock()
	m.data = data
	m.summaryMu.Unlock()
	return nil
}

// segmentCount returns the number of known segment summaries. | segmentCount
// 返回已知分段摘要数量。
func (m *manifest) segmentCount() uint64 {
	m.summaryMu.RLock()
	defer m.summaryMu.RUnlock()
	return uint64(len(m.data.segments))
}

// snapshot returns a deep copy of the segment directory. | snapshot 返回段目录的深拷贝。
func (m *manifest) snapshot() manifestData {
	m.summaryMu.RLock()
	defer m.summaryMu.RUnlock()
	out := manifestData{
		segments:      make(map[uint64]*segment, len(m.data.segments)),
		retired:       make(map[uint64]bool, len(m.data.retired)),
		retireFloor:   m.data.retireFloor,
		maxSeq:        m.data.maxSeq,
		maxCreatedSeq: m.data.maxCreatedSeq,
		firstLSN:      m.data.firstLSN,
		commitSeq:     m.data.commitSeq,
		walID:         m.data.walID,
		walIDSet:      m.data.walIDSet,
	}
	for k, v := range m.data.segments {
		out.segments[k] = v.cloneSummary()
	}
	for k, v := range m.data.retired {
		out.retired[k] = v
	}
	return out
}
