package wal

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	segments      map[uint64]*segment
	retired       map[uint64]bool
	maxSeq        uint64
	maxCreatedSeq uint64
	firstLSN      uint64
	commitSeq     uint64
	walID         [16]byte
	walIDSet      bool
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

// manifest is the append-only sharded segment directory. | manifest 是只追加的分片段目录。
type manifest struct {
	dir          string
	enabled      bool
	shardRecords int
	compactRatio float64
	fileMode     os.FileMode

	appendMu sync.Mutex
	current  int
	file     *os.File
	offset   int64
	count    int
	total    []int

	summaryMu sync.RWMutex
	data      manifestData
}

// openManifest loads all shards. A missing or empty manifest is not an error;
// the caller falls back to a directory scan and may rebuild it. | openManifest
// 加载全部 shard；MANIFEST 缺失或为空不是错误，调用方回退目录扫描并可重建。
func openManifest(dir string, enabled bool, shardRecords int, ratio float64, fileMode os.FileMode) (*manifest, bool, bool, error) {
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
		if e.IsDir() || len(e.Name()) != 11 || filepath.Ext(e.Name()) != ".mf" {
			continue
		}
		var idx int
		if _, err := fmt.Sscanf(e.Name(), "%08d.mf", &idx); err != nil {
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
	corrupt := false
	for _, name := range names {
		path := filepath.Join(m.dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false, false, errs.WrapDetail(err, ErrStorage, "read %s | 读取 %s 失败", path, path)
		}
		m.total = append(m.total, len(data)/int(manifestHeaderSize))
		for off := 0; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
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
		}
		if corrupt {
			break
		}
	}
	if corrupt {
		return m, true, true, nil
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
		_ = m.file.Truncate(good)
		_ = m.file.Sync()
		return wrapStorage("manifest write", err)
	}
	if err := syncMetaFile(m.file); err != nil {
		_ = m.file.Truncate(good)
		_ = m.file.Sync()
		return wrapStorage("manifest sync", err)
	}
	m.offset += int64(manifestHeaderSize)
	m.count++
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
	entries, err := os.ReadDir(m.dir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".mf" {
				continue
			}
			var idx int
			if _, err := fmt.Sscanf(e.Name(), "%08d.mf", &idx); err != nil {
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
	seenRetired := make(map[uint64]bool, len(data.retired))
	for _, seq := range seqs {
		if data.retired[seq] {
			records = append(records, manifestRecord{kind: manifestKindRetire, seq: seq, walID: data.walID})
			seenRetired[seq] = true
		}
	}
	for seq := range data.retired {
		if !seenRetired[seq] {
			records = append(records, manifestRecord{kind: manifestKindRetire, seq: seq, walID: data.walID})
		}
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
	if data.firstLSN > 0 {
		records = append(records, manifestRecord{kind: manifestKindTruncate, baseLSN: data.firstLSN, commitSeq: data.commitSeq, walID: data.walID})
	}
	if len(records) == 0 {
		_ = os.Remove(filepath.Join(m.dir, ".rebuild"))
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
		maxSeq:        m.data.maxSeq,
		maxCreatedSeq: m.data.maxCreatedSeq,
		firstLSN:      m.data.firstLSN,
		commitSeq:     m.data.commitSeq,
		walID:         m.data.walID,
		walIDSet:      m.data.walIDSet,
	}
	walDir := filepath.Dir(m.dir)
	for k, v := range m.data.segments {
		v.metaMu.RLock()
		n := newSegmentSummary(v.seq, v.baseLSN, v.lastLSN, v.size, v.walID, walDir)
		n.recordCount = v.recordCount
		n.minTime = v.minTime
		n.maxTime = v.maxTime
		n.crc = v.crc
		n.idxCRC = v.idxCRC
		n.commitSeq = v.commitSeq
		n.createdNano = v.createdNano
		v.metaMu.RUnlock()
		n.setState(v.currentState())
		n.retired = v.retired
		out.segments[k] = n
	}
	for k, v := range m.data.retired {
		out.retired[k] = v
	}
	return out
}
