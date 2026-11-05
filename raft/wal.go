package raft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

const (
	walMagic         = "YDRWAL01"
	walRecBatch      = byte(1)
	maxWALRecord     = 256 << 20
	walFlagState     = 1 << 0
	walFlagTrunc     = 1 << 1
	walFlagEntry     = 1 << 2
	walFlagSnap      = 1 << 3
	walFlagSnapReset = 1 << 4
	walKnownFlags    = walFlagState | walFlagTrunc | walFlagEntry | walFlagSnap | walFlagSnapReset
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// walSegment is one append-only file with the entries it contains. | walSegment
// 是一个只追加文件及其包含的日志项。
type walSegment struct {
	seq       uint64
	path      string
	file      *os.File
	size      int64
	lastIndex uint64
	hasMarker bool
}

// wal is the append-only log storage. All methods are called under FileStorage's
// mutex. | wal 是只追加日志存储。所有方法都在 FileStorage 的互斥锁下调用。
type wal struct {
	dir         string
	noSync      bool
	segmentSize int64
	segments    []*walSegment
	active      *walSegment
	nextSeq     uint64
	recBuf      []byte
}

// walRecovery is the reconstructed state. | walRecovery 是重建后的状态。
type walRecovery struct {
	hs       HardState
	entries  []Entry
	base     uint64
	sawState bool
}

// openWAL scans every segment, rebuilds state and opens the active segment.
// | openWAL 扫描所有分段、重建状态并打开活动分段。
func openWAL(dir string, base uint64, noSync bool, segmentSize int64) (*wal, walRecovery, error) {
	w := &wal{dir: dir, noSync: noSync, segmentSize: segmentSize}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, walRecovery{}, errs.Wrap(err, ErrStorage)
	}
	names, err := segmentNames(dir)
	if err != nil {
		return nil, walRecovery{}, err
	}
	rec := walRecovery{base: base}
	for i, name := range names {
		path := filepath.Join(dir, name)
		seq, _ := strconv.ParseUint(strings.TrimSuffix(name, ".wal"), 10, 64)
		seg := &walSegment{seq: seq, path: path}
		last := i == len(names)-1
		if err := readSegmentRecords(seg, last, func(b walBatch) error {
			if b.hasSnapshot {
				seg.hasMarker = true
			}
			return rec.apply(b, seg)
		}); err != nil {
			return nil, walRecovery{}, err
		}
		w.segments = append(w.segments, seg)
		if seq >= w.nextSeq {
			w.nextSeq = seq + 1
		}
	}
	if len(w.segments) == 0 {
		if err := w.rotateLocked(); err != nil {
			return nil, walRecovery{}, err
		}
	} else {
		active := w.segments[len(w.segments)-1]
		f, err := os.OpenFile(active.path, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			return nil, walRecovery{}, errs.Wrap(err, ErrStorage)
		}
		active.file = f
		w.active = active
	}
	if len(rec.entries) > 0 && rec.entries[0].Index != base+1 {
		return nil, walRecovery{}, errs.Detail(ErrCorrupt, "WAL starts at %d, snapshot ends at %d", rec.entries[0].Index, base)
	}
	return w, rec, nil
}

// segmentNames returns the *.wal files in ascending sequence order. | segmentNames
// 按序号升序返回 *.wal 文件。
func segmentNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wal") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// readSegmentRecords validates one segment and calls fn for every record. A
// partial trailing record in the last segment is a normal crash artifact and is
// truncated. The segment size is updated to the valid extent. | readSegmentRecords
// 校验一个分段并对每条记录调用 fn。最后分段末尾的残缺记录属于正常崩溃产物，会被
// 截断。分段大小会更新为有效长度。
func readSegmentRecords(seg *walSegment, last bool, fn func(walBatch) error) error {
	f, err := os.OpenFile(seg.path, os.O_RDWR, 0o600)
	if err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	seg.size = info.Size()
	var header [8]byte
	if seg.size < int64(len(header)) {
		if !last {
			return errs.Detail(ErrCorrupt, "short WAL header %s", seg.path)
		}
		if err := f.Truncate(0); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
		if _, err := f.WriteAt([]byte(walMagic), 0); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
		if err := f.Sync(); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
		seg.size = int64(len(walMagic))
		return nil
	}
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if string(header[:]) != walMagic {
		return errs.Detail(ErrCorrupt, "bad WAL magic in %s", seg.path)
	}
	offset := int64(len(header))
	var recHeader [8]byte
	for {
		n, err := io.ReadFull(f, recHeader[:])
		if err == io.EOF && n == 0 {
			break
		}
		if err != nil || n != len(recHeader) {
			if !last {
				return errs.Detail(ErrCorrupt, "short WAL record header in %s", seg.path)
			}
			break
		}
		length := binary.LittleEndian.Uint32(recHeader[0:4])
		wantCRC := binary.LittleEndian.Uint32(recHeader[4:8])
		if length == 0 || length > maxWALRecord {
			if !last {
				return errs.Detail(ErrCorrupt, "bad WAL record length %d in %s", length, seg.path)
			}
			break
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(f, payload); err != nil {
			if !last {
				return errs.Detail(ErrCorrupt, "short WAL record in %s", seg.path)
			}
			break
		}
		if crc32.Checksum(payload, castagnoli) != wantCRC {
			if !last {
				return errs.Detail(ErrCorrupt, "WAL CRC mismatch in %s", seg.path)
			}
			break
		}
		if len(payload) == 0 || payload[0] != walRecBatch {
			if !last {
				return errs.Detail(ErrCorrupt, "unknown WAL record type in %s", seg.path)
			}
			break
		}
		decoded, err := decodeWALBatch(payload[1:])
		if err != nil {
			if !last {
				return err
			}
			break
		}
		if err := fn(decoded); err != nil {
			return err
		}
		offset += int64(len(recHeader)) + int64(length)
	}
	if last {
		if err := f.Truncate(offset); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
		seg.size = offset
	}
	return nil
}

// apply merges one decoded record into the recovery state. | apply 将一条解码记录合并
// 进恢复状态。
func (rec *walRecovery) apply(b walBatch, seg *walSegment) error {
	if b.hs != nil {
		rec.hs = *b.hs
		rec.sawState = true
	}
	if b.truncate > 0 {
		cut := len(rec.entries)
		for cut > 0 && rec.entries[cut-1].Index >= b.truncate {
			cut--
		}
		rec.entries = rec.entries[:cut]
	}
	if b.hasSnapshot {
		if b.snapIndex > rec.base {
			return errs.Detail(ErrCorrupt, "WAL references missing snapshot %d (loaded %d)", b.snapIndex, rec.base)
		}
		if b.snapReset {
			// InstallSnapshot makes every older entry stale, including entries
			// scanned from segments that precede the marker. | InstallSnapshot 使
			// 所有更旧日志项失效，包括标记之前分段中已扫描到的日志项。
			rec.entries = nil
		}
	}
	for i := range b.entries {
		e := b.entries[i]
		if e.Index <= rec.base {
			continue
		}
		if len(rec.entries) == 0 {
			if e.Index != rec.base+1 {
				return errs.Detail(ErrCorrupt, "WAL gap: entry %d after snapshot %d", e.Index, rec.base)
			}
			rec.entries = append(rec.entries, e)
			if e.Index > seg.lastIndex {
				seg.lastIndex = e.Index
			}
			continue
		}
		last := rec.entries[len(rec.entries)-1]
		switch {
		case e.Index == last.Index+1:
			rec.entries = append(rec.entries, e)
		case e.Index <= last.Index:
			cut := int(e.Index - rec.entries[0].Index)
			if cut < 0 {
				return errs.Detail(ErrCorrupt, "WAL entry %d before base", e.Index)
			}
			if cut < len(rec.entries) && rec.entries[cut].Term == e.Term {
				continue
			}
			if cut < len(rec.entries) {
				rec.entries = rec.entries[:cut]
			}
			rec.entries = append(rec.entries, e)
		default:
			return errs.Detail(ErrCorrupt, "WAL gap: entry %d after %d", e.Index, last.Index)
		}
		if e.Index > seg.lastIndex {
			seg.lastIndex = e.Index
		}
	}
	if b.hasSnapshot && b.snapIndex > seg.lastIndex {
		seg.lastIndex = b.snapIndex
	}
	return nil
}

// append writes one batch. | append 写入一个批次。
func (w *wal) append(batch PersistBatch) error {
	if batch.HardState == nil && batch.Truncate == 0 && len(batch.Entries) == 0 && batch.Snapshot == nil {
		return nil
	}
	// Build the complete record in one buffer so a batch costs a single write
	// syscall instead of three. The eight-byte header is filled after encoding.
	// | 在一个缓冲区中构建完整记录，使一个批次只产生一次 write 系统调用而非三次。
	// 八字节头在编码完成后回填。
	w.recBuf = w.recBuf[:0]
	w.recBuf = append(w.recBuf, 0, 0, 0, 0, 0, 0, 0, 0, walRecBatch)
	w.recBuf = encodeWALBatch(w.recBuf, batch)
	payload := w.recBuf[9:]
	if w.active == nil || w.active.file == nil {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	crc := crc32.Checksum(w.recBuf[8:], castagnoli)
	binary.LittleEndian.PutUint32(w.recBuf[0:4], uint32(len(payload)+1))
	binary.LittleEndian.PutUint32(w.recBuf[4:8], crc)
	if _, err := w.active.file.Write(w.recBuf); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	w.active.size += int64(len(w.recBuf))
	if err := w.syncLocked(); err != nil {
		return err
	}
	if batch.Snapshot != nil {
		w.active.hasMarker = true
		if batch.Snapshot.Index > w.active.lastIndex {
			w.active.lastIndex = batch.Snapshot.Index
		}
	}
	if len(batch.Entries) > 0 {
		last := batch.Entries[len(batch.Entries)-1].Index
		if last > w.active.lastIndex {
			w.active.lastIndex = last
		}
	}
	// Never rotate immediately after a snapshot marker: the active segment is
	// the one compaction is allowed to preserve, and recovery must be able to
	// find the marker for the snapshot it loads. | 快照标记后不得立即轮转：活动
	// 分段是压缩时允许保留的分段，恢复必须能找到所加载快照的标记。
	if batch.Snapshot == nil && w.active.size >= w.segmentSize {
		return w.rotateLocked()
	}
	return nil
}

// rotateLocked starts a new segment. | rotateLocked 开启新分段。
func (w *wal) rotateLocked() error {
	if w.active != nil && w.active.file != nil {
		if err := w.active.file.Close(); err != nil {
			return errs.Wrap(err, ErrStorage)
		}
		w.active.file = nil
	}
	seq := w.nextSeq
	if seq == 0 {
		seq = 1
	}
	w.nextSeq = seq + 1
	path := filepath.Join(w.dir, fmt.Sprintf("%020d.wal", seq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|os.O_EXCL, 0o600)
	if err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	if _, err := f.Write([]byte(walMagic)); err != nil {
		_ = f.Close()
		return errs.Wrap(err, ErrStorage)
	}
	if !w.noSync {
		if err := syncFile(f); err != nil {
			_ = f.Close()
			return errs.Wrap(err, ErrStorage)
		}
		// The new segment's directory entry must be durable before any entry in
		// it is acknowledged. | 在确认新分段中的任何日志项之前，新分段的目录项必须
		// 已持久化。
		syncDir(w.dir)
	}
	seg := &walSegment{seq: seq, path: path, file: f, size: int64(len(walMagic))}
	w.segments = append(w.segments, seg)
	w.active = seg
	return nil
}

// syncLocked flushes the active segment. | syncLocked 刷新活动分段。
func (w *wal) syncLocked() error {
	if w.noSync || w.active == nil || w.active.file == nil {
		return nil
	}
	if err := syncFile(w.active.file); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	return nil
}

// compact deletes segments whose entire content is covered by the snapshot.
// The active segment is always retained. | compact 删除内容已被快照完全覆盖的分段；
// 活动分段始终保留。
func (w *wal) compact(index uint64) error {
	keep := w.segments[:0]
	for _, seg := range w.segments {
		if seg == w.active || seg.hasMarker {
			keep = append(keep, seg)
			continue
		}
		if seg.lastIndex > 0 && seg.lastIndex <= index {
			if err := os.Remove(seg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errs.Wrap(err, ErrStorage)
			}
			continue
		}
		keep = append(keep, seg)
	}
	w.segments = keep
	return nil
}

// compactAll deletes every segment except the active one. InstallSnapshot uses
// it because the snapshot replaces the entire prior log. | compactAll 删除除活动
// 分段外的所有分段。InstallSnapshot 使用它，因为快照替换了此前整段日志。
func (w *wal) compactAll() error {
	keep := w.segments[:0]
	for _, seg := range w.segments {
		if seg == w.active {
			keep = append(keep, seg)
			continue
		}
		if err := os.Remove(seg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errs.Wrap(err, ErrStorage)
		}
	}
	w.segments = keep
	return nil
}

// close flushes and closes the active segment. | close 刷新并关闭活动分段。
func (w *wal) close() error {
	if w.active == nil || w.active.file == nil {
		return nil
	}
	err := w.syncLocked()
	cerr := w.active.file.Close()
	w.active.file = nil
	if err != nil {
		return err
	}
	if cerr != nil {
		return errs.Wrap(cerr, ErrStorage)
	}
	return nil
}

// walBatch is the decoded payload of one WAL record. | walBatch 是一条 WAL 记录的
// 解码载荷。
type walBatch struct {
	hs          *HardState
	truncate    uint64
	entries     []Entry
	snapIndex   uint64
	snapTerm    uint64
	hasSnapshot bool
	snapReset   bool
}

// snapshotMarker is the newest snapshot referenced by the WAL. | snapshotMarker
// 是 WAL 引用的最新快照。
type snapshotMarker struct {
	index uint64
	term  uint64
	reset bool
	found bool
}

// scanWALMarkers finds the newest snapshot marker without loading snapshot
// data. This lets recovery ignore snapshot files whose durability marker was
// never written. | scanWALMarkers 在不加载快照数据的情况下找到最新快照标记，使恢复
// 可以忽略从未写入持久化标记的快照文件。
func scanWALMarkers(dir string) (snapshotMarker, error) {
	names, err := segmentNames(dir)
	if err != nil {
		return snapshotMarker{}, err
	}
	var marker snapshotMarker
	for i, name := range names {
		path := filepath.Join(dir, name)
		seg := &walSegment{path: path}
		last := i == len(names)-1
		if err := readSegmentRecords(seg, last, func(b walBatch) error {
			if !b.hasSnapshot {
				return nil
			}
			if !marker.found || b.snapIndex > marker.index ||
				(b.snapIndex == marker.index && b.snapTerm >= marker.term) {
				marker = snapshotMarker{index: b.snapIndex, term: b.snapTerm, reset: b.snapReset, found: true}
			}
			return nil
		}); err != nil {
			return snapshotMarker{}, err
		}
	}
	return marker, nil
}

// encodeWALBatch serializes one durable batch. | encodeWALBatch 序列化一个持久批次。
func encodeWALBatch(dst []byte, batch PersistBatch) []byte {
	flags := byte(0)
	if batch.HardState != nil {
		flags |= walFlagState
	}
	if batch.Truncate > 0 {
		flags |= walFlagTrunc
	}
	if len(batch.Entries) > 0 {
		flags |= walFlagEntry
	}
	if batch.Snapshot != nil {
		flags |= walFlagSnap
		if batch.SnapshotReplacesLog {
			flags |= walFlagSnapReset
		}
	}
	dst = append(dst, flags)
	if batch.HardState != nil {
		dst = binary.AppendUvarint(dst, batch.HardState.Term)
		dst = binary.AppendUvarint(dst, uint64(batch.HardState.Vote))
		dst = binary.AppendUvarint(dst, batch.HardState.Commit)
	}
	if batch.Truncate > 0 {
		dst = binary.AppendUvarint(dst, batch.Truncate)
	}
	if batch.Snapshot != nil {
		dst = binary.AppendUvarint(dst, batch.Snapshot.Index)
		dst = binary.AppendUvarint(dst, batch.Snapshot.Term)
	}
	if len(batch.Entries) > 0 {
		dst = appendEntries(dst, batch.Entries)
	}
	return dst
}

// decodeWALBatch parses one durable batch. | decodeWALBatch 解析一个持久批次。
func decodeWALBatch(data []byte) (walBatch, error) {
	d := decoder{src: data}
	flags := d.byte()
	if d.err != nil {
		return walBatch{}, d.err
	}
	if flags == 0 || flags&^walKnownFlags != 0 {
		return walBatch{}, errs.Detail(ErrCorrupt, "WAL flags %d", flags)
	}
	var out walBatch
	if flags&walFlagState != 0 {
		hs := HardState{
			Term:   d.uvarint(),
			Vote:   NodeID(d.uvarint()),
			Commit: d.uvarint(),
		}
		out.hs = &hs
	}
	if flags&walFlagTrunc != 0 {
		out.truncate = d.uvarint()
	}
	if flags&walFlagSnap != 0 {
		out.hasSnapshot = true
		out.snapReset = flags&walFlagSnapReset != 0
		out.snapIndex = d.uvarint()
		out.snapTerm = d.uvarint()
	}
	if flags&walFlagEntry != 0 {
		out.entries = d.entries()
	}
	if d.err != nil {
		return walBatch{}, d.err
	}
	if d.pos != len(data) {
		return walBatch{}, errs.Detail(ErrCorrupt, "trailing WAL bytes %d", len(data)-d.pos)
	}
	return out, nil
}
