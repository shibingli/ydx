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
	file        *os.File
	path        string
	seq         uint64
	size        int64
	lastIndex   uint64
	markerIndex uint64
	hasMarker   bool
}

// wal is the append-only log storage. All methods are called under FileStorage's
// mutex. | wal 是只追加日志存储。所有方法都在 FileStorage 的互斥锁下调用。
type wal struct {
	active      *walSegment
	dir         string
	segments    []*walSegment
	recBuf      []byte
	segmentSize int64
	nextSeq     uint64
	noSync      bool
}

// walRecovery is the reconstructed state. | walRecovery 是重建后的状态。
type walRecovery struct {
	entries  []Entry
	hs       HardState
	base     uint64
	sawState bool
}

// openWAL scans every segment once, rebuilds state, finds the newest snapshot
// marker and opens the active segment. Combining both recovery passes avoids
// decoding every WAL record twice at startup. | openWAL 一次扫描所有分段，重建
// 状态、查找最新快照标记并打开活动分段。合并两遍恢复扫描可避免启动时把每条 WAL
// 记录解码两次。
func openWAL(dir string, noSync bool, segmentSize int64) (*wal, walRecovery, snapshotMarker, error) {
	w := &wal{dir: dir, noSync: noSync, segmentSize: segmentSize}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, walRecovery{}, snapshotMarker{}, errs.Wrap(err, ErrStorage)
	}
	names, err := segmentNames(dir)
	if err != nil {
		return nil, walRecovery{}, snapshotMarker{}, err
	}
	var rec walRecovery
	var marker snapshotMarker
	for i, name := range names {
		path := filepath.Join(dir, name)
		seq, _ := strconv.ParseUint(strings.TrimSuffix(name, ".wal"), 10, 64)
		seg := &walSegment{seq: seq, path: path}
		last := i == len(names)-1
		if err := readSegmentRecords(seg, last, func(b walBatch) error {
			if b.hasSnapshot {
				seg.hasMarker = true
				if b.snapIndex > seg.markerIndex {
					seg.markerIndex = b.snapIndex
				}
				if !marker.found || b.snapIndex > marker.index ||
					(b.snapIndex == marker.index && b.snapTerm >= marker.term) {
					marker = snapshotMarker{
						index: b.snapIndex, term: b.snapTerm, found: true,
					}
				}
			}
			return rec.apply(b, seg)
		}); err != nil {
			return nil, walRecovery{}, snapshotMarker{}, err
		}
		w.segments = append(w.segments, seg)
		if seq >= w.nextSeq {
			w.nextSeq = seq + 1
		}
	}
	if len(w.segments) == 0 {
		if err := w.rotateLocked(); err != nil {
			return nil, walRecovery{}, snapshotMarker{}, err
		}
	} else {
		active := w.segments[len(w.segments)-1]
		f, err := os.OpenFile(active.path, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			return nil, walRecovery{}, snapshotMarker{}, errs.Wrap(err, ErrStorage)
		}
		active.file = f
		w.active = active
	}
	if len(rec.entries) > 0 && rec.entries[0].Index != rec.base+1 {
		return nil, walRecovery{}, snapshotMarker{}, errs.Detail(ErrCorrupt,
			"WAL starts at %d, snapshot ends at %d", rec.entries[0].Index, rec.base)
	}
	return w, rec, marker, nil
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
		// Markers advance the log base. Entries collected from earlier segments
		// that the new base covers are dropped here rather than retained until
		// the final snapshot is known. The snapshot file itself is opened after
		// the scan, so a marker without a durable image still fails recovery.
		// | 标记推进日志基点。此前分段中已被新基点覆盖的日志项在此丢弃，而不是保留到
		// 最终快照确定。快照文件在扫描后打开，因此缺少持久镜像的标记仍会让恢复失败。
		if b.snapIndex >= rec.base {
			rec.base = b.snapIndex
			cut := 0
			for cut < len(rec.entries) && rec.entries[cut].Index <= rec.base {
				cut++
			}
			if cut > 0 {
				rec.entries = append([]Entry(nil), rec.entries[cut:]...)
			}
		}
		if b.snapReset && b.snapIndex >= rec.base {
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
	// Large entry batches avoid the copy into the reusable record buffer and
	// reach the file through one vectored write. Snapshot markers stay on the
	// buffered path because their payload is metadata only. | 大日志项批次避免复制
	// 进复用记录缓冲区，并通过一次向量写落到文件。快照标记负载仅为元数据，保持缓冲
	// 路径。
	if writevEnabled {
		if parts, size, ok := walWritevParts(batch); ok {
			if err := w.writeWALParts(parts, size); err != nil {
				return err
			}
			if last := batch.Entries[len(batch.Entries)-1].Index; last > w.active.lastIndex {
				w.active.lastIndex = last
			}
			if w.active.size >= w.segmentSize {
				return w.rotateLocked()
			}
			return nil
		}
	}
	// Build the complete record in one buffer so a batch costs a single write
	// syscall instead of three. The eight-byte header is filled after encoding.
	// | 在一个缓冲区中构建完整记录，使一个批次只产生一次 write 系统调用而非三次。
	// 八字节头在编码完成后回填。
	estimated := len(batch.Entries) * 16
	for i := range batch.Entries {
		estimated += len(batch.Entries[i].Data)
	}
	if estimated > maxWALRecord {
		return errs.Detail(ErrTooLarge, "WAL batch %d bytes", estimated)
	}
	w.recBuf = w.recBuf[:0]
	w.recBuf = append(w.recBuf, 0, 0, 0, 0, 0, 0, 0, 0, walRecBatch)
	w.recBuf = encodeWALBatch(w.recBuf, batch)
	if len(w.recBuf)-8 > maxWALRecord {
		return errs.Detail(ErrTooLarge, "WAL record %d bytes", len(w.recBuf)-8)
	}
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
		if batch.Snapshot.Index > w.active.markerIndex {
			w.active.markerIndex = batch.Snapshot.Index
		}
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
		if err := syncDir(w.dir); err != nil {
			_ = f.Close()
			return errs.Wrap(err, ErrStorage)
		}
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
// The active segment and the segment holding the newest snapshot marker are
// always retained; older marker segments are deleted once covered. Keeping
// every marker segment would pin one segment per local snapshot forever.
// | compact 删除内容已被快照完全覆盖的分段。活动分段与持有最新快照标记的分段始终
// 保留；更旧的标记分段一旦被覆盖即删除。保留所有标记分段会让每次本地快照永久钉住
// 一个分段。
func (w *wal) compact(index uint64) error {
	var keepMarker *walSegment
	for _, seg := range w.segments {
		if !seg.hasMarker {
			continue
		}
		if keepMarker == nil || seg.markerIndex > keepMarker.markerIndex {
			keepMarker = seg
		}
	}
	keep := w.segments[:0]
	for _, seg := range w.segments {
		if seg == w.active || seg == keepMarker {
			keep = append(keep, seg)
			continue
		}
		if seg.hasMarker && seg.markerIndex >= index {
			keep = append(keep, seg)
			continue
		}
		// Only segments with no records at all can be dropped without checking
		// their hard state. A segment may contain a newer term/vote but no
		// entries (lastIndex stays zero), and deleting it could make recovery
		// reuse an older term or vote. | 只有完全不含记录的分段才能直接删除；
		// 分段可能只有更新的任期/选票而没有日志项（lastIndex 仍为零），删除它会让
		// 恢复复用更旧的任期或选票。
		if seg.size == int64(len(walMagic)) || seg.lastIndex > 0 && seg.lastIndex <= index {
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
