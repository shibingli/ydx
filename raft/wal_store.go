package raft

import (
	"context"
	"errors"
	"io"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/wal"
)

// walRecordMeta describes one durable record for compaction boundary selection.
// | walRecordMeta 描述一条用于压缩边界选择的持久记录。
type walRecordMeta struct {
	// lsn is the record's ydx/wal log sequence number. | lsn 是记录的 ydx/wal
	// 日志序号。
	lsn uint64
	// maxIndex is the highest raft index the record covers through entries or a
	// snapshot marker. | maxIndex 是记录通过日志项或快照标记覆盖的最高 raft 索引。
	maxIndex uint64
	// stateOnly marks a record that carries a hard state but no entries or
	// snapshot. Compaction must retain it: an older term or vote could otherwise
	// resurface after recovery. | stateOnly 标记只含硬状态、不含日志项或快照的记录。
	// 压缩必须保留它，否则恢复后可能复用更旧的任期或选票。
	stateOnly bool
	// isMarker marks a snapshot marker record. | isMarker 标记快照标记记录。
	isMarker bool
	// snapIndex and snapTerm identify the marker so compaction retains the
	// newest one even if records were appended out of index order. | snapIndex 与
	// snapTerm 标识标记，使压缩即使在记录未按索引顺序追加时也保留最新标记。
	snapIndex uint64
	snapTerm  uint64
}

// walRecordMetaOf summarizes a decoded batch. | walRecordMetaOf 汇总一个已解码批次。
func walRecordMetaOf(lsn uint64, b walBatch) walRecordMeta {
	m := walRecordMeta{lsn: lsn, isMarker: b.hasSnapshot}
	hasEntries := len(b.entries) > 0
	if hasEntries {
		m.maxIndex = b.entries[len(b.entries)-1].Index
	}
	if b.hasSnapshot {
		m.snapIndex = b.snapIndex
		m.snapTerm = b.snapTerm
		if b.snapIndex > m.maxIndex {
			m.maxIndex = b.snapIndex
		}
	}
	m.stateOnly = b.hs != nil && !hasEntries && !b.hasSnapshot
	return m
}

// newestMarker returns the position of the marker with the highest index and
// term, or -1. | newestMarker 返回索引与任期最高的标记位置，找不到时返回 -1。
func (st *walStore) newestMarker() int {
	best := -1
	for i := range st.recs {
		m := &st.recs[i]
		if !m.isMarker {
			continue
		}
		if best < 0 || m.snapIndex > st.recs[best].snapIndex ||
			(m.snapIndex == st.recs[best].snapIndex && m.snapTerm > st.recs[best].snapTerm) {
			best = i
		}
	}
	return best
}

// walStore adapts ydx/wal to raft's PersistBatch model. One PersistBatch becomes
// one atomic ydx/wal record; recovery replays records in LSN order and applies
// exactly the same rules as the retired in-tree WAL. | walStore 把 ydx/wal 适配到
// raft 的 PersistBatch 模型：一个 PersistBatch 变成一条原子 ydx/wal 记录；恢复按
// LSN 顺序重放，并应用与已移除的仓内 WAL 完全相同的规则。
type walStore struct {
	log  *wal.WAL
	buf  []byte
	recs []walRecordMeta
}

// openWALStore opens the ydx/wal directory and replays every committed record.
// | openWALStore 打开 ydx/wal 目录并重放全部已提交记录。
func openWALStore(dir string, noSync bool, segmentSize int64, policy wal.SizePolicy) (*walStore, walRecovery, snapshotMarker, error) {
	opts := []wal.Option{
		wal.WithSegmentMaxBytes(segmentSize),
		wal.WithSizePolicy(policy),
		// ydx/wal counts its record header and AEAD reserve against the limit;
		// leave headroom so a payload at raft's own cap is not rejected. |
		// ydx/wal 的上限包含记录头与 AEAD 预留；留出余量，避免恰好达到 raft
		// 自身上限的负载被拒绝。
		wal.WithMaxRecordBytes(maxWALRecord + 4096),
		// Raft always replays the full live record set at startup, so periodic
		// active-segment checkpoints only add sidecar fsyncs without shortening
		// recovery. Sealed segments still get a sidecar at rotation. |
		// raft 启动时总是重放全部存活记录，活动段的周期检查点只会增加侧车写入与
		// 同步，并不会缩短恢复时间；封段在轮转时仍会写侧车。
		wal.WithCheckpointBytes(1 << 40),
	}
	if noSync {
		// NoSync explicitly trades durability for throughput; flushing a whole
		// sealed segment on every rotation would add multi-hundred-millisecond
		// stalls to large-record tests and benchmarks. An adaptive userspace write
		// buffer additionally removes one write syscall per small batch and grows
		// with the observed batch-size distribution; it is flushed on sync,
		// rotation, compaction, read, and close. | NoSync 显式以持久性换吞吐；每次
		// 轮转刷新整个封段会在大记录测试与基准中造成数百毫秒停顿。自适应用户态写缓冲
		// 进一步消除每个小批次一次写系统调用，并随观测到的批次大小分布增长；它会在
		// 同步、轮转、压缩、读取与关闭时刷新。
		opts = append(opts,
			wal.WithSyncPolicy(wal.SyncNever()),
			wal.WithSyncOnRotate(false),
			wal.WithWriteBuffer(-1),
		)
	}
	log, err := wal.Open(dir, opts...)
	if err != nil {
		return nil, walRecovery{}, snapshotMarker{}, mapWALOpenError(err)
	}
	st := &walStore{log: log}
	rec, marker, err := st.replay()
	if err != nil {
		_ = log.Close()
		return nil, walRecovery{}, snapshotMarker{}, err
	}
	return st, rec, marker, nil
}

// replay rebuilds the recovery state from committed records. The first pass
// finds the newest snapshot marker so the second pass can preset the log base;
// a local snapshot image completes asynchronously, so entries beyond its base
// may be durable before the marker record itself. Without the preset, replay
// would see a gap at those entries and reject a valid WAL. | replay 从已提交记录
// 重建恢复状态。第一遍查找最新快照标记，第二遍据此预设日志基点；本地快照镜像异步
// 完成，因此其基点之后的日志项可能先于标记记录持久化。若不预设，重放会在这些日志项
// 处看到缺口并拒绝一份有效 WAL。
func (st *walStore) replay() (walRecovery, snapshotMarker, error) {
	marker, err := st.scanMarker()
	if err != nil {
		return walRecovery{}, snapshotMarker{}, err
	}
	var rec walRecovery
	if marker.found {
		rec.base = marker.index
	}
	r, err := st.log.NewReader(wal.From(0))
	if err != nil {
		return walRecovery{}, snapshotMarker{}, mapWALReadError(err)
	}
	for {
		record, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = r.Close()
			return walRecovery{}, snapshotMarker{}, mapWALReadError(err)
		}
		// Reader views expire on the next call; Clone owns one allocation for
		// Key+Data, and decoded Entry.Data slices alias it safely afterwards. |
		// Reader 视图在下一次调用后失效；Clone 为 Key+Data 拥有一次分配，解码出的
		// Entry.Data 之后可安全引用它。
		owned := record.Clone()
		b, err := decodeWALBatch(owned.Data)
		if err != nil {
			_ = r.Close()
			return walRecovery{}, snapshotMarker{}, err
		}
		st.recs = append(st.recs, walRecordMetaOf(record.LSN, b))
		if err := rec.apply(b); err != nil {
			_ = r.Close()
			return walRecovery{}, snapshotMarker{}, err
		}
	}
	if err := r.Close(); err != nil {
		return walRecovery{}, snapshotMarker{}, mapWALReadError(err)
	}
	if len(rec.entries) > 0 && rec.entries[0].Index != rec.base+1 {
		return walRecovery{}, snapshotMarker{}, errs.Detail(ErrCorrupt,
			"WAL starts at %d, snapshot ends at %d", rec.entries[0].Index, rec.base)
	}
	return rec, marker, nil
}

// scanMarker returns the newest snapshot marker without retaining any record
// view. Entries are discarded, so this pass performs no payload copy. |
// scanMarker 返回最新快照标记且不保留任何记录视图。日志项被丢弃，因此该遍不做
// 负载复制。
func (st *walStore) scanMarker() (snapshotMarker, error) {
	var marker snapshotMarker
	r, err := st.log.NewReader(wal.From(0))
	if err != nil {
		return snapshotMarker{}, mapWALReadError(err)
	}
	for {
		record, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = r.Close()
			return snapshotMarker{}, mapWALReadError(err)
		}
		b, err := decodeWALBatch(record.Data)
		if err != nil {
			_ = r.Close()
			return snapshotMarker{}, err
		}
		if b.hasSnapshot && (!marker.found || b.snapIndex > marker.index ||
			(b.snapIndex == marker.index && b.snapTerm >= marker.term)) {
			marker = snapshotMarker{index: b.snapIndex, term: b.snapTerm, found: true}
		}
	}
	if err := r.Close(); err != nil {
		return snapshotMarker{}, mapWALReadError(err)
	}
	return marker, nil
}

// append encodes one batch as one ydx/wal record. The returned LSN is tracked so
// Compact can release whole records without decoding them again. | append 将一个
// 批次编码为一条 ydx/wal 记录；返回的 LSN 被记录，使 Compact 无需再次解码即可释放
// 整条记录。
func (st *walStore) append(batch PersistBatch) error {
	if batch.HardState == nil && batch.Truncate == 0 && len(batch.Entries) == 0 && batch.Snapshot == nil {
		return nil
	}
	st.buf = encodeWALBatch(st.buf[:0], batch)
	if len(st.buf) > maxWALRecord {
		return errs.Detail(ErrTooLarge, "WAL record %d bytes", len(st.buf))
	}
	// FileStorage serializes every mutation through its mutex, so the direct path
	// avoids the writer-queue round trip without racing rotation or compaction. |
	// FileStorage 通过互斥锁串行化全部变更，因此直接路径可省去写队列往返，且不会
	// 与轮转或压缩竞争。
	lsn, err := st.log.AppendDirect(context.Background(), wal.Record{Data: st.buf})
	if err != nil {
		return mapWALWriteError(err)
	}
	st.recs = append(st.recs, walRecordMetaOf(lsn, walBatchOf(batch)))
	return nil
}

// walBatchOf converts a write batch into the decoded-batch view used by the
// record summary. | walBatchOf 把写入批次转换为记录汇总使用的已解码视图。
func walBatchOf(batch PersistBatch) walBatch {
	b := walBatch{
		hs:       batch.HardState,
		entries:  batch.Entries,
		truncate: batch.Truncate,
	}
	if batch.Snapshot != nil {
		b.hasSnapshot = true
		b.snapIndex = batch.Snapshot.Index
		b.snapTerm = batch.Snapshot.Term
		b.snapReset = batch.SnapshotReplacesLog
	}
	return b
}

// compact logically removes the covered prefix while retaining every record
// recovery still needs. Truncation is prefix-only, so the boundary is the first
// record that must survive: a hard-state-only record, an entry or marker beyond
// index, or the newest snapshot marker. | compact 逻辑删除已覆盖前缀，同时保留恢复
// 仍需的每条记录。截断只能作用于前缀，因此边界取第一条必须存活的记录：仅含硬状态的
// 记录、索引超过 index 的日志项或标记，或最新快照标记。
func (st *walStore) compact(index uint64) error {
	latestMarker := st.newestMarker()
	if latestMarker < 0 {
		// Without a durable marker the snapshot base cannot be rebuilt; keeping
		// every record is the only safe choice. | 没有持久标记就无法重建快照基点，
		// 保留全部记录是唯一安全的选择。
		return nil
	}
	cut := len(st.recs)
	for i := range st.recs {
		m := &st.recs[i]
		if m.stateOnly || m.maxIndex > index || i == latestMarker {
			cut = i
			break
		}
	}
	if cut == 0 || cut >= len(st.recs) {
		return nil
	}
	if _, err := st.log.Truncate(st.recs[cut].lsn); err != nil {
		return mapWALWriteError(err)
	}
	st.recs = append(st.recs[:0], st.recs[cut:]...)
	return nil
}

// compactAll releases every record before the newest marker. InstallSnapshot
// replaces the whole prior log, so this is its reset path. | compactAll 释放最新
// 标记之前的全部记录。InstallSnapshot 替换此前整段日志，因此这是它的重置路径。
func (st *walStore) compactAll() error {
	latestMarker := st.newestMarker()
	if latestMarker <= 0 {
		return nil
	}
	if _, err := st.log.Truncate(st.recs[latestMarker].lsn); err != nil {
		return mapWALWriteError(err)
	}
	st.recs = append(st.recs[:0], st.recs[latestMarker:]...)
	return nil
}

// close flushes and releases the ydx/wal directory. | close 刷新并释放 ydx/wal 目录。
func (st *walStore) close() error {
	if st == nil || st.log == nil {
		return nil
	}
	err := st.log.Close()
	st.log = nil
	return mapWALWriteError(err)
}

// mapWALOpenError maps ydx/wal open failures onto raft sentinels. | mapWALOpenError
// 把 ydx/wal 打开失败映射为 raft 哨兵。
func mapWALOpenError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, wal.ErrLocked):
		return errs.Wrap(err, ErrStorageLocked)
	case errors.Is(err, wal.ErrCorrupt), errors.Is(err, wal.ErrMissingSegment),
		errors.Is(err, wal.ErrUnsupported):
		return errs.Wrap(err, ErrCorrupt)
	default:
		return errs.Wrap(err, ErrStorage)
	}
}

// mapWALReadError maps ydx/wal replay failures onto raft sentinels. | mapWALReadError
// 把 ydx/wal 重放失败映射为 raft 哨兵。
func mapWALReadError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, wal.ErrClosed):
		return ErrStopped
	case errors.Is(err, wal.ErrCorrupt), errors.Is(err, wal.ErrMissingSegment),
		errors.Is(err, wal.ErrUnsupported):
		return errs.Wrap(err, ErrCorrupt)
	default:
		return errs.Wrap(err, ErrStorage)
	}
}

// mapWALWriteError maps ydx/wal mutation failures onto raft sentinels. | mapWALWriteError
// 把 ydx/wal 变更失败映射为 raft 哨兵。
func mapWALWriteError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, wal.ErrClosed):
		return ErrStopped
	case errors.Is(err, wal.ErrRecordTooLarge), errors.Is(err, wal.ErrTooLarge):
		return errs.Wrap(err, ErrTooLarge)
	default:
		return errs.Wrap(err, ErrStorage)
	}
}
