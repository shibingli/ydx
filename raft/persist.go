package raft

import (
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// maxPersistBatchBytes bounds one merged durable batch. It keeps a burst of
// large proposals from allocating an unbounded WAL buffer or exceeding the WAL
// record limit; a single oversized request is still processed alone so the
// storage layer can report the error. | maxPersistBatchBytes 限制一个合并持久批次，
// 避免大量大提案分配无界 WAL 缓冲区或超过 WAL 记录上限；单个超大请求仍单独处理，
// 由存储层报告错误。
const maxPersistBatchBytes = 32 << 20

// persistBytes estimates the encoded size of a request. | persistBytes 估算请求的
// 编码大小。
func persistBytes(req *persistRequest) int {
	if req == nil || len(req.batch.Entries) == 0 {
		return 0
	}
	total := len(req.batch.Entries) * 16
	for i := range req.batch.Entries {
		total += len(req.batch.Entries[i].Data)
	}
	return total
}

// persistRequest is one durable batch queued for the writer goroutine. | persistRequest
// 是排队给写协程的一个持久批次。
type persistRequest struct {
	batch      PersistBatch
	seq        uint64
	compact    uint64
	markerOnly bool
}

// snapshotFileResult reports the completion of an asynchronous local snapshot
// file write. The event loop then queues only the small WAL marker. |
// snapshotFileResult 报告异步本地快照文件写入完成。事件循环随后只排队小型 WAL
// 标记。
type snapshotFileResult struct {
	snap *Snapshot
	fn   func(error)
	err  error
}

// persistAck releases deferred protocol work after a durable write. maxSeq is
// the highest sequence included in the acked batch. | persistAck 在持久写完成后
// 释放延迟的协议工作。maxSeq 是被确认批次中的最高序号。
type persistAck struct {
	err    error
	maxSeq uint64
}

// deferredAction runs after the persistence with the same sequence completes.
// | deferredAction 在相同序号的持久化完成后运行。
type deferredAction struct {
	fn  func(error)
	seq uint64
}

// hardState snapshots the durable state for a batch. | hardState 为批次生成持久状态
// 快照。
func (n *Node) hardState() HardState {
	return HardState{Term: n.term, Vote: n.vote, Commit: n.committed}
}

// enqueuePersist appends a request to the ordered persist queue without ever
// blocking the Raft event loop. A bounded channel would let a slow snapshot
// write fill the queue; the event loop would then stop processing heartbeats
// and elections. The queue is consumed by the single persist goroutine in
// sequence order. | enqueuePersist 以永不阻塞 Raft 事件循环的方式把请求追加到有序
// 持久化队列。有界通道会在慢速快照写入时被填满，使事件循环停止处理心跳与选举。队列
// 由唯一的持久化协程按序号顺序消费。
func (n *Node) enqueuePersist(req *persistRequest) {
	n.persistMu.Lock()
	n.persistQueue = append(n.persistQueue, req)
	n.persistMu.Unlock()
	select {
	case n.persistNotify <- struct{}{}:
	default:
	}
}

// popPersist removes the oldest queued request. | popPersist 取出最旧的排队请求。
func (n *Node) popPersist() *persistRequest {
	n.persistMu.Lock()
	if len(n.persistQueue) == 0 {
		n.persistMu.Unlock()
		return nil
	}
	req := n.persistQueue[0]
	n.persistQueue[0] = nil
	n.persistQueue = n.persistQueue[1:]
	if len(n.persistQueue) == 0 {
		n.persistQueue = nil
	}
	n.persistMu.Unlock()
	return req
}

// persistDepth reports the number of queued persistence requests. | persistDepth
// 返回排队中的持久化请求数量。
func (n *Node) persistDepth() int {
	n.persistMu.Lock()
	depth := len(n.persistQueue)
	n.persistMu.Unlock()
	return depth
}

// persist queues a batch. compact, when non-zero, releases entries through that
// index after the batch is durable and reports failures without stopping the
// node: the snapshot marker already makes older entries ignorable. | persist
// 将批次入队。compact 非零时在批次持久化后释放该索引及之前的日志项；失败只报告而
// 不停止节点：快照标记已使更旧日志项可忽略。
func (n *Node) persist(batch PersistBatch, compact uint64, fn func(error)) uint64 {
	if n.immediateStore {
		err := n.storage.Persist(batch)
		if err == nil && compact > 0 {
			_ = n.storage.Compact(compact)
		}
		n.metrics.persistBatches.Add(1)
		if err != nil {
			n.metrics.persistErrors.Add(1)
			n.fatal(errs.Wrap(err, ErrStorage))
		}
		if fn != nil {
			fn(err)
		}
		return 0
	}
	n.persistSeq++
	seq := n.persistSeq
	if fn != nil {
		n.pending = append(n.pending, deferredAction{seq: seq, fn: fn})
	}
	req := &persistRequest{seq: seq, batch: batch, compact: compact}
	n.enqueuePersist(req)
	return seq
}

// persistHardState records term, vote and commit. | persistHardState 记录任期、选票
// 与提交索引。
func (n *Node) persistHardState() uint64 {
	hs := n.hardState()
	// A dedicated hard-state store keeps term/vote off the WAL queue. This is
	// critical while a follower is installing a large snapshot: otherwise the
	// vote would wait behind the image fsync and the group could stay leaderless
	// for the whole write. | 专用硬状态存储让 term/vote 绕过 WAL 队列。跟随者安装
	// 大快照时尤其关键：否则选票会排在镜像 fsync 之后，组可能在整个写入期间无
	// leader。
	if store, ok := n.storage.(HardStateStorage); ok {
		if err := store.PersistHardState(&hs); err != nil {
			n.metrics.persistErrors.Add(1)
			n.fatal(errs.Wrap(err, ErrStorage))
			return 0
		}
		n.metrics.persistBatches.Add(1)
		return 0
	}
	return n.persist(PersistBatch{HardState: &hs}, 0, nil)
}

// persistEntries records a log mutation and the hard state that accompanies it.
// | persistEntries 记录日志变更及随附的硬状态。
func (n *Node) persistEntries(entries []Entry, truncate uint64) uint64 {
	hs := n.hardState()
	return n.persist(PersistBatch{HardState: &hs, Truncate: truncate, Entries: entries}, 0, nil)
}

// persistSnapshot records a snapshot image and compacts storage through its
// index. replacesLog marks an InstallSnapshot whose entire prior log is stale.
// | persistSnapshot 记录快照镜像并压缩到该索引。replacesLog 标记整段旧日志都已
// 失效的 InstallSnapshot。
func (n *Node) persistSnapshot(snap *Snapshot, replacesLog bool, fn func(error)) uint64 {
	// A local image can be written and fsynced independently while WAL appends
	// continue. Only the small marker is queued afterwards. InstallSnapshot
	// stays synchronous because its marker resets the entire prior log and must
	// not race entries persisted after the image. | 本地镜像可独立写入并 fsync，
	// 同时 WAL 继续追加；随后只排队小型标记。InstallSnapshot 保持同步，因为其标记
	// 会重置此前整段日志，不能与镜像之后持久化的日志项竞争。
	if !replacesLog {
		if writer, ok := n.storage.(localSnapshotFileStorage); ok && !n.immediateStore {
			n.wg.Add(1)
			go func() {
				defer n.wg.Done()
				err := writer.WriteSnapshotFile(snap)
				select {
				case n.snapshotFileCh <- snapshotFileResult{snap: snap, fn: fn, err: err}:
				case <-n.stopCh:
				}
			}()
			return 0
		}
	}
	hs := n.hardState()
	return n.persist(PersistBatch{HardState: &hs, Snapshot: snap, SnapshotReplacesLog: replacesLog}, snap.Index, fn)
}

// persistSnapshotImage finalizes a streaming image outside the event loop and
// then queues its small WAL marker. | persistSnapshotImage 在事件循环之外完成
// 流式镜像定稿，随后只排队小型 WAL 标记。
func (n *Node) persistSnapshotImage(snap *Snapshot, image snapshotImage, fn func(error)) uint64 {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		err := image.Finalize()
		if err != nil {
			image.Abort()
		}
		select {
		case n.snapshotFileCh <- snapshotFileResult{snap: snap, fn: fn, err: err}:
		case <-n.stopCh:
			// No marker was written, so an uncommitted final file is garbage. |
			// 尚未写入标记，未提交的最终文件属于垃圾。
			image.Abort()
		}
	}()
	return 0
}

// handleSnapshotFileResult queues the WAL marker after an asynchronous local
// image write. The marker receives a new sequence number only now, so it cannot
// overtake WAL requests created while the image was being written. |
// handleSnapshotFileResult 在异步本地镜像写入后排队 WAL 标记。标记此时才分配新
// 序号，因此不会越过镜像写入期间产生的 WAL 请求。
func (n *Node) handleSnapshotFileResult(result snapshotFileResult) {
	if result.err != nil {
		n.fatal(errs.Wrap(result.err, ErrStorage))
		return
	}
	// A large image that will be sent in chunks no longer needs its heap copy;
	// senders read bounded slices on demand. Small images keep their payload so
	// a single MsgSnap does not touch the filesystem on the event loop. |
	// 将以分块发送的大镜像不再需要堆副本；发送方按需读取有界切片。小镜像保留负载，
	// 使单条 MsgSnap 不必在事件循环上访问文件系统。
	if result.snap != nil && result.snap.file != "" && n.snapshotChunkBytes > 0 &&
		result.snap.dataSize > int64(n.snapshotChunkBytes) {
		result.snap.Data = nil
	}
	n.persistSeq++
	seq := n.persistSeq
	if result.fn != nil {
		n.pending = append(n.pending, deferredAction{seq: seq, fn: result.fn})
	}
	hs := n.hardState()
	req := &persistRequest{
		seq:        seq,
		compact:    result.snap.Index,
		markerOnly: true,
		batch: PersistBatch{
			HardState: &hs,
			Snapshot:  &Snapshot{Index: result.snap.Index, Term: result.snap.Term},
		},
	}
	n.enqueuePersist(req)
}

// deferAction schedules fn after seq is durable. A zero sequence runs
// immediately because no durable write is involved. | deferAction 在 seq 持久化后
// 调度 fn。零序号表示不涉及持久写，立即执行。
func (n *Node) deferAction(seq uint64, fn func(error)) {
	if fn == nil {
		return
	}
	if seq == 0 {
		fn(n.Err())
		return
	}
	n.pending = append(n.pending, deferredAction{seq: seq, fn: fn})
}

// persistLoop is the only goroutine that calls Storage.Persist. It merges
// adjacent non-snapshot requests into one durable batch, amortizing fsync across
// concurrent proposals and followers. | persistLoop 是唯一调用 Storage.Persist 的
// 协程。它将相邻的非快照请求合并为一个持久批次，把 fsync 成本分摊到并发提案与跟随者
// 上。
func (n *Node) persistLoop() {
	defer n.wg.Done()
	var buf [64]*persistRequest
	for {
		first := n.popPersist()
		if first == nil {
			select {
			case <-n.stopCh:
				return
			case <-n.persistNotify:
				continue
			}
		}
		reqs := n.collectPersist(first, buf[:0])
		measure := true
		for _, req := range reqs {
			if req.batch.Snapshot != nil && !req.markerOnly {
				measure = false
				break
			}
		}
		start := time.Now()
		n.processPersistReqs(reqs)
		if measure {
			n.recordPersistLatency(time.Since(start))
		}
		for i := range reqs {
			reqs[i] = nil
		}
	}
}

// recordPersistLatency keeps an exponential moving average of durable batch
// cost. It is updated only by the persist goroutine. | recordPersistLatency 维护
// 持久批次开销的指数移动平均，只由持久化协程更新。
func (n *Node) recordPersistLatency(elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	next := int64(elapsed)
	if old := n.persistLatency.Load(); old > 0 {
		next = (old*7 + next) / 8
	}
	n.persistLatency.Store(next)
}

// persistWindow adapts the fixed group-commit base to the observed fsync cost
// and queued backlog. A window of half the measured fsync lets several requests
// share one sync without doubling the tail latency; deeper queues widen it
// further, bounded to avoid unbounded proposal delay. Zero keeps the feature
// disabled. | persistWindow 根据实测 fsync 成本与排队积压自适应调整固定组提交
// 基数。取实测 fsync 的一半可让多个请求共享一次 sync 而不过度延长尾延迟；队列越深
// 窗口越大，并设有上限避免提案延迟无界增长。零值保持关闭。
func (n *Node) persistWindow() time.Duration {
	base := n.cfg.PersistBatchDelay
	if base <= 0 {
		return 0
	}
	window := base
	if latency := time.Duration(n.persistLatency.Load()); latency > 0 {
		if target := latency / 2; target > window {
			window = target
		}
	}
	depth := n.persistDepth()
	switch {
	case depth >= 32:
		window *= 4
	case depth >= 8:
		window *= 2
	}
	limit := base * 8
	if limit < time.Millisecond {
		limit = time.Millisecond
	}
	if limit > 5*time.Millisecond {
		limit = 5 * time.Millisecond
	}
	if limit < base {
		// A configured base above the adaptive cap is still honored. | 高于自适应
		// 上限的显式基础窗口仍然生效。
		limit = base
	}
	if window > limit {
		window = limit
	}
	return window
}

// collectPersist merges queued write requests. When PersistBatchDelay is set,
// the first non-snapshot request opens a short group-commit window so concurrent
// requests share one storage fsync. Snapshot ordering is preserved: a snapshot
// request never waits, and later requests still queue behind it. | collectPersist
// 合并排队的写请求。设置 PersistBatchDelay 时，首个非快照请求开启短暂的组提交
// 窗口，使并发请求共享一次存储 fsync。快照顺序保持不变：快照请求从不等待，其后
// 请求仍在它之后排队。
func (n *Node) collectPersist(first *persistRequest, reqs []*persistRequest) []*persistRequest {
	reqs = append(reqs, first)
	if delay := n.persistWindow(); delay > 0 && first.batch.Snapshot == nil {
		timer := time.NewTimer(delay)
		for len(reqs) < 64 {
			for {
				req := n.popPersist()
				if req == nil {
					break
				}
				reqs = append(reqs, req)
			}
			if len(reqs) >= 64 {
				break
			}
			select {
			case <-n.persistNotify:
			case <-timer.C:
				timer.Stop()
				return reqs
			case <-n.stopCh:
				timer.Stop()
				return reqs
			}
		}
		timer.Stop()
	}
	for len(reqs) < 64 {
		req := n.popPersist()
		if req == nil {
			return reqs
		}
		reqs = append(reqs, req)
	}
	return reqs
}

// persistLastIndex returns the last entry index a request contributes. | persistLastIndex
// 返回请求贡献的最后日志索引。
func persistLastIndex(req *persistRequest) (uint64, bool) {
	if req == nil || len(req.batch.Entries) == 0 {
		return 0, false
	}
	return req.batch.Entries[len(req.batch.Entries)-1].Index, true
}

// persistMergeable reports whether req can extend a merged batch ending at last.
// Duplicate or overlapping entry ranges must not be coalesced: the WAL entry
// encoding uses index deltas and requires a strictly contiguous range. A
// truncating request is mergeable when its truncation point joins the current
// range; its entries then replace the overlapping suffix. | persistMergeable 报告
// req 能否扩展以 last 结尾的合并批次。重复或重叠的日志区间不得合并：WAL 日志项编码
// 使用索引增量，要求严格连续。截断请求在截断点与当前区间相接时可合并，其日志项会
// 替换重叠后缀。
func persistMergeable(last uint64, hasEntries bool, req *persistRequest) bool {
	if req == nil {
		return false
	}
	b := req.batch
	if b.Truncate > 0 {
		if len(b.Entries) == 0 {
			return false
		}
		if b.Entries[0].Index != b.Truncate {
			return false
		}
		return !hasEntries || b.Truncate <= last+1
	}
	if len(b.Entries) == 0 {
		return true
	}
	return !hasEntries || b.Entries[0].Index == last+1
}

// processPersistReqs splits snapshot requests from mergeable groups. | processPersistReqs
// 将快照请求与可合并分组分开处理。
func (n *Node) processPersistReqs(reqs []*persistRequest) {
	i := 0
	for i < len(reqs) {
		if reqs[i].markerOnly {
			// A deferred local snapshot marker can share one WAL record and one
			// fsync with entries that immediately follow its base. Combining is
			// only safe for a contiguous range after the snapshot index. |
			// 延迟的本地快照标记可与紧接其基点的日志项共享一条 WAL 记录和一次
			// fsync。只有快照索引之后的连续区间才能安全合并。
			j := i + 1
			bytes := 0
			last := reqs[i].batch.Snapshot.Index
			for j < len(reqs) && !reqs[j].markerOnly && reqs[j].batch.Snapshot == nil {
				next := persistBytes(reqs[j])
				if bytes+next > maxPersistBatchBytes || !persistMergeable(last, true, reqs[j]) {
					break
				}
				if nextLast, ok := persistLastIndex(reqs[j]); ok {
					last = nextLast
				}
				bytes += next
				j++
			}
			if j == i+1 {
				n.persistOne(reqs[i])
			} else {
				n.persistMarkerGroup(reqs[i:j])
			}
			i = j
			continue
		}
		if reqs[i].batch.Snapshot != nil {
			n.persistOne(reqs[i])
			i++
			continue
		}
		j := i + 1
		bytes := persistBytes(reqs[i])
		last, hasEntries := persistLastIndex(reqs[i])
		for j < len(reqs) && reqs[j].batch.Snapshot == nil {
			next := persistBytes(reqs[j])
			if bytes+next > maxPersistBatchBytes {
				break
			}
			if !persistMergeable(last, hasEntries, reqs[j]) {
				break
			}
			if nextLast, ok := persistLastIndex(reqs[j]); ok {
				last = nextLast
				hasEntries = true
			}
			bytes += next
			j++
		}
		n.persistGroup(reqs[i:j])
		i = j
	}
}

// persistOne writes one snapshot request and then compacts. Compaction failure
// is logged rather than fatal because the durable marker already makes covered
// entries ignorable. | persistOne 写入一个快照请求并随后压缩。压缩失败只记录日志
// 而不致命，因为持久标记已使被覆盖的日志项可忽略。
func (n *Node) persistOne(req *persistRequest) {
	var err error
	if req.markerOnly {
		writer, ok := n.storage.(localSnapshotFileStorage)
		if !ok {
			err = errs.Detail(ErrUnsupported, "storage does not support deferred snapshot markers | 存储不支持延迟快照标记")
		} else {
			err = writer.PersistLocalSnapshotMarker(req.batch.Snapshot, req.batch.HardState)
		}
	} else {
		err = n.storage.Persist(req.batch)
	}
	if err == nil && req.compact > 0 {
		if cerr := n.storage.Compact(req.compact); cerr != nil {
			n.logf("warn", "raft storage compact failed | raft 存储压缩失败",
				ydlog.Uint64("node", uint64(n.id)), ydlog.Err(cerr))
		}
	}
	if err != nil {
		n.metrics.persistErrors.Add(1)
	}
	n.sendPersistAck(req.seq, err)
}

// mergePersistEntries merges requests into one entry batch, preserving truncate
// ordering and taking the newest hard state. Snapshot fields are deliberately
// ignored so callers can merge only the non-snapshot parts. | mergePersistEntries
// 将请求合并为单个日志项批次，保持截断顺序并采用最新硬状态。快照字段被有意忽略，
// 调用方只合并非快照部分。
func mergePersistEntries(reqs []*persistRequest) (PersistBatch, uint64) {
	var hs *HardState
	truncate := uint64(0)
	total := 0
	for _, req := range reqs {
		if req.batch.Truncate == 0 {
			total += len(req.batch.Entries)
		}
	}
	entries := make([]Entry, 0, total)
	maxSeq := uint64(0)
	for _, req := range reqs {
		if req.batch.HardState != nil {
			h := *req.batch.HardState
			hs = &h
		}
		if req.batch.Truncate > 0 {
			t := req.batch.Truncate
			if truncate == 0 || t < truncate {
				truncate = t
			}
			cut := len(entries)
			for cut > 0 && entries[cut-1].Index >= t {
				cut--
			}
			entries = entries[:cut]
		}
		entries = append(entries, req.batch.Entries...)
		if req.seq > maxSeq {
			maxSeq = req.seq
		}
	}
	return PersistBatch{HardState: hs, Truncate: truncate, Entries: entries}, maxSeq
}

// persistMarkerGroup writes a deferred local snapshot marker and its following
// WAL requests in one durable call. | persistMarkerGroup 在一次持久调用中写入延迟
// 本地快照标记及其后的 WAL 请求。
func (n *Node) persistMarkerGroup(reqs []*persistRequest) {
	marker := reqs[0]
	batch, maxSeq := mergePersistEntries(reqs)
	writer, ok := n.storage.(localSnapshotFileStorage)
	var err error
	if !ok {
		err = errs.Detail(ErrUnsupported, "storage does not support deferred snapshot markers | 存储不支持延迟快照标记")
	} else {
		err = writer.PersistLocalSnapshotMarkerBatch(marker.batch.Snapshot, batch)
	}
	if err == nil && marker.compact > 0 {
		if cerr := n.storage.Compact(marker.compact); cerr != nil {
			n.logf("warn", "raft storage compact failed | raft 存储压缩失败",
				ydlog.Uint64("node", uint64(n.id)), ydlog.Err(cerr))
		}
	}
	if err != nil {
		n.metrics.persistErrors.Add(1)
	}
	n.sendPersistAck(maxSeq, err)
}

// persistGroup merges adjacent non-snapshot requests. | persistGroup 合并相邻的非快照
// 请求。
func (n *Node) persistGroup(reqs []*persistRequest) {
	if len(reqs) == 1 {
		req := reqs[0]
		err := n.storage.Persist(req.batch)
		if err != nil {
			n.metrics.persistErrors.Add(1)
		}
		n.sendPersistAck(req.seq, err)
		return
	}
	batch, maxSeq := mergePersistEntries(reqs)
	err := n.storage.Persist(batch)
	if err != nil {
		n.metrics.persistErrors.Add(1)
	}
	n.sendPersistAck(maxSeq, err)
}

// sendPersistAck hands one durable result to the event loop. | sendPersistAck 将
// 一个持久化结果交给事件循环。
func (n *Node) sendPersistAck(seq uint64, err error) {
	select {
	case n.persistAckCh <- persistAck{maxSeq: seq, err: err}:
	case <-n.stopCh:
	}
}

// handlePersistAck runs deferred protocol work in sequence order. | handlePersistAck
// 按序号顺序运行延迟的协议工作。
func (n *Node) handlePersistAck(ack persistAck) {
	if ack.err != nil {
		n.fatal(errs.Wrap(ack.err, ErrStorage))
		return
	}
	n.metrics.persistBatches.Add(1)
	for len(n.pending) > 0 && n.pending[0].seq <= ack.maxSeq {
		d := n.pending[0]
		n.pending[0] = deferredAction{}
		n.pending = n.pending[1:]
		d.fn(nil)
	}
	if len(n.pending) == 0 && cap(n.pending) > 64 {
		n.pending = nil
	}
	// Deferred actions may have advanced persistedIndex without advancing the
	// commit index; release any committed entries that are now durable. | 延迟动作
	// 可能推进了 persistedIndex 而未推进提交索引；释放现在已持久化的已提交日志项。
	n.advanceApply()
}
