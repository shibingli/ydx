package raft

import (
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// persistRequest is one durable batch queued for the writer goroutine. | persistRequest
// 是排队给写协程的一个持久批次。
type persistRequest struct {
	seq     uint64
	batch   PersistBatch
	compact uint64
}

// persistAck releases deferred protocol work after a durable write. maxSeq is
// the highest sequence included in the acked batch. | persistAck 在持久写完成后
// 释放延迟的协议工作。maxSeq 是被确认批次中的最高序号。
type persistAck struct {
	maxSeq uint64
	err    error
}

// deferredAction runs after the persistence with the same sequence completes.
// | deferredAction 在相同序号的持久化完成后运行。
type deferredAction struct {
	seq uint64
	fn  func(error)
}

// hardState snapshots the durable state for a batch. | hardState 为批次生成持久状态
// 快照。
func (n *Node) hardState() HardState {
	return HardState{Term: n.term, Vote: n.vote, Commit: n.committed}
}

// persist queues a batch. compact, when non-zero, asks the storage to release
// entries through that index after the batch is durable. | persist 将批次入队。
// compact 非零时，在批次持久化后请求存储释放该索引及之前的日志项。
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
	select {
	case n.persistCh <- req:
	case <-n.stopCh:
	}
	return seq
}

// persistHardState records term, vote and commit. | persistHardState 记录任期、选票
// 与提交索引。
func (n *Node) persistHardState() uint64 {
	hs := n.hardState()
	return n.persist(PersistBatch{HardState: &hs}, 0, nil)
}

// persistEntries records a log mutation and the hard state that accompanies it.
// | persistEntries 记录日志变更及随附的硬状态。
func (n *Node) persistEntries(entries []Entry, truncate uint64) uint64 {
	hs := n.hardState()
	return n.persist(PersistBatch{HardState: &hs, Truncate: truncate, Entries: entries}, 0, nil)
}

// persistSnapshot records a snapshot image and compacts storage after it.
// replacesLog marks an InstallSnapshot whose entire prior log is stale.
// | persistSnapshot 记录快照镜像并在其后压缩存储。replacesLog 标记整段旧日志都已
// 失效的 InstallSnapshot。
func (n *Node) persistSnapshot(snap *Snapshot, replacesLog bool, fn func(error)) uint64 {
	hs := n.hardState()
	return n.persist(PersistBatch{HardState: &hs, Snapshot: snap, SnapshotReplacesLog: replacesLog}, snap.Index, fn)
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
		select {
		case <-n.stopCh:
			return
		case first := <-n.persistCh:
			reqs := n.collectPersist(first, buf[:0])
			n.processPersistReqs(reqs)
			for i := range reqs {
				reqs[i] = nil
			}
		}
	}
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
	if delay := n.cfg.PersistBatchDelay; delay > 0 && first.batch.Snapshot == nil {
		timer := time.NewTimer(delay)
		for len(reqs) < 64 {
			select {
			case req := <-n.persistCh:
				reqs = append(reqs, req)
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
		select {
		case req := <-n.persistCh:
			reqs = append(reqs, req)
		default:
			return reqs
		}
	}
	return reqs
}

// processPersistReqs splits snapshot requests from mergeable groups. | processPersistReqs
// 将快照请求与可合并分组分开处理。
func (n *Node) processPersistReqs(reqs []*persistRequest) {
	i := 0
	for i < len(reqs) {
		if reqs[i].batch.Snapshot != nil {
			n.persistOne(reqs[i])
			i++
			continue
		}
		j := i + 1
		for j < len(reqs) && reqs[j].batch.Snapshot == nil {
			j++
		}
		n.persistGroup(reqs[i:j])
		i = j
	}
}

// persistOne writes one snapshot request and then compacts. | persistOne 写入一个
// 快照请求并随后压缩。
func (n *Node) persistOne(req *persistRequest) {
	err := n.storage.Persist(req.batch)
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
	err := n.storage.Persist(PersistBatch{HardState: hs, Truncate: truncate, Entries: entries})
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
}
