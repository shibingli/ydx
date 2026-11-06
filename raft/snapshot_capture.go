package raft

import (
	"errors"
	"io"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// snapshotRequest asks the apply worker to capture the current state. | snapshotRequest
// 请求 apply 协程捕获当前状态。
type snapshotRequest struct {
	done chan error
}

// snapshotConfRequest asks the event loop for the configuration at an applied
// index before a streaming image reserves its header. | snapshotConfRequest 在
// 流式镜像预留头部前向事件循环查询某个已应用索引处的配置。
type snapshotConfRequest struct {
	reply chan ConfState
	index uint64
}

// snapshotReady carries a captured image to the event loop for persistence.
// | snapshotReady 将捕获的镜像交给事件循环持久化。
type snapshotReady struct {
	err     error
	request *snapshotRequest
	image   snapshotImage
	snap    *Snapshot
	data    []byte
	index   uint64
	term    uint64
}

// snapshotSafe wraps FSM.Snapshot with panic containment. | snapshotSafe 用 panic
// 隔离包装 FSM.Snapshot。
func (n *Node) snapshotSafe() (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.Detail(ErrFSMPanic, "snapshot: %v", r)
		}
	}()
	return n.fsm.Snapshot()
}

// snapshotStreamSafe wraps StreamingFSM.SnapshotTo with panic containment. |
// snapshotStreamSafe 用 panic 隔离包装 StreamingFSM.SnapshotTo。
func (n *Node) snapshotStreamSafe(fsm StreamingFSM, w io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.Detail(ErrFSMPanic, "snapshot stream: %v", r)
		}
	}()
	return fsm.SnapshotTo(w)
}

// snapshotConf returns the configuration at index from the event loop. The apply
// worker must not read confHistory directly; it is owned by the event loop. |
// snapshotConf 从事件循环获取 index 处的配置。apply 协程不得直接读取 confHistory；
// 它由事件循环所有。
func (n *Node) snapshotConf(index uint64) (ConfState, bool) {
	req := &snapshotConfRequest{index: index, reply: make(chan ConfState, 1)}
	select {
	case n.snapshotConfCh <- req:
	case <-n.stopCh:
		return ConfState{}, false
	}
	select {
	case conf := <-req.reply:
		return conf, true
	case <-n.stopCh:
		return ConfState{}, false
	}
}

// shouldSnapshot reports whether the applied-entry threshold was crossed.
// | shouldSnapshot 报告是否跨过已应用日志项阈值。
func (n *Node) shouldSnapshot() bool {
	if n.snapshotEntries == 0 {
		return false
	}
	applied := n.applied.Load()
	base := n.lastSnapshot.Load()
	return applied > base && applied-base >= n.snapshotEntries
}

// createSnapshot captures the state machine at the current applied index. It
// returns true when an image was sent to the event loop. | createSnapshot 在当前
// 已应用索引处捕获状态机。镜像已发送给事件循环时返回 true。
func (n *Node) createSnapshot(req *snapshotRequest) bool {
	index := n.applied.Load()
	if index == 0 || index <= n.lastSnapshot.Load() {
		if req != nil {
			n.snapshotFailure(req, ErrSnapshotOutOfDate)
		}
		return false
	}
	// A streaming FSM can write its image straight into the storage backend. The
	// configuration must be known before reserving the file header, so ask the
	// event loop for the configuration at this applied index. | 流式 FSM 可直接把
	// 镜像写入存储后端。预留文件头部前必须知道配置，因此向事件循环查询该已应用
	// 索引处的配置。
	if stream, ok := n.fsm.(StreamingFSM); ok {
		if storage, ok := n.storage.(streamingSnapshotStorage); ok {
			conf, ok := n.snapshotConf(index)
			if !ok {
				if req != nil {
					sendErr(req.done, ErrStopped)
				}
				return false
			}
			snap := &Snapshot{Index: index, Term: n.appliedTerm, ConfState: conf}
			image, err := storage.NewSnapshotImage(snap, conf)
			if err != nil {
				n.metrics.applyErrors.Add(1)
				n.logf("warn", "raft snapshot image failed | raft 快照镜像失败",
					ydlog.Uint64("node", uint64(n.id)), ydlog.Err(err))
				if req != nil {
					n.snapshotFailure(req, err)
				}
				return false
			}
			if err := n.snapshotStreamSafe(stream, image); err != nil {
				image.Abort()
				n.metrics.applyErrors.Add(1)
				n.logf("warn", "raft snapshot stream failed | raft 快照流写入失败",
					ydlog.Uint64("node", uint64(n.id)), ydlog.Err(err))
				if req != nil {
					n.snapshotFailure(req, err)
				}
				return false
			}
			if err := image.Seal(); err != nil {
				image.Abort()
				n.metrics.applyErrors.Add(1)
				n.logf("warn", "raft snapshot seal failed | raft 快照封存失败",
					ydlog.Uint64("node", uint64(n.id)), ydlog.Err(err))
				if req != nil {
					n.snapshotFailure(req, err)
				}
				return false
			}
			ready := snapshotReady{index: index, term: n.appliedTerm,
				snap: snap, image: image, request: req}
			select {
			case n.snapshotReadyCh <- ready:
				return true
			case <-n.stopCh:
				image.Abort()
				if req != nil {
					sendErr(req.done, ErrStopped)
				}
				return false
			}
		}
	}
	data, err := n.snapshotSafe()
	if err != nil {
		n.metrics.applyErrors.Add(1)
		n.logf("warn", "raft snapshot failed | raft 快照失败",
			ydlog.Uint64("node", uint64(n.id)), ydlog.Err(err))
		if req != nil {
			n.snapshotFailure(req, err)
		}
		return false
	}
	ready := snapshotReady{index: index, term: n.appliedTerm, data: data, request: req}
	select {
	case n.snapshotReadyCh <- ready:
		return true
	case <-n.stopCh:
		if req != nil {
			sendErr(req.done, ErrStopped)
		}
		return false
	}
}

// snapshotFailure reports a capture that never produced an image to the event
// loop. The event loop owns snapshotting and must clear it even when the apply
// worker fails before sending a ready image. | snapshotFailure 将未能产出镜像的
// 捕获报告给事件循环。快照状态由事件循环持有，即使 apply 协程在发送就绪镜像前失败，
// 也必须清除它。
func (n *Node) snapshotFailure(req *snapshotRequest, err error) {
	select {
	case n.snapshotReadyCh <- snapshotReady{err: err, request: req}:
	case <-n.stopCh:
		sendErr(req.done, ErrStopped)
	}
}

// handleSnapshotRequest starts a manual snapshot or queues it behind one in
// flight. | handleSnapshotRequest 启动手动快照，或将其排在进行中快照之后。
func (n *Node) handleSnapshotRequest(req *snapshotRequest) {
	if n.snapshotting {
		n.snapshotWaiters = append(n.snapshotWaiters, req.done)
		return
	}
	n.snapshotting = true
	select {
	case n.applySnapshotCh <- req:
	case <-n.stopCh:
		n.snapshotting = false
		sendErr(req.done, ErrStopped)
	}
}

// handleSnapshotReady persists a captured image, compacts memory, and resolves
// the caller. | handleSnapshotReady 持久化捕获的镜像、压缩内存并结束调用方。
func (n *Node) handleSnapshotReady(ready snapshotReady) {
	if ready.err != nil {
		if ready.image != nil {
			ready.image.Abort()
		}
		if !errors.Is(ready.err, ErrSnapshotOutOfDate) {
			n.metrics.applyErrors.Add(1)
		}
		n.snapshotting = false
		n.signalSnapshotDone()
		if ready.request != nil {
			sendErr(ready.request.done, ready.err)
		}
		n.startNextSnapshot()
		return
	}
	if ready.index == 0 {
		if ready.image != nil {
			ready.image.Abort()
		}
		n.snapshotting = false
		n.signalSnapshotDone()
		if ready.request != nil {
			sendErr(ready.request.done, ErrSnapshotOutOfDate)
		}
		n.startNextSnapshot()
		return
	}
	// A remote InstallSnapshot may have advanced the log while the state machine
	// was capturing this image. Persisting and publishing an older image would
	// regress latestSnapshot/confBase below log.snapshotIndex and can send stale
	// snapshots in a loop. | 状态机捕获镜像期间，远端 InstallSnapshot 可能已推进
	// 日志。持久化并发布旧镜像会把 latestSnapshot/confBase 回退到
	// log.snapshotIndex 之下，并可能循环发送过期快照。
	if ready.index <= n.lastSnapshot.Load() || ready.index <= n.log.snapshotIndex {
		if ready.image != nil {
			ready.image.Abort()
		}
		n.snapshotting = false
		n.signalSnapshotDone()
		if ready.request != nil {
			sendErr(ready.request.done, ErrSnapshotOutOfDate)
		}
		n.startNextSnapshot()
		return
	}
	conf := n.configAt(ready.index)
	var snap *Snapshot
	if ready.image != nil {
		snap = ready.snap
		if snap == nil {
			ready.image.Abort()
			n.snapshotting = false
			n.signalSnapshotDone()
			if ready.request != nil {
				sendErr(ready.request.done, ErrStorage)
			}
			n.startNextSnapshot()
			return
		}
		snap.Index = ready.index
		snap.Term = ready.term
		snap.ConfState = conf.confState()
	} else {
		snap = &Snapshot{
			Index:     ready.index,
			Term:      ready.term,
			ConfState: conf.confState(),
			Data:      ready.data,
		}
	}
	n.snapshotting = true
	n.activeSnapshotReq = ready.request
	done := n.snapshotDoneCallback(snap, conf, ready.request)
	if ready.image != nil {
		n.persistSnapshotImage(snap, ready.image, done)
	} else {
		n.persistSnapshot(snap, false, done)
	}
}

// snapshotDoneCallback releases snapshot state after the image and marker are
// durable and publishes the new in-memory base. | snapshotDoneCallback 在镜像与
// 标记持久化后释放快照状态并发布新的内存基点。
func (n *Node) snapshotDoneCallback(snap *Snapshot, conf *membership, req *snapshotRequest) func(error) {
	return func(err error) {
		n.activeSnapshotReq = nil
		n.snapshotting = false
		n.signalSnapshotDone()
		if err == nil {
			// Re-check at durability time: another snapshot may have completed
			// while this one was being written. Never move the in-memory base
			// backwards. | 持久化完成时重新检查：该镜像写入期间可能有更新的快照
			// 完成，绝不能把内存基点向后移动。
			if snap.Index > n.lastSnapshot.Load() && snap.Index > n.log.snapshotIndex {
				n.latestSnapshot = snap
				n.lastSnapshot.Store(snap.Index)
				if snap.Index <= n.log.lastIndex {
					_ = n.log.compact(snap.Index, n.snapshotCatchUp)
				}
				n.compactConfig(snap.Index, conf)
			}
			n.metrics.snapshotsCreated.Add(1)
		}
		if req != nil {
			sendErr(req.done, err)
		}
		n.startNextSnapshot()
	}
}

// signalSnapshotDone wakes the apply worker so it may capture another image.
// | signalSnapshotDone 唤醒 apply 协程以捕获下一张镜像。
func (n *Node) signalSnapshotDone() {
	select {
	case n.snapshotDoneCh <- struct{}{}:
	default:
	}
}

// startNextSnapshot starts the next queued manual snapshot. | startNextSnapshot 启动
// 下一个排队的手动快照。
func (n *Node) startNextSnapshot() {
	if len(n.snapshotWaiters) == 0 {
		return
	}
	ch := n.snapshotWaiters[0]
	n.snapshotWaiters = n.snapshotWaiters[1:]
	req := &snapshotRequest{done: ch}
	n.snapshotting = true
	select {
	case n.applySnapshotCh <- req:
	case <-n.stopCh:
		n.snapshotting = false
		sendErr(ch, ErrStopped)
	}
}

// compactConfig folds configuration history through index into the snapshot
// base. | compactConfig 将 index 及之前的配置历史折叠进快照基点。
func (n *Node) compactConfig(index uint64, conf *membership) {
	n.confBase = conf
	n.confBaseIndex = index
	cut := 0
	for cut < len(n.confHistory) && n.confHistory[cut].index <= index {
		cut++
	}
	if cut > 0 {
		n.confHistory = append([]confVersion(nil), n.confHistory[cut:]...)
	}
	if n.conf.joint() {
		if n.jointIndex < index {
			n.jointIndex = index
		}
	} else {
		n.jointIndex = 0
	}
}
