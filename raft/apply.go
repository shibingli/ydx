package raft

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/shibingli/ydx/errs"
)

// appliedNotifier wakes WaitApplied callers without polling. The waiter count
// keeps the apply hot path free of channel allocation when nobody is waiting.
// | appliedNotifier 唤醒 WaitApplied 调用方，无需轮询。等待者计数让无人等待时的
// apply 热路径不再分配通道。
type appliedNotifier struct {
	ch      chan struct{}
	mu      sync.Mutex
	waiters atomic.Int32
}

// newAppliedNotifier returns an open notifier. | newAppliedNotifier 返回打开的
// 通知器。
func newAppliedNotifier() *appliedNotifier {
	return &appliedNotifier{ch: make(chan struct{})}
}

// notify releases every current waiter. | notify 释放所有当前等待者。
func (a *appliedNotifier) notify() {
	if a.waiters.Load() == 0 {
		return
	}
	a.mu.Lock()
	if a.waiters.Load() > 0 {
		close(a.ch)
		a.ch = make(chan struct{})
	}
	a.mu.Unlock()
}

// wait blocks until ready reports true, the notifier fires, stop closes, or ctx
// expires. The readiness check runs under the same lock that notify uses, which
// closes the lost-wakeup window between observing applied and capturing the
// channel. | wait 阻塞到 ready 为真、通知触发、stop 关闭或 ctx 到期。就绪检查与
// notify 使用同一把锁，消除了“观察到 applied 后、捕获通道前”丢失唤醒的窗口。
func (a *appliedNotifier) wait(ctx context.Context, stop <-chan struct{}, ready func() bool) error {
	a.mu.Lock()
	// Register before the readiness check. A notifier that misses this waiter
	// must have observed applied before the registration, so the check below
	// sees it; registering after the check would reopen the lost-wakeup window.
	// | 先登记再检查就绪。错过该等待者的通知器必然在登记前已观察到 applied，
	// 因此下面的检查必定看到它；若在检查后才登记，就会重新打开丢失唤醒的窗口。
	a.waiters.Add(1)
	if ready() {
		a.waiters.Add(-1)
		a.mu.Unlock()
		return nil
	}
	ch := a.ch
	a.mu.Unlock()
	var err error
	select {
	case <-ch:
	case <-stop:
		err = ErrStopped
	case <-ctx.Done():
		err = ctx.Err()
	}
	a.waiters.Add(-1)
	return err
}

// maxApplyBatchEntries bounds one apply task. A single huge task would keep
// Close waiting for the whole committed backlog and would delay snapshot
// boundaries; each task can still use BatchFSM. | maxApplyBatchEntries 限制单个
// apply 任务。单个超大任务会让 Close 等待整个已提交积压，并推迟快照边界；每个任务
// 仍可使用 BatchFSM。
const maxApplyBatchEntries = 4096

// applyTask is a committed batch or a snapshot restore. | applyTask 是已提交批次或
// 快照还原。
type applyTask struct {
	snapshot      *Snapshot
	snapshotReady chan struct{}
	entries       []Entry
}

// applyQueue is an unbounded handoff from the event loop to the apply worker.
// It never blocks the event loop, so heartbeats keep flowing while a slow FSM
// falls behind. | applyQueue 是事件循环到 apply 协程的无界交接。它从不阻塞事件
// 循环，因此慢 FSM 落后时心跳仍能流动。
type applyQueue struct {
	notify chan struct{}
	tasks  []applyTask
	mu     sync.Mutex
	closed bool
}

// newApplyQueue returns an empty queue. | newApplyQueue 返回空队列。
func newApplyQueue() *applyQueue {
	return &applyQueue{notify: make(chan struct{}, 1)}
}

// push appends a task without blocking. | push 非阻塞追加任务。
func (q *applyQueue) push(t applyTask) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.tasks = append(q.tasks, t)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// pop removes the oldest task. | pop 移除最旧任务。
func (q *applyQueue) pop() (applyTask, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.tasks) == 0 {
		return applyTask{}, false
	}
	t := q.tasks[0]
	q.tasks[0] = applyTask{}
	q.tasks = q.tasks[1:]
	if len(q.tasks) == 0 {
		q.tasks = nil
	}
	return t, true
}

// close discards pending tasks. | close 丢弃待处理任务。
func (q *applyQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.tasks = nil
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// applyLoop is the only goroutine that calls FSM.Apply, FSM.Snapshot and
// FSM.Restore. This serialization is the state machine's ordering guarantee.
// | applyLoop 是唯一调用 FSM.Apply、FSM.Snapshot 与 FSM.Restore 的协程。该串行化
// 是状态机的顺序保证。
func (n *Node) applyLoop() {
	defer n.wg.Done()
	snapshotting := false
	var pending *snapshotRequest
	for {
		select {
		case <-n.snapshotDoneCh:
			snapshotting = false
		default:
		}
		if !snapshotting && pending != nil {
			req := pending
			pending = nil
			if n.createSnapshot(req) {
				snapshotting = true
			}
		}
		if task, ok := n.applyQueue.pop(); ok {
			if !n.processApplyTask(task) {
				return
			}
			if !snapshotting && n.shouldSnapshot() {
				snapshotting = n.createSnapshot(nil)
			}
			continue
		}
		select {
		case <-n.stopCh:
			if pending != nil {
				sendErr(pending.done, ErrStopped)
			}
			return
		case <-n.applyQueue.notify:
		case req := <-n.applySnapshotCh:
			if snapshotting {
				// An automatic capture is in flight. Remember this request and
				// start it after the completion signal; otherwise two captures
				// could race with one shared node-level snapshot state. The event
				// loop serializes manual requests, so there is at most one.
				// | 自动捕获仍在进行。记住该请求并在完成信号后启动；否则两次捕获
				// 会与共享的节点级快照状态竞争。事件循环已串行化手动请求，因此至多
				// 一个。
				if pending != nil {
					sendErr(pending.done, ErrSnapshotOutOfDate)
				}
				pending = req
				continue
			}
			if n.createSnapshot(req) {
				snapshotting = true
			}
		case <-n.snapshotDoneCh:
			snapshotting = false
			if pending != nil {
				req := pending
				pending = nil
				if n.createSnapshot(req) {
					snapshotting = true
				}
			}
		}
	}
}

// processApplyTask applies one queued task. It returns false when the worker must
// stop. | processApplyTask 应用一个排队任务；需要停止协程时返回 false。
func (n *Node) processApplyTask(task applyTask) bool {
	if task.snapshot != nil {
		if task.snapshotReady != nil {
			select {
			case <-task.snapshotReady:
			case <-n.stopCh:
				return false
			}
		}
		if err := n.restoreSafe(task.snapshot.Data); err != nil {
			n.metrics.applyErrors.Add(1)
			n.fatal(err)
			return false
		}
		if task.snapshot.Index > n.applied.Load() {
			n.applied.Store(task.snapshot.Index)
		}
		n.appliedTerm = task.snapshot.Term
		n.appliedNotify.notify()
		return true
	}
	if len(task.entries) == 0 {
		return true
	}
	if !n.applyEntries(task.entries) {
		return false
	}
	return true
}

// applyEntries applies a contiguous committed batch and resolves proposal
// futures. A panic in user code stops the node instead of corrupting ordering.
// | applyEntries 应用连续已提交批次并完成提案 Future。用户代码 panic 会停止节点，
// 而不是破坏顺序。
func (n *Node) applyEntries(entries []Entry) bool {
	defer func() {
		if r := recover(); r != nil {
			n.metrics.applyErrors.Add(1)
			n.fatal(errs.Detail(ErrFSMPanic, "%v", r))
		}
	}()
	batchFSM, ok := n.fsm.(BatchFSM)
	var normals []Entry
	var values []any
	if ok {
		allNormal := true
		for i := range entries {
			if entries[i].Type != EntryNormal {
				allNormal = false
				break
			}
		}
		if allNormal {
			// The common case is a pure command batch; pass the caller's slice
			// directly instead of allocating a copy. | 常见情况是纯命令批次；直接
			// 传递调用方切片，避免复制分配。
			normals = entries
		} else {
			normals = make([]Entry, 0, len(entries))
			for i := range entries {
				if entries[i].Type == EntryNormal {
					normals = append(normals, entries[i])
				}
			}
		}
		if len(normals) > 0 {
			values = batchFSM.ApplyBatch(normals)
			if len(values) != len(normals) {
				n.metrics.applyErrors.Add(1)
				n.fatal(errs.Detail(ErrFSMPanic, "ApplyBatch returned %d values for %d entries",
					len(values), len(normals)))
				return false
			}
		}
	}
	valueIndex := 0
	for i := range entries {
		if i > 0 && i&1023 == 0 && n.stopped.Load() {
			// Shutdown is in progress. Do not keep Close waiting for a large
			// committed backlog; failWaiters has already resolved its futures.
			// | 正在关闭。不要让 Close 等待大量已提交积压；failWaiters 已结束其
			// Future。
			return false
		}
		e := &entries[i]
		var value any
		if e.Type == EntryNormal {
			if ok {
				if valueIndex < len(values) {
					value = values[valueIndex]
				}
			} else {
				value = n.fsm.Apply(e.Index, e.Term, e.Data)
			}
			valueIndex++
		}
		if f := n.futures.take(e.Index); f != nil {
			f.deliver(value)
		}
		n.appliedTerm = e.Term
	}
	last := entries[len(entries)-1]
	n.applied.Store(last.Index)
	n.appliedNotify.notify()
	n.metrics.applies.Add(uint64(len(entries)))
	n.metrics.applyBatches.Add(1)
	return true
}

// restoreSafe wraps FSM.Restore with panic containment. | restoreSafe 用 panic 隔离
// 包装 FSM.Restore。
func (n *Node) restoreSafe(data []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errs.Detail(ErrFSMPanic, "restore: %v", r)
		}
	}()
	return n.fsm.Restore(data)
}

// advanceApply hands newly committed entries to the apply worker. | advanceApply
// 将新提交的日志项交给 apply 协程。
func (n *Node) advanceApply() {
	// Only apply entries that are durable locally. The leader's commit index is
	// already bounded by persistedIndex, but a follower adopts the leader's
	// commit index with an append that may still be in the persist queue; applying
	// it first would let a crash lose an entry whose effects were already visible.
	// | 只应用本地已持久化的日志项。领导者的提交索引已受 persistedIndex 约束，但
	// 跟随者会在追加仍排队持久化时采用领导者提交索引；先应用会让崩溃丢失一个副作用
	// 已经可见的日志项。
	limit := n.committed
	if limit > n.persistedIndex {
		limit = n.persistedIndex
	}
	if limit <= n.sentApplied {
		return
	}
	start := n.sentApplied + 1
	if start < n.log.firstIndex {
		start = n.log.firstIndex
	}
	if start > limit {
		n.sentApplied = limit
		return
	}
	end := limit + 1
	if end-start > maxApplyBatchEntries {
		end = start + maxApplyBatchEntries
	}
	entries, err := n.log.slice(start, end, 0)
	if err != nil {
		n.fatal(err)
		return
	}
	if len(entries) == 0 {
		n.sentApplied = limit
		return
	}
	n.sentApplied = entries[len(entries)-1].Index
	n.applyQueue.push(applyTask{entries: entries})
}
