package raft

import (
	"context"
	"errors"
	"time"
)

// ProposeAsync appends data to the log and returns a Future. It copies data, so
// the caller may reuse its buffer immediately. | ProposeAsync 将 data 追加到日志并
// 返回 Future。它会复制 data，调用方可立即复用原缓冲。
func (n *Node) ProposeAsync(ctx context.Context, data []byte) (*Future, error) {
	return n.propose(ctx, data, false)
}

// ProposeOwned is ProposeAsync without the defensive copy. The caller transfers
// ownership of data and must not modify it afterwards. | ProposeOwned 是免防御性
// 复制的 ProposeAsync。调用方转移 data 所有权，之后不得修改。
func (n *Node) ProposeOwned(ctx context.Context, data []byte) (*Future, error) {
	return n.propose(ctx, data, true)
}

// propose performs the fast leader check and enqueues the proposal. | propose 执行
// 快速领导者检查并让提案入队。
func (n *Node) propose(ctx context.Context, data []byte, owned bool) (*Future, error) {
	f := newFuture(0, 0)
	if _, err := n.proposeWithFuture(ctx, data, owned, f, false); err != nil {
		return nil, err
	}
	return f, nil
}

// proposeWithFuture performs the fast leader check and enqueues one proposal.
// | proposeWithFuture 执行快速领导者检查并入队一个提案。
func (n *Node) proposeWithFuture(ctx context.Context, data []byte, owned bool, f *Future, reuse bool) (*proposal, error) {
	if n.stopped.Load() {
		return nil, ErrStopped
	}
	if n.State() != StateLeader {
		return nil, n.notLeaderError("propose")
	}
	if n.transferActive.Load() {
		return nil, ErrTransferInProgress
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p := n.allocProposal(data, owned, f, reuse)
	if err := n.proposals.push(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Propose appends data and waits until it is committed and applied. Synchronous
// proposals reuse their Future object after a completed wait, removing one
// channel allocation per proposal from the hot path. | Propose 追加 data，并等待其
// 被提交与应用。同步提案在等待完成后复用 Future 对象，从热路径移除每个提案一次的
// 通道分配。
func (n *Node) Propose(ctx context.Context, data []byte) (Result, error) {
	f := n.getFuture()
	p, err := n.proposeWithFuture(ctx, data, false, f, true)
	if err != nil {
		n.putFuture(f)
		return Result{}, err
	}
	res, err := f.Wait(ctx)
	if err == nil || (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)) {
		n.putFuture(f)
		n.releaseProposal(p)
	}
	return res, err
}

// ReadIndex returns a committed index that is linearizable with respect to the
// caller's invocation. Callers must wait for Applied >= index (use WaitApplied)
// before reading the state machine. | ReadIndex 返回与调用时刻线性一致的已提交
// 索引。调用方必须等待 Applied >= index（可用 WaitApplied）后再读取状态机。
func (n *Node) ReadIndex(ctx context.Context) (uint64, error) {
	if n.stopped.Load() {
		return 0, ErrStopped
	}
	if n.State() != StateLeader {
		return n.forwardReadIndex(ctx)
	}
	req := &readRequest{done: make(chan readResult, 1)}
	select {
	case n.readCh <- req:
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-n.stopCh:
		return 0, ErrStopped
	}
	select {
	case r := <-req.done:
		return r.index, r.err
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-n.stopCh:
		return 0, ErrStopped
	}
}

// forwardReadIndex asks the known leader to confirm a linearizable read index.
// The follower's apply loop may lag; callers still use WaitApplied. | forwardReadIndex
// 请求已知领导者确认线性一致读索引。跟随者的应用循环可能落后；调用方仍需
// WaitApplied。
func (n *Node) forwardReadIndex(ctx context.Context) (uint64, error) {
	leader := n.Leader()
	if leader == 0 || leader == n.id {
		return 0, ErrNoLeader
	}
	id := n.remoteReadSeq.Add(1)
	ch := n.remoteReads.add(id)
	msg := Message{
		Type: MsgReadIndex, From: n.id, To: leader, Group: n.group, Term: n.Term(),
		Context: encodeRoundContext(id),
	}
	select {
	case n.outCh <- outboundBatch{msgs: []Message{msg}}:
		n.metrics.messagesOut.Add(1)
	case <-ctx.Done():
		n.remoteReads.take(id)
		return 0, ctx.Err()
	case <-n.stopCh:
		n.remoteReads.take(id)
		return 0, ErrStopped
	}
	select {
	case r := <-ch:
		return r.index, r.err
	case <-ctx.Done():
		n.remoteReads.take(id)
		return 0, ctx.Err()
	case <-n.stopCh:
		n.remoteReads.take(id)
		return 0, ErrStopped
	}
}

// WaitApplied blocks until the local state machine has applied index. | WaitApplied
// 阻塞到本地状态机已应用 index。
func (n *Node) WaitApplied(ctx context.Context, index uint64) error {
	for {
		if n.applied.Load() >= index {
			return nil
		}
		if n.stopped.Load() {
			return ErrStopped
		}
		if err := n.appliedNotify.wait(ctx, func() bool { return n.applied.Load() >= index }); err != nil {
			return err
		}
	}
}

// Barrier performs a linearizable read barrier: it confirms leadership and
// waits until every entry committed before the call is applied locally. | Barrier
// 执行线性一致读屏障：确认领导权，并等待调用前提交的所有日志项在本地应用。
func (n *Node) Barrier(ctx context.Context) error {
	index, err := n.ReadIndex(ctx)
	if err != nil {
		return err
	}
	return n.WaitApplied(ctx, index)
}

// AddNode adds a voter. addr may be empty when the transport resolves by ID.
// | AddNode 增加投票成员。传输按 ID 解析地址时 addr 可为空。
func (n *Node) AddNode(ctx context.Context, id NodeID, addr string) error {
	return n.changeConf(ctx, ConfChange{Type: ConfChangeAddNode, NodeID: id, Addr: addr})
}

// RemoveNode removes a voter or learner. | RemoveNode 移除投票成员或不投票成员。
func (n *Node) RemoveNode(ctx context.Context, id NodeID) error {
	return n.changeConf(ctx, ConfChange{Type: ConfChangeRemoveNode, NodeID: id})
}

// AddLearner adds a non-voting member. | AddLearner 增加不投票成员。
func (n *Node) AddLearner(ctx context.Context, id NodeID, addr string) error {
	return n.changeConf(ctx, ConfChange{Type: ConfChangeAddLearner, NodeID: id, Addr: addr})
}

// Promote turns a learner into a voter. | Promote 将学习者提升为投票成员。
func (n *Node) Promote(ctx context.Context, id NodeID) error {
	return n.changeConf(ctx, ConfChange{Type: ConfChangePromote, NodeID: id})
}

// changeConf submits a membership change and waits for its final configuration
// to commit. | changeConf 提交成员变更，并等待最终配置提交。
func (n *Node) changeConf(ctx context.Context, cc ConfChange) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	if cc.NodeID == 0 {
		return ErrInvalidConfig
	}
	if n.State() != StateLeader {
		return n.notLeaderError("membership change")
	}
	if n.transferActive.Load() {
		return ErrTransferInProgress
	}
	p := &proposal{conf: &cc, future: newFuture(0, 0)}
	if err := n.proposals.push(p); err != nil {
		return err
	}
	_, err := p.future.Wait(ctx)
	return err
}

// TransferLeader hands leadership to target. New proposals are rejected while
// the transfer is in progress. | TransferLeader 将领导权交给 target。转移期间新提案
// 会被拒绝。
func (n *Node) TransferLeader(ctx context.Context, target NodeID) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	req := &transferRequest{target: target, done: make(chan error, 1)}
	select {
	case n.transferCh <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-n.stopCh:
		return ErrStopped
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-n.stopCh:
		return ErrStopped
	}
}

// Campaign forces the node to start an election and waits until it becomes
// leader or the context expires. | Campaign 强制节点发起选举，并等待其成为领导者或
// 上下文到期。
func (n *Node) Campaign(ctx context.Context) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	req := &campaignRequest{done: make(chan error, 1)}
	select {
	case n.campaignCh <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-n.stopCh:
		return ErrStopped
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-n.stopCh:
		return ErrStopped
	}
}

// Snapshot captures the local state machine and persists the image. It works on
// any replica. | Snapshot 捕获本地状态机并持久化镜像，可在任意副本上调用。
func (n *Node) Snapshot(ctx context.Context) error {
	if n.stopped.Load() {
		return ErrStopped
	}
	req := &snapshotRequest{done: make(chan error, 1)}
	select {
	case n.snapshotCh <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-n.stopCh:
		return ErrStopped
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-n.stopCh:
		return ErrStopped
	}
}

// Status returns a consistent view assembled by the Raft event loop. It waits
// at most one second; a stopped or wedged node yields a best-effort snapshot.
// | Status 返回由 Raft 事件循环组装的一致视图。最多等待一秒；停止或卡住的节点返回
// 尽力而为的快照。
func (n *Node) Status() Status {
	reply := make(chan Status, 1)
	select {
	case n.statusCh <- reply:
	case <-n.stopCh:
		return n.basicStatus()
	case <-time.After(time.Second):
		return n.basicStatus()
	}
	select {
	case st := <-reply:
		return st
	case <-n.stopCh:
		return n.basicStatus()
	case <-time.After(time.Second):
		return n.basicStatus()
	}
}

// basicStatus uses only atomic mirrors. | basicStatus 仅使用原子镜像。
func (n *Node) basicStatus() Status {
	return Status{
		ID:      n.id,
		Group:   n.group,
		State:   n.State(),
		Term:    n.Term(),
		Leader:  n.Leader(),
		Commit:  n.Commit(),
		Applied: n.Applied(),
	}
}
