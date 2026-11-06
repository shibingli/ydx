package raft

import (
	"encoding/binary"
	"time"

	"github.com/shibingli/ydx/errs"
)

// readRound is one leadership-confirmation round. Its id is echoed in heartbeat
// responses so late answers cannot satisfy a newer round. | readRound 是一次领导
// 权确认轮次。其 id 会随心跳响应回显，因此迟到的应答无法满足更新的轮次。
type readRound struct {
	startedAt time.Time
	acks      map[NodeID]bool
	reads     []*readRequest
	remote    []remoteReadResponse
	id        uint64
	index     uint64
}

// encodeRoundContext packs a round id into heartbeat context bytes. | encodeRoundContext
// 将轮次 id 打包为心跳上下文字节。
func encodeRoundContext(id uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], id)
	return buf[:]
}

// decodeRoundContext unpacks a heartbeat context. | decodeRoundContext 解包心跳上下文。
func decodeRoundContext(ctx []byte) (uint64, bool) {
	if len(ctx) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(ctx), true
}

// startReadRound begins a heartbeat round at the current commit index. | startReadRound
// 以当前提交索引开始一次心跳轮次。
func (n *Node) startReadRound() {
	n.readSeq++
	r := &readRound{
		id:        n.readSeq,
		index:     n.committed,
		startedAt: n.now(),
		acks:      map[NodeID]bool{n.id: true},
	}
	n.readRound = r
	n.heartbeatVoters(r.id)
	// A single-voter configuration has no peer to answer. Complete it locally;
	// otherwise ReadIndex and Barrier would wait forever. | 单投票成员配置没有对端
	// 应答；在本地完成，否则 ReadIndex 与 Barrier 会永远等待。
	if n.conf.hasQuorum(func(id NodeID) bool { return r.acks[id] }) {
		n.completeReadRound(r)
	}
}

// heartbeatVoters sends the current round context to every member. Commit is
// capped per follower so a heartbeat can never commit a divergent suffix.
// | heartbeatVoters 将当前轮次上下文发送给每个成员。提交索引按跟随者封顶，保证
// 心跳永远不会提交分叉后缀。
func (n *Node) heartbeatVoters(id uint64) {
	context := encodeRoundContext(id)
	for peer, pr := range n.progress {
		if peer == n.id || pr == nil {
			continue
		}
		n.send(Message{
			Type:     MsgHeartbeat,
			To:       peer,
			Term:     n.term,
			Commit:   min64(n.committed, pr.match),
			LogIndex: pr.match,
			Context:  context,
		})
	}
}

// leaseValid reports whether a leader lease can serve a linearizable read
// without a heartbeat round. | leaseValid 报告领导者租约能否在没有心跳轮次的情况下
// 服务线性一致读。
func (n *Node) leaseValid() bool {
	if n.cfg.DisableLeaseRead || n.cfg.DisableCheckQuorum {
		return false
	}
	// A lease read assumes no new leader can be elected before the lease ends.
	// Pre-vote provides that bound by refusing to campaign while a leader is
	// known; without it a follower may grant a vote within the window. A
	// leadership transfer deliberately bypasses pre-vote for the transferee, so
	// the outgoing leader must stop serving lease reads as soon as it starts.
	// | 租约读假定租约到期前不会选出新领导者。预投票通过在有领导者时拒绝竞选来
	// 提供该边界；关闭预投票后，跟随者可能在窗口内投票。领导权转移会有意为目标绕过
	// 预投票，因此原领导者在转移开始时必须停止服务租约读。
	if n.cfg.DisablePreVote || n.leadTransferee != 0 {
		return false
	}
	if n.state != StateLeader || n.termStartIndex == 0 || n.committed < n.termStartIndex {
		return false
	}
	return n.now().Before(n.leaseUntil)
}

// readReady reports whether the leader has committed an entry from its current
// term, which is the Raft ReadIndex prerequisite. | readReady 报告领导者是否已
// 提交当前任期的日志项，这是 Raft ReadIndex 的前提。
func (n *Node) readReady() bool {
	return n.termStartIndex != 0 && n.committed >= n.termStartIndex
}

// handleRead serves a local ReadIndex call. | handleRead 服务本地 ReadIndex 调用。
func (n *Node) handleRead(req *readRequest) {
	if n.state != StateLeader {
		sendIndex(req.done, 0, n.notLeaderError("read"))
		return
	}
	n.metrics.readIndex.Add(1)
	if !n.readReady() {
		if len(n.pendingReads) >= n.pendingReadLimit {
			sendIndex(req.done, 0, errs.Detail(ErrBusy,
				"too many reads waiting for the current-term commit | 等待当前任期提交的读过多"))
			return
		}
		n.pendingReads = append(n.pendingReads, req)
		return
	}
	n.serveRead(req)
}

// serveRead runs the lease or heartbeat confirmation path for a ready leader.
// | serveRead 为已就绪的领导者执行租约或心跳确认路径。
func (n *Node) serveRead(req *readRequest) {
	if n.leaseValid() {
		n.metrics.leaseReads.Add(1)
		sendIndex(req.done, n.committed, nil)
		return
	}
	if n.readRound == nil {
		n.startReadRound()
	}
	if n.readRound == nil {
		// The round completed synchronously, which happens for a single voter.
		// | 轮次已同步完成，单投票成员配置会出现这种情况。
		sendIndex(req.done, n.committed, nil)
		return
	}
	n.readRound.reads = append(n.readRound.reads, req)
}

// releasePendingReads serves reads parked while the leader was not yet ready.
// | releasePendingReads 服务领导者尚未就绪期间暂存的读。
func (n *Node) releasePendingReads() {
	if n.state != StateLeader || !n.readReady() {
		return
	}
	local := n.pendingReads
	remote := n.pendingRemoteRead
	n.pendingReads = nil
	n.pendingRemoteRead = nil
	for _, req := range local {
		n.serveRead(req)
	}
	for _, rr := range remote {
		n.answerForwardedRead(rr.from, rr.context)
	}
}

// failPendingReads resolves reads parked before the new term committed. |
// failPendingReads 结束新任期提交前暂存的读。
func (n *Node) failPendingReads(err error) {
	for _, req := range n.pendingReads {
		sendIndex(req.done, 0, err)
	}
	for _, rr := range n.pendingRemoteRead {
		n.send(Message{Type: MsgReadIndexResp, To: rr.from, Term: n.term, Reject: true,
			Index: uint64(n.leader), Context: rr.context})
	}
	n.pendingReads = nil
	n.pendingRemoteRead = nil
}

// ackReadRound records a heartbeat acknowledgement and completes the round on a
// majority of every voter set. | ackReadRound 记录心跳确认，并在每个投票集合达到
// 多数时完成轮次。
func (n *Node) ackReadRound(from NodeID, context []byte) {
	r := n.readRound
	if r == nil {
		return
	}
	id, ok := decodeRoundContext(context)
	if !ok || id != r.id || !n.conf.isVoter(from) {
		return
	}
	r.acks[from] = true
	if !n.conf.hasQuorum(func(node NodeID) bool { return r.acks[node] }) {
		return
	}
	n.completeReadRound(r)
}

// completeReadRound releases readers and extends the leader lease. | completeReadRound
// 释放读请求并延长领导者租约。
func (n *Node) completeReadRound(r *readRound) {
	if n.readRound != r {
		return
	}
	n.readRound = nil
	if !n.cfg.DisableCheckQuorum {
		// A lease must end before any follower can legally start an election.
		// Followers randomize their timeout in [ElectionTicks, 2*ElectionTicks)
		// ticks, but the first ticker tick after they reset can arrive almost
		// immediately, so only ElectionTicks-1 full intervals are guaranteed.
		// Measure from the round's send time, not the acknowledgement time: the
		// acknowledgement adds an RTT during which another node could already
		// have begun campaigning. | 租约必须在任何跟随者能够合法发起选举之前结束。
		// 跟随者超时在 [ElectionTicks, 2*ElectionTicks) 个 tick 内随机，但其重置后
		// 的第一个 ticker tick 可能几乎立即到达，因此只有 ElectionTicks-1 个完整
		// 间隔有保证。从轮次发送时刻起算而非确认时刻：确认间隔的 RTT 期间另一节点
		// 可能已经开始竞选。
		started := r.startedAt
		if started.IsZero() {
			started = n.now()
		}
		ticks := n.electionTicks - 1
		if ticks > 0 {
			n.leaseUntil = started.Add(time.Duration(ticks) * n.tickInterval)
		}
	}
	index := n.committed
	if r.index > index {
		index = r.index
	}
	for _, req := range r.reads {
		sendIndex(req.done, index, nil)
	}
	for _, rr := range r.remote {
		n.send(Message{Type: MsgReadIndexResp, To: rr.from, Term: n.term,
			Index: index, Context: rr.context})
	}
}

// resolveReads fails every reader attached to the active round. | resolveReads 使
// 活动轮次上的每个读请求失败。
func (n *Node) resolveReads(err error) {
	r := n.readRound
	if r == nil {
		return
	}
	n.readRound = nil
	for _, req := range r.reads {
		sendIndex(req.done, 0, err)
	}
	for _, rr := range r.remote {
		n.send(Message{Type: MsgReadIndexResp, To: rr.from, Term: n.term, Reject: true,
			Index: uint64(n.leader), Context: rr.context})
	}
}

// notLeaderError adds the known leader to ErrNotLeader. | notLeaderError 将已知领导
// 者附加到 ErrNotLeader。
func (n *Node) notLeaderError(op string) error {
	leader := n.Leader()
	if leader == 0 {
		return errs.Detail(ErrNotLeader, "%s: no leader", op)
	}
	return errs.Detail(ErrNotLeader, "%s: leader=%d", op, leader)
}
