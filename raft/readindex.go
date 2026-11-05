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
	id     uint64
	index  uint64
	acks   map[NodeID]bool
	reads  []*readRequest
	remote []remoteReadResponse
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
	n.readRound = &readRound{
		id:    n.readSeq,
		index: n.committed,
		acks:  map[NodeID]bool{n.id: true},
	}
	n.heartbeatVoters(n.readRound.id)
}

// heartbeatVoters sends the current round context to every voter. | heartbeatVoters
// 将当前轮次上下文发送给每个投票成员。
func (n *Node) heartbeatVoters(id uint64) {
	msg := Message{
		Type:    MsgHeartbeat,
		Term:    n.term,
		Commit:  n.committed,
		Context: encodeRoundContext(id),
	}
	// All members receive the heartbeat; only voter acknowledgements count
	// toward the quorum. | 所有成员都会收到心跳；只有投票成员的确认计入法定人数。
	n.broadcast(msg)
}

// leaseValid reports whether a leader lease can serve a linearizable read
// without a heartbeat round. | leaseValid 报告领导者租约能否在没有心跳轮次的情况下
// 服务线性一致读。
func (n *Node) leaseValid() bool {
	if n.cfg.DisableLeaseRead || n.cfg.DisableCheckQuorum {
		return false
	}
	if n.state != StateLeader || n.termStartIndex == 0 || n.committed < n.termStartIndex {
		return false
	}
	return n.now().Before(n.leaseUntil)
}

// handleRead serves a local ReadIndex call. | handleRead 服务本地 ReadIndex 调用。
func (n *Node) handleRead(req *readRequest) {
	if n.state != StateLeader {
		sendIndex(req.done, 0, n.notLeaderError("read"))
		return
	}
	n.metrics.readIndex.Add(1)
	if n.leaseValid() {
		n.metrics.leaseReads.Add(1)
		sendIndex(req.done, n.committed, nil)
		return
	}
	if n.readRound == nil {
		n.startReadRound()
	}
	n.readRound.reads = append(n.readRound.reads, req)
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
		n.leaseUntil = n.now().Add(time.Duration(n.electionTimeout) * n.tickInterval)
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
