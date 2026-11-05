package raft

import (
	"sync"

	"github.com/shibingli/ydx/errs"
)

// remoteReadStore tracks ReadIndex calls forwarded to a leader. | remoteReadStore
// 跟踪转发给领导者的 ReadIndex 调用。
type remoteReadStore struct {
	mu sync.Mutex
	m  map[uint64]chan readResult
}

// newRemoteReadStore returns an empty store. | newRemoteReadStore 返回空存储。
func newRemoteReadStore() *remoteReadStore {
	return &remoteReadStore{m: make(map[uint64]chan readResult)}
}

// add registers a result channel. | add 注册结果通道。
func (s *remoteReadStore) add(id uint64) chan readResult {
	ch := make(chan readResult, 1)
	s.mu.Lock()
	s.m[id] = ch
	s.mu.Unlock()
	return ch
}

// take removes and returns a result channel. | take 移除并返回结果通道。
func (s *remoteReadStore) take(id uint64) chan readResult {
	s.mu.Lock()
	ch := s.m[id]
	if ch != nil {
		delete(s.m, id)
	}
	s.mu.Unlock()
	return ch
}

// failAll resolves every pending forwarded read. | failAll 结束所有待处理转发读。
func (s *remoteReadStore) failAll(err error) {
	s.mu.Lock()
	pending := s.m
	s.m = make(map[uint64]chan readResult)
	s.mu.Unlock()
	for _, ch := range pending {
		sendIndex(ch, 0, err)
	}
}

// remoteReadResponse is a leader-side pending answer to a forwarded read.
// | remoteReadResponse 是领导者侧等待应答的转发读。
type remoteReadResponse struct {
	from    NodeID
	context []byte
}

// handleReadIndexMessage answers a forwarded ReadIndex request. A leader with a
// valid lease answers immediately; otherwise the request joins the next
// heartbeat confirmation round. | handleReadIndexMessage 应答转发的 ReadIndex
// 请求。持有有效租约的领导者立即应答；否则请求加入下一次心跳确认轮次。
func (n *Node) handleReadIndexMessage(m Message) {
	if m.Term < n.term {
		n.send(Message{Type: MsgReadIndexResp, To: m.From, Term: n.term, Reject: true,
			Index: uint64(n.Leader()), Context: m.Context})
		return
	}
	if n.state != StateLeader {
		n.send(Message{Type: MsgReadIndexResp, To: m.From, Term: n.term, Reject: true,
			Index: uint64(n.Leader()), Context: m.Context})
		return
	}
	if !n.conf.isMember(m.From) {
		return
	}
	if n.leaseValid() {
		n.metrics.leaseReads.Add(1)
		n.send(Message{Type: MsgReadIndexResp, To: m.From, Term: n.term,
			Index: n.committed, Context: m.Context})
		return
	}
	if n.readRound == nil {
		n.startReadRound()
	}
	n.readRound.remote = append(n.readRound.remote, remoteReadResponse{from: m.From, context: m.Context})
}

// handleReadIndexResp completes a forwarded read. | handleReadIndexResp 完成转发读。
func (n *Node) handleReadIndexResp(m Message) {
	id, ok := decodeRoundContext(m.Context)
	if !ok {
		return
	}
	ch := n.remoteReads.take(id)
	if ch == nil {
		return
	}
	if m.Reject {
		leader := NodeID(m.Index)
		if leader == 0 {
			sendIndex(ch, 0, ErrNoLeader)
			return
		}
		sendIndex(ch, 0, notLeaderDetail("read", leader))
		return
	}
	sendIndex(ch, m.Index, nil)
}

// notLeaderDetail builds a not-leader error with an explicit leader hint.
// | notLeaderDetail 构建带显式领导者提示的 not-leader 错误。
func notLeaderDetail(op string, leader NodeID) error {
	return errs.Detail(ErrNotLeader, "%s: leader=%d", op, leader)
}
