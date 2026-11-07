package raft

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// remoteReadStore tracks ReadIndex calls forwarded to a leader. | remoteReadStore
// 跟踪转发给领导者的 ReadIndex 调用。
type remoteReadStore struct {
	m  map[uint64]chan readResult
	mu sync.Mutex
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

// newRemoteReadEpoch returns a per-process identifier for forwarded reads.
// Sequence numbers restart at one after a restart; the epoch keeps a delayed
// response from the previous process from matching a new request. Randomness is
// not security-sensitive here. | newRemoteReadEpoch 返回转发读的进程级标识。
// 序号在重启后从 1 重新开始；纪元可避免上一进程的迟到响应匹配新请求。这里的随机性
// 不用于安全目的。
func newRemoteReadEpoch() uint64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return binary.BigEndian.Uint64(buf[:])
	}
	return uint64(time.Now().UnixNano())
}

// encodeRemoteReadContext packs an epoch and request id. | encodeRemoteReadContext
// 打包纪元与请求序号。
func encodeRemoteReadContext(epoch, id uint64) []byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], epoch)
	binary.BigEndian.PutUint64(buf[8:], id)
	return buf[:]
}

// decodeRemoteReadContext unpacks a forwarded read context. | decodeRemoteReadContext
// 解包转发读上下文。
func decodeRemoteReadContext(ctx []byte) (epoch, id uint64, ok bool) {
	if len(ctx) != 16 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint64(ctx[:8]), binary.BigEndian.Uint64(ctx[8:]), true
}

// remoteReadResponse is a leader-side pending answer to a forwarded read.
// | remoteReadResponse 是领导者侧等待应答的转发读。
type remoteReadResponse struct {
	context []byte
	from    NodeID
}

// handleReadIndexMessage answers a forwarded ReadIndex request. A leader with a
// valid lease answers immediately; otherwise the request joins the next
// heartbeat confirmation round. | handleReadIndexMessage 应答转发的 ReadIndex
// 请求。持有有效租约的领导者立即应答；否则请求加入下一次心跳确认轮次。
func (n *Node) handleReadIndexMessage(m *Message) {
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
	if !n.readReady() {
		if len(n.pendingRemoteRead) >= n.pendingReadLimit {
			n.send(Message{Type: MsgReadIndexResp, To: m.From, Term: n.term, Reject: true,
				Index: uint64(n.leader), Context: m.Context})
			return
		}
		n.pendingRemoteRead = append(n.pendingRemoteRead,
			remoteReadResponse{from: m.From, context: m.Context})
		return
	}
	n.answerForwardedRead(m.From, m.Context)
}

// answerForwardedRead serves a forwarded read after the leader has committed a
// current-term entry. | answerForwardedRead 在领导者提交当前任期日志项后服务转发
// 读请求。
func (n *Node) answerForwardedRead(from NodeID, context []byte) {
	if n.leaseValid() {
		n.metrics.leaseReads.Add(1)
		n.send(Message{Type: MsgReadIndexResp, To: from, Term: n.term,
			Index: n.committed, Context: context})
		return
	}
	if n.readRound == nil {
		n.startReadRound()
	}
	if n.readRound == nil {
		// Completed synchronously (single voter); answer the forwarded read now.
		// | 已同步完成（单投票成员）；立即应答转发的读请求。
		n.send(Message{Type: MsgReadIndexResp, To: from, Term: n.term,
			Index: n.committed, Context: context})
		return
	}
	n.readRound.remote = append(n.readRound.remote, remoteReadResponse{from: from, context: context})
}

// handleReadIndexResp completes a forwarded read. | handleReadIndexResp 完成转发读。
func (n *Node) handleReadIndexResp(m *Message) {
	epoch, id, ok := decodeRemoteReadContext(m.Context)
	if !ok || epoch != n.remoteEpoch {
		return
	}
	// Late responses from a previous term or a former leader must never satisfy
	// a current read. Leader changes already fail pending reads; this check also
	// covers a delayed reply after this node restarted at the same term. | 上一任期
	// 或前任领导者的迟到响应绝不能完成当前读。领导者变更已使挂起读失败；该检查还
	// 覆盖本节点在同一任期重启后的迟到应答。
	if m.Term != n.term || m.From != n.leader {
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
