package raft

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// handleTransferRequest starts a leadership transfer. New proposals are
// rejected until the transfer finishes or times out. | handleTransferRequest 启动
// 领导权转移。在转移完成或超时前，新提案会被拒绝。
func (n *Node) handleTransferRequest(req *transferRequest) {
	if n.state != StateLeader {
		sendErr(req.done, n.notLeaderError("transfer"))
		return
	}
	if req.target == n.id {
		sendErr(req.done, nil)
		return
	}
	if !n.conf.isVoter(req.target) {
		sendErr(req.done, errs.Detail(ErrUnknownNode, "node %d is not a voter", req.target))
		return
	}
	if n.leadTransferee != 0 {
		sendErr(req.done, ErrTransferInProgress)
		return
	}
	n.leadTransferee = req.target
	// The transferee campaigns without pre-vote, so the old leader's lease can
	// no longer prove linearizability. | 转移目标会跳过预投票直接竞选，因此原领导者
	// 的租约不再能证明线性一致性。
	n.leaseUntil = time.Time{}
	n.transferElapsed = 0
	n.transferSent = false
	n.transferActive.Store(true)
	n.transferWaiters = append(n.transferWaiters, req.done)
	pr := n.progress[req.target]
	if pr != nil && pr.match >= n.log.lastIndex {
		n.sendTimeoutNow()
		return
	}
	n.maybeSendAppend(req.target)
}

// sendTimeoutNow tells the transferee to campaign immediately. | sendTimeoutNow
// 通知转移目标立即竞选。
func (n *Node) sendTimeoutNow() {
	if n.leadTransferee == 0 || n.transferSent {
		return
	}
	n.transferSent = true
	n.send(Message{Type: MsgTimeoutNow, To: n.leadTransferee, Term: n.term})
}

// abortTransfer cancels an in-flight transfer. | abortTransfer 取消进行中的转移。
func (n *Node) abortTransfer(err error) {
	if n.leadTransferee == 0 && len(n.transferWaiters) == 0 {
		return
	}
	n.leadTransferee = 0
	n.transferSent = false
	n.transferElapsed = 0
	n.transferActive.Store(false)
	for _, ch := range n.transferWaiters {
		sendErr(ch, err)
	}
	n.transferWaiters = nil
}

// resolveTransfer finishes every waiting transfer call. | resolveTransfer 结束所有
// 等待中的转移调用。
func (n *Node) resolveTransfer(err error) {
	n.leadTransferee = 0
	n.transferSent = false
	n.transferElapsed = 0
	n.transferActive.Store(false)
	for _, ch := range n.transferWaiters {
		sendErr(ch, err)
	}
	n.transferWaiters = nil
}

// handleTransferMessage accepts a transfer request from a peer. Local callers
// use TransferLeader; this path keeps the protocol usable by custom clients.
// | handleTransferMessage 接受来自对端的转移请求。本地调用方使用 TransferLeader；
// 该路径让自定义客户端也能使用协议。
func (n *Node) handleTransferMessage(m *Message) {
	if n.state != StateLeader || m.Term != n.term || !n.conf.isVoter(m.From) {
		return
	}
	req := &transferRequest{target: m.From, done: make(chan error, 1)}
	n.handleTransferRequest(req)
}
