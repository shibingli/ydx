package raft

import (
	"context"
	"time"

	ydlog "github.com/shibingli/ydx/log"
)

// stop closes the shared stop channel exactly once. | stop 只关闭一次共享停止通道。
func (n *Node) stop() {
	n.stopOnce.Do(func() { close(n.stopCh) })
}

// run is the single Raft event loop. All mutable Raft state below the atomic
// mirrors belongs to this goroutine. | run 是唯一的 Raft 事件循环。原子镜像之下的
// 所有可变 Raft 状态都属于该协程。
func (n *Node) run() {
	defer n.wg.Done()
	defer close(n.doneCh)
	if n.autoCampaign {
		n.campaign(false)
	}
	n.advanceApply()
	for {
		n.drainControl()
		n.flushOutbound()
		select {
		case <-n.stopCh:
			n.failWaiters(ErrStopped)
			return
		case <-n.tickCh:
			n.tick()
		case m := <-n.recvCh:
			n.step(m)
		case <-n.proposals.notify:
			n.handleProposalIntake()
		case r := <-n.readCh:
			n.handleRead(r)
		case req := <-n.campaignCh:
			n.handleCampaignRequest(req)
		case req := <-n.transferCh:
			n.handleTransferRequest(req)
		case req := <-n.snapshotCh:
			n.handleSnapshotRequest(req)
		case ready := <-n.snapshotReadyCh:
			n.handleSnapshotReady(ready)
		case ack := <-n.persistAckCh:
			n.handlePersistAck(ack)
		case err := <-n.fatalCh:
			n.failWaiters(err)
			n.stopped.Store(true)
			n.stateAtomic.Store(uint32(StateShutdown))
			n.stop()
			return
		case reply := <-n.statusCh:
			reply <- n.buildStatus()
		}
		n.flushOutbound()
	}
}

// drainControl processes queued control messages before ordinary traffic. The
// cap prevents a flood of control traffic from starving replication. | drainControl
// 在普通流量之前处理排队的控制消息。上限避免控制流量洪峰饿死复制。
func (n *Node) drainControl() {
	for i := 0; i < 256; i++ {
		select {
		case m := <-n.controlCh:
			n.step(m)
		default:
			return
		}
	}
}

// tickerLoop turns wall time into Raft ticks. Missed ticks are coalesced: a busy
// event loop is never asked to catch up. | tickerLoop 将墙钟时间转为 Raft tick。
// 错过的 tick 会合并：繁忙的事件循环不会被要求补课。
func (n *Node) tickerLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(n.tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			select {
			case n.tickCh <- struct{}{}:
			default:
			}
		}
	}
}

// senderLoop performs transport I/O outside the event loop. | senderLoop 在事件循环
// 之外执行传输 I/O。
func (n *Node) senderLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.stopCh:
			return
		case batch := <-n.outCh:
			if len(batch.msgs) == 0 {
				continue
			}
			if err := n.transport.Send(context.Background(), batch.msgs); err != nil {
				n.metrics.messagesDropped.Add(uint64(len(batch.msgs)))
				n.logf("warn", "raft transport send failed | raft 传输发送失败",
					ydlog.Uint64("node", uint64(n.id)), ydlog.Err(err))
			}
		}
	}
}

// flushOutbound batches messages produced by one event loop iteration. If the
// outbound queue is full the batch is dropped; Raft retransmits. | flushOutbound
// 批量发送一个事件循环迭代产生的消息。出站队列满时整批丢弃；Raft 会重传。
func (n *Node) flushOutbound() {
	if len(n.outBuf) == 0 {
		return
	}
	msgs := n.outBuf
	n.outBuf = n.outBuf[:0]
	if n.immediateTransport {
		// Built-in transports only enqueue, so the slice is reusable as soon as
		// Send returns. | 内置传输只入队，因此 Send 返回后即可复用切片。
		if err := n.transport.Send(context.Background(), msgs); err != nil {
			n.metrics.messagesDropped.Add(uint64(len(msgs)))
		}
		return
	}
	out := append([]Message(nil), msgs...)
	select {
	case n.outCh <- outboundBatch{msgs: out}:
	default:
		n.metrics.messagesDropped.Add(uint64(len(msgs)))
	}
}

// send appends one message to the current outbound batch. | send 将一条消息追加到
// 当前出站批次。
func (n *Node) send(m Message) {
	m.From = n.id
	if n.group != 0 {
		m.Group = n.group
	}
	if m.To == 0 || m.To == n.id {
		return
	}
	n.metrics.messagesOut.Add(1)
	n.outBuf = append(n.outBuf, m)
}

// broadcast sends one message to every peer in the active configuration.
// | broadcast 向生效配置中的每个对端发送一条消息。
func (n *Node) broadcast(m Message) {
	for id := range n.conf.voters {
		if id == n.id {
			continue
		}
		m.To = id
		n.send(m)
	}
	for id := range n.conf.learners {
		if id == n.id {
			continue
		}
		m.To = id
		n.send(m)
	}
	for id := range n.conf.votersOut {
		if id == n.id {
			continue
		}
		m.To = id
		n.send(m)
	}
	for id := range n.conf.learnersOut {
		if id == n.id {
			continue
		}
		m.To = id
		n.send(m)
	}
}

// step dispatches one inbound message. | step 分发一条入站消息。
func (n *Node) step(m Message) {
	if m.To != n.id || m.From == 0 {
		return
	}
	if m.Term > n.term {
		if m.Type == MsgPreVote {
			// Pre-vote intentionally does not advance the local term. | 预投票有意
			// 不推进本地任期。
			n.handlePreVote(m)
			return
		}
		n.becomeFollower(m.Term, 0, true)
	}
	switch m.Type {
	case MsgHup:
		n.campaign(false)
	case MsgPreVote:
		n.handlePreVote(m)
	case MsgPreVoteResp:
		n.handlePreVoteResp(m)
	case MsgVote:
		n.handleVote(m)
	case MsgVoteResp:
		n.handleVoteResp(m)
	case MsgApp:
		n.handleAppend(m)
	case MsgAppResp:
		n.handleAppendResp(m)
	case MsgHeartbeat:
		n.handleHeartbeat(m)
	case MsgHeartbeatResp:
		n.handleHeartbeatResp(m)
	case MsgSnap:
		n.handleSnapshot(m)
	case MsgSnapResp:
		n.handleSnapshotResp(m)
	case MsgTransferLeader:
		n.handleTransferMessage(m)
	case MsgTimeoutNow:
		n.handleTimeoutNow(m)
	case MsgReadIndex:
		n.handleReadIndexMessage(m)
	case MsgReadIndexResp:
		n.handleReadIndexResp(m)
	}
}

// tick advances the logical clock. | tick 推进逻辑时钟。
func (n *Node) tick() {
	switch n.state {
	case StateLeader:
		n.tickLeader()
	case StateCandidate, StatePreCandidate:
		n.tickCandidate()
	default:
		n.tickFollower()
	}
}

// tickFollower starts an election after a randomized timeout. | tickFollower 在随机
// 超时后发起选举。
func (n *Node) tickFollower() {
	n.electionElapsed++
	if n.electionElapsed < n.electionTimeout {
		return
	}
	if !n.conf.isVoter(n.id) {
		n.electionElapsed = 0
		n.electionTimeout = n.cfg.electionTimeoutTicks()
		return
	}
	n.campaign(!n.cfg.DisablePreVote)
}

// tickCandidate retries an election after a timeout. | tickCandidate 在超时后重试选举。
func (n *Node) tickCandidate() {
	n.electionElapsed++
	if n.electionElapsed < n.electionTimeout {
		return
	}
	n.campaign(!n.cfg.DisablePreVote)
}

// tickLeader drives heartbeats, quorum checks and leader transfer deadlines.
// | tickLeader 驱动心跳、法定人数检查与领导权转移期限。
func (n *Node) tickLeader() {
	n.heartbeatElapsed++
	n.electionElapsed++
	if n.heartbeatElapsed >= n.heartbeatTicks {
		n.heartbeatElapsed = 0
		n.heartbeatRound()
	}
	if n.leadTransferee != 0 {
		n.transferElapsed++
		if n.transferElapsed >= n.electionTimeout {
			n.abortTransfer(ErrTimeout)
		}
	}
	if n.cfg.DisableCheckQuorum {
		return
	}
	if n.electionElapsed < n.electionTimeout {
		return
	}
	n.electionElapsed = 0
	if !n.quorumActive() {
		n.logf("warn", "raft leader lost quorum | raft 领导者失去法定人数",
			ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("term", n.term))
		n.becomeFollower(n.term, 0, false)
		return
	}
	for _, pr := range n.progress {
		pr.recentActive = false
	}
	if self := n.progress[n.id]; self != nil {
		self.recentActive = true
	}
}

// quorumActive reports whether a majority of every voter set was heard from
// during the last election interval. | quorumActive 报告上一选举周期内是否听到每个
// 投票集合的多数成员。
func (n *Node) quorumActive() bool {
	return n.conf.hasQuorum(func(id NodeID) bool {
		if id == n.id {
			return true
		}
		pr := n.progress[id]
		return pr != nil && pr.recentActive
	})
}

// failWaiters resolves every blocked API call with err. | failWaiters 用 err 结束所有
// 阻塞的 API 调用。
func (n *Node) failWaiters(err error) {
	// Proposals still queued when the node stops never reached the future store.
	// Fail them too so callers do not wait for their context to expire. | 节点
	// 停止时仍在队列中的提案从未进入 Future 存储；同样让它们失败，避免调用方等待
	// 上下文超时。
	for _, p := range n.proposals.drainAndClose() {
		if p != nil && p.future != nil {
			p.future.fail(err)
		}
	}
	n.futures.failAll(err)
	n.remoteReads.failAll(err)
	n.metrics.futuresFailed.Add(1)
	if n.pendingConf != nil && n.pendingConf.future != nil && !n.pendingConf.resolved {
		n.pendingConf.future.fail(err)
		n.pendingConf.resolved = true
	}
	n.resolveReads(err)
	for _, ch := range n.campaignWaiters {
		sendErr(ch, err)
	}
	n.campaignWaiters = nil
	for _, ch := range n.transferWaiters {
		sendErr(ch, err)
	}
	n.transferWaiters = nil
	for _, ch := range n.snapshotWaiters {
		sendErr(ch, err)
	}
	n.snapshotWaiters = nil
	if n.activeSnapshotReq != nil {
		sendErr(n.activeSnapshotReq.done, err)
		n.activeSnapshotReq = nil
	}
	n.snapshotting = false
	n.signalSnapshotDone()
}

// sendErr performs a non-blocking one-shot reply. | sendErr 执行非阻塞一次性应答。
func sendErr(ch chan error, err error) {
	if ch == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
}

// sendIndex performs a non-blocking read reply. | sendIndex 执行非阻塞读应答。
func sendIndex(ch chan readResult, index uint64, err error) {
	if ch == nil {
		return
	}
	select {
	case ch <- readResult{index: index, err: err}:
	default:
	}
}
