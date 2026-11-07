package raft

import (
	"context"
	"time"

	ydlog "github.com/shibingli/ydx/log"
)

// stop closes the shared stop channel exactly once. | stop 只关闭一次共享停止通道。
func (n *Node) stop() {
	n.stopOnce.Do(func() {
		// Discard queued apply work before waiting for the worker. Otherwise a
		// large backlog would keep Close blocked while it drains entries that
		// can no longer be acknowledged. | 在等待 apply 协程前丢弃排队工作，否则
		// 大量积压会让 Close 一直等待已经无法确认的日志项。
		if n.applyQueue != nil {
			n.applyQueue.close()
		}
		close(n.stopCh)
	})
}

// run is the single Raft event loop. All mutable Raft state below the atomic
// mirrors belongs to this goroutine. | run 是唯一的 Raft 事件循环。原子镜像之下的
// 所有可变 Raft 状态都属于该协程。
func (n *Node) run() {
	defer n.wg.Done()
	defer close(n.doneCh)
	defer n.stopElectionTimer()
	if n.autoCampaign {
		n.campaign(false)
	}
	n.advanceApply()
	for {
		// The fast drain handles work that is already queued with non-blocking
		// single-channel operations. Those compile to plain channel sends and
		// receives, so a busy node never pays selectgo's lock ordering for every
		// message. The multi-channel select below is only entered when the loop
		// is idle. | 快速排空用非阻塞的单通道操作处理已排队工作，编译为普通通道
		// 收发，繁忙节点因此无需为每条消息支付 selectgo 的锁排序开销。只有空闲时
		// 才进入下面的多通道 select。
		select {
		case <-n.stopCh:
			n.failWaiters(ErrStopped)
			return
		case err := <-n.fatalCh:
			n.failWaiters(err)
			n.stopped.Store(true)
			n.stateAtomic.Store(uint32(StateShutdown))
			n.stop()
			return
		default:
		}
		worked := n.drainControl()
		worked = n.drainMessages() || worked
		worked = n.drainPersistAcks() || worked
		worked = n.drainProposalNotify() || worked
		worked = n.drainTick() || worked
		worked = n.drainElectionTimer() || worked
		worked = n.drainLocalRequests() || worked
		n.flushOutbound()
		if worked {
			continue
		}
		select {
		case <-n.stopCh:
			n.failWaiters(ErrStopped)
			return
		case <-n.tickCh:
			n.tick()
		case <-n.electionTimer.C:
			n.handleElectionTimer()
		case m := <-n.controlCh:
			n.step(m)
			releaseMessage(m)
		case m := <-n.recvCh:
			n.step(m)
			releaseMessage(m)
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
		case req := <-n.snapshotConfCh:
			select {
			case req.reply <- n.configAt(req.index).confState():
			default:
			}
		case result := <-n.snapshotFileCh:
			n.handleSnapshotFileResult(result)
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

// fastDrainBatch bounds how much queued work one fast-drain pass handles, so
// ticks, elections, reads and control traffic stay responsive under a flood of
// replication messages. | fastDrainBatch 限制单次快速排空处理的工作量，保证在复制
// 消息洪峰下 tick、选举、读请求与控制流量仍能及时处理。
const fastDrainBatch = 64

// drainMessages processes queued peer messages without entering the blocking
// select. | drainMessages 不进入阻塞 select 处理已排队的对端消息。
func (n *Node) drainMessages() bool {
	worked := false
	for i := 0; i < fastDrainBatch; i++ {
		select {
		case m := <-n.recvCh:
			n.step(m)
			releaseMessage(m)
			worked = true
		default:
			return worked
		}
	}
	return true
}

// drainPersistAcks reaps completed persistence batches. | drainPersistAcks 回收已
// 完成的持久化批次。
func (n *Node) drainPersistAcks() bool {
	worked := false
	for i := 0; i < fastDrainBatch; i++ {
		select {
		case ack := <-n.persistAckCh:
			n.handlePersistAck(ack)
			worked = true
		default:
			return worked
		}
	}
	return true
}

// drainProposalNotify consumes one proposal wakeup. handleProposalIntake
// re-signals when more work remains. | drainProposalNotify 消费一次提案唤醒；
// 仍有工作时 handleProposalIntake 会重新发信号。
func (n *Node) drainProposalNotify() bool {
	select {
	case <-n.proposals.notify:
		n.handleProposalIntake()
		return true
	default:
		return false
	}
}

// drainTick consumes one queued tick. | drainTick 消费一个已排队的 tick。
func (n *Node) drainTick() bool {
	select {
	case <-n.tickCh:
		n.tick()
		return true
	default:
		return false
	}
}

// drainElectionTimer consumes an expired election timer. | drainElectionTimer 消费
// 已到期的选举定时器。
func (n *Node) drainElectionTimer() bool {
	select {
	case <-n.electionTimer.C:
		n.handleElectionTimer()
		return true
	default:
		return false
	}
}

// drainLocalRequests serves queued client-facing requests. These are rare, so
// each is polled once per pass. | drainLocalRequests 处理已排队的客户端请求。它们
// 很少，因此每轮各轮询一次。
func (n *Node) drainLocalRequests() bool {
	worked := false
	select {
	case r := <-n.readCh:
		n.handleRead(r)
		worked = true
	default:
	}
	select {
	case req := <-n.campaignCh:
		n.handleCampaignRequest(req)
		worked = true
	default:
	}
	select {
	case req := <-n.transferCh:
		n.handleTransferRequest(req)
		worked = true
	default:
	}
	select {
	case req := <-n.snapshotCh:
		n.handleSnapshotRequest(req)
		worked = true
	default:
	}
	select {
	case ready := <-n.snapshotReadyCh:
		n.handleSnapshotReady(ready)
		worked = true
	default:
	}
	select {
	case req := <-n.snapshotConfCh:
		select {
		case req.reply <- n.configAt(req.index).confState():
		default:
		}
		worked = true
	default:
	}
	select {
	case result := <-n.snapshotFileCh:
		n.handleSnapshotFileResult(result)
		worked = true
	default:
	}
	select {
	case reply := <-n.statusCh:
		reply <- n.buildStatus()
		worked = true
	default:
	}
	return worked
}

// drainControl processes queued control messages before ordinary traffic. The
// cap prevents a flood of control traffic from starving replication. | drainControl
// 在普通流量之前处理排队的控制消息。上限避免控制流量洪峰饿死复制。
func (n *Node) drainControl() bool {
	worked := false
	for i := 0; i < 256; i++ {
		select {
		case m := <-n.controlCh:
			n.step(m)
			releaseMessage(m)
			worked = true
		default:
			return worked
		}
	}
	return true
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

// flushOutbound batches messages produced by one event loop iteration. Control
// traffic is handed to the transport first so heartbeats, votes, snapshots and
// lease probes are not stuck behind a large replication batch. If the outbound
// queue is full the data batch is dropped; Raft retransmits. | flushOutbound 批量
// 发送一个事件循环迭代产生的消息。控制流量先交给传输层，避免心跳、选票、快照与
// 租约探测排在大批复制消息之后。出站队列满时数据批次被丢弃；Raft 会重传。
func (n *Node) flushOutbound() {
	if len(n.outBuf) == 0 {
		return
	}
	if n.outControls == 0 {
		msgs := n.outBuf
		n.outBuf = n.outBuf[:0]
		n.sendBatch(msgs)
		return
	}
	ctrl := n.outCtrlBuf[:0]
	data := n.outDataBuf[:0]
	for i := range n.outBuf {
		if isControlMessage(n.outBuf[i].Type) {
			ctrl = append(ctrl, n.outBuf[i])
		} else {
			data = append(data, n.outBuf[i])
		}
	}
	n.outBuf = n.outBuf[:0]
	n.outControls = 0
	n.outCtrlBuf = ctrl
	n.outDataBuf = data
	if len(ctrl) > 0 {
		n.sendBatch(ctrl)
	}
	if len(data) > 0 {
		n.sendBatch(data)
	}
}

// sendBatch hands one ordered batch to the transport. | sendBatch 将一个有序批次
// 交给传输层。
func (n *Node) sendBatch(msgs []Message) {
	if len(msgs) == 0 {
		return
	}
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

// sendSolo delivers one message in its own transport batch. Large snapshot
// chunks must not be coalesced with other control messages into one frame, or
// the transport frame limit would be exceeded again. | sendSolo 将一条消息作为
// 独立传输批次发送。大快照分块不得与其他控制消息合并进同一帧，否则会再次超过
// 传输帧上限。
func (n *Node) sendSolo(m Message) {
	m.From = n.id
	if n.group != 0 {
		m.Group = n.group
	}
	if m.To == 0 || m.To == n.id {
		return
	}
	n.metrics.messagesOut.Add(1)
	if n.immediateTransport {
		if err := n.transport.Send(context.Background(), []Message{m}); err != nil {
			n.metrics.messagesDropped.Add(1)
		}
		return
	}
	select {
	case n.outCh <- outboundBatch{msgs: []Message{m}}:
	default:
		n.metrics.messagesDropped.Add(1)
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
	if isControlMessage(m.Type) {
		n.outControls++
	}
	n.outBuf = append(n.outBuf, m)
}

// sendAfterTerm sends m once the hard-state write identified by seq is durable.
// A zero seq means the term was already durable and m can be sent immediately.
// | sendAfterTerm 在 seq 标识的硬状态写入持久化后发送 m。seq 为零表示任期已持久，
// 可立即发送。
func (n *Node) sendAfterTerm(seq uint64, term uint64, m Message) {
	if seq == 0 {
		n.send(m)
		return
	}
	n.deferAction(seq, func(err error) {
		if err == nil && n.term == term {
			n.send(m)
		}
	})
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
func (n *Node) step(m *Message) {
	if m.To != n.id || m.From == 0 {
		return
	}
	if m.Term < n.term {
		// Stale requests and most stale responses are ignored. Pre-vote replies
		// echo the responder's term, which may legitimately lag the candidate,
		// and read-index replies are matched by their unique context. | 过期请求与
		// 大多数过期响应会被忽略。预投票应答回显应答者任期，可能合法地低于候选者；
		// 读索引应答由唯一上下文匹配。
		switch m.Type {
		case MsgPreVote, MsgPreVoteResp, MsgReadIndexResp:
		default:
			return
		}
	}
	if m.Term > n.term {
		switch m.Type {
		case MsgPreVote:
			// Pre-vote intentionally does not advance the local term. | 预投票有意
			// 不推进本地任期。
			n.handlePreVote(m)
			return
		case MsgApp, MsgHeartbeat, MsgSnap:
			// The handler advances the term and persists it together with its
			// response barrier. | 处理器会推进任期，并与响应屏障一起持久化。
		case MsgTimeoutNow:
			// The sender is the new leader; install it so the handler's leader
			// check succeeds after the term is durable. | 发送者是新领导者；先安装
			// 它，使处理器在任期持久化后通过领导者校验。
			n.becomeFollower(m.Term, m.From, true)
		default:
			n.becomeFollower(m.Term, 0, true)
		}
	}
	switch m.Type {
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
	case MsgSnapChunk:
		n.handleSnapshotChunk(m)
	case MsgSnapChunkResp:
		n.handleSnapshotChunkResp(m)
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
	n.tickCount++
	// The wall-clock election timer is the primary trigger. A timer event can be
	// lost when a rapid heartbeat stream repeatedly stops and resets the same
	// timer; without this safety net the follower would then stay leaderless
	// forever while its deadline is already in the past. The tick check bounds
	// that liveness gap to one tick interval. | 墙钟选举定时器是主触发器。在密集心跳
	// 不断停止并重置同一计时器时，定时器事件可能丢失；若没有该兜底，跟随者的截止时间
	// 已过却会永久无 leader。tick 检查把该活性缺口限制在一个 tick 周期内。
	if n.state != StateLeader && !n.stopped.Load() && !n.electionDeadline.After(time.Now()) {
		n.logf("warn", "raft election deadline overdue | raft 选举截止时间已过",
			ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("state", uint64(n.state)),
			ydlog.Uint64("term", n.term), ydlog.Uint64("leader", uint64(n.leader)),
			ydlog.Int64("late_ms", time.Since(n.electionDeadline).Milliseconds()))
		n.handleElectionTimer()
	}
	switch n.state {
	case StateLeader:
		n.tickLeader()
	case StateCandidate, StatePreCandidate:
		n.tickCandidate()
	default:
		n.tickFollower()
	}
}

// tickFollower advances the tick clock used by pre-vote and leader-quorum
// checks. Elections are driven by the fine-grained wall-clock timer, not by
// tick quantization. | tickFollower 推进 pre-vote 与领导者法定人数检查使用的
// tick 时钟。选举由细粒度墙钟定时器驱动，而不是 tick 量化。
func (n *Node) tickFollower() {
	n.electionElapsed++
}

// tickCandidate advances the tick clock while a candidate waits for votes. |
// tickCandidate 在候选者等待选票时推进 tick 时钟。
func (n *Node) tickCandidate() {
	n.electionElapsed++
	if n.state == StatePreCandidate && len(n.preVoteRemaining) > 0 &&
		n.tickCount >= n.preVoteExpandTick {
		n.expandPreVote()
	}
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
	n.failPendingReads(err)
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
