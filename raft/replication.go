package raft

import (
	"time"

	ydlog "github.com/shibingli/ydx/log"
)

// broadcastAppend asks every follower to catch up. | broadcastAppend 请求每个跟随者
// 追赶日志。
func (n *Node) broadcastAppend() {
	if n.state != StateLeader {
		return
	}
	for id := range n.progress {
		if id == n.id {
			continue
		}
		n.maybeSendAppend(id)
	}
}

// maybeSendAppend sends the next pipelined AppendEntries batch to one follower.
// | maybeSendAppend 向一个跟随者发送下一批流水线 AppendEntries。
func (n *Node) maybeSendAppend(to NodeID) {
	if n.state != StateLeader {
		return
	}
	pr := n.progress[to]
	if pr == nil || pr.state == snapshot {
		return
	}
	next := pr.next
	if next <= n.log.firstIndex-1 || next <= n.log.snapshotIndex {
		n.sendSnapshot(to)
		return
	}
	if next > n.log.lastIndex {
		return
	}
	// Bound the source range before slicing. Otherwise a leader with a long log
	// scans up to MaxBatchBytes worth of entries (thousands) only to discard all
	// but MaxBatchEntries, adding O(log tail) work to every follower ack. | 先限制
	// 源区间。否则长日志领导者会为每次跟随者确认扫描最多 MaxBatchBytes 的日志项
	// （数千条），随后又丢弃到 MaxBatchEntries，给每个确认增加 O(日志尾部) 的工作。
	hi := n.log.lastIndex + 1
	if limit := next + uint64(n.maxBatchEntries); limit < hi {
		hi = limit
	}
	entries, err := n.log.slice(next, hi, n.maxBatchBytes)
	if err != nil {
		n.sendSnapshot(to)
		return
	}
	// Respect the per-follower pipeline window. The first entry is always
	// admitted so a large command cannot stall replication forever. | 遵守每跟随者
	// 流水线窗口。第一条日志项总是放行，避免超大命令永久阻塞复制。
	availMsgs := n.maxInflightMsgs - pr.inflights.count
	availBytes := n.maxInflightBytes - pr.inflights.bytes
	count := 0
	bytes := 0
	for count < len(entries) && count < availMsgs {
		sz := entries[count].size()
		if count > 0 && bytes+sz > availBytes {
			break
		}
		bytes += sz
		count++
	}
	if count == 0 {
		return
	}
	entries = entries[:count]
	for i := range entries {
		pr.inflights.add(entries[i].Index, entries[i].size())
	}
	prev := next - 1
	msg := Message{
		Type:     MsgApp,
		To:       to,
		Term:     n.term,
		LogIndex: prev,
		LogTerm:  n.log.mustTerm(prev),
		Entries:  entries,
		Commit:   n.committed,
	}
	pr.state = replicate
	n.metrics.appendsOut.Add(1)
	n.send(msg)
}

// sendSnapshot transfers the latest snapshot to a lagging follower. | sendSnapshot
// 将最新快照传输给落后跟随者。
func (n *Node) sendSnapshot(to NodeID) {
	if n.state != StateLeader {
		return
	}
	pr := n.progress[to]
	if pr == nil {
		return
	}
	snap := n.latestSnapshot
	if snap == nil {
		n.logf("warn", "raft cannot send snapshot | raft 无法发送快照",
			ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)))
		return
	}
	if snap.Index <= pr.match {
		pr.next = pr.match + 1
		pr.state = probe
		n.maybeSendAppend(to)
		return
	}
	pr.becomesSnapshot(snap.Index)
	pr.lastSnapshotTick = n.tickCount
	n.logf("info", "raft sending snapshot | raft 发送快照",
		ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
		ydlog.Uint64("index", snap.Index))
	n.send(Message{Type: MsgSnap, To: to, Term: n.term, Snapshot: snap})
}

// handleAppend processes an AppendEntries request. Log mutations and the new
// term are persisted before the success or rejection response is sent. | handleAppend
// 处理 AppendEntries 请求。日志变更与新任期在发送成功或拒绝响应之前持久化。
func (n *Node) handleAppend(m Message) {
	n.metrics.appendsIn.Add(1)
	if m.Term < n.term {
		n.send(Message{Type: MsgAppResp, To: m.From, Term: n.term, Reject: true,
			RejectHint: n.log.lastIndex + 1})
		return
	}
	termChanged := m.Term > n.term
	var termSeq uint64
	if termChanged {
		termSeq = n.becomeFollower(m.Term, m.From, true)
	} else {
		if n.state != StateFollower {
			n.becomeFollower(n.term, m.From, false)
		}
		n.setLeader(m.From)
		n.resetElection()
	}
	oldLast := n.log.lastIndex
	lastNew, commit, truncatedAt, conflict := n.log.maybeAppend(m.LogIndex, m.LogTerm, m.Commit, m.Entries)
	if conflict != nil {
		resp := Message{
			Type:       MsgAppResp,
			To:         m.From,
			Term:       n.term,
			Reject:     true,
			RejectHint: conflict.index,
			RejectTerm: conflict.term,
		}
		if termSeq > 0 {
			n.deferAction(termSeq, func(err error) {
				if err == nil {
					n.send(resp)
				}
			})
		} else {
			n.send(resp)
		}
		return
	}
	if truncatedAt > 0 {
		n.truncateConfig(truncatedAt)
	}
	from := oldLast + 1
	if truncatedAt > 0 {
		from = truncatedAt
	}
	if err := n.appendConfig(m.Entries, from); err != nil {
		n.fatal(err)
		return
	}
	if commit > n.committed {
		n.setCommitted(commit)
		n.advanceApply()
		n.maybeCompleteConf()
	}
	if !termChanged && len(m.Entries) == 0 && truncatedAt == 0 {
		n.send(Message{Type: MsgAppResp, To: m.From, Term: n.term, Index: lastNew})
		return
	}
	batchHS := n.hardState()
	seq := n.persist(PersistBatch{HardState: &batchHS, Truncate: truncatedAt, Entries: m.Entries}, 0, nil)
	n.deferAction(seq, func(err error) {
		if err != nil || n.term != m.Term {
			return
		}
		n.persistedIndex = max64(n.persistedIndex, lastNew)
		n.send(Message{Type: MsgAppResp, To: m.From, Term: n.term, Index: lastNew})
	})
}

// handleAppendResp processes a follower's append result, including fast
// backtracking on a rejected consistency check. | handleAppendResp 处理跟随者的追加
// 结果，包括一致性检查失败时的快速回退。
func (n *Node) handleAppendResp(m Message) {
	if n.state != StateLeader {
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, 0, true)
		return
	}
	if m.Term < n.term {
		return
	}
	pr := n.progress[m.From]
	if pr == nil {
		return
	}
	pr.recentActive = true
	// Responses to appends sent before a snapshot transfer are stale. Processing
	// them would switch the follower out of snapshot state and restart normal
	// replication from an index the follower cannot serve, starving the only
	// transfer that can recover it. | 快照传输开始前发出的追加响应已经过时。处理它们
	// 会让跟随者退出快照状态，并从一个它无法提供的位置重启普通复制，饿死唯一能恢复
	// 它的传输。
	if pr.state == snapshot {
		pr.inflights.freeTo(m.Index)
		return
	}
	if m.Reject {
		hint := m.RejectHint
		if m.RejectTerm != 0 {
			if last, ok := n.log.lastIndexInTerm(m.RejectTerm); ok {
				hint = last + 1
			}
		}
		if hint == 0 {
			hint = m.Index
		}
		if hint > n.log.lastIndex+1 {
			hint = n.log.lastIndex + 1
		}
		pr.maybeDecrTo(hint)
		n.maybeSendAppend(m.From)
		return
	}
	if m.Index > n.log.lastIndex {
		m.Index = n.log.lastIndex
	}
	if m.Index >= pr.match {
		pr.update(m.Index)
		n.maybeCommit()
	} else {
		pr.inflights.freeTo(m.Index)
	}
	if n.leadTransferee == m.From && !n.transferSent && pr.match >= n.log.lastIndex {
		n.sendTimeoutNow()
	}
	n.maybeSendAppend(m.From)
}

// handleHeartbeat processes a leader heartbeat. | handleHeartbeat 处理领导者心跳。
func (n *Node) handleHeartbeat(m Message) {
	n.metrics.heartbeatsIn.Add(1)
	if m.Term < n.term {
		n.send(Message{Type: MsgHeartbeatResp, To: m.From, Term: n.term, Reject: true})
		return
	}
	var seq uint64
	if m.Term > n.term {
		seq = n.becomeFollower(m.Term, m.From, true)
	} else {
		if n.state != StateFollower {
			n.becomeFollower(n.term, m.From, false)
		}
		n.setLeader(m.From)
		n.resetElection()
	}
	if m.Commit > n.committed {
		commit := min64(m.Commit, n.log.lastIndex)
		if commit > n.committed {
			n.setCommitted(commit)
			n.advanceApply()
			n.maybeCompleteConf()
		}
	}
	resp := Message{
		Type:    MsgHeartbeatResp,
		To:      m.From,
		Term:    n.term,
		Index:   n.log.lastIndex,
		Commit:  n.committed,
		Context: m.Context,
	}
	if seq > 0 {
		n.deferAction(seq, func(err error) {
			if err == nil && n.term == m.Term {
				n.send(resp)
			}
		})
		return
	}
	n.send(resp)
}

// handleHeartbeatResp processes heartbeat acknowledgements, lease rounds and
// follower catch-up. | handleHeartbeatResp 处理心跳确认、租约轮次与跟随者追赶。
func (n *Node) handleHeartbeatResp(m Message) {
	if n.state != StateLeader {
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, 0, true)
		return
	}
	if m.Term < n.term {
		return
	}
	pr := n.progress[m.From]
	if pr == nil {
		return
	}
	pr.recentActive = true
	pr.inflights.freeTo(m.Index)
	// A new or lagging member reports its last index in the heartbeat response.
	// Move next back so the probe can start from a position the follower can
	// verify; without this a freshly added node would never receive its first
	// AppendEntries. | 新成员或落后成员会在心跳响应中报告最后索引。将 next 回退到
	// 跟随者能够校验的位置；否则新加入节点永远收不到第一条 AppendEntries。
	if m.Index < pr.next-1 {
		next := m.Index + 1
		if next < 1 {
			next = 1
		}
		if next > n.log.lastIndex+1 {
			next = n.log.lastIndex + 1
		}
		if next < pr.match+1 {
			next = pr.match + 1
		}
		pr.next = next
		pr.state = probe
		pr.inflights.reset()
	} else if pr.state == replicate && pr.inflights.count >= pr.inflights.maxMsgs {
		// The pipeline is full and the follower answered a heartbeat. Acks for
		// messages sent to a previous incarnation may have been lost (a restart
		// or connection reset), so re-probe from match+1. This can duplicate
		// entries, which Raft handles idempotently. | 流水线已满且跟随者已回应心跳。
		// 发往旧实例的消息确认可能已丢失（重启或连接重置），因此从 match+1 重新探测。
		// 这会重复发送日志项，Raft 可幂等处理。
		pr.state = probe
		pr.next = pr.match + 1
		pr.inflights.reset()
	}
	n.ackReadRound(m.From, m.Context)
	if pr.state != snapshot {
		n.maybeSendAppend(m.From)
	}
	if n.leadTransferee == m.From && !n.transferSent && pr.match >= n.log.lastIndex {
		n.sendTimeoutNow()
	}
}

// heartbeatRound sends periodic heartbeats, starts a lease round when needed,
// and retries pending snapshot transfers. | heartbeatRound 发送周期心跳、在需要时
// 启动租约轮次，并重试未完成的快照传输。
func (n *Node) heartbeatRound() {
	if n.state != StateLeader {
		return
	}
	started := false
	if n.readRound == nil && !n.cfg.DisableCheckQuorum && !n.cfg.DisableLeaseRead {
		n.startReadRound()
		started = true
	}
	if !started {
		var context []byte
		if n.readRound != nil {
			context = encodeRoundContext(n.readRound.id)
		}
		msg := Message{Type: MsgHeartbeat, Term: n.term, Commit: n.committed, Context: context}
		n.broadcast(msg)
	}
	for id, pr := range n.progress {
		if id == n.id {
			continue
		}
		if pr.state == snapshot {
			if n.tickCount-pr.lastSnapshotTick >= 5 {
				n.sendSnapshot(id)
			}
			continue
		}
		if pr.next <= n.log.lastIndex {
			n.maybeSendAppend(id)
		}
	}
}

// maybeCommit advances the leader commit index to the highest entry replicated
// on a majority of every active voter set and stored in the current term.
// | maybeCommit 将领导者提交索引推进到每个生效投票集合多数已复制、且属于当前任期的
// 最高日志项。
func (n *Node) maybeCommit() {
	if n.state != StateLeader {
		return
	}
	selfMatch := min64(n.persistedIndex, n.log.lastIndex)
	quorum := n.conf.quorumMatch(n.progress, n.id, selfMatch, n.scratch)
	if quorum <= n.committed {
		return
	}
	if term, err := n.log.term(quorum); err != nil || term != n.term {
		return
	}
	n.setCommitted(quorum)
	n.advanceApply()
	n.maybeCompleteConf()
	n.maybeAutoLeave()
	n.finishRemovals()
	n.broadcastCommit()
	if n.state == StateLeader && !n.conf.isVoter(n.id) {
		if n.leaveIndex == 0 || n.committed >= n.leaveIndex {
			n.logf("info", "raft leader removed itself | raft 领导者移除了自身",
				ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("term", n.term))
			n.becomeFollower(n.term, 0, false)
		}
	}
}

// finishRemovals drops replication progress for members removed by a final
// configuration once that configuration commits. | finishRemovals 在最终配置提交后
// 丢弃被移除成员的复制进度。
func (n *Node) finishRemovals() {
	if n.leaveIndex == 0 || n.committed < n.leaveIndex || len(n.pendingRemoval) == 0 {
		return
	}
	for _, id := range n.pendingRemoval {
		delete(n.progress, id)
	}
	n.pendingRemoval = nil
}

// broadcastCommit informs followers that the leader's commit index advanced so
// they can apply entries without waiting for the next heartbeat. | broadcastCommit
// 通知跟随者领导者提交索引已推进，使其无需等待下次心跳即可应用日志。
func (n *Node) broadcastCommit() {
	msg := Message{Type: MsgHeartbeat, Term: n.term, Commit: n.committed}
	n.broadcast(msg)
}

// conflictHintFor computes the leader's restart index from a follower hint.
// | conflictHintFor 根据跟随者提示计算领导者重启索引。
func (n *Node) conflictHintFor(m Message) uint64 {
	hint := m.RejectHint
	if hint == 0 {
		hint = m.Index
	}
	if m.RejectTerm != 0 {
		if last, ok := n.log.lastIndexInTerm(m.RejectTerm); ok {
			hint = last + 1
		}
	}
	return hint
}

// now is a test seam for lease calculations. | now 是租约计算的可测试接缝。
func (n *Node) now() time.Time { return time.Now() }
