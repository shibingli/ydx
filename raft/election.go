package raft

import (
	"slices"
	"time"

	ydlog "github.com/shibingli/ydx/log"
)

// campaign starts a pre-vote or a real election. Pre-vote probes the cluster
// without advancing the term, so a partitioned member cannot depose a healthy
// leader. | campaign 发起预投票或真实选举。预投票在不推进任期的情况下探测集群，
// 因此被分区成员无法罢免健康领导者。
func (n *Node) campaign(preVote bool) {
	if n.state == StateLeader || !n.conf.isVoter(n.id) {
		return
	}
	if preVote && !n.cfg.DisablePreVote {
		n.startPreVote()
		return
	}
	n.startVote()
}

// startPreVote sends MsgPreVote with a hypothetical next term. | startPreVote 用假设
// 的下一任期发送 MsgPreVote。
func (n *Node) startPreVote() {
	n.setState(StatePreCandidate)
	n.setLeader(0)
	n.incomingSnapshot = nil
	n.selfVoteDurable = false
	n.resetElection()
	n.preVotes = make(map[NodeID]bool, len(n.conf.voters)+1)
	n.preVotes[n.id] = true
	n.preVoteSent = make(map[NodeID]struct{}, len(n.conf.voters)+1)
	n.preVotePending = make(map[NodeID]struct{}, len(n.conf.voters)+1)
	n.preVoteRemaining = nil
	n.preVoteExpandTick = n.tickCount + 1
	n.metrics.preVotes.Add(1)
	n.preVoteReq = Message{
		Type:     MsgPreVote,
		Term:     n.term + 1,
		LogIndex: n.log.lastIndex,
		LogTerm:  n.log.lastTerm(),
	}
	initial, remaining := n.preVoteTargets()
	n.preVoteRemaining = remaining
	n.sendPreVoteTargets(initial)
	if n.conf.hasQuorum(func(id NodeID) bool { return n.preVotes[id] }) {
		n.startVote()
	}
}

// preVoteTargets chooses the first bounded pre-vote wave. It always contains a
// quorum of every voter set (self included), plus a small failure budget; the
// rest are contacted only if needed. | preVoteTargets 选择首轮有界 pre-vote 目标。
// 首轮始终包含每个投票集合的多数（含自身）以及少量容错余量；其余成员仅在需要时
// 联系。
func (n *Node) preVoteTargets() (initial, remaining []NodeID) {
	allSet := make(map[NodeID]struct{}, len(n.conf.voters)+len(n.conf.votersOut))
	for id := range n.conf.voters {
		if id != n.id {
			allSet[id] = struct{}{}
		}
	}
	for id := range n.conf.votersOut {
		if id != n.id {
			allSet[id] = struct{}{}
		}
	}
	all := make([]NodeID, 0, len(allSet))
	for id := range allSet {
		all = append(all, id)
	}
	slices.Sort(all)
	if len(all)+1 <= n.cfg.PreVoteSubsetThreshold {
		return all, nil
	}
	selected := make(map[NodeID]struct{}, len(all))
	addQuorum := func(set map[NodeID]struct{}) {
		if len(set) == 0 {
			return
		}
		need := len(set)/2 + 1
		count := 0
		if _, self := set[n.id]; self {
			count++
		}
		for id := range selected {
			if _, ok := set[id]; ok {
				count++
			}
		}
		for _, id := range all {
			if count >= need {
				break
			}
			if _, ok := set[id]; !ok {
				continue
			}
			if _, ok := selected[id]; ok {
				continue
			}
			selected[id] = struct{}{}
			count++
		}
	}
	addQuorum(n.conf.voters)
	addQuorum(n.conf.votersOut)
	extra := n.cfg.PreVoteSubsetExtra
	for _, id := range all {
		if extra <= 0 {
			break
		}
		if _, ok := selected[id]; ok {
			continue
		}
		selected[id] = struct{}{}
		extra--
	}
	initial = make([]NodeID, 0, len(selected))
	for id := range selected {
		initial = append(initial, id)
	}
	slices.Sort(initial)
	remaining = make([]NodeID, 0, len(all)-len(initial))
	for _, id := range all {
		if _, ok := selected[id]; !ok {
			remaining = append(remaining, id)
		}
	}
	return initial, remaining
}

// sendPreVoteTargets sends the pre-vote request to peers not contacted yet. |
// sendPreVoteTargets 向尚未联系的成员发送 pre-vote 请求。
func (n *Node) sendPreVoteTargets(ids []NodeID) {
	for _, id := range ids {
		if _, sent := n.preVoteSent[id]; sent {
			continue
		}
		n.preVoteSent[id] = struct{}{}
		n.preVotePending[id] = struct{}{}
		m := n.preVoteReq
		m.To = id
		n.send(m)
	}
}

// expandPreVote contacts the remaining voters after the first wave cannot
// reach a quorum. | expandPreVote 在首轮无法达到多数后联系其余投票成员。
func (n *Node) expandPreVote() {
	if n.state != StatePreCandidate || len(n.preVoteRemaining) == 0 {
		return
	}
	targets := n.preVoteRemaining
	n.preVoteRemaining = nil
	n.sendPreVoteTargets(targets)
}

// startVote increments the term, votes for self and asks every voter for a vote
// only after the new term and vote are durable. | startVote 提升任期、自投票，并且
// 只在新任期与选票持久化后请求选票。
func (n *Node) startVote() {
	n.setTerm(n.term + 1)
	n.vote = n.id
	n.setState(StateCandidate)
	n.setLeader(0)
	n.incomingSnapshot = nil
	n.resetElection()
	n.votes = make(map[NodeID]bool, len(n.conf.voters)+1)
	n.preVotes = make(map[NodeID]bool)
	n.preVoteSent = nil
	n.preVotePending = nil
	n.preVoteRemaining = nil
	n.preVoteReq = Message{}
	n.selfVoteDurable = false
	n.metrics.elections.Add(1)
	last := n.log.lastIndex
	lastTerm := n.log.lastTerm()
	term := n.term
	seq := n.persistHardState()
	// Send the vote requests while the term and self-vote are being persisted.
	// Voters still persist their grants before responding, and this candidate
	// does not count its own vote or become leader until its hard state is
	// durable (see maybeBecomeLeader). This overlaps one fsync with the network
	// round trip; a crash before durability loses only this candidacy, because
	// the vote cannot be counted and no leader action is taken. | 在持久化任期与
	// 自投票的同时发送投票请求。投票者仍会在响应前持久化授权，而本候选者在硬状态
	// 持久化完成前不会计入自投票或成为领导者（见 maybeBecomeLeader）。这样把一次
	// fsync 与网络往返重叠；持久化前崩溃只会丢失本次候选资格，因为选票不会被计入，
	// 也不会执行领导者动作。
	n.broadcastVoters(Message{
		Type:     MsgVote,
		Term:     term,
		LogIndex: last,
		LogTerm:  lastTerm,
	})
	n.deferAction(seq, func(err error) {
		if err != nil || n.term != term || n.state != StateCandidate {
			return
		}
		n.selfVoteDurable = true
		n.votes[n.id] = true
		n.maybeBecomeLeader()
	})
}

// maybeBecomeLeader promotes a candidate once its own vote is durable and every
// active voter set has a quorum. | maybeBecomeLeader 在候选者自投票已持久化且每个
// 生效投票集合都达到多数时将其提升为领导者。
func (n *Node) maybeBecomeLeader() {
	if n.state != StateCandidate || !n.selfVoteDurable {
		return
	}
	if n.conf.hasQuorum(func(id NodeID) bool { return n.votes[id] }) {
		n.becomeLeader()
	}
}

// broadcastVoters sends one message to each voter in both joint sets. | broadcastVoters
// 向联合配置的两个投票集合中的每个成员发送一条消息。
func (n *Node) broadcastVoters(m Message) {
	seen := make(map[NodeID]struct{}, len(n.conf.voters)+len(n.conf.votersOut))
	for id := range n.conf.voters {
		if id == n.id {
			continue
		}
		seen[id] = struct{}{}
		m.To = id
		n.send(m)
	}
	for id := range n.conf.votersOut {
		if id == n.id {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		m.To = id
		n.send(m)
	}
}

// handlePreVote decides a pre-vote request without changing the local term.
// | handlePreVote 在不改变本地任期的情况下裁决预投票请求。
func (n *Node) handlePreVote(m Message) {
	grant := false
	if m.Term > n.term && n.conf.isVoter(n.id) && n.conf.isVoter(m.From) &&
		n.log.upToDate(m.LogIndex, m.LogTerm) {
		stickWindow := n.electionTicks
		if n.state == StateLeader {
			// A leader uses its full check-quorum interval; a healthy leader
			// must not grant a pre-vote just because the minimum window passed.
			// | 领导者使用完整法定人数检查间隔；健康领导者不能仅因最小窗口已过就
			// 授予预投票。
			stickWindow = n.electionTimeout
		}
		if n.leader == 0 || n.electionElapsed >= stickWindow {
			grant = true
		}
	}
	n.send(Message{
		Type:   MsgPreVoteResp,
		To:     m.From,
		Term:   n.term,
		Reject: !grant,
	})
}

// handlePreVoteResp counts a pre-vote grant and starts a real election on a
// majority of both voter sets. | handlePreVoteResp 统计预投票，并在两个投票集合都
// 达到多数时发起真实选举。
func (n *Node) handlePreVoteResp(m Message) {
	if n.state != StatePreCandidate {
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, 0, true)
		return
	}
	delete(n.preVotePending, m.From)
	if m.Reject || !n.conf.isVoter(m.From) {
		if len(n.preVotePending) == 0 {
			n.expandPreVote()
		}
		return
	}
	n.preVotes[m.From] = true
	if n.conf.hasQuorum(func(id NodeID) bool { return n.preVotes[id] }) {
		n.startVote()
		return
	}
	if len(n.preVotePending) == 0 {
		n.expandPreVote()
	}
}

// handleVote grants at most one vote per term, and only to an up-to-date
// candidate. The grant is persisted before the response is sent. | handleVote
// 每个任期最多投一票，且只投给日志足够新的候选者；响应前先持久化选票。
func (n *Node) handleVote(m Message) {
	if m.Term < n.term {
		n.send(Message{Type: MsgVoteResp, To: m.From, Term: n.term, Reject: true})
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, 0, true)
	}
	canVote := n.vote == 0 || n.vote == m.From
	if !canVote || !n.conf.isVoter(n.id) || !n.conf.isVoter(m.From) ||
		!n.log.upToDate(m.LogIndex, m.LogTerm) {
		n.send(Message{Type: MsgVoteResp, To: m.From, Term: n.term, Reject: true})
		return
	}
	n.vote = m.From
	n.resetElection()
	seq := n.persistHardState()
	n.deferAction(seq, func(err error) {
		if err != nil || n.term != m.Term || n.vote != m.From {
			return
		}
		n.send(Message{Type: MsgVoteResp, To: m.From, Term: n.term})
	})
}

// handleVoteResp counts a vote. | handleVoteResp 统计选票。
func (n *Node) handleVoteResp(m Message) {
	if n.state != StateCandidate {
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, 0, true)
		return
	}
	if m.Reject || m.Term < n.term || !n.conf.isVoter(m.From) {
		return
	}
	n.votes[m.From] = true
	n.maybeBecomeLeader()
}

// becomeLeader initializes replication progress and appends a no-op entry in the
// new term so earlier entries can commit safely. | becomeLeader 初始化复制进度并
// 追加新任期空操作日志项，使更早的日志项能够安全提交。
func (n *Node) becomeLeader() {
	if n.state == StateLeader {
		return
	}
	n.setState(StateLeader)
	n.setLeader(n.id)
	n.incomingSnapshot = nil
	n.metrics.leaderChanges.Add(1)
	n.resetElection()
	n.heartbeatElapsed = 0
	n.leadTransferee = 0
	n.transferElapsed = 0
	n.leaveIndex = 0
	n.pendingRemoval = nil
	n.leaseUntil = time.Time{}
	n.readRound = nil
	n.progress = make(map[NodeID]*progress, len(n.conf.voters)+len(n.conf.learners)+len(n.conf.votersOut)+len(n.conf.learnersOut))
	last := n.log.lastIndex
	for id := range n.conf.voters {
		n.progress[id] = newProgress(last+1, n.maxInflightMsgs, n.maxInflightBytes)
	}
	for id := range n.conf.learners {
		if _, ok := n.progress[id]; !ok {
			n.progress[id] = newProgress(last+1, n.maxInflightMsgs, n.maxInflightBytes)
		}
	}
	for id := range n.conf.votersOut {
		if _, ok := n.progress[id]; !ok {
			n.progress[id] = newProgress(last+1, n.maxInflightMsgs, n.maxInflightBytes)
		}
	}
	for id := range n.conf.learnersOut {
		if _, ok := n.progress[id]; !ok {
			n.progress[id] = newProgress(last+1, n.maxInflightMsgs, n.maxInflightBytes)
		}
	}
	if self := n.progress[n.id]; self != nil {
		self.match = min64(n.persistedIndex, last)
		self.next = last + 1
		self.state = replicate
		self.recentActive = true
	}
	noop := Entry{Index: last + 1, Term: n.term, Type: EntryNoop}
	if err := n.log.append([]Entry{noop}); err != nil {
		n.fatal(err)
		return
	}
	n.termStartIndex = noop.Index
	seq := n.persistEntries([]Entry{noop}, 0)
	// Replicate the no-op before the local fsync completes. Followers can
	// persist it and respond while this leader is still writing; the leader
	// never counts its own copy before persistedIndex advances, so it cannot
	// commit early. This shortens the interval until the new term is usable and
	// immediately resets followers' election timers. | 在本地 fsync 完成前复制空
	// 操作日志项。跟随者可在领导者仍写入时持久化并响应；领导者在 persistedIndex
	// 推进前不会计入自己的副本，因此不会提前提交。这缩短新任期可用的时间，并立即
	// 重置跟随者的选举计时器。
	n.broadcastAppend()
	n.deferAction(seq, func(err error) {
		if err != nil || n.state != StateLeader {
			return
		}
		n.persistedIndex = max64(n.persistedIndex, noop.Index)
		n.advanceApply()
		n.maybeCommit()
		n.resolveCampaign(nil)
	})
	n.logf("info", "raft became leader | raft 成为领导者",
		ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("term", n.term),
		ydlog.Uint64("last", last))
}

// becomeFollower steps down, optionally installing a new term and leader. The
// returned sequence identifies the hard-state persistence that must complete
// before any protocol response is sent; zero means nothing was queued.
// | becomeFollower 降级，可选安装新任期与领导者。返回序号标识发送任何协议响应前
// 必须完成的硬状态持久化；零表示未入队。
func (n *Node) becomeFollower(term uint64, leader NodeID, persist bool) uint64 {
	wasLeader := n.state == StateLeader
	oldTerm := n.term
	oldLeader := n.leader
	if term > n.term {
		n.setTerm(term)
		n.vote = 0
	}
	n.setState(StateFollower)
	n.setLeader(leader)
	// A partial chunked snapshot belongs to one leader and term. A new term or a
	// different leader invalidates it; heartbeats from the same leader do not. |
	// 分块快照属于特定领导者与任期。新任期内或不同领导者会使其中断；同一领导者的
	// 心跳不会。
	if term != oldTerm || (leader != 0 && leader != oldLeader) {
		n.incomingSnapshot = nil
	}
	n.resetElection()
	n.votes = make(map[NodeID]bool)
	n.preVotes = make(map[NodeID]bool)
	n.preVoteSent = nil
	n.preVotePending = nil
	n.preVoteRemaining = nil
	n.preVoteReq = Message{}
	n.selfVoteDurable = false
	n.progress = make(map[NodeID]*progress)
	n.pendingRemoval = nil
	n.leaseUntil = time.Time{}
	n.remoteReads.failAll(ErrLeadershipLost)
	n.termStartIndex = 0
	var seq uint64
	if persist && (term != oldTerm || n.vote == 0) {
		seq = n.persistHardState()
	}
	n.failPendingReads(ErrLeadershipLost)
	if wasLeader {
		n.futures.failAll(ErrLeadershipLost)
		n.metrics.futuresFailed.Add(1)
		// resolveReads clears and fails the active round; calling it after
		// clearing readRound would leave local and forwarded readers blocked
		// until their contexts expire. | resolveReads 会清除并结束活动轮次；若在清除
		// readRound 后调用，本地与转发读会一直阻塞到上下文超时。
		n.resolveReads(ErrLeadershipLost)
		n.resolveTransfer(nil)
		n.abortPendingConf(ErrLeadershipLost)
	} else {
		n.resolveReads(ErrLeadershipLost)
	}
	n.readRound = nil
	if leader != 0 {
		n.resolveCampaign(ErrNotLeader)
	}
	if wasLeader || n.state != StateLeader {
		n.logf("info", "raft became follower | raft 成为跟随者",
			ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("term", n.term),
			ydlog.Uint64("leader", uint64(leader)))
	}
	return seq
}

// resetElection draws a new randomized timeout and arms the fine-grained
// wall-clock election timer. The timer keeps the discrete tick window for the
// pre-vote lease check but adds sub-tick jitter, so large clusters do not all
// campaign on the same tick boundary. | resetElection 抽取新的随机超时并启动细粒度
// 墙钟选举定时器。定时器保留 pre-vote 租约检查所需的离散 tick 窗口，同时加入
// 亚 tick 抖动，避免大集群在同一 tick 边界同时竞选。
func (n *Node) resetElection() {
	n.electionElapsed = 0
	n.electionTimeout = n.cfg.electionTimeoutTicks()
	n.armElectionTimer()
}

// armElectionTimer schedules one election deadline. A single reusable timer is
// reset on each heartbeat, avoiding an allocation per AppendEntries. A stale
// timer event is recognized by comparing the current wall clock with
// electionDeadline. | armElectionTimer 安排一次选举截止时间。每次心跳重置同一个
// 可复用定时器，避免每条 AppendEntries 都分配定时器。通过当前墙钟与
// electionDeadline 比较识别过期事件。
func (n *Node) armElectionTimer() {
	interval := n.tickInterval
	if interval <= 0 {
		interval = n.cfg.TickInterval
	}
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	base := time.Duration(n.electionTimeout) * interval
	jitter := time.Duration(fastrand() % uint64(interval))
	delay := base + jitter
	if n.cfg.ElectionStagger > 0 {
		n.refreshElectionRank()
		stagger := time.Duration(n.electionRank) * n.cfg.ElectionStagger
		if stagger > base {
			// Bound the preference delay so a failed low-ranked node cannot make
			// failover arbitrarily slow in a very large cluster. | 限制优先延迟，
			// 避免大集群中低优先级首选节点故障时使故障转移无限变慢。
			stagger = base
		}
		delay += stagger
	}
	n.electionDeadline = time.Now().Add(delay)
	if n.electionTimer == nil {
		n.electionTimer = time.NewTimer(delay)
		return
	}
	if !n.electionTimer.Stop() {
		select {
		case <-n.electionTimer.C:
		default:
		}
	}
	n.electionTimer.Reset(delay)
}

// refreshElectionRank computes this node's zero-based rank among the sorted
// voter IDs. All replicas derive the same order from the replicated membership
// without exchanging extra priority state. | refreshElectionRank 计算本节点在
// voter ID 升序列表中的零基排名。所有副本从复制的成员配置推导同一顺序，无需交换
// 额外优先级状态。
func (n *Node) refreshElectionRank() {
	if n.electionRankConf == n.conf {
		return
	}
	n.electionRankConf = n.conf
	n.electionRank = 0
	if n.conf == nil {
		return
	}
	ids := make([]NodeID, 0, len(n.conf.voters)+len(n.conf.votersOut))
	for id := range n.conf.voters {
		ids = append(ids, id)
	}
	for id := range n.conf.votersOut {
		if _, ok := n.conf.voters[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for i, id := range ids {
		if id == n.id {
			n.electionRank = i
			return
		}
	}
	n.electionRank = len(ids)
}

// handleElectionTimer starts a campaign or re-arms for a non-voter. A timer
// event older than the current deadline is a harmless leftover from a reset. |
// handleElectionTimer 发起竞选，非投票成员则重新计时。早于当前截止时间的定时器
// 事件是重置后的无害残留。
func (n *Node) handleElectionTimer() {
	if n.stopped.Load() || n.electionDeadline.After(time.Now()) {
		return
	}
	if n.state == StateLeader {
		// A leader is driven by heartbeats and check-quorum, not this timer. |
		// 领导者由心跳与法定人数检查驱动，不使用该定时器。
		return
	}
	if !n.conf.isVoter(n.id) {
		n.resetElection()
		return
	}
	n.campaign(!n.cfg.DisablePreVote)
}

// stopElectionTimer stops the pending timer when the event loop exits. |
// stopElectionTimer 在事件循环退出时停止待触发定时器。
func (n *Node) stopElectionTimer() {
	if n.electionTimer != nil {
		n.electionTimer.Stop()
	}
}

// handleCampaignRequest responds to a forced Campaign call. | handleCampaignRequest
// 响应强制 Campaign 调用。
func (n *Node) handleCampaignRequest(req *campaignRequest) {
	if n.state == StateLeader {
		sendErr(req.done, nil)
		return
	}
	if !n.conf.isVoter(n.id) {
		sendErr(req.done, ErrNotLeader)
		return
	}
	n.campaignWaiters = append(n.campaignWaiters, req.done)
	if n.state != StateCandidate && n.state != StatePreCandidate {
		n.campaign(false)
	}
}

// resolveCampaign releases every waiting Campaign call. | resolveCampaign 释放所有
// 等待中的 Campaign 调用。
func (n *Node) resolveCampaign(err error) {
	for _, ch := range n.campaignWaiters {
		sendErr(ch, err)
	}
	n.campaignWaiters = nil
}

// handleTimeoutNow starts an immediate election for a leader transfer. | handleTimeoutNow
// 为领导权转移立即发起选举。
func (n *Node) handleTimeoutNow(m Message) {
	if m.Term != n.term || n.leader != m.From || !n.conf.isVoter(m.From) {
		return
	}
	if n.state == StateLeader || !n.conf.isVoter(n.id) {
		return
	}
	n.resetElection()
	n.campaign(false)
}

// min64 returns the smaller value. | min64 返回较小值。
func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// max64 returns the larger value. | max64 返回较大值。
func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
