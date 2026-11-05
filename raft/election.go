package raft

import (
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
	n.resetElection()
	n.preVotes = make(map[NodeID]bool, len(n.conf.voters)+1)
	n.preVotes[n.id] = true
	n.metrics.preVotes.Add(1)
	last := n.log.lastIndex
	lastTerm := n.log.lastTerm()
	msg := Message{
		Type:     MsgPreVote,
		Term:     n.term + 1,
		LogIndex: last,
		LogTerm:  lastTerm,
	}
	n.broadcastVoters(msg)
	if n.conf.hasQuorum(func(id NodeID) bool { return n.preVotes[id] }) {
		n.startVote()
	}
}

// startVote increments the term, votes for self and asks every voter for a vote
// only after the new term and vote are durable. | startVote 提升任期、自投票，并且
// 只在新任期与选票持久化后请求选票。
func (n *Node) startVote() {
	n.setTerm(n.term + 1)
	n.vote = n.id
	n.setState(StateCandidate)
	n.setLeader(0)
	n.resetElection()
	n.votes = make(map[NodeID]bool, len(n.conf.voters)+1)
	n.votes[n.id] = true
	n.preVotes = make(map[NodeID]bool)
	n.metrics.elections.Add(1)
	last := n.log.lastIndex
	lastTerm := n.log.lastTerm()
	seq := n.persistHardState()
	n.deferAction(seq, func(err error) {
		if err != nil || n.term == 0 || n.state != StateCandidate {
			return
		}
		msg := Message{
			Type:     MsgVote,
			Term:     n.term,
			LogIndex: last,
			LogTerm:  lastTerm,
		}
		n.broadcastVoters(msg)
		if n.conf.hasQuorum(func(id NodeID) bool { return n.votes[id] }) {
			n.becomeLeader()
		}
	})
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
	if m.Term > n.term && n.conf.isVoter(n.id) &&
		n.log.upToDate(m.LogIndex, m.LogTerm) {
		if n.leader == 0 || n.electionElapsed >= n.electionTimeout {
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
	if m.Reject || !n.conf.isVoter(m.From) {
		return
	}
	n.preVotes[m.From] = true
	if n.conf.hasQuorum(func(id NodeID) bool { return n.preVotes[id] }) {
		n.startVote()
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
	if !canVote || !n.conf.isVoter(n.id) || !n.log.upToDate(m.LogIndex, m.LogTerm) {
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
	if n.conf.hasQuorum(func(id NodeID) bool { return n.votes[id] }) {
		n.becomeLeader()
	}
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
	n.deferAction(seq, func(err error) {
		if err != nil || n.state != StateLeader {
			return
		}
		n.persistedIndex = max64(n.persistedIndex, noop.Index)
		n.broadcastAppend()
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
	if term > n.term {
		n.setTerm(term)
		n.vote = 0
	}
	n.setState(StateFollower)
	n.setLeader(leader)
	n.resetElection()
	n.votes = make(map[NodeID]bool)
	n.preVotes = make(map[NodeID]bool)
	n.progress = make(map[NodeID]*progress)
	n.pendingRemoval = nil
	n.leaseUntil = time.Time{}
	n.readRound = nil
	n.remoteReads.failAll(ErrLeadershipLost)
	n.termStartIndex = 0
	var seq uint64
	if persist && (term != oldTerm || n.vote == 0) {
		seq = n.persistHardState()
	}
	if wasLeader {
		n.futures.failAll(ErrLeadershipLost)
		n.metrics.futuresFailed.Add(1)
		n.resolveReads(ErrLeadershipLost)
		n.resolveTransfer(nil)
		n.abortPendingConf(ErrLeadershipLost)
	}
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

// resetElection draws a new randomized timeout. | resetElection 抽取新的随机超时。
func (n *Node) resetElection() {
	n.electionElapsed = 0
	n.electionTimeout = n.cfg.electionTimeoutTicks()
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
