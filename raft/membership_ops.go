package raft

import (
	"github.com/shibingli/ydx/errs"
)

// handleProposalIntake drains a bounded number of proposal batches per wakeup so
// a large backlog cannot starve messages, ticks or reads. | handleProposalIntake
// 每次唤醒最多处理有限个提案批次，避免大量积压饿死消息、tick 或读请求。
func (n *Node) handleProposalIntake() {
	for i := 0; i < 4; i++ {
		batch := n.proposals.popBatch(1)
		if len(batch) == 0 {
			return
		}
		n.handleProposalBatch(batch[0])
		if !n.proposals.hasItems() {
			return
		}
	}
	// More work remains; keep the event loop responsive and ask it to return.
	// | 仍有工作；让事件循环保持响应并安排下一次处理。
	n.proposals.signal()
}

// handleProposalBatch appends a batch of client proposals. Normal proposals are
// coalesced; a membership change is handled alone because only one may be in
// flight. | handleProposalBatch 追加一批客户端提案。普通提案会合并；成员变更单独
// 处理，因为同一时间只允许一个。
func (n *Node) handleProposalBatch(first *proposal) {
	if n.state != StateLeader {
		n.failProposal(first, n.notLeaderError("propose"))
		return
	}
	if n.leadTransferee != 0 {
		n.failProposal(first, ErrTransferInProgress)
		return
	}
	if first.conf != nil {
		n.handleConfProposal(first)
		return
	}
	batch := []*proposal{first}
	for len(batch) < n.maxBatchEntries {
		more := n.proposals.popBatch(n.maxBatchEntries - len(batch))
		if len(more) == 0 {
			break
		}
		for _, p := range more {
			if p.conf != nil {
				n.appendNormalBatch(batch)
				n.handleConfProposal(p)
				return
			}
			batch = append(batch, p)
		}
	}
	n.appendNormalBatch(batch)
}

// appendNormalBatch appends normal entries and persists them as one batch.
// | appendNormalBatch 追加普通日志项并作为一批持久化。
func (n *Node) appendNormalBatch(batch []*proposal) {
	if len(batch) == 0 {
		return
	}
	if n.state != StateLeader || n.leadTransferee != 0 {
		for _, p := range batch {
			if n.leadTransferee != 0 {
				n.failProposal(p, ErrTransferInProgress)
			} else {
				n.failProposal(p, n.notLeaderError("propose"))
			}
		}
		return
	}
	last := n.log.lastIndex
	entries := make([]Entry, len(batch))
	for i, p := range batch {
		entries[i] = Entry{Index: last + 1 + uint64(i), Term: n.term, Type: EntryNormal, Data: p.data}
		p.future.index = entries[i].Index
		p.future.term = n.term
		n.futures.add(p.future)
	}
	if err := n.log.append(entries); err != nil {
		for _, p := range batch {
			n.failProposal(p, errs.Wrap(err, ErrProposalDropped))
		}
		n.fatal(err)
		return
	}
	n.metrics.proposals.Add(uint64(len(batch)))
	n.metrics.proposalBatches.Add(1)
	lastNew := entries[len(entries)-1].Index
	seq := n.persistEntries(entries, 0)
	n.deferAction(seq, func(err error) {
		if err != nil || n.state != StateLeader {
			return
		}
		n.persistedIndex = max64(n.persistedIndex, lastNew)
		if self := n.progress[n.id]; self != nil {
			self.match = max64(self.match, lastNew)
			self.next = self.match + 1
			self.state = replicate
		}
		n.broadcastAppend()
		n.maybeCommit()
	})
}

// handleConfProposal appends one membership change. The resulting configuration
// is effective as soon as the entry enters the log, per Raft. | handleConfProposal
// 追加一次成员变更。按 Raft 规则，配置在日志项进入日志时立即生效。
func (n *Node) handleConfProposal(p *proposal) {
	if p.conf == nil {
		n.failProposal(p, ErrInvalidConfig)
		return
	}
	if n.pendingConf != nil || n.conf.joint() || (n.leaveIndex != 0 && n.committed < n.leaveIndex) {
		n.failProposal(p, ErrConfChangeInProgress)
		return
	}
	if p.conf.Type == ConfChangeLeaveJoint {
		n.failProposal(p, ErrInvalidConfig)
		return
	}
	next, err := n.conf.apply(*p.conf)
	if err != nil {
		n.failProposal(p, err)
		return
	}
	data, err := encodeConfChange(*p.conf)
	if err != nil {
		n.failProposal(p, err)
		return
	}
	entry := Entry{Index: n.log.lastIndex + 1, Term: n.term, Type: EntryConfChange, Data: data}
	if err := n.log.append([]Entry{entry}); err != nil {
		n.failProposal(p, errs.Wrap(err, ErrProposalDropped))
		n.fatal(err)
		return
	}
	oldJoint := n.conf.joint()
	if !oldJoint && next.joint() {
		n.jointIndex = entry.Index
		// A new transition owns its leave entry; an earlier transition's index
		// is stale and would otherwise block auto-leave. | 新过渡拥有自己的离开
		// 日志项；旧过渡的索引已过期，否则会阻塞自动离开。
		n.leaveIndex = 0
	}
	if !next.joint() {
		n.jointIndex = 0
	}
	n.conf = next
	n.confHistory = append(n.confHistory, confVersion{index: entry.Index, conf: next, jointIndex: n.jointIndex})
	n.updateProgressForConfig()
	n.updatePeerAddresses()
	n.pendingConf = &pendingConf{change: *p.conf, initialIndex: entry.Index, future: p.future}
	p.future.index = entry.Index
	p.future.term = n.term
	if n.cfg.OnConfChange != nil {
		n.cfg.OnConfChange(next.confState())
	}
	n.metrics.proposals.Add(1)
	seq := n.persistEntries([]Entry{entry}, 0)
	n.deferAction(seq, func(err error) {
		if err != nil || n.state != StateLeader {
			return
		}
		n.persistedIndex = max64(n.persistedIndex, entry.Index)
		if self := n.progress[n.id]; self != nil {
			self.match = max64(self.match, entry.Index)
			self.next = self.match + 1
		}
		n.broadcastAppend()
		n.maybeCommit()
	})
}

// maybeAutoLeave proposes the final configuration once the joint entry is
// committed. | maybeAutoLeave 在联合配置日志项提交后提案最终配置。
func (n *Node) maybeAutoLeave() {
	if n.state != StateLeader || !n.conf.joint() || n.leaveIndex != 0 {
		return
	}
	if n.committed < n.jointIndex {
		return
	}
	cc := ConfChange{Type: ConfChangeLeaveJoint}
	data, err := encodeConfChange(cc)
	if err != nil {
		n.fatal(err)
		return
	}
	entry := Entry{Index: n.log.lastIndex + 1, Term: n.term, Type: EntryConfChange, Data: data}
	if err := n.log.append([]Entry{entry}); err != nil {
		n.fatal(err)
		return
	}
	next, err := n.conf.apply(cc)
	if err != nil {
		n.fatal(errs.Wrap(err, ErrCorrupt))
		return
	}
	// Keep removed members in the replication set until the final configuration
	// commits so they learn that they are no longer voters and stop campaigning.
	// | 在最终配置提交前保留被移除成员的复制进度，使其得知自己不再投票并停止竞选。
	for id := range n.conf.votersOut {
		if _, ok := next.voters[id]; !ok {
			n.pendingRemoval = append(n.pendingRemoval, id)
		}
	}
	for id := range n.conf.learnersOut {
		if _, ok := next.learners[id]; !ok {
			n.pendingRemoval = append(n.pendingRemoval, id)
		}
	}
	n.conf = next
	n.jointIndex = 0
	n.confHistory = append(n.confHistory, confVersion{index: entry.Index, conf: next})
	n.updateProgressForConfig()
	n.updatePeerAddresses()
	n.leaveIndex = entry.Index
	if n.pendingConf != nil {
		n.pendingConf.leaveIndex = entry.Index
	}
	if n.cfg.OnConfChange != nil {
		n.cfg.OnConfChange(next.confState())
	}
	seq := n.persistEntries([]Entry{entry}, 0)
	n.deferAction(seq, func(err error) {
		if err != nil || n.state != StateLeader {
			return
		}
		n.persistedIndex = max64(n.persistedIndex, entry.Index)
		if self := n.progress[n.id]; self != nil {
			self.match = max64(self.match, entry.Index)
			self.next = self.match + 1
		}
		n.broadcastAppend()
		n.maybeCommit()
	})
}

// maybeCompleteConf resolves the public membership call once the final
// configuration is committed. | maybeCompleteConf 在最终配置提交后结束公共成员调用。
func (n *Node) maybeCompleteConf() {
	pc := n.pendingConf
	if pc == nil || pc.resolved || n.conf.joint() {
		return
	}
	target := pc.initialIndex
	if pc.leaveIndex != 0 {
		target = pc.leaveIndex
	}
	if n.committed < target {
		return
	}
	pc.resolved = true
	pc.future.deliver(nil)
	n.pendingConf = nil
	n.leaveIndex = 0
}

// abortPendingConf fails an in-flight membership call. | abortPendingConf 使进行中
// 的成员调用失败。
func (n *Node) abortPendingConf(err error) {
	if n.pendingConf != nil && !n.pendingConf.resolved {
		n.pendingConf.future.fail(err)
	}
	n.pendingConf = nil
	n.leaveIndex = 0
}

// failProposal resolves one rejected proposal. | failProposal 结束一个被拒提案。
func (n *Node) failProposal(p *proposal, err error) {
	if p == nil || p.future == nil {
		return
	}
	p.future.fail(err)
	n.metrics.proposalsDropped.Add(1)
}
