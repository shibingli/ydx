package raft

import "slices"

// buildStatus assembles a full status view on the event loop. | buildStatus 在事件
// 循环上组装完整状态视图。
func (n *Node) buildStatus() Status {
	cs := n.conf.confState()
	st := Status{
		ID:               n.id,
		Group:            n.group,
		State:            n.state,
		Term:             n.term,
		Leader:           n.leader,
		Commit:           n.committed,
		Applied:          n.applied.Load(),
		LastIndex:        n.log.lastIndex,
		LastTerm:         n.log.lastTerm(),
		FirstIndex:       n.log.firstIndex,
		SnapshotIndex:    n.log.snapshotIndex,
		Voters:           cs.Voters,
		Learners:         cs.Learners,
		VotersOutgoing:   cs.VotersOutgoing,
		LearnersOutgoing: cs.LearnersOutgoing,
		Joint:            n.conf.joint(),
		Snapshotting:     n.snapshotting,
		LeadTransferee:   n.leadTransferee,
	}
	members := make(map[NodeID]struct{}, len(n.progress)+8)
	for id := range n.conf.voters {
		members[id] = struct{}{}
	}
	for id := range n.conf.learners {
		members[id] = struct{}{}
	}
	for id := range n.conf.votersOut {
		members[id] = struct{}{}
	}
	for id := range n.conf.learnersOut {
		members[id] = struct{}{}
	}
	peerIDs := make([]NodeID, 0, len(members))
	for id := range members {
		peerIDs = append(peerIDs, id)
	}
	slices.Sort(peerIDs)
	st.Peers = make([]PeerStatus, 0, len(peerIDs))
	for _, id := range peerIDs {
		ps := PeerStatus{ID: id, Addr: n.conf.addr(id)}
		if pr := n.progress[id]; pr != nil {
			ps.Match = pr.match
			ps.Next = pr.next
			ps.State = pr.state.String()
			ps.RecentActive = pr.recentActive
			ps.PendingSnapshot = pr.pendingSnapshot
			ps.InflightMsgs = pr.inflights.count
			ps.InflightBytes = pr.inflights.bytes
		}
		st.Peers = append(st.Peers, ps)
	}
	return st
}
