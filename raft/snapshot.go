package raft

import (
	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// handleSnapshot installs a leader snapshot. The image is persisted before the
// success response; the state machine restore is queued behind the durability
// barrier so later entries can never be applied before it. | handleSnapshot 安装
// 领导者快照。镜像在成功响应前持久化；状态机还原排在持久化屏障之后，保证后续日志项
// 不会先于它被应用。
func (n *Node) handleSnapshot(m Message) {
	snap := m.Snapshot
	if m.Term < n.term {
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term, Reject: true, Index: n.committed})
		return
	}
	if snap == nil || validateConfState(snap.ConfState) != nil {
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term, Reject: true, Index: n.committed})
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, m.From, true)
	} else {
		if n.state != StateFollower {
			n.becomeFollower(n.term, m.From, false)
		}
		n.setLeader(m.From)
		n.resetElection()
	}
	if snap.Index <= n.committed {
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term, Index: n.committed})
		return
	}
	n.log.restore(snap)
	n.latestSnapshot = snap
	n.lastSnapshot.Store(snap.Index)
	n.setCommitted(snap.Index)
	n.sentApplied = snap.Index
	n.confBase = newMembershipFromState(snap.ConfState)
	n.confBaseIndex = snap.Index
	n.conf = n.confBase
	n.confHistory = nil
	n.jointIndex = 0
	if n.conf.joint() {
		n.jointIndex = snap.Index
	}
	n.progress = make(map[NodeID]*progress)
	n.futures.failAll(ErrLeadershipLost)
	n.resolveReads(ErrLeadershipLost)
	n.updatePeerAddresses()
	if n.cfg.OnConfChange != nil {
		n.cfg.OnConfChange(n.conf.confState())
	}
	ready := make(chan struct{})
	n.applyQueue.push(applyTask{snapshot: snap, snapshotReady: ready})
	n.logf("info", "raft installing snapshot | raft 安装快照",
		ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("index", snap.Index),
		ydlog.Uint64("term", snap.Term))
	n.persistSnapshot(snap, true, func(err error) {
		if err != nil {
			return
		}
		close(ready)
		n.metrics.snapshotsApplied.Add(1)
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term, Index: snap.Index})
	})
}

// handleSnapshotResp finishes a snapshot transfer. | handleSnapshotResp 结束快照传输。
func (n *Node) handleSnapshotResp(m Message) {
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
	if m.Reject {
		pr.pendingSnapshot = 0
		pr.state = probe
		n.maybeSendAppend(m.From)
		return
	}
	if m.Index > n.log.lastIndex {
		m.Index = n.log.lastIndex
	}
	pr.snapshotDone(m.Index)
	n.maybeCommit()
	if n.leadTransferee == m.From && !n.transferSent && pr.match >= n.log.lastIndex {
		n.sendTimeoutNow()
	}
	n.maybeSendAppend(m.From)
}

// validateConfState rejects a configuration that cannot form a cluster. | validateConfState
// 拒绝无法组成集群的配置。
func validateConfState(cs ConfState) error {
	if len(cs.Voters) == 0 && len(cs.VotersOutgoing) == 0 {
		return errs.Detail(ErrCorrupt, "snapshot has no voters")
	}
	return nil
}
