package raft

import (
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// handleSnapshot installs a leader snapshot. The image is persisted before the
// success response; the state machine restore is queued behind the durability
// barrier so later entries can never be applied before it. | handleSnapshot 安装
// 领导者快照。镜像在成功响应前持久化；状态机还原排在持久化屏障之后，保证后续日志项
// 不会先于它被应用。
func (n *Node) handleSnapshot(m *Message) {
	if m.Term < n.term {
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term, Reject: true, Index: n.committed})
		return
	}
	snap := m.Snapshot
	// A complete image supersedes any partially reassembled chunk transfer. |
	// 完整镜像取代任何尚未完成的分块重组。
	n.incomingSnapshot = nil
	// Persist the new term before any response, including a rejection. Responses
	// for a valid snapshot are already tied to the snapshot's own durable write.
	// | 在发送任何响应（包括拒绝）前持久化新任期。合法快照的响应已绑定到快照自身的
	// 持久写入。
	var termSeq uint64
	if m.Term > n.term {
		termSeq = n.becomeFollower(m.Term, m.From, true)
	} else {
		if n.state != StateFollower {
			n.becomeFollower(n.term, m.From, false)
		}
		n.setLeader(m.From)
		n.resetElection()
	}
	if snap == nil || validateConfState(snap.ConfState) != nil {
		n.sendAfterTerm(termSeq, m.Term, Message{Type: MsgSnapResp, To: m.From,
			Term: n.term, Reject: true, Index: n.committed, LogIndex: snapshotIndexOrZero(snap)})
		return
	}
	if snap.Index <= n.committed {
		n.sendAfterTerm(termSeq, m.Term, Message{Type: MsgSnapResp, To: m.From,
			Term: n.term, Index: n.committed, LogIndex: snap.Index})
		return
	}
	n.log.restore(snap)
	// Entries beyond the snapshot are not durable locally until their own
	// persist completes; an older persistedIndex must not authorize applying
	// them early. | 快照之后的日志项在自身持久化完成前并非本地持久化；旧的
	// persistedIndex 不得授权提前应用它们。
	if n.persistedIndex > snap.Index {
		n.persistedIndex = snap.Index
	}
	// The restored image makes every entry up to snap.Index durable locally, so
	// retries for that range can be acknowledged without another persist. |
	// 恢复镜像使 snap.Index 之前的日志项在本地持久化，因此该区间的重试可直接确认。
	n.persistPendingIndex = snap.Index
	// Keep the newest image if a concurrent local snapshot already completed at a
	// higher index. | 若并发本地快照已在更高索引完成，保留最新镜像。
	if n.latestSnapshot == nil || snap.Index > n.latestSnapshot.Index {
		n.latestSnapshot = snap
	}
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
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term,
			Index: snap.Index, LogIndex: snap.Index})
	})
}

// handleSnapshotResp finishes a snapshot transfer. | handleSnapshotResp 结束快照传输。
func (n *Node) handleSnapshotResp(m *Message) {
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
		// Ignore a rejection for an older image; otherwise a delayed response
		// could cancel a newer transfer that is already in flight. Followers that
		// reject a nil snapshot report zero and are accepted for any pending
		// transfer. | 忽略针对旧镜像的拒绝；否则迟到响应会取消已在途的新传输。
		// 拒绝空快照的跟随者上报零，可匹配任意在途传输。
		if m.LogIndex != 0 && pr.pendingSnapshot != 0 && m.LogIndex != pr.pendingSnapshot {
			return
		}
		pr.pendingSnapshot = 0
		pr.state = probe
		pr.snapshotErr = nil
		pr.snapshotErrIndex = 0
		pr.snapshotSentAt = time.Time{}
		pr.resetSnapshotChunks()
		n.maybeSendAppend(m.From)
		return
	}
	pr.snapshotErr = nil
	pr.snapshotErrIndex = 0
	pr.snapshotSentAt = time.Time{}
	pr.resetSnapshotChunks()
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

// snapshotData returns the image payload, loading a file-backed streaming
// snapshot on demand. The returned slice may be the snapshot's own Data. |
// snapshotData 返回镜像负载；文件支持的流式快照按需加载。返回切片可能是快照自身的
// Data。
func (n *Node) snapshotData(snap *Snapshot) ([]byte, error) {
	if snap == nil {
		return nil, errs.Detail(ErrCorrupt, "nil snapshot")
	}
	if snap.Data != nil {
		return snap.Data, nil
	}
	if snap.file == "" {
		return nil, errs.Detail(ErrCorrupt,
			"snapshot %d/%d has no image data | 快照缺少镜像数据", snap.Index, snap.Term)
	}
	loaded, err := readSnapshotFile(snap.file)
	if err != nil {
		return nil, err
	}
	if loaded.Index != snap.Index || loaded.Term != snap.Term {
		return nil, errs.Detail(ErrCorrupt,
			"snapshot file %d/%d does not match %d/%d | 快照文件与元数据不匹配",
			loaded.Index, loaded.Term, snap.Index, snap.Term)
	}
	return loaded.Data, nil
}

// snapshotIndexOrZero returns a snapshot index for rejection matching. | snapshotIndexOrZero
// 返回用于拒绝匹配的快照索引。
func snapshotIndexOrZero(snap *Snapshot) uint64 {
	if snap == nil {
		return 0
	}
	return snap.Index
}

// validateConfState rejects a configuration that cannot form a cluster. | validateConfState
// 拒绝无法组成集群的配置。
func validateConfState(cs ConfState) error {
	if len(cs.Voters) == 0 && len(cs.VotersOutgoing) == 0 {
		return errs.Detail(ErrCorrupt, "snapshot has no voters")
	}
	return nil
}
