package raft

import ydxjson "github.com/shibingli/ydx/json"

// statusJSON is the stable JSON view of Status. | statusJSON 是 Status 的稳定 JSON
// 视图。
type statusJSON struct {
	State            string           `json:"state"`
	Voters           []NodeID         `json:"voters"`
	Learners         []NodeID         `json:"learners"`
	VotersOutgoing   []NodeID         `json:"voters_outgoing"`
	LearnersOutgoing []NodeID         `json:"learners_outgoing"`
	Peers            []peerStatusJSON `json:"peers"`
	ID               NodeID           `json:"id"`
	Group            GroupID          `json:"group"`
	Term             uint64           `json:"term"`
	Leader           NodeID           `json:"leader"`
	Commit           uint64           `json:"commit"`
	Applied          uint64           `json:"applied"`
	LastIndex        uint64           `json:"last_index"`
	LastTerm         uint64           `json:"last_term"`
	FirstIndex       uint64           `json:"first_index"`
	SnapshotIndex    uint64           `json:"snapshot_index"`
	LeadTransferee   NodeID           `json:"lead_transferee"`
	Joint            bool             `json:"joint"`
	Snapshotting     bool             `json:"snapshotting"`
}

// peerStatusJSON is the stable JSON view of PeerStatus. | peerStatusJSON 是
// PeerStatus 的稳定 JSON 视图。
type peerStatusJSON struct {
	Addr            string `json:"addr"`
	State           string `json:"state"`
	SnapshotError   string `json:"snapshot_error,omitempty"`
	ID              NodeID `json:"id"`
	Match           uint64 `json:"match"`
	Next            uint64 `json:"next"`
	PendingSnapshot uint64 `json:"pending_snapshot"`
	InflightMsgs    int    `json:"inflight_msgs"`
	InflightBytes   int    `json:"inflight_bytes"`
	RecentActive    bool   `json:"recent_active"`
}

// statsJSON is the stable JSON view of Stats. | statsJSON 是 Stats 的稳定 JSON 视图。
type statsJSON struct {
	Proposals         uint64 `json:"proposals"`
	ProposalBatches   uint64 `json:"proposal_batches"`
	ProposalsDropped  uint64 `json:"proposals_dropped"`
	FuturesFailed     uint64 `json:"futures_failed"`
	Applies           uint64 `json:"applies"`
	ApplyBatches      uint64 `json:"apply_batches"`
	ApplyErrors       uint64 `json:"apply_errors"`
	Elections         uint64 `json:"elections"`
	PreVotes          uint64 `json:"pre_votes"`
	LeaderChanges     uint64 `json:"leader_changes"`
	TermChanges       uint64 `json:"term_changes"`
	MessagesIn        uint64 `json:"messages_in"`
	MessagesOut       uint64 `json:"messages_out"`
	MessagesDropped   uint64 `json:"messages_dropped"`
	TransportDrops    uint64 `json:"transport_drops"`
	AppendsIn         uint64 `json:"appends_in"`
	AppendsOut        uint64 `json:"appends_out"`
	HeartbeatsIn      uint64 `json:"heartbeats_in"`
	HeartbeatsOut     uint64 `json:"heartbeats_out"`
	SnapshotsCreated  uint64 `json:"snapshots_created"`
	SnapshotsApplied  uint64 `json:"snapshots_applied"`
	SnapshotChunksOut uint64 `json:"snapshot_chunks_out"`
	SnapshotChunksIn  uint64 `json:"snapshot_chunks_in"`
	ReadIndex         uint64 `json:"read_index"`
	LeaseReads        uint64 `json:"lease_reads"`
	PersistBatches    uint64 `json:"persist_batches"`
	PersistErrors     uint64 `json:"persist_errors"`
	StorageCompacts   uint64 `json:"storage_compacts"`
}

// MarshalJSON implements json.Marshaler with the ydx/json codec and a stable
// snake_case API. State is rendered by name. | MarshalJSON 使用 ydx/json 编解码器
// 与稳定的 snake_case API；State 输出名称。
// jsonIDs returns an empty array instead of null for an absent list. | jsonIDs
// 为缺失列表返回空数组而不是 null。
func jsonIDs(ids []NodeID) []NodeID {
	if ids == nil {
		return []NodeID{}
	}
	return ids
}

func (s Status) MarshalJSON() ([]byte, error) {
	peers := make([]peerStatusJSON, 0, len(s.Peers))
	for i := range s.Peers {
		p := &s.Peers[i]
		peers = append(peers, peerStatusJSON{
			ID: p.ID, Addr: p.Addr, State: p.State, Match: p.Match, Next: p.Next,
			PendingSnapshot: p.PendingSnapshot, InflightMsgs: p.InflightMsgs,
			InflightBytes: p.InflightBytes, SnapshotError: p.SnapshotError,
			RecentActive: p.RecentActive,
		})
	}
	return ydxjson.Marshal(statusJSON{
		ID: s.ID, Group: s.Group, State: s.State.String(), Term: s.Term,
		Leader: s.Leader, Commit: s.Commit, Applied: s.Applied,
		LastIndex: s.LastIndex, LastTerm: s.LastTerm, FirstIndex: s.FirstIndex,
		SnapshotIndex: s.SnapshotIndex, Snapshotting: s.Snapshotting,
		LeadTransferee: s.LeadTransferee, Joint: s.Joint,
		Voters: jsonIDs(s.Voters), Learners: jsonIDs(s.Learners),
		VotersOutgoing:   jsonIDs(s.VotersOutgoing),
		LearnersOutgoing: jsonIDs(s.LearnersOutgoing),
		Peers:            peers,
	})
}

// MarshalJSON implements json.Marshaler with the ydx/json codec and stable
// snake_case field names. | MarshalJSON 使用 ydx/json 编解码器与稳定 snake_case
// 字段名。
func (s Stats) MarshalJSON() ([]byte, error) {
	return ydxjson.Marshal(statsJSON{
		Proposals: s.Proposals, ProposalBatches: s.ProposalBatches,
		ProposalsDropped: s.ProposalsDropped, FuturesFailed: s.FuturesFailed,
		Applies: s.Applies, ApplyBatches: s.ApplyBatches, ApplyErrors: s.ApplyErrors,
		Elections: s.Elections, PreVotes: s.PreVotes,
		LeaderChanges: s.LeaderChanges, TermChanges: s.TermChanges,
		MessagesIn: s.MessagesIn, MessagesOut: s.MessagesOut,
		MessagesDropped: s.MessagesDropped, TransportDrops: s.TransportDrops,
		AppendsIn: s.AppendsIn, AppendsOut: s.AppendsOut,
		HeartbeatsIn: s.HeartbeatsIn, HeartbeatsOut: s.HeartbeatsOut,
		SnapshotsCreated: s.SnapshotsCreated, SnapshotsApplied: s.SnapshotsApplied,
		SnapshotChunksOut: s.SnapshotChunksOut, SnapshotChunksIn: s.SnapshotChunksIn,
		ReadIndex: s.ReadIndex, LeaseReads: s.LeaseReads,
		PersistBatches: s.PersistBatches, PersistErrors: s.PersistErrors,
		StorageCompacts: s.StorageCompacts,
	})
}
