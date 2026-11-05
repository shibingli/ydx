package raft

import "sync/atomic"

// Stats is a consistent-enough snapshot of node counters. Counters are updated
// with atomics on the hot path and never block Raft. | Stats 是节点计数器的快照。
// 计数器在热路径上以原子操作更新，不会阻塞 Raft。
type Stats struct {
	Proposals        uint64
	ProposalBatches  uint64
	ProposalsDropped uint64
	FuturesFailed    uint64
	Applies          uint64
	ApplyBatches     uint64
	ApplyErrors      uint64
	Elections        uint64
	PreVotes         uint64
	LeaderChanges    uint64
	TermChanges      uint64
	MessagesIn       uint64
	MessagesOut      uint64
	MessagesDropped  uint64
	AppendsIn        uint64
	AppendsOut       uint64
	HeartbeatsIn     uint64
	HeartbeatsOut    uint64
	SnapshotsCreated uint64
	SnapshotsApplied uint64
	ReadIndex        uint64
	LeaseReads       uint64
	PersistBatches   uint64
	PersistErrors    uint64
	StorageCompacts  uint64
}

// metrics owns atomic counters. | metrics 持有原子计数器。
type metrics struct {
	proposals        atomic.Uint64
	proposalBatches  atomic.Uint64
	proposalsDropped atomic.Uint64
	futuresFailed    atomic.Uint64
	applies          atomic.Uint64
	applyBatches     atomic.Uint64
	applyErrors      atomic.Uint64
	elections        atomic.Uint64
	preVotes         atomic.Uint64
	leaderChanges    atomic.Uint64
	termChanges      atomic.Uint64
	messagesIn       atomic.Uint64
	messagesOut      atomic.Uint64
	messagesDropped  atomic.Uint64
	appendsIn        atomic.Uint64
	appendsOut       atomic.Uint64
	heartbeatsIn     atomic.Uint64
	heartbeatsOut    atomic.Uint64
	snapshotsCreated atomic.Uint64
	snapshotsApplied atomic.Uint64
	readIndex        atomic.Uint64
	leaseReads       atomic.Uint64
	persistBatches   atomic.Uint64
	persistErrors    atomic.Uint64
	storageCompacts  atomic.Uint64
}

// newMetrics returns a zeroed counter set. | newMetrics 返回全零计数器集合。
func newMetrics() *metrics { return &metrics{} }

// snapshot exports the counters. | snapshot 导出计数器。
func (m *metrics) snapshot() Stats {
	return Stats{
		Proposals:        m.proposals.Load(),
		ProposalBatches:  m.proposalBatches.Load(),
		ProposalsDropped: m.proposalsDropped.Load(),
		FuturesFailed:    m.futuresFailed.Load(),
		Applies:          m.applies.Load(),
		ApplyBatches:     m.applyBatches.Load(),
		ApplyErrors:      m.applyErrors.Load(),
		Elections:        m.elections.Load(),
		PreVotes:         m.preVotes.Load(),
		LeaderChanges:    m.leaderChanges.Load(),
		TermChanges:      m.termChanges.Load(),
		MessagesIn:       m.messagesIn.Load(),
		MessagesOut:      m.messagesOut.Load(),
		MessagesDropped:  m.messagesDropped.Load(),
		AppendsIn:        m.appendsIn.Load(),
		AppendsOut:       m.appendsOut.Load(),
		HeartbeatsIn:     m.heartbeatsIn.Load(),
		HeartbeatsOut:    m.heartbeatsOut.Load(),
		SnapshotsCreated: m.snapshotsCreated.Load(),
		SnapshotsApplied: m.snapshotsApplied.Load(),
		ReadIndex:        m.readIndex.Load(),
		LeaseReads:       m.leaseReads.Load(),
		PersistBatches:   m.persistBatches.Load(),
		PersistErrors:    m.persistErrors.Load(),
		StorageCompacts:  m.storageCompacts.Load(),
	}
}

// Status is a point-in-time view assembled by the Raft event loop. | Status 是由
// Raft 事件循环组装的即时视图。
type Status struct {
	ID               NodeID
	Group            GroupID
	State            State
	Term             uint64
	Leader           NodeID
	Commit           uint64
	Applied          uint64
	LastIndex        uint64
	LastTerm         uint64
	FirstIndex       uint64
	SnapshotIndex    uint64
	Voters           []NodeID
	Learners         []NodeID
	VotersOutgoing   []NodeID
	LearnersOutgoing []NodeID
	Joint            bool
	Snapshotting     bool
	LeadTransferee   NodeID
	Peers            []PeerStatus
}

// PeerStatus is one follower's replication view. | PeerStatus 是单个跟随者的复制视图。
type PeerStatus struct {
	ID              NodeID
	Addr            string
	Match           uint64
	Next            uint64
	State           string
	RecentActive    bool
	PendingSnapshot uint64
	InflightMsgs    int
	InflightBytes   int
}
