package raft

import (
	"context"
	"testing"
	"time"
)

// TestPreVoteSubsetCoversQuorum verifies the bounded first wave contains a
// quorum of the voter set and leaves every remaining voter for expansion.
// | TestPreVoteSubsetCoversQuorum 验证有界首轮包含投票集合的多数，并保留所有
// 其余投票成员供扩展。
func TestPreVoteSubsetCoversQuorum(t *testing.T) {
	voters := make([]NodeID, 101)
	for i := range voters {
		voters[i] = NodeID(i + 1)
	}
	n := &Node{
		id:   1,
		conf: newMembership(voters, nil, nil),
		cfg: Config{
			PreVoteSubsetThreshold: 16,
			PreVoteSubsetExtra:     4,
		},
	}
	initial, remaining := n.preVoteTargets()
	if len(initial) >= len(voters)-1 {
		t.Fatalf("initial targets = %d, want a bounded subset", len(initial))
	}
	seen := make(map[NodeID]struct{}, len(initial)+len(remaining)+1)
	seen[n.id] = struct{}{}
	quorum := len(voters)/2 + 1
	if 1+len(initial) < quorum {
		t.Fatalf("initial wave %d + self < quorum %d", len(initial), quorum)
	}
	for _, id := range initial {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate target %d", id)
		}
		seen[id] = struct{}{}
	}
	for _, id := range remaining {
		if _, ok := seen[id]; ok {
			t.Fatalf("target %d both initial and remaining", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != len(voters) {
		t.Fatalf("covered %d voters, want %d", len(seen), len(voters))
	}
}

// TestPendingReadLimit derives from queue capacity and honors an explicit
// override. | TestPendingReadLimit 验证按队列容量推导及显式覆盖。
func TestPendingReadLimit(t *testing.T) {
	cfg := Config{MessageQueue: 8192}
	if got := cfg.pendingReadLimit(); got != 1024 {
		t.Fatalf("auto pending limit = %d, want 1024", got)
	}
	cfg.MessageQueue = 128
	if got := cfg.pendingReadLimit(); got != 256 {
		t.Fatalf("small queue pending limit = %d, want 256", got)
	}
	cfg.MessageQueue = 1 << 20
	if got := cfg.pendingReadLimit(); got != 4096 {
		t.Fatalf("large queue pending limit = %d, want 4096", got)
	}
	cfg.MaxPendingReads = 77
	if got := cfg.pendingReadLimit(); got != 77 {
		t.Fatalf("explicit pending limit = %d, want 77", got)
	}
}

// TestElectionStaggerRank verifies the deterministic voter-ID priority order.
// | TestElectionStaggerRank 验证确定性的 voter ID 优先级顺序。
func TestElectionStaggerRank(t *testing.T) {
	voters := []NodeID{5, 2, 4, 1, 3}
	for i, id := range []NodeID{1, 2, 3, 4, 5} {
		n := &Node{
			id:   id,
			conf: newMembership(voters, nil, nil),
			cfg:  Config{ElectionStagger: time.Millisecond},
		}
		n.refreshElectionRank()
		if n.electionRank != i {
			t.Fatalf("node %d rank = %d, want %d", id, n.electionRank, i)
		}
	}
}

// TestPreVoteExpandsWhenFirstWaveExhausted verifies the remaining voters are
// contacted after the first wave cannot reach a quorum. | TestPreVoteExpandsWhenFirstWaveExhausted
// 验证首轮无法达到多数后会联系其余投票成员。
func TestPreVoteExpandsWhenFirstWaveExhausted(t *testing.T) {
	voters := make([]NodeID, 17)
	for i := range voters {
		voters[i] = NodeID(i + 1)
	}
	n := &Node{
		id:               1,
		state:            StatePreCandidate,
		term:             3,
		conf:             newMembership(voters, nil, nil),
		cfg:              Config{PreVoteSubsetThreshold: 8, PreVoteSubsetExtra: 2},
		metrics:          newMetrics(),
		preVotes:         map[NodeID]bool{1: true},
		preVoteSent:      map[NodeID]struct{}{},
		preVotePending:   map[NodeID]struct{}{},
		preVoteRemaining: []NodeID{10, 11, 12},
		preVoteReq:       Message{Type: MsgPreVote, Term: 4, LogIndex: 1, LogTerm: 1},
	}
	n.handlePreVoteResp(&Message{Type: MsgPreVoteResp, From: 2, To: 1, Term: 3, Reject: true})
	if len(n.outBuf) != 3 {
		t.Fatalf("expanded messages = %d, want 3", len(n.outBuf))
	}
	if len(n.preVoteRemaining) != 0 {
		t.Fatalf("remaining targets = %d", len(n.preVoteRemaining))
	}
}

// TestLargeClusterPreVoteSubsetElectsLeader exercises the bounded pre-vote path
// end to end. | TestLargeClusterPreVoteSubsetElectsLeader 端到端覆盖有界
// pre-vote 路径。
func TestLargeClusterPreVoteSubsetElectsLeader(t *testing.T) {
	c := newTestCluster(t, 17, func(cfg *Config) {
		cfg.PreVoteSubsetThreshold = 8
		cfg.PreVoteSubsetExtra = 2
		cfg.ElectionStagger = time.Millisecond
		cfg.TickInterval = time.Millisecond
	})
	leader := c.waitLeader(5 * time.Second)
	if leader == nil {
		t.Fatal("no leader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := leader.Propose(ctx, []byte("subset=ok"))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, res.Index, 5*time.Second)
		if got := c.fsms[id].value("subset"); got != "ok" {
			t.Fatalf("node %d subset = %q", id, got)
		}
	}
}
