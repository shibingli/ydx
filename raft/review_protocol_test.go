package raft

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestHeartbeatCommitCappedPerPeer verifies every heartbeat advertises at most
// the follower's matched index. | TestHeartbeatCommitCappedPerPeer 验证每条心跳
// 最多通告跟随者已匹配的索引。
func TestHeartbeatCommitCappedPerPeer(t *testing.T) {
	n := &Node{
		id:        1,
		state:     StateLeader,
		term:      5,
		committed: 10,
		metrics:   newMetrics(),
		progress:  map[NodeID]*progress{},
	}
	n.progress[1] = newProgress(1, 1, 1)
	n.progress[2] = newProgress(4, 1, 1)
	n.progress[2].match = 3
	n.progress[3] = newProgress(9, 1, 1)
	n.progress[3].match = 8

	n.broadcastCommit()
	if len(n.outBuf) != 2 {
		t.Fatalf("heartbeats = %d, want 2", len(n.outBuf))
	}
	got := map[NodeID]uint64{}
	for _, m := range n.outBuf {
		if m.Type != MsgHeartbeat {
			t.Fatalf("message type %s", m.Type)
		}
		got[m.To] = m.Commit
	}
	if got[2] != 3 || got[3] != 8 {
		t.Fatalf("commit caps = %v, want 2:3 3:8", got)
	}

	n.outBuf = n.outBuf[:0]
	n.heartbeatVoters(42)
	if len(n.outBuf) != 2 {
		t.Fatalf("round heartbeats = %d, want 2", len(n.outBuf))
	}
	for _, m := range n.outBuf {
		want := uint64(3)
		if m.To == 3 {
			want = 8
		}
		if m.Commit != want {
			t.Fatalf("peer %d commit = %d, want %d", m.To, m.Commit, want)
		}
		if id, ok := decodeRoundContext(m.Context); !ok || id != 42 {
			t.Fatalf("peer %d round context = %v", m.To, m.Context)
		}
	}
}

// TestSendSnapshotDoesNotRecurseOnStaleImage verifies a stale leader snapshot
// cannot loop between snapshot and append for a follower that already matched
// beyond it. | TestSendSnapshotDoesNotRecurseOnStaleImage 验证当跟随者已匹配到
// 更靠后的位置时，过期领导者快照不会在快照与追加之间循环。
func TestSendSnapshotDoesNotRecurseOnStaleImage(t *testing.T) {
	n := &Node{
		id:             1,
		state:          StateLeader,
		term:           3,
		metrics:        newMetrics(),
		latestSnapshot: &Snapshot{Index: 100, Term: 2},
		log:            &raftLog{snapshotIndex: 150, snapshotTerm: 3, firstIndex: 151, lastIndex: 150},
		progress:       map[NodeID]*progress{},
	}
	pr := newProgress(101, 8, 1<<20)
	pr.match = 100
	n.progress[2] = pr

	n.sendSnapshot(2)
	if pr.state != snapshot {
		t.Fatalf("progress state = %s, want snapshot", pr.state)
	}
	if len(n.outBuf) != 0 {
		t.Fatalf("sent %d messages for an unusable snapshot", len(n.outBuf))
	}
}

// TestDivergentHeartbeatCannotCommit verifies a follower's conflicting suffix
// is never committed by a heartbeat before AppendEntries truncates it.
// | TestDivergentHeartbeatCannotCommit 验证跟随者的冲突后缀不会被心跳先提交，而
// 是等待 AppendEntries 截断它。
func TestDivergentHeartbeatCannotCommit(t *testing.T) {
	c := newTestCluster(t, 3, func(cfg *Config) {
		cfg.DisableCheckQuorum = true
		cfg.DisableLeaseRead = true
	})
	old := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	base, err := old.Propose(ctx, []byte("base=1"))
	if err != nil {
		t.Fatalf("base propose: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, base.Index, 5*time.Second)
	}

	var others []NodeID
	for id := range c.nodes {
		if id != old.ID() {
			others = append(others, id)
		}
	}
	c.net.Partition([]NodeID{old.ID()}, others)

	// The isolated old leader appends an entry it can never commit.
	if _, err := old.ProposeAsync(ctx, []byte("stale=1")); err != nil {
		t.Fatalf("propose stale: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if old.Status().LastIndex > base.Index {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if last := old.Status().LastIndex; last <= base.Index {
		t.Fatalf("stale entry not appended: last=%d base=%d", last, base.Index)
	}

	var fresh *Node
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for id, node := range c.nodes {
			if id != old.ID() && node.State() == StateLeader {
				fresh = node
				break
			}
		}
		if fresh != nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if fresh == nil {
		t.Fatal("majority did not elect a new leader")
	}
	res, err := fresh.Propose(ctx, []byte("fresh=1"))
	if err != nil {
		t.Fatalf("fresh propose: %v", err)
	}
	for _, id := range others {
		c.waitApplied(id, res.Index, 10*time.Second)
	}

	c.net.Heal()
	c.waitApplied(old.ID(), res.Index, 10*time.Second)
	if got := c.fsms[old.ID()].value("stale"); got != "" {
		t.Fatalf("old follower applied divergent entry: stale=%q", got)
	}
	if got := c.fsms[old.ID()].value("fresh"); got != "1" {
		t.Fatalf("old follower fresh=%q", got)
	}
}

// TestVoteFromNonMemberRejected verifies an unknown node cannot collect votes
// from a member with a current configuration. | TestVoteFromNonMemberRejected 验证
// 拥有当前配置的成员不会给未知节点投票。
func TestVoteFromNonMemberRejected(t *testing.T) {
	n := &Node{
		id:       1,
		state:    StateFollower,
		term:     5,
		log:      &raftLog{firstIndex: 1},
		conf:     newMembership([]NodeID{1, 2}, nil, nil),
		metrics:  newMetrics(),
		progress: map[NodeID]*progress{},
	}
	n.handleVote(&Message{Type: MsgVote, From: 3, To: 1, Term: 5, LogIndex: 1, LogTerm: 5})
	if len(n.outBuf) != 1 || !n.outBuf[0].Reject {
		t.Fatalf("outbound = %+v, want one rejection", n.outBuf)
	}
	if n.vote != 0 {
		t.Fatalf("vote = %d, want none", n.vote)
	}
}

// TestTimeoutNowRequiresCurrentLeader verifies a stale or spoofed TimeoutNow
// does not start an election. | TestTimeoutNowRequiresCurrentLeader 验证过期或
// 伪造的 TimeoutNow 不会发起选举。
func TestTimeoutNowRequiresCurrentLeader(t *testing.T) {
	n := &Node{id: 1, state: StateFollower, term: 5, leader: 2}
	n.handleTimeoutNow(&Message{Type: MsgTimeoutNow, From: 3, To: 1, Term: 5})
	n.handleTimeoutNow(&Message{Type: MsgTimeoutNow, From: 2, To: 1, Term: 4})
	if n.term != 5 || n.state != StateFollower {
		t.Fatalf("stale timeout changed state: term=%d state=%s", n.term, n.state)
	}
}

// TestHeartbeatResetsProgressForRestartedFollower verifies a lower reported
// last index clears the stale match and re-probes from the real tail.
// | TestHeartbeatResetsProgressForRestartedFollower 验证较低的已报告最后索引会清除
// 过期 match，并从真实尾部重新探测。
func TestHeartbeatResetsProgressForRestartedFollower(t *testing.T) {
	n := &Node{
		id:        1,
		state:     StateLeader,
		term:      2,
		committed: 52,
		metrics:   newMetrics(),
		log:       &raftLog{firstIndex: 1, lastIndex: 4, snapshotIndex: 0},
		progress:  map[NodeID]*progress{},
	}
	pr := newProgress(53, 8, 1<<20)
	pr.match = 52
	pr.state = replicate
	n.progress[3] = pr
	// A delayed reply that echoes an older match must not force a backtrack. | 回显
	// 旧 match 的延迟响应不得造成回退。
	n.handleHeartbeatResp(&Message{Type: MsgHeartbeatResp, From: 3, To: 1, Term: 2, Index: 4, LogIndex: 51})
	if pr.match != 52 {
		t.Fatalf("stale heartbeat lowered match to %d", pr.match)
	}
	n.handleHeartbeatResp(&Message{Type: MsgHeartbeatResp, From: 3, To: 1, Term: 2, Index: 4, LogIndex: 52})
	if pr.match != 4 || pr.next != 5 || pr.state != probe {
		t.Fatalf("progress match=%d next=%d state=%s, want 4/5/probe", pr.match, pr.next, pr.state)
	}
}

// TestLeaseBoundUsesMinimumElectionTimeout verifies a lease never outlives the
// shortest follower election timeout and is measured from round start.
// | TestLeaseBoundUsesMinimumElectionTimeout 验证租约不超过跟随者最短选举超时，
// 并从轮次开始时刻起算。
func TestLeaseBoundUsesMinimumElectionTimeout(t *testing.T) {
	n := &Node{
		state:         StateLeader,
		term:          2,
		committed:     10,
		electionTicks: 10,
		tickInterval:  time.Millisecond,
		metrics:       newMetrics(),
	}
	started := time.Now().Add(-time.Second)
	r := &readRound{id: 1, index: 10, startedAt: started, acks: map[NodeID]bool{1: true}}
	n.readRound = r
	n.completeReadRound(r)
	want := started.Add(9 * time.Millisecond)
	if !n.leaseUntil.Equal(want) {
		t.Fatalf("leaseUntil = %v, want %v", n.leaseUntil, want)
	}
	if n.leaseValid() {
		t.Fatal("expired lease reported valid")
	}
}

// TestStepDownFailsActiveReadRound verifies blocked readers are released when a
// leader steps down instead of waiting for their context. | TestStepDownFailsActiveReadRound
// 验证领导者降级时阻塞读会被释放，而不是等待上下文超时。
func TestStepDownFailsActiveReadRound(t *testing.T) {
	n := &Node{
		id:            1,
		state:         StateLeader,
		term:          5,
		leader:        1,
		cfg:           Config{ElectionTicks: 8, HeartbeatTicks: 1, TickInterval: time.Millisecond},
		conf:          newMembership([]NodeID{1, 2, 3}, nil, nil),
		metrics:       newMetrics(),
		futures:       newFutureStore(),
		remoteReads:   newRemoteReadStore(),
		votes:         map[NodeID]bool{},
		preVotes:      map[NodeID]bool{},
		progress:      map[NodeID]*progress{},
		appliedNotify: newAppliedNotifier(),
		log:           &raftLog{firstIndex: 1},
	}
	done := make(chan readResult, 1)
	r := &readRound{id: 7, index: 3, startedAt: time.Now(), acks: map[NodeID]bool{1: true},
		reads: []*readRequest{{done: done}}}
	n.readRound = r
	n.becomeFollower(6, 0, false)
	select {
	case res := <-done:
		if !errors.Is(res.err, ErrLeadershipLost) {
			t.Fatalf("read error = %v, want ErrLeadershipLost", res.err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read was not released on step-down")
	}
	if n.readRound != nil {
		t.Fatal("read round still active after step-down")
	}
}
