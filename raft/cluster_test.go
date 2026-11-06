package raft

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestPartitionElectsNewLeader verifies check-quorum and catch-up after a heal.
// | TestPartitionElectsNewLeader 验证法定人数检查与恢复后的追赶。
func TestPartitionElectsNewLeader(t *testing.T) {
	c := newTestCluster(t, 3, func(cfg *Config) { cfg.DisableCheckQuorum = false })
	old := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first, err := old.Propose(ctx, []byte("a=1"))
	if err != nil {
		t.Fatalf("first propose: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, first.Index, 5*time.Second)
	}
	var peers []NodeID
	for id := range c.nodes {
		if id != old.ID() {
			peers = append(peers, id)
		}
	}
	c.net.Partition([]NodeID{old.ID()}, peers)
	var fresh *Node
	deadline := time.Now().Add(10 * time.Second)
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
		time.Sleep(5 * time.Millisecond)
	}
	if fresh == nil {
		t.Fatal("majority did not elect a new leader")
	}
	second, err := fresh.Propose(ctx, []byte("a=2"))
	if err != nil {
		t.Fatalf("second propose: %v", err)
	}
	for id := range c.nodes {
		if id == old.ID() {
			continue
		}
		c.waitApplied(id, second.Index, 8*time.Second)
		if got := c.fsms[id].value("a"); got != "2" {
			t.Fatalf("node %d value = %q", id, got)
		}
	}
	c.net.Heal()
	c.waitApplied(old.ID(), second.Index, 10*time.Second)
	if got := c.fsms[old.ID()].value("a"); got != "2" {
		t.Fatalf("old leader value = %q", got)
	}
	if got := c.nodes[old.ID()].Leader(); got != fresh.ID() {
		t.Fatalf("old leader sees %d, want %d", got, fresh.ID())
	}
}

// TestPreVoteDoesNotDisrupt verifies that an isolated follower's pre-vote fails
// locally and never raises its term, so healing cannot disturb the leader.
// | TestPreVoteDoesNotDisrupt 验证被隔离跟随者的预投票在本地失败且不提升任期，
// 因此恢复连接不会打扰领导者。
func TestPreVoteDoesNotDisrupt(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	var isolated, other NodeID
	for id := range c.nodes {
		if id == leader.ID() {
			continue
		}
		if isolated == 0 {
			isolated = id
		} else {
			other = id
		}
	}
	c.net.Partition([]NodeID{isolated}, []NodeID{leader.ID(), other})
	before := c.nodes[isolated].Term()
	time.Sleep(400 * time.Millisecond)
	if got := c.nodes[isolated].Term(); got != before {
		t.Fatalf("isolated term rose from %d to %d without quorum", before, got)
	}
	if c.nodes[isolated].State() == StateLeader {
		t.Fatalf("isolated node became leader")
	}
	c.net.Heal()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := leader.Propose(ctx, []byte("healed=1"))
	if err != nil {
		t.Fatalf("propose after heal: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, res.Index, 10*time.Second)
	}
	if got := c.nodes[isolated].Leader(); got != leader.ID() {
		t.Fatalf("isolated node sees leader %d, want %d", got, leader.ID())
	}
}

// TestRestartFollowerReplaysLog restarts a follower with the same storage.
// | TestRestartFollowerReplaysLog 用同一存储重启跟随者。
func TestRestartFollowerReplaysLog(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := leader.Propose(ctx, []byte("a=1")); err != nil {
		t.Fatalf("propose: %v", err)
	}
	var follower NodeID
	for id := range c.nodes {
		if id != leader.ID() {
			follower = id
			break
		}
	}
	target := c.nodes[follower]
	storage := c.storages[follower]
	if err := target.Close(); err != nil {
		t.Fatalf("close follower: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := leader.Propose(ctx, []byte(fmt.Sprintf("b%d=%d", i, i))); err != nil {
			t.Fatalf("propose while down: %v", err)
		}
	}
	c.restartNode(follower, storage, false)
	c.waitApplied(follower, leader.Commit(), 10*time.Second)
	if got := c.fsms[follower].value("a"); got != "1" {
		t.Fatalf("restarted value = %q", got)
	}
	if got := c.fsms[follower].value("b9"); got != "9" {
		t.Fatalf("restarted b9 = %q", got)
	}
}

// TestSnapshotCatchUpLearner forces compaction and catches up a fresh learner.
// | TestSnapshotCatchUpLearner 强制压缩并让全新学习者追赶。
func TestSnapshotCatchUpLearner(t *testing.T) {
	c := newTestCluster(t, 3, func(cfg *Config) {
		cfg.SnapshotEntries = 5
		// Keep the catch-up window smaller than the log so a fresh learner at
		// index 1 still needs a snapshot; the default 256 would let it replay
		// entries and would not exercise InstallSnapshot. | 让追赶窗口小于日志，
		// 使索引 1 的全新学习者仍需快照；默认 256 会让它直接重放日志，无法覆盖
		// InstallSnapshot。
		cfg.SnapshotCatchUpEntries = 1
	})
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var last Result
	for i := 0; i < 40; i++ {
		res, err := leader.Propose(ctx, []byte(fmt.Sprintf("k%d=%d", i, i)))
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		last = res
	}
	waitSnapshot(t, leader, 10*time.Second)
	c.addNode(4, true)
	if err := leader.AddLearner(ctx, 4, ""); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	c.waitApplied(4, leader.Commit(), 15*time.Second)
	if got := c.fsms[4].value("k39"); got != "39" {
		t.Fatalf("learner value = %q", got)
	}
	if got := c.nodes[4].Status().SnapshotIndex; got == 0 {
		t.Fatalf("learner did not install a snapshot")
	}
	if err := leader.Promote(ctx, 4); err != nil {
		t.Fatalf("promote: %v", err)
	}
	third, err := leader.Propose(ctx, []byte("after=promote"))
	if err != nil {
		t.Fatalf("propose after promote: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, third.Index, 15*time.Second)
		if got := c.fsms[id].value("after"); got != "promote" {
			t.Fatalf("node %d after = %q", id, got)
		}
	}
	if got := c.nodes[4].Status().Voters; !contains(got, 4) {
		t.Fatalf("node 4 not a voter: %v", got)
	}
	_ = last
}

// TestAddRemoveVoter exercises joint consensus. | TestAddRemoveVoter 覆盖联合共识。
func TestAddRemoveVoter(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c.addNode(4, true)
	if err := leader.AddNode(ctx, 4, ""); err != nil {
		t.Fatalf("add node: %v", err)
	}
	if _, err := leader.Propose(ctx, []byte("with4=1")); err != nil {
		t.Fatalf("propose with 4: %v", err)
	}
	c.waitApplied(4, leader.Commit(), 15*time.Second)
	if got := c.fsms[4].value("with4"); got != "1" {
		t.Fatalf("node 4 value = %q", got)
	}
	if err := leader.RemoveNode(ctx, 4); err != nil {
		for id, node := range c.nodes {
			t.Logf("node %d state=%s term=%d leader=%d commit=%d applied=%d status=%+v",
				id, node.State(), node.Term(), node.Leader(), node.Commit(), node.Applied(), node.Status())
		}
		t.Logf("leader stats: %+v", leader.Stats())
		t.Fatalf("remove node: %v", err)
	}
	if _, err := leader.Propose(ctx, []byte("after=remove")); err != nil {
		t.Fatalf("propose after remove: %v", err)
	}
	for id := NodeID(1); id <= 3; id++ {
		c.waitApplied(id, leader.Commit(), 15*time.Second)
		if got := c.fsms[id].value("after"); got != "remove" {
			t.Fatalf("node %d after = %q", id, got)
		}
	}
}

// TestFollowerReadIndex forwards a linearizable read through the leader.
// | TestFollowerReadIndex 通过领导者转发线性一致读。
func TestFollowerReadIndex(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := leader.Propose(ctx, []byte("x=42"))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, res.Index, 5*time.Second)
	}
	var follower *Node
	for id, node := range c.nodes {
		if id != leader.ID() {
			follower = node
			break
		}
	}
	index, err := follower.ReadIndex(ctx)
	if err != nil {
		t.Fatalf("follower read index: %v", err)
	}
	if err := follower.WaitApplied(ctx, index); err != nil {
		t.Fatalf("follower wait applied: %v", err)
	}
	if got := c.fsms[follower.ID()].value("x"); got != "42" {
		t.Fatalf("value = %q", got)
	}
}

// TestReadIndexWithoutLeader fails cleanly on a joining node. | TestReadIndexWithoutLeader
// 在加入节点上干净地失败。
func TestReadIndexWithoutLeader(t *testing.T) {
	net := NewMemNetwork()
	defer net.Close()
	transport, err := net.NewTransport(9)
	if err != nil {
		t.Fatal(err)
	}
	node, err := New(Config{ID: 9, Join: true, Storage: NewMemStorage(), FSM: newKVFSM(),
		Transport: transport, TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := node.ReadIndex(ctx); !errors.Is(err, ErrNoLeader) {
		t.Fatalf("error = %v, want ErrNoLeader", err)
	}
}

// TestLeaderTransfer hands leadership to a follower. | TestLeaderTransfer 将领导权
// 交给跟随者。
func TestLeaderTransfer(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var target NodeID
	for id := range c.nodes {
		if id != leader.ID() {
			target = id
			break
		}
	}
	if _, err := leader.Propose(ctx, []byte("before=transfer")); err != nil {
		t.Fatalf("propose: %v", err)
	}
	if err := leader.TransferLeader(ctx, target); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if leader.State() == StateLeader {
		t.Fatalf("old leader still leader")
	}
	fresh := c.waitLeader(5 * time.Second)
	if fresh.ID() != target {
		t.Fatalf("new leader = %d, want %d", fresh.ID(), target)
	}
	if _, err := fresh.Propose(ctx, []byte("after=transfer")); err != nil {
		t.Fatalf("propose after transfer: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, fresh.Commit(), 10*time.Second)
		if got := c.fsms[id].value("after"); got != "transfer" {
			t.Fatalf("node %d after = %q", id, got)
		}
	}
}

// restartNode replaces a closed node with the same storage. | restartNode 用同一存储
// 替换已关闭节点。
func (c *testCluster) restartNode(id NodeID, storage Storage, join bool) {
	c.t.Helper()
	transport, err := c.net.NewTransport(id)
	if err != nil {
		c.t.Fatalf("restart transport: %v", err)
	}
	fsm := newKVFSM()
	cfg := Config{
		ID:              id,
		Join:            join,
		Storage:         storage,
		FSM:             fsm,
		Transport:       transport,
		TickInterval:    c.tick,
		HeartbeatTicks:  1,
		ElectionTicks:   8,
		MaxBatchEntries: 64,
	}
	if !join {
		cfg.Peers = c.peers
	}
	if c.tweak != nil {
		c.tweak(&cfg)
	}
	node, err := New(cfg)
	if err != nil {
		c.t.Fatalf("restart node %d: %v", id, err)
	}
	c.nodes[id] = node
	c.fsms[id] = fsm
	c.storages[id] = storage
}

// waitSnapshot waits for the leader to create a local snapshot. | waitSnapshot 等待
// 领导者创建本地快照。
func waitSnapshot(t *testing.T, node *Node, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if node.Status().SnapshotIndex > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no snapshot within %v (status=%+v)", timeout, node.Status())
}
