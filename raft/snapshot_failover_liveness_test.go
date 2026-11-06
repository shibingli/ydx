package raft

import (
	"context"
	"testing"
	"time"
)

// TestSnapshotInstallKeepsNewLeaderAlive verifies that, after the old leader is
// killed while a follower's snapshot persistence is still blocked, the newly
// elected leader keeps its check-quorum lease instead of stepping down as soon
// as the vote that elected it completes. | TestSnapshotInstallKeepsNewLeaderAlive
// 验证旧 leader 在跟随者快照持久化仍被阻塞时被杀死后，新当选 leader 不会在完成
// 当选选票后立刻因法定人数检查而降级。
func TestSnapshotInstallKeepsNewLeaderAlive(t *testing.T) {
	net := NewMemNetwork()
	defer net.Close()
	peers := []Peer{{ID: 1}, {ID: 2}, {ID: 3}}
	nodes := map[NodeID]*Node{}
	var slow *slowSnapshotFileStorage
	for id := 1; id <= 3; id++ {
		tr, err := net.NewTransport(NodeID(id))
		if err != nil {
			t.Fatal(err)
		}
		var storage Storage
		if id == 3 {
			fs, ferr := NewFileStorage(FileStorageOptions{Dir: t.TempDir(), NoSync: true})
			if ferr != nil {
				t.Fatal(ferr)
			}
			slow = &slowSnapshotFileStorage{
				FileStorage: fs, started: make(chan struct{}), release: make(chan struct{}),
			}
			storage = slow
		} else {
			storage = NewMemStorage()
		}
		node, err := New(Config{
			ID: NodeID(id), Peers: peers, Storage: storage, FSM: newKVFSM(),
			Transport: tr, TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1,
			ElectionTicks: 8, SnapshotEntries: 5, SnapshotCatchUpEntries: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes[NodeID(id)] = node
	}
	released := false
	release := func() {
		if !released {
			released = true
			close(slow.release)
		}
	}
	defer func() {
		release()
		for _, node := range nodes {
			_ = node.Close()
		}
	}()
	waitLeaderIn := func(ids ...NodeID) *Node {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			for _, id := range ids {
				if n := nodes[id]; n != nil && n.State() == StateLeader {
					return n
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
		return nil
	}
	if waitLeaderIn(1, 2, 3) == nil {
		t.Fatal("initial leader not elected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	net.Partition([]NodeID{1, 2})
	leader := waitLeaderIn(1, 2)
	if leader == nil {
		t.Fatal("majority did not elect a leader after isolating node 3")
	}
	for i := 0; i < 40; i++ {
		if _, err := leader.Propose(ctx, []byte{byte('a' + i%26)}); err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
	}
	waitSnapshot(t, leader, 10*time.Second)
	slow.block.Store(true)
	net.Heal()
	select {
	case <-slow.started:
	case <-ctx.Done():
		t.Fatal("snapshot install did not reach the slow follower")
	}
	oldLeaderID := leader.ID()
	if err := leader.Close(); err != nil {
		t.Fatal(err)
	}
	delete(nodes, oldLeaderID)
	var remaining []NodeID
	for id := range nodes {
		remaining = append(remaining, id)
	}
	next := waitLeaderIn(remaining...)
	if next == nil {
		t.Fatal("no leader elected while snapshot persistence was blocked")
	}
	// The follower is still blocked in snapshot Persist, but heartbeat
	// processing must remain independent of that write. The new leader must keep
	// its lease until the snapshot persistence is released.
	stableDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(stableDeadline) {
		if next.State() != StateLeader || next.Leader() != next.ID() {
			t.Fatalf("new leader %d lost leadership while snapshot persistence was blocked: state=%s leader=%d term=%d",
				next.ID(), next.State(), next.Leader(), next.Term())
		}
		time.Sleep(10 * time.Millisecond)
	}
	release()
	if _, err := next.Propose(ctx, []byte("after=release")); err != nil {
		t.Fatalf("propose after release: %v", err)
	}
}
