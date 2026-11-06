package raft

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowSnapshotFileStorage blocks InstallSnapshot persistence so a vote queued
// behind it would be delayed. It inherits FileStorage's dedicated hard-state
// persistence path. | slowSnapshotFileStorage 阻塞 InstallSnapshot 持久化，使排在
// 其后的选票写入被延迟；它继承 FileStorage 的专用硬状态持久化路径。
type slowSnapshotFileStorage struct {
	*FileStorage
	started chan struct{}
	release chan struct{}
	once    sync.Once
	block   atomic.Bool
}

func (s *slowSnapshotFileStorage) Persist(batch PersistBatch) error {
	if batch.Snapshot != nil && s.block.Load() {
		s.once.Do(func() { close(s.started) })
		<-s.release
	}
	return s.FileStorage.Persist(batch)
}

// TestSnapshotInstallDoesNotBlockVotePersist verifies a follower whose snapshot
// image write is still in flight can persist and answer a vote, so killing the
// old leader during snapshot catch-up does not leave the group leaderless for
// the duration of the snapshot fsync. | TestSnapshotInstallDoesNotBlockVotePersist
// 验证快照镜像仍在写入的跟随者仍能持久化并应答选票，因此旧 leader 在快照追赶
// 期间被杀死不会让组在整个快照 fsync 期间无 leader。
func TestSnapshotInstallDoesNotBlockVotePersist(t *testing.T) {
	net := NewMemNetwork()
	defer net.Close()
	peers := []Peer{{ID: 1}, {ID: 2}, {ID: 3}}
	var nodes map[NodeID]*Node
	nodes = make(map[NodeID]*Node)
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
				if node := nodes[id]; node != nil && node.State() == StateLeader {
					return node
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
	// Isolate the follower that will receive a snapshot. | 隔离将接收快照的跟随者。
	net.Partition([]NodeID{1, 2})
	leader := waitLeaderIn(1, 2)
	if leader == nil {
		t.Fatal("majority did not elect a leader after isolating node 3")
	}
	var last Result
	for i := 0; i < 40; i++ {
		res, err := leader.Propose(ctx, []byte{byte('a' + i%26)})
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		last = res
	}
	waitSnapshot(t, leader, 10*time.Second)
	slow.block.Store(true)
	net.Heal()
	select {
	case <-slow.started:
	case <-ctx.Done():
		t.Fatal("snapshot install did not reach the slow follower")
	}
	// Kill the old leader while the follower's snapshot persist is blocked. |
	// 在跟随者快照持久化被阻塞时杀死旧 leader。
	oldLeaderID := leader.ID()
	if err := leader.Close(); err != nil {
		t.Fatal(err)
	}
	delete(nodes, oldLeaderID)
	var remaining []NodeID
	for id := range nodes {
		remaining = append(remaining, id)
	}
	// The remaining voter must still be able to win a vote from the follower
	// whose snapshot fsync is blocked. | 剩余投票成员必须仍能从快照 fsync 被阻塞的
	// 跟随者获得选票。
	next := waitLeaderIn(remaining...)
	if next == nil {
		t.Fatal("no leader elected while snapshot persistence was blocked")
	}
	release()
	if err := next.WaitApplied(ctx, last.Index); err != nil {
		t.Fatalf("applied after snapshot release: %v", err)
	}
}
