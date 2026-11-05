package raft

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	etcdraft "go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// etcdCluster drives etcd raft Nodes through Ready/Advance. | etcdCluster 通过
// Ready/Advance 驱动 etcd raft Node。
type etcdCluster struct {
	nodes    []etcdraft.Node
	storages []*etcdraft.MemoryStorage
	inboxes  []chan *raftpb.Message
	stops    []chan struct{}
	waiters  sync.Map
	stopped  atomic.Bool
	wg       sync.WaitGroup
}

// newEtcdCluster starts size etcd raft nodes. | newEtcdCluster 启动 size 个 etcd raft
// 节点。
func newEtcdCluster(b *testing.B, size int) (*etcdCluster, etcdraft.Node) {
	b.Helper()
	peers := make([]etcdraft.Peer, size)
	for i := 0; i < size; i++ {
		peers[i] = etcdraft.Peer{ID: uint64(i + 1)}
	}
	discard := &etcdraft.DefaultLogger{Logger: log.New(io.Discard, "", 0)}
	c := &etcdCluster{
		nodes:    make([]etcdraft.Node, size),
		storages: make([]*etcdraft.MemoryStorage, size),
		inboxes:  make([]chan *raftpb.Message, size),
		stops:    make([]chan struct{}, size),
	}
	for i := 0; i < size; i++ {
		storage := etcdraft.NewMemoryStorage()
		node := etcdraft.StartNode(&etcdraft.Config{
			ID:               uint64(i + 1),
			ElectionTick:     20,
			HeartbeatTick:    2,
			Storage:          storage,
			MaxSizePerMsg:    1 << 20,
			MaxInflightMsgs:  128,
			MaxInflightBytes: 16 << 20,
			CheckQuorum:      true,
			PreVote:          true,
			Logger:           discard,
		}, peers)
		inbox := make(chan *raftpb.Message, 8192)
		stop := make(chan struct{})
		c.nodes[i] = node
		c.storages[i] = storage
		c.inboxes[i] = inbox
		c.stops[i] = stop
		c.wg.Add(1)
		go c.run(node, storage, inbox, stop)
	}
	waitUntil(b, "etcd leader", 5*time.Second, func() bool {
		leaders := 0
		for _, node := range c.nodes {
			if node.Status().RaftState == etcdraft.StateLeader {
				leaders++
			}
		}
		return leaders == 1
	})
	var leader etcdraft.Node
	for _, node := range c.nodes {
		if node.Status().RaftState == etcdraft.StateLeader {
			leader = node
		}
	}
	return c, leader
}

// run is the per-node Ready loop. | run 是每节点的 Ready 循环。
func (c *etcdCluster) run(node etcdraft.Node, storage *etcdraft.MemoryStorage, inbox chan *raftpb.Message, stop chan struct{}) {
	defer c.wg.Done()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	ctx := context.Background()
	for {
		if c.stopped.Load() {
			return
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
			node.Tick()
		case m := <-inbox:
			if m != nil {
				_ = node.Step(ctx, m)
			}
		case rd := <-node.Ready():
			c.process(node, storage, rd)
			node.Advance()
		}
	}
}

// process persists a Ready and applies committed entries. | process 持久化 Ready 并
// 应用已提交日志项。
func (c *etcdCluster) process(node etcdraft.Node, storage *etcdraft.MemoryStorage, rd etcdraft.Ready) {
	if !etcdraft.IsEmptyHardState(rd.HardState) {
		_ = storage.SetHardState(rd.HardState)
	}
	if !etcdraft.IsEmptySnap(rd.Snapshot) {
		_ = storage.ApplySnapshot(rd.Snapshot)
	}
	if len(rd.Entries) > 0 {
		_ = storage.Append(rd.Entries)
	}
	for _, m := range rd.Messages {
		c.deliver(m)
	}
	for _, e := range rd.CommittedEntries {
		switch e.GetType() {
		case raftpb.EntryNormal:
			if len(e.Data) < 8 {
				continue
			}
			seq := binary.BigEndian.Uint64(e.Data[:8])
			if w, ok := c.waiters.LoadAndDelete(seq); ok {
				close(w.(chan struct{}))
			}
		case raftpb.EntryConfChange:
			var cc raftpb.ConfChange
			if err := proto.Unmarshal(e.Data, &cc); err == nil {
				node.ApplyConfChange(&cc)
			}
		}
	}
}

// deliver hands a message to the destination inbox. | deliver 将消息交给目的收件箱。
func (c *etcdCluster) deliver(m *raftpb.Message) {
	if m == nil {
		return
	}
	to := m.GetTo()
	if to == 0 || to > uint64(len(c.inboxes)) {
		return
	}
	select {
	case c.inboxes[to-1] <- m:
	default:
	}
}

// close stops every etcd node. | close 停止所有 etcd 节点。
func (c *etcdCluster) close() {
	c.stopped.Store(true)
	for i := range c.nodes {
		close(c.stops[i])
		c.nodes[i].Stop()
	}
	c.wg.Wait()
}

// etcdProposer implements proposer. | etcdProposer 实现 proposer。
type etcdProposer struct {
	node etcdraft.Node
	c    *etcdCluster
	seq  atomic.Uint64
}

// propose implements proposer. | propose 实现 proposer。
func (p *etcdProposer) propose(ctx context.Context, size int) error {
	seq := p.seq.Add(1)
	ch := make(chan struct{})
	p.c.waiters.Store(seq, ch)
	if err := p.node.Propose(ctx, payload(seq, size)); err != nil {
		p.c.waiters.Delete(seq)
		return err
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		p.c.waiters.Delete(seq)
		return ctx.Err()
	}
}

// BenchmarkEtcdSingleNodePropose measures etcd raft's single-node path.
// | BenchmarkEtcdSingleNodePropose 测量 etcd raft 单节点路径。
func BenchmarkEtcdSingleNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newEtcdCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runSequential(b, &etcdProposer{node: leader, c: c})
	b.StopTimer()
}

// BenchmarkEtcdSingleNodeParallel measures etcd raft parallel proposals.
// | BenchmarkEtcdSingleNodeParallel 测量 etcd raft 并行提案。
func BenchmarkEtcdSingleNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newEtcdCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runParallel(b, &etcdProposer{node: leader, c: c})
	b.StopTimer()
}

// BenchmarkEtcdThreeNodePropose measures etcd raft three-node replication.
// | BenchmarkEtcdThreeNodePropose 测量 etcd raft 三节点复制。
func BenchmarkEtcdThreeNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newEtcdCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runSequential(b, &etcdProposer{node: leader, c: c})
	b.StopTimer()
}

// BenchmarkEtcdThreeNodeParallel measures etcd raft three-node parallel
// replication. | BenchmarkEtcdThreeNodeParallel 测量 etcd raft 三节点并行复制。
func BenchmarkEtcdThreeNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newEtcdCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runParallel(b, &etcdProposer{node: leader, c: c})
	b.StopTimer()
}
