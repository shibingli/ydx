package raft

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	hc "github.com/hashicorp/raft"
)

// hcFSM is a no-op hashicorp state machine. | hcFSM 是无操作 hashicorp 状态机。
type hcFSM struct{}

// Apply implements hc.FSM. | Apply 实现 hc.FSM。
func (*hcFSM) Apply(*hc.Log) interface{} { return nil }

// Snapshot implements hc.FSM. | Snapshot 实现 hc.FSM。
func (*hcFSM) Snapshot() (hc.FSMSnapshot, error) { return &hcSnapshot{}, nil }

// Restore implements hc.FSM. | Restore 实现 hc.FSM。
func (*hcFSM) Restore(io.ReadCloser) error { return nil }

// hcSnapshot is an empty snapshot. | hcSnapshot 是空快照。
type hcSnapshot struct{}

// Persist implements hc.FSMSnapshot. | Persist 实现 hc.FSMSnapshot。
func (*hcSnapshot) Persist(sink hc.SnapshotSink) error {
	if err := sink.Close(); err != nil {
		_ = sink.Cancel()
		return err
	}
	return nil
}

// Release implements hc.FSMSnapshot. | Release 实现 hc.FSMSnapshot。
func (*hcSnapshot) Release() {}

// hcCluster is an in-process hashicorp/raft cluster. | hcCluster 是进程内
// hashicorp/raft 集群。
type hcCluster struct {
	rafts      []*hc.Raft
	transports []*hc.InmemTransport
}

// newHCCluster starts size hashicorp/raft nodes. | newHCCluster 启动 size 个
// hashicorp/raft 节点。
func newHCCluster(b *testing.B, size int) (*hcCluster, *hc.Raft) {
	b.Helper()
	prefix := fmt.Sprintf("hc-%d-", time.Now().UnixNano())
	addrs := make([]hc.ServerAddress, size)
	stores := make([]*hc.InmemStore, size)
	snaps := make([]*hc.InmemSnapshotStore, size)
	configs := make([]*hc.Config, size)
	c := &hcCluster{
		rafts:      make([]*hc.Raft, size),
		transports: make([]*hc.InmemTransport, size),
	}
	for i := 0; i < size; i++ {
		addr := hc.ServerAddress(fmt.Sprintf("%s%d", prefix, i+1))
		_, transport := hc.NewInmemTransport(addr)
		c.transports[i] = transport
		addrs[i] = addr
		stores[i] = hc.NewInmemStore()
		snaps[i] = hc.NewInmemSnapshotStore()
		cfg := hc.DefaultConfig()
		cfg.LocalID = hc.ServerID(fmt.Sprint(i + 1))
		cfg.HeartbeatTimeout = 100 * time.Millisecond
		cfg.ElectionTimeout = 100 * time.Millisecond
		cfg.CommitTimeout = 10 * time.Millisecond
		cfg.LeaderLeaseTimeout = 50 * time.Millisecond
		cfg.MaxAppendEntries = 128
		cfg.BatchApplyCh = true
		cfg.SnapshotThreshold = 1 << 30
		cfg.SnapshotInterval = time.Hour
		cfg.LogOutput = io.Discard
		configs[i] = cfg
	}
	for i := range c.transports {
		for j := range c.transports {
			if i != j {
				c.transports[i].Connect(addrs[j], c.transports[j])
			}
		}
	}
	servers := make([]hc.Server, size)
	for i := 0; i < size; i++ {
		servers[i] = hc.Server{ID: hc.ServerID(fmt.Sprint(i + 1)), Address: addrs[i], Suffrage: hc.Voter}
	}
	if err := hc.BootstrapCluster(configs[0], stores[0], stores[0], snaps[0], c.transports[0],
		hc.Configuration{Servers: servers}); err != nil {
		b.Fatalf("bootstrap: %v", err)
	}
	for i := 0; i < size; i++ {
		r, err := hc.NewRaft(configs[i], &hcFSM{}, stores[i], stores[i], snaps[i], c.transports[i])
		if err != nil {
			b.Fatalf("new raft %d: %v", i+1, err)
		}
		c.rafts[i] = r
	}
	waitUntil(b, "hashicorp leader", 5*time.Second, func() bool {
		leaders := 0
		for _, r := range c.rafts {
			if r.State() == hc.Leader {
				leaders++
			}
		}
		return leaders == 1
	})
	var leader *hc.Raft
	for _, r := range c.rafts {
		if r.State() == hc.Leader {
			leader = r
		}
	}
	return c, leader
}

// close shuts every hashicorp node down. | close 关闭所有 hashicorp 节点。
func (c *hcCluster) close() {
	for _, r := range c.rafts {
		if r != nil {
			_ = r.Shutdown().Error()
		}
	}
	for _, transport := range c.transports {
		transport.DisconnectAll()
		_ = transport.Close()
	}
}

// hcProposer implements proposer. | hcProposer 实现 proposer。
type hcProposer struct {
	r   *hc.Raft
	seq atomic.Uint64
}

// propose implements proposer. | propose 实现 proposer。
func (p *hcProposer) propose(_ context.Context, size int) error {
	return p.r.Apply(payload(p.seq.Add(1), size), 10*time.Second).Error()
}

// BenchmarkHashicorpSingleNodePropose measures hashicorp/raft's single-node path.
// | BenchmarkHashicorpSingleNodePropose 测量 hashicorp/raft 单节点路径。
func BenchmarkHashicorpSingleNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newHCCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runSequential(b, &hcProposer{r: leader})
	b.StopTimer()
}

// BenchmarkHashicorpSingleNodeParallel measures hashicorp/raft parallel
// proposals. | BenchmarkHashicorpSingleNodeParallel 测量 hashicorp/raft 并行提案。
func BenchmarkHashicorpSingleNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newHCCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runParallel(b, &hcProposer{r: leader})
	b.StopTimer()
}

// BenchmarkHashicorpThreeNodePropose measures hashicorp/raft three-node
// replication. | BenchmarkHashicorpThreeNodePropose 测量 hashicorp/raft 三节点复制。
func BenchmarkHashicorpThreeNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newHCCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runSequential(b, &hcProposer{r: leader})
	b.StopTimer()
}

// BenchmarkHashicorpThreeNodeParallel measures hashicorp/raft parallel
// three-node replication. | BenchmarkHashicorpThreeNodeParallel 测量
// hashicorp/raft 三节点并行复制。
func BenchmarkHashicorpThreeNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newHCCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runParallel(b, &hcProposer{r: leader})
	b.StopTimer()
}
