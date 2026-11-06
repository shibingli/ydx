package raft

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	ydx "github.com/shibingli/ydx/raft"
)

// pipelineDepth is the per-worker outstanding proposal window used by the
// pipelined benchmark. | pipelineDepth 是流水线基准中每个 worker 的在途提案窗口。
const pipelineDepth = 16

// noopFSM is a zero-cost state machine. | noopFSM 是零成本状态机。
type noopFSM struct{}

// Apply implements ydx.FSM. | Apply 实现 ydx.FSM。
func (*noopFSM) Apply(uint64, uint64, []byte) any { return nil }

// Snapshot implements ydx.FSM. | Snapshot 实现 ydx.FSM。
func (*noopFSM) Snapshot() ([]byte, error) { return nil, nil }

// Restore implements ydx.FSM. | Restore 实现 ydx.FSM。
func (*noopFSM) Restore([]byte) error { return nil }

// ydxCluster is an in-process ydx/raft cluster. | ydxCluster 是进程内 ydx/raft 集群。
type ydxCluster struct {
	nodes []*ydx.Node
	net   *ydx.MemNetwork
}

// newYdxCluster starts size in-memory nodes. | newYdxCluster 启动 size 个内存节点。
func newYdxCluster(b *testing.B, size int) (*ydxCluster, *ydx.Node) {
	return newYdxClusterTweaked(b, size, nil)
}

// newYdxClusterTweaked starts size nodes and applies an optional config tweak.
// | newYdxClusterTweaked 启动 size 个节点并应用可选配置调整。
func newYdxClusterTweaked(b *testing.B, size int, tweak func(*ydx.Config)) (*ydxCluster, *ydx.Node) {
	b.Helper()
	net := ydx.NewMemNetwork()
	peers := make([]ydx.Peer, size)
	for i := 0; i < size; i++ {
		peers[i] = ydx.Peer{ID: ydx.NodeID(i + 1)}
	}
	c := &ydxCluster{net: net, nodes: make([]*ydx.Node, size)}
	for i := 0; i < size; i++ {
		var transport ydx.Transport
		if size > 1 {
			tr, err := net.NewTransport(ydx.NodeID(i + 1))
			if err != nil {
				b.Fatal(err)
			}
			transport = tr
		}
		cfg := ydx.Config{
			ID:               ydx.NodeID(i + 1),
			Peers:            peers,
			Storage:          ydx.NewMemStorage(),
			FSM:              &noopFSM{},
			Transport:        transport,
			TickInterval:     5 * time.Millisecond,
			HeartbeatTicks:   2,
			ElectionTicks:    20,
			MaxBatchEntries:  128,
			MaxInflightMsgs:  128,
			MaxInflightBytes: 16 << 20,
			SnapshotEntries:  1 << 30,
			ProposalQueue:    65536,
			MessageQueue:     65536,
			OutboundQueue:    65536,
		}
		if tweak != nil {
			tweak(&cfg)
		}
		node, err := ydx.New(cfg)
		if err != nil {
			b.Fatal(err)
		}
		c.nodes[i] = node
	}
	waitUntil(b, "ydx leader", 5*time.Second, func() bool {
		leaders := 0
		for _, node := range c.nodes {
			if node.State() == ydx.StateLeader {
				leaders++
			}
		}
		return leaders == 1
	})
	var leader *ydx.Node
	for _, node := range c.nodes {
		if node.State() == ydx.StateLeader {
			leader = node
		}
	}
	return c, leader
}

// close stops every node. | close 停止所有节点。
func (c *ydxCluster) close() {
	for _, node := range c.nodes {
		_ = node.Close()
	}
	c.net.Close()
}

// ydxProposer implements proposer. | ydxProposer 实现 proposer。
type ydxProposer struct {
	node *ydx.Node
	seq  atomic.Uint64
}

// propose implements proposer. | propose 实现 proposer。
func (p *ydxProposer) propose(ctx context.Context, size int) error {
	_, err := p.node.Propose(ctx, payload(p.seq.Add(1), size))
	return err
}

// BenchmarkYdxSingleNodePropose measures the single-node commit/apply path.
// | BenchmarkYdxSingleNodePropose 测量单节点提交/应用路径。
func BenchmarkYdxSingleNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newYdxCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runSequential(b, &ydxProposer{node: leader})
	b.StopTimer()
}

// BenchmarkYdxSingleNodeParallel measures single-node parallel proposals.
// | BenchmarkYdxSingleNodeParallel 测量单节点并行提案。
func BenchmarkYdxSingleNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newYdxCluster(b, 1)
	defer c.close()
	b.StartTimer()
	runParallel(b, &ydxProposer{node: leader})
	b.StopTimer()
}

// BenchmarkYdxThreeNodePropose measures three-node replication. | BenchmarkYdxThreeNodePropose
// 测量三节点复制。
func BenchmarkYdxThreeNodePropose(b *testing.B) {
	b.StopTimer()
	c, leader := newYdxCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runSequential(b, &ydxProposer{node: leader})
	b.StopTimer()
}

// BenchmarkYdxThreeNodeParallel measures three-node parallel replication.
// | BenchmarkYdxThreeNodeParallel 测量三节点并行复制。
func BenchmarkYdxThreeNodeParallel(b *testing.B) {
	b.StopTimer()
	c, leader := newYdxCluster(b, 3)
	defer c.close()
	b.StartTimer()
	runParallel(b, &ydxProposer{node: leader})
	b.StopTimer()
	st := leader.Stats()
	b.Logf("proposals=%d proposal_batches=%d applies=%d apply_batches=%d persist_batches=%d msgs_in=%d msgs_out=%d",
		st.Proposals, st.ProposalBatches, st.Applies, st.ApplyBatches, st.PersistBatches, st.MessagesIn, st.MessagesOut)
}

// BenchmarkYdxThreeNodePipelined measures a high-throughput client that keeps
// pipelineDepth proposals in flight per worker. | BenchmarkYdxThreeNodePipelined
// 测量每个 worker 保持 pipelineDepth 个在途提案的高吞吐客户端。
func BenchmarkYdxThreeNodePipelined(b *testing.B) {
	b.StopTimer()
	c, leader := newYdxClusterTweaked(b, 3, func(cfg *ydx.Config) {
		// Keep the long-running pipelined test bounded in memory. | 让长时间
		// 流水线测试的内存占用有界。
		cfg.SnapshotEntries = 100_000
		cfg.SnapshotCatchUpEntries = 256
	})
	defer c.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var seq atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		pending := make([]*ydx.Future, 0, pipelineDepth)
		for pb.Next() {
			f, err := leader.ProposeAsync(ctx, payload(seq.Add(1), benchmarkSize))
			if err != nil {
				b.Errorf("propose: %v", err)
				return
			}
			pending = append(pending, f)
			if len(pending) == pipelineDepth {
				if _, err := pending[0].Wait(ctx); err != nil {
					b.Errorf("wait: %v", err)
					return
				}
				pending = pending[1:]
			}
		}
		for _, f := range pending {
			if _, err := f.Wait(ctx); err != nil {
				b.Errorf("wait: %v", err)
				return
			}
		}
	})
	b.StopTimer()
	elapsed := time.Since(start)
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "ops/s")
	st := leader.Stats()
	b.Logf("proposals=%d proposal_batches=%d avg=%.2f applies=%d apply_batches=%d",
		st.Proposals, st.ProposalBatches, float64(st.Proposals)/float64(st.ProposalBatches),
		st.Applies, st.ApplyBatches)
}
