package raft

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	ydx "github.com/shibingli/ydx/raft"
)

// multiGroupHost is an in-process NodeHost cluster running several Raft groups.
// | multiGroupHost 是运行多个 Raft 组的进程内 NodeHost 集群。
type multiGroupHost struct {
	hosts   []*ydx.NodeHost
	net     *ydx.MemNetwork
	groups  int
	leaders map[ydx.GroupID]*ydx.NodeHost
}

// newMultiGroupHost starts nodes NodeHosts with groups groups each. | newMultiGroupHost
// 启动 nodes 个 NodeHost，每个运行 groups 个组。
func newMultiGroupHost(b *testing.B, nodes, groups int) *multiGroupHost {
	b.Helper()
	net := ydx.NewMemNetwork()
	peers := make([]ydx.Peer, nodes)
	for i := 0; i < nodes; i++ {
		peers[i] = ydx.Peer{ID: ydx.NodeID(i + 1)}
	}
	h := &multiGroupHost{
		net:     net,
		groups:  groups,
		leaders: make(map[ydx.GroupID]*ydx.NodeHost),
	}
	for i := 0; i < nodes; i++ {
		id := ydx.NodeID(i + 1)
		tr, err := net.NewTransport(id)
		if err != nil {
			b.Fatal(err)
		}
		host, err := ydx.NewNodeHost(ydx.NodeHostConfig{
			ID:        id,
			Transport: tr,
			Storage: func(ydx.GroupID) (ydx.Storage, error) {
				return ydx.NewMemStorage(), nil
			},
			FSM: func(ydx.GroupID) (ydx.FSM, error) {
				return &noopFSM{}, nil
			},
		})
		if err != nil {
			b.Fatal(err)
		}
		h.hosts = append(h.hosts, host)
		for g := 1; g <= groups; g++ {
			if _, err := host.StartGroup(ydx.GroupConfig{
				ID:               ydx.GroupID(g),
				Peers:            peers,
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
			}); err != nil {
				b.Fatal(err)
			}
		}
	}
	for g := 1; g <= groups; g++ {
		group := ydx.GroupID(g)
		waitUntil(b, fmt.Sprintf("group %d leader", g), 10*time.Second, func() bool {
			leaders := 0
			for _, host := range h.hosts {
				st, err := host.Status(group)
				if err == nil && st.State == ydx.StateLeader {
					leaders++
				}
			}
			return leaders == 1
		})
		for _, host := range h.hosts {
			st, err := host.Status(group)
			if err == nil && st.State == ydx.StateLeader {
				h.leaders[group] = host
			}
		}
	}
	return h
}

// close stops every NodeHost. | close 停止所有 NodeHost。
func (h *multiGroupHost) close() {
	for _, host := range h.hosts {
		_ = host.Close()
	}
	h.net.Close()
}

// multiGroupProposer spreads proposals across groups. | multiGroupProposer 将提案
// 分散到多个组。
type multiGroupProposer struct {
	h   *multiGroupHost
	seq atomic.Uint64
}

// propose implements proposer. | propose 实现 proposer。
func (p *multiGroupProposer) propose(ctx context.Context, size int) error {
	seq := p.seq.Add(1)
	group := ydx.GroupID(seq%uint64(p.h.groups)) + 1
	_, err := p.h.leaders[group].Propose(ctx, group, payload(seq, size))
	return err
}

// BenchmarkYdxNodeHostGroups measures aggregate throughput as independent Raft
// groups run in parallel on one NodeHost cluster. | BenchmarkYdxNodeHostGroups
// 测量同一 NodeHost 集群上多个独立 Raft 组并行运行时的聚合吞吐。
func BenchmarkYdxNodeHostGroups(b *testing.B) {
	for _, groups := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("groups%d", groups), func(b *testing.B) {
			b.StopTimer()
			h := newMultiGroupHost(b, 3, groups)
			defer h.close()
			// Keep the per-group client concurrency constant as groups are added.
			// | 组数增加时保持每组客户端并发恒定。
			b.SetParallelism(groups)
			b.StartTimer()
			runParallel(b, &multiGroupProposer{h: h})
			b.StopTimer()
		})
	}
}
