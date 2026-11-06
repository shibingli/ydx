package raft

import (
	"fmt"
	"testing"
	"time"

	ydx "github.com/shibingli/ydx/raft"
)

// delayedStorage simulates fixed storage latency without changing Raft's
// durability contract. | delayedStorage 在不改变 Raft 持久性契约的前提下模拟固定
// 存储延迟。
type delayedStorage struct {
	inner *ydx.MemStorage
	delay time.Duration
}

func (d *delayedStorage) Load() (ydx.Recovery, error) { return d.inner.Load() }
func (d *delayedStorage) Persist(batch ydx.PersistBatch) error {
	err := d.inner.Persist(batch)
	time.Sleep(d.delay)
	return err
}
func (d *delayedStorage) Compact(index uint64) error { return d.inner.Compact(index) }
func (d *delayedStorage) Close() error               { return d.inner.Close() }

// BenchmarkYdxElectionFailover measures the wall-clock time from closing the
// current leader to a different node reporting leadership. The in-memory
// transport isolates election-algorithm latency from network I/O; the optional
// delayed storage isolates the persistence overlap. Run with a workspace
// mapping ydx/raft to this repository to benchmark the current code. |
// BenchmarkYdxElectionFailover 测量从关闭当前领导者到另一个节点报告领导权的墙钟
// 时间。内存传输把选举算法延迟与网络 I/O 分离；可选的延迟存储用于隔离持久化重叠
// 的效果。使用将 ydx/raft 映射到本仓库的工作区可对当前代码运行。
func BenchmarkYdxElectionFailover(b *testing.B) {
	for _, size := range []int{3, 5, 9, 25, 51, 101} {
		for _, variant := range []struct {
			name  string
			delay time.Duration
		}{
			{name: "mem"},
			{name: "fsync-1ms", delay: time.Millisecond},
		} {
			b.Run(fmt.Sprintf("nodes-%02d/%s", size, variant.name), func(b *testing.B) {
				b.ReportAllocs()
				var total time.Duration
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					c, leader := newYdxClusterTweaked(b, size, func(cfg *ydx.Config) {
						cfg.TickInterval = time.Millisecond
						cfg.HeartbeatTicks = 1
						cfg.ElectionTicks = 8
						cfg.MaxBatchEntries = 128
						cfg.MaxInflightMsgs = 128
						cfg.MessageQueue = 16384
						cfg.OutboundQueue = 16384
						cfg.ProposalQueue = 16384
						if variant.delay > 0 {
							cfg.Storage = &delayedStorage{inner: ydx.NewMemStorage(), delay: variant.delay}
						}
					})
					old := leader.ID()
					b.StartTimer()
					start := time.Now()
					if err := leader.Close(); err != nil {
						b.Fatalf("close leader: %v", err)
					}
					waitUntil(b, "new leader", 5*time.Second, func() bool {
						for _, node := range c.nodes {
							if node.ID() != old && node.State() == ydx.StateLeader {
								return true
							}
						}
						return false
					})
					elapsed := time.Since(start)
					total += elapsed
					b.StopTimer()
					c.close()
				}
				b.ReportMetric(float64(total.Milliseconds())/float64(b.N), "ms/failover")
			})
		}
	}
}
