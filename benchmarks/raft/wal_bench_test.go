package raft

import (
	"path/filepath"
	"testing"
	"time"

	ydx "github.com/shibingli/ydx/raft"
)

// walEntries builds a contiguous batch of entries for storage benchmarks.
// | walEntries 为存储基准构建连续日志批次。
func walEntries(first uint64, count, size int) []ydx.Entry {
	entries := make([]ydx.Entry, count)
	for i := range entries {
		data := make([]byte, size)
		for j := range data {
			data[j] = byte(i)
		}
		entries[i] = ydx.Entry{Index: first + uint64(i), Term: 1, Type: ydx.EntryNormal, Data: data}
	}
	return entries
}

// BenchmarkYdxFileStoragePersist measures the durable WAL append path. Use
// -benchtime=1s and TMPDIR on the filesystem under test. | BenchmarkYdxFileStoragePersist
// 测量持久 WAL 追加路径。使用 -benchtime=1s，并把 TMPDIR 指向待测文件系统。
func BenchmarkYdxFileStoragePersist(b *testing.B) {
	for _, noSync := range []bool{false, true} {
		for _, batch := range []int{1, 32, 128} {
			name := "sync"
			if noSync {
				name = "nosync"
			}
			b.Run(name+"/batch"+itoa(batch), func(b *testing.B) {
				storage, err := ydx.NewFileStorage(ydx.FileStorageOptions{
					Dir:         filepath.Join(b.TempDir(), "wal"),
					NoSync:      noSync,
					SegmentSize: 1 << 30,
				})
				if err != nil {
					b.Fatal(err)
				}
				defer storage.Close()
				hs := ydx.HardState{Term: 1, Commit: 0}
				entries := walEntries(1, batch, benchmarkSize)
				b.SetBytes(int64(batch * benchmarkSize))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					first := uint64(i*batch + 1)
					for j := range entries {
						entries[j].Index = first + uint64(j)
					}
					hs.Commit = first + uint64(batch) - 1
					if err := storage.Persist(ydx.PersistBatch{HardState: &hs, Entries: entries}); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
			})
		}
	}
}

// BenchmarkYdxFileStorageLargeEntry measures the WAL path for entries large
// enough to use the vectored write on Unix. | BenchmarkYdxFileStorageLargeEntry
// 测量足以在 Unix 上使用向量写的大日志项 WAL 路径。
func BenchmarkYdxFileStorageLargeEntry(b *testing.B) {
	for _, kib := range []int{64, 256, 1024} {
		for _, noSync := range []bool{false, true} {
			mode := "sync"
			if noSync {
				mode = "nosync"
			}
			b.Run(mode+"/"+itoa(kib)+"KiB", func(b *testing.B) {
				storage, err := ydx.NewFileStorage(ydx.FileStorageOptions{
					Dir:         filepath.Join(b.TempDir(), "wal"),
					NoSync:      noSync,
					SegmentSize: 1 << 30,
				})
				if err != nil {
					b.Fatal(err)
				}
				defer storage.Close()
				hs := ydx.HardState{Term: 1, Commit: 0}
				entries := walEntries(1, 1, kib<<10)
				b.SetBytes(int64(kib << 10))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					entries[0].Index = uint64(i + 1)
					hs.Commit = uint64(i + 1)
					if err := storage.Persist(ydx.PersistBatch{HardState: &hs, Entries: entries}); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
			})
		}
	}
}

// itoa formats a small non-negative integer without importing strconv in the
// hot benchmark file's imports twice. | itoa 格式化小的非负整数。
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// ydxFileCluster is an in-process ydx cluster backed by FileStorage. | ydxFileCluster
// 是由 FileStorage 支撑的进程内 ydx 集群。
type ydxFileCluster struct {
	nodes []*ydx.Node
	net   *ydx.MemNetwork
}

// newYdxFileCluster starts size nodes with durable WAL directories. | newYdxFileCluster
// 以持久 WAL 目录启动 size 个节点。
func newYdxFileCluster(b *testing.B, size int, noSync bool) (*ydxFileCluster, *ydx.Node) {
	return newYdxFileClusterTuned(b, size, noSync, 0)
}

// newYdxFileClusterTuned starts size nodes with a group-commit window.
// | newYdxFileClusterTuned 以组提交窗口启动 size 个节点。
func newYdxFileClusterTuned(b *testing.B, size int, noSync bool, delay time.Duration) (*ydxFileCluster, *ydx.Node) {
	b.Helper()
	net := ydx.NewMemNetwork()
	peers := make([]ydx.Peer, size)
	for i := 0; i < size; i++ {
		peers[i] = ydx.Peer{ID: ydx.NodeID(i + 1)}
	}
	c := &ydxFileCluster{net: net, nodes: make([]*ydx.Node, size)}
	for i := 0; i < size; i++ {
		var transport ydx.Transport
		if size > 1 {
			tr, err := net.NewTransport(ydx.NodeID(i + 1))
			if err != nil {
				b.Fatal(err)
			}
			transport = tr
		}
		storage, err := ydx.NewFileStorage(ydx.FileStorageOptions{
			Dir:         filepath.Join(b.TempDir(), "node", itoa(i+1)),
			NoSync:      noSync,
			SegmentSize: 1 << 30,
		})
		if err != nil {
			b.Fatal(err)
		}
		node, err := ydx.New(ydx.Config{
			ID:                ydx.NodeID(i + 1),
			Peers:             peers,
			Storage:           storage,
			FSM:               &noopFSM{},
			Transport:         transport,
			TickInterval:      5 * time.Millisecond,
			HeartbeatTicks:    2,
			ElectionTicks:     20,
			MaxBatchEntries:   128,
			MaxInflightMsgs:   128,
			MaxInflightBytes:  16 << 20,
			SnapshotEntries:   1 << 30,
			PersistBatchDelay: delay,
			ProposalQueue:     65536,
			MessageQueue:      65536,
			OutboundQueue:     65536,
		})
		if err != nil {
			b.Fatal(err)
		}
		c.nodes[i] = node
	}
	waitUntil(b, "ydx file leader", 10*time.Second, func() bool {
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
func (c *ydxFileCluster) close() {
	for _, node := range c.nodes {
		_ = node.Close()
	}
	c.net.Close()
}

// BenchmarkYdxThreeNodeDurable measures three-node replication with FileStorage.
// | BenchmarkYdxThreeNodeDurable 测量使用 FileStorage 的三节点复制。
func BenchmarkYdxThreeNodeDurable(b *testing.B) {
	b.Run("sync", func(b *testing.B) {
		b.StopTimer()
		c, leader := newYdxFileCluster(b, 3, false)
		defer c.close()
		b.StartTimer()
		runSequential(b, &ydxProposer{node: leader})
		b.StopTimer()
	})
	b.Run("sync/parallel", func(b *testing.B) {
		b.StopTimer()
		c, leader := newYdxFileCluster(b, 3, false)
		defer c.close()
		b.StartTimer()
		runParallel(b, &ydxProposer{node: leader})
		b.StopTimer()
	})
	b.Run("nosync", func(b *testing.B) {
		b.StopTimer()
		c, leader := newYdxFileCluster(b, 3, true)
		defer c.close()
		b.StartTimer()
		runSequential(b, &ydxProposer{node: leader})
		b.StopTimer()
	})
	b.Run("nosync/parallel", func(b *testing.B) {
		b.StopTimer()
		c, leader := newYdxFileCluster(b, 3, true)
		defer c.close()
		b.StartTimer()
		runParallel(b, &ydxProposer{node: leader})
		b.StopTimer()
	})
}

// BenchmarkYdxThreeNodeGroupCommit measures how the durable write window
// amortizes fsync under concurrent clients. Run with TMPDIR on the target
// filesystem. | BenchmarkYdxThreeNodeGroupCommit 测量持久写窗口在并发客户端下
// 分摊 fsync 的效果。请把 TMPDIR 指向目标文件系统。
func BenchmarkYdxThreeNodeGroupCommit(b *testing.B) {
	for _, delay := range []time.Duration{0, 25 * time.Microsecond, 50 * time.Microsecond, 100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond} {
		name := "off"
		if delay > 0 {
			name = delay.String()
		}
		b.Run(name, func(b *testing.B) {
			b.StopTimer()
			c, leader := newYdxFileClusterTuned(b, 3, false, delay)
			defer c.close()
			b.StartTimer()
			runParallel(b, &ydxProposer{node: leader})
			b.StopTimer()
			st := leader.Stats()
			b.Logf("persist_batches=%d avg_entries=%.2f", st.PersistBatches,
				float64(st.Proposals)/float64(st.PersistBatches))
		})
	}
}
