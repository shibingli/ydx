package raft

import (
	"path/filepath"
	"testing"

	ydx "github.com/shibingli/ydx/raft"
)

// snapshotPayload returns a deterministic snapshot image. | snapshotPayload 返回
// 确定性的快照镜像。
func snapshotPayload(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i * 31)
	}
	return data
}

// BenchmarkYdxFileStorageSnapshotWrite measures snapshot file creation,
// checksumming, fsync and pruning. | BenchmarkYdxFileStorageSnapshotWrite 测量
// 快照文件创建、校验、fsync 与清理。
func BenchmarkYdxFileStorageSnapshotWrite(b *testing.B) {
	for _, noSync := range []bool{false, true} {
		name := "sync"
		if noSync {
			name = "nosync"
		}
		for _, size := range []int{64 << 10, 1 << 20, 8 << 20} {
			b.Run(name+"/"+itoa(size), func(b *testing.B) {
				storage, err := ydx.NewFileStorage(ydx.FileStorageOptions{
					Dir:         filepath.Join(b.TempDir(), "snap-write"),
					NoSync:      noSync,
					SegmentSize: 1 << 20,
				})
				if err != nil {
					b.Fatal(err)
				}
				defer storage.Close()
				data := snapshotPayload(size)
				conf := ydx.ConfState{Voters: []ydx.NodeID{1}}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					snap := &ydx.Snapshot{Index: uint64(i + 1), Term: 1, ConfState: conf, Data: data}
					if err := storage.Persist(ydx.PersistBatch{HardState: &ydx.HardState{Term: 1}, Snapshot: snap}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkYdxFileStorageSnapshotRead measures startup snapshot loading and
// validation. | BenchmarkYdxFileStorageSnapshotRead 测量启动时快照加载与校验。
func BenchmarkYdxFileStorageSnapshotRead(b *testing.B) {
	for _, size := range []int{64 << 10, 1 << 20, 8 << 20} {
		b.Run(itoa(size), func(b *testing.B) {
			dir := filepath.Join(b.TempDir(), "snap-read")
			storage, err := ydx.NewFileStorage(ydx.FileStorageOptions{
				Dir: dir, NoSync: true, SegmentSize: 1 << 20,
			})
			if err != nil {
				b.Fatal(err)
			}
			snap := &ydx.Snapshot{
				Index: 1, Term: 1, ConfState: ydx.ConfState{Voters: []ydx.NodeID{1}},
				Data: snapshotPayload(size),
			}
			if err := storage.Persist(ydx.PersistBatch{HardState: &ydx.HardState{Term: 1}, Snapshot: snap}); err != nil {
				b.Fatal(err)
			}
			if err := storage.Close(); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				read, err := ydx.NewFileStorage(ydx.FileStorageOptions{Dir: dir, NoSync: true})
				if err != nil {
					b.Fatal(err)
				}
				rec, err := read.Load()
				if err != nil {
					_ = read.Close()
					b.Fatal(err)
				}
				if rec.Snapshot == nil || len(rec.Snapshot.Data) != size {
					_ = read.Close()
					b.Fatalf("snapshot size = %d, want %d", len(rec.Snapshot.Data), size)
				}
				if err := read.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
