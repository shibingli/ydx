package raft

import (
	"path/filepath"
	"testing"

	ydx "github.com/shibingli/ydx/raft"
)

// BenchmarkYdxFileStorageRecovery measures FileStorage startup replay. The WAL
// is built once, then each iteration opens the directory and loads every entry.
// | BenchmarkYdxFileStorageRecovery 测量 FileStorage 启动重放。WAL 只构建一次，
// 每轮迭代打开目录并加载全部日志项。
func BenchmarkYdxFileStorageRecovery(b *testing.B) {
	for _, batches := range []int{1000, 10000, 50000} {
		b.Run(itoa(batches), func(b *testing.B) {
			root := filepath.Join(b.TempDir(), "storage")
			storage, err := ydx.NewFileStorage(ydx.FileStorageOptions{
				Dir:         root,
				NoSync:      true,
				SegmentSize: 1 << 30,
			})
			if err != nil {
				b.Fatal(err)
			}
			hs := ydx.HardState{Term: 1}
			for i := 0; i < batches; i++ {
				hs.Commit = uint64(i + 1)
				if err := storage.Persist(ydx.PersistBatch{
					HardState: &hs,
					Entries:   walEntries(uint64(i+1), 1, benchmarkSize),
				}); err != nil {
					b.Fatal(err)
				}
			}
			if err := storage.Close(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s, err := ydx.NewFileStorage(ydx.FileStorageOptions{
					Dir:         root,
					NoSync:      true,
					SegmentSize: 1 << 30,
				})
				if err != nil {
					b.Fatal(err)
				}
				rec, err := s.Load()
				if err != nil {
					b.Fatal(err)
				}
				if len(rec.Entries) != batches {
					b.Fatalf("recovered %d entries, want %d", len(rec.Entries), batches)
				}
				if err := s.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}
