package wal

import (
	"context"
	"math/rand"
	"os"
	"testing"

	rosewal "github.com/rosedblabs/wal"
	ydxwal "github.com/shibingli/ydx/wal"
	tidwal "github.com/tidwall/wal"
)

var benchPayload = make([]byte, 256)

func init() {
	for i := range benchPayload {
		benchPayload[i] = byte(i)
	}
}

func BenchmarkYdxAppend(b *testing.B) {
	dir := b.TempDir()
	w, err := ydxwal.Open(dir, ydxwal.WithSegmentMaxBytes(1<<30), ydxwal.WithCheckpointBytes(1<<30))
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Append(ctx, ydxwal.Record{Data: benchPayload}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTidwallAppend(b *testing.B) {
	dir := b.TempDir()
	l, err := tidwal.Open(dir, &tidwal.Options{SegmentSize: 1 << 30})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := l.Write(uint64(i+1), benchPayload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRosedbAppend(b *testing.B) {
	dir := b.TempDir()
	w, err := rosewal.Open(rosewal.Options{DirPath: dir, SegmentSize: 1 << 30, SegmentFileExt: ".SEG", Sync: true})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(benchPayload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkYdxAppendBatch512(b *testing.B) {
	dir := b.TempDir()
	w, err := ydxwal.Open(dir, ydxwal.WithSegmentMaxBytes(1<<30), ydxwal.WithCheckpointBytes(1<<30))
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	ctx := context.Background()
	batch := make([]ydxwal.Record, 512)
	for i := range batch {
		batch[i] = ydxwal.Record{Data: benchPayload}
	}
	b.SetBytes(int64(len(benchPayload) * len(batch)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.AppendBatch(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkYdxAppendBatch512NoSync(b *testing.B) {
	dir := b.TempDir()
	w, err := ydxwal.Open(dir, ydxwal.WithSegmentMaxBytes(1<<30), ydxwal.WithCheckpointBytes(1<<30), ydxwal.WithSyncPolicy(ydxwal.SyncNever()))
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	ctx := context.Background()
	batch := make([]ydxwal.Record, 512)
	for i := range batch {
		batch[i] = ydxwal.Record{Data: benchPayload}
	}
	b.SetBytes(int64(len(benchPayload) * len(batch)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.AppendBatch(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTidwallWriteBatch512(b *testing.B) {
	dir := b.TempDir()
	l, err := tidwal.Open(dir, &tidwal.Options{SegmentSize: 1 << 30})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	b.SetBytes(int64(len(benchPayload) * 512))
	b.ReportAllocs()
	b.ResetTimer()
	index := uint64(1)
	for i := 0; i < b.N; i++ {
		var batch tidwal.Batch
		for j := 0; j < 512; j++ {
			batch.Write(index, benchPayload)
			index++
		}
		if err := l.WriteBatch(&batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRosedbWriteAll512(b *testing.B) {
	dir := b.TempDir()
	w, err := rosewal.Open(rosewal.Options{DirPath: dir, SegmentSize: 1 << 30, SegmentFileExt: ".SEG", Sync: false})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	b.SetBytes(int64(len(benchPayload) * 512))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 512; j++ {
			w.PendingWrites(benchPayload)
		}
		if _, err := w.WriteAll(); err != nil {
			b.Fatal(err)
		}
		if err := w.Sync(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkYdxAppendParallel8(b *testing.B) {
	dir := b.TempDir()
	w, err := ydxwal.Open(dir, ydxwal.WithSegmentMaxBytes(1<<30), ydxwal.WithCheckpointBytes(1<<30))
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := w.Append(ctx, ydxwal.Record{Data: benchPayload}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func prefilledYdx(b *testing.B, count int) (*ydxwal.WAL, string) {
	dir := b.TempDir()
	w, err := ydxwal.Open(dir, ydxwal.WithSyncPolicy(ydxwal.SyncNever()), ydxwal.WithSegmentMaxBytes(1<<30))
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	batch := make([]ydxwal.Record, count)
	for i := range batch {
		batch[i] = ydxwal.Record{Data: benchPayload}
	}
	if _, err := w.AppendBatch(ctx, batch); err != nil {
		b.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		b.Fatal(err)
	}
	return w, dir
}

func BenchmarkYdxReadRandom(b *testing.B) {
	w, _ := prefilledYdx(b, 10000)
	defer w.Close()
	rng := rand.New(rand.NewSource(1))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lsn := uint64(rng.Intn(10000) + 1)
		if _, err := w.Read(lsn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkYdxReadRandomSealed(b *testing.B) {
	w, dir := prefilledYdx(b, 10000)
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	w2, err := ydxwal.Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer w2.Close()
	rng := rand.New(rand.NewSource(1))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lsn := uint64(rng.Intn(10000) + 1)
		if _, err := w2.Read(lsn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTidwallReadRandom(b *testing.B) {
	dir := b.TempDir()
	l, err := tidwal.Open(dir, &tidwal.Options{SegmentSize: 1 << 30, NoSync: true})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 10000; i++ {
		if err := l.Write(uint64(i+1), benchPayload); err != nil {
			b.Fatal(err)
		}
	}
	if err := l.Sync(); err != nil {
		b.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Read(uint64(rng.Intn(10000) + 1)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRosedbReadRandom(b *testing.B) {
	dir := b.TempDir()
	w, err := rosewal.Open(rosewal.Options{DirPath: dir, SegmentSize: 1 << 30, SegmentFileExt: ".SEG", Sync: false})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	positions := make([]*rosewal.ChunkPosition, 0, 10000)
	for i := 0; i < 10000; i++ {
		pos, err := w.Write(benchPayload)
		if err != nil {
			b.Fatal(err)
		}
		positions = append(positions, pos)
	}
	if err := w.Sync(); err != nil {
		b.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Read(positions[rng.Intn(len(positions))]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkYdxScan10000(b *testing.B) {
	w, _ := prefilledYdx(b, 10000)
	defer w.Close()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		if err := w.Scan(ctx, 0, 0, func(ydxwal.Record) error { count++; return nil }); err != nil {
			b.Fatal(err)
		}
		if count != 10000 {
			b.Fatalf("count=%d", count)
		}
	}
}

func BenchmarkTidwallReadAll10000(b *testing.B) {
	dir := b.TempDir()
	l, err := tidwal.Open(dir, &tidwal.Options{SegmentSize: 1 << 30, NoSync: true})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 10000; i++ {
		if err := l.Write(uint64(i+1), benchPayload); err != nil {
			b.Fatal(err)
		}
	}
	if err := l.Sync(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := uint64(1); j <= 10000; j++ {
			if _, err := l.Read(j); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkRosedbReadAll10000(b *testing.B) {
	dir := b.TempDir()
	w, err := rosewal.Open(rosewal.Options{DirPath: dir, SegmentSize: 1 << 30, SegmentFileExt: ".SEG", Sync: false})
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	positions := make([]*rosewal.ChunkPosition, 0, 10000)
	for i := 0; i < 10000; i++ {
		pos, err := w.Write(benchPayload)
		if err != nil {
			b.Fatal(err)
		}
		positions = append(positions, pos)
	}
	if err := w.Sync(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, pos := range positions {
			if _, err := w.Read(pos); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkYdxOpen1000(b *testing.B) {
	w, dir := prefilledYdx(b, 1000)
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inst, err := ydxwal.Open(dir, ydxwal.WithSegmentMaxBytes(1<<30))
		if err != nil {
			b.Fatal(err)
		}
		if err := inst.Close(); err != nil {
			b.Fatal(err)
		}
	}
	_ = os.RemoveAll(dir)
}

func BenchmarkTidwallOpen1000(b *testing.B) {
	dir := b.TempDir()
	l, err := tidwal.Open(dir, &tidwal.Options{SegmentSize: 1 << 30, NoSync: true})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if err := l.Write(uint64(i+1), benchPayload); err != nil {
			b.Fatal(err)
		}
	}
	if err := l.Sync(); err != nil {
		b.Fatal(err)
	}
	_ = l.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inst, err := tidwal.Open(dir, &tidwal.Options{SegmentSize: 1 << 30})
		if err != nil {
			b.Fatal(err)
		}
		if err := inst.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRosedbOpen1000(b *testing.B) {
	dir := b.TempDir()
	w, err := rosewal.Open(rosewal.Options{DirPath: dir, SegmentSize: 1 << 30, SegmentFileExt: ".SEG", Sync: false})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if _, err := w.Write(benchPayload); err != nil {
			b.Fatal(err)
		}
	}
	if err := w.Sync(); err != nil {
		b.Fatal(err)
	}
	_ = w.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inst, err := rosewal.Open(rosewal.Options{DirPath: dir, SegmentSize: 1 << 30, SegmentFileExt: ".SEG"})
		if err != nil {
			b.Fatal(err)
		}
		if err := inst.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
