package wal

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckpointRecoveryPreservesIndexesAndRecords verifies that a segment
// recovered from a checkpoint sidecar keeps every committed record readable and
// writes a valid full sidecar whose sparse index still starts at baseLSN. |
// 验证从检查点侧车恢复的分段：所有已提交记录仍可读，且封段写出的完整侧车
// 稀疏索引仍从 baseLSN 开始。
func TestCheckpointRecoveryPreservesIndexesAndRecords(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	w, err := Open(src, WithCheckpointBytes(128), WithSegmentMaxBytes(1<<30), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("c"), 100)
	want := make(map[uint64][]byte)
	for i := 0; i < 20; i++ {
		lsn, err := w.Append(ctx, Record{Data: payload})
		if err != nil {
			t.Fatal(err)
		}
		want[lsn] = append([]byte(nil), payload...)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	size := walFileSizeForTest(t, src)
	waitCheckpointAtEnd(t, src, size)
	// Durable/visible tail records not covered by the checkpoint. | 检查点未覆盖的尾部记录。
	for i := 0; i < 3; i++ {
		lsn, err := w.Append(ctx, Record{Data: payload})
		if err != nil {
			t.Fatal(err)
		}
		want[lsn] = append([]byte(nil), payload...)
	}
	time.Sleep(20 * time.Millisecond)

	dst := t.TempDir()
	copyTreeForTest(t, src, dst)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(dst)
	if err != nil {
		t.Fatalf("recover from checkpoint: %v", err)
	}
	for lsn, data := range want {
		rec, err := w2.Read(lsn)
		if err != nil {
			t.Fatalf("read %d: %v", lsn, err)
		}
		if rec.LSN != lsn || !bytes.Equal(rec.Data, data) {
			t.Fatalf("read %d returned lsn=%d data=%d bytes", lsn, rec.LSN, len(rec.Data))
		}
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("seal recovered segment: %v", err)
	}
	sc, err := loadSidecar(sidecarPath(dst, 1))
	if err != nil {
		t.Fatalf("full sidecar written after checkpoint recovery is invalid: %v", err)
	}
	if len(sc.sparse) == 0 || sc.sparse[0].lsn != sc.baseLSN {
		t.Fatalf("first sparse LSN = %+v, want baseLSN %d", sc.sparse, sc.baseLSN)
	}
}

func walFileSizeForTest(t *testing.T, dir string) int64 {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".wal" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		size = info.Size()
	}
	return size
}

func waitCheckpointAtEnd(t *testing.T, dir string, size int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if sc, err := loadSidecar(sidecarPath(dir, 1)); err == nil && sc.checkpoint && sc.segmentBytes == uint64(size) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint at segment size %d was not written", size)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func copyTreeForTest(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if filepath.Ext(path) == ".tmp" || d.Name() == "wal.lock" {
			return nil
		}
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
