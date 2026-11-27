package wal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestNoSyncRecoversLostSealedTail pins that a WAL rotated with syncOnRotate
// disabled tolerates a lost unsynced tail: recovery scans the sealed last segment
// instead of trusting its metadata by size, truncates the torn record and resumes
// from the durable prefix instead of returning ErrCorrupt. |
// TestNoSyncRecoversLostSealedTail 固定「禁用 syncOnRotate 的轮转能容忍丢失的未同步尾部」：
// 恢复扫描已封的最后分段而不是按大小信任元数据，截断撕裂记录并从持久前缀继续，而不是返回
// ErrCorrupt。
func TestNoSyncRecoversLostSealedTail(t *testing.T) {
	dir := t.TempDir()
	opts := []Option{WithSyncPolicy(SyncNever()), WithSyncOnRotate(false)}
	w, err := Open(dir, opts...)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const records = 4
	for i := 1; i <= records; i++ {
		if _, err := w.Append(context.Background(), Record{Data: []byte(fmt.Sprintf("record-%d", i))}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var segment string
	var maxSeq uint64
	for _, entry := range entries {
		seq, ok := parseSequence(entry.Name(), segmentSuffix)
		if ok && seq >= maxSeq {
			maxSeq = seq
			segment = entry.Name()
		}
	}
	if segment == "" {
		t.Fatal("no segment found")
	}
	path := filepath.Join(dir, segment)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-1); err != nil {
		t.Fatalf("truncate last record: %v", err)
	}

	reopened, err := Open(dir, opts...)
	if err != nil {
		t.Fatalf("reopen after lost tail: %v", err)
	}
	reader, err := reopened.NewReader()
	if err != nil {
		_ = reopened.Close()
		t.Fatalf("new reader: %v", err)
	}
	got := 0
	for {
		if _, err := reader.Next(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			_ = reader.Close()
			_ = reopened.Close()
			t.Fatalf("read after recovery: %v", err)
		}
		got++
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if got != records-1 {
		t.Fatalf("recovered records = %d, want %d", got, records-1)
	}
	if _, err := reopened.Append(context.Background(), Record{Data: []byte("after-recovery")}); err != nil {
		_ = reopened.Close()
		t.Fatalf("append after recovery: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
