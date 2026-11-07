package wal

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestAppendDirectRoundTrip verifies a direct append is durable and readable
// across reopen. | TestAppendDirectRoundTrip 验证直接追加可持久化并在重开后读取。
func TestAppendDirectRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	lsn, err := w.AppendDirect(context.Background(), Record{Key: []byte("k"), Data: []byte("v")})
	if err != nil {
		t.Fatalf("append direct: %v", err)
	}
	if lsn != 1 {
		t.Fatalf("lsn=%d, want 1", lsn)
	}
	rec, err := w.Read(lsn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(rec.Key, []byte("k")) || !bytes.Equal(rec.Data, []byte("v")) {
		t.Fatalf("record = %q/%q", rec.Key, rec.Data)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if got := w2.LastLSN(); got != 1 {
		t.Fatalf("LastLSN=%d, want 1", got)
	}
}

// TestAppendDirectInterleavesWithAppend verifies the direct path shares LSN
// ordering with the queued writer path. | TestAppendDirectInterleavesWithAppend
// 验证直接路径与队列写入路径共享 LSN 顺序。
func TestAppendDirectInterleavesWithAppend(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	ctx := context.Background()
	steps := []struct {
		direct bool
		data   string
	}{
		{true, "a"},
		{false, "b"},
		{true, "c"},
		{false, "d"},
	}
	for i, step := range steps {
		var lsn uint64
		if step.direct {
			lsn, err = w.AppendDirect(ctx, Record{Data: []byte(step.data)})
		} else {
			lsn, err = w.Append(ctx, Record{Data: []byte(step.data)})
		}
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if lsn != uint64(i+1) {
			t.Fatalf("step %d lsn=%d, want %d", i, lsn, i+1)
		}
	}
	var seen []string
	if err := w.Scan(ctx, 0, 0, func(r Record) error {
		seen = append(seen, string(r.Data))
		return nil
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(seen) != len(steps) {
		t.Fatalf("scan records=%d, want %d", len(seen), len(steps))
	}
	for i := range steps {
		if seen[i] != steps[i].data {
			t.Fatalf("record %d = %q, want %q", i, seen[i], steps[i].data)
		}
	}
}

// TestRotateWithoutSyncKeepsRecords verifies SyncNever with rotation sync
// disabled still rotates, reads, and recovers every record after a clean close.
// | TestRotateWithoutSyncKeepsRecords 验证 SyncNever 关闭轮转同步后仍能正常轮转，
// 且干净关闭后读取与恢复全部记录。
func TestRotateWithoutSyncKeepsRecords(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir,
		WithSyncPolicy(SyncNever()),
		WithSyncOnRotate(false),
		WithSegmentMaxBytes(1024),
	)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	payload := make([]byte, 128)
	for i := 0; i < 200; i++ {
		payload[0] = byte(i)
		if _, err := w.AppendDirect(ctx, Record{Data: payload}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	count := 0
	if err := w.Scan(ctx, 0, 0, func(Record) error { count++; return nil }); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count != 200 {
		t.Fatalf("scan records=%d, want 200", count)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	count = 0
	if err := w2.Scan(ctx, 0, 0, func(Record) error { count++; return nil }); err != nil {
		t.Fatalf("reopen scan: %v", err)
	}
	if count != 200 {
		t.Fatalf("reopen records=%d, want 200", count)
	}
}

// TestAppendDirectAfterClose verifies the direct path observes the closed state.
// | TestAppendDirectAfterClose 验证直接路径能观察到已关闭状态。
func TestAppendDirectAfterClose(t *testing.T) {
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := w.AppendDirect(context.Background(), Record{Data: []byte("x")}); !errors.Is(err, ErrClosed) {
		t.Fatalf("append direct after close = %v, want ErrClosed", err)
	}
}
