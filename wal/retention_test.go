package wal

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

type retentionTestBackup struct{}

func (retentionTestBackup) Target() string { return "test:retention" }

func (retentionTestBackup) Backup(ctx context.Context, seg SegmentBundle) error {
	_, err := io.Copy(io.Discard, seg.Data)
	return err
}

func (retentionTestBackup) Verify(context.Context, SegmentMeta) error { return nil }

// TestRetentionAfterBackup checks that the oldest sealed segment is deleted
// once a matching .bak marker exists and the verifier passes. A retention
// decision must use the same full SegmentMeta that the backup worker recorded. |
// 验证最旧封段在 `.bak` 匹配且校验通过后被删除；保留决策必须使用与备份 worker
// 记录一致的完整 SegmentMeta。
func TestRetentionAfterBackup(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir,
		WithSegmentMaxBytes(300),
		WithBackup(retentionTestBackup{}),
		WithRetention(Retention{MaxBytes: 1}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx := context.Background()
	payload := bytes.Repeat([]byte("y"), 120)
	for i := 0; i < 30; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: payload}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w.FirstLSN() > 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := w.Stats()
	t.Fatalf("retention never advanced FirstLSN: first=%d last=%d segments=%d sealed=%d skipped=%d backupDone=%d",
		w.FirstLSN(), w.LastLSN(), st.Segments, st.SealedSegments, st.RetentionSkipped, st.BackupDone)
}
