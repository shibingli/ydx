package wal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestTornTailAfterCompleteRecords simulates a crash between writing a batch's
// records and its commit marker. The records are durable but were never
// acknowledged, so recovery must roll LastLSN and the indexes back to the last
// marker instead of leaving a permanent LSN gap. | 模拟“整批记录已写、提交标记
// 未写”的崩溃：记录虽在磁盘上但从未确认，恢复必须把 LastLSN 与索引回滚到最后
// 一个标记，不能留下永久 LSN 缺口。
func TestTornTailAfterCompleteRecords(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	w, err := Open(src, WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AppendBatch(ctx, []Record{{Data: []byte("a")}, {Data: []byte("b")}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.AppendBatch(ctx, []Record{{Data: []byte("c")}, {Data: []byte("d")}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	copyFileForTest(t, filepath.Join(src, "META"), filepath.Join(dst, "META"))
	copyFileForTest(t, filepath.Join(src, "META.mirror"), filepath.Join(dst, "META.mirror"))
	walName := firstWALFileForTest(t, src)
	dstWal := filepath.Join(dst, walName)
	copyFileForTest(t, filepath.Join(src, walName), dstWal)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dstWal)
	if err != nil {
		t.Fatal(err)
	}
	// Drop only the final commit marker (48-byte header + 28-byte payload).
	if err := os.Truncate(dstWal, info.Size()-int64(recordHeaderSize+markerPayloadSize)); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(dst, WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatalf("open torn copy: %v", err)
	}
	if got := w2.LastLSN(); got != 2 {
		t.Fatalf("LastLSN after torn tail = %d, want 2", got)
	}
	if _, err := w2.Read(3); err == nil {
		t.Fatal("Read(3) succeeded for an uncommitted record")
	}
	lsn, err := w2.Append(ctx, Record{Data: []byte("e")})
	if err != nil {
		t.Fatal(err)
	}
	if lsn != 3 {
		t.Fatalf("next LSN = %d, want 3 (no permanent gap)", lsn)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	w3, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer w3.Close()
	if got := w3.LastLSN(); got != 3 {
		t.Fatalf("reopened LastLSN = %d, want 3", got)
	}
	for lsn, want := range map[uint64]string{1: "a", 2: "b", 3: "e"} {
		rec, err := w3.Read(lsn)
		if err != nil || string(rec.Data) != want {
			t.Fatalf("read %d = %q/%v, want %q", lsn, rec.Data, err, want)
		}
	}
}

func firstWALFileForTest(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".wal" {
			return e.Name()
		}
	}
	t.Fatal("no .wal file")
	return ""
}

func copyFileForTest(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
