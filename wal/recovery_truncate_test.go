package wal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// crashCopyAfterTruncate builds the SIGKILL state: the active segment is
// unsealed, its MANIFEST summary is only the creation placeholder, and
// Truncate has advanced firstLSN into (or past) that segment.
// crashCopyAfterTruncate 构造 SIGKILL 状态：活跃段未封存，MANIFEST 仅有创建
// 占位摘要，且 Truncate 已把 firstLSN 推进到该段中间（或之后）。
func crashCopyAfterTruncate(t *testing.T, before uint64, recordsAfterRotate int) (string, uint64) {
	t.Helper()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte('a' + i)}}); err != nil {
			_ = w.Close()
			t.Fatalf("append pre-rotate: %v", err)
		}
	}
	if err := w.Rotate(); err != nil {
		_ = w.Close()
		t.Fatalf("rotate: %v", err)
	}
	for i := 0; i < recordsAfterRotate; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte('A' + i)}}); err != nil {
			_ = w.Close()
			t.Fatalf("append post-rotate: %v", err)
		}
	}
	if _, err := w.Truncate(before); err != nil {
		_ = w.Close()
		t.Fatalf("truncate: %v", err)
	}
	crashed := copyCrashState(t, dir)
	if err := w.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}
	return crashed, uint64(10 + recordsAfterRotate)
}

// copyCrashState copies the durable state of a live WAL. Sidecars (.idx/.bak)
// are skipped because Windows keeps them open without read sharing; recovery
// rebuilds them from MANIFEST and by scanning the surviving segments.
// copyCrashState 复制活跃 WAL 的持久状态；Windows 上 .idx/.bak 可能不共享读，
// 因此跳过；恢复会从 MANIFEST 与扫描段文件重建。
func copyCrashState(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	copyFile := func(rel string) {
		data, err := os.ReadFile(filepath.Join(src, rel))
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			t.Fatalf("copy %s: %v", rel, err)
		}
		target := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	for _, name := range []string{"META", "META.mirror", "RECOVERY"} {
		copyFile(name)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("read wal dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) == ".wal" {
			copyFile(entry.Name())
		}
	}
	if manifestEntries, err := os.ReadDir(filepath.Join(src, "manifest")); err == nil {
		for _, entry := range manifestEntries {
			if !entry.IsDir() {
				copyFile(filepath.Join("manifest", entry.Name()))
			}
		}
	}
	return dst
}

// TestTruncateIntoSigkillKeepsActiveTail reproduces the aggressive-snapshot
// crash: firstLSN advances into the unsealed active segment, whose only
// MANIFEST record is kind=created (lastLSN=base-1). Recovery must scan the real
// tail instead of unlinking the segment.
// TestTruncateIntoSigkillKeepsActiveTail 复现激进快照崩溃：firstLSN 推进到未封存
// 活跃段中间，而该段只有 kind=created（lastLSN=base-1）摘要；恢复必须扫描真实
// 尾部，不能删除该段。
func TestTruncateIntoSigkillKeepsActiveTail(t *testing.T) {
	crashed, lastLSN := crashCopyAfterTruncate(t, 12, 3) // records 11,12,13
	active := segmentPath(crashed, 2)
	before, err := os.Stat(active)
	if err != nil {
		t.Fatalf("active segment missing before open: %v", err)
	}
	w, err := Open(crashed)
	if err != nil {
		t.Fatalf("open crashed WAL: %v", err)
	}
	defer w.Close()
	if got := w.FirstLSN(); got != 12 {
		t.Fatalf("FirstLSN=%d, want 12", got)
	}
	if got := w.LastLSN(); got != lastLSN {
		t.Fatalf("LastLSN=%d, want %d", got, lastLSN)
	}
	rec, err := w.Read(lastLSN)
	if err != nil || !bytes.Equal(rec.Data, []byte("C")) {
		t.Fatalf("read tail = %+v err=%v", rec, err)
	}
	after, err := os.Stat(active)
	if err != nil {
		t.Fatalf("active segment was deleted during recovery: %v", err)
	}
	if after.Size() != before.Size() {
		t.Fatalf("active segment size changed: %d -> %d", before.Size(), after.Size())
	}
	lsn, err := w.Append(context.Background(), Record{Data: []byte("post-crash")})
	if err != nil || lsn != lastLSN+1 {
		t.Fatalf("append after recovery lsn=%d err=%v", lsn, err)
	}
}

// TestTruncateAllIntoSigkillKeepsActiveSegment covers the fully-truncated tail:
// every record of the unsealed active segment is below firstLSN. The segment is
// still the active append target and must stay in w.segments.
// TestTruncateAllIntoSigkillKeepsActiveSegment 覆盖尾段全部低于 firstLSN 的情况：
// 该段仍是追加目标，必须保留在 w.segments 中。
func TestTruncateAllIntoSigkillKeepsActiveSegment(t *testing.T) {
	crashed, _ := crashCopyAfterTruncate(t, 14, 3) // truncate to nextLSN
	w, err := Open(crashed)
	if err != nil {
		t.Fatalf("open crashed WAL: %v", err)
	}
	defer w.Close()
	if got := w.FirstLSN(); got != 14 {
		t.Fatalf("FirstLSN=%d, want 14", got)
	}
	if got := w.LastLSN(); got != 13 {
		t.Fatalf("LastLSN=%d, want 13", got)
	}
	w.mu.RLock()
	segments := len(w.segments)
	w.mu.RUnlock()
	if segments != 1 {
		t.Fatalf("live segments=%d, want the active segment retained", segments)
	}
	lsn, err := w.Append(context.Background(), Record{Data: []byte("after-truncate-all")})
	if err != nil || lsn != 14 {
		t.Fatalf("append lsn=%d err=%v, want 14", lsn, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(crashed)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if rec, err := w2.Read(14); err != nil || !bytes.Equal(rec.Data, []byte("after-truncate-all")) {
		t.Fatalf("read after reopen = %+v err=%v", rec, err)
	}
}
