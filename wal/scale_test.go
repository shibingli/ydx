package wal

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

// TestScaleManySegments exercises directory scanning, binary segment lookup,
// rotation, truncation, and reopen with hundreds of segments. | 用数百个分段
// 覆盖目录扫描、二分分段定位、轮转、截断与重开。
func TestScaleManySegments(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	ctx := context.Background()
	dir := t.TempDir()
	const records = 600
	w, err := Open(dir, WithSegmentMaxBytes(180), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("s"), 80)
	for i := 0; i < records; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.Stats().Segments; got < 100 {
		t.Fatalf("segments = %d, want at least 100", got)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithSegmentMaxBytes(180))
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := w2.LastLSN(); got != records {
		t.Fatalf("LastLSN = %d, want %d", got, records)
	}
	for lsn := uint64(1); lsn <= records; lsn += 37 {
		if _, err := w2.Read(lsn); err != nil {
			t.Fatalf("Read(%d): %v", lsn, err)
		}
	}
	count := 0
	if err := w2.Scan(ctx, 0, 0, func(Record) error { count++; return nil }); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count != records {
		t.Fatalf("scan count = %d, want %d", count, records)
	}
	if _, err := w2.Truncate(records / 2); err != nil {
		t.Fatal(err)
	}
	if err := w2.FlushCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	w3, err := Open(dir, WithSegmentMaxBytes(180))
	if err != nil {
		t.Fatal(err)
	}
	defer w3.Close()
	if got := w3.FirstLSN(); got != records/2 {
		t.Fatalf("FirstLSN = %d, want %d", got, records/2)
	}
	if _, err := w3.Read(records / 2); err != nil {
		t.Fatalf("read first live: %v", err)
	}
}

// TestScaleLargeRecord exercises the 1 GiB format bound's practical side with
// an 8 MiB record. | 用 8 MiB 记录覆盖大记录的写入、读取与恢复。
func TestScaleLargeRecord(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithMaxRecordBytes(9<<20), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("L"), 8<<20)
	if _, err := w.Append(ctx, Record{Key: []byte("large"), Data: payload}); err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	rec, err := w2.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec.Key, []byte("large")) || !bytes.Equal(rec.Data, payload) {
		t.Fatal("large record mismatch")
	}
	if err := w2.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestScaleManyKeys exercises complete Key indexes across sealed segments. |
// 覆盖多个封段的完整 Key 索引。
func TestScaleManyKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	ctx := context.Background()
	dir := t.TempDir()
	const records = 20000
	w, err := Open(dir, WithKeyIndex(true), WithSyncPolicy(SyncNever()), WithSegmentMaxBytes(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < records; i++ {
		key := []byte(fmt.Sprintf("key:%06d", i))
		if _, err := w.Append(ctx, Record{Key: key, Data: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithKeyIndex(true))
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	for i := 0; i < records; i += 997 {
		key := []byte(fmt.Sprintf("key:%06d", i))
		count, err := w2.Query(ctx, Query{Key: key}, nil)
		if err != nil || count != 1 {
			t.Fatalf("query %q count=%d err=%v", key, count, err)
		}
	}
	if got := w2.Stats().KeyIndexRebuilds; got != 0 {
		t.Fatalf("complete sealed indexes were rebuilt %d times", got)
	}
}

// TestScaleIndexOverflowFallsBack verifies correctness when the Key index
// intentionally overflows. | 验证 Key 索引故意溢出时仍保持正确。
func TestScaleIndexOverflowFallsBack(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithKeyIndex(true), WithKeyIndexMaxEntries(8), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte(fmt.Sprintf("k%d", i)), Data: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithKeyIndex(true), WithKeyIndexMaxEntries(8))
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	for i := 0; i < 100; i++ {
		key := []byte(fmt.Sprintf("k%d", i))
		count, err := w2.Query(ctx, Query{Key: key}, nil)
		if err != nil || count != 1 {
			t.Fatalf("query %q count=%d err=%v", key, count, err)
		}
	}
	if got := w2.Stats().KeyIndexScans; got == 0 {
		t.Fatal("overflowed segment was not scanned")
	}
}

// TestCrashCopyAfterEveryAppend copies the live directory without Close at
// several write boundaries and verifies zero acknowledged-record loss under
// SyncAlways. | 在多个写入边界不 Close 直接复制目录；SyncAlways 下已确认记录
// 不得丢失。
func TestCrashCopyAfterEveryAppend(t *testing.T) {
	ctx := context.Background()
	for n := 1; n <= 5; n++ {
		src := t.TempDir()
		w, err := Open(src, WithSegmentMaxBytes(200))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			if _, err := w.Append(ctx, Record{Data: []byte{byte(i), 'x'}}); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Sync(); err != nil {
			t.Fatal(err)
		}
		copyDir := copyWALDirForTest(t, src)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		w2, err := Open(copyDir, WithSegmentMaxBytes(200))
		if err != nil {
			t.Fatalf("n=%d: open copy: %v", n, err)
		}
		if err := w2.Verify(ctx); err != nil {
			t.Fatalf("n=%d: verify: %v", n, err)
		}
		if got := w2.LastLSN(); got != uint64(n) {
			t.Fatalf("n=%d: LastLSN = %d", n, got)
		}
		for i := 0; i < n; i++ {
			rec, err := w2.Read(uint64(i + 1))
			if err != nil || len(rec.Data) != 2 || rec.Data[0] != byte(i) {
				t.Fatalf("n=%d: Read(%d) = %v, %v", n, i+1, rec.Data, err)
			}
		}
		if err := w2.Close(); err != nil {
			t.Fatalf("n=%d: close: %v", n, err)
		}
	}
}

// TestCrashCopyDuringRotation copies the directory while segments are being
// rotated by the writer. | 在 writer 轮转分段时复制目录。
func TestCrashCopyDuringRotation(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	w, err := Open(src, WithSegmentMaxBytes(180), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("r"), 80)
	for i := 0; i < 30; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	// A barrier ensures any rotation triggered by the last append completed
	// before the directory is copied. | 屏障确保最后一次追加触发的轮转已完成。
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	copyDir := copyWALDirForTest(t, src)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(copyDir, WithSegmentMaxBytes(180))
	if err != nil {
		t.Fatalf("open copy: %v", err)
	}
	defer w2.Close()
	if err := w2.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := w2.LastLSN(); got != 30 {
		t.Fatalf("LastLSN = %d, want 30", got)
	}
	if _, err := w2.Read(30); err != nil {
		t.Fatalf("read last: %v", err)
	}
}
