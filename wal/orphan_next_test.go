package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// TestOrphanNextSegmentFromInterruptedRotation reproduces a crash after a new
// segment file was created but before its MANIFEST kind=5 record and META
// nextSeq update. Recovery must remove the empty, never-acknowledged segment
// instead of failing every later Append with an O_EXCL conflict. |
// 复现“新分段文件已创建，但 MANIFEST kind=5 与 META nextSeq 尚未写入”的崩溃：
// 恢复必须删除这个从未确认的空分段，而不是让后续 Append 全部因 O_EXCL 冲突失败。
func TestOrphanNextSegmentFromInterruptedRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	h, _, err := readSegmentHeaderFile(segmentPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the crash window: the file exists and is durable, but no
	// MANIFEST/META record references it. | 模拟崩溃窗口：文件已持久化，但没有
	// MANIFEST/META 记录引用它。
	orphan, err := createSegmentFile(dir, 2, 2, h.walID, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	orphan.closeWriter()

	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with orphan next segment: %v", err)
	}
	defer w2.Close()
	if _, err := w2.Append(ctx, Record{Data: []byte("after")}); err != nil {
		t.Fatalf("Append after interrupted rotation: %v", err)
	}
	if got := w2.LastLSN(); got != 2 {
		t.Fatalf("LastLSN = %d, want 2", got)
	}
}

// TestPartialNextSegmentHeaderIsDiscarded reproduces a crash while the next
// segment's header is being written. The durable META.nextSeq points at a
// partial file that never accepted records; recovery must discard it instead of
// refusing to open the WAL. | 复现“下一分段头写入期间崩溃”的状态：持久
// META.nextSeq 指向一个从未接受记录的残缺文件；恢复必须丢弃它，而不是拒绝打开。
func TestPartialNextSegmentHeaderIsDiscarded(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segmentPath(dir, 2), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with partial next segment header: %v", err)
	}
	defer w2.Close()
	if _, err := w2.Append(ctx, Record{Data: []byte("after")}); err != nil {
		t.Fatalf("Append after partial next segment: %v", err)
	}
	if got := w2.LastLSN(); got != 2 {
		t.Fatalf("LastLSN = %d, want 2", got)
	}
}

// TestStaleEmptySegmentHeaderIsReplacedAtomically verifies that an empty last
// segment whose durable base LSN is stale gets a fresh header via atomic
// replacement, keeps its sequence, and never retires lower live segments. |
// 验证持久 base LSN 过期的空末尾分段会以原子替换获得新段头、保留序号，且绝不
// 连带退休更低的存活分段。
func TestStaleEmptySegmentHeaderIsReplacedAtomically(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	h, _, err := readSegmentHeaderFile(segmentPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	// Segment 2 exists but its base is stale (1 instead of 2). | 分段 2 存在，
	// 但 base 是过期的 1 而不是 2。
	stale, err := createSegmentFile(dir, 2, 1, h.walID, 0o600, 0)
	if err != nil {
		t.Fatal(err)
	}
	stale.closeWriter()

	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with stale empty segment: %v", err)
	}
	if _, err := w2.Append(ctx, Record{Data: []byte("after")}); err != nil {
		t.Fatal(err)
	}
	if got := w2.LastLSN(); got != 2 {
		t.Fatalf("LastLSN = %d, want 2 (no LSN reuse)", got)
	}
	w2.mu.RLock()
	activeSeq := uint64(0)
	if w2.active != nil {
		activeSeq = w2.active.seq
	}
	w2.mu.RUnlock()
	if activeSeq != 2 {
		t.Fatalf("active sequence = %d, want the retained segment 2", activeSeq)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	// A reopen must still see both the original and the new record. | 重新打开后
	// 原始记录与新记录都必须可读。
	w3, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after empty-header replacement: %v", err)
	}
	defer w3.Close()
	for lsn, want := range map[uint64]string{1: "first", 2: "after"} {
		rec, err := w3.Read(lsn)
		if err != nil || string(rec.Data) != want {
			t.Fatalf("Read(%d) = %q/%v, want %q", lsn, rec.Data, err, want)
		}
	}
}

// TestShortestSealedSegmentHeaderIsCorrupt verifies that a manifest-known last
// segment which lost its header is reported as corruption, not turned into a
// retire watermark that would hide every lower live segment. | 验证 MANIFEST
// 已知的最后分段丢失段头时报告损坏，而不是写入会连带隐藏所有更低存活分段的退休水位。
func TestShortestSealedSegmentHeaderIsCorrupt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: bytes.Repeat([]byte("s"), 64)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: bytes.Repeat([]byte("t"), 64)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Segment 2 is the last, sealed, non-empty segment. | 分段 2 是最后、已封且
	// 非空的分段。
	if err := os.Truncate(segmentPath(dir, 2), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open with truncated sealed header err = %v, want ErrCorrupt", err)
	}
	if _, err := os.Stat(segmentPath(dir, 1)); err != nil {
		t.Fatalf("lower live segment disappeared after failed Open: %v", err)
	}
}
