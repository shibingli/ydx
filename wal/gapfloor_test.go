package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestGapFloorAcceptsKnownGapAndRejectsNewLowerGap verifies the v1 gapFloor
// contract: an explicitly accepted lossy gap is persisted and may be reopened
// without the flag, while a newly appearing lower-address gap is rejected. |
// 验证 v1 gapFloor 契约：显式接受的有损缺口会持久化，之后无需重复传旗标；
// 新出现的更低地址缺口必须拒绝。
func TestGapFloorAcceptsKnownGapAndRejectsNewLowerGap(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("g"), 100)
	for i := 0; i < 20; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.Stats().Segments; got < 6 {
		t.Fatalf("segments = %d, want at least 6", got)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	removeSegmentForTest(t, dir, 4)
	// Force a directory scan so the gap is visible; a manifest fast-path entry
	// for a missing file is detected lazily on first read instead. | 强制目录扫描
	// 让缺口可见；MANIFEST 快速路径中缺失文件改为首次读取时检测。
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	// First loss is explicitly accepted and recorded in META.gapFloor. | 首次
	// 损失被显式接受并记录到 META.gapFloor。
	w2, err := Open(dir, WithAllowLSNGaps(true), WithAutoRepair(false))
	if err != nil {
		t.Fatalf("open with explicit lossy recovery: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	// The same gap reopens without the flag. | 同一缺口无需旗标即可重开。
	w3, err := Open(dir, WithAutoRepair(false))
	if err != nil {
		t.Fatalf("reopen known gap without flag: %v", err)
	}
	if err := w3.Close(); err != nil {
		t.Fatal(err)
	}
	// A new lower-address gap must be rejected when auto repair is opted out. |
	// 关闭自动修复时，新的更低地址缺口必须拒绝。
	removeSegmentForTest(t, dir, 2)
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	if _, err := Open(dir, WithAutoRepair(false)); !errors.Is(err, ErrMissingSegment) {
		t.Fatalf("open with new lower gap err = %v, want ErrMissingSegment", err)
	}
}

// TestNoAutoRepairRejectsUnrecordedGap verifies the strict opt-out: an
// unrecorded middle gap is an error when auto repair and lossy recovery are
// both off. | 验证严格退出模式：自动修复与有损恢复都关闭时，未记录的中间缺口
// 必须报错。
func TestNoAutoRepairRejectsUnrecordedGap(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("g"), 100)
	for i := 0; i < 20; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	removeSegmentForTest(t, dir, 3)
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	_ = os.Remove(anchorPath(dir))
	if _, err := Open(dir, WithAutoRepair(false)); !errors.Is(err, ErrMissingSegment) {
		t.Fatalf("Open err = %v, want ErrMissingSegment", err)
	}
}

// TestAutoRepairAcceptsNewGap verifies the default self-healing policy: a gap
// discovered after metadata loss is recorded in the anchor and the WAL stays
// usable without an explicit flag. | 验证默认自愈策略：元数据丢失后发现的缺口
// 会写入锚点，WAL 无需显式旗标即可继续使用。
func TestAutoRepairAcceptsNewGap(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("g"), 100)
	for i := 0; i < 20; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	removeSegmentForTest(t, dir, 3)
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("auto repair open: %v", err)
	}
	if got := w2.Stats().RecoveryMissingLSNs; got == 0 {
		t.Fatal("missing LSNs were not counted")
	}
	before := w2.LastLSN()
	if before == 0 {
		t.Fatal("no records recovered")
	}
	next, err := w2.Append(ctx, Record{Data: []byte("after-gap")})
	if err != nil {
		t.Fatal(err)
	}
	if next <= before {
		t.Fatalf("new LSN %d did not advance past %d", next, before)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
}

func removeSegmentForTest(t *testing.T, dir string, seq uint64) {
	t.Helper()
	for _, path := range []string{segmentPath(dir, seq), sidecarPath(dir, seq), backupPath(dir, seq)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}
