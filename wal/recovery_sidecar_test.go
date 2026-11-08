package wal

import (
	"context"
	"errors"
	"os"
	"testing"
)

// readSidecarForTest decodes one .idx file and fails the test on error. |
// readSidecarForTest 解码一个 .idx 文件，出错时终止测试。
func readSidecarForTest(t *testing.T, path string) *sidecar {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := decodeSidecar(data)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

// writeSidecarForTest encodes and writes one .idx file. |
// writeSidecarForTest 编码并写入一个 .idx 文件。
func writeSidecarForTest(t *testing.T, path string, sc *sidecar) {
	t.Helper()
	if err := os.WriteFile(path, encodeSidecar(sc), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestOpenAcceptsStaleSidecarPastFileEnd verifies B5: when a crash before the
// sidecar invalidation leaves segmentBytes beyond the current file end,
// recovery rescans the segment, accepts the sidecar as stale only because the
// committed waterline reaches the file end, and rewrites it. | 验证 B5：侧车
// 失效前崩溃导致 segmentBytes 超过当前文件末尾时，恢复重新扫描分段，仅在已提交
// 水位到达文件末尾时把侧车视为陈旧并重写。
func TestOpenAcceptsStaleSidecarPastFileEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte{'k', byte('0' + i)}, Data: []byte("stale-sidecar")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(segmentPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	sc := readSidecarForTest(t, sidecarPath(dir, 1))
	sc.segmentBytes = uint64(info.Size()) + 4096
	writeSidecarForTest(t, sidecarPath(dir, 1), sc)

	w2, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatalf("Open with stale sidecar past file end: %v", err)
	}
	if got := w2.LastLSN(); got != 3 {
		t.Fatalf("LastLSN = %d, want 3", got)
	}
	for lsn := uint64(1); lsn <= 3; lsn++ {
		if _, err := w2.Read(lsn); err != nil {
			t.Fatalf("read LSN %d after stale sidecar recovery: %v", lsn, err)
		}
	}
	rewritten := readSidecarForTest(t, sidecarPath(dir, 1))
	if rewritten.segmentBytes != uint64(info.Size()) {
		t.Fatalf("rewritten sidecar segmentBytes = %d, want %d", rewritten.segmentBytes, info.Size())
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}

	w3, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatalf("reopen after sidecar rewrite: %v", err)
	}
	if err := w3.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestOpenRejectsStaleSidecarWhenWaterlineShortOfFileEnd verifies B5's other
// branch: if a sidecar claims bytes past the file end but the committed
// waterline does not reach the file end, recovery must report corruption
// instead of silently truncating the tail. | 验证 B5 的另一分支：侧车声明的
// 字节数超过文件末尾，但已提交水位未到达文件末尾时，恢复必须报告损坏，而不是静默
// 截断尾部。
func TestOpenRejectsStaleSidecarWhenWaterlineShortOfFileEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte{'k', byte('0' + i)}, Data: []byte("stale-sidecar")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(segmentPath(dir, 1), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 4096)); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(segmentPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	sc := readSidecarForTest(t, sidecarPath(dir, 1))
	sc.segmentBytes = uint64(info.Size()) + 4096
	writeSidecarForTest(t, sidecarPath(dir, 1), sc)

	if _, err := Open(dir, WithManifest(false)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open err = %v, want ErrCorrupt for a stale sidecar whose waterline is short of the file end", err)
	}
}

// TestOpenSweepsOrphanSidecars verifies that a writable open removes .idx/.bak
// files without a matching .wal, preserving live sidecars, while a read-only
// open leaves them untouched. | 验证可写打开会删除没有对应 .wal 的 .idx/.bak
// 文件并保留活动侧车，只读打开则保持原样。
func TestOpenSweepsOrphanSidecars(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("orphan-sweep")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sidecarPath(dir, 1)); err != nil {
		t.Fatalf("live sidecar missing before sweep: %v", err)
	}
	orphans := []string{sidecarPath(dir, 99), backupPath(dir, 99)}
	for _, path := range orphans {
		if err := os.WriteFile(path, []byte("orphan"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w2, err := Open(dir, WithManifest(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range orphans {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("orphan %s survived a writable open: %v", path, err)
		}
	}
	if _, err := os.Stat(sidecarPath(dir, 1)); err != nil {
		t.Fatalf("live sidecar removed by the sweep: %v", err)
	}

	for _, path := range orphans {
		if err := os.WriteFile(path, []byte("orphan"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ro, err := Open(dir, WithReadOnly(true), WithManifest(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range orphans {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("read-only open removed orphan %s: %v", path, err)
		}
	}
}
