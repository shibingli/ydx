package wal

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIncompleteNewestSegmentIsHealed verifies that a file shorter than the
// 64-byte segment header (a creation that crashed before its header became
// durable) is discarded instead of making the WAL unopenable. | 验证短于 64 字节
// 段头的文件（段头尚未持久化就崩溃的创建过程）会被丢弃，而不是让 WAL 无法打开。
func TestIncompleteNewestSegmentIsHealed(t *testing.T) {
	for _, size := range []int{0, 10, 63} {
		dir := t.TempDir()
		path := filepath.Join(dir, "00000000000000000001.wal")
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("size %d: open returned %v", size, err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("size %d: incomplete file was not discarded", size)
		}
		if _, err := w.Append(t.Context(), Record{Data: []byte("x")}); err != nil {
			t.Fatalf("size %d: append after heal: %v", size, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("size %d: close: %v", size, err)
		}
	}
}
