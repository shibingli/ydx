package wal

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestReadOnlyDoesNotCreateLockFile verifies the documented read-only contract:
// opening a WAL directory without a lock file must not create or write any file. |
// 验证只读契约：在没有锁文件的目录上只读打开不得创建或写入任何文件。
func TestReadOnlyDoesNotCreateLockFile(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(context.Background(), Record{Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, "wal.lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	ro, err := Open(dir, WithReadOnly(true))
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	if _, err := ro.Read(1); err != nil {
		t.Fatalf("read-only read: %v", err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("read-only open created %s", lock)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("read-only close created %s", lock)
	}
}
