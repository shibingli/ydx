package wal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadOnlyRecreatesOnlyLockFile verifies that a read-only open on a directory whose lock
// file disappeared recreates that lock file — the reader/writer rendezvous — and that reading
// still works. Creating the empty lock file is the only write a read-only open may perform. |
// TestReadOnlyRecreatesOnlyLockFile 验证：锁文件消失后，只读打开会重建该锁文件（读写双方的
// 汇合点），且读取仍然可用。创建空锁文件是只读打开唯一允许的写入。
func TestReadOnlyRecreatesOnlyLockFile(t *testing.T) {
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
	lock := filepath.Join(dir, lockFileName)
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
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("read-only open did not recreate %s: %v", lock, err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReadOnlyLockExcludesWriter pins that a read-only open without a pre-existing lock file
// still takes the shared lock, so a writer cannot acquire the directory while the reader is
// active. | TestReadOnlyLockExcludesWriter 固定：锁文件原本不存在时，只读打开仍取得共享锁，
// 读取器活跃期间写者无法取得该目录。
func TestReadOnlyLockExcludesWriter(t *testing.T) {
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
	if err := os.Remove(filepath.Join(dir, lockFileName)); err != nil {
		t.Fatal(err)
	}
	ro, err := Open(dir, WithReadOnly(true))
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	reader, err := ro.NewReader()
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("writer open err = %v, want ErrLocked", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(dir)
	if err != nil {
		t.Fatalf("writer open after reader close: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDirectoryLockOutlivesCloseForReaders pins that Close keeps the directory lock while a
// reader lease is still active, and releases it when the last reader closes. A second process
// must not be able to rotate or unlink segments under a live reader. |
// TestDirectoryLockOutlivesCloseForReaders 固定：读租约仍活跃时 Close 保持目录锁，最后一个读取器
// 关闭后才释放。第二个进程不得在活跃读取器之下轮转或删除分段。
func TestDirectoryLockOutlivesCloseForReaders(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(context.Background(), Record{Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	reader, err := w.NewReader()
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("writer open while reader lease active = %v, want ErrLocked", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(dir)
	if err != nil {
		t.Fatalf("writer open after reader close: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}
