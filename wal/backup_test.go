package wal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestDirBackupRejectsSameSizeCorruption verifies that a target file with the
// right size but wrong contents is re-copied instead of being trusted, so
// retention can never delete the only good source copy. | 验证尺寸正确但内容
// 损坏的目标文件会被重新复制，而不是被信任，避免保留策略删掉唯一的好源副本。
func TestDirBackupRejectsSameSizeCorruption(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(src, WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: bytes.Repeat([]byte("b"), 100)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := w.FlushBackups(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(filepath.Join(backupDir, "*.wal"))
	if err != nil || len(backups) == 0 {
		t.Fatalf("backup files: %v", err)
	}
	target := backups[0]
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= int(segmentHeaderSize)+10 {
		t.Fatalf("backup too small: %d", len(data))
	}
	data[len(data)-10] ^= 0xFF
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Remove the durable backup marker so reconciliation re-runs. | 删除持久
	// 备份标记，使对账重新入队。
	markers, _ := filepath.Glob(filepath.Join(src, "*.bak"))
	for _, marker := range markers {
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
	}
	w2, err := Open(src, WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.FlushBackups(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(src, filepath.Base(target)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("same-size corrupted backup was not replaced")
	}
}
