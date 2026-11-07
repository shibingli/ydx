package wal

import (
	"context"
	"testing"
)

type plainBackupForTest struct{}

func (plainBackupForTest) Target() string { return "test:plain" }

func (plainBackupForTest) Backup(context.Context, SegmentBundle) error { return nil }

// TestBackupCapabilities verifies the configuration probes used by scheduled
// backup adapters. | 验证定时备份适配器使用的配置探测方法。
func TestBackupCapabilities(t *testing.T) {
	plain, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if plain.BackupConfigured() || plain.SupportsSnapshotBackup() {
		t.Fatal("WAL without a backup target reports backup capabilities")
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}

	segmentOnly, err := Open(t.TempDir(), WithBackup(plainBackupForTest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !segmentOnly.BackupConfigured() || segmentOnly.SupportsSnapshotBackup() {
		t.Fatalf("segment-only target: configured=%v snapshot=%v, want true/false",
			segmentOnly.BackupConfigured(), segmentOnly.SupportsSnapshotBackup())
	}
	if err := segmentOnly.Close(); err != nil {
		t.Fatal(err)
	}

	snapshot, err := Open(t.TempDir(), WithBackup(DirBackup(t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.BackupConfigured() || !snapshot.SupportsSnapshotBackup() {
		t.Fatalf("snapshot target: configured=%v snapshot=%v, want true/true",
			snapshot.BackupConfigured(), snapshot.SupportsSnapshotBackup())
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
}
