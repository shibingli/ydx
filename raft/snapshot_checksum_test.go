package raft

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSnapshotCRCOnlyRoundTripAndRecovery verifies a CRC-only snapshot can be
// read back and recovered, including when the reader uses the default stronger
// checksum policy. | TestSnapshotCRCOnlyRoundTripAndRecovery 验证仅 CRC 的快照可
// 读回并恢复，包括读取方使用默认更强校验策略时。
func TestSnapshotCRCOnlyRoundTripAndRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true,
		SnapshotChecksum: SnapshotChecksumCRC32C})
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 12, Term: 3, ConfState: ConfState{Voters: []NodeID{1}},
		Data: []byte("crc-only-payload")}
	if err := s.Persist(PersistBatch{Snapshot: snap, HardState: &HardState{Term: 3, Commit: 12}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := readSnapshotFile(s.snapshotPath(12, 3))
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Data) != "crc-only-payload" {
		t.Fatalf("loaded = %q", loaded.Data)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || string(rec.Snapshot.Data) != "crc-only-payload" {
		t.Fatalf("recovered snapshot = %+v", rec.Snapshot)
	}
}

// TestStreamingSnapshotCRCOnly verifies the streaming image path honors the
// CRC-only layout and writes a version 2 file. | TestStreamingSnapshotCRCOnly
// 验证流式镜像路径遵循仅 CRC 布局并写入版本 2 文件。
func TestStreamingSnapshotCRCOnly(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true,
		SnapshotChecksum: SnapshotChecksumCRC32C})
	if err != nil {
		t.Fatal(err)
	}
	fsm := newStreamingKVFSM()
	node, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: fs, FSM: fsm,
		TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Propose(ctx, []byte("crc=1")); err != nil {
		t.Fatal(err)
	}
	if err := node.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	snap := node.latestSnapshot
	if snap == nil || snap.file == "" {
		t.Fatalf("latest snapshot = %+v", snap)
	}
	raw, err := os.ReadFile(snap.file)
	if err != nil {
		t.Fatal(err)
	}
	if raw[8] != snapshotVersionCRCOnly {
		t.Fatalf("snapshot version = %d, want %d", raw[8], snapshotVersionCRCOnly)
	}
	loaded, err := readSnapshotFile(snap.file)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Data) != "crc=1\n" {
		t.Fatalf("loaded = %q", loaded.Data)
	}
}

// TestSnapshotCRCOnlyDetectsCorruption verifies dropping SHA-256 does not remove
// CRC32C corruption detection. | TestSnapshotCRCOnlyDetectsCorruption 验证去除
// SHA-256 后仍保留 CRC32C 损坏检测。
func TestSnapshotCRCOnlyDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true,
		SnapshotChecksum: SnapshotChecksumCRC32C})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap := &Snapshot{Index: 7, Term: 2, ConfState: ConfState{Voters: []NodeID{1}},
		Data: []byte("corrupt-me")}
	if err := s.Persist(PersistBatch{Snapshot: snap, HardState: &HardState{Term: 2, Commit: 7}}); err != nil {
		t.Fatal(err)
	}
	path := s.snapshotPath(7, 2)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshotFile(path); err == nil {
		t.Fatal("corrupt CRC-only snapshot was accepted")
	}
}
