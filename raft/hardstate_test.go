package raft

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestFileStoragePersistHardStateRecovery verifies the dedicated hard-state file
// is merged with the WAL on recovery: it wins over an older queued WAL write and
// loses to a newer term. | TestFileStoragePersistHardStateRecovery 验证专用硬状态
// 文件在恢复时与 WAL 合并：它覆盖更旧的排队 WAL 写入，并让位于更新的任期。
func TestFileStoragePersistHardStateRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 5, Vote: 2, Commit: 9}
	if err := s.PersistHardState(&hs); err != nil {
		t.Fatal(err)
	}
	// Simulate an older batch that was queued before the vote and reaches the
	// WAL afterwards. | 模拟投票前排队、随后才写入 WAL 的旧批次。
	old := HardState{Term: 4, Commit: 8}
	if err := s.Persist(PersistBatch{HardState: &old}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.HardState.Term != 5 || rec.HardState.Vote != 2 || rec.HardState.Commit != 9 {
		t.Fatalf("merged hard state = %+v, want term 5 vote 2 commit 9", rec.HardState)
	}
	// A newer WAL term supersedes the file and clears the stale vote. |
	// 更新的 WAL 任期覆盖文件并清除旧选票。
	newer := HardState{Term: 6, Commit: 10}
	if err := reopened.Persist(PersistBatch{HardState: &newer}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	rec, err = again.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.HardState.Term != 6 || rec.HardState.Vote != 0 || rec.HardState.Commit != 10 {
		t.Fatalf("newer hard state = %+v, want term 6 vote 0 commit 10", rec.HardState)
	}
}

// TestFileStorageHardStateCorruptionRejected verifies a torn dedicated
// hard-state file fails recovery instead of silently reusing an older term. |
// TestFileStorageHardStateCorruptionRejected 验证撕裂的专用硬状态文件会让恢复失败，
// 而不是静默复用更旧任期。
func TestFileStorageHardStateCorruptionRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 3, Vote: 1}
	if err := s.PersistHardState(&hs); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "HARDSTATE")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load error = %v, want ErrCorrupt", err)
	}
}
