package raft

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// TestFileStorageEncryptedSnapshotHeaderBinding verifies the authenticated
// header prefix covers the checksum flags, so clearing the SHA flag cannot skip
// verification silently. | TestFileStorageEncryptedSnapshotHeaderBinding 验证认证
// 头部前缀覆盖校验标志，清除 SHA 标志不能跳过校验。
func TestFileStorageEncryptedSnapshotHeaderBinding(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots)
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 8, Term: 3, ConfState: ConfState{Voters: []NodeID{1}},
		Data: bytes.Repeat([]byte("flag-binding"), 20)}
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 3}, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	path := store.snapshotPath(8, 3)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	confLen := len(appendConfState(nil, snap.ConfState))
	flagsOffset := 9 + 20 + confLen + 12
	if raw[flagsOffset]&snapshotFlagSHA256 == 0 {
		t.Fatal("new image did not set the SHA-256 flag")
	}
	raw[flagsOffset] = 0
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cleared SHA flag error = %v, want ErrCorrupt", err)
	}
}

// TestSnapshotChunkDataPlaintextPolicy verifies chunk reads of a plaintext file
// follow the same downgrade policy as Load. | TestSnapshotChunkDataPlaintextPolicy
// 验证明文文件的分块读取遵循与 Load 相同的降级策略。
func TestSnapshotChunkDataPlaintextPolicy(t *testing.T) {
	dir := t.TempDir()
	plain, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("plaintext-chunk-payload")
	snap := &Snapshot{Index: 3, Term: 1, ConfState: ConfState{Voters: []NodeID{1}}, Data: data}
	if err := plain.WriteSnapshotFile(snap); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	snap.Data = nil

	strict, err := NewFileStorage(testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Node{storage: strict}).snapshotChunkData(snap, 0, 4); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("strict chunk error = %v, want ErrInvalidConfig", err)
	}
	_ = strict.Close()

	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots)
	opts.Encryption.AllowPlaintextFiles = true
	allowed, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	got, err := (&Node{storage: allowed}).snapshotChunkData(snap, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data[:4]) {
		t.Fatalf("chunk = %q", got)
	}
}

// TestFileStorageEncryptedHardStateWrongKey verifies the dedicated hard-state
// file is authenticated independently. | TestFileStorageEncryptedHardStateWrongKey
// 验证独立硬状态文件会被单独认证。
func TestFileStorageEncryptedHardStateWrongKey(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptHardState)
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 7, Vote: 2, Commit: 5}
	if err := store.PersistHardState(&hs); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	bad := opts
	bad.Encryption.Keys = []EncryptionKey{{
		ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x92),
	}}
	reopened, err := NewFileStorage(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong hard-state key error = %v, want ErrCorrupt", err)
	}
}

// TestFileStorageEncryptedSnapshotTamper verifies payload corruption is
// detected at load. | TestFileStorageEncryptedSnapshotTamper 验证负载损坏会在加载时
// 被发现。
func TestFileStorageEncryptedSnapshotTamper(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots)
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 5, Term: 2, ConfState: ConfState{Voters: []NodeID{1}},
		Data: bytes.Repeat([]byte("tamper-me"), 100)}
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 2}, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	path := store.snapshotPath(5, 2)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered snapshot error = %v, want ErrCorrupt", err)
	}
}

// TestFileStorageEncryptedSnapshotMissingKey verifies an encrypted snapshot
// cannot be read without a key ring. | TestFileStorageEncryptedSnapshotMissingKey
// 验证没有密钥环时无法读取加密快照。
func TestFileStorageEncryptedSnapshotMissingKey(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots)
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 2, Term: 1, ConfState: ConfState{Voters: []NodeID{1}}, Data: []byte("secret")}
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 1}, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	path := store.snapshotPath(2, 1)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshotFileWith(path, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing key error = %v, want ErrInvalidConfig", err)
	}
	plain, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := plain.Load(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("load without keys error = %v, want ErrInvalidConfig", err)
	}
}
