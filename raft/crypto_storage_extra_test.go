package raft

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestFileStoragePlaintextFilesWithDisabledTargets verifies the plaintext-file
// guard applies only to enabled targets: a store that encrypts only the WAL
// still reads legacy plaintext snapshots and HARDSTATE without the migration
// switch. | TestFileStoragePlaintextFilesWithDisabledTargets 验证明文文件保护仅
// 作用于启用的目标：只加密 WAL 时仍可在不打开迁移开关的情况下读取旧明文快照与
// HARDSTATE。
func TestFileStoragePlaintextFilesWithDisabledTargets(t *testing.T) {
	dir := t.TempDir()
	plain, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 4, Vote: 1, Commit: 3}
	snap := &Snapshot{Index: 3, Term: 4, ConfState: ConfState{Voters: []NodeID{1}},
		Data: []byte("plain-target-snapshot")}
	if err := plain.Persist(PersistBatch{HardState: &hs, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	if err := plain.PersistHardState(&hs); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptWAL)
	opts.Encryption.AllowPlaintextWAL = true
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rec, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || string(rec.Snapshot.Data) != "plain-target-snapshot" {
		t.Fatalf("recovered snapshot = %+v", rec.Snapshot)
	}
	if rec.HardState.Term != hs.Term || rec.HardState.Vote != hs.Vote {
		t.Fatalf("recovered hard state = %+v", rec.HardState)
	}
}

// TestFileStoragePlaintextSnapshotMigration verifies plaintext snapshots are
// rejected once snapshot encryption is enabled unless the migration switch is
// set. | TestFileStoragePlaintextSnapshotMigration 验证启用快照加密后会拒绝明文
// 快照，除非显式打开迁移开关。
func TestFileStoragePlaintextSnapshotMigration(t *testing.T) {
	dir := t.TempDir()
	plain, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 5, Term: 2, ConfState: ConfState{Voters: []NodeID{1}},
		Data: []byte("legacy-plaintext")}
	if err := plain.Persist(PersistBatch{HardState: &HardState{Term: 2}, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots)
	denied, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Load(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("plaintext snapshot error = %v, want ErrInvalidConfig", err)
	}
	_ = denied.Close()
	opts.Encryption.AllowPlaintextFiles = true
	allowed, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	rec, err := allowed.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || string(rec.Snapshot.Data) != "legacy-plaintext" {
		t.Fatalf("recovered snapshot = %+v", rec.Snapshot)
	}
}

// TestFileStoragePlaintextHardStateMigration verifies plaintext HARDSTATE is
// rejected once hard-state encryption is enabled unless the migration switch is
// set. | TestFileStoragePlaintextHardStateMigration 验证启用硬状态加密后会拒绝
// 明文 HARDSTATE，除非显式打开迁移开关。
func TestFileStoragePlaintextHardStateMigration(t *testing.T) {
	dir := t.TempDir()
	plain, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 6, Vote: 1, Commit: 4}
	if err := plain.PersistHardState(&hs); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptHardState)
	denied, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Load(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("plaintext hard state error = %v, want ErrInvalidConfig", err)
	}
	_ = denied.Close()
	opts.Encryption.AllowPlaintextFiles = true
	allowed, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	rec, err := allowed.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.HardState.Term != hs.Term || rec.HardState.Vote != hs.Vote || rec.HardState.Commit != hs.Commit {
		t.Fatalf("recovered hard state = %+v", rec.HardState)
	}
}

// TestFileStorageEncryptionRotation verifies the active key can change at run
// time and old artifacts remain readable while their key is retained. |
// TestFileStorageEncryptionRotation 验证运行时可切换活动密钥，且只要保留旧密钥，旧
// 产物仍可读取。
func TestFileStorageEncryptionRotation(t *testing.T) {
	dir := t.TempDir()
	opts := FileStorageOptions{
		Dir:    dir,
		NoSync: true,
		Encryption: EncryptionOptions{
			Keys: []EncryptionKey{
				{ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x81)},
				{ID: 2, Suite: EncryptionSM4GCM, Bytes: testEncryptionKey(EncryptionSM4GCM, 0x82)},
			},
			ActiveKeyID: 1,
			Targets:     EncryptAll,
		},
	}
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("FIRST-ENTRY-MARKER")
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 1},
		Entries: []Entry{{Index: 1, Term: 1, Data: first}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActiveEncryptionKey(2); err != nil {
		t.Fatal(err)
	}
	second := []byte("SECOND-ENTRY-MARKER")
	hs := HardState{Term: 2, Commit: 2}
	if err := store.Persist(PersistBatch{HardState: &hs,
		Entries: []Entry{{Index: 2, Term: 2, Data: second}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistHardState(&hs); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	hsRaw, err := os.ReadFile(filepath.Join(dir, hardStateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(hsRaw[9:13]); got != 2 {
		t.Fatalf("hard state key ID = %d, want 2", got)
	}
	reopened, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Entries) != 2 ||
		!bytes.Equal(rec.Entries[0].Data, first) || !bytes.Equal(rec.Entries[1].Data, second) {
		t.Fatalf("recovered entries = %+v", rec.Entries)
	}
	if rec.HardState.Term != hs.Term {
		t.Fatalf("recovered hard state = %+v", rec.HardState)
	}
}

// TestFileStorageEncryptionTargets verifies each target can be enabled
// independently. | TestFileStorageEncryptionTargets 验证每个加密目标可独立启用。
func TestFileStorageEncryptionTargets(t *testing.T) {
	entryMarker := []byte("TARGET-ENTRY-MARKER")
	snapMarker := []byte("TARGET-SNAPSHOT-MARKER")
	cases := []struct {
		name      string
		targets   EncryptionTargets
		walPlain  bool
		snapPlain bool
		hardPlain bool
	}{
		{snapshotDirName, EncryptSnapshots, true, false, true},
		{walDirName, EncryptWAL, false, true, true},
		{"hardstate", EncryptHardState, true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := testStorageOptions(dir, EncryptionAES256GCM, tc.targets)
			store, err := NewFileStorage(opts)
			if err != nil {
				t.Fatal(err)
			}
			hs := HardState{Term: 2, Commit: 1}
			if err := store.Persist(PersistBatch{HardState: &hs,
				Entries: []Entry{{Index: 1, Term: 2, Data: entryMarker}}}); err != nil {
				t.Fatal(err)
			}
			snap := &Snapshot{Index: 1, Term: 2, ConfState: ConfState{Voters: []NodeID{1}}, Data: snapMarker}
			if err := store.Persist(PersistBatch{HardState: &hs, Snapshot: snap}); err != nil {
				t.Fatal(err)
			}
			if err := store.PersistHardState(&hs); err != nil {
				t.Fatal(err)
			}
			snapPath := store.snapshotPath(1, 2)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			walPlain := bytes.Contains(readTree(t, filepath.Join(dir, walDirName)), entryMarker)
			if walPlain != tc.walPlain {
				t.Fatalf("WAL plaintext = %v, want %v", walPlain, tc.walPlain)
			}
			snapRaw, err := os.ReadFile(snapPath)
			if err != nil {
				t.Fatal(err)
			}
			snapPlain := bytes.Contains(snapRaw, snapMarker)
			if snapPlain != tc.snapPlain {
				t.Fatalf("snapshot plaintext = %v, want %v", snapPlain, tc.snapPlain)
			}
			hsRaw, err := os.ReadFile(filepath.Join(dir, hardStateFileName))
			if err != nil {
				t.Fatal(err)
			}
			hardPlain := hsRaw[8] == hardStateVersion
			if hardPlain != tc.hardPlain {
				t.Fatalf("hard state plaintext = %v, want %v", hardPlain, tc.hardPlain)
			}
		})
	}
}

// TestFileStorageEncryptionRejectsSuite verifies ChaCha20-Poly1305 is rejected
// only when the WAL target is enabled. | TestFileStorageEncryptionRejectsSuite
// 验证仅在启用 WAL 目标时拒绝 ChaCha20-Poly1305。
func TestFileStorageEncryptionRejectsSuite(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionChaCha20Poly1305, EncryptAll)
	if _, err := NewFileStorage(opts); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("all targets error = %v, want ErrInvalidKey", err)
	}
	opts.Encryption.Targets = EncryptSnapshots | EncryptHardState
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snap := &Snapshot{Index: 3, Term: 1, ConfState: ConfState{Voters: []NodeID{1}}, Data: []byte("chacha")}
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 1}, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	loaded, err := readSnapshotFileWith(store.snapshotPath(3, 1), store.cipher)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.Data) != "chacha" {
		t.Fatalf("snapshot payload = %q", loaded.Data)
	}
}

// TestFileStorageRotationBeforeLoad verifies the active key can be switched
// before the store has opened its WAL. | TestFileStorageRotationBeforeLoad 验证
// 存储尚未打开 WAL 时也可以切换活动密钥。
func TestFileStorageRotationBeforeLoad(t *testing.T) {
	dir := t.TempDir()
	opts := FileStorageOptions{
		Dir:    dir,
		NoSync: true,
		Encryption: EncryptionOptions{
			Keys: []EncryptionKey{
				{ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0xa1)},
				{ID: 2, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0xa2)},
			},
			ActiveKeyID: 1,
			Targets:     EncryptAll,
		},
	}
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetActiveEncryptionKey(2); err != nil {
		t.Fatal(err)
	}
	marker := []byte("ROTATED-BEFORE-LOAD")
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 1},
		Entries: []Entry{{Index: 1, Term: 1, Data: marker}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Entries) != 1 || !bytes.Equal(rec.Entries[0].Data, marker) {
		t.Fatalf("recovered entries = %+v", rec.Entries)
	}
}

// TestFileStorageEncryptionPlaintextWAL verifies opening an existing plaintext
// WAL with a key ring requires the explicit allowance. |
// TestFileStorageEncryptionPlaintextWAL 验证带密钥环打开既有明文 WAL 需要显式许可。
func TestFileStorageEncryptionPlaintextWAL(t *testing.T) {
	dir := t.TempDir()
	plain := FileStorageOptions{Dir: dir, NoSync: true}
	store, err := NewFileStorage(plain)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("LEGACY-PLAINTEXT-ENTRY")
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 1},
		Entries: []Entry{{Index: 1, Term: 1, Data: marker}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	encrypted := testStorageOptions(dir, EncryptionAES256GCM, EncryptAll)
	denied, err := NewFileStorage(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Load(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("downgrade error = %v, want ErrInvalidConfig", err)
	}
	_ = denied.Close()

	encrypted.Encryption.AllowPlaintextWAL = true
	allowed, err := NewFileStorage(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	rec, err := allowed.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Entries) != 1 || !bytes.Equal(rec.Entries[0].Data, marker) {
		t.Fatalf("recovered entries = %+v", rec.Entries)
	}
	if err := allowed.SetActiveEncryptionKey(1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("plaintext WAL rotation error = %v, want ErrInvalidConfig", err)
	}
}

// TestFileStorageSetActiveKeyErrors verifies rotation rejects missing keys and
// unencrypted stores. | TestFileStorageSetActiveKeyErrors 验证轮换会拒绝不存在的
// 密钥与未加密存储。
func TestFileStorageSetActiveKeyErrors(t *testing.T) {
	dir := t.TempDir()
	plain, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.SetActiveEncryptionKey(1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unencrypted rotation error = %v, want ErrInvalidConfig", err)
	}
	_ = plain.Close()

	store, err := NewFileStorage(testStorageOptions(filepath.Join(dir, "enc"), EncryptionAES256GCM, EncryptAll))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetActiveEncryptionKey(99); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing key error = %v, want ErrKeyNotFound", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActiveEncryptionKey(1); !errors.Is(err, ErrStopped) {
		t.Fatalf("closed rotation error = %v, want ErrStopped", err)
	}
}
