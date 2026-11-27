package raft

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testStorageOptions builds FileStorage options with one fixed test key. |
// testStorageOptions 使用一个固定测试密钥构建 FileStorage 选项。
func testStorageOptions(dir string, suite EncryptionSuite, targets EncryptionTargets) FileStorageOptions {
	return FileStorageOptions{
		Dir:    dir,
		NoSync: true,
		Encryption: EncryptionOptions{
			Keys:    []EncryptionKey{{ID: 1, Suite: suite, Bytes: testEncryptionKey(suite, 0x77)}},
			Targets: targets,
		},
	}
}

// readTree concatenates every regular file below root for raw-byte checks. |
// readTree 拼接 root 下的所有普通文件，用于原始字节检查。
func readTree(t *testing.T, root string) []byte {
	t.Helper()
	var out []byte
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		out = append(out, data...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestFileStorageEncryptionRoundTrip verifies WAL entries, snapshots and hard
// state are encrypted at rest and recover with the same key ring. |
// TestFileStorageEncryptionRoundTrip 验证 WAL 日志项、快照与硬状态在静态加密后可用
// 同一密钥环恢复。
func TestFileStorageEncryptionRoundTrip(t *testing.T) {
	for _, suite := range []EncryptionSuite{EncryptionAES256GCM, EncryptionSM4GCM} {
		t.Run(suite.String(), func(t *testing.T) {
			dir := t.TempDir()
			opts := testStorageOptions(dir, suite, EncryptAll)
			store, err := NewFileStorage(opts)
			if err != nil {
				t.Fatal(err)
			}
			entryMarker := []byte("ENTRY-PLAINTEXT-MARKER-0123456789")
			snapMarker := []byte("SNAPSHOT-PLAINTEXT-MARKER-0123456789")
			hs := HardState{Term: 4, Vote: 1, Commit: 2}
			if err := store.Persist(PersistBatch{HardState: &hs, Entries: []Entry{
				{Index: 1, Term: 4, Data: entryMarker},
			}}); err != nil {
				t.Fatal(err)
			}
			snap := &Snapshot{Index: 2, Term: 4, ConfState: ConfState{Voters: []NodeID{1}}, Data: snapMarker}
			if err := store.Persist(PersistBatch{HardState: &hs, Snapshot: snap}); err != nil {
				t.Fatal(err)
			}
			if err := store.PersistHardState(&hs); err != nil {
				t.Fatal(err)
			}
			snapPath := store.snapshotPath(2, 4)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			if raw := readTree(t, filepath.Join(dir, walDirName)); bytes.Contains(raw, entryMarker) {
				t.Fatal("WAL contains plaintext entry payload")
			}
			snapRaw, err := os.ReadFile(snapPath)
			if err != nil {
				t.Fatal(err)
			}
			if snapRaw[8] != snapshotVersionEncrypted {
				t.Fatalf("snapshot version = %d, want %d", snapRaw[8], snapshotVersionEncrypted)
			}
			if bytes.Contains(snapRaw, snapMarker) {
				t.Fatal("snapshot contains plaintext payload")
			}
			hsRaw, err := os.ReadFile(filepath.Join(dir, hardStateFileName))
			if err != nil {
				t.Fatal(err)
			}
			if hsRaw[8] != hardStateVersionEncrypted || len(hsRaw) != hardStateEncryptedSize {
				t.Fatalf("hard state version/size = %d/%d", hsRaw[8], len(hsRaw))
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
			if rec.HardState.Term != hs.Term || rec.HardState.Vote != hs.Vote || rec.HardState.Commit != hs.Commit {
				t.Fatalf("recovered hard state = %+v", rec.HardState)
			}
			if rec.Snapshot == nil || !bytes.Equal(rec.Snapshot.Data, snapMarker) {
				t.Fatalf("recovered snapshot = %+v", rec.Snapshot)
			}
			if len(rec.Entries) != 0 {
				t.Fatalf("recovered %d entries below the snapshot base", len(rec.Entries))
			}
		})
	}
}

// TestFileStorageEncryptionCRCOnlySnapshot verifies an encrypted image can omit
// SHA-256 while keeping CRC32C and AEAD checks. |
// TestFileStorageEncryptionCRCOnlySnapshot 验证加密镜像可省略 SHA-256，同时保留
// CRC32C 与 AEAD 校验。
func TestFileStorageEncryptionCRCOnlySnapshot(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots)
	opts.SnapshotChecksum = SnapshotChecksumCRC32C
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("crc-only-encrypted-payload")
	snap := &Snapshot{Index: 6, Term: 3, ConfState: ConfState{Voters: []NodeID{1}}, Data: data}
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 3}, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	path := store.snapshotPath(6, 3)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	flagsOffset := 9 + 20 + len(appendConfState(nil, snap.ConfState)) + 12
	if raw[8] != snapshotVersionEncrypted {
		t.Fatalf("version = %d", raw[8])
	}
	if raw[flagsOffset] != 0 {
		t.Fatalf("checksum flags = %d, want 0", raw[flagsOffset])
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
	if rec.Snapshot == nil || !bytes.Equal(rec.Snapshot.Data, data) {
		t.Fatalf("recovered snapshot = %+v", rec.Snapshot)
	}
}

// TestFileStorageEncryptionDefaultTargets verifies an empty Targets field enables
// every target. | TestFileStorageEncryptionDefaultTargets 验证 Targets 为空时启用
// 全部目标。
func TestFileStorageEncryptionDefaultTargets(t *testing.T) {
	dir := t.TempDir()
	opts := FileStorageOptions{
		Dir:    dir,
		NoSync: true,
		Encryption: EncryptionOptions{
			Keys: []EncryptionKey{{
				ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x91),
			}},
		},
	}
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("DEFAULT-TARGET-MARKER")
	hs := HardState{Term: 1}
	if err := store.Persist(PersistBatch{HardState: &hs,
		Entries: []Entry{{Index: 1, Term: 1, Data: marker}}}); err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 2, Term: 1, ConfState: ConfState{Voters: []NodeID{1}}, Data: marker}
	if err := store.Persist(PersistBatch{HardState: &hs, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistHardState(&hs); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(readTree(t, filepath.Join(dir, walDirName)), marker) {
		t.Fatal("default targets left WAL plaintext")
	}
	hsRaw, err := os.ReadFile(filepath.Join(dir, hardStateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if hsRaw[8] != hardStateVersionEncrypted {
		t.Fatalf("hard state version = %d", hsRaw[8])
	}
}

// TestFileStorageEncryptedEmptySnapshot verifies an empty encrypted image uses
// only the authenticated end marker. | TestFileStorageEncryptedEmptySnapshot
// 验证空加密镜像只使用认证结束标记。
func TestFileStorageEncryptedEmptySnapshot(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptSnapshots)
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 4, Term: 2, ConfState: ConfState{Voters: []NodeID{1}}}
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 2}, Snapshot: snap}); err != nil {
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
	if rec.Snapshot == nil || len(rec.Snapshot.Data) != 0 {
		t.Fatalf("recovered empty snapshot = %+v", rec.Snapshot)
	}
}

// TestFileStorageEncryptionConfigErrors verifies unusable encryption options are
// rejected before the storage directory is created. |
// TestFileStorageEncryptionConfigErrors 验证不可用的加密选项在创建存储目录前被拒绝。
func TestFileStorageEncryptionConfigErrors(t *testing.T) {
	key := EncryptionKey{ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x66)}
	cases := []struct {
		name string
		opts FileStorageOptions
		want error
	}{
		{"targets-without-keys", FileStorageOptions{Encryption: EncryptionOptions{Targets: EncryptWAL}}, ErrInvalidConfig},
		{"active-without-keys", FileStorageOptions{Encryption: EncryptionOptions{ActiveKeyID: 2}}, ErrInvalidConfig},
		{"unknown-target", FileStorageOptions{Encryption: EncryptionOptions{
			Keys: []EncryptionKey{key}, Targets: EncryptionTargets(0x80),
		}}, ErrInvalidConfig},
		{"bad-key", FileStorageOptions{Encryption: EncryptionOptions{
			Keys: []EncryptionKey{{ID: 1, Suite: EncryptionAES256GCM, Bytes: []byte("short")}},
		}}, ErrInvalidKey},
		{"missing-active", FileStorageOptions{Encryption: EncryptionOptions{
			Keys: []EncryptionKey{key}, ActiveKeyID: 3,
		}}, ErrKeyNotFound},
		{"bad-chunk", FileStorageOptions{Encryption: EncryptionOptions{
			Keys: []EncryptionKey{key}, ChunkSize: maxEncryptionChunkSize + 1,
		}}, ErrInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Dir = t.TempDir()
			tc.opts.NoSync = true
			if _, err := NewFileStorage(tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestFileStorageEncryptionWrongKey verifies a mismatched key ring cannot read
// encrypted state. | TestFileStorageEncryptionWrongKey 验证密钥不匹配时无法读取加密
// 状态。
func TestFileStorageEncryptionWrongKey(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionAES256GCM, EncryptAll)
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Persist(PersistBatch{HardState: &HardState{Term: 1},
		Entries: []Entry{{Index: 1, Term: 1, Data: []byte("payload")}}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	bad := opts
	bad.Encryption.Keys = []EncryptionKey{{
		ID: 1, Suite: EncryptionAES256GCM, Bytes: testEncryptionKey(EncryptionAES256GCM, 0x78),
	}}
	reopened, err := NewFileStorage(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Load(); err == nil {
		t.Fatal("wrong key ring loaded encrypted state")
	} else if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrAuth) && !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("wrong key error = %v", err)
	}
}

// TestFileStorageEncryptedSnapshotChunks verifies file-backed encrypted
// snapshots can be read whole and in random-access chunks. |
// TestFileStorageEncryptedSnapshotChunks 验证文件支持的加密快照可整体读取，也可随机
// 访问分块读取。
func TestFileStorageEncryptedSnapshotChunks(t *testing.T) {
	dir := t.TempDir()
	opts := testStorageOptions(dir, EncryptionSM4GCM, EncryptSnapshots)
	opts.Encryption.ChunkSize = 256
	store, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	data := make([]byte, 4096+123)
	for i := range data {
		data[i] = byte(i * 13)
	}
	copy(data[100:], []byte("SNAPSHOT-CHUNK-MARKER"))
	snap := &Snapshot{Index: 9, Term: 2, ConfState: ConfState{Voters: []NodeID{1}}, Data: data}
	if err := store.WriteSnapshotFile(snap); err != nil {
		t.Fatal(err)
	}
	if snap.crypto == nil {
		t.Fatal("snapshot has no crypto metadata")
	}
	raw, err := os.ReadFile(snap.file)
	if err != nil {
		t.Fatal(err)
	}
	if raw[8] != snapshotVersionEncrypted {
		t.Fatalf("snapshot version = %d", raw[8])
	}
	if bytes.Contains(raw, data[:64]) {
		t.Fatal("snapshot payload is plaintext")
	}
	snap.Data = nil
	node := &Node{storage: store}
	whole, err := node.snapshotData(snap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, data) {
		t.Fatal("whole snapshot mismatch")
	}
	for _, tc := range []struct{ offset, size int }{
		{0, 1},
		{100, 500},
		{4095, 124},
		{0, len(data)},
	} {
		got, err := node.snapshotChunkData(snap, uint64(tc.offset), tc.size)
		if err != nil {
			t.Fatalf("chunk %d/%d: %v", tc.offset, tc.size, err)
		}
		if !bytes.Equal(got, data[tc.offset:tc.offset+tc.size]) {
			t.Fatalf("chunk %d/%d mismatch", tc.offset, tc.size)
		}
	}
}
