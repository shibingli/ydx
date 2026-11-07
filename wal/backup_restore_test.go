package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func backupSetForTest(t *testing.T, dir string) BackupSet {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "BACKUP.snap"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := DecodeBackupSet(data)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// TestBackupNowPublishesRestoreCompleteSet verifies that BackupNow publishes
// metadata and that RestoreDir produces a WAL with every record and a safe
// next LSN. | 验证 BackupNow 发布元数据，RestoreDir 生成的 WAL 保留全部记录并
// 使用安全的下一 LSN。
func TestBackupNowPublishesRestoreCompleteSet(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(src,
		WithSegmentMaxBytes(200),
		WithSyncPolicy(SyncNever()),
		WithBackup(DirBackup(backupDir)),
		WithBackupWorkers(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	var want [][]byte
	for i := 0; i < 10; i++ {
		data := bytes.Repeat([]byte{byte('a' + i)}, 100)
		if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: data}); err != nil {
			t.Fatal(err)
		}
		want = append(want, data)
	}
	if err := w.BackupNow(ctx); err != nil {
		t.Fatalf("BackupNow: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	set := backupSetForTest(t, backupDir)
	if set.FirstLSN != 1 || set.LastLSN != 10 || set.NextLSN != 11 {
		t.Fatalf("set LSN range = [%d,%d) next %d", set.FirstLSN, set.LastLSN, set.NextLSN)
	}
	if len(set.Segments) < 2 {
		t.Fatalf("segments = %d, want at least 2", len(set.Segments))
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := RestoreDir(ctx, backupDir, dst); err != nil {
		t.Fatalf("RestoreDir: %v", err)
	}
	w2, err := Open(dst, WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatalf("Open restored: %v", err)
	}
	defer w2.Close()
	if got := w2.FirstLSN(); got != 1 {
		t.Fatalf("FirstLSN = %d", got)
	}
	if got := w2.LastLSN(); got != 10 {
		t.Fatalf("LastLSN = %d", got)
	}
	for i, data := range want {
		rec, err := w2.Read(uint64(i + 1))
		if err != nil {
			t.Fatalf("Read(%d): %v", i+1, err)
		}
		if !bytes.Equal(rec.Data, data) || !bytes.Equal(rec.Key, []byte("k")) {
			t.Fatalf("record %d mismatch", i+1)
		}
	}
	next, err := w2.Append(ctx, Record{Data: []byte("after-restore")})
	if err != nil {
		t.Fatal(err)
	}
	if next != 11 {
		t.Fatalf("next LSN = %d, want 11", next)
	}
}

// TestRestoreRejectsCorruptSegment verifies that a corrupted segment prevents
// the restore from publishing a destination. | 验证损坏分段会阻止恢复发布目标目录。
func TestRestoreRejectsCorruptSegment(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(src, WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("corrupt-me")}); err != nil {
		t.Fatal(err)
	}
	if err := w.BackupNow(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(backupDir, "*.wal"))
	if err != nil || len(files) != 1 {
		t.Fatalf("backup files: %v", err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xFF
	if err := os.WriteFile(files[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := RestoreDir(ctx, backupDir, dst); !errors.Is(err, ErrBackup) {
		t.Fatalf("RestoreDir err = %v, want ErrBackup", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("destination exists after failed restore: %v", err)
	}
}

// TestRestoreRequiresSnapshot verifies that a segment-only backup cannot be
// restored as a complete set. | 验证只有分段的备份不能作为完整恢复集还原。
func TestRestoreRequiresSnapshot(t *testing.T) {
	ctx := context.Background()
	backupDir := t.TempDir()
	if err := RestoreDir(ctx, backupDir, filepath.Join(t.TempDir(), "dst")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RestoreDir err = %v, want ErrNotFound", err)
	}
}

// TestBackupNowRequiresSnapshotTarget verifies that BackupNow refuses a target
// that only implements the segment-level Backup interface. | 验证 BackupNow 拒绝
// 只实现分段级 Backup 接口的目标。
func TestBackupNowRequiresSnapshotTarget(t *testing.T) {
	ctx := context.Background()
	target := BackupFunc("legacy", func(context.Context, SegmentBundle) error { return nil })
	w, err := Open(t.TempDir(), WithBackup(target))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(ctx, Record{Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := w.BackupNow(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("BackupNow err = %v, want ErrUnsupported", err)
	}
}

// TestBackupRestoreEncrypted verifies the encryption policy and KCV survive a
// restore. | 验证加密策略与 KCV 在恢复后仍然有效。
func TestBackupRestoreEncrypted(t *testing.T) {
	ctx := context.Background()
	ring, err := NewKeyRing(1,
		Key{ID: 1, Suite: SuiteAESGCM, Bytes: bytes.Repeat([]byte{7}, 32)},
		Key{ID: 2, Suite: SuiteAESGCM, Bytes: bytes.Repeat([]byte{9}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(src, WithEncryption(ring), WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte("secret")}); err != nil {
		t.Fatal(err)
	}
	if err := w.BackupNow(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := RestoreDir(ctx, backupDir, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dst); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Open without keys err = %v, want ErrKeyNotFound", err)
	}
	wrong, err := NewKeyRing(1, Key{ID: 1, Suite: SuiteAESGCM, Bytes: bytes.Repeat([]byte{8}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dst, WithEncryption(wrong)); !errors.Is(err, ErrAuth) {
		t.Fatalf("Open with wrong key err = %v, want ErrAuth", err)
	}
	w2, err := Open(dst, WithEncryption(ring))
	if err != nil {
		t.Fatalf("Open with keys: %v", err)
	}
	defer w2.Close()
	rec, err := w2.Read(1)
	if err != nil || !bytes.Equal(rec.Data, []byte("secret")) {
		t.Fatalf("Read = %q, %v", rec.Data, err)
	}
}

// TestBackupSnapshotRecordsGaps verifies that an auto-repaired gap is part of
// the backup metadata and restores without an extra flag. | 验证自动修复的缺口
// 进入备份元数据，并在恢复后无需额外旗标。
func TestBackupSnapshotRecordsGaps(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(src,
		WithSegmentMaxBytes(200),
		WithSyncPolicy(SyncNever()),
		WithBackup(DirBackup(backupDir)),
		WithBackupWorkers(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("g"), 100)
	for i := 0; i < 16; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	removeSegmentForTest(t, src, 3)
	_ = os.RemoveAll(filepath.Join(src, "manifest"))
	w, err = Open(src, WithSegmentMaxBytes(200), WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatalf("auto repair: %v", err)
	}
	if err := w.BackupNow(ctx); err != nil {
		t.Fatalf("BackupNow: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	set := backupSetForTest(t, backupDir)
	if len(set.Gaps) == 0 {
		t.Fatal("backup set did not record the accepted gap")
	}
	dst := filepath.Join(t.TempDir(), "restored")
	if err := RestoreDir(ctx, backupDir, dst); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dst, WithAutoRepair(false), WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatalf("strict open of restored gap: %v", err)
	}
	defer w2.Close()
	if got := w2.Stats().RecoveryMissingLSNs; got == 0 {
		t.Fatal("restored gap was not observed")
	}
	if _, err := w2.Read(set.FirstLSN); err != nil {
		t.Fatalf("read first live LSN: %v", err)
	}
}

// TestBackupSetRoundTrip is a unit test for the public snapshot codec. | 公共
// 快照编解码器的单元测试。
func TestBackupSetRoundTrip(t *testing.T) {
	set := BackupSet{
		WalID: [16]byte{1}, CreatedNano: 123, FirstLSN: 1, LastLSN: 20,
		NextLSN: 21, NextSeq: 4, CommitSeq: 3, Serializable: true,
		HashAlgorithm: HashSM3, ActiveKeyID: 1, ActiveKeyKCV: 9, Encrypted: true,
		Segments: []SegmentMeta{
			{Seq: 1, BaseLSN: 1, LastLSN: 10, Bytes: 100, SegmentCRC: 1, WalID: [16]byte{1}},
			{Seq: 2, BaseLSN: 11, LastLSN: 20, Bytes: 100, SegmentCRC: 2, WalID: [16]byte{1}},
		},
		Gaps: []BackupGap{{Start: 5, End: 5}},
	}
	data, err := EncodeBackupSet(set)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBackupSet(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.WalID != set.WalID || got.FirstLSN != set.FirstLSN || got.LastLSN != set.LastLSN ||
		got.NextLSN != set.NextLSN || got.NextSeq != set.NextSeq || got.CommitSeq != set.CommitSeq ||
		!got.Serializable || !got.Encrypted || got.HashAlgorithm != HashSM3 ||
		got.ActiveKeyID != set.ActiveKeyID || got.ActiveKeyKCV != set.ActiveKeyKCV ||
		len(got.Segments) != 2 || len(got.Gaps) != 1 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// TestConcurrentBackupNowPublishesValidSnapshot runs two snapshots at once and
// verifies the published BACKUP.snap is intact and restore-complete. |
// 并发执行两次快照，验证发布的 BACKUP.snap 完整且可恢复。
func TestConcurrentBackupNowPublishesValidSnapshot(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(src, WithBackup(DirBackup(backupDir)), WithBackupWorkers(2))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 4; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte{'k', byte('0' + i)}, Data: bytes.Repeat([]byte{byte('a' + i)}, 64)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errsCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errsCh <- w.BackupNow(ctx)
		}()
	}
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		if err != nil {
			t.Fatalf("BackupNow: %v", err)
		}
	}
	set := backupSetForTest(t, backupDir)
	if set.LastLSN != 4 || set.NextLSN != 5 {
		t.Fatalf("snapshot LSN range [%d,%d) is invalid", set.FirstLSN, set.NextLSN)
	}
	restore := filepath.Join(t.TempDir(), "restored")
	if err := RestoreDir(ctx, backupDir, restore); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(restore)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if got := w2.LastLSN(); got != 4 {
		t.Fatalf("restored LastLSN = %d, want 4", got)
	}
	for lsn := uint64(1); lsn <= 4; lsn++ {
		if _, err := w2.Read(lsn); err != nil {
			t.Fatalf("read restored LSN %d: %v", lsn, err)
		}
	}
}
