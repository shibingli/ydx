package wal

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// TestBackupMarkerWithoutTargetIsReuploaded verifies that a durable .bak marker
// whose target object has disappeared does not suppress the upload forever: the
// worker re-uploads the segment instead of retrying verification. | 验证目标对象
// 已消失的 .bak 标记不会永久阻止上传：worker 会重新上传分段，而不是一直重试校验。
func TestBackupMarkerWithoutTargetIsReuploaded(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(src, WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: bytes.Repeat([]byte("r"), 100)}); err != nil {
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
	want, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	// Delete only the target object; the durable marker in the source directory
	// stays valid and names the now-missing object. | 只删除目标对象；源目录中的
	// 持久标记仍然有效，并指向已不存在的对象。
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(src, WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if err := w2.FlushBackups(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("backup target was not re-uploaded: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("re-uploaded backup differs from the source segment")
	}
}

// TestTruncateCancelsPendingBackups verifies that segments retired by truncation
// while another upload is in flight leave the backup queue without being
// uploaded again, without retries, failures, or ErrorHandler reports. | 验证
// 上传阻塞期间被截断退休的分段立即离开备份队列，不再上传、不重试、不计失败、
// 不调用 ErrorHandler。
func TestTruncateCancelsPendingBackups(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	// Seed a valid META so Open does not report the documented empty-WAL
	// initialization through the ErrorHandler. | 先写入有效 META，避免 Open 通过
	// ErrorHandler 报告文档规定的空 WAL 初始化。
	seed, err := Open(src, WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()), WithManifest(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls, reported atomic.Int32
	backup := BackupFunc("blocking", func(context.Context, SegmentBundle) error {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	w, err := Open(src,
		WithSegmentMaxBytes(200),
		WithSyncPolicy(SyncNever()),
		WithManifest(false),
		WithBackup(backup),
		WithBackupWorkers(1),
		WithErrorHandler(func(err error) {
			reported.Add(1)
			t.Logf("async error: %v", err)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("t"), 100)
	for i := 0; i < 8; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("backup worker did not start")
	}
	// Seal more segments behind the blocked upload, then retire all sealed
	// segments with one truncation. | 在阻塞的上传之后继续封段，然后用一次截断
	// 退休全部封段。
	for i := 0; i < 8; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Truncate(w.LastLSN() + 1); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	close(release)
	if err := w.FlushBackups(ctx); err != nil {
		t.Fatalf("FlushBackups: %v", err)
	}
	if err := w.FlushCleanup(ctx); err != nil {
		t.Fatalf("FlushCleanup: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("backup callbacks = %d, want 1 (deleted segments must not be uploaded)", got)
	}
	if got := w.Stats().BackupFailed; got != 0 {
		t.Fatalf("BackupFailed = %d, want 0", got)
	}
	if got := reported.Load(); got != 0 {
		t.Fatalf("ErrorHandler calls = %d, want 0", got)
	}
}

// TestBackupReceivesWholeSegment verifies that the Backup callback receives the
// whole segment from offset zero, including the 64-byte header, even though
// identity validation performs a positional read on the same handle. | 验证
// Backup 回调从第 0 字节收到完整分段（含 64 字节段头），即使身份校验在同一
// 句柄上执行位置读。
func TestBackupReceivesWholeSegment(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	type upload struct {
		data []byte
		meta SegmentMeta
	}
	var mu sync.Mutex
	uploads := make(map[uint64]upload)
	backup := BackupFunc("whole", func(_ context.Context, bundle SegmentBundle) error {
		data, err := io.ReadAll(bundle.Data)
		if err != nil {
			return err
		}
		mu.Lock()
		uploads[bundle.Meta.Seq] = upload{data: data, meta: bundle.Meta}
		mu.Unlock()
		return nil
	})
	w, err := Open(src,
		WithSegmentMaxBytes(200),
		WithSyncPolicy(SyncNever()),
		WithBackup(backup),
		WithBackupWorkers(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 6; i++ {
		if _, err := w.Append(ctx, Record{Data: bytes.Repeat([]byte{byte('a' + i)}, 100)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := w.FlushBackups(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(uploads) == 0 {
		t.Fatal("no segment was uploaded")
	}
	for seq, up := range uploads {
		want, err := os.ReadFile(segmentPath(src, seq))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(up.data, want) {
			t.Fatalf("segment %d upload has %d bytes, want %d bytes from offset 0", seq, len(up.data), len(want))
		}
		if up.meta.Bytes != uint64(len(want)) {
			t.Fatalf("segment %d meta.Bytes = %d, want %d", seq, up.meta.Bytes, len(want))
		}
		if _, err := decodeSegmentHeader(up.data[:segmentHeaderSize]); err != nil {
			t.Fatalf("segment %d upload has no valid header: %v", seq, err)
		}
	}
}
