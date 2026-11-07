package wal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// openBufferedWAL opens a NoSync WAL whose appends collect in the userspace
// write buffer. | openBufferedWAL 打开一个 NoSync WAL，其追加先收集在用户态写缓冲中。
func openBufferedWAL(t *testing.T, opts ...Option) (*WAL, string) {
	t.Helper()
	dir := t.TempDir()
	base := []Option{
		WithSyncPolicy(SyncNever()),
		WithSyncOnRotate(false),
		WithWriteBuffer(64 << 10),
	}
	w, err := Open(dir, append(base, opts...)...)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, dir
}

// readAllLSNs scans every committed record through a fresh Reader. | readAllLSNs
// 通过新的 Reader 扫描全部已提交记录。
func readAllLSNs(t *testing.T, w *WAL) []uint64 {
	t.Helper()
	r, err := w.NewReader(From(0))
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	defer r.Close()
	var lsns []uint64
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		lsns = append(lsns, rec.LSN)
	}
	return lsns
}

// TestWriteBufferReaderSeesBufferedRecords verifies that opening a reader
// flushes buffered appends and that appends made while the reader exists bypass
// the buffer. | TestWriteBufferReaderSeesBufferedRecords 验证打开读取器会刷新缓冲的
// 追加，且读取器存在期间的追加绕过缓冲区。
func TestWriteBufferReaderSeesBufferedRecords(t *testing.T) {
	w, _ := openBufferedWAL(t)
	defer w.Close()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte{byte('a' + i)}}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	r, err := w.NewReader(From(0))
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	var got []uint64
	for {
		rec, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, rec.LSN)
	}
	if len(got) != 3 {
		t.Fatalf("reader saw %v, want 3 records", got)
	}
	// While the reader is open, appends must be written through so continuing
	// reads observe them. | 读取器打开期间的追加必须直接写出，使后续读取可见。
	if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte("later")}); err != nil {
		t.Fatalf("append while reading: %v", err)
	}
	rec, err := r.Next()
	if err != nil {
		t.Fatalf("next while reading: %v", err)
	}
	if !bytes.Equal(rec.Data, []byte("later")) {
		t.Fatalf("record while reading = %q", rec.Data)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("reader close: %v", err)
	}
	if got := readAllLSNs(t, w); len(got) != 4 {
		t.Fatalf("scan after reader close = %v, want 4 records", got)
	}
}

// TestWriteBufferCloseFlushes verifies that buffered appends survive a clean
// close and recovery. | TestWriteBufferCloseFlushes 验证缓冲追加在正常关闭与恢复后
// 仍然存在。
func TestWriteBufferCloseFlushes(t *testing.T) {
	w, dir := openBufferedWAL(t)
	ctx := context.Background()
	const n = 100
	for i := 0; i < n; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte{byte(i)}}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if got := w2.LastLSN(); got != n {
		t.Fatalf("recovered LastLSN=%d, want %d", got, n)
	}
	if got := readAllLSNs(t, w2); len(got) != n {
		t.Fatalf("recovered %d records, want %d", len(got), n)
	}
}

// TestWriteBufferRotationFlushes verifies that a buffered batch is flushed
// before the active segment seals. | TestWriteBufferRotationFlushes 验证缓冲批次在
// 活动段封存前被刷新。
func TestWriteBufferRotationFlushes(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 2048)
	w, dir := openBufferedWAL(t, WithSegmentMaxBytes(16<<10))
	ctx := context.Background()
	const n = 64
	for i := 0; i < n; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if got := w.Stats().Segments; got < 2 {
		t.Fatalf("expected rotation, got %d segments", got)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if got := readAllLSNs(t, w2); len(got) != n {
		t.Fatalf("recovered %d records, want %d", len(got), n)
	}
}

// TestWriteBufferSyncFlushes verifies that an explicit Sync flushes buffered
// bytes before synchronizing. | TestWriteBufferSyncFlushes 验证显式 Sync 在同步前
// 刷新缓冲字节。
func TestWriteBufferSyncFlushes(t *testing.T) {
	w, dir := openBufferedWAL(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte(i)}}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if len(w.writeBuf) == 0 {
		t.Fatal("appends were not buffered")
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(w.writeBuf) != 0 {
		t.Fatalf("write buffer still holds %d bytes after Sync", len(w.writeBuf))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if got := w2.LastLSN(); got != 5 {
		t.Fatalf("recovered LastLSN=%d, want 5", got)
	}
}
