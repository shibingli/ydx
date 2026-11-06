package wal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDedupResolveAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	data := bytes.Repeat([]byte("dedup-data-"), 64)
	lsn1, err := w.Append(ctx, Record{Key: []byte("k"), Data: data})
	if err != nil {
		t.Fatalf("append1: %v", err)
	}
	lsn2, err := w.Append(ctx, Record{Key: []byte("k"), Data: data})
	if err != nil {
		t.Fatalf("append2: %v", err)
	}
	if lsn2 != lsn1+1 {
		t.Fatalf("lsn2=%d", lsn2)
	}
	if got := w.Stats().DedupRefs; got == 0 {
		t.Fatalf("expected a dedup reference, stats=%+v", w.Stats())
	}
	rec, err := w.Read(lsn2)
	if err != nil {
		t.Fatalf("read ref: %v", err)
	}
	if !bytes.Equal(rec.Data, data) {
		t.Fatalf("dedup data mismatch")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir, WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	rec, err = w2.Read(lsn2)
	if err != nil {
		t.Fatalf("reopen read ref: %v", err)
	}
	if !bytes.Equal(rec.Data, data) {
		t.Fatalf("reopen dedup data mismatch")
	}
}

func TestRotationAndReopen(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(128))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	payload := bytes.Repeat([]byte("x"), 100)
	for i := 0; i < 5; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if got := w.Stats().Segments; got < 2 {
		t.Fatalf("segments=%d, want at least 2", got)
	}
	for i := uint64(1); i <= 5; i++ {
		rec, err := w.Read(i)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(rec.Data, payload) {
			t.Fatalf("read %d data mismatch", i)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir, WithSegmentMaxBytes(128))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	for i := uint64(1); i <= 5; i++ {
		if _, err := w2.Read(i); err != nil {
			t.Fatalf("reopen read %d: %v", i, err)
		}
	}
}

func TestFollowReader(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	r, err := w.NewReader(Follow())
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	defer r.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Append(context.Background(), Record{Data: []byte("live")})
		_ = w.Close()
	}()
	rec, err := r.NextContext(context.Background())
	if err != nil {
		t.Fatalf("follow next: %v", err)
	}
	if string(rec.Data) != "live" {
		t.Fatalf("follow data=%q", rec.Data)
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("follow end err=%v, want EOF", err)
	}
	<-done
}

func TestBackupRotateAndFlush(t *testing.T) {
	dir := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(dir, WithBackup(DirBackup(backupDir)), WithBackupWorkers(2))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	ctx := context.Background()
	if _, err := w.Append(ctx, Record{Data: []byte("backup-me")}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := w.FlushBackups(ctx); err != nil {
		t.Fatalf("flush backups: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var backed bool
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".bak" {
			backed = true
		}
	}
	if !backed {
		t.Fatal("expected a .bak marker")
	}
	if entries, err := os.ReadDir(backupDir); err != nil || len(entries) == 0 {
		t.Fatalf("backup dir empty: %v", err)
	}
}

func TestSerializableConflict(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithSerializableDurability(true), WithDefaultIsolation(IsolationSerializable))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	ctx := context.Background()
	txA, err := w.Begin(ctx)
	if err != nil {
		t.Fatalf("begin a: %v", err)
	}
	if err := txA.WriteKey([]byte("k")); err != nil {
		t.Fatalf("write key a: %v", err)
	}
	if _, err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit a: %v", err)
	}
	txB, err := w.Begin(ctx)
	if err != nil {
		t.Fatalf("begin b: %v", err)
	}
	if err := txB.ReadKey([]byte("k")); err != nil {
		t.Fatalf("read key b: %v", err)
	}
	txC, err := w.Begin(ctx)
	if err != nil {
		t.Fatalf("begin c: %v", err)
	}
	if err := txC.WriteKey([]byte("k")); err != nil {
		t.Fatalf("write key c: %v", err)
	}
	if _, err := txC.Commit(ctx); err != nil {
		t.Fatalf("commit c: %v", err)
	}
	if _, err := txB.Commit(ctx); !errors.Is(err, ErrTxnConflict) {
		t.Fatalf("commit b err=%v, want ErrTxnConflict", err)
	}
}

func TestTruncateAllAndReopen(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte(i)}}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if _, err := w.Truncate(4); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if got := w.FirstLSN(); got != 4 {
		t.Fatalf("FirstLSN=%d, want 4", got)
	}
	if _, err := w.Read(1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read truncated err=%v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if got := w2.FirstLSN(); got != 4 {
		t.Fatalf("reopened FirstLSN=%d, want 4", got)
	}
	if got := w2.LastLSN(); got != 3 {
		t.Fatalf("reopened LastLSN=%d, want 3", got)
	}
	lsn, err := w2.Append(ctx, Record{Data: []byte("new")})
	if err != nil {
		t.Fatalf("append after truncate: %v", err)
	}
	if lsn != 4 {
		t.Fatalf("append after truncate lsn=%d, want 4", lsn)
	}
}

func TestTornTailTruncatedOnOpen(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Data: bytes.Repeat([]byte("x"), 32)}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Remove the sidecar and manifest so Open must scan, then append a torn tail. | 删除侧车与 MANIFEST 以强制扫描，再追加撕裂尾部。
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		switch filepath.Ext(e.Name()) {
		case ".idx":
			_ = os.Remove(filepath.Join(dir, e.Name()))
		case ".wal":
			f, err := os.OpenFile(filepath.Join(dir, e.Name()), os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatalf("open wal: %v", err)
			}
			_, _ = f.Write(bytes.Repeat([]byte{0xFF}, 37))
			_ = f.Close()
		}
	}
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen with torn tail: %v", err)
	}
	defer w2.Close()
	for i := uint64(1); i <= 3; i++ {
		if _, err := w2.Read(i); err != nil {
			t.Fatalf("read %d after truncation: %v", i, err)
		}
	}
}
