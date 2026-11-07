package wal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestTruncateFlushesPendingSync(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte('a' + i)}}); err != nil {
			t.Fatal(err)
		}
	}
	before := w.Stats().Syncs
	if _, err := w.Truncate(2); err != nil {
		t.Fatal(err)
	}
	if got := w.Stats().Syncs; got <= before {
		t.Fatalf("Truncate did not flush pending data: syncs %d -> %d", before, got)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if got := w2.LastLSN(); got != 3 {
		t.Fatalf("LastLSN=%d, want 3", got)
	}
}

func TestFollowReaderDoesNotMissConcurrentCommit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := w.NewReader(Follow())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	const n = 200
	go func() {
		for i := 0; i < n; i++ {
			if _, err := w.Append(ctx, Record{Data: []byte("x")}); err != nil {
				return
			}
			runtime.Gosched()
		}
	}()
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for i := uint64(1); i <= n; i++ {
		rec, err := r.NextContext(deadline)
		if err != nil {
			t.Fatalf("Next %d: %v", i, err)
		}
		if rec.LSN != i {
			t.Fatalf("LSN=%d, want %d", rec.LSN, i)
		}
	}
}

func TestBenignSetActiveKeyErrorDoesNotPoison(t *testing.T) {
	dir := t.TempDir()
	ring, err := NewKeyRing(1, Key{ID: 1, Suite: SuiteAESGCM, Bytes: testAESKey(0x51)})
	if err != nil {
		t.Fatal(err)
	}
	w, err := Open(dir, WithEncryption(ring))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ctx := context.Background()
	if _, err := w.Append(ctx, Record{Data: []byte("before")}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetActiveKey(0); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("SetActiveKey(0) err=%v, want ErrInvalidKey", err)
	}
	if err := w.SetActiveKey(99); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("SetActiveKey(99) err=%v, want ErrKeyNotFound", err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("after")}); err != nil {
		t.Fatalf("WAL was poisoned by a caller-input error: %v", err)
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync after benign error: %v", err)
	}
}

func TestBatchValidationIsolation(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithMaxRecordBytes(128), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.ensureActive(); err != nil {
		t.Fatal(err)
	}
	good := w.acquireRequest(kindData)
	good.one[0] = Record{Data: []byte("ok")}
	good.recs = good.one[:1]
	bad := w.acquireRequest(kindData)
	bad.one[0] = Record{Data: bytes.Repeat([]byte("x"), 200)}
	bad.recs = bad.one[:1]
	w.commitBatch([]*appendRequest{good, bad})
	resGood := <-good.done
	resBad := <-bad.done
	w.releaseRequest(good)
	w.releaseRequest(bad)
	if resGood.err != nil || resGood.lsn != 1 {
		t.Fatalf("valid request failed: lsn=%d err=%v", resGood.lsn, resGood.err)
	}
	if !errors.Is(resBad.err, ErrRecordTooLarge) {
		t.Fatalf("invalid request err=%v, want ErrRecordTooLarge", resBad.err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if rec, err := w2.Read(1); err != nil || string(rec.Data) != "ok" {
		t.Fatalf("read committed valid record: %q/%v", rec.Data, err)
	}
}

func TestStreamChunkClamp(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithMaxRecordBytes(512))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("s"), 2000)
	info, err := w.AppendStream(ctx, bytes.NewReader(payload), StreamChunkSize(1<<20))
	if err != nil {
		t.Fatalf("AppendStream: %v", err)
	}
	sr, err := w.NewStreamReader(info)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(sr)
	_ = sr.Close()
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("stream payload mismatch: %d vs %d", len(got), len(payload))
	}

	tx, err := w.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txInfo, err := tx.AppendStream(ctx, bytes.NewReader(payload), StreamChunkSize(1<<30))
	if err != nil {
		t.Fatalf("Tx.AppendStream: %v", err)
	}
	if _, err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx stream: %v", err)
	}
	sr2, err := w.NewStreamReader(txInfo)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(sr2)
	_ = sr2.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("tx stream mismatch: err=%v len=%d", err, len(got))
	}

	tooSmall, err := Open(t.TempDir(), WithMaxRecordBytes(recordHeaderSizeEncrypted+aeadTagSize+1))
	if err != nil {
		t.Fatal(err)
	}
	defer tooSmall.Close()
	if _, err := tooSmall.AppendStream(ctx, bytes.NewReader([]byte("x"))); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("stream with too-small max record err=%v, want ErrInvalidOptions", err)
	}
}

func TestDrainBatchCountsRecords(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithMaxBatchRecords(5), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(n int) *appendRequest {
		req := &appendRequest{kind: kindData, done: make(chan appendResult, 1)}
		for i := 0; i < n; i++ {
			req.recs = append(req.recs, Record{Data: []byte("x")})
		}
		return req
	}
	first := mk(3)
	second := mk(3)
	w.appendQ <- second
	batch, deferred := w.drainBatch(first)
	if len(batch) != 1 || deferred != second {
		t.Fatalf("drainBatch accepted %d requests (deferred=%v), want the second deferred", len(batch), deferred != nil)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupItemsReleased(t *testing.T) {
	dir := t.TempDir()
	backupDir := t.TempDir()
	w, err := Open(dir, WithBackup(DirBackup(backupDir)), WithBackupWorkers(1))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := w.Append(ctx, Record{Data: []byte("backup")}); err != nil {
		t.Fatal(err)
	}
	if err := w.BackupNow(ctx); err != nil {
		t.Fatal(err)
	}
	w.backupMu.Lock()
	n := len(w.backupItems)
	w.backupMu.Unlock()
	if n != 0 {
		t.Fatalf("%d completed backup items retained in memory", n)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyOpensReadOnlySegment(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	w, err := Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("readonly")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dst := copyWALDirForTest(t, src)
	// Force a directory scan and the last-segment open path. | 强制目录扫描与
	// 最后分段打开路径。
	_ = os.RemoveAll(filepath.Join(dst, "manifest"))
	entries, _ := os.ReadDir(dst)
	segPath := ""
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".idx" {
			_ = os.Remove(filepath.Join(dst, e.Name()))
		}
		if filepath.Ext(e.Name()) == ".wal" {
			segPath = filepath.Join(dst, e.Name())
		}
	}
	if segPath == "" {
		t.Fatal("no segment")
	}
	if err := os.Chmod(segPath, 0o444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(segPath, 0o600)
	ro, err := Open(dst, WithReadOnly(true), WithNoLock(true))
	if err != nil {
		t.Fatalf("read-only open with 0444 segment: %v", err)
	}
	defer ro.Close()
	rec, err := ro.Read(1)
	if err != nil || string(rec.Data) != "readonly" {
		t.Fatalf("read-only read: %q/%v", rec.Data, err)
	}
}

type metaRecorder struct {
	mu sync.Mutex
	m  map[uint64]RecordMeta
}

func (r *metaRecorder) Index(meta RecordMeta, _, _ []byte) {
	r.mu.Lock()
	r.m[meta.LSN] = meta
	r.mu.Unlock()
}

func TestStreamIndexerNormalizedTimestamp(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rec := &metaRecorder{m: make(map[uint64]RecordMeta)}
	w, err := Open(dir, WithIndexer(rec))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	info, err := w.AppendStream(ctx, bytes.NewReader(bytes.Repeat([]byte("z"), 300)), StreamChunkSize(100))
	if err != nil {
		t.Fatal(err)
	}
	for lsn := info.FirstLSN; lsn <= info.LastLSN; lsn++ {
		rec2, err := w.Read(lsn)
		if err != nil {
			t.Fatal(err)
		}
		rec.mu.Lock()
		meta := rec.m[lsn]
		rec.mu.Unlock()
		if meta.LSN == 0 || meta.Timestamp == 0 || meta.Timestamp != rec2.Timestamp {
			t.Fatalf("lsn %d indexed timestamp=%d, record timestamp=%d", lsn, meta.Timestamp, rec2.Timestamp)
		}
	}
}

func TestMissingLastSegmentBoundary(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	w, err := Open(src)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte('a' + i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	removeLastWALForTest(t, src)
	if _, err := Open(copyWALDirForTest(t, src)); !errors.Is(err, ErrMissingSegment) {
		t.Fatalf("missing last segment without allow err=%v, want ErrMissingSegment", err)
	}
	dir := copyWALDirForTest(t, src)
	ro, err := Open(dir, WithAllowLSNGaps(true))
	if err != nil {
		t.Fatalf("missing last segment with allow: %v", err)
	}
	lsn, err := ro.Append(ctx, Record{Data: []byte("next")})
	if err != nil {
		t.Fatal(err)
	}
	if lsn != 4 {
		t.Fatalf("next LSN=%d, want 4 (never reuse the lost segment's LSN range)", lsn)
	}
	if _, err := ro.Read(1); !errors.Is(err, ErrMissingSegment) {
		t.Fatalf("read lost segment err=%v, want ErrMissingSegment", err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
}

func removeLastWALForTest(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".wal" {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSerializableConflictCountedOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSerializableDurability(true), WithDefaultIsolation(IsolationSerializable))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	txA, _ := w.Begin(ctx)
	_ = txA.WriteKey([]byte("k"))
	if _, err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	txB, _ := w.Begin(ctx)
	_ = txB.ReadKey([]byte("k"))
	txC, _ := w.Begin(ctx)
	_ = txC.WriteKey([]byte("k"))
	if _, err := txC.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := txB.Commit(ctx); !errors.Is(err, ErrTxnConflict) {
		t.Fatalf("commit err=%v, want ErrTxnConflict", err)
	}
	if got := w.Stats().TxnConflicts; got != 1 {
		t.Fatalf("TxnConflicts=%d, want 1", got)
	}
}
