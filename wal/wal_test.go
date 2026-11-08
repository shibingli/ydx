package wal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// TestStreamReaderRequiresEndRecord verifies that a StreamInfo claiming to be
// complete cannot hide a missing FlagStreamEnd record: reaching the readable
// range end without observing it returns ErrStreamIncomplete. | 验证声称完整但
// 缺少 FlagStreamEnd 记录的 StreamInfo 不能掩盖缺失的结束记录：到达可读区间末尾
// 仍未观察到它时必须返回 ErrStreamIncomplete。
func TestStreamReaderRequiresEndRecord(t *testing.T) {
	ctx := context.Background()
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	id, err := newStreamID()
	if err != nil {
		t.Fatal(err)
	}
	first, err := w.appendStreamRecord(ctx, Record{Flags: FlagStreamChunk, Key: id[:], Data: []byte("abc")})
	if err != nil {
		t.Fatal(err)
	}
	last, err := w.appendStreamRecord(ctx, Record{Flags: FlagStreamChunk, Key: id[:], Data: []byte("def")})
	if err != nil {
		t.Fatal(err)
	}
	info := StreamInfo{ID: id, FirstLSN: first, LastLSN: last, Chunks: 2, Bytes: 6, Complete: true}
	sr, err := w.NewStreamReader(info)
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Close()
	got, err := io.ReadAll(sr)
	if !errors.Is(err, ErrStreamIncomplete) {
		t.Fatalf("ReadAll err = %v, want ErrStreamIncomplete", err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("ReadAll data = %q, want %q", got, "abcdef")
	}
}

func TestAppendReadCloseReopen(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		lsn, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte{byte('a' + i)}})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if lsn != uint64(i+1) {
			t.Fatalf("append %d lsn=%d, want %d", i, lsn, i+1)
		}
	}
	if got := w.LastLSN(); got != 3 {
		t.Fatalf("LastLSN=%d, want 3", got)
	}
	rec, err := w.Read(2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(rec.Key, []byte("k")) || !bytes.Equal(rec.Data, []byte("b")) {
		t.Fatalf("read record = %q/%q", rec.Key, rec.Data)
	}
	var seen int
	if err := w.Scan(ctx, 0, 0, func(r Record) error {
		seen++
		if r.LSN != uint64(seen) {
			t.Fatalf("scan lsn %d at %d", r.LSN, seen)
		}
		return nil
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if seen != 3 {
		t.Fatalf("scan seen=%d", seen)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if got := w2.FirstLSN(); got != 1 {
		t.Fatalf("FirstLSN=%d, want 1", got)
	}
	if got := w2.LastLSN(); got != 3 {
		t.Fatalf("reopened LastLSN=%d, want 3", got)
	}
	rec, err = w2.Read(3)
	if err != nil {
		t.Fatalf("reopen read: %v", err)
	}
	if !bytes.Equal(rec.Data, []byte("c")) {
		t.Fatalf("reopen read data=%q", rec.Data)
	}
	lsn, err := w2.Append(ctx, Record{Data: []byte("d")})
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if lsn != 4 {
		t.Fatalf("append after reopen lsn=%d, want 4", lsn)
	}
	if err := w2.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestAppendBatchAndAppendOnce(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithIdempotency(IdempotencyOptions{}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	ctx := context.Background()
	last, err := w.AppendBatch(ctx, []Record{{Data: []byte("1")}, {Data: []byte("2")}, {Data: []byte("3")}})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if last != 3 {
		t.Fatalf("batch last=%d, want 3", last)
	}
	lsn, dup, err := w.AppendOnce(ctx, []byte("id-1"), Record{Data: []byte("once")})
	if err != nil || dup || lsn != 4 {
		t.Fatalf("append once lsn=%d dup=%v err=%v", lsn, dup, err)
	}
	lsn2, dup2, err := w.AppendOnce(ctx, []byte("id-1"), Record{Data: []byte("once")})
	if err != nil || !dup2 || lsn2 != 4 {
		t.Fatalf("append once duplicate lsn=%d dup=%v err=%v", lsn2, dup2, err)
	}
	if _, _, err := w.AppendOnce(ctx, []byte("id-1"), Record{Data: []byte("other")}); err == nil {
		t.Fatal("expected idempotency conflict")
	}
	var count int
	if err := w.Scan(ctx, 0, 0, func(Record) error { count++; return nil }); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count != 4 {
		t.Fatalf("scan count=%d, want 4", count)
	}
}

func TestTransactionCommit(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, WithSerializableDurability(true))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	ctx := context.Background()
	tx, err := w.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.Append(ctx, Record{Key: []byte("a"), Data: []byte("1")}); err != nil {
		t.Fatalf("tx append: %v", err)
	}
	if err := tx.WriteKey([]byte("a")); err != nil {
		t.Fatalf("write key: %v", err)
	}
	info, err := tx.Commit(ctx)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if info.FirstLSN != 1 || info.LastLSN != 1 || info.CommitSeq == 0 {
		t.Fatalf("info = %+v", info)
	}
	if got := w.LastLSN(); got != 1 {
		t.Fatalf("LastLSN=%d", got)
	}
}

func TestEncryptionAndCompression(t *testing.T) {
	dir := t.TempDir()
	ring, err := NewKeyRing(7, Key{ID: 7, Suite: SuiteAESGCM, Bytes: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	comp := Compression{Active: 1, Codecs: []Codec{FlateCodec(6)}, MinBytes: 1}
	w, err := Open(dir, WithEncryption(ring), WithCompression(comp))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	data := bytes.Repeat([]byte("compressible-"), 200)
	lsn, err := w.Append(ctx, Record{Key: []byte("secret"), Data: data})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	rec, err := w.Read(lsn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(rec.Key, []byte("secret")) || !bytes.Equal(rec.Data, data) {
		t.Fatalf("round trip mismatch")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	w2, err := Open(dir, WithEncryption(ring), WithCompression(comp))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	rec, err = w2.Read(lsn)
	if err != nil {
		t.Fatalf("reopen read: %v", err)
	}
	if !bytes.Equal(rec.Data, data) {
		t.Fatalf("reopen data mismatch")
	}
}

func TestStreamRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer w.Close()
	ctx := context.Background()
	payload := bytes.Repeat([]byte("stream-"), 10000)
	info, err := w.AppendStream(ctx, bytes.NewReader(payload), StreamChunkSize(1024))
	if err != nil {
		t.Fatalf("append stream: %v", err)
	}
	if !info.Complete || info.Bytes != uint64(len(payload)) {
		t.Fatalf("info = %+v", info)
	}
	sr, err := w.NewStreamReader(info)
	if err != nil {
		t.Fatalf("stream reader: %v", err)
	}
	defer sr.Close()
	got, err := io.ReadAll(sr)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("stream payload mismatch: got %d want %d", len(got), len(payload))
	}
}
