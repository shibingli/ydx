package wal

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestDedupSplitCollision verifies that two records whose key||data
// concatenations match but whose field split differs are both stored and
// readable, instead of the second becoming an unresolvable dedup reference. |
// 验证 key||data 拼接相同但字段切分不同的两条记录都能写入并读取，而不是第二条
// 变成无法解析的去重引用。
func TestDedupSplitCollision(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("X"), 49)
	lsn1, err := w.Append(ctx, Record{Key: []byte("a"), Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	lsn2, err := w.Append(ctx, Record{Key: []byte("aX"), Data: payload[:48]})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		lsn  uint64
		key  []byte
		data []byte
	}{{lsn1, []byte("a"), payload}, {lsn2, []byte("aX"), payload[:48]}} {
		rec, err := w.Read(tc.lsn)
		if err != nil {
			t.Fatalf("read %d: %v", tc.lsn, err)
		}
		if !bytes.Equal(rec.Key, tc.key) || !bytes.Equal(rec.Data, tc.data) {
			t.Fatalf("read %d returned a different split", tc.lsn)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if rec, err := w2.Read(lsn2); err != nil || !bytes.Equal(rec.Data, payload[:48]) {
		t.Fatalf("reopened read %d: %v", lsn2, err)
	}
}

// TestAppendOnceSplitCollision verifies that the in-memory idempotency
// comparison frames field lengths, so a different key/data split is a content
// conflict rather than a silent duplicate. | 验证内存幂等比较对字段长度做框架，
// 不同 key/data 切分是内容冲突而不是静默重复。
func TestAppendOnceSplitCollision(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithIdempotency(IdempotencyOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	payload := bytes.Repeat([]byte("Y"), 49)
	if _, _, err := w.AppendOnce(ctx, []byte("id"), Record{Key: []byte("a"), Data: payload}); err != nil {
		t.Fatal(err)
	}
	if _, dup, err := w.AppendOnce(ctx, []byte("id"), Record{Key: []byte("aY"), Data: payload[:48]}); !errors.Is(err, ErrIdempotencyConflict) || dup {
		t.Fatalf("split-colliding AppendOnce dup=%v err=%v, want ErrIdempotencyConflict", dup, err)
	}
}

// TestDedupWithTransactionRecords verifies the v1 rule that transaction
// records are never dedup references themselves, while a later non-transaction
// record may reference a committed transaction record. | 验证 v1 规则：事务记录
// 本身不作为去重引用，但之后的非事务记录可以引用已提交的事务记录。
func TestDedupWithTransactionRecords(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("dedup-txn-"), 64)
	commit := func() uint64 {
		tx, err := w.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Append(ctx, Record{Key: []byte("k"), Data: data}); err != nil {
			t.Fatal(err)
		}
		info, err := tx.Commit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return info.LastLSN
	}
	first := commit()
	second := commit()
	if first == second {
		t.Fatalf("both transactions committed at LSN %d", first)
	}
	if got := w.Stats().DedupRefs; got != 0 {
		t.Fatalf("transaction records wrote %d dedup references; the v1 format forbids them", got)
	}
	// A later non-transaction record can reference a committed transaction
	// record, because the reference itself has txnID 0. | 之后的非事务记录可以
	// 引用已提交的事务记录，因为引用记录本身 txnID 为 0。
	third, err := w.Append(ctx, Record{Key: []byte("k"), Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if got := w.Stats().DedupRefs; got == 0 {
		t.Fatalf("expected a dedup reference outside transactions, stats=%+v", w.Stats())
	}
	for _, lsn := range []uint64{first, second, third} {
		rec, err := w.Read(lsn)
		if err != nil {
			t.Fatalf("read %d: %v", lsn, err)
		}
		if !bytes.Equal(rec.Data, data) {
			t.Fatalf("read %d data mismatch", lsn)
		}
	}
	if err := w.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	for _, lsn := range []uint64{first, second, third} {
		rec, err := w2.Read(lsn)
		if err != nil || !bytes.Equal(rec.Data, data) {
			t.Fatalf("reopened read %d: %v", lsn, err)
		}
	}
	var count int
	if err := w2.Scan(ctx, first, third, func(Record) error { count++; return nil }); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count != 3 {
		t.Fatalf("scan count = %d, want 3", count)
	}
}
