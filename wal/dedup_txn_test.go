package wal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
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

// TestTxAppendBatchTooLargeIsAtomic verifies that a batch rejected by
// TxnMaxBytes or TxnMaxRecords leaves the transaction buffer exactly as it was,
// so a later Commit cannot persist a partial prefix. | 验证因 TxnMaxBytes 或
// TxnMaxRecords 被拒的批不会改变事务缓冲，后续 Commit 不会写入部分前缀。
func TestTxAppendBatchTooLargeIsAtomic(t *testing.T) {
	ctx := context.Background()
	t.Run("Bytes", func(t *testing.T) {
		w, err := Open(t.TempDir(), WithTxnMaxBytes(200))
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		tx, err := w.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Append(ctx, Record{Data: []byte("a")}); err != nil {
			t.Fatal(err)
		}
		beforeBytes, beforeRecords := tx.bytes, len(tx.records)
		if err := tx.AppendBatch(ctx, []Record{{Data: []byte("b")}, {Data: []byte("c")}}); !errors.Is(err, ErrTxnTooLarge) {
			t.Fatalf("AppendBatch err = %v, want ErrTxnTooLarge", err)
		}
		if tx.bytes != beforeBytes || len(tx.records) != beforeRecords {
			t.Fatalf("rejected batch mutated buffer: bytes %d->%d records %d->%d",
				beforeBytes, tx.bytes, beforeRecords, len(tx.records))
		}
		info, err := tx.Commit(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.Records != 1 || info.LastLSN != 1 {
			t.Fatalf("commit info = %+v, want one record at LSN 1", info)
		}
		count := 0
		if err := w.Scan(ctx, 0, 0, func(Record) error { count++; return nil }); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("scan count = %d, want 1", count)
		}
	})
	t.Run("Records", func(t *testing.T) {
		w, err := Open(t.TempDir(), WithTxnMaxRecords(2))
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		tx, err := w.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Append(ctx, Record{Data: []byte("a")}); err != nil {
			t.Fatal(err)
		}
		if err := tx.AppendBatch(ctx, []Record{{Data: []byte("b")}, {Data: []byte("c")}}); !errors.Is(err, ErrTxnTooLarge) {
			t.Fatalf("AppendBatch err = %v, want ErrTxnTooLarge", err)
		}
		if len(tx.records) != 1 {
			t.Fatalf("rejected batch left %d buffered records, want 1", len(tx.records))
		}
	})
}

// TestTxAppendStreamRollsBackOnCapacity verifies that a stream whose chunk
// exceeds TxnMaxBytes leaves no buffered chunk behind, while the transaction
// itself stays active and can still commit its previous records. | 验证超过
// TxnMaxBytes 的流不会留下已缓冲分块，事务保持 active 且仍可提交之前的记录。
func TestTxAppendStreamRollsBackOnCapacity(t *testing.T) {
	ctx := context.Background()
	w, err := Open(t.TempDir(), WithTxnMaxBytes(214))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	tx, err := w.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Append(ctx, Record{Data: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	beforeBytes, beforeRecords := tx.bytes, len(tx.records)
	r := &fixedChunkReader{chunks: [][]byte{[]byte("bbbb"), []byte("cccc")}}
	if _, err := tx.AppendStream(ctx, r, StreamChunkSize(4)); !errors.Is(err, ErrTxnTooLarge) {
		t.Fatalf("AppendStream err = %v, want ErrTxnTooLarge", err)
	}
	if tx.bytes != beforeBytes || len(tx.records) != beforeRecords || len(tx.streams) != 0 {
		t.Fatalf("failed stream left partial state: bytes %d->%d records %d->%d streams %d",
			beforeBytes, tx.bytes, beforeRecords, len(tx.records), len(tx.streams))
	}
	info, err := tx.Commit(ctx)
	if err != nil {
		t.Fatalf("commit after failed stream: %v", err)
	}
	if info.Records != 1 {
		t.Fatalf("commit records = %d, want 1", info.Records)
	}
}

// fixedChunkReader yields fixed chunks and then io.EOF. | fixedChunkReader 依次
// 返回固定分块，随后返回 io.EOF。
type fixedChunkReader struct {
	chunks [][]byte
	next   int
}

func (r *fixedChunkReader) Read(p []byte) (int, error) {
	if r.next >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.next])
	r.next++
	return n, nil
}

// TestTxRollbackTerminalStates verifies the documented lifecycle: Rollback is a
// no-op after a failed Commit, every later Commit/Rollback returns
// ErrTxnClosed, and a committed transaction cannot be rolled back. | 验证文档
// 生命周期：Commit 失败后 Rollback 为 no-op，之后任何 Commit/Rollback 都返回
// ErrTxnClosed，已提交事务不能回滚。
func TestTxRollbackTerminalStates(t *testing.T) {
	ctx := context.Background()
	w, err := Open(t.TempDir(), WithSerializableDurability(true), WithDefaultIsolation(IsolationSerializable))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	txA, err := w.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := txA.WriteKey([]byte("k")); err != nil {
		t.Fatal(err)
	}
	if _, err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	txB, err := w.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := txB.ReadKey([]byte("k")); err != nil {
		t.Fatal(err)
	}
	txC, err := w.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := txC.WriteKey([]byte("k")); err != nil {
		t.Fatal(err)
	}
	if _, err := txC.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := txB.Commit(ctx); !errors.Is(err, ErrTxnConflict) {
		t.Fatalf("conflicting commit err = %v, want ErrTxnConflict", err)
	}
	if err := txB.Rollback(); err != nil {
		t.Fatalf("Rollback after failed Commit = %v, want nil", err)
	}
	if _, err := txB.Commit(ctx); !errors.Is(err, ErrTxnClosed) {
		t.Fatalf("Commit after failure err = %v, want ErrTxnClosed", err)
	}
	if err := txB.Rollback(); !errors.Is(err, ErrTxnClosed) {
		t.Fatalf("second Rollback err = %v, want ErrTxnClosed", err)
	}
	if err := txA.Rollback(); !errors.Is(err, ErrTxnClosed) {
		t.Fatalf("Rollback after commit err = %v, want ErrTxnClosed", err)
	}
}

// TestDedupTargetCorruptionIsDedupCorrupt verifies that damaging the record a
// dedup reference points at is reported as ErrDedupCorrupt, not as a generic
// record corruption without the dedup context. | 验证损坏去重引用指向的记录会
// 报告 ErrDedupCorrupt，而不是丢失去重上下文的普通记录损坏。
func TestDedupTargetCorruptionIsDedupCorrupt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	data := bytes.Repeat([]byte("target-"), 16)
	if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: data}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: data}); err != nil {
		t.Fatal(err)
	}
	if got := w.Stats().DedupRefs; got == 0 {
		t.Fatal("expected a dedup reference")
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(segmentPath(dir, 1), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var raw [recordHeaderSize]byte
	if err := readAtFull(f, raw[:], int64(segmentHeaderSize)); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	hdr, err := parseRecordHeader(raw[:])
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	pos := int64(segmentHeaderSize) + int64(hdr.headerLen) + 1
	var one [1]byte
	if err := readAtFull(f, one[:], pos); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	one[0] ^= 0xff
	if _, err := f.WriteAt(one[:], pos); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read(2); !errors.Is(err, ErrDedupCorrupt) {
		t.Fatalf("Read through damaged dedup target err = %v, want ErrDedupCorrupt", err)
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
