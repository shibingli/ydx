package wal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueryKeyIndex(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithKeyIndex(true), WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]uint64{}
	appendKey := func(key, data string) uint64 {
		lsn, err := w.Append(ctx, Record{Key: []byte(key), Data: []byte(data)})
		if err != nil {
			t.Fatal(err)
		}
		want[key] = append(want[key], lsn)
		return lsn
	}
	for i := 0; i < 12; i++ {
		if i%3 == 0 {
			appendKey("a", "aa")
		} else {
			appendKey("b", "bb")
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen so sealed-segment indexes are loaded from sidecars. | 重新打开，使
	// 封段索引从侧车加载。
	w, err = Open(dir, WithKeyIndex(true), WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, key := range []string{"a", "b", "missing"} {
		var got []uint64
		count, err := w.Query(ctx, Query{Key: []byte(key)}, func(rec Record) error {
			got = append(got, rec.LSN)
			if string(rec.Key) != key {
				t.Fatalf("key %q returned record key %q", key, rec.Key)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("query %q: %v", key, err)
		}
		if count != len(want[key]) || len(got) != count {
			t.Fatalf("query %q count=%d got=%v want=%v", key, count, got, want[key])
		}
		for i := range got {
			if got[i] != want[key][i] {
				t.Fatalf("query %q order=%v want=%v", key, got, want[key])
			}
		}
	}
	count, err := w.Query(ctx, Query{Key: []byte("a"), Limit: 1}, nil)
	if err != nil || count != 1 {
		t.Fatalf("limit query count=%d err=%v", count, err)
	}
}

func TestQueryKeyIndexWithEviction(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithKeyIndex(true), WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		key := []byte("a")
		if i%2 == 1 {
			key = []byte("b")
		}
		if _, err := w.Append(ctx, Record{Key: key, Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = Open(dir, WithKeyIndex(true), WithIndexCacheBytes(1), WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for round := 0; round < 3; round++ {
		for key, want := range map[string]int{"a": 10, "b": 10} {
			got, err := w.Query(ctx, Query{Key: []byte(key)}, nil)
			if err != nil || got != want {
				t.Fatalf("round %d key %q count=%d err=%v, want %d", round, key, got, err, want)
			}
		}
	}
}

func TestOldSidecarKeyIndexFallsBack(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithKeyIndex(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Rewrite the sidecar as an old-format one: has a key index but no
	// "complete" flag, as v0.1.0 wrote it. | 改写为旧格式：有 Key 索引但没有
	// “完整”标志（v0.1.0 的写法）。
	path := sidecarPath(dir, 1)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	flags := binary.LittleEndian.Uint16(raw[idxOffFlags:])
	binary.LittleEndian.PutUint16(raw[idxOffFlags:], flags&^sidecarFlagKeyIndexComplete)
	binary.LittleEndian.PutUint32(raw[len(raw)-sidecarTrailer:], checksum(raw[:len(raw)-sidecarTrailer]))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := loadSidecar(path)
	if err != nil || sc.keyIndexComplete {
		t.Fatalf("old sidecar complete=%v err=%v, want incomplete", sc != nil && sc.keyIndexComplete, err)
	}
	w, err = Open(dir, WithKeyIndex(true))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	count, err := w.Query(ctx, Query{Key: []byte("k")}, nil)
	if err != nil || count != 1 {
		t.Fatalf("query with old sidecar count=%d err=%v", count, err)
	}
	firstRebuilds := w.Stats().KeyIndexRebuilds
	if firstRebuilds == 0 {
		t.Fatal("old sidecar was not rebuilt")
	}
	// The rebuilt sidecar must be persisted as a complete index. | 重建后的侧车
	// 必须作为完整索引持久化。
	upgraded, err := loadSidecar(path)
	if err != nil || !upgraded.keyIndexComplete {
		t.Fatalf("upgraded sidecar complete=%v err=%v", upgraded != nil && upgraded.keyIndexComplete, err)
	}
	count, err = w.Query(ctx, Query{Key: []byte("k")}, nil)
	if err != nil || count != 1 {
		t.Fatalf("second query count=%d err=%v", count, err)
	}
	if got := w.Stats().KeyIndexRebuilds; got != firstRebuilds {
		t.Fatalf("second query rebuilt the index again: %d -> %d", firstRebuilds, got)
	}
}

func TestQueryEmptyKeyIndex(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithKeyIndex(true), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("empty-key")}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte("other")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = Open(dir, WithKeyIndex(true))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	count, err := w.Query(ctx, Query{Key: []byte{}}, func(rec Record) error {
		if len(rec.Key) != 0 || string(rec.Data) != "empty-key" {
			t.Fatalf("empty-key query returned key=%q data=%q", rec.Key, rec.Data)
		}
		return nil
	})
	if err != nil || count != 1 {
		t.Fatalf("empty-key query count=%d err=%v", count, err)
	}
}

func TestQueryFiltersAndCancel(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	base := time.Now()
	times := []time.Time{base, base.Add(time.Second), base.Add(2 * time.Second)}
	for i, ts := range times {
		if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: []byte{byte('0' + i)}, Timestamp: ts.UnixNano()}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := w.Query(ctx, Query{Since: times[1], Until: times[2]}, nil)
	if err != nil || got != 2 {
		t.Fatalf("time query count=%d err=%v", got, err)
	}
	if got, err := w.Query(ctx, Query{Contains: []byte("1")}, nil); err != nil || got != 1 {
		t.Fatalf("contains query count=%d err=%v", got, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := w.Query(canceled, Query{}, func(Record) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled query err=%v", err)
	}
	scanned := 0
	if err := w.Scan(ctx, 2, 3, func(rec Record) error {
		scanned++
		if rec.LSN < 2 || rec.LSN > 3 {
			t.Fatalf("scan returned LSN %d outside [2,3]", rec.LSN)
		}
		return nil
	}); err != nil {
		t.Fatalf("scan err=%v", err)
	}
	if scanned != 2 {
		t.Fatalf("scan count=%d, want 2", scanned)
	}
}

func TestQueryAliasRequiresClone(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, Record{Data: []byte{byte('A' + i)}}); err != nil {
			t.Fatal(err)
		}
	}
	var cloned []Record
	if err := w.Scan(ctx, 0, 0, func(rec Record) error {
		cloned = append(cloned, rec.Clone())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i, rec := range cloned {
		if !bytes.Equal(rec.Data, []byte{byte('A' + i)}) {
			t.Fatalf("cloned[%d]=%q", i, rec.Data)
		}
	}
}

// TestVerifyDetectsSummaryMismatch verifies that Verify proves the manifest
// summary describes the segment file, not merely that the file is internally
// consistent. | 验证 Verify 会证明 MANIFEST 摘要描述的就是该分段文件，而不只是
// 文件自身自洽。
func TestVerifyDetectsSummaryMismatch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte{'k', byte('0' + i)}, Data: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest", manifestShardName(0))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for off := 0; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
		r, err := decodeManifestRecord(data[off : off+int(manifestHeaderSize)])
		if err != nil {
			t.Fatal(err)
		}
		if r.kind == manifestKindSegment && r.seq == 1 {
			r.lastLSN += 1000
			encodeManifestRecord(data[off:off+int(manifestHeaderSize)], r)
			changed = true
		}
	}
	if !changed {
		t.Fatal("no sealed manifest record for segment 1")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with tampered summary: %v", err)
	}
	defer w2.Close()
	if err := w2.Verify(ctx); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Verify err = %v, want ErrCorrupt", err)
	}
}

// TestReadIntoMatchesRead verifies the zero-copy read path against Read for
// ordinary and deduplication-reference records, including short destinations
// and the closed lifecycle. | 验证零拷贝读取路径与 Read 在普通记录和去重引用
// 记录上一致，并覆盖目标过短与关闭后的生命周期。
func TestReadIntoMatchesRead(t *testing.T) {
	ctx := context.Background()
	w, err := Open(t.TempDir(), WithContentDedup(DedupOptions{MinBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("read-into-"), 64)
	for i := 0; i < 2; i++ {
		if _, err := w.Append(ctx, Record{Key: []byte("k"), Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.Stats().DedupRefs; got == 0 {
		t.Fatalf("expected a dedup reference, stats=%+v", w.Stats())
	}
	for lsn := uint64(1); lsn <= 2; lsn++ {
		want, err := w.Read(lsn)
		if err != nil {
			t.Fatal(err)
		}
		dst := make([]byte, len(want.Key)+len(want.Data)+16)
		rec, buf, err := w.ReadInto(lsn, dst)
		if err != nil {
			t.Fatalf("ReadInto(%d): %v", lsn, err)
		}
		if !bytes.Equal(rec.Key, want.Key) || !bytes.Equal(rec.Data, want.Data) {
			t.Fatalf("ReadInto(%d) key/data mismatch", lsn)
		}
		if len(buf) != len(want.Key)+len(want.Data) || len(rec.Key)+len(rec.Data) != len(buf) {
			t.Fatalf("ReadInto(%d) returned %d bytes, want %d", lsn, len(buf), len(want.Key)+len(want.Data))
		}
		if lsn == 1 {
			if _, _, err := w.ReadInto(lsn, make([]byte, 1)); !errors.Is(err, ErrTooShort) {
				t.Fatalf("ReadInto short destination err = %v, want ErrTooShort", err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.ReadInto(1, make([]byte, len(data)+1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReadInto after Close err = %v, want ErrClosed", err)
	}
}

// TestReaderClampsExplicitToAndFrom verifies that an explicit To above the
// call-time high-water never follows later appends, and that From above the
// high-water does not consume a future record. | 验证显式 To 超过调用时高水位时
// 不会跟随后续追加，且 From 高于高水位时不会消费未来记录。
func TestReaderClampsExplicitToAndFrom(t *testing.T) {
	ctx := context.Background()
	w, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(ctx, Record{Data: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	bounded, err := w.NewReader(To(100))
	if err != nil {
		t.Fatal(err)
	}
	defer bounded.Close()
	if rec, err := bounded.Next(); err != nil || rec.LSN != 1 {
		t.Fatalf("first Next = %d/%v", rec.LSN, err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	if rec, err := bounded.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("bounded Next after append = %d/%v, want io.EOF", rec.LSN, err)
	}

	future, err := w.NewReader(From(5))
	if err != nil {
		t.Fatal(err)
	}
	defer future.Close()
	if _, err := w.Append(ctx, Record{Data: []byte("three")}); err != nil {
		t.Fatal(err)
	}
	if rec, err := future.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("future From Next = %d/%v, want io.EOF", rec.LSN, err)
	}
}

// TestScanAndQueryClampExplicitTo verifies that Scan and Query clamp an
// explicit To above the call-time high-water, so a callback that appends a new
// record cannot extend the finite range. | 验证 Scan 与 Query 会截断超过调用时
// 高水位的显式 To，回调中的新追加不能扩展该有限范围。
func TestScanAndQueryClampExplicitTo(t *testing.T) {
	ctx := context.Background()
	open := func(t *testing.T) *WAL {
		t.Helper()
		w, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = w.Close() })
		if _, err := w.Append(ctx, Record{Data: []byte("one")}); err != nil {
			t.Fatal(err)
		}
		return w
	}
	appendTwo := func(t *testing.T, w *WAL) error {
		t.Helper()
		_, err := w.Append(ctx, Record{Data: []byte("two")})
		return err
	}

	t.Run("Scan", func(t *testing.T) {
		w := open(t)
		count := 0
		if err := w.Scan(ctx, 1, 100, func(Record) error {
			count++
			if count == 1 {
				return appendTwo(t, w)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("Scan returned %d records, want 1", count)
		}
	})
	t.Run("Query", func(t *testing.T) {
		w := open(t)
		count, err := w.Query(ctx, Query{From: 1, To: 100}, func(Record) error {
			return appendTwo(t, w)
		})
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("Query returned %d records, want 1", count)
		}
	})
}

// TestNewRangeReaderSkipsTruncatedStart verifies that a range whose start was
// truncated away is retried from the new FirstLSN instead of failing with
// ErrNotFound. | 验证起点已被截断的范围会从新的 FirstLSN 重试，而不是返回
// ErrNotFound 失败。
func TestNewRangeReaderSkipsTruncatedStart(t *testing.T) {
	ctx := context.Background()
	w, err := Open(t.TempDir(), WithSegmentMaxBytes(100), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 4; i++ {
		if _, err := w.Append(ctx, Record{Data: bytes.Repeat([]byte("q"), 64)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Truncate(3); err != nil {
		t.Fatal(err)
	}
	if got := w.FirstLSN(); got != 3 {
		t.Fatalf("FirstLSN = %d, want 3", got)
	}
	r, err := w.newRangeReader(1, Snapshot{LastLSN: 4})
	if err != nil {
		t.Fatalf("newRangeReader after truncation: %v", err)
	}
	defer r.Close()
	for want := uint64(3); want <= 4; want++ {
		rec, err := r.Next()
		if err != nil {
			t.Fatalf("next %d: %v", want, err)
		}
		if rec.LSN != want {
			t.Fatalf("LSN = %d, want %d", rec.LSN, want)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("final Next err = %v, want io.EOF", err)
	}
	// A fully truncated range is empty, not an error. | 完全被截断的范围为空，
	// 不是错误。
	r2, err := w.newRangeReader(1, Snapshot{LastLSN: 2})
	if err != nil {
		t.Fatalf("newRangeReader fully truncated range: %v", err)
	}
	defer r2.Close()
	if _, err := r2.Next(); err != io.EOF {
		t.Fatalf("fully truncated range Next err = %v, want io.EOF", err)
	}
}
