package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestManifestRetireFloorReplay verifies that a compacted MANIFEST may keep
// only the highest kind=2 record and replay still retires every lower
// sequence. | 验证压缩后的 MANIFEST 只保留最高 kind=2 记录时，回放仍会把所有
// 更低序号视为已退休。
func TestManifestRetireFloorReplay(t *testing.T) {
	d := newManifestData()
	dir := t.TempDir()
	walID := [16]byte{1}
	for seq := uint64(1); seq <= 3; seq++ {
		if err := d.apply(manifestRecord{
			kind: manifestKindSegment, seq: seq, baseLSN: seq*10 + 1,
			lastLSN: seq*10 + 10, segmentBytes: 100, walID: walID,
		}, dir); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.apply(manifestRecord{kind: manifestKindRetire, seq: 2, walID: walID}, dir); err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 2; seq++ {
		if !d.retiredAt(seq) {
			t.Fatalf("seq %d should be retired by the floor", seq)
		}
	}
	if d.retiredAt(3) {
		t.Fatal("seq 3 must remain live")
	}
}

// TestManifestCompactionDoesNotResurrectRetiredSegments forces a close-time
// MANIFEST compaction after a prefix truncation. Reopening must not treat the
// deleted lower segments as live. | 在截断前缀后强制 Close 期 MANIFEST 压缩；
// 重新打开不得把已删除的低序号段当作存活段。
func TestManifestCompactionDoesNotResurrectRetiredSegments(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(180), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("p"), 80)
	var lsns []uint64
	for i := 0; i < 8; i++ {
		lsn, err := w.Append(ctx, Record{Data: payload})
		if err != nil {
			t.Fatal(err)
		}
		lsns = append(lsns, lsn)
	}
	// Retire every segment that ends before lsns[5]; the cleaner deletes them
	// and Close compacts the manifest. | 退休 lsns[5] 之前结束的所有分段；cleaner
	// 删除文件，Close 压缩 MANIFEST。
	target := lsns[5]
	if _, err := w.Truncate(target); err != nil {
		t.Fatal(err)
	}
	if err := w.FlushCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithSegmentMaxBytes(180))
	if err != nil {
		t.Fatalf("Open after compaction: %v", err)
	}
	defer w2.Close()
	if got := w2.FirstLSN(); got != target {
		t.Fatalf("FirstLSN = %d, want %d", got, target)
	}
	if _, err := w2.Read(lsns[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retired LSN read err = %v, want ErrNotFound", err)
	}
	if _, err := w2.Read(target); err != nil {
		t.Fatalf("first live LSN read: %v", err)
	}
	next, err := w2.Append(ctx, Record{Data: []byte("after")})
	if err != nil {
		t.Fatal(err)
	}
	if next <= lsns[len(lsns)-1] {
		t.Fatalf("new LSN %d reused the old high water %d", next, lsns[len(lsns)-1])
	}
}

// TestKeyRotationRecordEvidenceWinsKCV simulates a crash after SetActiveKey
// persisted a new active key but before the new segment received records. The
// last non-empty segment still names the old key; its header must win over the
// META KCV instead of failing authentication. | 模拟 SetActiveKey 已持久化新
// 活动密钥、但新段尚未写入记录的崩溃：最后非空段仍指向旧密钥，记录头必须优先于
// META KCV，而不是误报认证失败。
func TestKeyRotationRecordEvidenceWinsKCV(t *testing.T) {
	ring, err := NewKeyRing(1,
		Key{ID: 1, Suite: SuiteAESGCM, Bytes: bytes.Repeat([]byte{1}, 32)},
		Key{ID: 2, Suite: SuiteAESGCM, Bytes: bytes.Repeat([]byte{2}, 32)},
	)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	w, err := Open(dir, WithEncryption(ring))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(context.Background(), Record{Key: []byte("k"), Data: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	key2, err := w.bound.key(2)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the META half of SetActiveKey without creating a new segment. |
	// 模拟 SetActiveKey 只完成 META 写入、没有创建新分段的状态。
	w.activeKeyID = 2
	w.activeKCV = key2.kcv
	if err := w.meta.write(w.metaSnapshot()); err != nil {
		t.Fatal(err)
	}
	copyDir := copyWALDirForTest(t, dir)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(copyDir, WithEncryption(ring))
	if err != nil {
		t.Fatalf("Open with record key evidence: %v", err)
	}
	defer w2.Close()
	rec, err := w2.Read(1)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(rec.Data, []byte("v")) {
		t.Fatalf("Data = %q", rec.Data)
	}
}

// TestEncryptionDowngradeRejectedWithoutMeta verifies that losing META cannot
// silently turn an encrypted caller's plaintext WAL into a successful open. |
// 验证 META 丢失时，带密钥的调用方不能把明文 WAL 静默当作成功打开。
func TestEncryptionDowngradeRejectedWithoutMeta(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("plain")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "META"))
	_ = os.Remove(filepath.Join(dir, "META.mirror"))
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	_ = os.Remove(anchorPath(dir))
	ring, err := NewKeyRing(1, Key{ID: 1, Suite: SuiteAESGCM, Bytes: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, WithEncryption(ring)); !errors.Is(err, ErrCipherMismatch) {
		t.Fatalf("Open with keys on plaintext WAL err = %v, want ErrCipherMismatch", err)
	}
	w2, err := Open(dir, WithEncryption(ring), WithAllowPlaintext(true))
	if err != nil {
		t.Fatalf("Open with AllowPlaintext: %v", err)
	}
	defer w2.Close()
	if _, err := w2.Read(1); err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
}

// TestCheckpointSidecarDoesNotHideSealedTail verifies that a checkpoint .idx
// left on a sealed segment is not treated as a complete index. The query must
// still return a key that exists only after the checkpoint prefix. | 验证封段上
// 残留的检查点 .idx 不会被当作完整索引；只存在于前缀之后的 Key 仍必须被查询到。
func TestCheckpointSidecarDoesNotHideSealedTail(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithKeyIndex(true), WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Key: []byte("a"), Data: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Key: []byte("b"), Data: []byte("2")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Key: []byte("c"), Data: []byte("3")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Build a checkpoint sidecar for segment 1 that covers only its first
	// record, as the checkpoint worker would before the second record was
	// synced. | 为分段 1 构造只覆盖第一条记录的检查点侧车，模拟第二条记录同步前
	// 检查点 worker 写下的前缀。
	walPath := segmentPath(dir, 1)
	f, err := os.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	var hdr [recordHeaderSize]byte
	if err := readAtFull(f, hdr[:], int64(segmentHeaderSize)); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	rh, err := parseRecordHeader(hdr[:])
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	end := int64(segmentHeaderSize) + int64(rh.size)
	prefix := make([]byte, end-int64(segmentHeaderSize))
	if err := readAtFull(f, prefix, int64(segmentHeaderSize)); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()
	full, err := loadSidecar(sidecarPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	ckpt := &sidecar{
		seq: full.seq, baseLSN: full.baseLSN, lastLSN: 1, recordCount: 1,
		segmentBytes: uint64(end), minTime: full.minTime, maxTime: full.maxTime,
		segmentCRC: checksum(prefix), walID: full.walID, commitSeq: full.commitSeq,
		checkpoint: true, hasKeyIndex: true,
		keyIndex: map[string][]uint64{"a": {1}},
	}
	if err := os.WriteFile(sidecarPath(dir, 1), encodeSidecar(ckpt), 0o600); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithKeyIndex(true), WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w2.Close()
	count, err := w2.Query(ctx, Query{Key: []byte("b")}, nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if count != 1 {
		t.Fatalf("tail key count = %d, want 1 (checkpoint sidecar hid the tail)", count)
	}
	seg := w2.segBySeq[1]
	if seg == nil {
		t.Fatal("segment 1 missing")
	}
	w2.ensureSparse(seg)
	seg.metaMu.RLock()
	_, hasTail := seg.keyIndex["b"]
	seg.metaMu.RUnlock()
	if !hasTail {
		t.Fatal("tail key missing from the rebuilt sealed-segment index")
	}
	if got := w2.Stats().KeyIndexRebuilds; got == 0 {
		t.Fatal("checkpoint prefix was not rebuilt")
	}
}

// TestRetentionDoesNotResurrectAfterManifestCompaction is a compact variant of
// the compaction test that exercises automatic retention rather than an
// explicit Truncate. | 使用自动保留而非显式 Truncate 的压缩复活回归测试。
func TestRetentionDoesNotResurrectAfterManifestCompaction(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir,
		WithSegmentMaxBytes(180),
		WithSyncPolicy(SyncNever()),
		WithRetention(Retention{MaxBytes: 300}),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("r"), 80)
	for i := 0; i < 10; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	// Retention runs asynchronously; wait for its truncation to become visible
	// instead of racing the worker. | 保留策略异步运行；等待其截断可见，避免
	// 与 worker 竞争。
	deadline := time.Now().Add(5 * time.Second)
	for w.FirstLSN() == 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	first := w.FirstLSN()
	if first == 1 {
		t.Fatal("retention did not truncate any segment")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(dir, WithSegmentMaxBytes(180), WithRetention(Retention{MaxBytes: 300}))
	if err != nil {
		t.Fatalf("Open after retention compaction: %v", err)
	}
	defer w2.Close()
	if w2.FirstLSN() < first {
		t.Fatalf("FirstLSN rolled back: %d < %d", w2.FirstLSN(), first)
	}
	for lsn := uint64(1); lsn < w2.FirstLSN(); lsn++ {
		if _, err := w2.Read(lsn); !errors.Is(err, ErrNotFound) {
			t.Fatalf("retired LSN %d read err = %v, want ErrNotFound", lsn, err)
		}
	}
}
