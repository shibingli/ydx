package wal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestRetiredHighestSequenceIsNotActivated reproduces the state left when every
// segment file is retired but the cleaner has not removed them and the active
// segment file is gone. Recovery must never open a retired sequence as the
// active segment; otherwise new acknowledged records land in a segment readers
// treat as retired. | 复现“所有分段已退休但清理未完成、活动段文件已缺失”的状态。
// 恢复绝不能把已退休序号当作活动段打开，否则新确认的记录会写入读者视为退休的
// 分段而不可见。
func TestRetiredHighestSequenceIsNotActivated(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(180), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("p"), 80)
	for i := 0; i < 12; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	next := w.LastLSN() + 1
	// Seal every data segment and create an empty active segment. | 封存全部数据
	// 分段并创建一个空活动段。
	if err := w.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	h, _, err := readSegmentHeaderFile(segmentPath(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	// Emulate an interrupted truncate-to-end: the MANIFEST carries the truncate
	// watermark and a retire record for every created sequence, while META and
	// the recovery anchor are lost. | 模拟中断的“截断到末尾”：MANIFEST 带有截断
	// 水位和每个已创建序号的退休记录，而 META 与恢复锚点已丢失。
	o := defaultOptions()
	m, _, _, err := openManifest(dir, true, o.manifestShardRecords, o.manifestCompactRatio, 0o600, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.append(manifestRecord{kind: manifestKindTruncate, baseLSN: next, walID: h.walID}); err != nil {
		_ = m.close()
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= next; seq++ {
		if err := m.append(manifestRecord{kind: manifestKindRetire, seq: seq, walID: h.walID}); err != nil {
			_ = m.close()
			t.Fatal(err)
		}
	}
	if err := m.close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"META", "META.mirror", "RECOVERY"} {
		_ = os.Remove(filepath.Join(dir, name))
	}

	w2, err := Open(dir, WithSegmentMaxBytes(180), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatalf("Open with all segments retired: %v", err)
	}
	defer w2.Close()
	lsn, err := w2.Append(ctx, Record{Data: []byte("after")})
	if err != nil {
		t.Fatal(err)
	}
	if lsn != next {
		t.Fatalf("Append LSN = %d, want %d (no LSN reuse)", lsn, next)
	}
	rec, err := w2.Read(lsn)
	if err != nil {
		t.Fatalf("Read newly appended record: %v", err)
	}
	if !bytes.Equal(rec.Data, []byte("after")) {
		t.Fatalf("Data = %q", rec.Data)
	}
	w2.mu.RLock()
	activeSeq := uint64(0)
	if w2.active != nil {
		activeSeq = w2.active.seq
	}
	_, reused := w2.segBySeq[next-1]
	_, fresh := w2.segBySeq[activeSeq]
	w2.mu.RUnlock()
	if reused {
		t.Fatalf("retired segment %d became active", next-1)
	}
	if activeSeq <= next-1 {
		t.Fatalf("new active sequence %d is inside the retired range", activeSeq)
	}
	if !fresh {
		t.Fatalf("new record was not written to a fresh segment %d", activeSeq)
	}
}
