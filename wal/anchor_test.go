package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestManifestDisabledTotalMetadataLossSelfHeals verifies that a WAL created
// with WithManifest(false) can still be rebuilt after META, the anchor, and
// every manifest file are gone. | 验证 WithManifest(false) 创建的 WAL 在 META、
// 锚点与全部分片都丢失后仍能自愈。
func TestManifestDisabledTotalMetadataLossSelfHeals(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithManifest(false), WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("m"), 100)
	for i := 0; i < 8; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(dir, "META"), filepath.Join(dir, "META.mirror"),
		filepath.Join(dir, "RECOVERY"), filepath.Join(dir, "manifest"),
	} {
		_ = os.RemoveAll(path)
	}
	w2, err := Open(dir, WithManifest(false), WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !w2.autoRepaired {
		t.Fatal("auto repair flag not set")
	}
	if got := w2.LastLSN(); got != 8 {
		t.Fatalf("LastLSN = %d, want 8", got)
	}
	for lsn := uint64(1); lsn <= 8; lsn++ {
		rec, err := w2.Read(lsn)
		if err != nil || !bytes.Equal(rec.Data, payload) {
			t.Fatalf("Read(%d): %v", lsn, err)
		}
	}
	next, err := w2.Append(ctx, Record{Data: []byte("after")})
	if err != nil {
		t.Fatal(err)
	}
	if next != 9 {
		t.Fatalf("next LSN = %d, want 9", next)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	// A second open must use the healed META/anchor, not repair again. |
	// 第二次打开必须使用已自愈的 META/锚点，而不是再次重建。
	w3, err := Open(dir, WithManifest(false), WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatal(err)
	}
	defer w3.Close()
	if w3.autoRepaired {
		t.Fatal("second open repaired again instead of using healed metadata")
	}
}

// TestAnchorPreservesTruncationBeforeCleaner verifies that the anchor keeps a
// truncation watermark even when a pinned reader prevented the cleaner from
// deleting the retired segment files. | 验证即使被固定的读者阻止 cleaner 删除
// 已退休段，锚点仍保留截断水位。
func TestAnchorPreservesTruncationBeforeCleaner(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("t"), 100)
	var lsns []uint64
	for i := 0; i < 20; i++ {
		lsn, err := w.Append(ctx, Record{Data: payload})
		if err != nil {
			t.Fatal(err)
		}
		lsns = append(lsns, lsn)
	}
	r, err := w.NewReader(From(1), pinRange())
	if err != nil {
		t.Fatal(err)
	}
	target := lsns[10]
	if _, err := w.Truncate(target); err != nil {
		t.Fatal(err)
	}
	copyDir := copyWALDirForTest(t, dir)
	_ = r.Close()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(copyDir, "META"), filepath.Join(copyDir, "META.mirror"),
		filepath.Join(copyDir, "manifest"),
	} {
		_ = os.RemoveAll(path)
	}
	w2, err := Open(copyDir, WithSegmentMaxBytes(200))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w2.Close()
	if got := w2.FirstLSN(); got != target {
		t.Fatalf("FirstLSN = %d, want truncation watermark %d", got, target)
	}
	if _, err := w2.Read(lsns[0]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retired LSN read err = %v, want ErrNotFound", err)
	}
	if _, err := w2.Read(target); err != nil {
		t.Fatalf("first live LSN read: %v", err)
	}
}

// TestCorruptAnchorFallsBackToSegments verifies that a damaged anchor is
// ignored, the directory is repaired with the default policy, and a valid
// anchor is written back. | 验证损坏锚点会被忽略，默认策略从分段修复目录，并
// 重新写回有效锚点。
func TestCorruptAnchorFallsBackToSegments(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("anchor")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(anchorPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < anchorSlotMaxSize {
		t.Fatalf("anchor file has %d bytes, want at least %d", len(data), anchorSlotMaxSize)
	}
	data[0] ^= 0xFF
	if len(data) >= anchorSlotMaxSize+1 {
		data[anchorSlotMaxSize] ^= 0xFF
	}
	if err := os.WriteFile(anchorPath(dir), data, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "META"))
	_ = os.Remove(filepath.Join(dir, "META.mirror"))
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with corrupt anchor: %v", err)
	}
	if !w2.autoRepaired || w2.recoveredFromAnchor {
		t.Fatalf("autoRepaired=%v recoveredFromAnchor=%v", w2.autoRepaired, w2.recoveredFromAnchor)
	}
	if _, err := w2.Read(1); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, valid, err := loadAnchor(dir); err != nil || !valid {
		t.Fatalf("repaired anchor valid=%v err=%v", valid, err)
	}
}

// TestAnchorFromAnotherWALIsIgnored verifies that a copied anchor cannot
// override a valid META. | 验证复制的锚点不能覆盖有效 META。
func TestAnchorFromAnotherWALIsIgnored(t *testing.T) {
	ctx := context.Background()
	src := t.TempDir()
	w, err := Open(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("src")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := os.ReadFile(anchorPath(src))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	w2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Append(ctx, Record{Data: []byte("dst")}); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorPath(dir), other, 0o600); err != nil {
		t.Fatal(err)
	}
	w3, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with foreign anchor: %v", err)
	}
	if w3.recoveredFromAnchor {
		t.Fatal("foreign anchor was trusted")
	}
	rec, err := w3.Read(1)
	if err != nil || !bytes.Equal(rec.Data, []byte("dst")) {
		t.Fatalf("Read = %q, %v", rec.Data, err)
	}
	if err := w3.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestV1WALWithoutAnchorUpgrades verifies that a WAL created before the
// recovery anchor existed still opens, then gains a valid anchor on its next
// write/close cycle. | 验证恢复锚点出现前创建的 WAL 仍可打开，并在下一次
// 写入/关闭周期获得有效锚点。
func TestV1WALWithoutAnchorUpgrades(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(ctx, Record{Data: []byte("v1")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(anchorPath(dir))
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("open without anchor: %v", err)
	}
	if _, err := w2.Append(ctx, Record{Data: []byte("v2")}); err != nil {
		t.Fatal(err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, valid, err := loadAnchor(dir); err != nil || !valid {
		t.Fatalf("anchor not upgraded: valid=%v err=%v", valid, err)
	}
	// Losing META, MANIFEST and the old segments must now heal from the anchor.
	_ = os.Remove(filepath.Join(dir, "META"))
	_ = os.Remove(filepath.Join(dir, "META.mirror"))
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	w3, err := Open(dir)
	if err != nil {
		t.Fatalf("anchor recovery after upgrade: %v", err)
	}
	defer w3.Close()
	if _, err := w3.Read(2); err != nil {
		t.Fatalf("read anchored record: %v", err)
	}
}

// TestAnchorTornSlotKeepsPreviousGeneration verifies the two-slot anchor
// survives a torn newer slot. | 验证双槽锚点在较新槽撕裂时保留上一代。
func TestAnchorTornSlotKeepsPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	path := anchorPath(dir)
	s, err := openAnchorStore(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	st1 := anchorState{
		generation: 1, walID: [16]byte{1}, createdNano: 1,
		nextSeq: 2, nextLSN: 2, firstLSN: 1,
	}
	if err := s.write(st1); err != nil {
		t.Fatal(err)
	}
	st2 := st1
	st2.generation = 2
	st2.nextLSN = 3
	if err := s.write(st2); err != nil {
		t.Fatal(err)
	}
	newSlot := s.slot
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	off := newSlot * anchorSlotMaxSize
	data[off] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, valid, err := loadAnchor(dir)
	if err != nil || !valid {
		t.Fatalf("load valid=%v err=%v", valid, err)
	}
	if got.generation != 1 || got.nextLSN != 2 {
		t.Fatalf("got generation=%d nextLSN=%d, want the previous slot", got.generation, got.nextLSN)
	}
}

// TestGapSetMergeAndLimit verifies interval merging and the degradation cap. |
// 验证区间合并与降级上限。
func TestGapSetMergeAndLimit(t *testing.T) {
	g := newGapSet()
	if !g.add(10, 20) || !g.add(21, 30) {
		t.Fatal("add reported no change")
	}
	if len(g.snapshot()) != 1 || !g.covers(10, 30) {
		t.Fatalf("adjacent intervals did not merge: %+v", g.snapshot())
	}
	if g.add(15, 17) {
		t.Fatal("covered interval reported a change")
	}
	if !g.add(6, 9) || !g.add(5, 5) || !g.covers(5, 30) {
		t.Fatalf("adjacent lower intervals did not merge: %+v", g.snapshot())
	}
	for i := uint64(100); i < 2500; i += 2 {
		g.add(i, i)
	}
	if !g.isDegraded() || len(g.snapshot()) > 1 {
		t.Fatalf("gap set did not degrade: count=%d degraded=%v", len(g.snapshot()), g.isDegraded())
	}
	if !g.covers(1, 2498) {
		t.Fatal("degraded floor does not cover the high end")
	}
}

// TestAnchorGapsSurviveReopen verifies that a gap accepted by auto repair is
// persisted and a later strict open does not need the lossy flag. | 验证自动修复
// 接受的缺口会持久化，后续严格打开无需有损旗标。
func TestAnchorGapsSurviveReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	w, err := Open(dir, WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("p"), 100)
	for i := 0; i < 16; i++ {
		if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	removeSegmentForTest(t, dir, 3)
	_ = os.RemoveAll(filepath.Join(dir, "manifest"))
	w2, err := Open(dir)
	if err != nil {
		t.Fatalf("auto repair: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatal(err)
	}
	w3, err := Open(dir, WithAutoRepair(false))
	if err != nil {
		t.Fatalf("strict reopen of persisted gap: %v", err)
	}
	defer w3.Close()
	if got := w3.Stats().RecoveryMissingLSNs; got == 0 {
		t.Fatal("persisted gap was not observed on reopen")
	}
}
