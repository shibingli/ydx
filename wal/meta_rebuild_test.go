package wal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func seedWALForRebuild(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("rebuild")
	if _, err := w.Append(context.Background(), Record{Data: payload}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, payload
}

func copyWALDirForTest(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	copyTreeForTest(t, src, dst)
	return dst
}

// TestMetaRebuildMatrix covers the B2 decision matrix for missing or fully
// invalid META slots with and without a usable MANIFEST. | 覆盖 B2 决策矩阵：
// META 缺失或四槽全无效时，有无可用 MANIFEST 的不同结果。
func TestMetaRebuildMatrix(t *testing.T) {
	src, payload := seedWALForRebuild(t)

	t.Run("no meta and no manifest is corrupt with auto repair off", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		_ = os.Remove(filepath.Join(dir, "META"))
		_ = os.Remove(filepath.Join(dir, "META.mirror"))
		_ = os.RemoveAll(filepath.Join(dir, "manifest"))
		_ = os.Remove(anchorPath(dir))
		if _, err := Open(dir, WithAutoRepair(false)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("no meta and no manifest self heals", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		for _, path := range []string{
			filepath.Join(dir, "META"), filepath.Join(dir, "META.mirror"),
			filepath.Join(dir, "RECOVERY"), filepath.Join(dir, "manifest"),
		} {
			_ = os.RemoveAll(path)
		}
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		rec, err := w.Read(1)
		if err != nil || !bytes.Equal(rec.Data, payload) {
			t.Fatalf("read: %v", err)
		}
		if !w.autoRepaired {
			t.Fatal("autoRepaired flag not set")
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		w2, err := Open(dir)
		if err != nil {
			t.Fatalf("reopen after repair: %v", err)
		}
		if _, err := w2.Read(1); err != nil {
			t.Fatalf("read after repair: %v", err)
		}
		if err := w2.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("anchor survives meta and manifest loss", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		_ = os.Remove(filepath.Join(dir, "META"))
		_ = os.Remove(filepath.Join(dir, "META.mirror"))
		_ = os.RemoveAll(filepath.Join(dir, "manifest"))
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !w.recoveredFromAnchor {
			t.Fatal("recovery did not use the anchor")
		}
		if _, err := w.Read(1); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("no meta with manifest rebuilds", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		_ = os.Remove(filepath.Join(dir, "META"))
		_ = os.Remove(filepath.Join(dir, "META.mirror"))
		_ = os.Remove(anchorPath(dir))
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		rec, err := w.Read(1)
		if err != nil || !bytes.Equal(rec.Data, payload) {
			t.Fatalf("read: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid meta slots with manifest rebuild", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		for _, name := range []string{"META", "META.mirror"} {
			if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{0xFF}, metaFileSize), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_ = os.Remove(anchorPath(dir))
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := w.Read(1); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid meta slots and missing manifest is corrupt with auto repair off", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		for _, name := range []string{"META", "META.mirror"} {
			if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{0xFF}, metaFileSize), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_ = os.RemoveAll(filepath.Join(dir, "manifest"))
		_ = os.Remove(anchorPath(dir))
		if _, err := Open(dir, WithAutoRepair(false)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open err = %v, want ErrCorrupt", err)
		}
	})

	t.Run("invalid meta slots and missing manifest self heals", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		for _, name := range []string{"META", "META.mirror"} {
			if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{0xFF}, metaFileSize), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_ = os.RemoveAll(filepath.Join(dir, "manifest"))
		_ = os.Remove(anchorPath(dir))
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := w.Read(1); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("torn manifest tail is truncated", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		shards, err := filepath.Glob(filepath.Join(dir, "manifest", "*.mf"))
		if err != nil || len(shards) == 0 {
			t.Fatalf("manifest shards: %v", err)
		}
		shard := shards[len(shards)-1]
		before, err := os.Stat(shard)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(shard, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(bytes.Repeat([]byte{0xFF}, int(manifestHeaderSize))); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		after, err := os.Stat(shard)
		if err != nil {
			t.Fatal(err)
		}
		if after.Size() != before.Size() {
			t.Fatalf("manifest tail not truncated: %d -> %d", before.Size(), after.Size())
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("manifest gap is probed and rewritten", func(t *testing.T) {
		dir := t.TempDir()
		w, err := Open(dir, WithSegmentMaxBytes(200), WithSyncPolicy(SyncNever()))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		payload := bytes.Repeat([]byte("p"), 100)
		for i := 0; i < 6; i++ {
			if _, err := w.Append(ctx, Record{Data: payload}); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		shards, err := filepath.Glob(filepath.Join(dir, "manifest", "*.mf"))
		if err != nil || len(shards) == 0 {
			t.Fatalf("manifest shards: %v", err)
		}
		data, err := os.ReadFile(shards[len(shards)-1])
		if err != nil {
			t.Fatal(err)
		}
		var kept []byte
		for off := 0; off+int(manifestHeaderSize) <= len(data); off += int(manifestHeaderSize) {
			r, err := decodeManifestRecord(data[off : off+int(manifestHeaderSize)])
			if err != nil {
				t.Fatal(err)
			}
			if r.kind == manifestKindSegment && r.seq == 3 {
				continue
			}
			kept = append(kept, data[off:off+int(manifestHeaderSize)]...)
		}
		if err := os.WriteFile(shards[len(shards)-1], kept, 0o600); err != nil {
			t.Fatal(err)
		}
		w2, err := Open(dir)
		if err != nil {
			t.Fatalf("open with manifest gap: %v", err)
		}
		if _, err := w2.Read(3); err != nil {
			t.Fatalf("missing manifest entry was not recovered: %v", err)
		}
		if err := w2.Close(); err != nil {
			t.Fatal(err)
		}
		// The recovered summary must be written back as a sealed record. | 恢复出的
		// 摘要必须补写为封段记录。
		after, err := os.ReadFile(shards[len(shards)-1])
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for off := 0; off+int(manifestHeaderSize) <= len(after); off += int(manifestHeaderSize) {
			r, err := decodeManifestRecord(after[off : off+int(manifestHeaderSize)])
			if err == nil && r.kind == manifestKindSegment && r.seq == 3 {
				found = true
			}
		}
		if !found {
			t.Fatal("recovered manifest entry was not persisted")
		}
	})

	t.Run("corrupt manifest with valid meta rebuilds", func(t *testing.T) {
		dir := copyWALDirForTest(t, src)
		shards, err := filepath.Glob(filepath.Join(dir, "manifest", "*.mf"))
		if err != nil || len(shards) == 0 {
			t.Fatalf("manifest shards: %v", err)
		}
		for _, path := range shards {
			if err := os.WriteFile(path, bytes.Repeat([]byte{0xFF}, int(manifestHeaderSize)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		w, err := Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := w.Read(1); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
