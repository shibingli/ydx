package wal

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManifestRejectsShardGap verifies that a missing shard index is treated as
// corruption instead of reading around the hole and silently dropping the
// records stored in it. | 验证缺失 shard 索引按损坏处理，而不是绕过缺口读取并
// 静默丢失其中记录。
func TestManifestRejectsShardGap(t *testing.T) {
	dir := t.TempDir()
	mdir := filepath.Join(dir, "manifest")
	if err := os.MkdirAll(mdir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeShard := func(index int, seq uint64) {
		var rec [manifestHeaderSize]byte
		encodeManifestRecord(rec[:], manifestRecord{
			kind: manifestKindCreated, seq: seq, baseLSN: seq, walID: [16]byte{1},
		})
		if err := os.WriteFile(filepath.Join(mdir, manifestShardName(index)), rec[:], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeShard(0, 1)
	writeShard(2, 3)
	if _, exists, corrupt, err := openManifest(dir, true, 4096, 0.5, 0o600, false); err != nil {
		t.Fatalf("openManifest: %v", err)
	} else if !exists || !corrupt {
		t.Fatalf("exists=%v corrupt=%v, want exists=true corrupt=true", exists, corrupt)
	}
	// A contiguous set must still load. | 连续 shard 必须正常加载。
	writeShard(1, 2)
	if _, exists, corrupt, err := openManifest(dir, true, 4096, 0.5, 0o600, false); err != nil {
		t.Fatalf("openManifest contiguous: %v", err)
	} else if !exists || corrupt {
		t.Fatalf("contiguous: exists=%v corrupt=%v, want exists=true corrupt=false", exists, corrupt)
	}
}

// TestManifestEmptyRewriteRemovesStaleShards verifies that rebuilding an empty
// manifest directory removes obsolete shards, so a corrupt/old shard cannot
// force a directory scan on every future Open. | 验证空 MANIFEST 重建会删除陈旧
// shard，避免损坏/旧 shard 让以后每次 Open 都回退目录扫描。
func TestManifestEmptyRewriteRemovesStaleShards(t *testing.T) {
	dir := t.TempDir()
	mdir := filepath.Join(dir, "manifest")
	if err := os.MkdirAll(mdir, 0o700); err != nil {
		t.Fatal(err)
	}
	var rec [manifestHeaderSize]byte
	encodeManifestRecord(rec[:], manifestRecord{
		kind: manifestKindCreated, seq: 1, baseLSN: 1, walID: [16]byte{1},
	})
	if err := os.WriteFile(filepath.Join(mdir, manifestShardName(0)), rec[:], 0o600); err != nil {
		t.Fatal(err)
	}
	m, exists, corrupt, err := openManifest(dir, true, 4096, 0.5, 0o600, false)
	if err != nil || !exists || corrupt {
		t.Fatalf("openManifest = exists:%v corrupt:%v err:%v", exists, corrupt, err)
	}
	if err := m.rewrite(newManifestData()); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	entries, err := os.ReadDir(mdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".mf" {
			t.Fatalf("stale manifest shard %s survived an empty rewrite", e.Name())
		}
	}
	if got := m.segmentCount(); got != 0 {
		t.Fatalf("segmentCount = %d, want 0", got)
	}
}
