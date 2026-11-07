package raft

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shibingli/ydx/wal"
)

// TestFileStorageForwardsSizePolicy verifies that FileStorageOptions.SizePolicy
// reaches the underlying ydx/wal instance. | TestFileStorageForwardsSizePolicy
// 验证 FileStorageOptions.SizePolicy 传递到底层 ydx/wal 实例。
func TestFileStorageForwardsSizePolicy(t *testing.T) {
	dir := t.TempDir()
	policy := wal.SizePolicy{
		Mode:                wal.SizePolicyManual,
		CRCCombineMinBytes:  48 << 10,
		StagingJoinMaxBytes: 24 << 10,
	}
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true, SizePolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	got := s.wlog.log.EffectiveSizePolicy()
	if got.Mode != wal.SizePolicyManual {
		t.Fatalf("mode = %v, want manual", got.Mode)
	}
	if got.CRCCombineMinBytes != 48<<10 {
		t.Fatalf("crc threshold = %d, want %d", got.CRCCombineMinBytes, 48<<10)
	}
	if got.StagingJoinMaxBytes != 24<<10 {
		t.Fatalf("staging threshold = %d, want %d", got.StagingJoinMaxBytes, 24<<10)
	}
}

// TestFileStorageUsesYdxWAL verifies FileStorage is backed by the ydx/wal
// module. Opening a store with the ydx/wal backend creates its directory lock
// file; the retired in-tree WAL never did. | TestFileStorageUsesYdxWAL 验证
// FileStorage 由 ydx/wal 模块支撑。使用 ydx/wal 后端打开存储会创建其目录锁文件；
// 已移除的仓内 WAL 从不会创建该文件。
func TestFileStorageUsesYdxWAL(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wal", "wal.lock")); err != nil {
		t.Fatalf("ydx/wal lock file missing: %v", err)
	}
}

// TestFileStorageRecoversEntriesBeforeSnapshotMarker reproduces an asynchronous
// local snapshot: entries beyond the snapshot base reach the WAL before the
// marker record, and compaction drops the fully covered records below the base.
// Recovery must preset the newest marker as its base instead of rejecting the
// resulting entry gap. | TestFileStorageRecoversEntriesBeforeSnapshotMarker 复现
// 异步本地快照：快照基点之后的日志项先于标记记录进入 WAL，压缩删除基点以下已被完全
// 覆盖的记录。恢复必须以最新标记预设基点，而不是拒绝由此产生的日志项缺口。
func TestFileStorageRecoversEntriesBeforeSnapshotMarker(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 1}
	for i := 1; i <= 10; i++ {
		hs.Commit = uint64(i)
		if err := s.Persist(PersistBatch{HardState: &hs, Entries: entriesRange(uint64(i), uint64(i), 1)}); err != nil {
			t.Fatalf("persist %d: %v", i, err)
		}
	}
	snap := &Snapshot{Index: 5, Term: 1, ConfState: ConfState{Voters: []NodeID{1}}}
	if err := s.WriteSnapshotFile(snap); err != nil {
		t.Fatal(err)
	}
	if err := s.PersistLocalSnapshotMarkerBatch(snap, PersistBatch{HardState: &hs}); err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(5); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || rec.Snapshot.Index != 5 {
		t.Fatalf("snapshot = %+v, want index 5", rec.Snapshot)
	}
	if len(rec.Entries) != 5 || rec.Entries[0].Index != 6 || rec.Entries[4].Index != 10 {
		t.Fatalf("entries = %+v, want 6..10", rec.Entries)
	}
}

// TestFileStorageYdxWALRecordRoundTrip verifies one Persist call becomes one
// durable ydx/wal record that recovery replays exactly. |
// TestFileStorageYdxWALRecordRoundTrip 验证一次 Persist 变为一条持久 ydx/wal
// 记录，恢复时逐字节重放一致。
func TestFileStorageYdxWALRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 4, Vote: 2, Commit: 2}
	batch := PersistBatch{HardState: &hs, Entries: []Entry{
		{Index: 1, Term: 1, Type: EntryBootstrap, Data: []byte("a")},
		{Index: 2, Term: 4, Type: EntryNormal, Data: []byte("hello")},
	}}
	if err := s.Persist(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.HardState != hs {
		t.Fatalf("hard state = %+v, want %+v", rec.HardState, hs)
	}
	if len(rec.Entries) != 2 || rec.Entries[0].Index != 1 || rec.Entries[1].Index != 2 ||
		string(rec.Entries[1].Data) != "hello" {
		t.Fatalf("entries = %+v", rec.Entries)
	}
}
