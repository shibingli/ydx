package raft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// testFileStorage opens a temporary file-backed store. | testFileStorage 打开临时
// 文件存储。
func testFileStorage(t *testing.T) (*FileStorage, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatalf("new file storage: %v", err)
	}
	return s, dir
}

// entriesRange builds contiguous entries. | entriesRange 构建连续日志项。
func entriesRange(from, to, term uint64) []Entry {
	out := make([]Entry, 0, to-from+1)
	for i := from; i <= to; i++ {
		out = append(out, Entry{Index: i, Term: term, Type: EntryNormal, Data: []byte{byte(i)}})
	}
	return out
}

// TestFileStorageRoundTrip persists and reloads hard state and entries.
// | TestFileStorageRoundTrip 持久化并重新加载硬状态与日志项。
func TestFileStorageRoundTrip(t *testing.T) {
	s, dir := testFileStorage(t)
	hs := HardState{Term: 2, Vote: 1, Commit: 3}
	if err := s.Persist(PersistBatch{HardState: &hs, Entries: entriesRange(1, 3, 2)}); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rec, err := s2.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rec.HardState != hs {
		t.Fatalf("hard state = %+v", rec.HardState)
	}
	if len(rec.Entries) != 3 || rec.Entries[2].Index != 3 {
		t.Fatalf("entries = %+v", rec.Entries)
	}
}

// TestFileStorageTruncate replaces a conflicting suffix. | TestFileStorageTruncate
// 替换冲突后缀。
func TestFileStorageTruncate(t *testing.T) {
	s, dir := testFileStorage(t)
	if err := s.Persist(PersistBatch{Entries: entriesRange(1, 5, 1)}); err != nil {
		t.Fatal(err)
	}
	replacement := []Entry{{Index: 3, Term: 2, Type: EntryNormal, Data: []byte("x")}}
	hs := HardState{Term: 2}
	if err := s.Persist(PersistBatch{HardState: &hs, Truncate: 3, Entries: replacement}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rec, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Entries) != 3 || rec.Entries[2].Term != 2 || !bytes.Equal(rec.Entries[2].Data, []byte("x")) {
		t.Fatalf("entries = %+v", rec.Entries)
	}
}

// TestFileStorageSnapshotKeepsTail checks a local snapshot plus later entries.
// | TestFileStorageSnapshotKeepsTail 检查本地快照及其后的日志项。
func TestFileStorageSnapshotKeepsTail(t *testing.T) {
	s, dir := testFileStorage(t)
	if err := s.Persist(PersistBatch{Entries: entriesRange(1, 10, 1)}); err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 10, Term: 1, Data: []byte("state"),
		ConfState: ConfState{Voters: []NodeID{1}, Addresses: []Peer{{ID: 1}}}}
	if err := s.Persist(PersistBatch{Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	if err := s.Persist(PersistBatch{Entries: entriesRange(11, 12, 2)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rec, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || rec.Snapshot.Index != 10 || string(rec.Snapshot.Data) != "state" {
		t.Fatalf("snapshot = %+v", rec.Snapshot)
	}
	if len(rec.Entries) != 2 || rec.Entries[0].Index != 11 {
		t.Fatalf("entries = %+v", rec.Entries)
	}
}

// TestFileStorageInstallResetsLog drops stale entries on InstallSnapshot.
// | TestFileStorageInstallResetsLog 在 InstallSnapshot 时丢弃陈旧日志项。
func TestFileStorageInstallResetsLog(t *testing.T) {
	s, dir := testFileStorage(t)
	if err := s.Persist(PersistBatch{Entries: entriesRange(1, 10, 1)}); err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 20, Term: 4, Data: []byte("installed"),
		ConfState: ConfState{Voters: []NodeID{1, 2, 3}}}
	if err := s.Persist(PersistBatch{Snapshot: snap, SnapshotReplacesLog: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Persist(PersistBatch{Entries: entriesRange(21, 22, 4)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rec, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || rec.Snapshot.Index != 20 {
		t.Fatalf("snapshot = %+v", rec.Snapshot)
	}
	if len(rec.Entries) != 2 || rec.Entries[0].Index != 21 {
		t.Fatalf("entries = %+v", rec.Entries)
	}
}

// TestFileStorageCorruptTailTruncates recovers everything before a torn write.
// | TestFileStorageCorruptTailTruncates 恢复撕裂写之前的全部数据。
func TestFileStorageCorruptTailTruncates(t *testing.T) {
	s, dir := testFileStorage(t)
	if err := s.Persist(PersistBatch{Entries: entriesRange(1, 4, 1)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "wal", "*.wal"))
	if err != nil || len(files) == 0 {
		t.Fatalf("wal files: %v %v", files, err)
	}
	f, err := os.OpenFile(files[len(files)-1], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte{0xff}, 32)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	s2, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rec, err := s2.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rec.Entries) != 4 {
		t.Fatalf("entries = %d", len(rec.Entries))
	}
}

// TestFileStorageCorruptSnapshotFails checks integrity verification. | TestFileStorageCorruptSnapshotFails
// 检查完整性校验。
func TestFileStorageCorruptSnapshotFails(t *testing.T) {
	s, dir := testFileStorage(t)
	snap := &Snapshot{Index: 5, Term: 1, Data: []byte("payload"),
		ConfState: ConfState{Voters: []NodeID{1}}}
	if err := s.Persist(PersistBatch{Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "snapshots", "*.snap"))
	if err != nil || len(files) != 1 {
		t.Fatalf("snapshot files: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(files[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("load error = %v, want ErrCorrupt", err)
	}
}

// TestNodeSnapshotRestart verifies snapshot restore plus WAL tail replay.
// | TestNodeSnapshotRestart 验证快照还原与 WAL 尾部重放。
func TestNodeSnapshotRestart(t *testing.T) {
	dir := t.TempDir()
	start := func() (*Node, *kvFSM) {
		storage, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		fsm := newKVFSM()
		node, err := New(Config{
			ID: 1, Peers: []Peer{{ID: 1}}, Storage: storage, FSM: fsm,
			TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
			SnapshotEntries: 5,
		})
		if err != nil {
			t.Fatal(err)
		}
		return node, fsm
	}
	node, _ := start()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	var last Result
	for i := 0; i < 24; i++ {
		res, err := node.Propose(ctx, []byte(fmt.Sprintf("k%d=%d", i, i)))
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		last = res
	}
	if err := node.WaitApplied(ctx, last.Index); err != nil {
		t.Fatal(err)
	}
	waitSnapshot(t, node, 10*time.Second)
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	node2, fsm2 := start()
	defer node2.Close()
	if err := node2.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := node2.WaitApplied(ctx, last.Index); err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 5, 12, 23} {
		if got := fsm2.value(fmt.Sprintf("k%d", i)); got != strconv.Itoa(i) {
			t.Fatalf("k%d = %q", i, got)
		}
	}
	if node2.Status().SnapshotIndex == 0 {
		t.Fatal("restored node reports no snapshot")
	}
}

// TestNodeRestartWithFileStorage verifies end-to-end WAL recovery. | TestNodeRestartWithFileStorage
// 验证端到端 WAL 恢复。
func TestNodeRestartWithFileStorage(t *testing.T) {
	dir := t.TempDir()
	peers := []Peer{{ID: 1}}
	start := func() (*Node, *kvFSM) {
		storage, err := NewFileStorage(FileStorageOptions{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		fsm := newKVFSM()
		node, err := New(Config{
			ID: 1, Peers: peers, Storage: storage, FSM: fsm,
			TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		})
		if err != nil {
			t.Fatal(err)
		}
		return node, fsm
	}
	node, fsm := start()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	var last Result
	for i := 0; i < 10; i++ {
		res, err := node.Propose(ctx, []byte{byte('a' + i), '=', byte('0' + i)})
		if err != nil {
			t.Fatalf("propose: %v", err)
		}
		last = res
	}
	if err := node.WaitApplied(ctx, last.Index); err != nil {
		t.Fatal(err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	node2, fsm2 := start()
	defer node2.Close()
	if err := node2.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := node2.WaitApplied(ctx, last.Index); err != nil {
		t.Fatalf("wait applied after restart: %v", err)
	}
	if got := fsm.value("a"); got != "0" {
		t.Fatalf("original fsm a = %q", got)
	}
	if got := fsm2.value("j"); got != "9" {
		t.Fatalf("recovered fsm j = %q", got)
	}
}

// TestFileStorageSegmentRotation persists across many WAL segments and verifies
// that recovery reconstructs every entry and the latest hard state. | TestFileStorageSegmentRotation
// 跨越多个 WAL 分段持久化，并验证恢复能重建所有日志项与最新硬状态。
func TestFileStorageSegmentRotation(t *testing.T) {
	dir := t.TempDir()
	opts := FileStorageOptions{Dir: dir, NoSync: true, SegmentSize: 256}
	s, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 1}
	data := bytes.Repeat([]byte{'x'}, 64)
	for i := 1; i <= 200; i++ {
		hs.Commit = uint64(i)
		entry := Entry{Index: uint64(i), Term: 1, Type: EntryNormal, Data: data}
		if err := s.Persist(PersistBatch{HardState: &hs, Entries: []Entry{entry}}); err != nil {
			t.Fatalf("persist %d: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "wal", "*.wal"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("WAL segments = %d, want at least 2", len(files))
	}
	s2, err := NewFileStorage(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rec, err := s2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Entries) != 200 {
		t.Fatalf("recovered %d entries, want 200", len(rec.Entries))
	}
	for i, entry := range rec.Entries {
		if entry.Index != uint64(i+1) {
			t.Fatalf("entry %d index = %d", i, entry.Index)
		}
	}
	if rec.HardState.Commit != 200 {
		t.Fatalf("commit = %d, want 200", rec.HardState.Commit)
	}
}

// TestNodePersistBatchDelay exercises the durable group-commit window with a
// real FileStorage. | TestNodePersistBatchDelay 使用真实 FileStorage 覆盖持久化
// 组提交窗口。
func TestNodePersistBatchDelay(t *testing.T) {
	dir := t.TempDir()
	storage, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	fsm := newKVFSM()
	node, err := New(Config{
		ID:                1,
		Storage:           storage,
		FSM:               fsm,
		TickInterval:      5 * time.Millisecond,
		HeartbeatTicks:    1,
		ElectionTicks:     8,
		PersistBatchDelay: 100 * time.Microsecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := node.Propose(ctx, []byte(fmt.Sprintf("k%d=%d", i, i))); err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
	}
	if got := fsm.value("k19"); got != "19" {
		t.Fatalf("value = %q", got)
	}
}
