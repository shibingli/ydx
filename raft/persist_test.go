package raft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// markerBatchStorage records which persistence entry point the event loop uses
// for a deferred local snapshot marker. | markerBatchStorage 记录事件循环为延迟
// 本地快照标记使用哪个持久化入口。
type markerBatchStorage struct {
	*MemStorage
	markerCalls int
	batchCalls  int
	persistHits int
	lastBatch   PersistBatch
	lastSnap    *Snapshot
}

func newMarkerBatchStorage() *markerBatchStorage {
	return &markerBatchStorage{MemStorage: NewMemStorage()}
}

func (s *markerBatchStorage) WriteSnapshotFile(snap *Snapshot) error { return nil }

func (s *markerBatchStorage) PersistLocalSnapshotMarker(snap *Snapshot, hs *HardState) error {
	s.markerCalls++
	return s.MemStorage.Persist(PersistBatch{HardState: hs,
		Snapshot: &Snapshot{Index: snap.Index, Term: snap.Term}})
}

func (s *markerBatchStorage) PersistLocalSnapshotMarkerBatch(snap *Snapshot, batch PersistBatch) error {
	s.batchCalls++
	s.lastSnap = snap
	s.lastBatch = batch
	batch.Snapshot = &Snapshot{Index: snap.Index, Term: snap.Term}
	return s.MemStorage.Persist(batch)
}

func (s *markerBatchStorage) Persist(batch PersistBatch) error {
	s.persistHits++
	return s.MemStorage.Persist(batch)
}

// TestSnapshotMarkerMergesWithFollowingWALBatch verifies the marker for a local
// snapshot does not force its own fsync when a contiguous WAL batch is already
// queued behind it. | TestSnapshotMarkerMergesWithFollowingWALBatch 验证本地快照
// 标记在后方已有连续 WAL 批次排队时不再单独触发一次 fsync。
func TestSnapshotMarkerMergesWithFollowingWALBatch(t *testing.T) {
	st := newMarkerBatchStorage()
	n := &Node{storage: st, metrics: newMetrics(), persistAckCh: make(chan persistAck, 8)}
	marker := &persistRequest{
		seq:        1,
		compact:    10,
		markerOnly: true,
		batch: PersistBatch{
			HardState: &HardState{Term: 2, Commit: 10},
			Snapshot:  &Snapshot{Index: 10, Term: 2},
		},
	}
	entries := &persistRequest{
		seq: 2,
		batch: PersistBatch{
			HardState: &HardState{Term: 2, Commit: 11},
			Entries:   []Entry{{Index: 11, Term: 2, Type: EntryNormal, Data: []byte("x")}},
		},
	}
	n.processPersistReqs([]*persistRequest{marker, entries})
	if st.batchCalls != 1 {
		t.Fatalf("combined marker batches = %d, want 1", st.batchCalls)
	}
	if st.markerCalls != 0 || st.persistHits != 0 {
		t.Fatalf("separate marker=%d persist=%d, want 0/0", st.markerCalls, st.persistHits)
	}
	if st.lastSnap == nil || st.lastSnap.Index != 10 {
		t.Fatalf("marker snapshot = %+v", st.lastSnap)
	}
	if len(st.lastBatch.Entries) != 1 || st.lastBatch.Entries[0].Index != 11 {
		t.Fatalf("merged entries = %+v", st.lastBatch.Entries)
	}
	if st.lastBatch.HardState == nil || st.lastBatch.HardState.Commit != 11 {
		t.Fatalf("merged hard state = %+v", st.lastBatch.HardState)
	}
	select {
	case ack := <-n.persistAckCh:
		if ack.maxSeq != 2 || ack.err != nil {
			t.Fatalf("ack = %+v, want seq 2 success", ack)
		}
	default:
		t.Fatal("no persist ack")
	}
}

// TestSnapshotMarkerDoesNotMergeAcrossGap verifies a WAL request whose first
// entry does not immediately follow the snapshot base keeps its own record; the
// combined record must preserve contiguous WAL entry encoding. |
// TestSnapshotMarkerDoesNotMergeAcrossGap 验证首条日志项不紧接快照基点的 WAL 请求
// 保持独立记录；合并记录必须保持 WAL 日志项的连续编码。
func TestSnapshotMarkerDoesNotMergeAcrossGap(t *testing.T) {
	st := newMarkerBatchStorage()
	n := &Node{storage: st, metrics: newMetrics(), persistAckCh: make(chan persistAck, 8)}
	marker := &persistRequest{
		seq:        1,
		compact:    10,
		markerOnly: true,
		batch: PersistBatch{
			HardState: &HardState{Term: 2, Commit: 10},
			Snapshot:  &Snapshot{Index: 10, Term: 2},
		},
	}
	entries := &persistRequest{
		seq: 2,
		batch: PersistBatch{
			Entries: []Entry{{Index: 12, Term: 2, Type: EntryNormal}},
		},
	}
	n.processPersistReqs([]*persistRequest{marker, entries})
	if st.batchCalls != 0 {
		t.Fatalf("combined marker batches = %d, want 0 across a gap", st.batchCalls)
	}
	if st.markerCalls != 1 || st.persistHits != 1 {
		t.Fatalf("separate marker=%d persist=%d, want 1/1", st.markerCalls, st.persistHits)
	}
}

// TestAdaptivePersistWindow verifies the group-commit window grows with observed
// fsync latency and queue depth, and stays disabled by default. |
// TestAdaptivePersistWindow 验证组提交窗口随实测 fsync 延迟与队列深度增长，且默认
// 关闭。
func TestAdaptivePersistWindow(t *testing.T) {
	n := &Node{cfg: Config{PersistBatchDelay: 100 * time.Microsecond},
		persistNotify: make(chan struct{}, 1)}
	if got := n.persistWindow(); got != 100*time.Microsecond {
		t.Fatalf("base window = %v, want 100us", got)
	}
	n.persistLatency.Store(int64(900 * time.Microsecond))
	if got := n.persistWindow(); got < 400*time.Microsecond {
		t.Fatalf("latency-adaptive window = %v, want >= 400us", got)
	}
	for i := 0; i < 10; i++ {
		n.enqueuePersist(&persistRequest{seq: uint64(i + 1)})
	}
	withDepth := n.persistWindow()
	if withDepth <= 400*time.Microsecond || withDepth > 5*time.Millisecond {
		t.Fatalf("queue-adaptive window = %v", withDepth)
	}
	for i := 0; i < 40; i++ {
		n.enqueuePersist(&persistRequest{seq: uint64(i + 100)})
	}
	if got := n.persistWindow(); got < withDepth || got > 5*time.Millisecond {
		t.Fatalf("deep queue window = %v, want between %v and 5ms", got, withDepth)
	}
	disabled := &Node{cfg: Config{}, persistNotify: make(chan struct{}, 1)}
	disabled.persistLatency.Store(int64(time.Millisecond))
	if got := disabled.persistWindow(); got != 0 {
		t.Fatalf("disabled window = %v, want 0", got)
	}
	largeBase := &Node{cfg: Config{PersistBatchDelay: 10 * time.Millisecond},
		persistNotify: make(chan struct{}, 1)}
	largeBase.persistLatency.Store(int64(time.Millisecond))
	if got := largeBase.persistWindow(); got != 10*time.Millisecond {
		t.Fatalf("large base window = %v, want 10ms", got)
	}
}

// TestFileStorageSeparateSnapshotDir verifies snapshot images and WAL segments
// can live on different volumes while recovery still correlates them. |
// TestFileStorageSeparateSnapshotDir 验证快照镜像与 WAL 分段可位于不同卷，恢复仍能
// 正确关联。
func TestFileStorageSeparateSnapshotDir(t *testing.T) {
	root := t.TempDir()
	snapDir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: root, SnapshotDir: snapDir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 4, Term: 2, ConfState: ConfState{Voters: []NodeID{1}}, Data: []byte("four")}
	if err := s.Persist(PersistBatch{Snapshot: snap, HardState: &HardState{Term: 2, Commit: 4}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".snap") {
			found = true
		}
	}
	if !found {
		t.Fatal("snapshot image not written to SnapshotDir")
	}
	if _, err := os.Stat(filepath.Join(root, "snapshots")); !os.IsNotExist(err) {
		t.Fatalf("default snapshot directory unexpectedly used: %v", err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: root, SnapshotDir: snapDir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || rec.Snapshot.Index != 4 || string(rec.Snapshot.Data) != "four" {
		t.Fatalf("snapshot = %+v", rec.Snapshot)
	}
}

// TestFileStorageMergedSnapshotMarkerRecovery verifies a marker written in the
// same WAL record as following entries recovers both the image base and the tail.
// | TestFileStorageMergedSnapshotMarkerRecovery 验证与后续日志项写入同一条 WAL
// 记录的标记可在恢复时同时得到镜像基点与日志尾部。
func TestFileStorageMergedSnapshotMarkerRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{Index: 10, Term: 2, ConfState: ConfState{Voters: []NodeID{1}}, Data: []byte("ten")}
	if err := s.WriteSnapshotFile(snap); err != nil {
		t.Fatal(err)
	}
	hs := HardState{Term: 2, Commit: 12}
	if err := s.PersistLocalSnapshotMarkerBatch(snap, PersistBatch{
		HardState: &hs,
		Entries: []Entry{
			{Index: 11, Term: 2, Type: EntryNormal, Data: []byte("a")},
			{Index: 12, Term: 2, Type: EntryNormal, Data: []byte("b")},
		},
	}); err != nil {
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
	if rec.Snapshot == nil || rec.Snapshot.Index != 10 || string(rec.Snapshot.Data) != "ten" {
		t.Fatalf("snapshot = %+v", rec.Snapshot)
	}
	if len(rec.Entries) != 2 || rec.Entries[0].Index != 11 || rec.Entries[1].Index != 12 {
		t.Fatalf("entries = %+v", rec.Entries)
	}
	if rec.HardState.Commit != 12 {
		t.Fatalf("hard state = %+v", rec.HardState)
	}
}
