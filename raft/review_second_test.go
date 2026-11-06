package raft

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// frameLimitedTransport reports a frame limit without sending anything.
// | frameLimitedTransport 只报告帧上限，不发送任何消息。
type frameLimitedTransport struct{ limit int64 }

func (t frameLimitedTransport) Start(func(Message)) error             { return nil }
func (t frameLimitedTransport) Send(context.Context, []Message) error { return nil }
func (t frameLimitedTransport) UpdatePeer(NodeID, string)             {}
func (t frameLimitedTransport) Close() error                          { return nil }
func (t frameLimitedTransport) FrameLimit() int64                     { return t.limit }

// TestNetworkMsgHupIgnored verifies a peer cannot trigger an election through
// the public Step entry point. | TestNetworkMsgHupIgnored 验证对端无法通过公开的
// Step 入口触发选举。
func TestNetworkMsgHupIgnored(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	var follower *Node
	for id, node := range c.nodes {
		if id != leader.ID() {
			follower = node
			break
		}
	}
	if follower == nil {
		t.Fatal("no follower")
	}
	term := follower.Term()
	state := follower.State()
	follower.Step(Message{Type: MsgHup, From: leader.ID(), To: follower.ID()})
	time.Sleep(50 * time.Millisecond)
	if follower.Term() != term || follower.State() != state {
		t.Fatalf("remote MsgHup changed follower: term %d->%d state %s->%s",
			term, follower.Term(), state, follower.State())
	}
}

// TestLeaseReadRequiresPreVoteAndNoTransfer verifies lease reads are disabled
// when pre-vote is off or a leadership transfer is in progress.
// | TestLeaseReadRequiresPreVoteAndNoTransfer 验证关闭预投票或领导权转移期间禁用
// 租约读。
func TestLeaseReadRequiresPreVoteAndNoTransfer(t *testing.T) {
	n := &Node{
		state:          StateLeader,
		termStartIndex: 1,
		committed:      2,
		leaseUntil:     time.Now().Add(time.Second),
		cfg:            Config{DisablePreVote: true},
	}
	if n.leaseValid() {
		t.Fatal("lease valid with pre-vote disabled")
	}
	n.cfg.DisablePreVote = false
	if !n.leaseValid() {
		t.Fatal("lease invalid with pre-vote enabled")
	}
	n.leadTransferee = 2
	if n.leaseValid() {
		t.Fatal("lease valid during leadership transfer")
	}
}

// blockingSnapshotStorage blocks the snapshot file writer so a test can prove
// WAL proposals continue while the image fsync is in flight. |
// blockingSnapshotStorage 阻塞快照文件写入，用于证明镜像 fsync 期间 WAL 提案仍可
// 继续。
type blockingSnapshotStorage struct {
	*FileStorage
	started chan struct{}
	release chan struct{}
}

func (s *blockingSnapshotStorage) WriteSnapshotFile(snap *Snapshot) error {
	close(s.started)
	<-s.release
	return s.FileStorage.WriteSnapshotFile(snap)
}

// TestAsyncSnapshotDoesNotBlockProposals verifies a local snapshot file write is
// off the WAL persist path. | TestAsyncSnapshotDoesNotBlockProposals 验证本地快照
// 文件写入不在 WAL 持久化关键路径上。
func TestAsyncSnapshotDoesNotBlockProposals(t *testing.T) {
	fs, err := NewFileStorage(FileStorageOptions{Dir: t.TempDir(), NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	gate := &blockingSnapshotStorage{
		FileStorage: fs,
		started:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	node, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: gate, FSM: newKVFSM(),
		TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := node.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Propose(ctx, []byte("a=1")); err != nil {
		t.Fatal(err)
	}
	snapshotDone := make(chan error, 1)
	go func() { snapshotDone <- node.Snapshot(ctx) }()
	select {
	case <-gate.started:
	case <-ctx.Done():
		t.Fatal("snapshot file writer did not start")
	}
	// WAL persistence must still make progress while the image is blocked.
	res, err := node.Propose(ctx, []byte("b=2"))
	if err != nil {
		t.Fatalf("propose during snapshot: %v", err)
	}
	if err := node.WaitApplied(ctx, res.Index); err != nil {
		t.Fatalf("apply during snapshot: %v", err)
	}
	close(gate.release)
	select {
	case err := <-snapshotDone:
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("snapshot did not finish")
	}
}

// gateStorage delegates to MemStorage and blocks selected Persist calls after
// the in-memory write, simulating a slow fsync without changing durability.
// | gateStorage 委托 MemStorage，并在内存写入后阻塞指定的 Persist 调用，模拟慢
// fsync 而不改变持久性。
type gateStorage struct {
	inner   *MemStorage
	release chan struct{}
	calls   atomic.Int64
	blockAt int64
}

func (g *gateStorage) Load() (Recovery, error) { return g.inner.Load() }
func (g *gateStorage) Persist(batch PersistBatch) error {
	err := g.inner.Persist(batch)
	if g.calls.Add(1) >= g.blockAt {
		<-g.release
	}
	return err
}
func (g *gateStorage) Compact(index uint64) error { return g.inner.Compact(index) }
func (g *gateStorage) Close() error               { return g.inner.Close() }

// TestReadIndexWaitsForCurrentTermCommit verifies ReadIndex is parked until
// the new leader commits its no-op, so it cannot return a stale commit index.
// | TestReadIndexWaitsForCurrentTermCommit 验证 ReadIndex 会等到新领导者提交
// no-op，避免返回过期提交索引。
func TestReadIndexWaitsForCurrentTermCommit(t *testing.T) {
	gate := &gateStorage{
		inner:   NewMemStorage(),
		release: make(chan struct{}),
		blockAt: 3, // bootstrap, campaign hard state, then leader no-op
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	node, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: gate, FSM: newKVFSM(),
		TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		release()
		t.Fatal(err)
	}
	defer node.Close()
	defer release()
	deadline := time.Now().Add(3 * time.Second)
	for node.State() != StateLeader && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if node.State() != StateLeader {
		t.Fatal("node did not become leader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		index uint64
		err   error
	}
	done := make(chan result, 1)
	go func() {
		index, err := node.ReadIndex(ctx)
		done <- result{index, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("ReadIndex returned before current-term commit: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case r := <-done:
		if r.err != nil || r.index < 2 {
			t.Fatalf("ReadIndex = %d, %v; want index >= 2", r.index, r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadIndex did not resume after current-term commit")
	}
}

// TestCandidateWaitsForDurableSelfVote verifies a candidate with a quorum of
// remote grants cannot become leader until its own vote is durable.
// | TestCandidateWaitsForDurableSelfVote 验证已有远端多数授权的候选者在自投票
// 持久化前不能成为领导者。
func TestCandidateWaitsForDurableSelfVote(t *testing.T) {
	n := &Node{
		state: StateCandidate,
		conf:  newMembership([]NodeID{1}, nil, nil),
		votes: map[NodeID]bool{1: true},
	}
	n.maybeBecomeLeader()
	if n.state != StateCandidate {
		t.Fatalf("state = %v before self vote durability", n.state)
	}
}

// TestForwardedReadRejectsStaleResponse verifies a response from another term,
// leader or process epoch cannot complete a forwarded read.
// | TestForwardedReadRejectsStaleResponse 验证其他任期、领导者或进程纪元的响应不能
// 完成转发读。
func TestForwardedReadRejectsStaleResponse(t *testing.T) {
	n := &Node{
		term:        5,
		leader:      2,
		remoteEpoch: 42,
		remoteReads: newRemoteReadStore(),
	}
	ch := n.remoteReads.add(1)
	n.handleReadIndexResp(Message{Type: MsgReadIndexResp, From: 3, Term: 5,
		Index: 9, Context: encodeRemoteReadContext(42, 1)})
	n.handleReadIndexResp(Message{Type: MsgReadIndexResp, From: 2, Term: 4,
		Index: 9, Context: encodeRemoteReadContext(42, 1)})
	n.handleReadIndexResp(Message{Type: MsgReadIndexResp, From: 2, Term: 5,
		Index: 9, Context: encodeRemoteReadContext(41, 1)})
	select {
	case r := <-ch:
		t.Fatalf("stale response completed read: %+v", r)
	default:
	}
	n.handleReadIndexResp(Message{Type: MsgReadIndexResp, From: 2, Term: 5,
		Index: 9, Context: encodeRemoteReadContext(42, 1)})
	select {
	case r := <-ch:
		if r.err != nil || r.index != 9 {
			t.Fatalf("valid response = %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("valid response did not complete read")
	}
}

// TestWALKeepsHardStateOnlySegment verifies compaction never deletes a segment
// whose only record is a newer hard state, which would let recovery reuse an
// older term or vote. | TestWALKeepsHardStateOnlySegment 验证压缩不会删除仅含更新
// 硬状态的分段，否则恢复会复用更旧的任期或选票。
func TestWALKeepsHardStateOnlySegment(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true, SegmentSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	term1 := HardState{Term: 1, Commit: 1}
	if err := s.Persist(PersistBatch{HardState: &term1,
		Entries: []Entry{{Index: 1, Term: 1, Type: EntryNormal}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.wal.rotateLocked(); err != nil {
		t.Fatal(err)
	}
	term7 := HardState{Term: 7, Vote: 2, Commit: 1}
	if err := s.Persist(PersistBatch{HardState: &term7}); err != nil {
		t.Fatal(err)
	}
	if err := s.wal.rotateLocked(); err != nil {
		t.Fatal(err)
	}
	if err := s.wal.compact(1); err != nil {
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
	if rec.HardState.Term != 7 || rec.HardState.Vote != 2 {
		t.Fatalf("hard state = %+v, want term 7 vote 2", rec.HardState)
	}
}

// TestFileStorageSingleScanRecovery verifies multiple snapshot markers and WAL
// tails recover correctly with the merged one-pass scanner. | TestFileStorageSingleScanRecovery
// 验证多个快照标记与 WAL 尾部在合并的单遍扫描下正确恢复。
func TestFileStorageSingleScanRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true, SegmentSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	persist := func(batch PersistBatch) {
		t.Helper()
		if err := s.Persist(batch); err != nil {
			t.Fatal(err)
		}
	}
	persist(PersistBatch{Entries: entriesRange(1, 10, 1)})
	persist(PersistBatch{Snapshot: &Snapshot{Index: 5, Term: 1,
		ConfState: ConfState{Voters: []NodeID{1}}, Data: []byte("five")}})
	persist(PersistBatch{Entries: entriesRange(11, 20, 1)})
	persist(PersistBatch{Snapshot: &Snapshot{Index: 15, Term: 1,
		ConfState: ConfState{Voters: []NodeID{1}}, Data: []byte("fifteen")}})
	persist(PersistBatch{Entries: entriesRange(21, 30, 2)})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true, SegmentSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rec, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || rec.Snapshot.Index != 15 || string(rec.Snapshot.Data) != "fifteen" {
		t.Fatalf("snapshot = %+v", rec.Snapshot)
	}
	if len(rec.Entries) != 15 || rec.Entries[0].Index != 16 || rec.Entries[14].Index != 30 {
		t.Fatalf("entries = %d first=%d last=%d", len(rec.Entries),
			rec.Entries[0].Index, rec.Entries[len(rec.Entries)-1].Index)
	}
}

// TestMemStorageIgnoresOlderSnapshot verifies a delayed older image cannot
// regress the in-memory base. | TestMemStorageIgnoresOlderSnapshot 验证迟到的更旧
// 镜像不会回退内存基点。
func TestMemStorageIgnoresOlderSnapshot(t *testing.T) {
	s := NewMemStorage()
	if err := s.Persist(PersistBatch{Snapshot: &Snapshot{Index: 10, Term: 2, Data: []byte("new")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Persist(PersistBatch{Snapshot: &Snapshot{Index: 5, Term: 1, Data: []byte("old")}}); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Snapshot == nil || rec.Snapshot.Index != 10 || string(rec.Snapshot.Data) != "new" {
		t.Fatalf("snapshot after older persist = %+v", rec.Snapshot)
	}
}

// TestFileStorageExclusiveLock verifies a second writer cannot open the same
// directory and that closing releases the lock. | TestFileStorageExclusiveLock
// 验证第二个写入者无法打开同一目录，且关闭后释放锁。
func TestFileStorageExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	first, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true}); !errors.Is(err, ErrStorageLocked) {
		t.Fatalf("second open error = %v, want ErrStorageLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestSnapshotFrameLimitReported verifies an unsendable snapshot is exposed in
// status instead of being retried silently. | TestSnapshotFrameLimitReported
// 验证无法发送的快照会暴露在状态中，而不是静默重试。
func TestSnapshotFrameLimitReported(t *testing.T) {
	pr := newProgress(1, 8, 1<<20)
	n := &Node{
		id:             1,
		state:          StateLeader,
		term:           2,
		metrics:        newMetrics(),
		log:            &raftLog{firstIndex: 1, lastIndex: 10},
		latestSnapshot: &Snapshot{Index: 5, Term: 1, Data: make([]byte, 1024)},
		progress:       map[NodeID]*progress{2: pr},
		transport:      frameLimitedTransport{limit: 128},
	}
	n.sendSnapshot(2)
	if pr.snapshotErr == nil || !errors.Is(pr.snapshotErr, ErrTooLarge) {
		t.Fatalf("snapshot error = %v, want ErrTooLarge", pr.snapshotErr)
	}
	if pr.state != snapshot || pr.pendingSnapshot != 5 {
		t.Fatalf("progress state=%v pending=%d", pr.state, pr.pendingSnapshot)
	}
	// A second call inside the retry window must not enqueue the image again.
	n.sendSnapshot(2)
	if pr.snapshotErrIndex != 5 {
		t.Fatalf("snapshot error index = %d", pr.snapshotErrIndex)
	}
}

// TestSnapshotCatchUpWithoutInstall verifies a follower within the catch-up
// window replays retained entries instead of receiving a snapshot.
// | TestSnapshotCatchUpWithoutInstall 验证处于追赶窗口内的跟随者重放保留日志项，
// 而不是接收快照。
func TestSnapshotCatchUpWithoutInstall(t *testing.T) {
	c := newTestCluster(t, 3, func(cfg *Config) {
		cfg.SnapshotEntries = 5
		cfg.SnapshotCatchUpEntries = 4096
	})
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var last Result
	for i := 0; i < 40; i++ {
		res, err := leader.Propose(ctx, []byte(fmt.Sprintf("k%d=%d", i, i)))
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		last = res
	}
	waitSnapshot(t, leader, 10*time.Second)
	c.addNode(4, true)
	if err := leader.AddLearner(ctx, 4, ""); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	c.waitApplied(4, last.Index, 15*time.Second)
	// The learner may still take its own local snapshot; only an InstallSnapshot
	// received from the leader would mean the catch-up window did not work.
	// | 学习者仍可能自行创建本地快照；只有从领导者收到 InstallSnapshot 才说明追赶
	// 窗口未生效。
	if got := c.nodes[4].metrics.snapshotsApplied.Load(); got != 0 {
		t.Fatalf("learner applied %d install snapshots, want entry replay", got)
	}
	if got := c.fsms[4].value("k39"); got != "39" {
		t.Fatalf("learner value = %q", got)
	}
}
