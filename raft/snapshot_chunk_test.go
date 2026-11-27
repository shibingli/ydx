package raft

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chunkRecordingTransport records messages passed to Send. |
// chunkRecordingTransport 记录传给 Send 的消息。
type chunkRecordingTransport struct {
	msgs []Message
}

func (t *chunkRecordingTransport) Start(func(Message)) error { return nil }
func (t *chunkRecordingTransport) Send(_ context.Context, msgs []Message) error {
	t.msgs = append(t.msgs, msgs...)
	return nil
}
func (t *chunkRecordingTransport) UpdatePeer(NodeID, string) {}
func (t *chunkRecordingTransport) Close() error              { return nil }

// TestChunkedSnapshotTransfer verifies a learner whose snapshot exceeds the
// configured chunk size catches up through ack-gated snapshot chunks instead of
// one whole-image message. | TestChunkedSnapshotTransfer 验证快照超过配置分块大小时，
// 学习者通过逐块确认的快照分块追赶，而不是单条整镜像消息。
func TestChunkedSnapshotTransfer(t *testing.T) {
	c := newTestCluster(t, 3, func(cfg *Config) {
		cfg.SnapshotEntries = 5
		cfg.SnapshotCatchUpEntries = 1
		cfg.SnapshotChunkBytes = 64
	})
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	var last Result
	for i := 0; i < 30; i++ {
		res, err := leader.Propose(ctx, append([]byte(fmt.Sprintf("k%d=", i)), payload...))
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
	c.waitApplied(4, last.Index, 20*time.Second)
	if got := c.fsms[4].value("k29"); string(got) != string(payload) {
		t.Fatalf("learner value length = %d, want %d", len(got), len(payload))
	}
	if got := leader.metrics.snapshotChunksOut.Load(); got == 0 {
		t.Fatal("leader did not send chunked snapshot messages")
	}
	if got := c.nodes[4].metrics.snapshotChunksIn.Load(); got == 0 {
		t.Fatal("learner did not receive chunked snapshot messages")
	}
	if got := c.nodes[4].metrics.snapshotsApplied.Load(); got != 1 {
		t.Fatalf("learner applied %d snapshots, want 1", got)
	}
}

// TestChunkedSnapshotSenderState verifies chunk offsets, acknowledgements,
// stale-response rejection and the final liveness probe. |
// TestChunkedSnapshotSenderState 验证分块偏移、确认、过期响应拒绝以及最终存活探测。
func TestChunkedSnapshotSenderState(t *testing.T) {
	transport := &chunkRecordingTransport{}
	snap := &Snapshot{Index: 5, Term: 1, Data: make([]byte, 200)}
	pr := newProgress(6, 4, 1<<20)
	n := &Node{
		id: 1, state: StateLeader, term: 1, transport: transport,
		immediateTransport: true, metrics: newMetrics(),
		progress:           map[NodeID]*progress{2: pr},
		latestSnapshot:     snap,
		snapshotChunkBytes: 64,
	}
	n.sendSnapshot(2)
	if len(transport.msgs) != 1 {
		t.Fatalf("first send count = %d, want 1", len(transport.msgs))
	}
	first := transport.msgs[0]
	if first.Type != MsgSnapChunk || first.LogIndex != 0 || first.LogTerm != 200 ||
		len(first.Snapshot.Data) != 64 {
		t.Fatalf("first chunk = type %v offset %d total %d size %d",
			first.Type, first.LogIndex, first.LogTerm, len(first.Snapshot.Data))
	}
	// A retry before any acknowledgement resends the same offset. |
	// 未收到任何确认前的重试会重发同一偏移。
	pr.snapshotSentAt = time.Now().Add(-2 * snapshotRetryInterval)
	n.sendSnapshot(2)
	if len(transport.msgs) != 2 || transport.msgs[1].LogIndex != 0 {
		t.Fatalf("retry offset = %d", transport.msgs[len(transport.msgs)-1].LogIndex)
	}
	// A stale acknowledgement with the wrong echoed offset is ignored. |
	// 回显偏移不匹配的过期确认会被忽略。
	before := len(transport.msgs)
	n.handleSnapshotChunkResp(&Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 64, LogIndex: 99, Commit: 5})
	if len(transport.msgs) != before {
		t.Fatal("stale chunk acknowledgement advanced the sender")
	}
	// Valid acknowledgements advance one chunk at a time. | 合法确认逐块推进。
	n.handleSnapshotChunkResp(&Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 64, LogIndex: 0, Commit: 5})
	if got := transport.msgs[len(transport.msgs)-1]; got.LogIndex != 64 || len(got.Snapshot.Data) != 64 {
		t.Fatalf("second chunk offset=%d size=%d", got.LogIndex, len(got.Snapshot.Data))
	}
	n.handleSnapshotChunkResp(&Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 128, LogIndex: 64, Commit: 5})
	if got := transport.msgs[len(transport.msgs)-1]; got.LogIndex != 128 || len(got.Snapshot.Data) != 64 {
		t.Fatalf("third chunk offset=%d size=%d", got.LogIndex, len(got.Snapshot.Data))
	}
	n.handleSnapshotChunkResp(&Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 192, LogIndex: 128, Commit: 5})
	if got := transport.msgs[len(transport.msgs)-1]; got.LogIndex != 192 || len(got.Snapshot.Data) != 8 {
		t.Fatalf("last chunk offset=%d size=%d", got.LogIndex, len(got.Snapshot.Data))
	}
	n.handleSnapshotChunkResp(&Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 200, LogIndex: 192, Commit: 5})
	if pr.snapshotOffset != 200 {
		t.Fatalf("final offset = %d", pr.snapshotOffset)
	}
	// With the final chunk acknowledged, a retry sends a zero-length probe
	// carrying the total offset. | 最后一块确认后，重试发送携带总偏移的零长度探测。
	pr.snapshotSentAt = time.Now().Add(-2 * snapshotRetryInterval)
	n.sendSnapshot(2)
	last := transport.msgs[len(transport.msgs)-1]
	if last.Type != MsgSnapChunk || last.LogIndex != 200 || len(last.Snapshot.Data) != 0 {
		t.Fatalf("probe = type %v offset %d size %d", last.Type, last.LogIndex, len(last.Snapshot.Data))
	}
}

// TestChunkedFileBackedSnapshotTransfer verifies a streaming, file-backed
// leader image reaches a learner through chunk messages without materializing
// the whole payload in the leader's heap. | TestChunkedFileBackedSnapshotTransfer
// 验证流式、文件支持的领导者镜像通过分块消息到达学习者，且领导者堆中不物化完整负载。
func TestChunkedFileBackedSnapshotTransfer(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	net := NewMemNetwork()
	t.Cleanup(net.Close)
	tr1, err := net.NewTransport(1)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := net.NewTransport(2)
	if err != nil {
		t.Fatal(err)
	}
	leaderFSM := newStreamingKVFSM()
	leader, err := New(Config{
		ID: 1, Peers: []Peer{{ID: 1}}, Storage: fs, FSM: leaderFSM, Transport: tr1,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		SnapshotEntries: 5, SnapshotCatchUpEntries: 1, SnapshotChunkBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leader.Close() })
	learnerFSM := newKVFSM()
	learner, err := New(Config{
		ID: 2, Join: true, Storage: NewMemStorage(), FSM: learnerFSM, Transport: tr2,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		SnapshotChunkBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = learner.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := leader.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 180)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	var last Result
	for i := 0; i < 20; i++ {
		res, err := leader.Propose(ctx, append([]byte(fmt.Sprintf("f%d=", i)), payload...))
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		last = res
	}
	waitSnapshot(t, leader, 10*time.Second)
	if err := leader.AddLearner(ctx, 2, ""); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	if err := learner.WaitApplied(ctx, last.Index); err != nil {
		t.Fatalf("learner apply: %v", err)
	}
	if got := learnerFSM.value("f19"); string(got) != string(payload) {
		t.Fatalf("learner value length = %d, want %d", len(got), len(payload))
	}
	if got := leader.metrics.snapshotChunksOut.Load(); got == 0 {
		t.Fatal("leader sent no file-backed snapshot chunks")
	}
	if got := learner.metrics.snapshotChunksIn.Load(); got == 0 {
		t.Fatal("learner received no file-backed snapshot chunks")
	}
}

// TestSnapshotChunkDataReadsFile verifies chunk reads for a file-backed
// streaming snapshot seek directly into the image payload. |
// TestSnapshotChunkDataReadsFile 验证文件支持的流式快照分块读取直接定位到镜像负载。
func TestSnapshotChunkDataReadsFile(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	snap := &Snapshot{Index: 9, Term: 2, ConfState: ConfState{Voters: []NodeID{1}}, Data: data}
	if err := fs.WriteSnapshotFile(snap); err != nil {
		t.Fatal(err)
	}
	snap.Data = nil
	n := &Node{storage: fs}
	got, err := n.snapshotChunkData(snap, 100, 37)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data[100:137]) {
		t.Fatalf("chunk mismatch at 100: %x", got)
	}
	if size := n.snapshotSize(snap); size != int64(len(data)) {
		t.Fatalf("snapshot size = %d, want %d", size, len(data))
	}
}

// TestSnapshotReceiveCap rejects a chunk whose declared total exceeds the
// configured install budget before allocating the image. |
// TestSnapshotReceiveCap 在分配镜像前拒绝声明总大小超过配置安装预算的分块。
func TestSnapshotReceiveCap(t *testing.T) {
	n := &Node{id: 1, maxSnapshotReceive: 16, metrics: newMetrics()}
	n.handleSnapshotChunk(&Message{
		Type: MsgSnapChunk, From: 2, To: 1, Term: 1,
		LogIndex: 0, LogTerm: 32,
		Snapshot: &Snapshot{Index: 1, Term: 1},
	})
	if len(n.outBuf) != 1 || n.outBuf[0].Type != MsgSnapResp || !n.outBuf[0].Reject {
		t.Fatalf("rejection = %+v", n.outBuf)
	}
}

// TestSnapshotInstallSlots bounds concurrent chunked reassembly and releases a
// discarded partial image. | TestSnapshotInstallSlots 限制并发分块重组，并在丢弃
// 部分镜像时释放名额。
func TestSnapshotInstallSlots(t *testing.T) {
	n := &Node{id: 1, cfg: Config{snapshotSlots: make(chan struct{}, 1)}}
	if !n.acquireSnapshotSlot() {
		t.Fatal("first slot not acquired")
	}
	if n.acquireSnapshotSlot() {
		t.Fatal("second slot acquired past the limit")
	}
	n.incomingSnapshot = &incomingSnapshot{slot: true}
	n.discardIncomingSnapshot()
	if !n.acquireSnapshotSlot() {
		t.Fatal("slot not released by discard")
	}
	n.releaseSnapshotSlot()
}

// TestNodeHostSnapshotInstallLimit wires the host limit into every group. |
// TestNodeHostSnapshotInstallLimit 将主机级上限接入每个组。
func TestNodeHostSnapshotInstallLimit(t *testing.T) {
	net := NewMemNetwork()
	defer net.Close()
	tr, err := net.NewTransport(1)
	if err != nil {
		t.Fatal(err)
	}
	host, err := NewNodeHost(NodeHostConfig{
		ID: 1, Transport: tr,
		Storage: func(GroupID) (Storage, error) { return NewMemStorage(), nil },
		FSM:     func(GroupID) (FSM, error) { return newKVFSM(), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	g, err := host.StartGroup(GroupConfig{ID: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := cap(g.Node().cfg.snapshotSlots); got != 2 {
		t.Fatalf("snapshot slots = %d, want 2", got)
	}
}

// TestSnapshotThresholdJitter keeps the threshold inside the configured band.
// | TestSnapshotThresholdJitter 保证阈值位于配置区间内。
func TestSnapshotThresholdJitter(t *testing.T) {
	if got := (&Node{snapshotEntries: 100}).snapshotThreshold(); got != 100 {
		t.Fatalf("plain threshold = %d", got)
	}
	jittered := &Node{snapshotEntries: 100, cfg: Config{SnapshotJitter: 50}}
	for i := 0; i < 200; i++ {
		got := jittered.snapshotThreshold()
		if got < 50 || got > 150 {
			t.Fatalf("jittered threshold = %d outside [50,150]", got)
		}
	}
}

// TestSnapshotChunkInstallStreamsToFile installs a chunked snapshot on a
// FileStorage learner, restores it through RestoreFrom, and verifies the staged
// temp file is replaced by a durable final snapshot. |
// TestSnapshotChunkInstallStreamsToFile 在 FileStorage 学习者上安装分块快照，通过
// RestoreFrom 还原，并验证暂存临时文件被持久快照替换。
func TestSnapshotChunkInstallStreamsToFile(t *testing.T) {
	net := NewMemNetwork()
	defer net.Close()
	peers := []Peer{{ID: 1}, {ID: 2}, {ID: 3}}
	nodes := make(map[NodeID]*Node, 4)
	for i := 1; i <= 3; i++ {
		tr, err := net.NewTransport(NodeID(i))
		if err != nil {
			t.Fatal(err)
		}
		node, err := New(Config{
			ID: NodeID(i), Peers: peers, Storage: NewMemStorage(), FSM: newKVFSM(),
			Transport: tr, TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
			SnapshotEntries: 5, SnapshotCatchUpEntries: 1, SnapshotChunkBytes: 64,
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes[NodeID(i)] = node
	}
	defer func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	}()
	leader := waitOneLeader(t, nodes, 8*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := 0; i < 40; i++ {
		if _, err := leader.Propose(ctx, []byte(fmt.Sprintf("k%d=%d", i, i))); err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
	}
	waitSnapshot(t, leader, 10*time.Second)

	dir := t.TempDir()
	store, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	fsm := newStreamingKVFSM()
	tr4, err := net.NewTransport(4)
	if err != nil {
		t.Fatal(err)
	}
	node4, err := New(Config{
		ID: 4, Join: true, Storage: store, FSM: fsm, Transport: tr4,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		MaxBatchEntries: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodes[4] = node4
	if err := leader.AddLearner(ctx, 4, ""); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	waitAppliedOn(t, node4, leader.Commit(), 15*time.Second)
	if fsm.restores() == 0 {
		t.Fatal("learner did not use StreamingRestoreFSM")
	}
	if got := fsm.value("k39"); got != "39" {
		t.Fatalf("restored value = %q", got)
	}
	entries, err := os.ReadDir(filepath.Join(dir, snapshotDirName))
	if err != nil {
		t.Fatal(err)
	}
	final := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), snapshotTempPrefix) {
			t.Fatalf("staged temp survived install: %s", entry.Name())
		}
		if strings.HasSuffix(entry.Name(), snapshotFileSuffix) {
			final++
		}
	}
	if final == 0 {
		t.Fatal("final snapshot file missing")
	}
}

// TestRestoreFromSafeFallback loads a bounded image for an FSM without
// StreamingRestoreFSM. | TestRestoreFromSafeFallback 为未实现 StreamingRestoreFSM
// 的 FSM 加载有界镜像。
func TestRestoreFromSafeFallback(t *testing.T) {
	fsm := newKVFSM()
	n := &Node{fsm: fsm}
	if err := n.restoreFromSafe(strings.NewReader("a=1\n")); err != nil {
		t.Fatal(err)
	}
	if got := fsm.value("a"); got != "1" {
		t.Fatalf("value = %q", got)
	}
}
