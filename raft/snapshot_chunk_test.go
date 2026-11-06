package raft

import (
	"context"
	"fmt"
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
	n.handleSnapshotChunkResp(Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 64, LogIndex: 99, Commit: 5})
	if len(transport.msgs) != before {
		t.Fatal("stale chunk acknowledgement advanced the sender")
	}
	// Valid acknowledgements advance one chunk at a time. | 合法确认逐块推进。
	n.handleSnapshotChunkResp(Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 64, LogIndex: 0, Commit: 5})
	if got := transport.msgs[len(transport.msgs)-1]; got.LogIndex != 64 || len(got.Snapshot.Data) != 64 {
		t.Fatalf("second chunk offset=%d size=%d", got.LogIndex, len(got.Snapshot.Data))
	}
	n.handleSnapshotChunkResp(Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 128, LogIndex: 64, Commit: 5})
	if got := transport.msgs[len(transport.msgs)-1]; got.LogIndex != 128 || len(got.Snapshot.Data) != 64 {
		t.Fatalf("third chunk offset=%d size=%d", got.LogIndex, len(got.Snapshot.Data))
	}
	n.handleSnapshotChunkResp(Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
		Index: 192, LogIndex: 128, Commit: 5})
	if got := transport.msgs[len(transport.msgs)-1]; got.LogIndex != 192 || len(got.Snapshot.Data) != 8 {
		t.Fatalf("last chunk offset=%d size=%d", got.LogIndex, len(got.Snapshot.Data))
	}
	n.handleSnapshotChunkResp(Message{Type: MsgSnapChunkResp, From: 2, Term: 1,
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
