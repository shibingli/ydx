package raft

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"path/filepath"
	"testing"
	"time"
)

// TestWALDropsCoveredMarkerRecords verifies local snapshots do not pin one WAL
// record each. | TestWALDropsCoveredMarkerRecords 验证本地快照不会各自永久钉住
// 一条 WAL 记录。
func TestWALDropsCoveredMarkerRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStorage(FileStorageOptions{Dir: dir, NoSync: true, SegmentSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 1; i <= 6; i++ {
		idx := uint64(i * 10)
		snap := &Snapshot{
			Index:     idx,
			Term:      1,
			ConfState: ConfState{Voters: []NodeID{1}},
			Data:      make([]byte, 256),
		}
		if err := s.Persist(PersistBatch{HardState: &HardState{Term: 1}, Snapshot: snap}); err != nil {
			t.Fatalf("persist snapshot %d: %v", idx, err)
		}
		if err := s.Compact(idx); err != nil {
			t.Fatalf("compact snapshot %d: %v", idx, err)
		}
	}
	// Truncate retires sealed segments by queuing them to the cleaner goroutine,
	// which unlinks them asynchronously. Wait for the cleaner to drain before
	// counting files so a slow runner cannot observe already-retired segments. |
	// Truncate 把封段交给 cleaner 协程异步删除；计数前等待其排空，避免慢速运行器
	// 观察到已退休但尚未 unlink 的分段。
	deadline := time.Now().Add(5 * time.Second)
	var files []string
	for {
		files, err = filepath.Glob(filepath.Join(dir, "wal", "*.wal"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) <= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(files) > 2 {
		t.Fatalf("wal segments = %d, want at most 2", len(files))
	}
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
		t.Fatalf("load: %v", err)
	}
	if rec.Snapshot == nil || rec.Snapshot.Index != 60 {
		t.Fatalf("recovered snapshot = %+v", rec.Snapshot)
	}
}

// TestCodecRejectsImpossibleEntryCount verifies a tiny payload cannot request a
// huge Entry slice. | TestCodecRejectsImpossibleEntryCount 验证极小载荷不能请求
// 巨大的 Entry 切片。
func TestCodecRejectsImpossibleEntryCount(t *testing.T) {
	data := []byte{protocolVersion, byte(MsgApp), flagEntries}
	for i := 0; i < 10; i++ {
		data = append(data, 0) // ten zero varints for the fixed header
	}
	data = append(data, 0xff, 0xff, 0x3f) // varint 1<<20 - 1
	if _, err := UnmarshalMessage(data); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}

	frame := make([]byte, 0, 16)
	frame = append(frame, httpFrameMagic...)
	frame = append(frame, httpFrameVersion, 0)
	frame = append(frame, 0, 0, 0, 0)
	payload := []byte{0xff, 0xff, 0xff, 0xff, 0x0f} // varint 2^32-1
	binary.LittleEndian.PutUint32(frame[6:10], crc32.Checksum(payload, castagnoli))
	frame = append(frame, payload...)
	if _, err := decodeHTTPFrame(frame); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("http error = %v, want ErrTooLarge", err)
	}
}

// TestAdvanceApplyWaitsForDurability verifies committed entries are not handed
// to the FSM before their local persist completes. | TestAdvanceApplyWaitsForDurability
// 验证已提交日志项在本地持久化完成前不会交给 FSM。
func TestAdvanceApplyWaitsForDurability(t *testing.T) {
	log, err := newLog(nil, []Entry{
		{Index: 1, Term: 1, Type: EntryNormal},
		{Index: 2, Term: 1, Type: EntryNormal},
		{Index: 3, Term: 1, Type: EntryNormal},
	})
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{
		log:            log,
		committed:      3,
		persistedIndex: 1,
		applyQueue:     newApplyQueue(),
	}
	n.advanceApply()
	if n.sentApplied != 1 {
		t.Fatalf("sentApplied = %d, want 1 (durable prefix)", n.sentApplied)
	}
	task, ok := n.applyQueue.pop()
	if !ok || len(task.entries) != 1 || task.entries[0].Index != 1 {
		t.Fatalf("first task = %+v, want entry 1 only", task)
	}
	n.persistedIndex = 3
	n.advanceApply()
	if n.sentApplied != 3 {
		t.Fatalf("sentApplied = %d, want 3", n.sentApplied)
	}
	task, ok = n.applyQueue.pop()
	if !ok || len(task.entries) != 2 || task.entries[0].Index != 2 || task.entries[1].Index != 3 {
		t.Fatalf("second task = %+v, want entries 2,3", task)
	}
}

// TestFileStorageRestartReplaysDurably exercises a real FileStorage cluster and
// restart. | TestFileStorageRestartReplaysDurably 覆盖真实 FileStorage 集群与重启。
func TestFileStorageRestartReplaysDurably(t *testing.T) {
	dir := t.TempDir()
	net := NewMemNetwork()
	defer net.Close()
	peers := []Peer{{ID: 1}, {ID: 2}, {ID: 3}}
	nodes := map[NodeID]*Node{}
	fsms := map[NodeID]*kvFSM{}
	dirs := map[NodeID]string{}
	for _, p := range peers {
		path := filepath.Join(dir, "node-"+string(rune('0'+p.ID)))
		dirs[p.ID] = path
		fs, err := NewFileStorage(FileStorageOptions{Dir: path, NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		tr, err := net.NewTransport(p.ID)
		if err != nil {
			t.Fatal(err)
		}
		fsm := newKVFSM()
		n, err := New(Config{
			ID: p.ID, Peers: peers, Storage: fs, FSM: fsm, Transport: tr,
			TickInterval: 2 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes[p.ID] = n
		fsms[p.ID] = fsm
	}
	defer func() {
		for _, n := range nodes {
			_ = n.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	var leader *Node
	for time.Now().Before(deadline) {
		count := 0
		for _, n := range nodes {
			if n.State() == StateLeader {
				leader = n
				count++
			}
		}
		if count == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if leader == nil {
		t.Fatal("no leader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var last Result
	for i := 0; i < 50; i++ {
		res, err := leader.Propose(ctx, []byte("k=v"))
		if err != nil {
			for id, n := range nodes {
				t.Logf("node %d state=%s term=%d leader=%d commit=%d applied=%d stats=%+v",
					id, n.State(), n.Term(), n.Leader(), n.Commit(), n.Applied(), n.Stats())
			}
			t.Fatalf("propose: %v", err)
		}
		last = res
	}
	for id, n := range nodes {
		if err := n.WaitApplied(ctx, last.Index); err != nil {
			t.Fatalf("node %d wait applied: %v", id, err)
		}
	}
	var follower NodeID
	for id := range nodes {
		if id != leader.ID() {
			follower = id
			break
		}
	}
	if err := nodes[follower].Close(); err != nil {
		t.Fatalf("close follower: %v", err)
	}
	// Verify the WAL still contains the follower's log before restarting. | 重启前
	// 验证 WAL 仍包含跟随者日志。
	probe, err := NewFileStorage(FileStorageOptions{Dir: dirs[follower], NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := probe.Load()
	if err != nil {
		t.Fatalf("probe load: %v", err)
	}
	if len(rec.Entries) < 50 {
		t.Fatalf("WAL recovered only %d entries before restart", len(rec.Entries))
	}
	_ = probe.Close()
	fs, err := NewFileStorage(FileStorageOptions{Dir: dirs[follower], NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := net.NewTransport(follower)
	if err != nil {
		t.Fatal(err)
	}
	fsm := newKVFSM()
	restarted, err := New(Config{
		ID: follower, Peers: peers, Storage: fs, FSM: fsm, Transport: tr,
		TickInterval: 2 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	nodes[follower] = restarted
	fsms[follower] = fsm
	res, err := leader.Propose(ctx, []byte("after=restart"))
	if err != nil {
		t.Fatalf("propose after restart: %v", err)
	}
	if err := restarted.WaitApplied(ctx, res.Index); err != nil {
		for id, n := range nodes {
			t.Logf("node %d state=%s term=%d leader=%d commit=%d applied=%d status=%+v stats=%+v",
				id, n.State(), n.Term(), n.Leader(), n.Commit(), n.Applied(), n.Status(), n.Stats())
		}
		t.Fatalf("restarted wait: %v", err)
	}
	if got := fsm.value("after"); got != "restart" {
		t.Fatalf("restarted value = %q", got)
	}
}

// TestPersistMergeableRejectsOverlap verifies duplicate append retries are not
// coalesced into one WAL record, whose delta encoding requires contiguous
// indexes. | TestPersistMergeableRejectsOverlap 验证重复追加重试不会被合并为一条
// WAL 记录；该记录的增量编码要求索引连续。
func TestPersistMergeableRejectsOverlap(t *testing.T) {
	entry := func(index uint64) *persistRequest {
		return &persistRequest{batch: PersistBatch{Entries: []Entry{{Index: index, Term: 2, Type: EntryNormal}}}}
	}
	if persistMergeable(5, true, entry(5)) {
		t.Fatal("duplicate index must not merge")
	}
	if !persistMergeable(5, true, entry(6)) {
		t.Fatal("contiguous index must merge")
	}
	if persistMergeable(5, true, entry(7)) {
		t.Fatal("gap must not merge")
	}
	if !persistMergeable(0, false, entry(3)) {
		t.Fatal("first entry must merge into an empty batch")
	}
	trunc := &persistRequest{batch: PersistBatch{
		Truncate: 4,
		Entries:  []Entry{{Index: 4, Term: 2, Type: EntryNormal}},
	}}
	if !persistMergeable(5, true, trunc) {
		t.Fatal("joining truncate must merge")
	}
	truncFar := &persistRequest{batch: PersistBatch{
		Truncate: 9,
		Entries:  []Entry{{Index: 9, Term: 2, Type: EntryNormal}},
	}}
	if persistMergeable(5, true, truncFar) {
		t.Fatal("truncate beyond the current tail must not merge")
	}
}

// TestWALDecoderAcceptsDuplicateIndex verifies recovery can read a WAL record
// that an older group-commit build coalesced from duplicate append retries.
// | TestWALDecoderAcceptsDuplicateIndex 验证恢复能读取旧版组提交由重复追加重试
// 合并写出的 WAL 记录。
func TestWALDecoderAcceptsDuplicateIndex(t *testing.T) {
	payload := encodeWALBatch(nil, PersistBatch{Entries: []Entry{
		{Index: 1, Term: 1, Type: EntryNormal},
		{Index: 1, Term: 1, Type: EntryNormal},
	}})
	rec, err := decodeWALBatch(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rec.entries) != 2 || rec.entries[0].Index != 1 || rec.entries[1].Index != 1 {
		t.Fatalf("entries = %+v", rec.entries)
	}
	// Message decoding must remain strict. | 消息解码必须保持严格。
	msgData, err := MarshalMessage(Message{Type: MsgApp, From: 1, To: 2, Term: 1,
		Entries: []Entry{{Index: 1, Term: 1}, {Index: 1, Term: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalMessage(msgData); err == nil {
		t.Fatal("message decoder accepted a non-contiguous entry range")
	}
}

// TestTruncationLowersPersistedIndex verifies a conflicting append cannot use
// the durable index of the replaced suffix to apply the new entries early.
// | TestTruncationLowersPersistedIndex 验证冲突追加不能借助被替换后缀的持久索引
// 提前应用新日志项。
func TestTruncationLowersPersistedIndex(t *testing.T) {
	log, err := newLog(nil, []Entry{
		{Index: 1, Term: 1, Type: EntryNormal},
		{Index: 2, Term: 1, Type: EntryNormal},
		{Index: 3, Term: 1, Type: EntryNormal},
	})
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{
		id:             1,
		state:          StateFollower,
		term:           2,
		log:            log,
		persistedIndex: 3,
		sentApplied:    1,
		cfg:            Config{ElectionTicks: 8, HeartbeatTicks: 1, TickInterval: time.Millisecond},
		conf:           newMembership(nil, nil, nil),
		confBase:       newMembership(nil, nil, nil),
		metrics:        newMetrics(),
		futures:        newFutureStore(),
		remoteReads:    newRemoteReadStore(),
		applyQueue:     newApplyQueue(),
		persistNotify:  make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
	}
	n.handleAppend(&Message{
		Type: MsgApp, From: 2, To: 1, Term: 2,
		LogIndex: 2, LogTerm: 1, Commit: 3,
		Entries: []Entry{{Index: 3, Term: 2, Type: EntryNormal}},
	})
	if n.persistedIndex != 2 {
		t.Fatalf("persistedIndex = %d, want 2 after truncation", n.persistedIndex)
	}
	if n.sentApplied != 2 {
		t.Fatalf("sentApplied = %d, want only the durable prefix 2", n.sentApplied)
	}
	task, ok := n.applyQueue.pop()
	if !ok || len(task.entries) != 1 || task.entries[0].Index != 2 {
		t.Fatalf("apply task = %+v, want entry 2 only", task)
	}
	if n.persistDepth() != 1 {
		t.Fatalf("persist requests = %d, want 1", n.persistDepth())
	}
}
