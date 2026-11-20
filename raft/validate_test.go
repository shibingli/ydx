package raft

import (
	"errors"
	"math"
	"slices"
	"testing"
	"time"
)

// guardState is the subset of node state that peer input must never change when
// validation rejects it. | guardState 是校验收到的对端输入被拒绝时绝不能被改变的
// 节点状态子集。
type guardState struct {
	term      uint64
	leader    NodeID
	state     State
	lastIndex uint64
	committed uint64
	voters    []NodeID
}

// captureGuardState snapshots the guarded fields. | captureGuardState 采集受保护字段。
func captureGuardState(n *Node) guardState {
	gs := guardState{
		term:      n.term,
		leader:    n.leader,
		state:     n.state,
		lastIndex: n.log.lastIndex,
		committed: n.committed,
	}
	if n.conf != nil {
		gs.voters = n.conf.confState().Voters
	}
	return gs
}

// requireGuardState asserts that no guarded field changed. | requireGuardState 断言
// 没有任何受保护字段发生变化。
func requireGuardState(t *testing.T, n *Node, want guardState) {
	t.Helper()
	got := captureGuardState(n)
	if got.term != want.term || got.leader != want.leader || got.state != want.state ||
		got.lastIndex != want.lastIndex || got.committed != want.committed ||
		!slices.Equal(got.voters, want.voters) {
		t.Fatalf("state changed: got %+v want %+v", got, want)
	}
}

// newGuardNode builds a self-contained node for sender and poison tests. It is
// not started; handlers run synchronously on the calling goroutine. |
// newGuardNode 为发送者与毒化测试构建自包含节点。节点不会启动，处理器在调用协程上
// 同步执行。
func newGuardNode(t *testing.T, term uint64, state State, leader NodeID, voters []NodeID) *Node {
	t.Helper()
	log, err := newLog(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	conf := newMembership(voters, nil, nil)
	n := &Node{
		id:            1,
		term:          term,
		leader:        leader,
		state:         state,
		cfg:           Config{ElectionTicks: 8, HeartbeatTicks: 1, TickInterval: time.Millisecond},
		log:           log,
		conf:          conf,
		confBase:      conf,
		metrics:       newMetrics(),
		futures:       newFutureStore(),
		remoteReads:   newRemoteReadStore(),
		appliedNotify: newAppliedNotifier(),
		applyQueue:    newApplyQueue(),
		progress:      make(map[NodeID]*progress),
		votes:         make(map[NodeID]bool),
		preVotes:      make(map[NodeID]bool),
		recvCh:        make(chan *Message, 16),
		controlCh:     make(chan *Message, 16),
		persistNotify: make(chan struct{}, 1),
		fatalCh:       make(chan error, 1),
		stopCh:        make(chan struct{}),
	}
	n.termAtomic.Store(term)
	n.leaderAtomic.Store(uint64(leader))
	n.stateAtomic.Store(uint32(state))
	return n
}

// TestTransportRequiresSecretOrAllowInsecure verifies the fail-closed default of
// the HTTP and TCP transports and the explicit opt-out. |
// TestTransportRequiresSecretOrAllowInsecure 验证 HTTP/TCP 传输默认拒绝空密钥，以及
// 显式退出保护的行为。
func TestTransportRequiresSecretOrAllowInsecure(t *testing.T) {
	if _, err := NewHTTPTransport(HTTPTransportOptions{ID: 1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty HTTP secret error = %v, want ErrInvalidConfig", err)
	}
	httpInsecure, err := NewHTTPTransport(HTTPTransportOptions{ID: 1, AllowInsecure: true})
	if err != nil {
		t.Fatalf("AllowInsecure HTTP transport: %v", err)
	}
	_ = httpInsecure.Close()

	if _, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty TCP secret error = %v, want ErrInvalidConfig", err)
	}
	tcpInsecure, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", AllowInsecure: true})
	if err != nil {
		t.Fatalf("AllowInsecure TCP transport: %v", err)
	}
	_ = tcpInsecure.Close()

	// A short secret stays invalid even when AllowInsecure is set; the flag only
	// permits an empty secret. | 即使设置 AllowInsecure，过短的密钥仍然非法；该标志
	// 只允许空密钥。
	if _, err := NewTCPTransport(TCPTransportOptions{
		ListenAddr: "127.0.0.1:0", SharedSecret: []byte("short"), AllowInsecure: true,
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short secret error = %v, want ErrInvalidConfig", err)
	}
	// A full-length secret needs no opt-out. | 足够长的密钥无需显式退出保护。
	httpSecure, err := NewHTTPTransport(HTTPTransportOptions{
		ID: 1, SharedSecret: []byte("0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("secret HTTP transport: %v", err)
	}
	_ = httpSecure.Close()
}

// TestInboundSenderValidation verifies that non-members and same-term
// non-leaders cannot mutate term, leader, log, commit or configuration. |
// TestInboundSenderValidation 验证非成员与同任期非领导者无法改变任期、领导者、日志、
// 提交索引或配置。
func TestInboundSenderValidation(t *testing.T) {
	voters := []NodeID{1, 2, 3}
	newSnapshot := func() *Snapshot {
		return &Snapshot{Index: 4, Term: 5, ConfState: ConfState{Voters: []NodeID{9}}}
	}

	t.Run("non-member dropped even with higher term", func(t *testing.T) {
		n := newGuardNode(t, 5, StateFollower, 2, voters)
		before := captureGuardState(n)
		n.step(&Message{Type: MsgApp, From: 9, To: 1, Term: 99, LogIndex: 0, LogTerm: 0,
			Entries: []Entry{{Index: 1, Term: 99, Type: EntryNormal}}})
		n.step(&Message{Type: MsgSnap, From: 9, To: 1, Term: 99, Snapshot: newSnapshot()})
		n.step(&Message{Type: MsgHeartbeat, From: 9, To: 1, Term: 99})
		requireGuardState(t, n, before)
	})

	t.Run("same-term non-leader dropped", func(t *testing.T) {
		n := newGuardNode(t, 5, StateFollower, 2, voters)
		before := captureGuardState(n)
		n.step(&Message{Type: MsgApp, From: 3, To: 1, Term: 5, LogIndex: 0, LogTerm: 0,
			Entries: []Entry{{Index: 1, Term: 5, Type: EntryNormal}}})
		n.step(&Message{Type: MsgSnap, From: 3, To: 1, Term: 5, Snapshot: newSnapshot()})
		n.step(&Message{Type: MsgHeartbeat, From: 3, To: 1, Term: 5})
		requireGuardState(t, n, before)
	})

	t.Run("second leader in the same term rejected", func(t *testing.T) {
		n := newGuardNode(t, 5, StateLeader, 1, voters)
		before := captureGuardState(n)
		n.step(&Message{Type: MsgApp, From: 2, To: 1, Term: 5, LogIndex: 0, LogTerm: 0,
			Entries: []Entry{{Index: 1, Term: 5, Type: EntryNormal}}})
		n.step(&Message{Type: MsgSnap, From: 2, To: 1, Term: 5, Snapshot: newSnapshot()})
		requireGuardState(t, n, before)
	})

	t.Run("self-addressed sender rejected", func(t *testing.T) {
		n := newGuardNode(t, 5, StateFollower, 2, voters)
		before := captureGuardState(n)
		n.step(&Message{Type: MsgApp, From: 1, To: 1, Term: 5, LogIndex: 0, LogTerm: 0,
			Entries: []Entry{{Index: 1, Term: 5, Type: EntryNormal}}})
		requireGuardState(t, n, before)
	})

	t.Run("higher term from a member is a normal transition", func(t *testing.T) {
		n := newGuardNode(t, 5, StateFollower, 2, voters)
		n.step(&Message{Type: MsgHeartbeat, From: 3, To: 1, Term: 6})
		if n.term != 6 || n.leader != 3 || n.state != StateFollower {
			t.Fatalf("term=%d leader=%d state=%s, want 6/3/follower", n.term, n.leader, n.state)
		}
	})

	t.Run("injected membership query", func(t *testing.T) {
		n := newGuardNode(t, 5, StateFollower, 2, voters)
		n.cfg.senderFilter = func(id NodeID) bool { return id == 42 }
		n.step(&Message{Type: MsgHeartbeat, From: 42, To: 1, Term: 6})
		if n.term != 6 || n.leader != 42 || n.state != StateFollower {
			t.Fatalf("injected filter not consulted: term=%d leader=%d state=%s",
				n.term, n.leader, n.state)
		}
	})
}

// TestMaxUint64MessagesRejected verifies poison counters are dropped at ingress
// without queueing or changing state. | TestMaxUint64MessagesRejected 验证毒化计数
// 在入口处被丢弃，既不入队也不改变状态。
func TestMaxUint64MessagesRejected(t *testing.T) {
	n := newGuardNode(t, 5, StateFollower, 2, []NodeID{1, 2, 3})
	before := captureGuardState(n)
	validSnapshot := func(index, term uint64) *Snapshot {
		return &Snapshot{Index: index, Term: term, ConfState: ConfState{Voters: []NodeID{1, 2, 3}}}
	}
	poisoned := []Message{
		{Type: MsgApp, From: 2, To: 1, Term: math.MaxUint64},
		{Type: MsgVote, From: 3, To: 1, Term: math.MaxUint64, LogIndex: 1, LogTerm: 5},
		{Type: MsgHeartbeat, From: 2, To: 1, Term: math.MaxUint64},
		{Type: MsgApp, From: 2, To: 1, Term: 5, LogIndex: math.MaxUint64},
		{Type: MsgApp, From: 2, To: 1, Term: 5, LogIndex: 0, LogTerm: 0,
			Entries: []Entry{{Index: math.MaxUint64, Term: 5, Type: EntryNormal}}},
		{Type: MsgAppResp, From: 2, To: 1, Term: 5, Index: math.MaxUint64},
		{Type: MsgSnap, From: 2, To: 1, Term: 5, Snapshot: validSnapshot(math.MaxUint64, 5)},
		{Type: MsgSnap, From: 2, To: 1, Term: 5, Snapshot: validSnapshot(4, math.MaxUint64)},
		// A snapshot term ahead of its carrying message is invalid as well. |
		// 高于承载消息任期的快照任期同样非法。
		{Type: MsgSnap, From: 2, To: 1, Term: 5, Snapshot: validSnapshot(4, 6)},
	}
	for i := range poisoned {
		n.Step(poisoned[i])
	}
	select {
	case m := <-n.recvCh:
		t.Fatalf("poisoned message queued on recvCh: %+v", m)
	default:
	}
	select {
	case m := <-n.controlCh:
		t.Fatalf("poisoned message queued on controlCh: %+v", m)
	default:
	}
	requireGuardState(t, n, before)

	// The term ceiling must not wrap n.term+1. | 任期上限不得让 n.term+1 回绕。
	ceiling := newGuardNode(t, maxCounter, StateFollower, 2, []NodeID{1, 2, 3})
	ceiling.startVote()
	ceiling.startPreVote()
	if ceiling.term != maxCounter || ceiling.state != StateFollower {
		t.Fatalf("term ceiling wrapped: term=%d state=%s", ceiling.term, ceiling.state)
	}
}

// TestForgedAppendRespCannotAdvanceCommit verifies that only acknowledgements
// inside the already-sent pipeline window advance match or commit. |
// TestForgedAppendRespCannotAdvanceCommit 验证只有落在已发送流水线窗口内的确认才能
// 推进 match 或提交索引。
func TestForgedAppendRespCannotAdvanceCommit(t *testing.T) {
	log, err := newLog(nil, entriesRange(1, 5, 2))
	if err != nil {
		t.Fatal(err)
	}
	conf := newMembership([]NodeID{1, 2, 3}, nil, nil)
	n := &Node{
		id:             1,
		state:          StateLeader,
		term:           2,
		leader:         1,
		committed:      1,
		persistedIndex: 5,
		sentApplied:    1,
		cfg:            Config{ElectionTicks: 8, HeartbeatTicks: 1, TickInterval: time.Millisecond},
		log:            log,
		conf:           conf,
		confBase:       conf,
		metrics:        newMetrics(),
		futures:        newFutureStore(),
		remoteReads:    newRemoteReadStore(),
		appliedNotify:  newAppliedNotifier(),
		applyQueue:     newApplyQueue(),
		progress:       make(map[NodeID]*progress),
	}
	n.termAtomic.Store(2)
	n.leaderAtomic.Store(1)
	n.progress[1] = newProgress(6, 8, 1<<20)
	n.progress[1].match = 5
	pr := newProgress(2, 8, 1<<20)
	pr.match = 1
	pr.state = replicate
	// The leader sent entries [2, 3] and is waiting for their acknowledgement. |
	// 领导者已发送日志项 [2, 3]，正在等待确认。
	pr.inflights.add(2, 1)
	pr.inflights.add(3, 1)
	n.progress[2] = pr
	n.progress[3] = newProgress(2, 8, 1<<20)
	n.progress[3].match = 1

	n.handleAppendResp(&Message{Type: MsgAppResp, From: 2, To: 1, Term: 2, Index: 5})
	if pr.match != 1 || n.committed != 1 {
		t.Fatalf("forged ack advanced state: match=%d committed=%d", pr.match, n.committed)
	}
	if pr.state != replicate || pr.next != 2 {
		t.Fatalf("forged ack changed progress: state=%s next=%d", pr.state, pr.next)
	}

	// A real acknowledgement inside the sent window still works. | 已发送窗口内的
	// 真实确认仍然有效。
	n.handleAppendResp(&Message{Type: MsgAppResp, From: 2, To: 1, Term: 2, Index: 3})
	if pr.match != 3 || n.committed != 3 {
		t.Fatalf("valid ack: match=%d committed=%d, want 3/3", pr.match, n.committed)
	}
}

// TestForgedSnapshotRespIgnored verifies a snapshot response must match the
// pending image before it can advance match or commit. |
// TestForgedSnapshotRespIgnored 验证快照响应必须匹配在途镜像，才能推进 match 或提交
// 索引。
func TestForgedSnapshotRespIgnored(t *testing.T) {
	log, err := newLog(nil, entriesRange(1, 10, 2))
	if err != nil {
		t.Fatal(err)
	}
	conf := newMembership([]NodeID{1, 2, 3}, nil, nil)
	newLeader := func(pr *progress) *Node {
		n := &Node{
			id:             1,
			state:          StateLeader,
			term:           2,
			leader:         1,
			committed:      1,
			persistedIndex: 10,
			sentApplied:    1,
			cfg:            Config{ElectionTicks: 8, HeartbeatTicks: 1, TickInterval: time.Millisecond},
			log:            log,
			conf:           conf,
			confBase:       conf,
			metrics:        newMetrics(),
			futures:        newFutureStore(),
			remoteReads:    newRemoteReadStore(),
			appliedNotify:  newAppliedNotifier(),
			applyQueue:     newApplyQueue(),
			progress:       map[NodeID]*progress{2: pr},
		}
		n.termAtomic.Store(2)
		n.leaderAtomic.Store(1)
		n.progress[1] = newProgress(11, 8, 1<<20)
		n.progress[1].match = 10
		n.progress[3] = newProgress(2, 8, 1<<20)
		n.progress[3].match = 1
		return n
	}

	pr := newProgress(2, 8, 1<<20)
	pr.match = 1
	pr.state = snapshot
	pr.pendingSnapshot = 5
	n := newLeader(pr)
	n.handleSnapshotResp(&Message{Type: MsgSnapResp, From: 2, To: 1, Term: 2, Index: 10})
	if pr.match != 1 || n.committed != 1 || pr.state != snapshot || pr.pendingSnapshot != 5 {
		t.Fatalf("forged snapshot ack changed state: match=%d committed=%d state=%s pending=%d",
			pr.match, n.committed, pr.state, pr.pendingSnapshot)
	}

	// Without a pending image any success response is ignored. | 没有在途镜像时任何
	// 成功响应都被忽略。
	pr.snapshotDone(0)
	pr.match = 1
	pr.next = 2
	pr.state = probe
	pr.pendingSnapshot = 0
	n.handleSnapshotResp(&Message{Type: MsgSnapResp, From: 2, To: 1, Term: 2, Index: 5})
	if pr.match != 1 || n.committed != 1 {
		t.Fatalf("unsolicited snapshot ack advanced state: match=%d committed=%d",
			pr.match, n.committed)
	}

	// A mismatched LogIndex is ignored even when Index matches. | 即使 Index 匹配，
	// LogIndex 不匹配的响应仍被忽略。
	pr.match = 1
	pr.next = 2
	pr.state = snapshot
	pr.pendingSnapshot = 5
	n.handleSnapshotResp(&Message{Type: MsgSnapResp, From: 2, To: 1, Term: 2, Index: 5, LogIndex: 4})
	if pr.match != 1 || n.committed != 1 || pr.state != snapshot {
		t.Fatalf("mismatched snapshot ack: match=%d committed=%d state=%s",
			pr.match, n.committed, pr.state)
	}

	// The matching response completes the transfer. | 匹配的响应完成传输。
	n.handleSnapshotResp(&Message{Type: MsgSnapResp, From: 2, To: 1, Term: 2, Index: 5})
	if pr.match != 5 || n.committed != 5 || pr.state != probe {
		t.Fatalf("valid snapshot ack: match=%d committed=%d state=%s, want 5/5/probe",
			pr.match, n.committed, pr.state)
	}

	// A follower that already committed the base echoes it in LogIndex while
	// reporting its own commit index in Index. | 已提交该基点的跟随者会在 LogIndex
	// 回显快照索引，并在 Index 报告自身提交索引。
	pr.match = 1
	pr.next = 2
	pr.state = snapshot
	pr.pendingSnapshot = 5
	n.handleSnapshotResp(&Message{Type: MsgSnapResp, From: 2, To: 1, Term: 2, Index: 6, LogIndex: 5})
	if pr.match != 6 || n.committed != 6 || pr.state != probe {
		t.Fatalf("committed-base snapshot ack: match=%d committed=%d state=%s, want 6/6/probe",
			pr.match, n.committed, pr.state)
	}
}

// TestGarbageConfChangeDoesNotStopNode verifies invalid membership entries are
// rejected without a fatal shutdown or state mutation, and that the node keeps
// processing later traffic. | TestGarbageConfChangeDoesNotStopNode 验证非法成员日志项
// 被拒收且不会 fatal 停机或改变状态，节点继续处理后续流量。
func TestGarbageConfChangeDoesNotStopNode(t *testing.T) {
	addExisting, err := encodeConfChange(ConfChange{Type: ConfChangeAddNode, NodeID: 2})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		entry Entry
	}{
		{"undecodable conf change", Entry{Index: 1, Term: 5, Type: EntryConfChange, Data: []byte{0xff}}},
		{"conflict with existing member", Entry{Index: 1, Term: 5, Type: EntryConfChange, Data: addExisting}},
		{"empty bootstrap config", Entry{Index: 1, Term: 5, Type: EntryBootstrap,
			Data: appendConfState(nil, ConfState{})}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newGuardNode(t, 5, StateFollower, 2, []NodeID{1, 2, 3})
			before := captureGuardState(n)
			n.step(&Message{Type: MsgApp, From: 2, To: 1, Term: 5, LogIndex: 0, LogTerm: 0,
				Entries: []Entry{tc.entry}})
			if err := n.Err(); err != nil {
				t.Fatalf("node stopped on invalid conf entry: %v", err)
			}
			select {
			case err := <-n.fatalCh:
				t.Fatalf("fatal reported: %v", err)
			default:
			}
			requireGuardState(t, n, before)
			if len(n.outBuf) != 1 || !n.outBuf[0].Reject {
				t.Fatalf("outbound = %+v, want one rejection", n.outBuf)
			}
			// The node must still process valid traffic afterwards. | 节点之后仍须
			// 处理合法流量。
			n.outBuf = n.outBuf[:0]
			n.step(&Message{Type: MsgHeartbeat, From: 2, To: 1, Term: 5})
			if len(n.outBuf) != 1 || n.outBuf[0].Type != MsgHeartbeatResp ||
				n.outBuf[0].Reject {
				t.Fatalf("post-rejection heartbeat response = %+v", n.outBuf)
			}
		})
	}
}
