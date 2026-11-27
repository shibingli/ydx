package raft

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// recordingTransport records the peer directory pushed by the node. | recordingTransport
// 记录节点推送的对端目录。
type recordingTransport struct {
	mu    sync.Mutex
	peers map[NodeID]string
}

// Start implements Transport. | Start 实现 Transport。
func (t *recordingTransport) Start(func(Message)) error { return nil }

// Send implements Transport. | Send 实现 Transport。
func (t *recordingTransport) Send(context.Context, []Message) error { return nil }

// UpdatePeer implements Transport. | UpdatePeer 实现 Transport。
func (t *recordingTransport) UpdatePeer(id NodeID, addr string) {
	t.mu.Lock()
	t.peers[id] = addr
	t.mu.Unlock()
}

// Close implements Transport. | Close 实现 Transport。
func (t *recordingTransport) Close() error { return nil }

// addr returns the recorded address for id. | addr 返回 id 的记录地址。
func (t *recordingTransport) addr(id NodeID) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peers[id]
}

// TestJoinSeedsTransportAddressBook verifies a Join node installs the configured
// peers into its transport even though its membership is empty. Without this
// seed a real transport cannot deliver the joining node's first replies, so the
// leader never learns its log position and replication never starts. |
// TestJoinSeedsTransportAddressBook 验证 Join 节点即使成员配置为空，也会把配置中的
// 对端安装到传输层。没有该种子时，真实传输无法投递加入节点的首批回复，领导者因而
// 永远不知道其日志位置，复制不会开始。
func TestJoinSeedsTransportAddressBook(t *testing.T) {
	tr := &recordingTransport{peers: make(map[NodeID]string)}
	peers := []Peer{
		{ID: 1, Addr: "127.0.0.1:21001"},
		{ID: 2, Addr: "127.0.0.1:21002"},
		{ID: 3, Addr: "127.0.0.1:21003"},
		{ID: 4, Addr: "127.0.0.1:21004"},
	}
	node, err := New(Config{
		ID: 4, Join: true, Peers: peers, Storage: NewMemStorage(), FSM: newKVFSM(),
		Transport: tr, TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	for _, p := range peers {
		if p.ID == 4 {
			if got := tr.addr(p.ID); got != "" {
				t.Fatalf("seeded the join node's own address %q", got)
			}
			continue
		}
		if got := tr.addr(p.ID); got != p.Addr {
			t.Fatalf("peer %d address = %q, want %q", p.ID, got, p.Addr)
		}
	}
}

// TestMembershipAddressOverridesSeed verifies a configured peer address never
// overrides the authoritative membership directory. | TestMembershipAddressOverridesSeed
// 验证配置中的对端地址永远不会覆盖权威的成员目录。
func TestMembershipAddressOverridesSeed(t *testing.T) {
	tr := &recordingTransport{peers: make(map[NodeID]string)}
	n := &Node{
		id:        1,
		cfg:       Config{Peers: []Peer{{ID: 2, Addr: "seed:1"}}},
		transport: tr,
		conf:      newMembership([]NodeID{1, 2}, nil, map[NodeID]string{2: "member:2"}),
	}
	n.seedPeerAddresses()
	n.updatePeerAddresses()
	if got := tr.addr(2); got != "member:2" {
		t.Fatalf("peer 2 address = %q, want membership address", got)
	}
}

// TestClusterJoinOverTCP runs a dynamic learner join and promotion over real
// loopback TCP. The joining node is started with the existing members as its
// transport address book, which lets it answer the leader before the first
// configuration entry arrives. The leader is forced to compact first, so the
// learner must also acknowledge snapshot chunks over the same reply path. |
// TestClusterJoinOverTCP 在真实回环 TCP 上执行动态学习者加入与提升。加入节点以
// 现有成员作为传输层地址簿启动，从而在首条配置日志项到达前就能回复领导者。领导者
// 被强制先压缩，因此学习者还必须通过同一回复路径确认快照分块。
func TestClusterJoinOverTCP(t *testing.T) {
	const size = 3
	transports := make([]*TCPTransport, size)
	peers := make([]Peer, size)
	for i := 0; i < size; i++ {
		tr, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", Queue: 256, AllowInsecure: true})
		if err != nil {
			t.Fatal(err)
		}
		transports[i] = tr
		peers[i] = Peer{ID: NodeID(i + 1), Addr: tr.Addr()}
	}
	nodes := make(map[NodeID]*Node, size+1)
	fsms := make(map[NodeID]*kvFSM, size+1)
	for i := 0; i < size; i++ {
		fsm := newKVFSM()
		node, err := New(Config{
			ID: NodeID(i + 1), Peers: peers, Storage: NewMemStorage(), FSM: fsm,
			Transport: transports[i], TickInterval: 5 * time.Millisecond,
			HeartbeatTicks: 1, ElectionTicks: 8, MaxBatchEntries: 64,
			SnapshotEntries: 5, SnapshotCatchUpEntries: 1,
		})
		if err != nil {
			t.Fatalf("node %d: %v", i+1, err)
		}
		nodes[NodeID(i+1)] = node
		fsms[NodeID(i+1)] = fsm
	}
	defer func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	}()
	leader := waitOneLeader(t, nodes, 8*time.Second)
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

	tr4, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", Queue: 256, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	fsm4 := newKVFSM()
	node4, err := New(Config{
		ID: 4, Join: true, Peers: peers, Storage: NewMemStorage(), FSM: fsm4,
		Transport: tr4, TickInterval: 5 * time.Millisecond,
		HeartbeatTicks: 1, ElectionTicks: 8, MaxBatchEntries: 64,
	})
	if err != nil {
		t.Fatalf("join node: %v", err)
	}
	nodes[4] = node4
	fsms[4] = fsm4

	if err := leader.AddLearner(ctx, 4, tr4.Addr()); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	waitAppliedOn(t, node4, leader.Commit(), 15*time.Second)
	if got := fsm4.value("k39"); got != "39" {
		t.Fatalf("learner replayed value = %q", got)
	}
	if got := node4.Status().SnapshotIndex; got == 0 {
		t.Fatalf("learner did not install a snapshot (last=%d)", last.Index)
	}
	if got := node4.Status().Peers; len(got) != size+1 {
		t.Fatalf("learner peers = %+v, want %d entries", got, size+1)
	}
	for _, p := range node4.Status().Peers {
		if p.Addr == "" {
			t.Fatalf("learner has no address for peer %d", p.ID)
		}
	}

	res, err := leader.Propose(ctx, []byte("after=join"))
	if err != nil {
		t.Fatalf("propose after join: %v", err)
	}
	waitAppliedOn(t, node4, res.Index, 15*time.Second)
	if got := fsm4.value("after"); got != "join" {
		t.Fatalf("learner live value = %q", got)
	}
	if err := leader.Promote(ctx, 4); err != nil {
		t.Fatalf("promote learner: %v", err)
	}
	res, err = leader.Propose(ctx, []byte("voter=yes"))
	if err != nil {
		t.Fatalf("propose after promote: %v", err)
	}
	waitAppliedOn(t, node4, res.Index, 15*time.Second)
	if got := fsm4.value("voter"); got != "yes" {
		t.Fatalf("promoted voter value = %q", got)
	}
	if got := node4.Status().Voters; !contains(got, 4) {
		t.Fatalf("join node is not a voter: %v", got)
	}
}

// waitOneLeader waits for exactly one leader among nodes. | waitOneLeader 等待 nodes
// 中出现唯一领导者。
func waitOneLeader(t *testing.T, nodes map[NodeID]*Node, timeout time.Duration) *Node {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var leader *Node
		count := 0
		for _, node := range nodes {
			if node.State() == StateLeader {
				leader = node
				count++
			}
		}
		if count == 1 {
			return leader
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no single leader")
	return nil
}

// waitAppliedOn waits for a specific node to apply index. | waitAppliedOn 等待指定
// 节点应用到 index。
func waitAppliedOn(t *testing.T, node *Node, index uint64, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := node.WaitApplied(ctx, index); err != nil {
		t.Fatalf("node %d wait applied %d: %v (leader=%d commit=%d applied=%d status=%+v)",
			node.ID(), index, err, node.Leader(), node.Commit(), node.Applied(), node.Status())
	}
}

// TestClusterJoinOverHTTP runs a dynamic join over the HTTP transport. The
// joining node must post its replies to the leader's base URL, which it can
// only learn from the Peers seed before the first configuration arrives. |
// TestClusterJoinOverHTTP 在 HTTP 传输上执行动态加入。加入节点必须把回复 POST 到
// 领导者的基础 URL，而它只能在首份配置到达前从 Peers 种子获知该 URL。
func TestClusterJoinOverHTTP(t *testing.T) {
	const size = 3
	transports := make([]*HTTPTransport, size)
	servers := make([]*httptest.Server, 0, size+1)
	peers := make([]Peer, size)
	for i := 0; i < size; i++ {
		tr, err := NewHTTPTransport(HTTPTransportOptions{ID: NodeID(i + 1), AllowInsecure: true})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(tr.Handler())
		servers = append(servers, server)
		transports[i] = tr
		peers[i] = Peer{ID: NodeID(i + 1), Addr: server.URL}
	}
	nodes := make(map[NodeID]*Node, size+1)
	fsms := make(map[NodeID]*kvFSM, size+1)
	for i := 0; i < size; i++ {
		fsm := newKVFSM()
		node, err := New(Config{
			ID: NodeID(i + 1), Peers: peers, Storage: NewMemStorage(), FSM: fsm,
			Transport: transports[i], TickInterval: 5 * time.Millisecond,
			HeartbeatTicks: 1, ElectionTicks: 8, MaxBatchEntries: 64,
		})
		if err != nil {
			t.Fatalf("node %d: %v", i+1, err)
		}
		nodes[NodeID(i+1)] = node
		fsms[NodeID(i+1)] = fsm
	}
	defer func() {
		for _, node := range nodes {
			_ = node.Close()
		}
		for _, server := range servers {
			server.Close()
		}
	}()
	leader := waitOneLeader(t, nodes, 8*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := leader.Propose(ctx, []byte("before=http-join")); err != nil {
		t.Fatalf("propose before join: %v", err)
	}

	tr4, err := NewHTTPTransport(HTTPTransportOptions{ID: 4, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	server4 := httptest.NewServer(tr4.Handler())
	servers = append(servers, server4)
	fsm4 := newKVFSM()
	node4, err := New(Config{
		ID: 4, Join: true, Peers: peers, Storage: NewMemStorage(), FSM: fsm4,
		Transport: tr4, TickInterval: 5 * time.Millisecond,
		HeartbeatTicks: 1, ElectionTicks: 8, MaxBatchEntries: 64,
	})
	if err != nil {
		t.Fatalf("join node: %v", err)
	}
	nodes[4] = node4
	fsms[4] = fsm4

	if err := leader.AddLearner(ctx, 4, server4.URL); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	waitAppliedOn(t, node4, leader.Commit(), 15*time.Second)
	if got := fsm4.value("before"); got != "http-join" {
		t.Fatalf("learner replayed value = %q", got)
	}
	res, err := leader.Propose(ctx, []byte("after=http-join"))
	if err != nil {
		t.Fatalf("propose after join: %v", err)
	}
	waitAppliedOn(t, node4, res.Index, 15*time.Second)
	if got := fsm4.value("after"); got != "http-join" {
		t.Fatalf("learner live value = %q", got)
	}
}

// TestNodeHostJoinOverTCP starts a fourth NodeHost as a joining group over real
// TCP and verifies the shared base transport receives the group's Peers seed. |
// TestNodeHostJoinOverTCP 在真实 TCP 上把第四个 NodeHost 作为加入组启动，并验证
// 共享基础传输收到该组的 Peers 种子。
func TestNodeHostJoinOverTCP(t *testing.T) {
	const size = 3
	transports := make([]*TCPTransport, size)
	peers := make([]Peer, size)
	for i := 0; i < size; i++ {
		tr, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", Queue: 256, AllowInsecure: true})
		if err != nil {
			t.Fatal(err)
		}
		transports[i] = tr
		peers[i] = Peer{ID: NodeID(i + 1), Addr: tr.Addr()}
	}
	states := make([]*hostState, size)
	for i := 0; i < size; i++ {
		states[i] = newHostState(NodeID(i+1), transports[i])
		states[i].startHost(t)
		startGroup(t, states[i].host, 100, peers)
	}
	defer func() {
		for _, s := range states {
			if s.host != nil {
				_ = s.host.Close()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	leaderIdx := waitHostLeader(t, states, 100)
	if _, err := states[leaderIdx].host.Propose(ctx, 100, []byte("before=host-join")); err != nil {
		t.Fatalf("propose before join: %v", err)
	}

	tr4, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", Queue: 256, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	state4 := newHostState(4, tr4)
	state4.startHost(t)
	states = append(states, state4)
	defer func() { _ = state4.host.Close() }()
	if _, err := state4.host.StartGroup(GroupConfig{
		ID: 100, Join: true, Peers: peers,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	}); err != nil {
		t.Fatalf("start joining group: %v", err)
	}
	leader := states[leaderIdx].host
	if err := leader.AddLearner(ctx, 100, 4, tr4.Addr()); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	status, err := leader.Status(100)
	if err != nil {
		t.Fatal(err)
	}
	if err := state4.host.WaitApplied(ctx, 100, status.Commit); err != nil {
		t.Fatalf("join host applied: %v", err)
	}
	if got := state4.fsms[100].value("before"); got != "host-join" {
		t.Fatalf("join host value = %q", got)
	}
	res, err := leader.Propose(ctx, 100, []byte("after=host-join"))
	if err != nil {
		t.Fatalf("propose after join: %v", err)
	}
	if err := state4.host.WaitApplied(ctx, 100, res.Index); err != nil {
		t.Fatalf("join host live applied: %v", err)
	}
	if got := state4.fsms[100].value("after"); got != "host-join" {
		t.Fatalf("join host live value = %q", got)
	}
}
