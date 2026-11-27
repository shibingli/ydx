package raft

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestMembershipUpdateNode changes one address without touching the sets. |
// TestMembershipUpdateNode 在不改变集合的情况下修改一个地址。
func TestMembershipUpdateNode(t *testing.T) {
	m := newMembership([]NodeID{1, 2, 3}, nil, map[NodeID]string{2: "old"})
	next, err := m.apply(ConfChange{Type: ConfChangeUpdateNode, NodeID: 2, Addr: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if got := next.addr(2); got != "new" {
		t.Fatalf("address = %q", got)
	}
	if next.joint() || !next.isVoter(2) || len(next.voters) != 3 {
		t.Fatalf("membership changed: %+v", next)
	}
	if got := m.addr(2); got != "old" {
		t.Fatalf("source membership mutated: %q", got)
	}
	if _, err := m.apply(ConfChange{Type: ConfChangeUpdateNode, NodeID: 9, Addr: "x"}); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("unknown node error = %v", err)
	}
	if _, err := m.apply(ConfChange{Type: ConfChangeUpdateNode, NodeID: 2}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty address error = %v", err)
	}
}

// TestConfChangeUpdateNodeCodec round-trips an address update. |
// TestConfChangeUpdateNodeCodec 往返编码地址更新。
func TestConfChangeUpdateNodeCodec(t *testing.T) {
	raw, err := encodeConfChange(ConfChange{Type: ConfChangeUpdateNode, NodeID: 3, Addr: "10.0.0.3:1"})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := decodeConfChange(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Type != ConfChangeUpdateNode || cc.NodeID != 3 || cc.Addr != "10.0.0.3:1" {
		t.Fatalf("round trip = %+v", cc)
	}
	if _, err := encodeConfChange(ConfChange{Type: ConfChangeUpdateNode, NodeID: 3}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty address encode error = %v", err)
	}
}

// TestUpdateNodeAddressRejectsEmpty checks the public API guard. |
// TestUpdateNodeAddressRejectsEmpty 检查公共 API 的空地址保护。
func TestUpdateNodeAddressRejectsEmpty(t *testing.T) {
	node, err := New(Config{ID: 1, Storage: NewMemStorage(), FSM: newKVFSM()})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	if err := node.UpdateNodeAddress(context.Background(), 2, ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
}

// peerAddressOf returns the address a status reports for id. | peerAddressOf
// 返回状态中 id 的地址。
func peerAddressOf(st Status, id NodeID) string {
	for _, p := range st.Peers {
		if p.ID == id {
			return p.Addr
		}
	}
	return ""
}

// TestClusterUpdateNodeAddressOverTCP restarts a follower on a new address and
// updates it through the replicated membership entry. | TestClusterUpdateNodeAddressOverTCP
// 用新地址重启跟随者，并通过复制的成员日志项更新地址。
func TestClusterUpdateNodeAddressOverTCP(t *testing.T) {
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
	nodes := make(map[NodeID]*Node, size)
	fsms := make(map[NodeID]*kvFSM, size)
	stores := make(map[NodeID]Storage, size)
	for i := 0; i < size; i++ {
		store := NewMemStorage()
		fsm := newKVFSM()
		node, err := New(Config{
			ID: NodeID(i + 1), Peers: peers, Storage: store, FSM: fsm,
			Transport: transports[i], TickInterval: 5 * time.Millisecond,
			HeartbeatTicks: 1, ElectionTicks: 8, MaxBatchEntries: 64,
		})
		if err != nil {
			t.Fatalf("node %d: %v", i+1, err)
		}
		nodes[NodeID(i+1)] = node
		fsms[NodeID(i+1)] = fsm
		stores[NodeID(i+1)] = store
	}
	defer func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	}()
	leader := waitOneLeader(t, nodes, 8*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := leader.Propose(ctx, []byte("before=1")); err != nil {
		t.Fatalf("propose before update: %v", err)
	}
	var follower NodeID
	for id := range nodes {
		if id != leader.ID() {
			follower = id
			break
		}
	}
	store := stores[follower]
	if err := nodes[follower].Close(); err != nil {
		t.Fatalf("close follower: %v", err)
	}

	trNew, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", Queue: 256, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	fsmNew := newKVFSM()
	nodeNew, err := New(Config{
		ID: follower, Peers: peers, Storage: store, FSM: fsmNew,
		Transport: trNew, TickInterval: 5 * time.Millisecond,
		HeartbeatTicks: 1, ElectionTicks: 8, MaxBatchEntries: 64,
	})
	if err != nil {
		t.Fatalf("restart follower: %v", err)
	}
	nodes[follower] = nodeNew
	fsms[follower] = fsmNew

	if err := leader.UpdateNodeAddress(ctx, follower, trNew.Addr()); err != nil {
		t.Fatalf("update address: %v", err)
	}
	if got := peerAddressOf(leader.Status(), follower); got != trNew.Addr() {
		t.Fatalf("leader address = %q, want %q", got, trNew.Addr())
	}
	res, err := leader.Propose(ctx, []byte("after=1"))
	if err != nil {
		t.Fatalf("propose after update: %v", err)
	}
	waitAppliedOn(t, nodeNew, res.Index, 15*time.Second)
	if got := fsmNew.value("after"); got != "1" {
		t.Fatalf("restarted follower value = %q", got)
	}
	if got := peerAddressOf(nodeNew.Status(), follower); got != trNew.Addr() {
		t.Fatalf("follower address = %q, want %q", got, trNew.Addr())
	}
}

// TestRemoveNodeReleasesTransportPeers verifies removed members are dropped from
// every surviving transport address book. | TestRemoveNodeReleasesTransportPeers
// 验证被移除成员会从所有幸存传输的地址簿中删除。
func TestRemoveNodeReleasesTransportPeers(t *testing.T) {
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
		})
		if err != nil {
			t.Fatalf("node %d: %v", i+1, err)
		}
		nodes[NodeID(i+1)] = node
		fsms[NodeID(i+1)] = fsm
	}
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
	defer func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	}()
	leader := waitOneLeader(t, nodes, 8*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := leader.AddLearner(ctx, 4, tr4.Addr()); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	waitAppliedOn(t, node4, leader.Commit(), 15*time.Second)
	if err := leader.RemoveNode(ctx, 4); err != nil {
		t.Fatalf("remove node: %v", err)
	}
	for i := 0; i < size; i++ {
		tr := transports[i]
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := tr.PeerAddress(4); !ok {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if _, ok := tr.PeerAddress(4); ok {
			t.Fatalf("node %d transport kept removed peer 4", i+1)
		}
	}
}

// TestTruncateConfigReconcilesTransport verifies a truncated configuration
// re-adds restored addresses and drops members it no longer contains. |
// TestTruncateConfigReconcilesTransport 验证被截断的配置会恢复成员地址并删除不再
// 包含的成员。
func TestTruncateConfigReconcilesTransport(t *testing.T) {
	base := newMembership(nil, nil, nil)
	one := newMembership([]NodeID{1}, nil, map[NodeID]string{1: "a1"})
	two := newMembership([]NodeID{1, 2}, nil, map[NodeID]string{1: "a1", 2: "a2"})

	removed := &recordingTransport{peers: map[NodeID]string{2: "a2"}}
	n := &Node{
		id: 1, cfg: Config{}, transport: removed,
		confBase: base, confHistory: []confVersion{{index: 2, conf: two}}, conf: two,
	}
	n.truncateConfig(2)
	if n.conf.isMember(2) {
		t.Fatal("node 2 survived truncation")
	}
	if got := removed.addr(2); got != "" {
		t.Fatalf("removed peer 2 address = %q", got)
	}

	restored := &recordingTransport{peers: make(map[NodeID]string)}
	r := &Node{
		id: 1, cfg: Config{}, transport: restored, confBase: base,
		confHistory: []confVersion{{index: 2, conf: two}, {index: 4, conf: one}}, conf: one,
	}
	r.truncateConfig(4)
	if !r.conf.isMember(2) {
		t.Fatal("node 2 not restored")
	}
	if got := restored.addr(2); got != "a2" {
		t.Fatalf("restored peer 2 address = %q", got)
	}
}
