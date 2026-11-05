package raft

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// hostState holds one NodeHost and its per-group test state. | hostState 持有一个
// NodeHost 及其每组的测试状态。
type hostState struct {
	id        NodeID
	host      *NodeHost
	transport Transport
	stores    map[GroupID]*MemStorage
	fsms      map[GroupID]*kvFSM
}

// newHostState builds factories backed by the maps. | newHostState 构建由 map 支撑的
// 工厂。
func newHostState(id NodeID, transport Transport) *hostState {
	s := &hostState{id: id, transport: transport, stores: make(map[GroupID]*MemStorage), fsms: make(map[GroupID]*kvFSM)}
	return s
}

// startHost creates the NodeHost with the state's factories. | startHost 用状态的工厂
// 创建 NodeHost。
func (s *hostState) startHost(t *testing.T) {
	t.Helper()
	host, err := NewNodeHost(NodeHostConfig{
		ID:        s.id,
		Transport: s.transport,
		Storage: func(g GroupID) (Storage, error) {
			if st := s.stores[g]; st != nil {
				return st, nil
			}
			st := NewMemStorage()
			s.stores[g] = st
			return st, nil
		},
		FSM: func(g GroupID) (FSM, error) {
			if f := s.fsms[g]; f != nil {
				return f, nil
			}
			f := newKVFSM()
			s.fsms[g] = f
			return f, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.host = host
}

// startGroup starts one group with common test tuning. | startGroup 以通用测试参数
// 启动一个组。
func startGroup(t *testing.T, host *NodeHost, id GroupID, peers []Peer) {
	t.Helper()
	if _, err := host.StartGroup(GroupConfig{
		ID: id, Peers: peers,
		TickInterval: 5 * time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	}); err != nil {
		t.Fatalf("start group %d: %v", id, err)
	}
}

// waitHostLeader waits for exactly one leader in a group. | waitHostLeader 等待一个组
// 内恰好一个领导者。
func waitHostLeader(t *testing.T, states []*hostState, group GroupID) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		leaders, index := 0, -1
		for i, s := range states {
			g, ok := s.host.Group(group)
			if ok && g.Node().State() == StateLeader {
				leaders++
				index = i
			}
		}
		if leaders == 1 {
			return index
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("group %d has no single leader", group)
	return -1
}

// proposeGroup proposes with a small retry across leadership changes. | proposeGroup
// 在领导权变化时做少量重试。
func proposeGroup(t *testing.T, states []*hostState, group GroupID, data []byte) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for attempt := 0; attempt < 5; attempt++ {
		idx := waitHostLeader(t, states, group)
		res, err := states[idx].host.Propose(ctx, group, data)
		if err == nil {
			return res
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("propose to group %d failed", group)
	return Result{}
}

// TestNodeHostTwoGroups verifies group isolation and restart recovery. | TestNodeHostTwoGroups
// 验证组隔离与重启恢复。
func TestNodeHostTwoGroups(t *testing.T) {
	net := NewMemNetwork()
	defer net.Close()
	peers := []Peer{{ID: 1}, {ID: 2}, {ID: 3}}
	states := make([]*hostState, 3)
	for i := range states {
		tr, err := net.NewTransport(NodeID(i + 1))
		if err != nil {
			t.Fatal(err)
		}
		states[i] = newHostState(NodeID(i+1), tr)
		states[i].startHost(t)
		for _, group := range []GroupID{10, 20} {
			startGroup(t, states[i].host, group, peers)
		}
	}
	defer func() {
		for _, s := range states {
			if s.host != nil {
				_ = s.host.Close()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res10 := proposeGroup(t, states, 10, []byte("a=1"))
	res20 := proposeGroup(t, states, 20, []byte("b=2"))
	for _, s := range states {
		if err := s.host.WaitApplied(ctx, 10, res10.Index); err != nil {
			t.Fatalf("host %d group 10 apply: %v", s.id, err)
		}
		if err := s.host.WaitApplied(ctx, 20, res20.Index); err != nil {
			t.Fatalf("host %d group 20 apply: %v", s.id, err)
		}
		if got := s.fsms[10].value("a"); got != "1" {
			t.Fatalf("host %d group 10 a = %q", s.id, got)
		}
		if got := s.fsms[20].value("b"); got != "2" {
			t.Fatalf("host %d group 20 b = %q", s.id, got)
		}
		if got := s.fsms[10].value("b"); got != "" {
			t.Fatalf("group 10 leaked group 20 data: %q", got)
		}
		if got := s.fsms[20].value("a"); got != "" {
			t.Fatalf("group 20 leaked group 10 data: %q", got)
		}
		if got := s.host.Groups(); len(got) != 2 {
			t.Fatalf("host %d groups = %v", s.id, got)
		}
	}
	// Restart host 3 and recover both groups from the same stores. | 重启主机 3，
	// 从同一存储恢复两个组。
	restarted := states[2]
	if err := restarted.host.Close(); err != nil {
		t.Fatal(err)
	}
	tr, err := net.NewTransport(3)
	if err != nil {
		t.Fatal(err)
	}
	restarted.transport = tr
	restarted.startHost(t)
	for _, group := range []GroupID{10, 20} {
		startGroup(t, restarted.host, group, peers)
	}
	res10b := proposeGroup(t, states, 10, []byte("a=3"))
	res20b := proposeGroup(t, states, 20, []byte("b=4"))
	for _, s := range states {
		if err := s.host.WaitApplied(ctx, 10, res10b.Index); err != nil {
			t.Fatalf("host %d group 10 after restart: %v", s.id, err)
		}
		if err := s.host.WaitApplied(ctx, 20, res20b.Index); err != nil {
			t.Fatalf("host %d group 20 after restart: %v", s.id, err)
		}
		if got := s.fsms[10].value("a"); got != "3" {
			t.Fatalf("host %d group 10 a = %q", s.id, got)
		}
		if got := s.fsms[20].value("b"); got != "4" {
			t.Fatalf("host %d group 20 b = %q", s.id, got)
		}
	}
}

// TestNodeHostTCPGroups verifies group multiplexing over the wire. | TestNodeHostTCPGroups
// 验证线上组多路复用。
func TestNodeHostTCPGroups(t *testing.T) {
	const size = 3
	transports := make([]*TCPTransport, size)
	peers := make([]Peer, size)
	for i := 0; i < size; i++ {
		tr, err := NewTCPTransport(TCPTransportOptions{ListenAddr: "127.0.0.1:0", Queue: 256})
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
		for _, group := range []GroupID{100, 200} {
			startGroup(t, states[i].host, group, peers)
		}
	}
	defer func() {
		for _, s := range states {
			if s.host != nil {
				_ = s.host.Close()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res1 := proposeGroup(t, states, 100, []byte("x=tcp"))
	res2 := proposeGroup(t, states, 200, []byte("y=tcp"))
	for _, s := range states {
		if err := s.host.WaitApplied(ctx, 100, res1.Index); err != nil {
			t.Fatalf("host %d group 100: %v", s.id, err)
		}
		if err := s.host.WaitApplied(ctx, 200, res2.Index); err != nil {
			t.Fatalf("host %d group 200: %v", s.id, err)
		}
		if got := s.fsms[100].value("x"); got != "tcp" {
			t.Fatalf("host %d group 100 x = %q", s.id, got)
		}
		if got := s.fsms[200].value("y"); got != "tcp" {
			t.Fatalf("host %d group 200 y = %q", s.id, got)
		}
	}
}

// TestListGroups scans persisted group directories. | TestListGroups 扫描持久化组目录。
func TestListGroups(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "group-3"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "group-1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "not-a-group"), 0o700); err != nil {
		t.Fatal(err)
	}
	ids, err := ListGroups(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 3 {
		t.Fatalf("groups = %v", ids)
	}
}
