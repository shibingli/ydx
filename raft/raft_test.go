package raft

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// kvFSM is a small deterministic state machine for tests. | kvFSM 是测试用的小型
// 确定性状态机。
type kvFSM struct {
	mu      sync.RWMutex
	data    map[string]string
	applied []string
	index   uint64
}

// newKVFSM returns an empty state machine. | newKVFSM 返回空状态机。
func newKVFSM() *kvFSM {
	return &kvFSM{data: make(map[string]string)}
}

// Apply implements FSM. Commands are key=value pairs. | Apply 实现 FSM。命令为
// key=value 形式。
func (f *kvFSM) Apply(index, _ uint64, data []byte) any {
	key, value, ok := strings.Cut(string(data), "=")
	if !ok {
		return nil
	}
	f.mu.Lock()
	f.data[key] = value
	f.applied = append(f.applied, key+"="+value)
	f.index = index
	f.mu.Unlock()
	return value
}

// Snapshot implements FSM. | Snapshot 实现 FSM。
func (f *kvFSM) Snapshot() ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(f.data[k])
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// Restore implements FSM. | Restore 实现 FSM。
func (f *kvFSM) Restore(data []byte) error {
	next := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("bad snapshot line %q", line)
		}
		next[k] = v
	}
	f.mu.Lock()
	f.data = next
	f.applied = nil
	f.mu.Unlock()
	return nil
}

// value returns a key. | value 返回键值。
func (f *kvFSM) value(key string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.data[key]
}

// appliedCount returns how many commands were applied. | appliedCount 返回已应用命令数。
func (f *kvFSM) appliedCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.applied)
}

// testCluster wires nodes over a MemNetwork. | testCluster 通过 MemNetwork 连接节点。
type testCluster struct {
	t        *testing.T
	net      *MemNetwork
	nodes    map[NodeID]*Node
	fsms     map[NodeID]*kvFSM
	storages map[NodeID]Storage
	peers    []Peer
	tick     time.Duration
	tweak    func(*Config)
}

// newTestCluster starts n nodes with the given configuration tweaks. | newTestCluster
// 以给定配置调整启动 n 个节点。
func newTestCluster(t *testing.T, n int, tweak func(*Config)) *testCluster {
	t.Helper()
	peers := make([]Peer, n)
	for i := range peers {
		peers[i] = Peer{ID: NodeID(i + 1)}
	}
	c := &testCluster{
		t:        t,
		net:      NewMemNetwork(),
		nodes:    make(map[NodeID]*Node),
		fsms:     make(map[NodeID]*kvFSM),
		storages: make(map[NodeID]Storage),
		peers:    peers,
		tick:     5 * time.Millisecond,
		tweak:    tweak,
	}
	for _, p := range peers {
		c.addNode(p.ID, false)
	}
	t.Cleanup(c.close)
	return c
}

// addNode starts one more node. join skips bootstrap. | addNode 启动一个节点；join
// 跳过引导。
func (c *testCluster) addNode(id NodeID, join bool) {
	c.t.Helper()
	transport, err := c.net.NewTransport(id)
	if err != nil {
		c.t.Fatalf("new transport: %v", err)
	}
	storage := NewMemStorage()
	fsm := newKVFSM()
	cfg := Config{
		ID:              id,
		Peers:           c.peers,
		Join:            join,
		Storage:         storage,
		FSM:             fsm,
		Transport:       transport,
		TickInterval:    c.tick,
		HeartbeatTicks:  1,
		ElectionTicks:   8,
		MaxBatchEntries: 64,
	}
	if join {
		cfg.Peers = nil
	}
	if tweak := c.tweak; tweak != nil {
		tweak(&cfg)
	}
	node, err := New(cfg)
	if err != nil {
		c.t.Fatalf("new node %d: %v", id, err)
	}
	c.nodes[id] = node
	c.fsms[id] = fsm
	c.storages[id] = storage
}

// tweak is an optional hook. | tweak 是可选钩子。
func (c *testCluster) setTweak(fn func(*Config)) { c.tweak = fn }

// close shuts the cluster down. | close 关闭集群。
func (c *testCluster) close() {
	for _, node := range c.nodes {
		_ = node.Close()
	}
	c.net.Close()
}

// waitLeader waits for one leader and returns it. | waitLeader 等待一个领导者并返回。
func (c *testCluster) waitLeader(timeout time.Duration) *Node {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var leader *Node
		count := 0
		for _, node := range c.nodes {
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
	c.t.Fatalf("no single leader within %v", timeout)
	return nil
}

// waitApplied waits until node applied index. | waitApplied 等待节点应用 index。
func (c *testCluster) waitApplied(id NodeID, index uint64, timeout time.Duration) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.nodes[id].WaitApplied(ctx, index); err != nil {
		for nid, node := range c.nodes {
			c.t.Logf("node %d state=%s term=%d leader=%d commit=%d applied=%d status=%+v",
				nid, node.State(), node.Term(), node.Leader(), node.Commit(), node.Applied(), node.Status())
		}
		c.t.Fatalf("node %d wait applied %d: %v (applied=%d)", id, index, err, c.nodes[id].Applied())
	}
}

// TestSingleNodePropose covers the shortest write path. | TestSingleNodePropose 覆盖
// 最短写路径。
func TestSingleNodePropose(t *testing.T) {
	c := newTestCluster(t, 1, nil)
	leader := c.waitLeader(3 * time.Second)
	if leader.ID() != 1 {
		t.Fatalf("leader = %d", leader.ID())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := leader.Propose(ctx, []byte("a=1"))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if got := c.fsms[1].value("a"); got != "1" {
		t.Fatalf("value = %q, res=%+v", got, res)
	}
	if res.Index == 0 || res.Value != "1" {
		t.Fatalf("unexpected result %+v", res)
	}
	if leader.Applied() < res.Index {
		t.Fatalf("applied %d < %d", leader.Applied(), res.Index)
	}
}

// TestThreeNodeReplication replicates to every follower. | TestThreeNodeReplication
// 复制到每个跟随者。
func TestThreeNodeReplication(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := leader.Propose(ctx, []byte("k=v"))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	for id := range c.nodes {
		c.waitApplied(id, res.Index, 5*time.Second)
		if got := c.fsms[id].value("k"); got != "v" {
			t.Fatalf("node %d value = %q", id, got)
		}
	}
}

// TestConcurrentProposals checks batching and ordering under load. | TestConcurrentProposals
// 在负载下检查批处理与顺序。
func TestConcurrentProposals(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	const writers = 8
	const perWriter = 25
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errs := make(chan error, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				key := fmt.Sprintf("w%d-%d", w, i)
				if _, err := leader.Propose(ctx, []byte(key+"=1")); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("propose: %v", err)
	}
	last := leader.Commit()
	for id := range c.nodes {
		c.waitApplied(id, last, 10*time.Second)
		if got := c.fsms[id].appliedCount(); got != writers*perWriter {
			t.Fatalf("node %d applied %d commands, want %d", id, got, writers*perWriter)
		}
	}
}

// TestReadIndex checks the linearizable read barrier. | TestReadIndex 检查线性一致读
// 屏障。
func TestReadIndex(t *testing.T) {
	c := newTestCluster(t, 3, nil)
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := leader.Propose(ctx, []byte("x=42")); err != nil {
		t.Fatalf("propose: %v", err)
	}
	index, err := leader.ReadIndex(ctx)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	if err := leader.WaitApplied(ctx, index); err != nil {
		t.Fatalf("wait applied: %v", err)
	}
	if got := c.fsms[leader.ID()].value("x"); got != "42" {
		t.Fatalf("value = %q", got)
	}
}

// TestCodecRoundTrip covers message encoding including snapshots. | TestCodecRoundTrip
// 覆盖包含快照的消息编码。
func TestCodecRoundTrip(t *testing.T) {
	msgs := []Message{
		{Type: MsgVote, From: 1, To: 2, Group: 42, Term: 7, LogIndex: 9, LogTerm: 3},
		{Type: MsgAppResp, From: 2, To: 1, Term: 8, Index: 11, Reject: true, RejectHint: 4, RejectTerm: 2},
		{Type: MsgApp, From: 1, To: 2, Term: 9, LogIndex: 10, LogTerm: 9, Commit: 8,
			Entries: []Entry{
				{Index: 11, Term: 9, Type: EntryNormal, Data: []byte("hello")},
				{Index: 12, Term: 9, Type: EntryNoop},
			}},
		{Type: MsgHeartbeat, From: 1, To: 3, Term: 9, Commit: 12, Context: encodeRoundContext(42)},
		{Type: MsgSnap, From: 1, To: 3, Term: 9, Snapshot: &Snapshot{
			Index: 20, Term: 9,
			ConfState: ConfState{Voters: []NodeID{1, 2, 3}, Addresses: []Peer{{ID: 1, Addr: "a"}}},
			Data:      bytes.Repeat([]byte("x"), 1024),
		}},
	}
	for _, want := range msgs {
		data, err := MarshalMessage(want)
		if err != nil {
			t.Fatalf("marshal %s: %v", want.Type, err)
		}
		got, err := UnmarshalMessage(data)
		if err != nil {
			t.Fatalf("unmarshal %s: %v", want.Type, err)
		}
		if got.Type != want.Type || got.From != want.From || got.To != want.To || got.Group != want.Group || got.Term != want.Term ||
			got.LogIndex != want.LogIndex || got.LogTerm != want.LogTerm || got.Index != want.Index ||
			got.Commit != want.Commit || got.Reject != want.Reject ||
			got.RejectHint != want.RejectHint || got.RejectTerm != want.RejectTerm {
			t.Fatalf("header mismatch: got %+v want %+v", got, want)
		}
		if len(got.Entries) != len(want.Entries) {
			t.Fatalf("entries = %d want %d", len(got.Entries), len(want.Entries))
		}
		for i := range got.Entries {
			if got.Entries[i].Index != want.Entries[i].Index ||
				got.Entries[i].Term != want.Entries[i].Term ||
				got.Entries[i].Type != want.Entries[i].Type ||
				!bytes.Equal(got.Entries[i].Data, want.Entries[i].Data) {
				t.Fatalf("entry %d mismatch: %+v vs %+v", i, got.Entries[i], want.Entries[i])
			}
		}
		if want.Snapshot != nil {
			if got.Snapshot == nil || got.Snapshot.Index != want.Snapshot.Index ||
				got.Snapshot.Term != want.Snapshot.Term ||
				!bytes.Equal(got.Snapshot.Data, want.Snapshot.Data) ||
				!sameConfState(got.Snapshot.ConfState, want.Snapshot.ConfState) {
				t.Fatalf("snapshot mismatch")
			}
		}
		if len(want.Context) > 0 && !bytes.Equal(got.Context, want.Context) {
			t.Fatalf("context mismatch")
		}
	}
}

// TestUnmarshalRejectsCorruption checks bounds and trailing data. | TestUnmarshalRejectsCorruption
// 检查边界与尾随数据。
func TestUnmarshalRejectsCorruption(t *testing.T) {
	good, err := MarshalMessage(Message{Type: MsgApp, From: 1, To: 2, Term: 1,
		Entries: []Entry{{Index: 5, Term: 1, Type: EntryNormal, Data: []byte("abc")}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, {9}, append(append([]byte(nil), good...), 0), good[:len(good)-1]} {
		if _, err := UnmarshalMessage(data); err == nil {
			t.Fatalf("accepted corrupt input %v", data)
		}
	}
}
