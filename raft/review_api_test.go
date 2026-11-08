package raft

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestSingleNodeReadIndexBarrier covers ReadIndex and Barrier on a one-voter
// cluster, which has no peer to answer a heartbeat round. | TestSingleNodeReadIndexBarrier
// 覆盖单投票成员集群的 ReadIndex 与 Barrier；该集群没有对端应答心跳轮次。
func TestSingleNodeReadIndexBarrier(t *testing.T) {
	c := newTestCluster(t, 1, nil)
	leader := c.waitLeader(3 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := leader.Propose(ctx, []byte("a=1"))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	index, err := leader.ReadIndex(ctx)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	if index < res.Index {
		t.Fatalf("read index %d < committed %d", index, res.Index)
	}
	if err := leader.Barrier(ctx); err != nil {
		t.Fatalf("barrier: %v", err)
	}
}

// TestWaitAppliedAfterClose verifies WaitApplied does not hang after Close.
// | TestWaitAppliedAfterClose 验证 Close 后 WaitApplied 不会挂起。
func TestWaitAppliedAfterClose(t *testing.T) {
	c := newTestCluster(t, 1, nil)
	leader := c.waitLeader(3 * time.Second)
	done := make(chan error, 1)
	go func() { done <- leader.WaitApplied(context.Background(), 1<<40) }()
	time.Sleep(20 * time.Millisecond)
	if err := leader.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrStopped) {
			t.Fatalf("error = %v, want ErrStopped", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitApplied did not return after Close")
	}
}

// TestInvalidTransportDoesNotBootstrap verifies a failed New leaves storage
// untouched. | TestInvalidTransportDoesNotBootstrap 验证失败的 New 不修改存储。
func TestInvalidTransportDoesNotBootstrap(t *testing.T) {
	storage := NewMemStorage()
	_, err := New(Config{
		ID:      1,
		Peers:   []Peer{{ID: 1}, {ID: 2}},
		Storage: storage,
		FSM:     newKVFSM(),
	})
	if err == nil {
		t.Fatal("New accepted a multi-node cluster without a transport")
	}
	rec, loadErr := storage.Load()
	if loadErr != nil {
		t.Fatalf("load: %v", loadErr)
	}
	if len(rec.Entries) != 0 || rec.Snapshot != nil || rec.HardState.Term != 0 {
		t.Fatalf("failed New mutated storage: %+v", rec)
	}
}

// failingSnapshotFSM fails every Snapshot call. | failingSnapshotFSM 在每次
// Snapshot 调用时失败。
type failingSnapshotFSM struct{ *kvFSM }

// Snapshot implements FSM. | Snapshot 实现 FSM。
func (f *failingSnapshotFSM) Snapshot() ([]byte, error) {
	return nil, errors.New("snapshot boom")
}

// TestSnapshotFailureDoesNotWedge verifies a failed manual capture clears the
// in-flight flag so the next call also completes. | TestSnapshotFailureDoesNotWedge
// 验证失败的手动捕获会清除进行中标志，使下一次调用也能完成。
func TestSnapshotFailureDoesNotWedge(t *testing.T) {
	net := NewMemNetwork()
	defer net.Close()
	transport, err := net.NewTransport(1)
	if err != nil {
		t.Fatal(err)
	}
	fsm := &failingSnapshotFSM{kvFSM: newKVFSM()}
	node, err := New(Config{
		ID: 1, Storage: NewMemStorage(), FSM: fsm, Transport: transport,
		TickInterval: time.Millisecond, HeartbeatTicks: 1, ElectionTicks: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	deadline := time.Now().Add(3 * time.Second)
	for node.State() != StateLeader && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if node.State() != StateLeader {
		t.Fatalf("node did not become leader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := node.Propose(ctx, []byte("a=1")); err != nil {
		t.Fatalf("propose: %v", err)
	}
	for i := 0; i < 2; i++ {
		callCtx, callCancel := context.WithTimeout(ctx, time.Second)
		err := node.Snapshot(callCtx)
		callCancel()
		if err == nil {
			t.Fatalf("snapshot %d unexpectedly succeeded", i)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("snapshot %d hung after failure", i)
		}
	}
}

// TestPipelinedProposalsProgress stresses the async proposal path.
// | TestPipelinedProposalsProgress 对异步提案路径施加压力。
func TestPipelinedProposalsProgress(t *testing.T) {
	c := newTestCluster(t, 3, func(cfg *Config) {
		cfg.MaxBatchEntries = 128
		cfg.MaxInflightMsgs = 128
		cfg.MaxInflightBytes = 16 << 20
		cfg.ProposalQueue = 65536
		cfg.MessageQueue = 65536
		cfg.OutboundQueue = 65536
		cfg.SnapshotEntries = 1 << 30
		// This test saturates every replica with 160k pipelined proposals; the default 40ms
		// election timeout is below shared-runner scheduling jitter, so a healthy leader can
		// miss heartbeats and step down. Elections are not under test here. |
		// 本测试用 16 万条流水线提案压满每个副本；默认 40ms 选举超时低于共享运行器的调度抖动，
		// 健康领导者可能错过心跳而退位。此处不测试选举。
		cfg.ElectionTicks = 200
	})
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const workers = 8
	const depth = 16
	const perWorker = 20000
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			pending := make([]*Future, 0, depth)
			for i := 0; i < perWorker; i++ {
				f, err := leader.ProposeAsync(ctx, []byte("k=v"))
				if err != nil {
					errCh <- err
					return
				}
				pending = append(pending, f)
				if len(pending) == depth {
					if _, err := pending[0].Wait(ctx); err != nil {
						errCh <- err
						return
					}
					pending = pending[1:]
				}
			}
			for _, f := range pending {
				if _, err := f.Wait(ctx); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(25 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("pipelined proposals stalled: commit=%d applied=%d stats=%+v\n%s",
			leader.Commit(), leader.Applied(), leader.Stats(), buf[:n])
	}
	close(errCh)
	for err := range errCh {
		t.Fatalf("pipeline error: %v", err)
	}
}

// TestFollowerObservesConfChanges verifies every replica reports membership
// changes when the entries enter its log. | TestFollowerObservesConfChanges 验证
// 每个副本在成员变更项进入日志时都会上报。
func TestFollowerObservesConfChanges(t *testing.T) {
	var mu sync.Mutex
	counts := map[NodeID]int{}
	c := newTestCluster(t, 3, func(cfg *Config) {
		id := cfg.ID
		cfg.OnConfChange = func(ConfState) {
			mu.Lock()
			counts[id]++
			mu.Unlock()
		}
	})
	leader := c.waitLeader(5 * time.Second)
	c.addNode(4, true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := leader.AddLearner(ctx, 4, ""); err != nil {
		t.Fatalf("add learner: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := counts[1] > 0 && counts[2] > 0 && counts[3] > 0 && counts[4] > 0
		mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	got := map[NodeID]int{}
	for id, n := range counts {
		got[id] = n
	}
	mu.Unlock()
	t.Fatalf("conf callbacks = %v, want every node", got)
}
