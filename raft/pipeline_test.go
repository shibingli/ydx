package raft

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestPipelinedProposalsWithSnapshots keeps a deep proposal window while
// snapshots repeatedly compact the log and stream to followers. It is a
// regression test for stale AppendEntries responses re-entering a follower that
// is already receiving a snapshot. | TestPipelinedProposalsWithSnapshots 在快照
// 反复压缩日志并流向跟随者时保持较深的提案窗口。它回归测试“快照传输中的跟随者被
// 过时 AppendEntries 响应重新拉回普通复制”的问题。
func TestPipelinedProposalsWithSnapshots(t *testing.T) {
	c := newTestCluster(t, 3, func(cfg *Config) {
		cfg.SnapshotEntries = 128
		cfg.SnapshotCatchUpEntries = 16
		cfg.MaxBatchEntries = 64
	})
	leader := c.waitLeader(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const (
		workers   = 8
		depth     = 8
		perWorker = 500
	)
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			pending := make([]*Future, 0, depth)
			flush := func() error {
				_, err := pending[0].Wait(ctx)
				pending = pending[1:]
				return err
			}
			for i := 0; i < perWorker; i++ {
				f, err := leader.ProposeAsync(ctx, []byte(fmt.Sprintf("w%d-%d=v", w, i)))
				if err != nil {
					errCh <- err
					return
				}
				pending = append(pending, f)
				if len(pending) == depth {
					if err := flush(); err != nil {
						errCh <- err
						return
					}
				}
			}
			for len(pending) > 0 {
				if err := flush(); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		st := leader.Status()
		t.Fatalf("pipeline stalled: state=%s commit=%d applied=%d last=%d voters=%v learners=%v",
			st.State, st.Commit, st.Applied, st.LastIndex, st.Voters, st.Learners)
	}
	close(errCh)
	for err := range errCh {
		t.Fatalf("pipeline proposal: %v", err)
	}
	last := leader.Commit()
	for id := range c.nodes {
		c.waitApplied(id, last, 10*time.Second)
	}
	if got := c.fsms[leader.ID()].appliedCount(); got != workers*perWorker {
		t.Fatalf("applied %d commands, want %d", got, workers*perWorker)
	}
}

// TestFutureStoreReplacement checks that reusing an index fails the superseded
// waiter instead of orphaning it. | TestFutureStoreReplacement 检查复用索引时让
// 被取代的等待者失败，而不是将其遗弃。
func TestFutureStoreReplacement(t *testing.T) {
	s := newFutureStore()
	first := newFuture(7, 1)
	second := newFuture(7, 1)
	s.add(first)
	s.add(second)
	select {
	case r := <-first.ch:
		if !errors.Is(r.err, ErrProposalDropped) {
			t.Fatalf("superseded future error = %v", r.err)
		}
	default:
		t.Fatal("superseded future was not failed")
	}
	if got := s.take(7); got != second {
		t.Fatalf("take returned %p, want second future %p", got, second)
	}
}

// TestStaleAppendRespDuringSnapshot checks that an append response sent before
// a snapshot transfer cannot switch the follower back to normal replication.
// | TestStaleAppendRespDuringSnapshot 检查快照传输开始前发出的追加响应不会把
// 跟随者切回普通复制。
func TestStaleAppendRespDuringSnapshot(t *testing.T) {
	n := &Node{
		id:      1,
		state:   StateLeader,
		term:    5,
		log:     &raftLog{firstIndex: 1, lastIndex: 10},
		metrics: newMetrics(),
		progress: map[NodeID]*progress{
			2: {state: snapshot, match: 4, next: 5, inflights: newInflights(8, 1<<20)},
		},
	}
	n.handleAppendResp(Message{Type: MsgAppResp, From: 2, To: 1, Term: 5, Index: 10})
	pr := n.progress[2]
	if pr.state != snapshot {
		t.Fatalf("progress state = %s, want snapshot", pr.state)
	}
	if pr.match != 4 || pr.next != 5 {
		t.Fatalf("progress match=%d next=%d, want 4/5", pr.match, pr.next)
	}
	n.handleAppendResp(Message{Type: MsgAppResp, From: 2, To: 1, Term: 5, Index: 3, Reject: true, RejectHint: 3})
	if pr.state != snapshot || pr.match != 4 || pr.next != 5 {
		t.Fatalf("reject changed snapshot progress: state=%s match=%d next=%d", pr.state, pr.match, pr.next)
	}
}

// TestProposalQueueStripedIntake checks the bounded striped intake preserves
// every accepted proposal exactly once and rejects overflow. | TestProposalQueueStripedIntake
// 检查有界分片入口对每个已接受提案恰好保留一次，并拒绝溢出。
func TestProposalQueueStripedIntake(t *testing.T) {
	q := newProposalQueue(proposalShards)
	pushed := make(map[*proposal]bool)
	for i := 0; i < proposalShards*4; i++ {
		p := newProposal([]byte{byte(i)}, true)
		if err := q.push(p); err == nil {
			pushed[p] = true
		} else if !errors.Is(err, ErrBusy) {
			t.Fatalf("push error = %v", err)
		}
	}
	if len(pushed) == 0 || len(pushed) > proposalShards {
		t.Fatalf("accepted %d proposals, want 1..%d", len(pushed), proposalShards)
	}
	got := 0
	for {
		batch := q.popBatch(proposalShards)
		if len(batch) == 0 {
			break
		}
		for _, p := range batch {
			if !pushed[p] {
				t.Fatalf("popped unexpected proposal")
			}
			delete(pushed, p)
			got++
		}
	}
	if got == 0 || len(pushed) != 0 || q.hasItems() {
		t.Fatalf("popped %d, leftover %d, hasItems=%v", got, len(pushed), q.hasItems())
	}
	if drained := q.drainAndClose(); len(drained) != 0 {
		t.Fatalf("drained %d after empty", len(drained))
	}
	if err := q.push(newProposal(nil, true)); !errors.Is(err, ErrStopped) {
		t.Fatalf("push after close = %v", err)
	}
}

// TestApplyQueueCloseDropsPending verifies shutdown cannot be stuck draining a
// backlog that can no longer be acknowledged. | TestApplyQueueCloseDropsPending
// 验证关闭时不会因排空无法再确认的积压而卡住。
func TestApplyQueueCloseDropsPending(t *testing.T) {
	q := newApplyQueue()
	q.push(applyTask{entries: []Entry{{Index: 1}}})
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("closed queue returned a task")
	}
}
