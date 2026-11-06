package raft

import (
	"math/bits"
	"math/rand/v2"
	"sync"
	"sync/atomic"
)

// proposalShards is the number of lock-striped intake queues. Power of two.
// | proposalShards 是锁分片的提案入口数量，必须是 2 的幂。
const proposalShards = 64

// proposalShard is one lock-protected intake stripe. | proposalShard 是一个带锁的
// 入口分片。
type proposalShard struct {
	items []*proposal
	mu    sync.Mutex
}

// proposalQueue is a bounded multi-producer intake drained in batches by the
// Raft event loop. Producers hash onto lock-striped queues, so 32 concurrent
// clients rarely contend on one mutex; a per-shard empty-to-nonempty transition
// signals a shared notify channel. A bitmask lets the event loop find ready
// shards without scanning all of them. | proposalQueue 是有界多生产者入口，由 Raft
// 事件循环批量取出。生产者散列到锁分片队列，32 个并发客户端很少争用同一互斥锁；
// 分片由空变非空时通知共享通道。位图让事件循环无需扫描全部分片即可找到就绪分片。
type proposalQueue struct {
	notify chan struct{}
	shards [proposalShards]proposalShard
	ready  atomic.Uint64
	limit  int
	closed atomic.Bool
}

// newProposalQueue returns a bounded striped queue. | newProposalQueue 返回有界分片
// 队列。
func newProposalQueue(limit int) *proposalQueue {
	if limit < proposalShards {
		limit = proposalShards
	}
	return &proposalQueue{notify: make(chan struct{}, 1), limit: limit / proposalShards}
}

// push appends one proposal. It returns ErrBusy when the selected stripe is full
// and ErrStopped after close. | push 追加一个提案。选中的分片已满时返回 ErrBusy，
// 关闭后返回 ErrStopped。
func (q *proposalQueue) push(p *proposal) error {
	// A per-P random source distributes producers without a contended atomic
	// counter on every proposal. | 每个 P 的随机源分散生产者，避免每个提案争用
	// 同一个原子计数器。
	idx := int(rand.Uint64() & (proposalShards - 1))
	sh := &q.shards[idx]
	sh.mu.Lock()
	if q.closed.Load() {
		sh.mu.Unlock()
		return ErrStopped
	}
	if len(sh.items) >= q.limit {
		sh.mu.Unlock()
		return ErrBusy
	}
	empty := len(sh.items) == 0
	sh.items = append(sh.items, p)
	if empty {
		q.ready.Or(uint64(1) << idx)
	}
	sh.mu.Unlock()
	if empty {
		q.signal()
	}
	return nil
}

// signal wakes the event loop if it is not already notified. | signal 在事件循环
// 尚未收到通知时唤醒它。
func (q *proposalQueue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// popBatch removes up to n proposals from one ready stripe. The returned slice
// is never mutated by later appends: a stripe only grows at the tail or resets
// when empty. | popBatch 从一个就绪分片取出至多 n 个提案。后续追加只发生在尾部或
// 空分片重置，因此返回切片不会被修改。
func (q *proposalQueue) popBatch(n int) []*proposal {
	if n <= 0 {
		return nil
	}
	for {
		mask := q.ready.Load()
		if mask == 0 {
			return nil
		}
		idx := bits.TrailingZeros64(mask)
		sh := &q.shards[idx]
		sh.mu.Lock()
		if len(sh.items) == 0 {
			q.ready.And(^(uint64(1) << idx))
			sh.mu.Unlock()
			continue
		}
		if n > len(sh.items) {
			n = len(sh.items)
		}
		out := sh.items[:n]
		sh.items = sh.items[n:]
		if len(sh.items) == 0 {
			sh.items = nil
			q.ready.And(^(uint64(1) << idx))
		}
		sh.mu.Unlock()
		return out
	}
}

// hasItems reports whether any stripe has work. | hasItems 报告是否有任一分片仍有
// 工作。
func (q *proposalQueue) hasItems() bool { return q.ready.Load() != 0 }

// drainAndClose removes every queued proposal and rejects future pushes. | drainAndClose
// 取出所有排队提案并拒绝后续追加。
func (q *proposalQueue) drainAndClose() []*proposal {
	q.closed.Store(true)
	var out []*proposal
	for i := 0; i < proposalShards; i++ {
		sh := &q.shards[i]
		sh.mu.Lock()
		out = append(out, sh.items...)
		sh.items = nil
		q.ready.And(^(uint64(1) << i))
		sh.mu.Unlock()
	}
	return out
}
