package raft

import (
	"context"
	"sync"
)

// Result is the outcome of a committed proposal. | Result 是已提交提案的结果。
type Result struct {
	Index uint64
	Term  uint64
	Value any
}

// futureResult is the channel payload. | futureResult 是通道载荷。
type futureResult struct {
	result Result
	err    error
}

// Future waits for a proposal to be committed and applied. The zero value is
// not usable. | Future 等待提案被提交并应用。零值不可用。
type Future struct {
	index uint64
	term  uint64
	ch    chan futureResult
}

// newFuture builds a one-shot future. | newFuture 构建一次性 Future。
func newFuture(index, term uint64) *Future {
	return &Future{index: index, term: term, ch: make(chan futureResult, 1)}
}

// getFuture returns a reusable future for a synchronous Propose. | getFuture 为同步
// Propose 返回可复用的 Future。
func (n *Node) getFuture() *Future {
	if v := n.futurePool.Get(); v != nil {
		f := v.(*Future)
		f.index, f.term = 0, 0
		return f
	}
	return newFuture(0, 0)
}

// putFuture recycles a future after its only waiter received the outcome. The
// channel is drained defensively; Propose never recycles a future after a
// context cancellation because a late delivery may still target it. | putFuture
// 在唯一等待者收到结果后回收 Future。防御性地排空通道；Propose 在上下文取消后
// 不回收，因为迟到的投递仍可能指向它。
func (n *Node) putFuture(f *Future) {
	if f == nil {
		return
	}
	select {
	case <-f.ch:
	default:
	}
	f.index, f.term = 0, 0
	n.futurePool.Put(f)
}

// Index returns the log index reserved for the proposal. | Index 返回提案预留的日志
// 索引。
func (f *Future) Index() uint64 { return f.index }

// Term returns the term in which the proposal was appended. | Term 返回提案追加时的
// 任期。
func (f *Future) Term() uint64 { return f.term }

// Wait blocks until the proposal is applied, fails, or ctx expires. | Wait 阻塞到
// 提案被应用、失败或 ctx 到期。
func (f *Future) Wait(ctx context.Context) (Result, error) {
	if f == nil {
		return Result{}, ErrProposalDropped
	}
	// Pipelined clients almost always wait on a future that already completed.
	// A non-blocking receive avoids the much heavier multi-case select on that
	// path. | 流水线客户端等待的 Future 通常已经完成；非阻塞接收避免该路径上更重的
	// 多路 select。
	select {
	case r := <-f.ch:
		return r.result, r.err
	default:
	}
	select {
	case r := <-f.ch:
		return r.result, r.err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

// deliver records a successful outcome. | deliver 记录成功结果。
func (f *Future) deliver(value any) {
	select {
	case f.ch <- futureResult{result: Result{Index: f.index, Term: f.term, Value: value}}:
	default:
	}
}

// fail records a failure. | fail 记录失败。
func (f *Future) fail(err error) {
	if err == nil {
		err = ErrProposalDropped
	}
	select {
	case f.ch <- futureResult{err: err}:
	default:
	}
}

// futureShards is the number of index-sharded future maps. Power of two. More
// shards keep many concurrent proposers off the same lock without a measurable
// memory cost. | futureShards 是索引分片 Future map 的数量，必须是 2 的幂。
// 更多分片让大量并发提案避开同一把锁，且内存开销可忽略。
const futureShards = 64

// futureShard is one lock-protected map. | futureShard 是一个带锁的 map。
type futureShard struct {
	mu sync.Mutex
	m  map[uint64]*Future
}

// futureStore tracks proposals by log index. Apply runs on its own goroutine,
// so the store is the synchronization point between apply and the Raft loop.
// Sharding keeps producers and the apply worker off one global mutex. | futureStore
// 按日志索引跟踪提案。Apply 在独立协程运行，因此该存储是 apply 与 Raft 循环之间的
// 同步点。分片让生产者与 apply 协程避开单一全局互斥锁。
type futureStore struct {
	shards [futureShards]futureShard
}

// newFutureStore returns an empty store. | newFutureStore 返回空存储。
func newFutureStore() *futureStore {
	s := &futureStore{}
	for i := range s.shards {
		s.shards[i].m = make(map[uint64]*Future)
	}
	return s
}

// shard returns the shard for an index. | shard 返回索引对应的分片。
func (s *futureStore) shard(index uint64) *futureShard {
	return &s.shards[index&(futureShards-1)]
}

// add registers f. A later proposal at the same index supersedes and fails the
// earlier one instead of silently orphaning its waiter. | add 注册 f。同一索引的
// 后续提案会取代先前提案，并使先前的 Future 失败，而不是静默遗弃其等待者。
func (s *futureStore) add(f *Future) {
	sh := s.shard(f.index)
	sh.mu.Lock()
	if old := sh.m[f.index]; old != nil {
		old.fail(ErrProposalDropped)
	}
	sh.m[f.index] = f
	sh.mu.Unlock()
}

// take removes and returns the future at index. | take 移除并返回 index 处的 Future。
func (s *futureStore) take(index uint64) *Future {
	sh := s.shard(index)
	sh.mu.Lock()
	f := sh.m[index]
	if f != nil {
		delete(sh.m, index)
	}
	sh.mu.Unlock()
	return f
}

// failFrom fails every future at or after index. | failFrom 使 index 及之后的每个
// Future 失败。
func (s *futureStore) failFrom(index uint64, err error) {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for idx, f := range sh.m {
			if idx >= index {
				delete(sh.m, idx)
				f.fail(err)
			}
		}
		sh.mu.Unlock()
	}
}

// failAll fails every registered future. | failAll 使所有已注册 Future 失败。
func (s *futureStore) failAll(err error) {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for idx, f := range sh.m {
			delete(sh.m, idx)
			f.fail(err)
		}
		sh.mu.Unlock()
	}
}
