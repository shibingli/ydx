package pool

import (
	"math/bits"
	"sync/atomic"
)

// cacheLine is the padding unit for hot shared counters. | cacheLine 是热共享计数器的填充单位。
//
// 64 bytes covers the common x86-64 and 32-bit ARM cache line; the padding keeps
// independent producers and consumers from bouncing one line between cores. |
// 64 字节覆盖常见的 x86-64 与 32 位 ARM 缓存行；填充避免独立的生产者与消费者在同一
// 缓存行上往返。
const cacheLine = 64

// maxRingCapacity bounds queue allocation so a hostile or accidental option cannot
// overflow the power-of-two rounding. | maxRingCapacity 限制队列分配，避免恶意或误用的
// 选项让 2 的幂取整溢出。
const maxRingCapacity = 1 << 24

// paddedSeq keeps one slot sequence number on its own cache line. | paddedSeq 让每个槽位
// 的序列号独占一条缓存行。
type paddedSeq struct {
	v atomic.Uint64
	_ [cacheLine - 8]byte
}

// paddedPos keeps one ring position on its own cache line. | paddedPos 让环的位置计数器
// 独占一条缓存行。
type paddedPos struct {
	v atomic.Uint64
	_ [cacheLine - 8]byte
}

// ring is a bounded lock-free multi-producer multi-consumer queue. | ring 是有界无锁
// 多生产者多消费者队列。
//
// It implements Dmitry Vyukov's sequence-number algorithm: producers reserve a
// tail position with CAS and then publish the slot sequence, consumers reserve a
// head position with CAS and publish the next round's sequence. Every dequeued
// value is cleared so the ring never keeps task closures or contexts alive. |
// 它实现 Dmitry Vyukov 的序列号算法：生产者用 CAS 预占 tail 位置后发布槽位序列号，
// 消费者用 CAS 预占 head 位置后发布下一轮序列号。每个出队的值都会被清零，避免环长期
// 持有任务闭包或 context。
type ring[T any] struct {
	seqs []paddedSeq
	vals []T
	head paddedPos
	tail paddedPos
	mask uint64
}

// newRing creates a ring whose capacity is the next power of two at least capacity,
// clamped to maxRingCapacity. | newRing 创建容量为不小于 capacity 的下一个 2 的幂的环，
// 上限为 maxRingCapacity。
func newRing[T any](capacity int) *ring[T] {
	if capacity < 2 {
		capacity = 2
	}
	if capacity > maxRingCapacity {
		capacity = maxRingCapacity
	}
	size := 1 << bits.Len(uint(capacity-1))
	r := &ring[T]{
		mask: uint64(size - 1),
		seqs: make([]paddedSeq, size),
		vals: make([]T, size),
	}
	for i := range r.seqs {
		r.seqs[i].v.Store(uint64(i))
	}
	return r
}

// tryEnqueue appends v and reports whether the ring had room. | tryEnqueue 追加 v，
// 并报告环中是否有空位。
func (r *ring[T]) tryEnqueue(v T) bool {
	for {
		pos := r.tail.v.Load()
		slot := &r.seqs[pos&r.mask]
		seq := slot.v.Load()
		dif := int64(seq) - int64(pos)
		if dif == 0 {
			if r.tail.v.CompareAndSwap(pos, pos+1) {
				r.vals[pos&r.mask] = v
				slot.v.Store(pos + 1)
				return true
			}
			continue
		}
		if dif < 0 {
			return false
		}
	}
}

// tryDequeue removes the oldest value and reports whether one was available. | tryDequeue
// 取出最旧的值，并报告是否取到。
func (r *ring[T]) tryDequeue() (T, bool) {
	for {
		pos := r.head.v.Load()
		slot := &r.seqs[pos&r.mask]
		seq := slot.v.Load()
		dif := int64(seq) - int64(pos+1)
		if dif == 0 {
			if r.head.v.CompareAndSwap(pos, pos+1) {
				idx := pos & r.mask
				v := r.vals[idx]
				var zero T
				r.vals[idx] = zero
				slot.v.Store(pos + r.mask + 1)
				return v, true
			}
			continue
		}
		if dif < 0 {
			var zero T
			return zero, false
		}
	}
}

// len returns the approximate number of queued values. | len 返回排队值的近似数量。
//
// Concurrent producers and consumers make the result a snapshot, never a hard
// guarantee. | 并发生产与消费使其只是快照，不构成硬性保证。
func (r *ring[T]) len() int {
	tail := r.tail.v.Load()
	head := r.head.v.Load()
	if tail <= head {
		return 0
	}
	n := tail - head
	if size := r.mask + 1; n > size {
		n = size
	}
	return int(n)
}

// tailPos returns the monotonically increasing number of successful enqueues. | tailPos
// 返回成功入队次数的单调递增值。
func (r *ring[T]) tailPos() uint64 { return r.tail.v.Load() }

// headPos returns the monotonically increasing number of successful dequeues. | headPos
// 返回成功出队次数的单调递增值。
func (r *ring[T]) headPos() uint64 { return r.head.v.Load() }
