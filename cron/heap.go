package cron

import (
	"container/heap"
	"sync/atomic"
	"time"
)

// entry is one scheduled job inside the scheduler and the timer heap. |
// entry 是调度器与定时器堆中的一个已调度任务。
type entry struct {
	// next is the next activation; zero means not scheduled. | next 是下次触发时刻；零值表示未调度。
	next time.Time
	// job is an immutable snapshot replaced by Update. | job 是不可变快照，由 Update 整体替换。
	job *Job
	// definition is the cached serializable view of job; snapshots reuse it instead
	// of rebuilding the definition on every List. | definition 是 job 的缓存可序列化视图；
	// 快照复用它，避免每次 List 重新构建定义。
	definition Definition
	// stats accumulates counters and the bounded history. | stats 累积计数器与有界历史。
	stats jobStats
	// index is the heap position; -1 means not in the heap. | index 是堆位置；-1 表示不在堆中。
	index int
	// running counts in-flight runs; the skip policy uses it as a 0/1 guard. |
	// running 统计在途运行；跳过策略把它当作 0/1 守卫。
	running atomic.Int32
	// removed marks an entry deleted from the scheduler map, so the enqueue hot
	// path can reject stale tasks without taking the scheduler lock. |
	// removed 标记已从调度器映射删除的元素，使入队热路径无需取调度器锁即可拒绝过期任务。
	removed atomic.Bool
}

// newEntry wraps a job and its cached definition outside the heap. |
// newEntry 在堆外包装任务及其缓存定义。
func newEntry(job *Job, definition Definition) *entry {
	return &entry{job: job, definition: definition, index: -1}
}

// entryBox co-allocates an entry with the job it owns, so Add pays one heap
// allocation instead of two. | entryBox 把元素与其拥有的任务放在同一次分配中，
// 使 Add 只付一次堆分配而不是两次。
type entryBox struct {
	// job is the job owned by item. | job 是 item 拥有的任务。
	job Job
	// item is the scheduler entry. | item 是调度器元素。
	item entry
}

// dueFire is one activation removed from the heap before dispatch. |
// dueFire 是派发前从堆中取出的一次触发。
type dueFire struct {
	entry *entry
	job   *Job
	at    time.Time
}

// timerHeap is a min-heap ordered by next activation, breaking ties by job id so
// equal schedules have deterministic order. | timerHeap 是按下次触发时刻排序的最小堆；
// 相同时按任务 ID 排序，使相同调度具有确定顺序。
type timerHeap []*entry

// Len returns the number of entries. | Len 返回元素数量。
func (h timerHeap) Len() int { return len(h) }

// Less orders by next activation and then by id. | Less 先按下次触发时刻、再按 ID 排序。
func (h timerHeap) Less(i, j int) bool {
	if h[i].next.Equal(h[j].next) {
		return h[i].job.ID < h[j].job.ID
	}
	return h[i].next.Before(h[j].next)
}

// Swap exchanges two entries and repairs their indices. | Swap 交换两个元素并修复索引。
func (h timerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

// Push appends an entry. | Push 追加元素。
func (h *timerHeap) Push(value any) {
	item := value.(*entry)
	item.index = len(*h)
	*h = append(*h, item)
}

// Pop removes the last entry. | Pop 移除末尾元素。
func (h *timerHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	old[last] = nil
	*h = old[:last]
	item.index = -1
	return item
}

// compile-time assertion that timerHeap implements heap.Interface. |
// 编译期断言 timerHeap 实现 heap.Interface。
var _ heap.Interface = (*timerHeap)(nil)
