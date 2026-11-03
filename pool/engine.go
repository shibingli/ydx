package pool

import (
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
)

// pendingBatch is the number of completed tasks a worker accumulates before
// decrementing the shared pending counter. Batching shrinks the number of
// cross-core atomic writes on the wait path by this factor. | pendingBatch 是 worker
// 递减共享 pending 计数前累计的完成任务数。批量处理把等待路径上的跨核原子写按此倍数
// 减少。
const pendingBatch = 64

// spaceSpin is the number of enqueue retries a blocked submitter performs before
// sleeping on the space condition. Under sustained load a worker frees a slot
// within a few iterations, so the mutex/condition handoff stays off the hot path. |
// spaceSpin 是阻塞提交方在休眠于 space 条件变量前进行入队重试的次数。持续负载下 worker
// 通常几次迭代就释放槽位，因此互斥量/条件变量的交接不会进入热路径。
const spaceSpin = 32

// Stats is a point-in-time snapshot of pool activity. | Stats 是协程池活动的瞬时快照。
//
// Queued and Running are approximate under concurrency; Submitted, Completed,
// Failed and Panicked are exact after Wait returns. Submitted counts tasks, so a
// batch of N contributes N. | 并发下 Queued 与 Running 是近似值；Wait 返回后
// Submitted、Completed、Failed 与 Panicked 是精确值。Submitted 按任务计数，因此长度为
// N 的批次贡献 N。
type Stats struct {
	// Workers is the number of live worker goroutines. | Workers 是存活的 worker 协程数。
	Workers int
	// TargetWorkers is the worker count requested by the last Resize. | TargetWorkers 是最近一次 Resize 请求的 worker 数。
	TargetWorkers int
	// Shards is the number of queue shards. | Shards 是队列分片数。
	Shards int
	// Capacity is the configured queue capacity across shards and fallback. | Capacity 是分片与 fallback 的配置容量总和。
	Capacity int
	// Queued is the approximate number of tasks waiting in queues. | Queued 是队列中等待任务的近似数量。
	Queued int
	// Running is the number of workers currently executing a task. | Running 是当前正在执行任务的 worker 数。
	Running int
	// Submitted is the number of accepted tasks. | Submitted 是已接受的任务数。
	Submitted uint64
	// Completed is the number of finished tasks, successful or not. | Completed 是已完成任务数（无论成功与否）。
	Completed uint64
	// Failed is the number of tasks that returned an error. | Failed 是返回错误的任务数。
	Failed uint64
	// Panicked is the number of tasks that panicked. | Panicked 是发生 panic 的任务数。
	Panicked uint64
	// Rejected is the number of submissions rejected by a closed or full pool. | Rejected 是被关闭或满队列拒绝的提交数。
	Rejected uint64
	// Fallback is the number of tasks accepted by the shared overflow ring. | Fallback 是由共享溢出环接受的任务数。
	Fallback uint64
	// Discarded is the number of queued tasks dropped by Close. | Discarded 是 Close 丢弃的排队任务数。
	Discarded uint64
}

// engineConfig is the normalized configuration shared by all pool kinds. | engineConfig
// 是各类协程池共享的归一化配置。
type engineConfig struct {
	workers      int
	shards       int
	queueSize    int
	fallbackSize int
	spinCount    int
	nonblocking  bool
	metrics      bool
}

// workerState is the per-worker identity and statistics. | workerState 是每个 worker 的
// 身份与统计。
type workerState struct {
	id        int
	retired   atomic.Bool
	_         [cacheLine]byte
	running   atomic.Bool
	processed atomic.Uint64
	failed    atomic.Uint64
	panicked  atomic.Uint64
	_         [cacheLine]byte
	// localDone is worker-exclusive and only read by its worker. | localDone 由 worker
	// 独占，只被其自身读取。
	localDone uint64
}

// count records finished work. Each counter is written only by its worker, so the
// atomic adds stay on a cache line the worker already owns. | count 记录已完成工作。
// 每个计数器只由其 worker 写入，因此原子加始终落在该 worker 已独占的缓存行上。
func (w *workerState) count(tasks, failed, panicked uint64) {
	if tasks > 0 {
		w.processed.Add(tasks)
	}
	if failed > 0 {
		w.failed.Add(failed)
	}
	if panicked > 0 {
		w.panicked.Add(panicked)
	}
}

// engine is the generic scheduling core shared by Pool, ResultPool and ParamPool.
// | engine 是 Pool、ResultPool 与 ParamPool 共享的泛型调度核心。
type engine[J any] struct {
	cfg          engineConfig
	shards       []*ring[J]
	shardMask    uint64
	perShard     int
	fallback     *ring[J]
	fallbackSize int

	run     func(*workerState, J)
	discard func(J)

	next paddedPos

	mu      sync.Mutex
	workers []*workerState
	target  int
	nextID  int

	wake     chan struct{}
	handoff  chan J
	stop     chan struct{}
	stopOnce sync.Once

	// Hot counters live on separate cache lines: producers read sleepers,
	// workers read spaceWaiters, and every submission writes pending. |
	// 热计数器各自独占缓存行：提交方读 sleepers，worker 读出队侧的
	// spaceWaiters，而每次提交都会写 pending。
	_         [cacheLine]byte
	sleepers  atomic.Int32
	workerN   atomic.Int32
	_         [cacheLine - 8]byte
	spaceMu   sync.Mutex
	spaceCond *sync.Cond

	_            [cacheLine]byte
	spaceWaiters atomic.Int32
	_            [cacheLine - 4]byte

	pending  atomic.Int64
	_        [cacheLine - 8]byte
	waitMu   sync.Mutex
	waitCond *sync.Cond

	closing  atomic.Bool
	closed   atomic.Bool
	graceful atomic.Bool
	_        [cacheLine - 3]byte

	done chan struct{}
	wg   sync.WaitGroup

	totalProcessed atomic.Uint64
	totalFailed    atomic.Uint64
	totalPanicked  atomic.Uint64

	rejected   atomic.Uint64
	fallbackN  atomic.Uint64
	handoffN   atomic.Uint64
	discardedN atomic.Uint64
	batchExtra atomic.Uint64
}

// nextPowerOfTwo returns the smallest power of two at least n, clamped to
// maxRingCapacity. | nextPowerOfTwo 返回不小于 n 的最小 2 的幂，上限为 maxRingCapacity。
func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	if n > maxRingCapacity {
		n = maxRingCapacity
	}
	return 1 << bits.Len(uint(n-1))
}

// newEngine builds the rings and starts the initial workers. | newEngine 构造环并启动
// 初始 worker。
func newEngine[J any](cfg engineConfig, run func(*workerState, J), discard func(J)) *engine[J] {
	if cfg.workers < 1 {
		cfg.workers = 1
	}
	if cfg.shards < 1 {
		cfg.shards = 1
	}
	shards := nextPowerOfTwo(cfg.shards)
	if cfg.queueSize > maxRingCapacity {
		cfg.queueSize = maxRingCapacity
	}
	perShard := cfg.queueSize
	if perShard < shards*2 {
		perShard = shards * 2
	}
	perShard = (perShard + shards - 1) / shards
	perShard = nextPowerOfTwo(perShard)
	if perShard < 2 {
		perShard = 2
	}
	fallbackSize := nextPowerOfTwo(cfg.fallbackSize)
	if fallbackSize < 2 {
		fallbackSize = 2
	}
	if cfg.spinCount < 0 {
		cfg.spinCount = 0
	}
	e := &engine[J]{
		cfg:          cfg,
		shards:       make([]*ring[J], shards),
		shardMask:    uint64(shards - 1),
		perShard:     perShard,
		fallback:     newRing[J](fallbackSize),
		fallbackSize: fallbackSize,
		run:          run,
		discard:      discard,
		target:       cfg.workers,
		nextID:       cfg.workers,
		done:         make(chan struct{}),
	}
	for i := range e.shards {
		e.shards[i] = newRing[J](perShard)
	}
	wakeCap := cfg.workers
	if wakeCap < 64 {
		wakeCap = 64
	}
	if wakeCap > 4096 {
		wakeCap = 4096
	}
	e.wake = make(chan struct{}, wakeCap)
	e.handoff = make(chan J, wakeCap)
	e.stop = make(chan struct{})
	e.spaceCond = sync.NewCond(&e.spaceMu)
	e.waitCond = sync.NewCond(&e.waitMu)

	e.wg.Add(cfg.workers)
	e.workerN.Store(int32(cfg.workers))
	e.mu.Lock()
	for i := 0; i < cfg.workers; i++ {
		w := &workerState{id: i}
		e.workers = append(e.workers, w)
		go e.work(w, uint64(i)&e.shardMask)
	}
	e.mu.Unlock()

	go func() {
		e.wg.Wait()
		close(e.done)
	}()
	return e
}

// submit accepts j, blocking for room unless the engine is nonblocking. | submit 接受 j；
// 除非引擎为非阻塞模式，否则在无空位时阻塞。
func (e *engine[J]) submit(j J) error {
	if e.closed.Load() {
		return ErrPoolClosed
	}
	e.pending.Add(1)
	start := e.next.v.Add(1) & e.shardMask
	// Direct handoff is used only when the whole pool is idle: it transfers the
	// job and wakes a worker in one channel operation. Saturated paths stay on
	// the sharded rings. | 直接握手仅在整个池空闲时使用：一次 channel 操作同时传递作业并
	// 唤醒 worker。饱和路径仍走分片环。
	if n := e.workerN.Load(); n > 0 && e.sleepers.Load() >= n {
		select {
		case e.handoff <- j:
			e.handoffN.Add(1)
			return nil
		default:
		}
	}
	if e.trySubmitAt(j, start) {
		return nil
	}
	if e.cfg.nonblocking {
		e.rejected.Add(1)
		e.pendingDone()
		return ErrQueueFull
	}
	for i := 0; i < spaceSpin; i++ {
		if e.trySubmit(j) {
			return nil
		}
		if i&15 == 0 {
			if e.closed.Load() {
				e.rejected.Add(1)
				e.pendingDone()
				return ErrPoolClosed
			}
			runtime.Gosched()
		}
	}
	for {
		if e.closed.Load() {
			e.rejected.Add(1)
			e.pendingDone()
			return ErrPoolClosed
		}
		e.spaceWaiters.Add(1)
		if e.trySubmit(j) {
			e.spaceWaiters.Add(-1)
			return nil
		}
		e.spaceMu.Lock()
		if e.closed.Load() {
			e.spaceMu.Unlock()
			e.spaceWaiters.Add(-1)
			e.rejected.Add(1)
			e.pendingDone()
			return ErrPoolClosed
		}
		if e.trySubmit(j) {
			e.spaceMu.Unlock()
			e.spaceWaiters.Add(-1)
			return nil
		}
		e.spaceCond.Wait()
		e.spaceMu.Unlock()
		e.spaceWaiters.Add(-1)
	}
}

// trySubmit makes one nonblocking routing attempt from a random shard. |
// trySubmit 从随机分片开始执行一次非阻塞路由尝试。
func (e *engine[J]) trySubmit(j J) bool {
	return e.trySubmitAt(j, e.next.v.Add(1)&e.shardMask)
}

// trySubmitAt scans shards from start and then the fallback ring. | trySubmitAt
// 从 start 开始扫描分片，最后尝试 fallback 环。
func (e *engine[J]) trySubmitAt(j J, start uint64) bool {
	n := uint64(len(e.shards))
	for i := uint64(0); i < n; i++ {
		idx := (start + i) & e.shardMask
		if e.shards[idx].tryEnqueue(j) {
			e.wakeSleeper()
			return true
		}
	}
	if e.fallback.tryEnqueue(j) {
		e.fallbackN.Add(1)
		e.wakeSleeper()
		return true
	}
	return false
}

// addBatchExtra records the extra tasks contributed by a batched job. | addBatchExtra
// 记录批量作业额外贡献的任务数。
func (e *engine[J]) addBatchExtra(n int) {
	if n > 0 {
		e.batchExtra.Add(uint64(n))
	}
}

// wakeSleeper signals one parked worker when there is one. | wakeSleeper 在存在休眠 worker
// 时唤醒一个。
func (e *engine[J]) wakeSleeper() {
	if e.sleepers.Load() == 0 {
		return
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// wakeAll delivers a token for every live worker without blocking. | wakeAll 以非阻塞
// 方式为每个存活 worker 投递一个令牌。
func (e *engine[J]) wakeAll() {
	e.mu.Lock()
	n := len(e.workers)
	e.mu.Unlock()
	for i := 0; i < n; i++ {
		select {
		case e.wake <- struct{}{}:
		default:
			return
		}
	}
}

// spaceSignal wakes one submitter blocked on a full queue. | spaceSignal 唤醒一个因队列满
// 而阻塞的提交方。
func (e *engine[J]) spaceSignal() {
	if e.spaceWaiters.Load() == 0 {
		return
	}
	e.spaceMu.Lock()
	e.spaceCond.Signal()
	e.spaceMu.Unlock()
}

// pendingDone marks one accepted task finished. | pendingDone 标记一个已接受任务完成。
func (e *engine[J]) pendingDone() {
	if e.pending.Add(-1) == 0 {
		e.signalWait()
	}
}

// completed accumulates one finished task for w and flushes in batches. | completed
// 为 w 累计一个已完成任务并分批 flush。
func (e *engine[J]) completed(w *workerState) {
	w.localDone++
	if w.localDone >= pendingBatch {
		e.flushLocalDone(w)
	}
}

// flushLocalDone publishes w's accumulated completion count. | flushLocalDone 发布 w 累计
// 的完成计数。
func (e *engine[J]) flushLocalDone(w *workerState) {
	n := w.localDone
	if n == 0 {
		return
	}
	w.localDone = 0
	if e.pending.Add(-int64(n)) == 0 {
		e.signalWait()
	}
}

// signalWait wakes every Wait caller. | signalWait 唤醒所有 Wait 调用方。
func (e *engine[J]) signalWait() {
	e.waitMu.Lock()
	e.waitCond.Broadcast()
	e.waitMu.Unlock()
}

// wait blocks until every accepted task has finished or been discarded. | wait 阻塞到所有
// 已接受任务完成或被丢弃。
func (e *engine[J]) wait() {
	e.waitMu.Lock()
	for e.pending.Load() > 0 {
		e.waitCond.Wait()
	}
	e.waitMu.Unlock()
}

// stats returns a snapshot of the engine. | stats 返回引擎快照。
func (e *engine[J]) stats() Stats {
	e.mu.Lock()
	workers := len(e.workers)
	target := e.target
	running := 0
	completed := e.totalProcessed.Load()
	failed := e.totalFailed.Load()
	panicked := e.totalPanicked.Load()
	for _, w := range e.workers {
		if w.running.Load() {
			running++
		}
		completed += w.processed.Load()
		failed += w.failed.Load()
		panicked += w.panicked.Load()
	}
	e.mu.Unlock()

	var submitted uint64
	queued := 0
	for _, r := range e.shards {
		submitted += r.tailPos()
		queued += r.len()
	}
	submitted += e.fallback.tailPos() + e.handoffN.Load() + e.batchExtra.Load()
	queued += e.fallback.len() + len(e.handoff)

	return Stats{
		Workers:       workers,
		TargetWorkers: target,
		Shards:        len(e.shards),
		Capacity:      len(e.shards)*e.perShard + e.fallbackSize + cap(e.handoff),
		Queued:        queued,
		Running:       running,
		Submitted:     submitted,
		Completed:     completed,
		Failed:        failed,
		Panicked:      panicked,
		Rejected:      e.rejected.Load(),
		Fallback:      e.fallbackN.Load(),
		Discarded:     e.discardedN.Load(),
	}
}
