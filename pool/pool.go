package pool

import (
	"context"
	"runtime"
	"runtime/debug"
)

// defaultSpinCount is the number of polling iterations before a worker parks. |
// defaultSpinCount 是 worker 休眠前的轮询次数。
const defaultSpinCount = 32

// defaultQueuePerShard is the default queue capacity shared across shards. |
// defaultQueuePerShard 是各分片默认分摊的队列容量。
const defaultQueuePerShard = 256

// defaultFallbackSize is the default shared overflow queue capacity. |
// defaultFallbackSize 是共享溢出队列的默认容量。
const defaultFallbackSize = 1024

// jobFunc is the internal task stored by Pool. | jobFunc 是 Pool 存储的内部任务。
type jobFunc struct {
	fn  func(context.Context) error
	ctx context.Context
	fut *completion[struct{}]
}

// Option configures a pool. | Option 配置协程池。
type Option func(*options)

// options is the user-facing configuration before normalization. | options 是归一化前的
// 用户配置。
type options struct {
	panicHandler func(PanicInfo)
	errorHandler func(error)
	workers      int
	shards       int
	queueSize    int
	fallbackSize int
	spinCount    int
	nonblocking  bool
	metrics      bool
}

// defaultOptions returns the default configuration. | defaultOptions 返回默认配置。
func defaultOptions() options {
	return options{
		workers:      runtime.GOMAXPROCS(0),
		fallbackSize: defaultFallbackSize,
		spinCount:    defaultSpinCount,
		metrics:      true,
	}
}

// WithWorkers sets the initial and target worker count. A non-positive value
// selects runtime.GOMAXPROCS(0). | WithWorkers 设置初始与目标 worker 数。非正数选择
// runtime.GOMAXPROCS(0)。
func WithWorkers(n int) Option {
	return func(o *options) { o.workers = n }
}

// WithShards sets the number of queue shards. The value is rounded up to a power
// of two; a non-positive value defaults to the next power of two at or above the
// worker count. | WithShards 设置队列分片数。取值向上取整为 2 的幂；非正数默认为不小于
// worker 数的下一个 2 的幂。
func WithShards(n int) Option {
	return func(o *options) { o.shards = n }
}

// WithQueueSize sets the requested total queue capacity across shards. The
// per-shard capacity is the total divided by the shard count, rounded up to a
// power of two with a minimum of two, so the effective capacity reported by
// Stats may exceed n. A non-positive value uses 256 slots per shard. |
// WithQueueSize 设置各分片合计的请求队列容量。每分片容量为总量除以分片数，向上取整为
// 2 的幂且最小为 2，因此 Stats 报告的实际容量可能大于 n。非正数使用每分片 256 个槽位。
func WithQueueSize(n int) Option {
	return func(o *options) { o.queueSize = n }
}

// WithFallbackQueueSize sets the shared overflow ring capacity, rounded up to a
// power of two with a minimum of two. A non-positive value uses 1024 slots. |
// WithFallbackQueueSize 设置共享溢出环容量，向上取整为 2 的幂且最小为 2。非正数使用
// 1024 个槽位。
func WithFallbackQueueSize(n int) Option {
	return func(o *options) { o.fallbackSize = n }
}

// WithNonblocking makes a full queue reject with ErrQueueFull instead of blocking
// the submitter. | WithNonblocking 使满队列以 ErrQueueFull 拒绝，而不是阻塞提交方。
func WithNonblocking() Option {
	return func(o *options) { o.nonblocking = true }
}

// WithSpinCount sets how many times a worker polls before parking. Zero parks as
// soon as the queues are empty; a negative value is treated as zero. | WithSpinCount
// 设置 worker 休眠前的轮询次数。0 表示队列一空就休眠；负数按 0 处理。
func WithSpinCount(n int) Option {
	return func(o *options) {
		if n < 0 {
			n = 0
		}
		o.spinCount = n
	}
}

// WithPanicHandler sets the callback invoked with every recovered panic. | WithPanicHandler
// 设置每次恢复 panic 时调用的回调。
func WithPanicHandler(h func(PanicInfo)) Option {
	return func(o *options) { o.panicHandler = h }
}

// WithErrorHandler sets the callback invoked with task errors that have no
// waiter, such as errors from Go, GoContext and GoBatch. | WithErrorHandler 设置接收
// 无等待者任务错误的回调，例如 Go、GoContext 与 GoBatch 的错误。
func WithErrorHandler(h func(error)) Option {
	return func(o *options) { o.errorHandler = h }
}

// WithoutMetrics disables per-task completion counters. Structural counters such
// as Submitted, Queued and Rejected remain available. | WithoutMetrics 关闭每任务完成
// 计数。Submitted、Queued、Rejected 等结构指标仍然可用。
func WithoutMetrics() Option {
	return func(o *options) { o.metrics = false }
}

// config normalizes the options into the engine configuration. | config 把选项归一化为
// 引擎配置。
func (o options) config() engineConfig {
	workers := o.workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}
	shards := o.shards
	if shards <= 0 {
		shards = nextPowerOfTwo(workers)
	}
	shards = nextPowerOfTwo(shards)
	queueSize := o.queueSize
	if queueSize <= 0 {
		queueSize = shards * defaultQueuePerShard
	}
	if queueSize > maxRingCapacity {
		queueSize = maxRingCapacity
	}
	fallbackSize := o.fallbackSize
	if fallbackSize <= 0 {
		fallbackSize = defaultFallbackSize
	}
	return engineConfig{
		workers:      workers,
		shards:       shards,
		queueSize:    queueSize,
		fallbackSize: fallbackSize,
		spinCount:    o.spinCount,
		nonblocking:  o.nonblocking,
		metrics:      o.metrics,
	}
}

// Pool is a low-latency pool for tasks that return only an error. | Pool 是只返回错误的
// 低延迟任务池。
//
// Use Go for fire-and-forget work, Submit for an awaitable Task, and Call for a
// synchronous round trip. A Pool must not be copied after first use. | 使用 Go 提交
// fire-and-forget 工作，使用 Submit 获得可等待的 Task，使用 Call 做同步往返。Pool 首次
// 使用后不得复制。
type Pool struct {
	eng          *engine[jobFunc]
	panicHandler func(PanicInfo)
	errorHandler func(error)
	metrics      bool
}

// New creates a Pool. | New 创建 Pool。
func New(opts ...Option) *Pool {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	p := &Pool{
		panicHandler: o.panicHandler,
		errorHandler: o.errorHandler,
		metrics:      o.metrics,
	}
	p.eng = newEngine(o.config(), p.run, discardJobFunc)
	return p
}

// discardJobFunc completes a discarded job with ErrPoolClosed. | discardJobFunc 用
// ErrPoolClosed 完成被丢弃的作业。
func discardJobFunc(j jobFunc) {
	if j.fut != nil {
		j.fut.finish(struct{}{}, ErrPoolClosed)
	}
}

// run executes one job and publishes its result. | run 执行一个作业并发布结果。
func (p *Pool) run(w *workerState, j jobFunc) {
	ctx := j.ctx
	if ctx == nil {
		ctx = context.Background()
	} else if err := ctx.Err(); err != nil {
		p.complete(w, j, err)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.completePanic(w, j, r)
		}
	}()
	p.complete(w, j, j.fn(ctx))
}

// complete publishes a normal result. | complete 发布普通结果。
func (p *Pool) complete(w *workerState, j jobFunc, err error) {
	if p.metrics {
		if err != nil {
			w.count(1, 1, 0)
		} else {
			w.count(1, 0, 0)
		}
	}
	if err != nil && j.fut == nil {
		p.reportError(err)
	}
	if j.fut != nil {
		j.fut.finish(struct{}{}, err)
	}
}

// completePanic publishes a recovered panic. | completePanic 发布被恢复的 panic。
func (p *Pool) completePanic(w *workerState, j jobFunc, value any) {
	stack := debug.Stack()
	p.reportPanic(PanicInfo{Value: value, Stack: stack})
	if p.metrics {
		w.count(1, 0, 1)
	}
	err := &PanicError{Value: value, Stack: stack, Worker: w.id}
	if j.fut == nil {
		p.reportError(err)
	} else {
		j.fut.finish(struct{}{}, err)
	}
}

// reportError invokes the error handler without letting its panic escape. | reportError
// 调用错误处理器且不让其 panic 逃逸。
func (p *Pool) reportError(err error) {
	if p.errorHandler == nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		p.errorHandler(err)
	}()
}

// reportPanic invokes the panic handler without letting its panic escape. | reportPanic
// 调用 panic 处理器且不让其 panic 逃逸。
func (p *Pool) reportPanic(info PanicInfo) {
	if p.panicHandler == nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		p.panicHandler(info)
	}()
}

// Go submits fn without waiting for its result. | Go 提交 fn 且不等待结果。
//
// fn receives context.Background. Task errors and panics go to the configured
// ErrorHandler. Go returns ErrPoolClosed or ErrQueueFull when the pool cannot
// accept the task. | fn 接收 context.Background。任务错误与 panic 交给配置的
// ErrorHandler。池无法接受任务时 Go 返回 ErrPoolClosed 或 ErrQueueFull。
func (p *Pool) Go(fn func(context.Context) error) error {
	if fn == nil {
		return ErrNilTask
	}
	return p.eng.submit(jobFunc{fn: fn})
}

// GoContext submits fn with ctx without waiting for its result. | GoContext 使用 ctx
// 提交 fn 且不等待结果。
//
// A nil ctx behaves like Go. An already-canceled ctx returns its error without
// enqueueing. | ctx 为 nil 时等价于 Go。已取消的 ctx 直接返回其错误且不入队。
func (p *Pool) GoContext(ctx context.Context, fn func(context.Context) error) error {
	if fn == nil {
		return ErrNilTask
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return p.eng.submit(jobFunc{fn: fn, ctx: ctx})
}

// Submit enqueues fn and returns a Task that can be waited on. | Submit 入队 fn 并返回
// 可等待的 Task。
//
// A nil ctx behaves like context.Background. A nil fn or an already-canceled ctx
// returns an already-finished Task. | ctx 为 nil 时等价于 context.Background。fn 为 nil
// 或 ctx 已取消时返回已完成的 Task。
func (p *Pool) Submit(ctx context.Context, fn func(context.Context) error) *Task {
	if fn == nil {
		return failedTask(ErrNilTask)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return failedTask(err)
		}
	}
	task, c := newTask()
	if err := p.eng.submit(jobFunc{fn: fn, ctx: ctx, fut: c}); err != nil {
		c.finish(struct{}{}, err)
	}
	return task
}

// Call enqueues fn and waits for it to finish. | Call 入队 fn 并等待其结束。
//
// A nil ctx behaves like context.Background. When ctx expires first, Call returns
// the context error while fn may keep running. | ctx 为 nil 时等价于
// context.Background。ctx 先到期时 Call 返回 context 错误，而 fn 可能继续执行。
func (p *Pool) Call(ctx context.Context, fn func(context.Context) error) error {
	if fn == nil {
		return ErrNilTask
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	c := newCompletion[struct{}]()
	if err := p.eng.submit(jobFunc{fn: fn, ctx: ctx, fut: c}); err != nil {
		return err
	}
	_, err := c.wait(ctx)
	return err
}

// Wait blocks until every accepted task has finished or been discarded. | Wait 阻塞到
// 所有已接受任务完成或被丢弃。
func (p *Pool) Wait() { p.eng.wait() }

// Close stops the pool immediately. Queued tasks are discarded with ErrPoolClosed;
// running tasks finish before Close returns. | Close 立即停止池。排队任务以
// ErrPoolClosed 丢弃；正在运行的任务在 Close 返回前结束。
func (p *Pool) Close() { p.eng.close(false) }

// Shutdown stops accepting tasks and drains the queues. It returns ctx.Err when
// the deadline expires; workers keep draining in the background. | Shutdown 停止接受
// 任务并排空队列。期限到时返回 ctx.Err；worker 在后台继续排空。
func (p *Pool) Shutdown(ctx context.Context) error { return p.eng.shutdown(ctx) }

// Resize changes the worker count. Growth is immediate; shrink happens when
// workers next become idle. | Resize 调整 worker 数。扩容立即生效；缩容在 worker 下次
// 空闲时生效。
func (p *Pool) Resize(workers int) error { return p.eng.resize(workers) }

// Stats returns a point-in-time snapshot. | Stats 返回瞬时快照。
func (p *Pool) Stats() Stats { return p.eng.stats() }

// failedTask returns an already-finished Task carrying err. | failedTask 返回携带 err 的
// 已完成 Task。
func failedTask(err error) *Task {
	t, c := newTask()
	c.finish(struct{}{}, err)
	return t
}
