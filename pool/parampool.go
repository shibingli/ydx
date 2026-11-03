package pool

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"
)

// batchJob is one batched submission. | batchJob 是一次批量提交。
type batchJob[T, R any] struct {
	args    []T
	results []R
	ctx     context.Context
	fut     *completion[[]R]
}

// jobParam is the internal task stored by ParamPool. | jobParam 是 ParamPool 存储的内部
// 任务。
type jobParam[T, R any] struct {
	arg   T
	ctx   context.Context
	fut   *completion[R]
	batch *batchJob[T, R]
}

// ParamPool is a low-latency pool with a fixed handler and per-task arguments. |
// ParamPool 是处理器固定、逐任务传参的低延迟任务池。
//
// Because the handler is fixed at construction, Go and Submit copy the argument
// into the ring slot instead of allocating a closure per task. A ParamPool must
// not be copied after first use. | 由于处理器在构造时固定，Go 与 Submit 把参数复制进环槽，
// 而不是为每个任务分配闭包。ParamPool 首次使用后不得复制。
type ParamPool[T, R any] struct {
	eng          *engine[jobParam[T, R]]
	handler      func(context.Context, T) (R, error)
	panicHandler func(PanicInfo)
	errorHandler func(error)
	metrics      bool
	batchPool    sync.Pool
}

// NewParamPool creates a ParamPool. A nil handler makes every task fail with
// ErrNilTask. | NewParamPool 创建 ParamPool。处理器为 nil 时每个任务以 ErrNilTask 失败。
func NewParamPool[T, R any](handler func(context.Context, T) (R, error), opts ...Option) *ParamPool[T, R] {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	p := &ParamPool[T, R]{
		handler:      handler,
		panicHandler: o.panicHandler,
		errorHandler: o.errorHandler,
		metrics:      o.metrics,
	}
	p.eng = newEngine(o.config(), p.run, p.discard)
	return p
}

// getBatch returns a reusable batch header. | getBatch 返回可复用的批次头。
func (p *ParamPool[T, R]) getBatch() *batchJob[T, R] {
	if v := p.batchPool.Get(); v != nil {
		return v.(*batchJob[T, R])
	}
	return &batchJob[T, R]{}
}

// putBatch resets and recycles a finished batch header. | putBatch 重置并回收已完成的
// 批次头。
func (p *ParamPool[T, R]) putBatch(b *batchJob[T, R]) {
	b.args = nil
	b.results = nil
	b.ctx = nil
	b.fut = nil
	p.batchPool.Put(b)
}

// discard completes a discarded typed job with ErrPoolClosed and recycles its
// batch header. | discard 用 ErrPoolClosed 完成被丢弃的类型化作业，并回收其批次头。
func (p *ParamPool[T, R]) discard(j jobParam[T, R]) {
	if j.batch != nil {
		if j.batch.fut != nil {
			j.batch.fut.finish(nil, ErrPoolClosed)
		}
		p.putBatch(j.batch)
		return
	}
	if j.fut != nil {
		var zero R
		j.fut.finish(zero, ErrPoolClosed)
	}
}

// invoke calls the fixed handler and converts a panic into a PanicError. | invoke
// 调用固定处理器并把 panic 转为 PanicError。
func (p *ParamPool[T, R]) invoke(w *workerState, ctx context.Context, arg T) (value R, err error) {
	if p.handler == nil {
		return value, ErrNilTask
	}
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			p.reportPanic(PanicInfo{Value: r, Stack: stack})
			err = &PanicError{Value: r, Stack: stack, Worker: w.id}
		}
	}()
	return p.handler(ctx, arg)
}

// run executes one single or batched typed job. | run 执行一个单个或批量类型化作业。
func (p *ParamPool[T, R]) run(w *workerState, j jobParam[T, R]) {
	if j.batch != nil {
		p.runBatch(w, j.batch)
		return
	}
	ctx := j.ctx
	if ctx == nil {
		ctx = context.Background()
	} else if err := ctx.Err(); err != nil {
		var zero R
		p.complete(w, j, zero, err)
		return
	}
	value, err := p.invoke(w, ctx, j.arg)
	p.complete(w, j, value, err)
}

// runBatch executes every element of a batch in order. | runBatch 按顺序执行批次的每个
// 元素。
func (p *ParamPool[T, R]) runBatch(w *workerState, b *batchJob[T, R]) {
	defer p.putBatch(b)
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		firstErr  error
		processed uint64
		failed    uint64
		panicked  uint64
	)
	for i, arg := range b.args {
		if b.ctx != nil {
			if err := ctx.Err(); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				if b.fut == nil {
					p.reportError(err)
				}
				break
			}
		}
		value, err := p.invoke(w, ctx, arg)
		processed++
		if b.results != nil {
			b.results[i] = value
		}
		if err == nil {
			continue
		}
		failed++
		var panicErr *PanicError
		if errors.As(err, &panicErr) {
			panicked++
			failed--
		}
		if firstErr == nil {
			firstErr = err
		}
		if b.fut == nil {
			p.reportError(err)
		}
	}
	if p.metrics {
		w.count(processed, failed, panicked)
	}
	if b.fut != nil {
		b.fut.finish(b.results, firstErr)
	}
}

// complete publishes a typed normal result. | complete 发布类型化普通结果。
func (p *ParamPool[T, R]) complete(w *workerState, j jobParam[T, R], value R, err error) {
	panicked := false
	if err != nil {
		var panicErr *PanicError
		panicked = errors.As(err, &panicErr)
	}
	if p.metrics {
		switch {
		case panicked:
			w.count(1, 0, 1)
		case err != nil:
			w.count(1, 1, 0)
		default:
			w.count(1, 0, 0)
		}
	}
	if err != nil && j.fut == nil {
		p.reportError(err)
	}
	if j.fut != nil {
		j.fut.finish(value, err)
	}
}

// reportError invokes the error handler without letting its panic escape. | reportError
// 调用错误处理器且不让其 panic 逃逸。
func (p *ParamPool[T, R]) reportError(err error) {
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
func (p *ParamPool[T, R]) reportPanic(info PanicInfo) {
	if p.panicHandler == nil {
		return
	}
	func() {
		defer func() { _ = recover() }()
		p.panicHandler(info)
	}()
}

// Go submits arg without waiting for the result. | Go 提交 arg 且不等待结果。
func (p *ParamPool[T, R]) Go(arg T) error {
	if p.handler == nil {
		return ErrNilTask
	}
	return p.eng.submit(jobParam[T, R]{arg: arg})
}

// GoContext submits arg with ctx without waiting for the result. | GoContext 使用 ctx
// 提交 arg 且不等待结果。
func (p *ParamPool[T, R]) GoContext(ctx context.Context, arg T) error {
	if p.handler == nil {
		return ErrNilTask
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return p.eng.submit(jobParam[T, R]{arg: arg, ctx: ctx})
}

// Submit enqueues arg and returns a typed Future. | Submit 入队 arg 并返回类型化 Future。
func (p *ParamPool[T, R]) Submit(ctx context.Context, arg T) *Future[R] {
	if p.handler == nil {
		return failedFuture[R](ErrNilTask)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return failedFuture[R](err)
		}
	}
	future, c := newFuture[R]()
	if err := p.eng.submit(jobParam[T, R]{arg: arg, ctx: ctx, fut: c}); err != nil {
		var zero R
		c.finish(zero, err)
	}
	return future
}

// Call enqueues arg and waits for its typed result. | Call 入队 arg 并等待其类型化结果。
func (p *ParamPool[T, R]) Call(ctx context.Context, arg T) (R, error) {
	if p.handler == nil {
		var zero R
		return zero, ErrNilTask
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			var zero R
			return zero, err
		}
	}
	c := newCompletion[R]()
	if err := p.eng.submit(jobParam[T, R]{arg: arg, ctx: ctx, fut: c}); err != nil {
		var zero R
		return zero, err
	}
	return c.wait(ctx)
}

// GoBatch submits every element as one batched job without waiting. | GoBatch 把每个元素
// 作为一个批量作业提交且不等待。
//
// The pool takes ownership of args: the caller must not modify or reuse the slice
// until the batch finishes. GoBatch has no completion handle, so callers that
// reuse the slice should use CallBatch or copy it first. After warm-up the batch
// header is recycled, so GoBatch normally does not allocate. | 池取得 args 的所有权：在
// 批次完成前调用方不得修改或复用该切片。GoBatch 没有完成句柄，需要复用切片的调用方应使用
// CallBatch 或先复制。预热后批次头会被回收，因此 GoBatch 通常不再分配。
func (p *ParamPool[T, R]) GoBatch(args []T) error {
	if p.handler == nil {
		return ErrNilTask
	}
	if len(args) == 0 {
		return nil
	}
	b := p.getBatch()
	b.args = args
	if err := p.eng.submit(jobParam[T, R]{batch: b}); err != nil {
		p.putBatch(b)
		return err
	}
	p.eng.addBatchExtra(len(args) - 1)
	return nil
}

// startBatch submits one batch and returns its result slice and completion. |
// startBatch 提交一个批次并返回其结果切片与完成通知。
func (p *ParamPool[T, R]) startBatch(ctx context.Context, dst []R, args []T) ([]R, *completion[[]R], error) {
	var results []R
	if cap(dst) >= len(args) {
		results = dst[:len(args)]
	} else {
		results = make([]R, len(args))
	}
	c := newCompletion[[]R]()
	b := p.getBatch()
	b.args = args
	b.results = results
	b.ctx = ctx
	b.fut = c
	if err := p.eng.submit(jobParam[T, R]{batch: b}); err != nil {
		p.putBatch(b)
		return results, nil, err
	}
	p.eng.addBatchExtra(len(args) - 1)
	return results, c, nil
}

// CallBatch submits args as one batched job and waits for ordered results. | CallBatch
// 把 args 作为一个批量作业提交并等待有序结果。
//
// Every element runs in order; the first error is returned together with the
// results produced so far. Context cancellation stops the remaining elements.
// If the context expires before the batch finishes, the internal results slice
// is not returned (nil) because a worker may still be writing it. | 每个元素按顺序执行；
// 返回首个错误与已产生的结果。context 取消会停止剩余元素。若 context 在批次完成前到期，
// 不返回内部结果切片（nil），因为 worker 可能仍在写入。
func (p *ParamPool[T, R]) CallBatch(ctx context.Context, args []T) ([]R, error) {
	if p.handler == nil {
		return nil, ErrNilTask
	}
	if len(args) == 0 {
		return nil, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	_, c, err := p.startBatch(ctx, nil, args)
	if err != nil {
		return nil, err
	}
	return c.wait(ctx)
}

// CallBatchTo is CallBatch with a caller-provided result buffer. | CallBatchTo 是带调用方
// 结果缓冲区的 CallBatch。
//
// It blocks until the batch finishes, so the caller may reuse dst after it
// returns. When cap(dst) is at least len(args) the buffer is used as-is;
// otherwise a fresh slice is allocated. Reusing the returned slice across calls
// removes the per-batch result allocation. | 它阻塞到批次结束，因此返回后调用方可以复用
// dst。当 dst 的容量不小于 len(args) 时直接使用该缓冲区，否则分配新切片。跨调用复用返回
// 切片可消除每批的结果分配。
func (p *ParamPool[T, R]) CallBatchTo(dst []R, args []T) ([]R, error) {
	if p.handler == nil {
		return dst, ErrNilTask
	}
	if len(args) == 0 {
		return dst, nil
	}
	_, c, err := p.startBatch(nil, dst, args)
	if err != nil {
		return dst, err
	}
	return c.wait(nil)
}

// SubmitBatch submits args as one batched job and returns an awaitable Future.
// | SubmitBatch 把 args 作为一个批量作业提交并返回可等待的 Future。
//
// The caller must not modify args until the Future completes. The Future result
// is the ordered result slice. | 在 Future 完成前调用方不得修改 args。Future 的结果是
// 按输入顺序排列的结果切片。
func (p *ParamPool[T, R]) SubmitBatch(ctx context.Context, args []T) *Future[[]R] {
	if p.handler == nil {
		return failedFuture[[]R](ErrNilTask)
	}
	if len(args) == 0 {
		future, c := newFuture[[]R]()
		c.finish(nil, nil)
		return future
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return failedFuture[[]R](err)
		}
	}
	_, c, err := p.startBatch(ctx, nil, args)
	if err != nil {
		return failedFuture[[]R](err)
	}
	return &Future[[]R]{c: c}
}

// Wait blocks until every accepted task has finished or been discarded. | Wait 阻塞到
// 所有已接受任务完成或被丢弃。
func (p *ParamPool[T, R]) Wait() { p.eng.wait() }

// Close stops the pool immediately. | Close 立即停止池。
func (p *ParamPool[T, R]) Close() { p.eng.close(false) }

// Shutdown stops accepting tasks and drains the queues. | Shutdown 停止接受任务并排空队列。
func (p *ParamPool[T, R]) Shutdown(ctx context.Context) error { return p.eng.shutdown(ctx) }

// Resize changes the worker count. | Resize 调整 worker 数。
func (p *ParamPool[T, R]) Resize(workers int) error { return p.eng.resize(workers) }

// Stats returns a point-in-time snapshot. | Stats 返回瞬时快照。
func (p *ParamPool[T, R]) Stats() Stats { return p.eng.stats() }
