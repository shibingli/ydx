package pool

import (
	"context"
	"runtime/debug"
)

// jobResult is the internal task stored by ResultPool. | jobResult 是 ResultPool 存储的
// 内部任务。
type jobResult[R any] struct {
	fn  func(context.Context) (R, error)
	ctx context.Context
	fut *completion[R]
}

// ResultPool is a low-latency pool for tasks that return a value and an error. |
// ResultPool 是返回值与错误的低延迟任务池。
//
// A ResultPool must not be copied after first use. | ResultPool 首次使用后不得复制。
type ResultPool[R any] struct {
	eng          *engine[jobResult[R]]
	panicHandler func(PanicInfo)
	errorHandler func(error)
	metrics      bool
}

// NewResultPool creates a ResultPool. | NewResultPool 创建 ResultPool。
func NewResultPool[R any](opts ...Option) *ResultPool[R] {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	p := &ResultPool[R]{
		panicHandler: o.panicHandler,
		errorHandler: o.errorHandler,
		metrics:      o.metrics,
	}
	p.eng = newEngine(o.config(), p.run, discardResultJob[R])
	return p
}

// discardResultJob completes a discarded typed job with ErrPoolClosed. | discardResultJob
// 用 ErrPoolClosed 完成被丢弃的类型化作业。
func discardResultJob[R any](j jobResult[R]) {
	if j.fut == nil {
		return
	}
	var zero R
	j.fut.finish(zero, ErrPoolClosed)
}

// run executes one typed job. | run 执行一个类型化作业。
func (p *ResultPool[R]) run(w *workerState, j jobResult[R]) {
	ctx := j.ctx
	if ctx == nil {
		ctx = context.Background()
	} else if err := ctx.Err(); err != nil {
		var zero R
		p.complete(w, j, zero, err)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			p.completePanic(w, j, r)
		}
	}()
	value, err := j.fn(ctx)
	p.complete(w, j, value, err)
}

// complete publishes a typed normal result. | complete 发布类型化普通结果。
func (p *ResultPool[R]) complete(w *workerState, j jobResult[R], value R, err error) {
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
		j.fut.finish(value, err)
	}
}

// completePanic publishes a typed recovered panic. | completePanic 发布类型化被恢复的
// panic。
func (p *ResultPool[R]) completePanic(w *workerState, j jobResult[R], value any) {
	stack := debug.Stack()
	p.reportPanic(PanicInfo{Value: value, Stack: stack})
	if p.metrics {
		w.count(1, 0, 1)
	}
	err := &PanicError{Value: value, Stack: stack, Worker: w.id}
	if j.fut == nil {
		p.reportError(err)
		return
	}
	var zero R
	j.fut.finish(zero, err)
}

// reportError invokes the error handler without letting its panic escape. | reportError
// 调用错误处理器且不让其 panic 逃逸。
func (p *ResultPool[R]) reportError(err error) {
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
func (p *ResultPool[R]) reportPanic(info PanicInfo) {
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
// ErrorHandler. | fn 接收 context.Background。任务错误与 panic 交给配置的
// ErrorHandler。
func (p *ResultPool[R]) Go(fn func(context.Context) (R, error)) error {
	if fn == nil {
		return ErrNilTask
	}
	return p.eng.submit(jobResult[R]{fn: fn})
}

// GoContext submits fn with ctx without waiting for its result. | GoContext 使用 ctx
// 提交 fn 且不等待结果。
func (p *ResultPool[R]) GoContext(ctx context.Context, fn func(context.Context) (R, error)) error {
	if fn == nil {
		return ErrNilTask
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return p.eng.submit(jobResult[R]{fn: fn, ctx: ctx})
}

// Submit enqueues fn and returns a typed Future. | Submit 入队 fn 并返回类型化 Future。
func (p *ResultPool[R]) Submit(ctx context.Context, fn func(context.Context) (R, error)) *Future[R] {
	if fn == nil {
		return failedFuture[R](ErrNilTask)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return failedFuture[R](err)
		}
	}
	future, c := newFuture[R]()
	if err := p.eng.submit(jobResult[R]{fn: fn, ctx: ctx, fut: c}); err != nil {
		var zero R
		c.finish(zero, err)
	}
	return future
}

// Call enqueues fn and waits for its typed result. | Call 入队 fn 并等待其类型化结果。
func (p *ResultPool[R]) Call(ctx context.Context, fn func(context.Context) (R, error)) (R, error) {
	if fn == nil {
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
	if err := p.eng.submit(jobResult[R]{fn: fn, ctx: ctx, fut: c}); err != nil {
		var zero R
		return zero, err
	}
	return c.wait(ctx)
}

// Wait blocks until every accepted task has finished or been discarded. | Wait 阻塞到
// 所有已接受任务完成或被丢弃。
func (p *ResultPool[R]) Wait() { p.eng.wait() }

// Close stops the pool immediately. | Close 立即停止池。
func (p *ResultPool[R]) Close() { p.eng.close(false) }

// Shutdown stops accepting tasks and drains the queues. | Shutdown 停止接受任务并排空队列。
func (p *ResultPool[R]) Shutdown(ctx context.Context) error { return p.eng.shutdown(ctx) }

// Resize changes the worker count. | Resize 调整 worker 数。
func (p *ResultPool[R]) Resize(workers int) error { return p.eng.resize(workers) }

// Stats returns a point-in-time snapshot. | Stats 返回瞬时快照。
func (p *ResultPool[R]) Stats() Stats { return p.eng.stats() }

// failedFuture returns an already-finished Future carrying err. | failedFuture 返回携带
// err 的已完成 Future。
func failedFuture[R any](err error) *Future[R] {
	future, c := newFuture[R]()
	var zero R
	c.finish(zero, err)
	return future
}
