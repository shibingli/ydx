package pool

import (
	"context"
	"sync/atomic"
)

// waitSpin is the number of times a waiter checks completion before blocking. | waitSpin
// 是等待者在阻塞前检查完成状态的次数。
//
// Nanosecond tasks usually finish during this window, so the common synchronous
// call path never touches a scheduler wait. | 纳秒级任务通常在此窗口内完成，因此常见的
// 同步调用路径不会进入调度器等待。
const waitSpin = 4096

// completion carries one task result to any number of waiters. | completion 把一次任务
// 结果交给任意数量的等待者。
//
// state moves 0 (pending) -> 1 (claimed) -> 2 (published). The value and error
// are written after the claim and before the published store, so a waiter that
// observes 2 also observes the result through Go's sequentially consistent
// atomics. finish is idempotent: only the first caller publishes. | state 依次为
// 0（等待）、1（已有发布者）、2（已发布）。值与错误在认领之后、发布存储之前写入，因此
// 观察到 2 的等待者也能通过 Go 的顺序一致原子操作观察到结果。finish 幂等：只有第一个
// 调用者发布。
type completion[R any] struct {
	state atomic.Uint32
	ch    chan struct{}
	value R
	err   error
}

// newCompletion creates a pending completion. | newCompletion 创建等待中的 completion。
func newCompletion[R any]() *completion[R] {
	return &completion[R]{ch: make(chan struct{})}
}

// finish publishes the result unless another caller already did. | finish 发布结果，
// 除非已有调用者发布。
func (c *completion[R]) finish(value R, err error) {
	if !c.state.CompareAndSwap(0, 1) {
		return
	}
	c.value = value
	c.err = err
	c.state.Store(2)
	close(c.ch)
}

// wait blocks until the result is published or ctx expires. | wait 阻塞到结果发布或
// ctx 到期。
func (c *completion[R]) wait(ctx context.Context) (R, error) {
	if c.state.Load() == 2 {
		return c.value, c.err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for i := 0; i < waitSpin; i++ {
		if c.state.Load() == 2 {
			return c.value, c.err
		}
	}
	select {
	case <-c.ch:
		return c.value, c.err
	case <-ctx.Done():
		if c.state.Load() == 2 {
			return c.value, c.err
		}
		var zero R
		return zero, ctx.Err()
	}
}

// doneCh returns a channel closed when the result is published. | doneCh 返回在结果发布时
// 关闭的 channel。
func (c *completion[R]) doneCh() <-chan struct{} { return c.ch }

// Task is the awaitable handle returned by Pool.Submit. | Task 是 Pool.Submit 返回的
// 可等待句柄。
type Task struct {
	c *completion[struct{}]
}

// Wait blocks until the task finishes or ctx expires. | Wait 阻塞到任务结束或 ctx 到期。
//
// A nil ctx means context.Background. The task error, ErrPoolClosed,
// ErrQueueFull, a context error or a *PanicError is returned. | ctx 为 nil 时表示
// context.Background。返回任务错误、ErrPoolClosed、ErrQueueFull、context 错误或
// *PanicError。
func (t *Task) Wait(ctx context.Context) error {
	_, err := t.c.wait(ctx)
	return err
}

// Done returns a channel closed when the task finishes. | Done 返回任务结束时关闭的 channel。
func (t *Task) Done() <-chan struct{} { return t.c.doneCh() }

// newTask creates a public Task and its internal completion. | newTask 创建公开 Task
// 及其内部 completion。
func newTask() (*Task, *completion[struct{}]) {
	c := newCompletion[struct{}]()
	return &Task{c: c}, c
}

// Future is the awaitable, typed handle returned by ResultPool.Submit and
// ParamPool.Submit. | Future 是 ResultPool.Submit 与 ParamPool.Submit 返回的类型化
// 可等待句柄。
type Future[R any] struct {
	c *completion[R]
}

// Wait blocks until the task finishes or ctx expires. | Wait 阻塞到任务结束或 ctx 到期。
//
// A nil ctx means context.Background. When ctx expires first, the zero value and
// the context error are returned; the task itself keeps running. | ctx 为 nil 时表示
// context.Background。若 ctx 先到期，返回零值与 context 错误；任务本身继续执行。
func (f *Future[R]) Wait(ctx context.Context) (R, error) { return f.c.wait(ctx) }

// Done returns a channel closed when the task finishes. | Done 返回任务结束时关闭的 channel。
func (f *Future[R]) Done() <-chan struct{} { return f.c.doneCh() }

// newFuture creates a public Future and its internal completion. | newFuture 创建公开
// Future 及其内部 completion。
func newFuture[R any]() (*Future[R], *completion[R]) {
	c := newCompletion[R]()
	return &Future[R]{c: c}, c
}
