package pool_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/pool"
)

// testOptions returns small deterministic options for tests. | testOptions 返回测试用的
// 小型确定性选项。
func testOptions() []pool.Option {
	return []pool.Option{
		pool.WithWorkers(2),
		pool.WithShards(2),
		pool.WithQueueSize(64),
		pool.WithFallbackQueueSize(64),
		pool.WithSpinCount(2),
	}
}

// waitUntil polls condition until it holds or the deadline expires. | waitUntil 轮询条件
// 直到成立或超时。
func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s | 等待 %s 超时", what, what)
}

// TestGoRuns verifies asynchronous execution and Wait. | TestGoRuns 验证异步执行与 Wait。
func TestGoRuns(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()

	var ran atomic.Int64
	for i := 0; i < 100; i++ {
		if err := p.Go(func(context.Context) error {
			ran.Add(1)
			return nil
		}); err != nil {
			t.Fatalf("go: %v | 提交失败", err)
		}
	}
	p.Wait()
	if got := ran.Load(); got != 100 {
		t.Fatalf("ran = %d, want 100 | 执行数量不符", got)
	}
}

// TestGoContextCanceledSkips verifies that a canceled context prevents execution.
// | TestGoContextCanceledSkips 验证已取消的 context 会阻止执行。
func TestGoContextCanceledSkips(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ran atomic.Bool
	if err := p.GoContext(ctx, func(context.Context) error {
		ran.Store(true)
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("GoContext error = %v, want context.Canceled | 错误不符", err)
	}
	if ran.Load() {
		t.Fatal("function ran with canceled context | 已取消 context 仍执行")
	}
}

// TestSubmitResult verifies that Submit returns a waitable Task. | TestSubmitResult 验证
// Submit 返回可等待的 Task。
func TestSubmitResult(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()

	task := p.Submit(context.Background(), func(context.Context) error { return nil })
	if err := task.Wait(context.Background()); err != nil {
		t.Fatalf("task wait: %v | 等待失败", err)
	}
	select {
	case <-task.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed | Done 未关闭")
	}
}

// TestSubmitError verifies that task errors reach the waiter. | TestSubmitError 验证任务
// 错误会交给等待者。
func TestSubmitError(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()

	boom := errors.New("boom")
	task := p.Submit(context.Background(), func(context.Context) error { return boom })
	if err := task.Wait(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("task error = %v, want boom | 错误不符", err)
	}
}

// TestCallSync verifies synchronous return values and errors. | TestCallSync 验证同步返回值
// 与错误。
func TestCallSync(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()

	if err := p.Call(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("call: %v | 同步调用失败", err)
	}
	boom := errors.New("boom")
	if err := p.Call(context.Background(), func(context.Context) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("call error = %v, want boom | 错误不符", err)
	}
}

// TestPanicRecovered verifies panic recovery, stacks and worker survival. | TestPanicRecovered
// 验证 panic 恢复、栈与 worker 存活。
func TestPanicRecovered(t *testing.T) {
	infos := make(chan pool.PanicInfo, 1)
	p := pool.New(append(testOptions(), pool.WithPanicHandler(func(info pool.PanicInfo) {
		infos <- info
	}))...)
	defer p.Close()

	task := p.Submit(context.Background(), func(context.Context) error {
		panic("boom")
	})
	err := task.Wait(context.Background())
	if !errors.Is(err, pool.ErrTaskPanicked) {
		t.Fatalf("task error = %v, want ErrTaskPanicked | 错误不符", err)
	}
	var panicErr *pool.PanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("error %v is not *PanicError | 错误类型不符", err)
	}
	if len(panicErr.Stack) == 0 {
		t.Fatal("empty panic stack | panic 栈为空")
	}
	select {
	case info := <-infos:
		if info.Value != "boom" || len(info.Stack) == 0 {
			t.Fatalf("panic info = %+v | panic 信息不符", info)
		}
	case <-time.After(time.Second):
		t.Fatal("panic handler not called | panic 处理器未调用")
	}

	var ran atomic.Bool
	if err := p.Call(context.Background(), func(context.Context) error {
		ran.Store(true)
		return nil
	}); err != nil {
		t.Fatalf("call after panic: %v | panic 后调用失败", err)
	}
	if !ran.Load() {
		t.Fatal("worker did not survive panic | worker 未存活")
	}
}

// TestErrorHandler verifies that Go errors reach the error handler. | TestErrorHandler
// 验证 Go 错误会交给错误处理器。
func TestErrorHandler(t *testing.T) {
	errsCh := make(chan error, 1)
	p := pool.New(append(testOptions(), pool.WithErrorHandler(func(err error) {
		errsCh <- err
	}))...)
	defer p.Close()

	boom := errors.New("boom")
	if err := p.Go(func(context.Context) error { return boom }); err != nil {
		t.Fatalf("go: %v | 提交失败", err)
	}
	select {
	case got := <-errsCh:
		if !errors.Is(got, boom) {
			t.Fatalf("handler error = %v, want boom | 错误不符", got)
		}
	case <-time.After(time.Second):
		t.Fatal("error handler not called | 错误处理器未调用")
	}
}

// TestCloseRejects verifies submission after Close. | TestCloseRejects 验证关闭后提交。
func TestCloseRejects(t *testing.T) {
	p := pool.New(testOptions()...)
	p.Close()
	if err := p.Go(func(context.Context) error { return nil }); !errors.Is(err, pool.ErrPoolClosed) {
		t.Fatalf("Go error = %v, want ErrPoolClosed | 错误不符", err)
	}
	task := p.Submit(context.Background(), func(context.Context) error { return nil })
	if err := task.Wait(context.Background()); !errors.Is(err, pool.ErrPoolClosed) {
		t.Fatalf("Submit error = %v, want ErrPoolClosed | 错误不符", err)
	}
	if err := p.Call(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, pool.ErrPoolClosed) {
		t.Fatalf("Call error = %v, want ErrPoolClosed | 错误不符", err)
	}
}

// TestShutdownDrains verifies that Shutdown runs submitted work. | TestShutdownDrains
// 验证 Shutdown 会执行已提交工作。
func TestShutdownDrains(t *testing.T) {
	p := pool.New(append(testOptions(), pool.WithWorkers(1))...)
	var ran atomic.Int64
	for i := 0; i < 50; i++ {
		if err := p.Go(func(context.Context) error {
			ran.Add(1)
			return nil
		}); err != nil {
			t.Fatalf("go: %v | 提交失败", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v | 关闭失败", err)
	}
	if got := ran.Load(); got != 50 {
		t.Fatalf("ran = %d, want 50 | 执行数量不符", got)
	}
}

// TestResize verifies hot resize. | TestResize 验证热调整 worker 数。
func TestResize(t *testing.T) {
	p := pool.New(append(testOptions(), pool.WithWorkers(1), pool.WithShards(1))...)
	defer p.Close()

	if err := p.Resize(4); err != nil {
		t.Fatalf("resize up: %v | 扩容失败", err)
	}
	waitUntil(t, "four workers", func() bool { return p.Stats().Workers == 4 })
	if err := p.Resize(1); err != nil {
		t.Fatalf("resize down: %v | 缩容失败", err)
	}
	waitUntil(t, "one worker", func() bool { return p.Stats().Workers == 1 })
}

// TestNilContext verifies nil contexts behave like Background. | TestNilContext 验证 nil
// context 等价于 Background。
func TestNilContext(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()

	if err := p.Call(nil, func(ctx context.Context) error {
		if ctx == nil {
			t.Error("nil context passed to function | 传给函数的是 nil context")
		}
		return nil
	}); err != nil {
		t.Fatalf("call: %v | 同步调用失败", err)
	}
	task := p.Submit(nil, func(context.Context) error { return nil })
	if err := task.Wait(nil); err != nil {
		t.Fatalf("wait: %v | 等待失败", err)
	}
}

// TestStats verifies the main counters after a quiescent wait. | TestStats 验证静默后的
// 主要计数。
func TestStats(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()

	const n = 500
	for i := 0; i < n; i++ {
		if err := p.Go(func(context.Context) error { return nil }); err != nil {
			t.Fatalf("go: %v | 提交失败", err)
		}
	}
	p.Wait()
	st := p.Stats()
	if st.Submitted != n || st.Completed != n || st.Failed != 0 || st.Queued != 0 {
		t.Fatalf("stats = %+v | 统计不符", st)
	}
	if st.Workers < 1 || st.Shards < 1 || st.Capacity <= 0 {
		t.Fatalf("stats = %+v | 结构字段不符", st)
	}
}

// TestNilTask verifies nil task rejection. | TestNilTask 验证拒绝 nil 任务。
func TestNilTask(t *testing.T) {
	p := pool.New(testOptions()...)
	defer p.Close()
	if err := p.Go(nil); !errors.Is(err, pool.ErrNilTask) {
		t.Fatalf("Go(nil) = %v, want ErrNilTask | 错误不符", err)
	}
	if err := p.Call(context.Background(), nil); !errors.Is(err, pool.ErrNilTask) {
		t.Fatalf("Call(nil) = %v, want ErrNilTask | 错误不符", err)
	}
}

// TestCloseConcurrentSubmit verifies that submissions racing with Close never hang.
// | TestCloseConcurrentSubmit 验证与 Close 并发的提交不会挂起。
func TestCloseConcurrentSubmit(t *testing.T) {
	p := pool.New(append(testOptions(),
		pool.WithWorkers(4),
		pool.WithShards(4),
		pool.WithQueueSize(32),
		pool.WithFallbackQueueSize(32),
		pool.WithSpinCount(0),
	)...)
	const submitters = 8
	var wg sync.WaitGroup
	failures := make(chan error, submitters)
	fn := func(context.Context) error { return nil }
	for i := 0; i < submitters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				task := p.Submit(context.Background(), fn)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err := task.Wait(ctx)
				cancel()
				switch {
				case err == nil:
				case errors.Is(err, pool.ErrPoolClosed):
					return
				case errors.Is(err, context.DeadlineExceeded):
					failures <- errors.New("task wait timed out | 任务等待超时")
					return
				default:
					failures <- err
					return
				}
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	p.Close()
	wg.Wait()
	select {
	case err := <-failures:
		t.Fatalf("concurrent submit: %v | 并发提交失败", err)
	default:
	}
	p.Wait()
}

// TestShutdownConcurrentSubmit verifies that submissions racing with Shutdown drain
// or report ErrPoolClosed. | TestShutdownConcurrentSubmit 验证与 Shutdown 并发的提交会
// 排空或返回 ErrPoolClosed。
func TestShutdownConcurrentSubmit(t *testing.T) {
	p := pool.New(append(testOptions(),
		pool.WithWorkers(4),
		pool.WithShards(4),
		pool.WithQueueSize(32),
		pool.WithFallbackQueueSize(32),
		pool.WithSpinCount(0),
	)...)
	const submitters = 8
	var wg sync.WaitGroup
	failures := make(chan error, submitters)
	fn := func(context.Context) error { return nil }
	for i := 0; i < submitters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				task := p.Submit(context.Background(), fn)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err := task.Wait(ctx)
				cancel()
				switch {
				case err == nil:
				case errors.Is(err, pool.ErrPoolClosed):
					return
				case errors.Is(err, context.DeadlineExceeded):
					failures <- errors.New("task wait timed out | 任务等待超时")
					return
				default:
					failures <- err
					return
				}
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v | 关闭失败", err)
	}
	wg.Wait()
	select {
	case err := <-failures:
		t.Fatalf("concurrent submit: %v | 并发提交失败", err)
	default:
	}
}

// TestNonblockingQueueFull verifies that a saturated nonblocking pool reports
// ErrQueueFull through the public API. | TestNonblockingQueueFull 验证饱和的非阻塞池
// 通过公开 API 返回 ErrQueueFull。
func TestNonblockingQueueFull(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	p := pool.New(append(testOptions(),
		pool.WithWorkers(1),
		pool.WithShards(1),
		pool.WithQueueSize(2),
		pool.WithFallbackQueueSize(2),
		pool.WithSpinCount(0),
		pool.WithNonblocking(),
	)...)
	t.Cleanup(func() {
		releaseFn()
		p.Close()
	})

	started := make(chan struct{})
	if err := p.Go(func(context.Context) error {
		close(started)
		<-release
		return nil
	}); err != nil {
		t.Fatalf("blocker: %v | 提交阻塞任务失败", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker did not start | 阻塞任务未启动")
	}

	accepted := 0
	var full error
	for i := 0; i < 100; i++ {
		err := p.Go(func(context.Context) error { return nil })
		if err == nil {
			accepted++
			continue
		}
		full = err
		break
	}
	if accepted == 0 {
		t.Fatal("no task was accepted | 没有任务被接受")
	}
	if !errors.Is(full, pool.ErrQueueFull) {
		t.Fatalf("full error = %v, want ErrQueueFull | 错误不符", full)
	}
	releaseFn()
	p.Wait()
}

// TestPanicHandlerPanicIsolated verifies that panics in the panic and error
// handlers do not kill a worker or poison the pool. | TestPanicHandlerPanicIsolated
// 验证 panic 处理器与错误处理器自身的 panic 不会杀死 worker 或污染协程池。
func TestPanicHandlerPanicIsolated(t *testing.T) {
	p := pool.New(append(testOptions(),
		pool.WithPanicHandler(func(pool.PanicInfo) { panic("panic handler boom") }),
		pool.WithErrorHandler(func(error) { panic("error handler boom") }),
	)...)
	defer p.Close()

	for i := 0; i < 10; i++ {
		iteration := i
		task := p.Submit(context.Background(), func(context.Context) error {
			if iteration%2 == 0 {
				panic("task boom")
			}
			return errors.New("task error")
		})
		if err := task.Wait(context.Background()); err == nil {
			t.Fatalf("iteration %d: expected error | 预期错误", iteration)
		}
	}
	if err := p.Go(func(context.Context) error { return errors.New("go boom") }); err != nil {
		t.Fatalf("go: %v | 提交失败", err)
	}
	p.Wait()
	if err := p.Call(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("pool unusable after handler panics: %v | 处理器 panic 后池不可用", err)
	}
}

// TestSubmitCanceledWhileQueued verifies that a task canceled before its turn
// does not run and settles with the context error. | TestSubmitCanceledWhileQueued
// 验证轮到自己之前被取消的任务不会执行，并以 context 错误结算。
func TestSubmitCanceledWhileQueued(t *testing.T) {
	p := pool.New(append(testOptions(),
		pool.WithWorkers(1),
		pool.WithShards(1),
		pool.WithQueueSize(4),
		pool.WithFallbackQueueSize(4),
		pool.WithSpinCount(0),
	)...)
	defer p.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	if err := p.Go(func(context.Context) error {
		close(started)
		<-release
		return nil
	}); err != nil {
		t.Fatalf("blocker: %v | 提交阻塞任务失败", err)
	}
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	var ran atomic.Bool
	task := p.Submit(ctx, func(context.Context) error {
		ran.Store(true)
		return nil
	})
	cancel()
	close(release)
	if err := task.Wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("task error = %v, want context.Canceled | 错误不符", err)
	}
	if ran.Load() {
		t.Fatal("canceled queued task ran | 已取消的排队任务仍执行")
	}
	p.Wait()
}

// TestCallContextExpiry verifies that Call returns the context error while the
// running task is allowed to finish. | TestCallContextExpiry 验证 Call 返回 context
// 错误，同时允许运行中的任务结束。
func TestCallContextExpiry(t *testing.T) {
	p := pool.New(append(testOptions(), pool.WithWorkers(1), pool.WithShards(1))...)
	defer p.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- p.Call(ctx, func(context.Context) error {
			close(started)
			<-release
			return nil
		})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("task did not start | 任务未启动")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Call error = %v, want context.Canceled | 错误不符", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Call did not return after cancellation | 取消后 Call 未返回")
	}
	close(release)
	p.Wait()
	if st := p.Stats(); st.Completed != 1 {
		t.Fatalf("completed = %d, want 1 | 完成计数不符", st.Completed)
	}
}

// TestBlockedSubmitterReleasedByShutdown verifies that Shutdown releases a
// submitter blocked on a full queue with ErrPoolClosed. | TestBlockedSubmitterReleasedByShutdown
// 验证 Shutdown 以 ErrPoolClosed 释放阻塞在满队列上的提交方。
func TestBlockedSubmitterReleasedByShutdown(t *testing.T) {
	p := pool.New(append(testOptions(),
		pool.WithWorkers(1),
		pool.WithShards(1),
		pool.WithQueueSize(2),
		pool.WithFallbackQueueSize(2),
		pool.WithSpinCount(0),
	)...)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseFn()
		p.Close()
	})
	if err := p.Go(func(context.Context) error {
		close(started)
		<-release
		return nil
	}); err != nil {
		t.Fatalf("blocker: %v | 提交阻塞任务失败", err)
	}
	<-started
	for i := 0; i < 4; i++ {
		if err := p.Go(func(context.Context) error { return nil }); err != nil {
			t.Fatalf("fill %d: %v | 填充队列失败", i, err)
		}
	}
	blocked := make(chan error, 1)
	go func() {
		blocked <- p.Go(func(context.Context) error { return nil })
	}()
	time.Sleep(10 * time.Millisecond)
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- p.Shutdown(ctx)
	}()
	select {
	case err := <-blocked:
		if !errors.Is(err, pool.ErrPoolClosed) {
			t.Fatalf("blocked submit error = %v, want ErrPoolClosed | 错误不符", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked submitter not released by Shutdown | 提交方未被 Shutdown 释放")
	}
	releaseFn()
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown: %v | 关闭失败", err)
	}
}

// TestConcurrentClose verifies that Close is idempotent and concurrent callers
// all return. | TestConcurrentClose 验证 Close 幂等且并发调用全部返回。
func TestConcurrentClose(t *testing.T) {
	p := pool.New(testOptions()...)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Close()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Close hung | 并发 Close 挂起")
	}
}

// TestResizeAfterClose verifies that Resize rejects a closed pool. |
// TestResizeAfterClose 验证 Resize 拒绝已关闭的池。
func TestResizeAfterClose(t *testing.T) {
	p := pool.New(testOptions()...)
	p.Close()
	if err := p.Resize(4); !errors.Is(err, pool.ErrPoolClosed) {
		t.Fatalf("Resize error = %v, want ErrPoolClosed | 错误不符", err)
	}
}

// TestWithoutMetrics verifies that completion counters are disabled while
// Submitted remains available. | TestWithoutMetrics 验证完成计数被关闭而 Submitted
// 仍可用。
func TestWithoutMetrics(t *testing.T) {
	p := pool.New(append(testOptions(), pool.WithoutMetrics())...)
	defer p.Close()
	for i := 0; i < 100; i++ {
		if err := p.Go(func(context.Context) error { return nil }); err != nil {
			t.Fatalf("go: %v | 提交失败", err)
		}
	}
	p.Wait()
	st := p.Stats()
	if st.Submitted != 100 || st.Completed != 0 || st.Failed != 0 || st.Panicked != 0 {
		t.Fatalf("stats = %+v | 统计不符", st)
	}
}

// TestShutdownTimeoutDrainsInBackground verifies that a timed-out Shutdown
// stops accepting work but keeps draining the queues. | TestShutdownTimeoutDrainsInBackground
// 验证超时的 Shutdown 停止接受新任务但继续在后台排空队列。
func TestShutdownTimeoutDrainsInBackground(t *testing.T) {
	p := pool.New(append(testOptions(), pool.WithWorkers(1), pool.WithShards(1))...)
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() {
		releaseFn()
		p.Close()
	})
	var ran atomic.Int64
	if err := p.Go(func(context.Context) error {
		close(started)
		<-release
		ran.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("blocker: %v | 提交阻塞任务失败", err)
	}
	<-started
	for i := 0; i < 19; i++ {
		if err := p.Go(func(context.Context) error {
			ran.Add(1)
			return nil
		}); err != nil {
			t.Fatalf("go: %v | 提交失败", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := p.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v, want DeadlineExceeded | 错误不符", err)
	}
	if err := p.Go(func(context.Context) error { return nil }); !errors.Is(err, pool.ErrPoolClosed) {
		t.Fatalf("post-shutdown Go = %v, want ErrPoolClosed | 错误不符", err)
	}
	releaseFn()
	p.Wait()
	if got := ran.Load(); got != 20 {
		t.Fatalf("ran = %d, want 20 | 执行数量不符", got)
	}
}

// TestShutdownPrefersCompletedDrain verifies that an already-drained shutdown
// returns nil even when the context has expired. | TestShutdownPrefersCompletedDrain
// 验证已排空的 Shutdown 即使 context 已到期也返回 nil。
func TestShutdownPrefersCompletedDrain(t *testing.T) {
	p := pool.New(testOptions()...)
	p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 100; i++ {
		if err := p.Shutdown(ctx); err != nil {
			t.Fatalf("iteration %d: Shutdown = %v, want nil | 已排空仍返回错误", i, err)
		}
	}
	if err := p.Shutdown(nil); err != nil {
		t.Fatalf("Shutdown(nil) = %v, want nil | nil context 错误", err)
	}
}

// TestGoZeroAllocations verifies the fire-and-forget fast path allocation claim.
// | TestGoZeroAllocations 验证 fire-and-forget 快路径的零分配声明。
func TestGoZeroAllocations(t *testing.T) {
	p := pool.New(append(testOptions(),
		pool.WithWorkers(2),
		pool.WithShards(2),
		pool.WithQueueSize(1024),
		pool.WithFallbackQueueSize(1024),
		pool.WithSpinCount(0),
	)...)
	defer p.Close()
	fn := func(context.Context) error { return nil }
	if err := p.Go(fn); err != nil {
		t.Fatalf("warm-up go: %v | 预热提交失败", err)
	}
	p.Wait()
	allocs := testing.AllocsPerRun(1000, func() {
		_ = p.Go(fn)
		p.Wait()
	})
	if allocs != 0 {
		t.Fatalf("Go allocs = %v, want 0 | Go 分配次数不符", allocs)
	}
}
