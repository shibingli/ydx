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
