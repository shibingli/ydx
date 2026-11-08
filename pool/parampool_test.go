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

// double is the handler used by the ParamPool tests. | double 是 ParamPool 测试使用的
// 处理器。
func double(_ context.Context, n int) (int, error) { return n * 2, nil }

// TestParamPoolCall verifies typed parameter passing and results. | TestParamPoolCall
// 验证类型化参数传递与结果。
func TestParamPoolCall(t *testing.T) {
	p := pool.NewParamPool[int, int](double, testOptions()...)
	defer p.Close()

	got, err := p.Call(context.Background(), 21)
	if err != nil || got != 42 {
		t.Fatalf("Call = (%d, %v), want (42, nil) | 同步调用结果不符", got, err)
	}
}

// TestParamPoolGo verifies fire-and-forget parameter passing. | TestParamPoolGo 验证
// fire-and-forget 参数传递。
func TestParamPoolGo(t *testing.T) {
	args := make(chan int, 1)
	p := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
		args <- n
		return n, nil
	}, testOptions()...)
	defer p.Close()

	if err := p.Go(7); err != nil {
		t.Fatalf("go: %v | 提交失败", err)
	}
	select {
	case got := <-args:
		if got != 7 {
			t.Fatalf("arg = %d, want 7 | 参数不符", got)
		}
	case <-time.After(time.Second):
		t.Fatal("handler not called | 处理器未调用")
	}
}

// TestParamPoolSubmit verifies typed awaitable results. | TestParamPoolSubmit 验证类型化
// 可等待结果。
func TestParamPoolSubmit(t *testing.T) {
	p := pool.NewParamPool[int, int](double, testOptions()...)
	defer p.Close()

	got, err := p.Submit(context.Background(), 5).Wait(context.Background())
	if err != nil || got != 10 {
		t.Fatalf("Wait = (%d, %v), want (10, nil) | 等待结果不符", got, err)
	}
}

// TestParamPoolBatch verifies ordered batch results. | TestParamPoolBatch 验证批量结果的
// 顺序。
func TestParamPoolBatch(t *testing.T) {
	p := pool.NewParamPool[int, int](double, testOptions()...)
	defer p.Close()

	results, err := p.CallBatch(context.Background(), []int{1, 2, 3})
	if err != nil {
		t.Fatalf("CallBatch: %v | 批量调用失败", err)
	}
	want := []int{2, 4, 6}
	for i := range want {
		if results[i] != want[i] {
			t.Fatalf("results = %v, want %v | 批量结果不符", results, want)
		}
	}
}

// TestParamPoolBatchError verifies that all elements run and the first error is
// returned. | TestParamPoolBatchError 验证所有元素都执行且返回首个错误。
func TestParamPoolBatchError(t *testing.T) {
	boom := errors.New("boom")
	p := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
		if n == 2 {
			return n * 2, boom
		}
		return n * 2, nil
	}, testOptions()...)
	defer p.Close()

	results, err := p.CallBatch(context.Background(), []int{1, 2, 3})
	if !errors.Is(err, boom) {
		t.Fatalf("CallBatch error = %v, want boom | 错误不符", err)
	}
	want := []int{2, 4, 6}
	for i := range want {
		if results[i] != want[i] {
			t.Fatalf("results = %v, want %v | 批量结果不符", results, want)
		}
	}
}

// TestParamPoolBatchCancel verifies that cancellation stops the remaining elements.
// | TestParamPoolBatchCancel 验证取消会停止剩余元素。
func TestParamPoolBatchCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int64
	p := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
		calls.Add(1)
		if n == 1 {
			cancel()
		}
		return n * 2, nil
	}, testOptions()...)
	defer p.Close()

	_, err := p.CallBatch(ctx, []int{1, 2, 3})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CallBatch error = %v, want context.Canceled | 错误不符", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1 | 调用次数不符", got)
	}
}

// TestParamPoolGoBatch verifies that GoBatch runs every element. | TestParamPoolGoBatch
// 验证 GoBatch 执行所有元素。
func TestParamPoolGoBatch(t *testing.T) {
	var calls atomic.Int64
	p := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
		calls.Add(1)
		return n, nil
	}, testOptions()...)
	defer p.Close()

	if err := p.GoBatch([]int{1, 2, 3, 4}); err != nil {
		t.Fatalf("GoBatch: %v | 批量提交失败", err)
	}
	p.Wait()
	if got := calls.Load(); got != 4 {
		t.Fatalf("calls = %d, want 4 | 调用次数不符", got)
	}
}

// TestParamPoolPanic verifies per-element panic recovery and worker survival.
// | TestParamPoolPanic 验证逐元素 panic 恢复与 worker 存活。
func TestParamPoolPanic(t *testing.T) {
	p := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
		if n == 1 {
			panic("boom")
		}
		return n, nil
	}, testOptions()...)
	defer p.Close()

	_, err := p.Call(context.Background(), 1)
	if !errors.Is(err, pool.ErrTaskPanicked) {
		t.Fatalf("Call error = %v, want ErrTaskPanicked | 错误不符", err)
	}
	got, err := p.Call(context.Background(), 2)
	if err != nil || got != 2 {
		t.Fatalf("Call after panic = (%d, %v), want (2, nil) | panic 后调用结果不符", got, err)
	}
}

// TestParamPoolBatchPanic verifies that a panicking element does not stop the batch
// and is reported as the first error. | TestParamPoolBatchPanic 验证 panic 元素不会中断
// 批次，并作为首个错误返回。
func TestParamPoolBatchPanic(t *testing.T) {
	var calls atomic.Int64
	p := pool.NewParamPool[int, int](func(_ context.Context, n int) (int, error) {
		calls.Add(1)
		if n == 2 {
			panic("boom")
		}
		return n, nil
	}, testOptions()...)
	defer p.Close()

	results, err := p.CallBatch(context.Background(), []int{1, 2, 3})
	if !errors.Is(err, pool.ErrTaskPanicked) {
		t.Fatalf("CallBatch error = %v, want ErrTaskPanicked | 错误不符", err)
	}
	if results[0] != 1 || results[2] != 3 {
		t.Fatalf("results = %v, want [1 0 3] | 批量结果不符", results)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3 | 调用次数不符", got)
	}
}

// TestParamPoolNilHandler verifies nil handler rejection. | TestParamPoolNilHandler 验证
// 拒绝 nil 处理器。
func TestParamPoolNilHandler(t *testing.T) {
	p := pool.NewParamPool[int, int](nil, testOptions()...)
	defer p.Close()
	if err := p.Go(1); !errors.Is(err, pool.ErrNilTask) {
		t.Fatalf("Go = %v, want ErrNilTask | 错误不符", err)
	}
	if _, err := p.Call(context.Background(), 1); !errors.Is(err, pool.ErrNilTask) {
		t.Fatalf("Call = %v, want ErrNilTask | 错误不符", err)
	}
}

// TestParamPoolEmptyBatch verifies empty batches. | TestParamPoolEmptyBatch 验证空批次。
func TestParamPoolEmptyBatch(t *testing.T) {
	p := pool.NewParamPool[int, int](double, testOptions()...)
	defer p.Close()
	results, err := p.CallBatch(context.Background(), nil)
	if err != nil || results != nil {
		t.Fatalf("CallBatch(nil) = (%v, %v), want (nil, nil) | 空批次结果不符", results, err)
	}
	if err := p.GoBatch(nil); err != nil {
		t.Fatalf("GoBatch(nil) = %v, want nil | 空批次错误", err)
	}
}

// TestParamPoolCallBatchTo verifies caller-provided result buffer reuse. |
// TestParamPoolCallBatchTo 验证调用方结果缓冲区的复用。
func TestParamPoolCallBatchTo(t *testing.T) {
	p := pool.NewParamPool[int, int](double, testOptions()...)
	defer p.Close()

	dst := make([]int, 0, 8)
	results, err := p.CallBatchTo(dst, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("CallBatchTo: %v | 批量调用失败", err)
	}
	want := []int{2, 4, 6}
	for i := range want {
		if results[i] != want[i] {
			t.Fatalf("results = %v, want %v | 批量结果不符", results, want)
		}
	}
	if &results[0] != &dst[:3][0] {
		t.Fatal("CallBatchTo did not reuse dst | CallBatchTo 未复用 dst")
	}
	again, err := p.CallBatchTo(results[:0], []int{4, 5})
	if err != nil {
		t.Fatalf("CallBatchTo reuse: %v | 复用批量调用失败", err)
	}
	if &again[0] != &results[0] || again[0] != 8 || again[1] != 10 {
		t.Fatalf("reuse results = %v | 复用结果不符", again)
	}
}

// TestParamPoolSubmitBatch verifies the awaitable batch API. | TestParamPoolSubmitBatch
// 验证可等待批量 API。
func TestParamPoolSubmitBatch(t *testing.T) {
	p := pool.NewParamPool[int, int](double, testOptions()...)
	defer p.Close()

	ctx := context.Background()
	got, err := p.SubmitBatch(ctx, []int{1, 2, 3}).Wait(ctx)
	if err != nil {
		t.Fatalf("SubmitBatch: %v | 批量提交失败", err)
	}
	want := []int{2, 4, 6}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("results = %v, want %v | 批量结果不符", got, want)
		}
	}
	empty, err := p.SubmitBatch(ctx, nil).Wait(ctx)
	if err != nil || empty != nil {
		t.Fatalf("empty SubmitBatch = (%v, %v), want (nil, nil) | 空批次结果不符", empty, err)
	}
}

// TestParamPoolBatchStats verifies that a batch contributes one Submitted and one
// Completed per element. | TestParamPoolBatchStats 验证批次按元素计入 Submitted 与
// Completed。
func TestParamPoolBatchStats(t *testing.T) {
	p := pool.NewParamPool[int, int](double, testOptions()...)
	defer p.Close()

	ctx := context.Background()
	if _, err := p.SubmitBatch(ctx, []int{1, 2, 3, 4, 5}).Wait(ctx); err != nil {
		t.Fatalf("SubmitBatch: %v | 批量提交失败", err)
	}
	st := p.Stats()
	if st.Submitted != 5 || st.Completed != 5 {
		t.Fatalf("after SubmitBatch stats = %+v | 批量提交统计不符", st)
	}
	if err := p.GoBatch([]int{6, 7, 8}); err != nil {
		t.Fatalf("GoBatch: %v | 批量提交失败", err)
	}
	p.Wait()
	st = p.Stats()
	if st.Submitted != 8 || st.Completed != 8 {
		t.Fatalf("after GoBatch stats = %+v | 批量提交统计不符", st)
	}
}

// TestParamPoolStatsConcurrent verifies that Submitted never lags Completed while
// batches are submitted and waited concurrently. | TestParamPoolStatsConcurrent
// 验证并发批量提交与等待时 Submitted 不会落后于 Completed。
func TestParamPoolStatsConcurrent(t *testing.T) {
	p := pool.NewParamPool[int, int](double, append(testOptions(),
		pool.WithWorkers(8),
		pool.WithShards(8),
		pool.WithQueueSize(1024),
		pool.WithFallbackQueueSize(1024),
		pool.WithSpinCount(0),
	)...)
	defer p.Close()

	const (
		submitters = 4
		batches    = 2000
		batchSize  = 4
		waiters    = 4
	)
	total := uint64(submitters * batches * batchSize)
	failures := make(chan error, waiters)
	submitted := make(chan struct{})
	var submitWG sync.WaitGroup
	for s := 0; s < submitters; s++ {
		submitWG.Add(1)
		go func() {
			defer submitWG.Done()
			for i := 0; i < batches; i++ {
				args := make([]int, batchSize)
				for j := range args {
					args[j] = j
				}
				if err := p.GoBatch(args); err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	go func() {
		submitWG.Wait()
		close(submitted)
	}()

	var waitWG sync.WaitGroup
	for w := 0; w < waiters; w++ {
		waitWG.Add(1)
		go func() {
			defer waitWG.Done()
			for {
				p.Wait()
				st := p.Stats()
				if st.Completed > st.Submitted {
					failures <- errors.New("Completed exceeded Submitted | 完成数超过提交数")
					return
				}
				select {
				case <-submitted:
					return
				default:
				}
			}
		}()
	}
	waitWG.Wait()
	p.Wait()
	select {
	case err := <-failures:
		t.Fatalf("concurrent stats: %v | 并发统计不一致", err)
	default:
	}
	st := p.Stats()
	if st.Submitted != total || st.Completed != total {
		t.Fatalf("stats = %+v, want Submitted=Completed=%d | 批量统计不符", st, total)
	}
}

// TestParamPoolBatchCloseSettlesFutures verifies that a queued batch discarded by
// Close completes its Future with ErrPoolClosed. | TestParamPoolBatchCloseSettlesFutures
// 验证被 Close 丢弃的排队批次以 ErrPoolClosed 完成 Future。
func TestParamPoolBatchCloseSettlesFutures(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	handler := func(_ context.Context, n int) (int, error) {
		if n == 0 {
			close(started)
			<-release
		}
		return n * 2, nil
	}
	p := pool.NewParamPool[int, int](handler, append(testOptions(),
		pool.WithWorkers(1),
		pool.WithShards(1),
		pool.WithQueueSize(4),
		pool.WithFallbackQueueSize(4),
		pool.WithSpinCount(0),
	)...)
	t.Cleanup(func() {
		releaseFn()
		p.Close()
	})

	if err := p.Go(0); err != nil {
		t.Fatalf("blocker: %v | 提交阻塞任务失败", err)
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	future := p.SubmitBatch(ctx, []int{1, 2, 3})

	closed := make(chan struct{})
	go func() {
		p.Close()
		close(closed)
	}()
	waitUntil(t, "pool closed", func() bool {
		return errors.Is(p.Go(1), pool.ErrPoolClosed)
	})
	releaseFn()

	got, err := future.Wait(ctx)
	if !errors.Is(err, pool.ErrPoolClosed) {
		t.Fatalf("Future error = %v, want ErrPoolClosed | 批量 Future 错误不符", err)
	}
	if got != nil {
		t.Fatalf("Future results = %v, want nil | 丢弃批次不应返回结果", got)
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("Close did not return | Close 未返回")
	}
}

// TestParamPoolGoZeroAllocations verifies the fixed-handler fast path allocation
// claim. | TestParamPoolGoZeroAllocations 验证固定处理器快路径的零分配声明。
func TestParamPoolGoZeroAllocations(t *testing.T) {
	p := pool.NewParamPool[int, int](double, append(testOptions(),
		pool.WithWorkers(2),
		pool.WithShards(2),
		pool.WithQueueSize(1024),
		pool.WithFallbackQueueSize(1024),
		pool.WithSpinCount(0),
	)...)
	defer p.Close()
	if err := p.Go(1); err != nil {
		t.Fatalf("warm-up go: %v | 预热提交失败", err)
	}
	p.Wait()
	allocs := testing.AllocsPerRun(1000, func() {
		_ = p.Go(1)
		p.Wait()
	})
	if allocs != 0 {
		t.Fatalf("ParamPool.Go allocs = %v, want 0 | ParamPool.Go 分配次数不符", allocs)
	}
}

// TestParamPoolGoBatchZeroAllocations verifies the batch header recycling claim.
// | TestParamPoolGoBatchZeroAllocations 验证批次头复用后的零分配声明。
func TestParamPoolGoBatchZeroAllocations(t *testing.T) {
	p := pool.NewParamPool[int, int](double, append(testOptions(),
		pool.WithWorkers(2),
		pool.WithShards(2),
		pool.WithQueueSize(1024),
		pool.WithFallbackQueueSize(1024),
		pool.WithSpinCount(0),
	)...)
	defer p.Close()
	args := []int{1, 2, 3}
	if err := p.GoBatch(args); err != nil {
		t.Fatalf("warm-up GoBatch: %v | 预热批量提交失败", err)
	}
	p.Wait()
	allocs := testing.AllocsPerRun(1000, func() {
		_ = p.GoBatch(args)
		p.Wait()
	})
	if allocs != 0 {
		t.Fatalf("GoBatch allocs = %v, want 0 | GoBatch 分配次数不符", allocs)
	}
}
