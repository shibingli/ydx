package pool_test

import (
	"context"
	"errors"
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
