package pool_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/pool"
)

// TestResultPoolCall verifies typed synchronous results. | TestResultPoolCall 验证类型化
// 同步结果。
func TestResultPoolCall(t *testing.T) {
	p := pool.NewResultPool[int](testOptions()...)
	defer p.Close()

	got, err := p.Call(context.Background(), func(context.Context) (int, error) {
		return 42, nil
	})
	if err != nil || got != 42 {
		t.Fatalf("Call = (%d, %v), want (42, nil) | 同步调用结果不符", got, err)
	}
}

// TestResultPoolSubmit verifies typed awaitable results. | TestResultPoolSubmit 验证类型化
// 可等待结果。
func TestResultPoolSubmit(t *testing.T) {
	p := pool.NewResultPool[string](testOptions()...)
	defer p.Close()

	future := p.Submit(context.Background(), func(context.Context) (string, error) {
		return "ok", nil
	})
	got, err := future.Wait(context.Background())
	if err != nil || got != "ok" {
		t.Fatalf("Wait = (%q, %v), want (\"ok\", nil) | 等待结果不符", got, err)
	}
	select {
	case <-future.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed | Done 未关闭")
	}
}

// TestResultPoolGoError verifies that fire-and-forget errors reach the handler.
// | TestResultPoolGoError 验证 fire-and-forget 错误会交给处理器。
func TestResultPoolGoError(t *testing.T) {
	errsCh := make(chan error, 1)
	p := pool.NewResultPool[int](append(testOptions(), pool.WithErrorHandler(func(err error) {
		errsCh <- err
	}))...)
	defer p.Close()

	boom := errors.New("boom")
	if err := p.Go(func(context.Context) (int, error) { return 0, boom }); err != nil {
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

// TestResultPoolPanic verifies typed panic recovery. | TestResultPoolPanic 验证类型化
// panic 恢复。
func TestResultPoolPanic(t *testing.T) {
	p := pool.NewResultPool[int](testOptions()...)
	defer p.Close()

	_, err := p.Call(context.Background(), func(context.Context) (int, error) {
		panic("boom")
	})
	if !errors.Is(err, pool.ErrTaskPanicked) {
		t.Fatalf("Call error = %v, want ErrTaskPanicked | 错误不符", err)
	}
	var panicErr *pool.PanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("error %v is not *PanicError | 错误类型不符", err)
	}
}

// TestResultPoolConcurrent verifies concurrent typed calls. | TestResultPoolConcurrent
// 验证并发类型化调用。
func TestResultPoolConcurrent(t *testing.T) {
	p := pool.NewResultPool[int](testOptions()...)
	defer p.Close()

	var sum atomic.Int64
	futures := make([]*pool.Future[int], 0, 100)
	for i := 0; i < 100; i++ {
		n := i
		futures = append(futures, p.Submit(context.Background(), func(context.Context) (int, error) {
			return n, nil
		}))
	}
	for i, f := range futures {
		got, err := f.Wait(context.Background())
		if err != nil || got != i {
			t.Fatalf("future %d = (%d, %v) | 结果不符", i, got, err)
		}
		sum.Add(int64(got))
	}
	if got := sum.Load(); got != 4950 {
		t.Fatalf("sum = %d, want 4950 | 求和不符", got)
	}
}

// TestResultPoolNilTask verifies nil function rejection. | TestResultPoolNilTask 验证拒绝
// nil 函数。
func TestResultPoolNilTask(t *testing.T) {
	p := pool.NewResultPool[int](testOptions()...)
	defer p.Close()
	if err := p.Go(nil); !errors.Is(err, pool.ErrNilTask) {
		t.Fatalf("Go(nil) = %v, want ErrNilTask | 错误不符", err)
	}
	future := p.Submit(context.Background(), nil)
	if _, err := future.Wait(context.Background()); !errors.Is(err, pool.ErrNilTask) {
		t.Fatalf("Submit(nil) error = %v, want ErrNilTask | 错误不符", err)
	}
}
