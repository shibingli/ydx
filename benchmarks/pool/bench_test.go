package pool_test

import (
	"context"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alitto/pond/v2"
	"github.com/gammazero/workerpool"
	"github.com/panjf2000/ants/v2"
	concpool "github.com/sourcegraph/conc/pool"

	ydxpool "github.com/shibingli/ydx/pool"
)

const (
	queueSize = 4096
	batchSize = 64
)

// workers returns the worker count shared by every adapter. | workers 返回所有适配器共享的
// worker 数。
func workers() int { return runtime.GOMAXPROCS(0) }

// instance is one benchmark adapter. | instance 是一个基准适配器。
type instance struct {
	// submit enqueues one task and reports acceptance. | submit 入队一个任务并报告是否接受。
	submit func(fn func()) error
	// close releases the pool after the timed region. | close 在计时区之后释放池。
	close func()
}

// adapterNames lists the compared implementations. | adapterNames 列出对比实现。
var adapterNames = []string{"ydx", "ants", "pond", "workerpool", "conc", "goroutine"}

// newInstance creates one adapter with a bounded concurrency of workers(). |
// newInstance 创建一个并发上限为 workers() 的适配器。
func newInstance(b *testing.B, name string) instance {
	b.Helper()
	switch name {
	case "ydx":
		p := ydxpool.NewParamPool[func(), struct{}](func(_ context.Context, fn func()) (struct{}, error) {
			fn()
			return struct{}{}, nil
		},
			ydxpool.WithWorkers(workers()),
			ydxpool.WithQueueSize(queueSize),
			ydxpool.WithFallbackQueueSize(queueSize),
			ydxpool.WithSpinCount(64),
		)
		return instance{
			submit: func(fn func()) error { return p.Go(fn) },
			close:  p.Close,
		}
	case "ants":
		p, err := ants.NewPool(workers(), ants.WithPreAlloc(true))
		if err != nil {
			b.Fatalf("ants.NewPool: %v | 创建 ants 池失败", err)
		}
		return instance{
			submit: p.Submit,
			close:  p.Release,
		}
	case "pond":
		p := pond.NewPool(workers(), pond.WithQueueSize(queueSize))
		return instance{
			submit: func(fn func()) error {
				p.Submit(fn)
				return nil
			},
			close: p.StopAndWait,
		}
	case "workerpool":
		p := workerpool.New(workers())
		return instance{
			submit: func(fn func()) error {
				p.Submit(fn)
				return nil
			},
			close: p.StopWait,
		}
	case "conc":
		p := concpool.New().WithMaxGoroutines(workers())
		return instance{
			submit: func(fn func()) error {
				p.Go(fn)
				return nil
			},
			close: p.Wait,
		}
	case "goroutine":
		sem := make(chan struct{}, workers())
		return instance{
			submit: func(fn func()) error {
				sem <- struct{}{}
				go func() {
					defer func() { <-sem }()
					fn()
				}()
				return nil
			},
			close: func() {},
		}
	default:
		b.Fatalf("unknown adapter %q | 未知适配器", name)
		return instance{}
	}
}

// BenchmarkGoNoop measures fire-and-forget submission of a no-op task. | BenchmarkGoNoop
// 测量空任务的 fire-and-forget 提交。
func BenchmarkGoNoop(b *testing.B) {
	for _, name := range adapterNames {
		b.Run(name, func(b *testing.B) {
			ad := newInstance(b, name)
			b.Cleanup(ad.close)

			var wg sync.WaitGroup
			wg.Add(b.N)
			fn := wg.Done
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := ad.submit(fn); err != nil {
					wg.Done()
					b.Fatalf("submit: %v | 提交失败", err)
				}
			}
			wg.Wait()
			b.StopTimer()
		})
	}
}

// BenchmarkGoAtomic measures a nanosecond-scale atomic increment task. |
// BenchmarkGoAtomic 测量纳秒级原子递增任务。
func BenchmarkGoAtomic(b *testing.B) {
	for _, name := range adapterNames {
		b.Run(name, func(b *testing.B) {
			ad := newInstance(b, name)
			b.Cleanup(ad.close)

			var wg sync.WaitGroup
			wg.Add(b.N)
			var counter atomic.Int64
			fn := func() {
				counter.Add(1)
				wg.Done()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := ad.submit(fn); err != nil {
					wg.Done()
					b.Fatalf("submit: %v | 提交失败", err)
				}
			}
			wg.Wait()
			b.StopTimer()
			if got := counter.Load(); got != int64(b.N) {
				b.Fatalf("counter = %d, want %d | 计数不符", got, b.N)
			}
		})
	}
}

// BenchmarkGoParallel measures high-contention submission from every P. |
// BenchmarkGoParallel 测量每个 P 高并发提交。
func BenchmarkGoParallel(b *testing.B) {
	for _, name := range adapterNames {
		b.Run(name, func(b *testing.B) {
			ad := newInstance(b, name)
			b.Cleanup(ad.close)

			var wg sync.WaitGroup
			wg.Add(b.N)
			fn := wg.Done
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := ad.submit(fn); err != nil {
						wg.Done()
						b.Errorf("submit: %v | 提交失败", err)
						return
					}
				}
			})
			wg.Wait()
			b.StopTimer()
		})
	}
}

// BenchmarkCall measures a synchronous submit-and-wait round trip. Only
// implementations with a synchronous API are compared. | BenchmarkCall 测量同步提交并等待的
// 往返。仅比较提供同步 API 的实现。
func BenchmarkCall(b *testing.B) {
	b.Run("ydx", func(b *testing.B) {
		p := ydxpool.New(
			ydxpool.WithWorkers(workers()),
			ydxpool.WithQueueSize(queueSize),
			ydxpool.WithFallbackQueueSize(queueSize),
			ydxpool.WithSpinCount(64),
		)
		defer p.Close()
		fn := func(context.Context) error { return nil }
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := p.Call(context.Background(), fn); err != nil {
				b.Fatalf("call: %v | 同步调用失败", err)
			}
		}
	})
	b.Run("pond", func(b *testing.B) {
		p := pond.NewPool(workers(), pond.WithQueueSize(queueSize))
		defer p.StopAndWait()
		fn := func() {}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := p.Submit(fn).Wait(); err != nil {
				b.Fatalf("wait: %v | 等待失败", err)
			}
		}
	})
	b.Run("workerpool", func(b *testing.B) {
		p := workerpool.New(workers())
		defer p.StopWait()
		fn := func() {}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p.SubmitWait(fn)
		}
	})
}

// BenchmarkBatch measures one batch of 64 no-op tasks per operation. | BenchmarkBatch
// 测量每次操作 64 个空任务的批量提交。
func BenchmarkBatch(b *testing.B) {
	b.Run("ydx-batch", func(b *testing.B) {
		var wg sync.WaitGroup
		p := ydxpool.NewParamPool[int, struct{}](func(context.Context, int) (struct{}, error) {
			wg.Done()
			return struct{}{}, nil
		},
			ydxpool.WithWorkers(workers()),
			ydxpool.WithQueueSize(queueSize),
			ydxpool.WithFallbackQueueSize(queueSize),
			ydxpool.WithSpinCount(64),
		)
		defer p.Close()
		args := make([]int, batchSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wg.Add(batchSize)
			if err := p.GoBatch(args); err != nil {
				wg.Add(-batchSize)
				b.Fatalf("GoBatch: %v | 批量提交失败", err)
			}
			wg.Wait()
		}
	})
	b.Run("ydx-loop", func(b *testing.B) {
		var wg sync.WaitGroup
		p := ydxpool.NewParamPool[int, struct{}](func(context.Context, int) (struct{}, error) {
			wg.Done()
			return struct{}{}, nil
		},
			ydxpool.WithWorkers(workers()),
			ydxpool.WithQueueSize(queueSize),
			ydxpool.WithFallbackQueueSize(queueSize),
			ydxpool.WithSpinCount(64),
		)
		defer p.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wg.Add(batchSize)
			for j := 0; j < batchSize; j++ {
				if err := p.Go(0); err != nil {
					wg.Done()
					b.Fatalf("Go: %v | 提交失败", err)
				}
			}
			wg.Wait()
		}
	})
	for _, name := range []string{"ants", "pond", "workerpool", "conc"} {
		b.Run(name, func(b *testing.B) {
			var wg sync.WaitGroup
			p := newInstance(b, name)
			b.Cleanup(p.close)
			fn := wg.Done
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wg.Add(batchSize)
				for j := 0; j < batchSize; j++ {
					if err := p.submit(fn); err != nil {
						wg.Done()
						b.Fatalf("submit: %v | 提交失败", err)
					}
				}
				wg.Wait()
			}
		})
	}
}

// TestLatency reports submit-to-start latency percentiles for every adapter. |
// TestLatency 报告每个适配器从提交到开始执行的延迟分位数。
//
// It is a measurement harness, not a regression gate; run it with -v to see the
// table. | 它是测量工具而非回归门禁；使用 -v 查看表格。
func TestLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement skipped in -short mode | -short 模式跳过延迟测量")
	}
	const n = 100_000
	for _, name := range adapterNames {
		name := name
		t.Run(name, func(t *testing.T) {
			starts := make([]time.Time, n)
			lat := make([]int64, n)
			var wg sync.WaitGroup
			wg.Add(n)
			// Bound the backlog to two tasks per worker so the measurement
			// compares dispatch latency at equal concurrency rather than the
			// producer's raw submission rate. | 把积压限制为每 worker 两个任务，使测量
			// 比较相同并发下的分发延迟，而不是提交方的原始提交速率。
			inflight := make(chan struct{}, workers()*2)
			var submit func(i int) error
			var closeFn func()
			switch name {
			case "ydx":
				p := ydxpool.NewParamPool[int, struct{}](func(_ context.Context, i int) (struct{}, error) {
					lat[i] = time.Since(starts[i]).Nanoseconds()
					<-inflight
					wg.Done()
					return struct{}{}, nil
				},
					ydxpool.WithWorkers(workers()),
					ydxpool.WithQueueSize(queueSize),
					ydxpool.WithFallbackQueueSize(queueSize),
					ydxpool.WithSpinCount(16),
				)
				submit = func(i int) error { return p.Go(i) }
				closeFn = p.Close
			case "ants":
				p, err := ants.NewPoolWithFunc(workers(), func(arg any) {
					i := arg.(int)
					lat[i] = time.Since(starts[i]).Nanoseconds()
					<-inflight
					wg.Done()
				}, ants.WithPreAlloc(true))
				if err != nil {
					t.Fatalf("ants.NewPoolWithFunc: %v | 创建 ants 池失败", err)
				}
				submit = func(i int) error { return p.Invoke(i) }
				closeFn = p.Release
			case "pond":
				// These APIs take a closure per task; the allocation is part of
				// their measured cost. | 这些 API 每任务接收闭包，分配计入其被测成本。
				p := pond.NewPool(workers(), pond.WithQueueSize(queueSize))
				submit = func(i int) error {
					p.Submit(func() {
						lat[i] = time.Since(starts[i]).Nanoseconds()
						<-inflight
						wg.Done()
					})
					return nil
				}
				closeFn = p.StopAndWait
			case "workerpool":
				p := workerpool.New(workers())
				submit = func(i int) error {
					p.Submit(func() {
						lat[i] = time.Since(starts[i]).Nanoseconds()
						<-inflight
						wg.Done()
					})
					return nil
				}
				closeFn = p.StopWait
			case "conc":
				p := concpool.New().WithMaxGoroutines(workers())
				submit = func(i int) error {
					p.Go(func() {
						lat[i] = time.Since(starts[i]).Nanoseconds()
						<-inflight
						wg.Done()
					})
					return nil
				}
				closeFn = p.Wait
			case "goroutine":
				submit = func(i int) error {
					go func() {
						lat[i] = time.Since(starts[i]).Nanoseconds()
						<-inflight
						wg.Done()
					}()
					return nil
				}
				closeFn = func() {}
			default:
				t.Fatalf("unknown adapter %q | 未知适配器", name)
			}

			start := time.Now()
			for i := 0; i < n; i++ {
				inflight <- struct{}{}
				starts[i] = time.Now()
				if err := submit(i); err != nil {
					<-inflight
					wg.Done()
					t.Fatalf("submit %d: %v | 提交失败", i, err)
				}
			}
			wg.Wait()
			elapsed := time.Since(start)
			closeFn()

			reportPercentiles(t, lat, elapsed)
		})
	}
}

// reportPercentiles logs p50/p90/p99/p99.9/max for lat. | reportPercentiles 输出 lat 的
// p50/p90/p99/p99.9/max。
func reportPercentiles(t *testing.T, lat []int64, elapsed time.Duration) {
	t.Helper()
	if len(lat) == 0 {
		t.Fatal("no latency samples | 没有延迟样本")
	}
	sorted := append([]int64(nil), lat...)
	slices.Sort(sorted)
	pick := func(q float64) int64 {
		idx := int(float64(len(sorted)-1) * q)
		return sorted[idx]
	}
	t.Logf("samples=%d elapsed=%s p50=%dns p90=%dns p99=%dns p999=%dns max=%dns | 延迟分位",
		len(sorted), elapsed, pick(0.50), pick(0.90), pick(0.99), pick(0.999), sorted[len(sorted)-1])
}

// BenchmarkCallBatch compares per-batch results allocation with a caller-provided
// buffer. Each operation runs batchSize tasks. | BenchmarkCallBatch 对比每批结果分配
// 与调用方缓冲复用。每次操作执行 batchSize 个任务。
func BenchmarkCallBatch(b *testing.B) {
	opts := []ydxpool.Option{
		ydxpool.WithWorkers(workers()),
		ydxpool.WithQueueSize(queueSize),
		ydxpool.WithFallbackQueueSize(queueSize),
		ydxpool.WithSpinCount(64),
	}
	handler := func(_ context.Context, n int) (int, error) { return n * 2, nil }
	args := make([]int, batchSize)
	for i := range args {
		args[i] = i
	}
	ctx := context.Background()

	b.Run("ydx-alloc", func(b *testing.B) {
		p := ydxpool.NewParamPool[int, int](handler, opts...)
		defer p.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.CallBatch(ctx, args); err != nil {
				b.Fatalf("CallBatch: %v | 批量调用失败", err)
			}
		}
	})
	b.Run("ydx-reuse", func(b *testing.B) {
		p := ydxpool.NewParamPool[int, int](handler, opts...)
		defer p.Close()
		dst := make([]int, 0, batchSize)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var err error
			dst, err = p.CallBatchTo(dst[:0], args)
			if err != nil {
				b.Fatalf("CallBatchTo: %v | 批量调用失败", err)
			}
		}
	})
}
