package pool

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testEngineConfig returns a small engine configuration for tests. | testEngineConfig
// 返回测试用的小型引擎配置。
func testEngineConfig() engineConfig {
	return engineConfig{
		workers:      2,
		shards:       2,
		queueSize:    64,
		fallbackSize: 64,
		spinCount:    2,
		metrics:      true,
	}
}

// waitFor polls condition until it holds or the deadline expires. | waitFor 轮询条件直到成立
// 或超时。
func waitFor(t *testing.T, what string, condition func() bool) {
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

// TestEngineSubmitRun verifies basic submission and execution. | TestEngineSubmitRun
// 验证基本提交与执行。
func TestEngineSubmitRun(t *testing.T) {
	cfg := testEngineConfig()
	values := make(chan int, 100)
	e := newEngine[int](cfg, func(w *workerState, v int) {
		values <- v
		w.count(1, 0, 0)
	}, func(int) {})
	defer e.close(false)

	for i := 0; i < 100; i++ {
		if err := e.submit(i); err != nil {
			t.Fatalf("submit %d: %v | 提交失败", i, err)
		}
	}
	e.wait()
	close(values)
	seen := make(map[int]bool, 100)
	for v := range values {
		if seen[v] {
			t.Fatalf("duplicate value %d | 重复值", v)
		}
		seen[v] = true
	}
	if len(seen) != 100 {
		t.Fatalf("got %d values, want 100 | 结果数量不符", len(seen))
	}
	st := e.stats()
	if st.Submitted != 100 || st.Completed != 100 {
		t.Fatalf("stats submitted/completed = %d/%d, want 100/100 | 统计不符", st.Submitted, st.Completed)
	}
}

// TestEngineNonblockingFull verifies that a saturated nonblocking engine rejects work.
// | TestEngineNonblockingFull 验证饱和的非阻塞引擎会拒绝任务。
func TestEngineNonblockingFull(t *testing.T) {
	cfg := testEngineConfig()
	cfg.workers = 1
	cfg.shards = 1
	cfg.queueSize = 2
	cfg.fallbackSize = 2
	cfg.spinCount = 0
	cfg.nonblocking = true

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	e := newEngine[int](cfg, func(w *workerState, v int) {
		once.Do(func() {
			close(started)
			<-release
		})
		w.count(1, 0, 0)
	}, func(int) {})
	defer e.close(false)

	if err := e.submit(0); err != nil {
		t.Fatalf("submit blocker: %v | 提交阻塞任务失败", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker did not start | 阻塞任务未启动")
	}

	accepted := 0
	var rejected error
	for i := 0; i < 100; i++ {
		err := e.submit(i + 1)
		if err == nil {
			accepted++
			continue
		}
		rejected = err
		break
	}
	if !errors.Is(rejected, ErrQueueFull) {
		t.Fatalf("rejection = %v, want ErrQueueFull | 拒绝错误不符", rejected)
	}
	if accepted != 4 {
		t.Fatalf("accepted = %d, want 4 | 接受数量不符", accepted)
	}
	close(release)
	e.wait()
}

// TestEngineCloseDiscard verifies that immediate close discards queued work.
// | TestEngineCloseDiscard 验证立即关闭会丢弃排队任务。
func TestEngineCloseDiscard(t *testing.T) {
	cfg := testEngineConfig()
	cfg.workers = 1
	cfg.shards = 1
	cfg.queueSize = 8
	cfg.fallbackSize = 8
	cfg.spinCount = 0

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var ran atomic.Int64
	var discarded atomic.Int64
	e := newEngine[int](cfg, func(w *workerState, v int) {
		once.Do(func() {
			close(started)
			<-release
		})
		ran.Add(1)
		w.count(1, 0, 0)
	}, func(int) {
		discarded.Add(1)
	})

	if err := e.submit(0); err != nil {
		t.Fatalf("submit blocker: %v | 提交阻塞任务失败", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker did not start | 阻塞任务未启动")
	}
	for i := 0; i < 10; i++ {
		if err := e.submit(i + 1); err != nil {
			t.Fatalf("submit %d: %v | 提交失败", i+1, err)
		}
	}
	closed := make(chan struct{})
	go func() {
		e.close(false)
		close(closed)
	}()
	// Close must be observed before the blocked worker can dequeue the ten queued
	// jobs; otherwise that worker may legitimately run them before close starts.
	// | 必须先让 worker 观察到关闭，再解除阻塞；否则它可能在关闭开始前合法地执行排队的
	// 十个任务。
	waitFor(t, "engine close starts", func() bool { return e.closed.Load() })
	close(release)
	<-closed

	if got := ran.Load(); got != 1 {
		t.Fatalf("ran = %d, want 1 | 执行数量不符", got)
	}
	if got := discarded.Load(); got != 10 {
		t.Fatalf("discarded = %d, want 10 | 丢弃数量不符", got)
	}
	if st := e.stats(); st.Discarded != 10 || st.Queued != 0 {
		t.Fatalf("stats discarded/queued = %d/%d, want 10/0 | 统计不符", st.Discarded, st.Queued)
	}
}

// TestEngineShutdownDrain verifies that graceful shutdown runs every queued job.
// | TestEngineShutdownDrain 验证优雅关闭会执行所有排队任务。
func TestEngineShutdownDrain(t *testing.T) {
	cfg := testEngineConfig()
	cfg.workers = 1
	cfg.shards = 1
	cfg.queueSize = 16
	cfg.fallbackSize = 16
	cfg.spinCount = 0

	var ran atomic.Int64
	e := newEngine[int](cfg, func(w *workerState, v int) {
		ran.Add(1)
		w.count(1, 0, 0)
	}, func(int) {})
	for i := 0; i < 50; i++ {
		if err := e.submit(i); err != nil {
			t.Fatalf("submit %d: %v | 提交失败", i, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v | 关闭失败", err)
	}
	if got := ran.Load(); got != 50 {
		t.Fatalf("ran = %d, want 50 | 执行数量不符", got)
	}
	if err := e.submit(51); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("submit after shutdown = %v, want ErrPoolClosed | 关闭后提交错误不符", err)
	}
}

// TestEngineWait verifies that wait blocks until all accepted jobs finish. | TestEngineWait
// 验证 wait 会等待所有已接受任务完成。
func TestEngineWait(t *testing.T) {
	cfg := testEngineConfig()
	var ran atomic.Int64
	e := newEngine[int](cfg, func(w *workerState, v int) {
		ran.Add(1)
		w.count(1, 0, 0)
	}, func(int) {})
	defer e.close(false)
	for i := 0; i < 200; i++ {
		if err := e.submit(i); err != nil {
			t.Fatalf("submit %d: %v | 提交失败", i, err)
		}
	}
	e.wait()
	if got := ran.Load(); got != 200 {
		t.Fatalf("ran = %d, want 200 | 执行数量不符", got)
	}
}

// TestEngineResize verifies growth and lazy shrink. | TestEngineResize 验证扩容与惰性缩容。
func TestEngineResize(t *testing.T) {
	cfg := testEngineConfig()
	cfg.workers = 1
	cfg.shards = 1
	e := newEngine[int](cfg, func(w *workerState, v int) {
		w.count(1, 0, 0)
	}, func(int) {})
	defer e.close(false)

	if err := e.resize(4); err != nil {
		t.Fatalf("resize up: %v | 扩容失败", err)
	}
	if got := e.stats().Workers; got != 4 {
		t.Fatalf("workers after grow = %d, want 4 | 扩容后 worker 数不符", got)
	}
	if err := e.resize(1); err != nil {
		t.Fatalf("resize down: %v | 缩容失败", err)
	}
	waitFor(t, "shrink to one worker", func() bool { return e.stats().Workers == 1 })
}

// TestEngineNoGoroutineLeak verifies that closed engines release their workers.
// | TestEngineNoGoroutineLeak 验证关闭后的引擎会释放 worker。
func TestEngineNoGoroutineLeak(t *testing.T) {
	base := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		cfg := testEngineConfig()
		e := newEngine[int](cfg, func(w *workerState, v int) {
			w.count(1, 0, 0)
		}, func(int) {})
		if err := e.submit(i); err != nil {
			t.Fatalf("submit: %v | 提交失败", err)
		}
		e.wait()
		e.close(false)
	}
	waitFor(t, "goroutines to return to baseline", func() bool {
		return runtime.NumGoroutine() <= base+2
	})
}

// TestEngineStress verifies concurrent producers, stealing and completion counts.
// | TestEngineStress 验证并发生产者、工作窃取与完成计数。
func TestEngineStress(t *testing.T) {
	const (
		producers   = 8
		perProducer = 5000
		total       = producers * perProducer
	)
	cfg := testEngineConfig()
	cfg.workers = 4
	cfg.shards = 2
	cfg.queueSize = 256
	cfg.fallbackSize = 256
	values := make(chan int, total)
	e := newEngine[int](cfg, func(w *workerState, v int) {
		values <- v
		w.count(1, 0, 0)
	}, func(int) {})
	defer e.close(false)

	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				if err := e.submit(base + i); err != nil {
					t.Errorf("submit: %v | 提交失败", err)
					return
				}
			}
		}(p * perProducer)
	}
	wg.Wait()
	e.wait()
	close(values)

	seen := make([]bool, total)
	count := 0
	for v := range values {
		if v < 0 || v >= total || seen[v] {
			t.Fatalf("bad or duplicate value %d | 非法或重复值", v)
		}
		seen[v] = true
		count++
	}
	if count != total {
		t.Fatalf("count = %d, want %d | 数量不符", count, total)
	}
	st := e.stats()
	if st.Submitted != total || st.Completed != total || st.Queued != 0 {
		t.Fatalf("stats = %+v | 统计不符", st)
	}
}
