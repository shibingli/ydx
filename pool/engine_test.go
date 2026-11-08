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

// TestEngineResizeUnderLoad submits continuously while the worker count
// oscillates, so every shard must still be drained exactly once by stealing.
// | TestEngineResizeUnderLoad 在 worker 数反复变化时持续提交，验证所有分片仍被窃取并
// 恰好执行一次。
func TestEngineResizeUnderLoad(t *testing.T) {
	const total = 40000
	cfg := testEngineConfig()
	cfg.workers = 2
	cfg.shards = 8
	cfg.queueSize = 4096
	cfg.fallbackSize = 4096
	cfg.spinCount = 0
	seen := make([]atomic.Bool, total)
	var duplicate atomic.Bool
	e := newEngine[int](cfg, func(w *workerState, v int) {
		if seen[v].Swap(true) {
			duplicate.Store(true)
		}
		w.count(1, 0, 0)
	}, func(int) {})
	defer e.close(false)

	stop := make(chan struct{})
	var resizeWG sync.WaitGroup
	resizeWG.Add(1)
	go func() {
		defer resizeWG.Done()
		n := 1
		for {
			select {
			case <-stop:
				if err := e.resize(8); err != nil {
					t.Errorf("final grow: %v | 最终扩容失败", err)
				}
				return
			default:
			}
			if err := e.resize(n); err != nil {
				t.Errorf("resize %d: %v | 调整 worker 数失败", n, err)
				return
			}
			if n == 1 {
				n = 8
			} else {
				n = 1
			}
			runtime.Gosched()
		}
	}()

	for i := 0; i < total; i++ {
		if err := e.submit(i); err != nil {
			t.Fatalf("submit %d: %v | 提交失败", i, err)
		}
	}
	e.wait()
	close(stop)
	resizeWG.Wait()

	if duplicate.Load() {
		t.Fatal("task ran more than once | 任务重复执行")
	}
	for i := range seen {
		if !seen[i].Load() {
			t.Fatalf("task %d missing | 任务丢失", i)
		}
	}
	st := e.stats()
	if st.Submitted != total || st.Completed != total {
		t.Fatalf("stats = %+v, want submitted/completed %d | 统计不符", st, total)
	}
}

// TestEngineCloseHandoffRace repeatedly closes while submitters are active and
// checks that every accepted job is either run or discarded and settles. |
// TestEngineCloseHandoffRace 反复在提交进行时关闭，检查每个已接受作业要么执行要么丢弃
// 且完成结算。
func TestEngineCloseHandoffRace(t *testing.T) {
	const rounds = 50
	for round := 0; round < rounds; round++ {
		cfg := testEngineConfig()
		cfg.workers = 2
		cfg.shards = 2
		cfg.queueSize = 4
		cfg.fallbackSize = 4
		cfg.spinCount = 0
		var ran, discarded atomic.Int64
		e := newEngine[int](cfg, func(w *workerState, v int) {
			ran.Add(1)
			w.count(1, 0, 0)
		}, func(int) { discarded.Add(1) })

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < 20; j++ {
					_ = e.submit(1)
				}
			}()
		}
		close(start)
		runtime.Gosched()
		done := make(chan struct{})
		go func() {
			e.close(false)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: close hung | 关闭挂起", round)
		}
		wg.Wait()

		st := e.stats()
		if got := uint64(ran.Load() + discarded.Load()); got != st.Submitted {
			t.Fatalf("round %d: ran+discarded = %d, submitted = %d | 统计不符", round, got, st.Submitted)
		}
		if st.Queued != 0 {
			t.Fatalf("round %d: queued = %d after close | 关闭后队列非空", round, st.Queued)
		}
	}
}

// TestEngineStatsFallbackRejected verifies fallback and rejection counters, and
// that a rejected submission rolls back its batch extra. | TestEngineStatsFallbackRejected
// 验证 fallback 与拒绝计数，并确认被拒绝的提交会回滚批量附加计数。
func TestEngineStatsFallbackRejected(t *testing.T) {
	cfg := testEngineConfig()
	cfg.workers = 1
	cfg.shards = 1
	cfg.queueSize = 2
	cfg.fallbackSize = 4
	cfg.spinCount = 0
	cfg.nonblocking = true
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	var once sync.Once
	e := newEngine[int](cfg, func(w *workerState, v int) {
		once.Do(func() {
			close(started)
			<-release
		})
		w.count(1, 0, 0)
	}, func(int) {})
	t.Cleanup(func() {
		releaseFn()
		e.close(false)
	})

	if err := e.submit(0); err != nil {
		t.Fatalf("submit blocker: %v | 提交阻塞任务失败", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker did not start | 阻塞任务未启动")
	}
	for i := 1; i <= 6; i++ {
		if err := e.submit(i); err != nil {
			t.Fatalf("submit %d: %v | 提交失败", i, err)
		}
	}
	if err := e.submit(7); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("submit full = %v, want ErrQueueFull | 满队列错误不符", err)
	}
	if err := e.submitExtra(8, 5); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("submitExtra full = %v, want ErrQueueFull | 满队列错误不符", err)
	}
	st := e.stats()
	if st.Submitted != 7 || st.Fallback != 4 || st.Rejected != 2 || st.Completed != 0 {
		t.Fatalf("stats while blocked = %+v | 阻塞期间统计不符", st)
	}

	releaseFn()
	e.wait()
	if st := e.stats(); st.Completed != 7 || st.Submitted != 7 || st.Fallback != 4 {
		t.Fatalf("final stats = %+v | 最终统计不符", st)
	}

	e.close(false)
	before := e.stats().Submitted
	if err := e.submitExtra(9, 3); !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("submitExtra closed = %v, want ErrPoolClosed | 关闭后错误不符", err)
	}
	if after := e.stats().Submitted; after != before {
		t.Fatalf("rejected closed submission changed submitted: %d -> %d | 关闭后拒绝改变了统计", before, after)
	}
}

// TestEngineStealOtherShard verifies that a worker whose home shard is empty can
// dequeue from another shard. | TestEngineStealOtherShard 验证 home 分片为空的 worker
// 可以从其它分片取走作业。
func TestEngineStealOtherShard(t *testing.T) {
	cfg := testEngineConfig()
	cfg.workers = 1
	cfg.shards = 4
	cfg.spinCount = 0
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	e := newEngine[int](cfg, func(w *workerState, v int) {
		if v == 0 {
			close(started)
			<-release
		}
		w.count(1, 0, 0)
	}, func(int) {})
	t.Cleanup(func() {
		releaseFn()
		e.close(false)
	})

	if err := e.submit(0); err != nil {
		t.Fatalf("submit blocker: %v | 提交阻塞任务失败", err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocker did not start | 阻塞任务未启动")
	}
	// The worker's home shard (0) is empty while it runs the blocker; the remote
	// job is in shard 2, so take cannot find it but steal can. | worker 正在执行阻塞
	// 任务时 home 分片 0 为空；远端作业在分片 2，take 找不到而 steal 可以。
	if !e.shards[2].tryEnqueue(42) {
		t.Fatal("enqueue remote job failed | 远端任务入队失败")
	}
	if v, ok := e.take(0); ok {
		t.Fatalf("take returned cross-shard job %d | take 返回了跨分片作业", v)
	}
	v, ok := e.steal(0)
	if !ok || v != 42 {
		t.Fatalf("steal = (%d, %v), want (42, true) | 工作窃取结果不符", v, ok)
	}
	releaseFn()
	e.wait()
}
