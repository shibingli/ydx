package gc

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCollector records and optionally delays collections. | fakeCollector 记录并可选延迟回收。
type fakeCollector struct {
	// startCh is closed when the first collection starts. | startCh 在第一次回收开始时关闭。
	startCh chan struct{}
	// once guards startCh. | once 保护 startCh。
	once sync.Once
	// delay is how long each collection blocks. | delay 是每次回收阻塞的时长。
	delay time.Duration
	// starts counts collection invocations. | starts 统计回收调用次数。
	starts atomic.Int64
	// reclaim controls how much of the heap the fake collection frees; zero frees nothing. | reclaim
	// 控制模拟回收释放的堆比例；零表示不释放。
	reclaim uint64
}

// collect implements the collector signature. | collect 实现回收器签名。
func (f *fakeCollector) collect(_ Mode, before heapReading) heapReading {
	f.starts.Add(1)
	if f.startCh != nil {
		f.once.Do(func() { close(f.startCh) })
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	after := before
	after.gcCycles = before.gcCycles + 1
	if f.reclaim > 0 {
		after.heapObjects = before.heapObjects - before.heapObjects*f.reclaim/100
	}
	return after
}

// fakeHeap returns a reader with a fixed, valid snapshot. | fakeHeap 返回固定有效快照的读取器。
func fakeHeap(objects, mapped uint64) *heapReader {
	return &heapReader{readRaw: func() heapReading {
		return heapReading{heapObjects: objects, mapped: mapped, gcCycles: 1, ok: true}
	}}
}

// fastOptions returns a scheduler that fires almost immediately. | fastOptions 返回几乎立即
// 触发的调度器选项。
func fastOptions() Options {
	return Options{
		Enabled:        true,
		Interval:       10 * time.Millisecond,
		MaxInterval:    time.Second,
		SampleInterval: 2 * time.Millisecond,
		QuietWindow:    0,
		LoadThreshold:  0,
		PressureRatio:  0,
		Jitter:         0,
		Logger:         discardLogger(),
	}
}

// newFakeScheduler builds a scheduler whose heap and collector are deterministic. | newFakeScheduler
// 构建堆与回收器均确定性的调度器。
func newFakeScheduler(t *testing.T, o Options, collector *fakeCollector, objects, mapped uint64) *Scheduler {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v | 构造调度器失败", err)
	}
	s.heap = fakeHeap(objects, mapped)
	s.collect = collector.collect
	return s
}

// waitFor polls cond until it holds or the timeout expires. | waitFor 轮询 cond，直到成立或超时。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not met before the timeout | 条件未在超时前成立")
}

func TestSchedulerCollectsAndStops(t *testing.T) {
	c := &fakeCollector{}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)
	s.Start()

	waitFor(t, 3*time.Second, func() bool { return s.Stats().Runs >= 1 })
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v | 停止失败", err)
	}

	after := c.starts.Load()
	time.Sleep(50 * time.Millisecond)
	if got := c.starts.Load(); got != after {
		t.Fatalf("collections continued after Stop: %d -> %d | Stop 之后仍在回收", after, got)
	}
	if s.Stats().Last.Manual {
		t.Fatal("a scheduled collection must not be marked manual | 定时回收不应标记为手动")
	}
}

func TestSchedulerDisabled(t *testing.T) {
	c := &fakeCollector{}
	o := fastOptions()
	o.Enabled = false
	s := newFakeScheduler(t, o, c, 64<<20, 64<<20)

	s.Start()
	time.Sleep(50 * time.Millisecond)
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.starts.Load() != 0 {
		t.Fatal("a disabled scheduler must not collect | 关闭的调度器不得回收")
	}
}

func TestRunOnceBypassesGates(t *testing.T) {
	c := &fakeCollector{reclaim: 50}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)

	res, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Manual || res.HeapBefore != 64<<20 || res.Reclaimed != 32<<20 {
		t.Fatalf("result = %+v | 手动回收结果不符", res)
	}
	if s.Stats().Runs != 1 || !s.Stats().Last.Manual {
		t.Fatalf("stats = %+v | 手动回收必须计入统计", s.Stats())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled RunOnce error = %v, want context.Canceled | 已取消的上下文应直接返回", err)
	}
}

func TestRunOnceConcurrent(t *testing.T) {
	c := &fakeCollector{delay: time.Millisecond}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RunOnce(context.Background()); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := s.Stats().Runs; got != workers {
		t.Fatalf("runs = %d, want %d | 并发手动回收必须全部串行计入", got, workers)
	}
}

func TestStopTimeoutThenCompletes(t *testing.T) {
	c := &fakeCollector{startCh: make(chan struct{}), delay: 100 * time.Millisecond}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)
	s.Start()

	select {
	case <-c.startCh:
	case <-time.After(3 * time.Second):
		t.Fatal("collection did not start | 回收未开始")
	}

	short, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := s.Stop(short); !errors.Is(err, ErrStopTimeout) {
		t.Fatalf("short Stop error = %v, want ErrStopTimeout | 短超时应返回 ErrStopTimeout", err)
	}

	long, cancelLong := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelLong()
	if err := s.Stop(long); err != nil {
		t.Fatalf("second Stop: %v | 继续等待后应成功停止", err)
	}
}

func TestAdaptiveBackoffAndReset(t *testing.T) {
	c := &fakeCollector{}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)
	s.opts.Interval = 10 * time.Millisecond
	s.opts.MaxInterval = 100 * time.Millisecond
	s.opts.Adaptive = true
	s.interval = 10 * time.Millisecond

	for _, want := range []time.Duration{20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond, 100 * time.Millisecond} {
		if _, err := s.RunOnce(context.Background()); err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if got := s.Stats().Interval; got != want {
			t.Fatalf("interval = %v, want %v | 自适应退避不符", got, want)
		}
	}

	c.reclaim = 50
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := s.Stats().Interval; got != s.opts.Interval {
		t.Fatalf("interval after reclaim = %v, want %v | 有效回收后应重置间隔", got, s.opts.Interval)
	}
}

func TestPressureForcesCollectionWhileBusy(t *testing.T) {
	c := &fakeCollector{}
	o := fastOptions()
	o.Interval = 5 * time.Millisecond
	o.LoadThreshold = 10
	o.QuietWindow = 30 * time.Second
	o.PressureRatio = 0.8
	o.Busy = func() bool { return true }
	s := newFakeScheduler(t, o, c, 64<<20, 900)
	s.limit = func() uint64 { return 1000 }

	s.Start()
	waitFor(t, 3*time.Second, func() bool { return s.Stats().Forced >= 1 })
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if c.starts.Load() == 0 {
		t.Fatal("memory pressure must force a collection | 内存压力必须强制回收")
	}
}

func TestBusyDefersThenResumes(t *testing.T) {
	c := &fakeCollector{}
	var busy atomic.Bool
	busy.Store(true)

	o := fastOptions()
	o.Interval = 5 * time.Millisecond
	o.SampleInterval = 2 * time.Millisecond
	o.Busy = busy.Load
	s := newFakeScheduler(t, o, c, 64<<20, 64<<20)

	s.Start()
	time.Sleep(80 * time.Millisecond)
	if c.starts.Load() != 0 {
		t.Fatal("a busy process must not be collected | 繁忙进程不得回收")
	}
	if s.Stats().Deferred == 0 {
		t.Fatal("the deferral must be counted | 繁忙推迟必须计数")
	}

	busy.Store(false)
	waitFor(t, 3*time.Second, func() bool { return c.starts.Load() >= 1 })
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestRunDueAbortsWhenDeadlineMoved(t *testing.T) {
	c := &fakeCollector{}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)
	s.mu.Lock()
	s.nextDue = s.now().Add(time.Minute)
	s.mu.Unlock()

	if !s.runDue(context.Background(), s.now().Add(-time.Second)) {
		t.Fatal("runDue must hand control back to the loop | runDue 应把控制权交回循环")
	}
	if c.starts.Load() != 0 {
		t.Fatal("a moved deadline must cancel the duplicate collection | 期限被移动后不得重复回收")
	}
}

func TestStopBeforeStart(t *testing.T) {
	s := newFakeScheduler(t, fastOptions(), &fakeCollector{}, 64<<20, 64<<20)
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop before Start: %v | 启动前停止应成功", err)
	}
	s.Start()
	s.Start()
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop after duplicate Start: %v | 重复启动后停止应成功", err)
	}
}
