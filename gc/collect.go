package gc

import (
	"context"
	"runtime"
	"runtime/debug"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// minReclaimRatio is the reclaimed-to-heap ratio below which an adaptive scheduler
// doubles its interval: the heap is almost entirely live, so collecting it again soon
// would only burn CPU. | minReclaimRatio 是触发自适应调度器把间隔翻倍的「回收量/堆」比例
// 下限：堆几乎全是存活对象时，很快再收一次只会白烧 CPU。
const minReclaimRatio = 0.05

// collectRuntime performs one runtime collection and returns the post-collection heap
// snapshot. | collectRuntime 执行一次运行时回收，并返回回收后的堆快照。
func (s *Scheduler) collectRuntime(mode Mode, _ heapReading) heapReading {
	switch mode {
	case ModeSoft:
		runtime.GC()
	case ModeRelease:
		debug.FreeOSMemory()
	default:
		debug.FreeOSMemory()
	}
	return s.heap.read()
}

// RunOnce performs one collection immediately, bypassing the load, quiet-window and heap
// gates. It is the operator escape hatch and is safe to call while the scheduler runs;
// the two paths are serialised, and a running scheduler is woken so the manual run also
// moves its next deadline. A panic in the collection path is recovered and returned as
// ErrPanic instead of tearing down the caller. | RunOnce 立即执行一次回收，绕过负载、
// 空闲窗口与堆下限门。它是运维逃生口；在调度器运行时调用也安全：两条路径串行执行，运行中
// 的调度器会被唤醒，因此手动回收同样会移动下次期限。回收路径中的 panic 会被恢复并以
// ErrPanic 返回，而不是拖垮调用方。
func (s *Scheduler) RunOnce(ctx context.Context) (res Result, err error) {
	if s == nil {
		return Result{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	s.runMu.Lock()
	defer s.runMu.Unlock()
	// The recover is registered after the unlock defer, so it runs first and the lock is
	// always released. | recover 在解锁 defer 之后注册，因此它先执行，锁一定会被释放。
	defer func() {
		if rec := recover(); rec != nil {
			s.reportPanic("manual", rec)
			res = Result{}
			err = errs.Detail(ErrPanic, "recovered=%v | 已恢复=%v", rec, rec)
		}
	}()

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	res = s.collectOnce(s.heap.read(), false, true)
	s.recordRun(res)
	s.scheduleNext(res.Finished, false)
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return res, nil
}

// execute runs a scheduled collection; forced reports that a policy gate overrode the
// busy/quiet conditions. | execute 执行一次定时回收；forced 报告某个策略门压过了繁忙/空闲条件。
func (s *Scheduler) execute(forced bool, before heapReading) Result {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	res := s.collectOnce(before, forced, false)
	s.recordRun(res)
	return res
}

// collectOnce performs the runtime action and derives the result. It runs with runMu held,
// so a scheduled and a manual collection can never overlap. | collectOnce 执行运行时动作并
// 推导结果。它在持有 runMu 时运行，因此定时与手动回收不会重叠。
func (s *Scheduler) collectOnce(before heapReading, forced, manual bool) Result {
	start := s.now()
	after := s.collect(s.opts.Mode, before)
	finish := s.now()

	res := Result{
		Mode:         s.opts.Mode,
		Started:      start,
		Finished:     finish,
		Duration:     finish.Sub(start),
		HeapBefore:   before.heapObjects,
		HeapAfter:    after.heapObjects,
		MappedBefore: before.mapped,
		MappedAfter:  after.mapped,
		Reclaimed:    subtractFloor(before.heapObjects, after.heapObjects),
		Released:     subtractFloor(after.released, before.released),
		GCCycles:     subtractFloor(after.gcCycles, before.gcCycles),
		Forced:       forced,
		Manual:       manual,
	}

	s.logger.Info("runtime gc completed | 运行时 GC 已完成",
		log.Str("mode", string(res.Mode)),
		log.Uint64("heap_before", res.HeapBefore),
		log.Uint64("heap_after", res.HeapAfter),
		log.Uint64("reclaimed", res.Reclaimed),
		log.Uint64("released", res.Released),
		log.Uint64("gc_cycles", res.GCCycles),
		log.Dur("duration", res.Duration),
		log.Bool("forced", res.Forced),
		log.Bool("manual", res.Manual),
	)
	return res
}

// recordRun updates the statistics and the adaptive interval. | recordRun 更新统计与自适应间隔。
func (s *Scheduler) recordRun(res Result) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.Runs++
	s.stats.LastRun = res.Finished
	s.stats.Last = res
	if res.Forced {
		s.stats.Forced++
	}

	if s.opts.Adaptive {
		switch {
		case res.Forced || res.HeapBefore == 0:
			s.interval = s.opts.Interval
		case float64(res.Reclaimed) >= float64(res.HeapBefore)*minReclaimRatio:
			s.interval = s.opts.Interval
		case s.interval <= s.opts.MaxInterval/2:
			s.interval *= 2
		default:
			s.interval = s.opts.MaxInterval
		}
	}
	s.stats.Interval = s.interval
}

// recordHeapSkip counts one cycle skipped by the heap floor. | recordHeapSkip 统计一次因堆
// 下限被跳过的周期。
func (s *Scheduler) recordHeapSkip() {
	s.mu.Lock()
	s.stats.SkippedHeap++
	s.mu.Unlock()
}

// recordDeferred counts one due cycle that observed a busy process. | recordDeferred 统计一次
// 观察到繁忙进程的到期周期。
func (s *Scheduler) recordDeferred() {
	s.mu.Lock()
	s.stats.Deferred++
	s.mu.Unlock()
}

// subtractFloor returns a-b, or zero when b is not smaller than a. | subtractFloor 返回 a-b；
// b 不小于 a 时返回零。
func subtractFloor(a, b uint64) uint64 {
	if b >= a {
		return 0
	}
	return a - b
}
