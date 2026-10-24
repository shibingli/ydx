package gc

import (
	"context"
	"time"

	"github.com/shibingli/ydx/log"
)

// maxUnknownSamples is how many consecutive missing load measurements are tolerated before
// the busy gate fails closed: a probe that never reports a window must never make the
// scheduler collect during unknown load. | maxUnknownSamples 是繁忙门失败关闭之前容忍的连续
// 缺失负载读数次数：永远给不出窗口的探针绝不能让调度器在未知负载下回收。
const maxUnknownSamples = 3

// pressureRecheck caps the delay after a pressure-forced collection, so sustained memory
// pressure is re-sampled long before the next regular interval. | pressureRecheck 限制内存
// 压力强制回收后的等待时长，使持续的内存压力远早于下一个常规间隔就被重新采样。
const pressureRecheck = time.Minute

// action is the outcome of one gate evaluation. | action 是一次门判定的结果。
type action uint8

const (
	// actionWait keeps observing the load. | actionWait 继续观察负载。
	actionWait action = iota
	// actionCollect performs a collection now. | actionCollect 立即执行回收。
	actionCollect
	// actionHeapSkip skips this cycle because the heap is below the floor. | actionHeapSkip
	// 因为堆低于下限而跳过本轮。
	actionHeapSkip
)

// gateState carries the observation state across samples of one due cycle. | gateState
// 承载单次到期周期内跨采样的观察状态。
type gateState struct {
	// quietSince is when the process first fell below the threshold; zero means the
	// quiet window has not started. | quietSince 是进程首次低于阈值的时刻；零表示空闲
	// 窗口尚未开始。
	quietSince time.Time
	// unknownStreak counts consecutive samples with no measurement. | unknownStreak 统计
	// 连续没有读数的采样次数。
	unknownStreak int
	// deferred records that this cycle already counted a busy deferral. | deferred 记录本轮
	// 已计入一次繁忙推迟。
	deferred bool
	// busyLogged records that the busy transition has been logged. | busyLogged 记录繁忙
	// 转换已写日志。
	busyLogged bool
	// unknownWarned records that the degraded probe has been reported. | unknownWarned
	// 记录探针降级已上报。
	unknownWarned bool
	// unknownDegraded reports that the probe failed long enough to fail closed for the rest
	// of this cycle. | unknownDegraded 报告探针失败时间已足够长，本轮剩余时间按失败关闭处理。
	unknownDegraded bool
}

// decision is one gate verdict. | decision 是一次门判定结论。
type decision struct {
	// wait is how long to sleep before the next sample. | wait 是下次采样前的等待时长。
	wait time.Duration
	// action is the selected action. | action 是选定的动作。
	action action
	// busy reports whether the load gate is currently busy. | busy 报告负载门当前是否繁忙。
	busy bool
	// forced reports that memory pressure or MaxDefer overrode the busy gate. | forced
	// 报告内存压力或 MaxDefer 压过了繁忙门。
	forced bool
	// pressure reports that the forced collection came from memory pressure, which also
	// shortens the next recheck. | pressure 报告强制回收来自内存压力，它同时会缩短下次复查间隔。
	pressure bool
	// unknown reports that the sample had no measurement yet. | unknown 报告本次采样尚无读数。
	unknown bool
	// unknownExhausted reports that the probe failed closed for the rest of the cycle. | unknownExhausted
	// 报告探针在本轮剩余时间按失败关闭处理。
	unknownExhausted bool
}

// decide applies the policy gates in priority order: memory pressure, heap floor, load
// and quiet window. It is pure apart from the injected Busy, load and limit callbacks,
// which makes the gate behaviour directly testable without running the loop. | decide 按
// 优先级应用策略门：内存压力、堆下限、负载与空闲窗口。除注入的 Busy、负载与上限回调外，
// 它是纯函数，因此无需运行循环即可直接测试门行为。
func (s *Scheduler) decide(now, due time.Time, st *gateState, load float64, loadKnown bool, hp heapReading) decision {
	// 1) Memory pressure overrides every other gate, so an unattended process cannot grow
	//    without bound. | 内存压力压过其余所有门，使无人值守的进程不会无限增长。
	if hp.ok && s.opts.PressureRatio > 0 {
		if limit := s.limit(); limit > 0 && hp.mapped >= uint64(float64(limit)*s.opts.PressureRatio) {
			return decision{action: actionCollect, forced: true, pressure: true}
		}
	}

	// 2) A small heap has nothing worth collecting. | 小堆没有值得回收的东西。
	if hp.ok && s.opts.MinHeap > 0 && hp.heapObjects < s.opts.MinHeap {
		return decision{action: actionHeapSkip}
	}

	// 3) Load gate: the application gate comes first, then the sampled percentage. A
	//    statically unavailable probe disables only the sampled part; a probe that fails at
	//    run time fails closed (busy) so unknown state never triggers a peak-time collection.
	// | 负载门：先看应用级硬门，再看采样的百分比。静态不可用的探针只关闭采样部分；
	// 运行期失败的探针按失败关闭（繁忙）处理，使未知状态绝不会在高峰触发回收。
	busy := s.busyGate()
	if s.opts.LoadThreshold > 0 && s.loadAvailable {
		switch {
		case loadKnown:
			st.unknownStreak = 0
			st.unknownDegraded = false
			busy = busy || load >= s.opts.LoadThreshold
		case !st.unknownDegraded:
			st.unknownStreak++
			if st.unknownStreak <= maxUnknownSamples {
				return decision{action: actionWait, wait: s.opts.SampleInterval, unknown: true}
			}
			st.unknownDegraded = true
			return decision{action: actionWait, wait: s.opts.SampleInterval, busy: true, unknownExhausted: true}
		default:
			busy = true
		}
	}

	if busy {
		st.quietSince = time.Time{}
		if s.opts.MaxDefer > 0 && now.Sub(due) >= s.opts.MaxDefer {
			return decision{action: actionCollect, forced: true, busy: true}
		}
		return decision{action: actionWait, wait: s.opts.SampleInterval, busy: true}
	}

	// 4) Quiet window: collect only after the process stayed idle long enough. | 空闲窗口：
	// 只有进程持续空闲足够久才回收。
	if st.quietSince.IsZero() {
		st.quietSince = now
	}
	if elapsed := now.Sub(st.quietSince); elapsed >= s.opts.QuietWindow {
		return decision{action: actionCollect}
	}
	wait := s.opts.QuietWindow - now.Sub(st.quietSince)
	if wait <= 0 || wait > s.opts.SampleInterval {
		wait = s.opts.SampleInterval
	}
	return decision{action: actionWait, wait: wait}
}

// loop waits for each deadline and runs the gate cycle. A panic anywhere in the cycle is
// contained: the scheduler logs it, backs off to MaxInterval and keeps serving. | loop 等待
// 每个期限并执行门循环。周期内任何位置的 panic 都会被收敛：调度器记录日志、退避到
// MaxInterval 并继续工作。
func (s *Scheduler) loop(ctx context.Context) {
	for {
		if !s.safeCycle(ctx) {
			return
		}
	}
}

// safeCycle runs one wait-and-collect iteration under a recover guard. | safeCycle 在 recover
// 保护下执行一轮等待与回收。
func (s *Scheduler) safeCycle(ctx context.Context) (cont bool) {
	defer func() {
		if rec := recover(); rec != nil {
			s.reportPanic("cycle", rec)
			s.scheduleBackoff(s.now())
			cont = ctx.Err() == nil
		}
	}()

	due, ok := s.waitForDue(ctx)
	if !ok {
		return false
	}
	return s.runDue(ctx, due)
}

// waitForDue blocks until the next deadline or a manual run moves it. | waitForDue 阻塞到
// 下次期限，或手动回收移动期限为止。
func (s *Scheduler) waitForDue(ctx context.Context) (time.Time, bool) {
	for {
		due := s.currentDue()
		wait := due.Sub(s.now())
		if wait <= 0 {
			return due, ctx.Err() == nil
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return time.Time{}, false
		case <-s.wake:
			timer.Stop()
		case <-timer.C:
			return due, true
		}
	}
}

// runDue observes one due cycle until it collects, skips or the context is cancelled. | runDue
// 观察一次到期周期，直到回收、跳过或上下文被取消。
func (s *Scheduler) runDue(ctx context.Context, due time.Time) bool {
	st := gateState{}
	for {
		if ctx.Err() != nil {
			return false
		}
		// A manual run may have moved the deadline while this cycle was waiting; hand
		// control back to the loop instead of collecting twice in a row. | 手动回收可能在本轮
		// 等待期间移动了期限；此时把控制权交回循环，避免连续回收两次。
		if s.currentDue().After(due) {
			return true
		}

		now := s.now()
		hp := s.heap.read()
		load, known := s.sampleLoad()
		d := s.decide(now, due, &st, load, known, hp)

		switch d.action {
		case actionCollect:
			s.execute(d.forced, hp)
			s.scheduleNext(s.now(), d.pressure)
			return true
		case actionHeapSkip:
			s.recordHeapSkip()
			s.scheduleNext(now, false)
			return true
		default:
			if d.busy && !st.deferred {
				st.deferred = true
				s.recordDeferred()
			}
			if d.busy && !st.busyLogged {
				st.busyLogged = true
				s.logger.Debug("runtime gc deferred while busy | 运行时 GC 因繁忙推迟",
					log.Float64("load", load),
					log.Bool("load_known", known),
					log.Dur("deferred_for", now.Sub(due)),
				)
			}
			if d.unknownExhausted && !st.unknownWarned {
				st.unknownWarned = true
				s.logger.Warn("runtime gc load probe produced no measurement; failing closed for this cycle | 运行时 GC 负载探针没有读数，本轮按失败关闭处理")
			}
			if !sleepCtx(ctx, d.wait) {
				return false
			}
		}
	}
}

// currentDue returns the next scheduled deadline. | currentDue 返回下次调度期限。
func (s *Scheduler) currentDue() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextDue
}

// scheduleNext moves the deadline from a given instant using the current interval and
// jitter. A pressure-forced cycle rechecks sooner (capped at pressureRecheck). | scheduleNext
// 从指定时刻依据当前间隔与抖动移动下次期限。内存压力强制的一轮会更早复查（上限为
// pressureRecheck）。
func (s *Scheduler) scheduleNext(from time.Time, pressure bool) {
	s.mu.Lock()
	interval := s.interval
	if interval <= 0 {
		interval = s.opts.Interval
	}
	s.mu.Unlock()

	delay := interval
	if pressure {
		delay = min(delay, pressureRecheck)
		if delay < s.opts.SampleInterval {
			delay = s.opts.SampleInterval
		}
	}
	next := from.Add(s.jitter(delay))
	s.mu.Lock()
	s.nextDue = next
	s.stats.NextRun = next
	s.stats.Interval = interval
	s.mu.Unlock()
}

// sleepCtx waits for d or until ctx is cancelled, reporting whether the wait completed. | sleepCtx
// 等待 d 或被 ctx 取消，并报告等待是否完成。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
