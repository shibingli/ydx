package gc

import (
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// Scheduler runs the periodic collection loop. | Scheduler 运行周期性回收循环。
//
// One Scheduler owns at most one goroutine; Start is idempotent and Stop waits for the
// goroutine to exit. All other methods are safe for concurrent use. | 一个 Scheduler 最多
// 拥有一个协程；Start 幂等，Stop 会等待协程退出。其余方法均可并发使用。
type Scheduler struct {
	// nextDue is when the next scheduled collection is due. | nextDue 是下次定时回收的到期时刻。
	nextDue time.Time
	// lastPanicLog rate-limits recovered panic reports. | lastPanicLog 限制已恢复 panic 的上报频率。
	lastPanicLog time.Time
	// logger receives lifecycle and collection records. | logger 接收生命周期与回收记录。
	logger *log.Logger
	// load probes process CPU utilisation. | load 探测进程 CPU 利用率。
	load *cpuProbe
	// heap reads heap gauges. | heap 读取堆指标。
	heap *heapReader
	// collect performs one runtime collection; tests replace it. | collect 执行一次运行时
	// 回收；测试会替换它。
	collect func(Mode, heapReading) heapReading
	// now reads the wall clock; tests replace it. | now 读取墙钟；测试会替换它。
	now func() time.Time
	// limit returns the effective memory ceiling; tests replace it. | limit 返回生效的内存
	// 上限；测试会替换它。
	limit func() uint64
	// wake interrupts a long wait when a manual run moves the next deadline. | wake 在手动
	// 回收移动下次期限时打断长等待。
	wake chan struct{}

	// cancel stops the loop. | cancel 停止循环。
	cancel context.CancelFunc
	// done closes after the loop exits. | done 在循环退出后关闭。
	done chan struct{}
	// opts is the normalised, immutable policy. | opts 是归一化后的不可变策略。
	opts Options
	// stats is the published counter set. | stats 是发布的计数集。
	stats Stats
	// interval is the current (possibly backed-off) interval. | interval 是当前（可能已退避的）间隔。
	interval time.Duration

	// runMu serialises scheduled and manual collections. | runMu 串行化定时与手动回收。
	runMu sync.Mutex

	// mu guards the lifecycle state, statistics and schedule. | mu 保护生命周期状态、统计与调度。
	mu sync.Mutex
	// running reports whether the loop goroutine is alive. | running 报告循环协程是否存活。
	running bool
	// loadAvailable reports whether a load gate can be evaluated at all. A statically
	// unavailable probe disables the load gate; a probe that fails at run time fails closed
	// instead. | loadAvailable 报告负载门是否可评估。静态不可用的探针会关闭负载门；运行期
	// 失败的探针则按失败关闭处理。
	loadAvailable bool
}

// New validates opts and builds a stopped Scheduler. It never starts a goroutine; call
// Start once the application is ready to serve. | New 校验 opts 并构建一个已停止的调度器。
// 它不会启动协程；应用准备好服务后再调用 Start。
func New(opts Options) (*Scheduler, error) {
	normalized, err := opts.normalize()
	if err != nil {
		return nil, err
	}

	s := &Scheduler{
		logger:   normalized.Logger,
		opts:     normalized,
		load:     newCPUProbe(),
		heap:     newHeapReader(),
		now:      time.Now,
		limit:    effectiveMemoryLimit,
		wake:     make(chan struct{}, 1),
		interval: normalized.Interval,
	}
	s.collect = s.collectRuntime
	s.loadAvailable = normalized.Load != nil || s.load.available()
	return s, nil
}

// Start launches the scheduling goroutine. It is a no-op when the scheduler is already
// running or when Options.Enabled is false. | Start 启动调度协程。调度器已在运行或
// Options.Enabled 为 false 时，它不做任何事。
func (s *Scheduler) Start() {
	if s == nil {
		return
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	if !s.opts.Enabled {
		s.mu.Unlock()
		s.logger.Debug("runtime gc scheduler disabled | 运行时 GC 调度器已关闭")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	now := s.now()
	s.running = true
	s.cancel = cancel
	s.done = done
	s.stats.Started = now
	s.interval = s.opts.Interval
	s.nextDue = now.Add(s.jitter(s.opts.Interval))
	s.stats.NextRun = s.nextDue
	s.stats.Interval = s.interval
	s.mu.Unlock()

	// Drain a wake left by a manual run before the scheduler started. | 清掉调度器启动前
	// 手动回收留下的唤醒信号。
	select {
	case <-s.wake:
	default:
	}

	s.logger.Info("runtime gc scheduler started | 运行时 GC 调度器已启动",
		log.Str("mode", string(s.opts.Mode)),
		log.Dur("interval", s.opts.Interval),
		log.Dur("quiet_window", s.opts.QuietWindow),
		log.Float64("load_threshold", s.opts.LoadThreshold),
		log.Uint64("min_heap", s.opts.MinHeap),
		log.Float64("pressure_ratio", s.opts.PressureRatio),
	)

	go func() {
		defer close(done)
		defer s.markStopped()
		s.loop(ctx)
	}()
}

// Stop cancels the loop and waits for the goroutine to exit. It is idempotent and safe
// before Start. A collection already in progress cannot be cancelled, so ctx bounds the
// wait; when it expires ErrStopTimeout is returned and the caller decides whether to keep
// waiting. | Stop 取消循环并等待协程退出。它幂等，且在 Start 之前调用也安全。已经开始的
// 回收无法取消，因此由 ctx 限定等待；到期时返回 ErrStopTimeout，由调用方决定是否继续等待。
func (s *Scheduler) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	running := s.running
	s.mu.Unlock()

	if cancel != nil && running {
		cancel()
	}
	if done == nil {
		return nil
	}

	select {
	case <-done:
		if running {
			s.logger.Info("runtime gc scheduler stopped | 运行时 GC 调度器已停止")
		}
		return nil
	case <-ctx.Done():
		return errs.Wrap(ctx.Err(), ErrStopTimeout)
	}
}

// Enabled reports whether background scheduling is configured. Manual runs work either
// way. | Enabled 报告是否配置了后台调度；无论如何手动执行都可使用。
func (s *Scheduler) Enabled() bool { return s != nil && s.opts.Enabled }

// Mode returns the configured collection mode. | Mode 返回配置的回收模式。
func (s *Scheduler) Mode() Mode {
	if s == nil {
		return ModeRelease
	}
	return s.opts.Mode
}

// Stats returns a consistent copy of the scheduler counters. It never blocks on a
// collection. | Stats 返回调度器计数的一致副本，且绝不会阻塞在回收上。
func (s *Scheduler) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// markStopped clears the lifecycle state when the loop exits. | markStopped 在循环退出时
// 清理生命周期状态。
func (s *Scheduler) markStopped() {
	s.mu.Lock()
	s.running = false
	s.cancel = nil
	s.mu.Unlock()
}

// sampleLoad reads the configured load source and normalises it. Unknown or non-finite
// values are reported as unknown rather than as a busy signal. | sampleLoad 读取配置的负载
// 来源并归一化。未知或非有限值按未知处理，而不是繁忙信号。
//
// A panicking Load callback is contained: the scheduler treats the sample as unknown and
// keeps running, because a background goroutine that panics would terminate the whole
// process. | 发生 panic 的 Load 回调会被收敛：调度器把它当作未知读数并继续运行，因为
// 后台协程里的 panic 会终止整个进程。
func (s *Scheduler) sampleLoad() (percent float64, known bool) {
	if s.opts.Load == nil {
		return s.load.sample()
	}

	defer func() {
		if rec := recover(); rec != nil {
			s.reportPanic("load", rec)
			percent, known = 0, false
		}
	}()

	value, ok := s.opts.Load()
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, false
	}
	if value > 100 {
		value = 100
	}
	return value, true
}

// busyGate evaluates the application-level Busy callback with panic containment. A panic
// fails closed: the process is treated as busy, so an unknown state can never trigger a
// disruptive collection during peak load. Memory pressure still forces one when needed. | busyGate
// 评估应用级 Busy 回调，并收敛其中的 panic。panic 按失败关闭处理：进程被视为繁忙，未知状态
// 因此绝不会在高峰触发干扰性回收；需要时内存压力仍会强制回收。
func (s *Scheduler) busyGate() (busy bool) {
	if s.opts.Busy == nil {
		return false
	}
	defer func() {
		if rec := recover(); rec != nil {
			s.reportPanic("busy", rec)
			busy = true
		}
	}()
	return s.opts.Busy()
}

// reportPanic records a recovered panic and reports it at most once per minute. A broken
// callback must neither kill the process nor flood the log on every sample. | reportPanic
// 记录一次已恢复的 panic，并最多每分钟上报一次。有缺陷的回调既不能杀死进程，也不能在每次
// 采样时刷爆日志。
func (s *Scheduler) reportPanic(where string, recovered any) {
	now := s.now()
	s.mu.Lock()
	s.stats.Errors++
	loud := s.lastPanicLog.IsZero() || now.Sub(s.lastPanicLog) >= time.Minute
	if loud {
		s.lastPanicLog = now
	}
	s.mu.Unlock()

	if loud {
		s.logger.Error("runtime gc recovered from a panic; the scheduler keeps running | 运行时 GC 已从 panic 恢复，调度器继续运行",
			log.Str("where", where),
			log.Any("panic", recovered),
		)
		return
	}
	s.logger.Debug("runtime gc recovered from another panic | 运行时 GC 又恢复了一次 panic",
		log.Str("where", where),
		log.Any("panic", recovered),
	)
}

// scheduleBackoff postpones the next cycle to MaxInterval after a recovered panic, so a
// permanently failing collection cannot turn into a hot retry loop. | scheduleBackoff 在
// 恢复 panic 后把下一轮推迟到 MaxInterval，避免永久失败的回收退化成热重试。
func (s *Scheduler) scheduleBackoff(from time.Time) {
	next := from.Add(s.opts.MaxInterval)
	s.mu.Lock()
	s.nextDue = next
	s.stats.NextRun = next
	s.mu.Unlock()
}

// jitter spreads a duration by ±Options.Jitter. | jitter 按 ±Options.Jitter 展开时长。
func (s *Scheduler) jitter(d time.Duration) time.Duration {
	if d <= 0 || s.opts.Jitter <= 0 {
		return d
	}
	factor := 1 + (rand.Float64()*2-1)*s.opts.Jitter
	out := time.Duration(float64(d) * factor)
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}
