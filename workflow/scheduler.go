package workflow

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// ErrSchedulerTimeout reports a scheduler that did not stop in time. | ErrSchedulerTimeout 表示调度器未能及时停止。
var ErrSchedulerTimeout = errs.New("workflow scheduler stop timed out | 流程调度器停止超时")

// Scheduler drives due reminders, notification retries and timer events. It keeps no state that
// must be replicated: every scan re-reads the database, and every item is claimed by a conditional
// update, so any number of nodes may run it at once. | Scheduler 驱动到期催办、通知重试与定时事件。
// 它不保存需要复制的状态：每次扫描都重新读库，每一项都经条件更新领取，因此任意数量的节点可以同时运行。
type Scheduler struct {
	// service is the owning service. | service 是所属服务。
	service *Service
	// log records background failures. | log 记录后台失败。
	log *ydlog.Logger
	// stop cancels the ticker. | stop 取消定时器。
	stop context.CancelFunc
	// done closes when the goroutine exits. | done 在协程退出时关闭。
	done chan struct{}
	// interval is the tick period. | interval 是扫描周期。
	interval time.Duration
	// once guards Start and Stop. | once 保护 Start 与 Stop。
	once sync.Once
	// mu guards running. | mu 保护 running。
	mu sync.Mutex
	// running reports whether the goroutine is alive. | running 报告协程是否存活。
	running bool
}

// NewScheduler builds a scheduler; a non-positive interval uses the service default. | NewScheduler
// 构建调度器；非正周期使用服务默认值。
func NewScheduler(service *Service, interval time.Duration, logger *ydlog.Logger) *Scheduler {
	if service == nil {
		return nil
	}
	if interval <= 0 {
		interval = service.options.ScanInterval
	}
	if logger == nil {
		logger = ydlog.Default()
	}
	return &Scheduler{service: service, interval: interval, log: logger, done: make(chan struct{})}
}

// Start launches the scan loop. It is idempotent. | Start 启动扫描循环，且幂等。
func (s *Scheduler) Start(ctx context.Context) error {
	if s == nil {
		return ErrUnavailable
	}
	started := false
	s.once.Do(func() {
		runCtx, cancel := context.WithCancel(ctx)
		s.stop = cancel
		s.mu.Lock()
		s.running = true
		s.mu.Unlock()
		started = true
		go s.loop(runCtx)
	})
	if !started {
		return nil
	}
	return nil
}

// loop runs until the context is cancelled. | loop 运行直到上下文被取消。
func (s *Scheduler) loop(ctx context.Context) {
	defer close(s.done)
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.log.Info("workflow scheduler stopped | 流程调度器已停止")
			return
		case <-ticker.C:
			s.safeRun(ctx)
		}
	}
}

// safeRun runs one scan and contains a background panic. | safeRun 执行一次扫描并收敛后台 panic。
func (s *Scheduler) safeRun(ctx context.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.log.Error("workflow scheduler recovered from a panic | 流程调度器从 panic 中恢复",
				ydlog.Str("panic", stringifyPanic(recovered)),
			)
		}
	}()
	report, err := s.service.RunDue(ctx, 0)
	if err != nil {
		s.log.Warn("workflow scheduler scan failed | 流程调度扫描失败", ydlog.Err(err))
		return
	}
	if report.Reminded > 0 || report.Notifications > 0 || report.Timers > 0 {
		s.log.Debug("workflow scheduler scan finished | 流程调度扫描完成",
			ydlog.Int("reminded", report.Reminded),
			ydlog.Int("notifications", report.Notifications),
			ydlog.Int("timers", report.Timers),
		)
	}
}

// RunOnce performs one scan immediately. | RunOnce 立即执行一次扫描。
func (s *Scheduler) RunOnce(ctx context.Context) (SchedulerReport, error) {
	if s == nil {
		return SchedulerReport{}, ErrUnavailable
	}
	return s.service.RunDue(ctx, 0)
}

// Stop cancels the loop and waits up to timeout for it to exit. | Stop 取消循环并最多等待 timeout。
func (s *Scheduler) Stop(timeout time.Duration) error {
	if s == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if !running || s.stop == nil {
		return nil
	}
	s.stop()
	select {
	case <-s.done:
		return nil
	case <-time.After(timeout):
		return ErrSchedulerTimeout
	}
}

// stringifyPanic renders a recovered panic value without importing fmt. | stringifyPanic 在不导入 fmt 的前提下渲染恢复的 panic 值。
func stringifyPanic(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case error:
		return v.Error()
	default:
		return "non-string panic | 非字符串 panic"
	}
}
