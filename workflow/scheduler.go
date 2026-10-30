package workflow

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shibingli/ydx/cron"
	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// Declared scheduler errors. | 已声明的调度器错误。
var (
	// ErrSchedulerTimeout reports a scheduler that did not stop in time. | ErrSchedulerTimeout 表示调度器未能及时停止。
	ErrSchedulerTimeout = errs.New("workflow scheduler stop timed out | 流程调度器停止超时")
	// ErrSchedulerDetach reports a scan job that could not be removed from a shared
	// cron scheduler. | ErrSchedulerDetach 表示无法从共享 cron 调度器移除扫描任务。
	ErrSchedulerDetach = errs.New("workflow scheduler detach failed | 流程调度器卸载任务失败")
)

// scanJobID names the default maintenance job registered with the cron scheduler. |
// scanJobID 命名默认注册到 cron 调度器的维护任务。
const scanJobID = "workflow-scan"

// SchedulerOption customizes a Scheduler. | SchedulerOption 定制 Scheduler。
type SchedulerOption func(*Scheduler)

// WithCronScheduler mounts the scan job on shared instead of a private cron
// scheduler. The caller owns shared: Start adds the job without starting shared,
// and Stop removes the job without stopping shared, so the application can run
// its own jobs on the same instance. shared must not persist definitions: a
// Store-backed Reload would drop the in-memory scan job. Cancelling the context
// passed to Start does not stop shared; call Stop explicitly. |
// WithCronScheduler 把扫描任务挂到 shared 而不是私有 cron 调度器。shared 由调用方拥有：
// Start 只添加任务而不启动 shared，Stop 只移除任务而不停止 shared，因此应用可以在同一实例上
// 运行自己的任务。shared 不得持久化定义：带 Store 的 Reload 会丢弃内存中的扫描任务。
// 取消传给 Start 的上下文不会停止 shared；请显式调用 Stop。
func WithCronScheduler(shared *cron.Scheduler) SchedulerOption {
	return func(s *Scheduler) { s.shared = shared }
}

// WithScanJobID overrides the scan job id. Use distinct ids when several
// workflow services share one cron scheduler. | WithScanJobID 覆盖扫描任务 ID。
// 多个流程服务共享一个 cron 调度器时使用不同的 ID。
func WithScanJobID(id string) SchedulerOption {
	return func(s *Scheduler) { s.jobID = id }
}

// Scheduler drives due reminders, notification retries and timer events. It is a thin
// lifecycle around ydx/cron: one fixed-interval job calls Service.RunDue and the cron
// scheduler owns the timer loop. It keeps no state that must be replicated: every scan
// re-reads the database, and every item is claimed by a conditional update, so any
// number of nodes may run it at once. | Scheduler 驱动到期催办、通知重试与定时事件。
// 它是 ydx/cron 之上的薄生命周期：单个固定间隔任务调用 Service.RunDue，由 cron 调度器拥有定时循环。
// 它不保存需要复制的状态：每次扫描都重新读库，每一项都经条件更新领取，因此任意数量的节点可以同时运行。
type Scheduler struct {
	// startErr is the outcome of the first Start. | startErr 是首次 Start 的结果。
	startErr error
	// service is the owning service. | service 是所属服务。
	service *Service
	// log records background failures. | log 记录后台失败。
	log *ydlog.Logger
	// scheduler owns the timer loop; it is shared or private. | scheduler 拥有定时循环；
	// 它可能是共享实例或私有实例。
	scheduler *cron.Scheduler
	// shared is the caller-owned cron scheduler, nil for a private one. |
	// shared 是调用方拥有的 cron 调度器；私有实例时为 nil。
	shared *cron.Scheduler
	// scanCancel stops an in-flight scan. | scanCancel 停止在途扫描。
	scanCancel context.CancelFunc
	// cancel stops the private scheduler's contexts. | cancel 停止私有调度器的上下文。
	cancel context.CancelFunc
	// jobID is the scan job id. | jobID 是扫描任务 ID。
	jobID string
	// interval is the scan period. | interval 是扫描周期。
	interval time.Duration
	// once guards Start. | once 保护 Start。
	once sync.Once
	// mu guards running, scheduler, scanCancel and cancel. | mu 保护 running、scheduler、
	// scanCancel 与 cancel。
	mu sync.Mutex
	// running reports whether the scheduler is alive. | running 报告调度器是否存活。
	running bool
}

// NewScheduler builds a scheduler; a non-positive interval uses the service
// default. Options may attach the scan job to an existing cron scheduler. |
// NewScheduler 构建调度器；非正周期使用服务默认值。选项可把扫描任务挂到既有 cron 调度器。
func NewScheduler(service *Service, interval time.Duration, logger *ydlog.Logger, opts ...SchedulerOption) *Scheduler {
	if service == nil {
		return nil
	}
	if interval <= 0 {
		interval = service.options.ScanInterval
	}
	if logger == nil {
		logger = ydlog.Default()
	}
	scheduler := &Scheduler{service: service, interval: interval, log: logger, jobID: scanJobID}
	for _, opt := range opts {
		if opt != nil {
			opt(scheduler)
		}
	}
	if scheduler.jobID == "" {
		scheduler.jobID = scanJobID
	}
	return scheduler
}

// Start launches the scan job. A private cron scheduler is started with it;
// WithCronScheduler only adds the job and leaves the shared scheduler's
// lifecycle to its owner. It is idempotent. | Start 启动扫描任务。私有 cron
// 调度器会随之一并启动；WithCronScheduler 只添加任务，共享调度器的生命周期由其所有者负责。
// 该方法幂等。
func (s *Scheduler) Start(ctx context.Context) error {
	if s == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.once.Do(func() {
		// The scan context is detached from the caller's cancellation so Stop owns the
		// graceful budget; the private scheduler's run context still follows ctx. |
		// 扫描上下文与调用方取消解耦，由 Stop 掌握优雅预算；私有调度器的运行上下文仍跟随 ctx。
		scanCtx, scanCancel := context.WithCancel(context.WithoutCancel(ctx))
		job := s.newScanJob(scanCtx)
		if shared := s.shared; shared != nil {
			if err := shared.Add(ctx, job); err != nil {
				scanCancel()
				s.startErr = err
				return
			}
			s.mu.Lock()
			s.scheduler = shared
			s.scanCancel = scanCancel
			s.running = true
			s.mu.Unlock()
			return
		}
		runCtx, cancel := context.WithCancel(ctx)
		scheduler := cron.New(cron.Options{
			Logger:       s.log,
			Namespace:    "workflow",
			Concurrency:  1,
			QueueSize:    1,
			HistoryLimit: -1,
		})
		if err := scheduler.Add(ctx, job); err != nil {
			cancel()
			scanCancel()
			s.startErr = err
			return
		}
		if err := scheduler.Start(runCtx); err != nil {
			cancel()
			scanCancel()
			s.startErr = err
			return
		}
		s.mu.Lock()
		s.scheduler = scheduler
		s.cancel = cancel
		s.scanCancel = scanCancel
		s.running = true
		s.mu.Unlock()
	})
	return s.startErr
}

// newScanJob builds the maintenance job. A shared scheduler also makes the job
// Singleton, so a configured Locker lets only one node scan per tick; the
// database claims remain the correctness boundary. | newScanJob 构建维护任务。
// 共享调度器还会把任务设为 Singleton，配置 Locker 后每个周期只有一个节点扫描；
// 正确性仍由数据库条件领取保证。
func (s *Scheduler) newScanJob(scanCtx context.Context) *cron.Job {
	return &cron.Job{
		ID:        s.jobID,
		Name:      "workflow scan | 流程扫描",
		Schedule:  cron.Interval(s.interval),
		Overlap:   cron.SkipIfRunning,
		Singleton: s.shared != nil,
		Handler: func(ctx context.Context, _ *cron.Job) error {
			runCtx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(scanCtx, cancel)
			defer stop()
			defer cancel()
			s.safeRun(runCtx)
			return nil
		},
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
		// Cancellation is the normal shutdown path, not a scan failure. |
		// 取消属于正常关闭路径，不是扫描失败。
		if errors.Is(err, context.Canceled) {
			return
		}
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

// Stop cancels the running scan and then either stops a private cron scheduler
// or removes the job from a shared one, waiting up to timeout. |
// Stop 取消运行中的扫描，然后停止私有 cron 调度器或从共享调度器移除任务，最多等待 timeout。
func (s *Scheduler) Stop(timeout time.Duration) error {
	if s == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	s.mu.Lock()
	running := s.running
	scheduler := s.scheduler
	shared := s.shared
	cancel := s.cancel
	scanCancel := s.scanCancel
	jobID := s.jobID
	s.mu.Unlock()
	if !running || scheduler == nil {
		return nil
	}
	// Cancel first so an in-flight RunDue observes shutdown immediately, matching the
	// previous ticker contract instead of waiting for the cron deadline. |
	// 先取消，使在途 RunDue 立即感知退出，保持原 ticker 契约而不是等 cron 截止。
	if scanCancel != nil {
		scanCancel()
	}
	ctx, stop := context.WithTimeout(context.Background(), timeout)
	defer stop()
	var err error
	if shared != nil {
		err = shared.Remove(ctx, jobID)
		// Another owner may have removed the job, or the shared scheduler may already
		// be closed; neither leaves a scan behind. | 任务可能已被其它持有者移除，或共享
		// 调度器已经关闭；这两种情况都不会留下扫描。
		if errors.Is(err, cron.ErrJobNotFound) || errors.Is(err, cron.ErrSchedulerClosed) {
			err = nil
		}
	} else {
		if cancel != nil {
			cancel()
		}
		err = scheduler.Stop(ctx)
	}

	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
	if err != nil {
		if shared != nil {
			return errs.Wrap(err, ErrSchedulerDetach)
		}
		return errs.Wrap(err, ErrSchedulerTimeout)
	}
	return nil
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
