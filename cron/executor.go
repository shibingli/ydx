package cron

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// runTask is one accepted run travelling from the event loop to a worker. |
// runTask 是从事件循环送往工作协程的一次已接受运行。
type runTask struct {
	// scheduled is the planned activation, used as the distributed lock key. |
	// scheduled 是计划触发时刻，用作分布式锁键。
	scheduled time.Time
	// entry owns the per-job running guard and statistics. | entry 拥有任务级运行守卫与统计。
	entry *entry
	// job is the immutable definition at dispatch time. | job 是派发时刻的不可变定义。
	job *Job
	// trigger records why the run happened. | trigger 记录运行原因。
	trigger Trigger
}

// executor owns a bounded run queue and a fixed worker pool. |
// executor 拥有有界运行队列与固定工作池。
type executor struct {
	scheduler *Scheduler
	// queue carries runTask values, so the common enqueue path allocates nothing
	// beyond the preallocated channel buffer. | queue 传递 runTask 值，使常见入队路径
	// 除预分配通道缓冲外不产生分配。
	queue     chan runTask
	quit      chan struct{}
	workCtx   context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	accepting atomic.Bool
	closeOnce sync.Once
	workers   int
}

// newExecutor builds a stopped executor; start launches the workers. |
// newExecutor 构建未启动的执行器；start 启动工作协程。
func newExecutor(scheduler *Scheduler, workers, queueSize int, parent context.Context) *executor {
	workCtx, cancel := context.WithCancel(parent)
	return &executor{
		scheduler: scheduler,
		queue:     make(chan runTask, queueSize),
		quit:      make(chan struct{}),
		workCtx:   workCtx,
		cancel:    cancel,
		workers:   workers,
	}
}

// start launches the workers. | start 启动工作协程。
func (e *executor) start() {
	e.accepting.Store(true)
	e.wg.Add(e.workers)
	for index := 0; index < e.workers; index++ {
		go e.worker()
	}
}

// worker drains the queue until quit closes, then drains what is already
// buffered before exiting. | worker 消费队列直到 quit 关闭，随后清空已缓冲任务再退出。
func (e *executor) worker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.quit:
			for {
				select {
				case task := <-e.queue:
					e.scheduler.execute(e.workCtx, task)
				default:
					return
				}
			}
		case task := <-e.queue:
			e.scheduler.execute(e.workCtx, task)
		}
	}
}

// queued reports the current queue depth. | queued 返回当前队列深度。
func (e *executor) queued() int { return len(e.queue) }

// stop stops accepting runs, asks workers to drain, and waits until the deadline.
// When the deadline passes it cancels in-flight handlers and reports
// ErrShutdownTimeout after giving them the same budget to observe cancellation. |
// stop 停止接受运行，要求工作协程清空队列并等待截止时间；超时后取消在途处理器，
// 再给同样的预算让其响应取消，最后返回 ErrShutdownTimeout。
func (e *executor) stop(ctx context.Context, grace time.Duration) error {
	e.accepting.Store(false)
	e.closeOnce.Do(func() { close(e.quit) })

	deadline := time.Now().Add(grace)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	wait := time.Until(deadline)
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
		e.cancel()
		return nil
	case <-timer.C:
		e.cancel()
		forced := time.NewTimer(grace)
		defer forced.Stop()
		select {
		case <-done:
		case <-forced.C:
		}
		return ErrShutdownTimeout
	}
}

// dispatch hands one due fire to the executor, applying jitter when configured. |
// dispatch 把一次到期触发交给执行器，必要时应用抖动。
func (s *Scheduler) dispatch(fire *dueFire) {
	task := runTask{entry: fire.entry, job: fire.job, trigger: TriggerScheduled, scheduled: fire.at}
	jitter := fire.job.Jitter
	if jitter > 0 {
		if fire.job.Singleton && s.options.Locker != nil && jitter >= s.options.LockTTL {
			jitter = s.options.LockTTL / 2
		}
		if jitter > 0 {
			delay := rand.N(jitter)
			time.AfterFunc(delay, func() { _ = s.enqueue(task) })
			return
		}
	}
	_ = s.enqueue(task)
}

// enqueue applies the overlap policy and puts a task on the worker queue. |
// enqueue 应用并发策略并把任务放入工作队列。
func (s *Scheduler) enqueue(task runTask) error {
	if task.entry == nil || task.job == nil {
		return ErrJobNotFound
	}
	if task.entry.removed.Load() {
		return errs.Detail(ErrJobNotFound, "%q", task.job.ID)
	}
	s.mu.RLock()
	workers := s.exec
	s.mu.RUnlock()

	if workers == nil || !workers.accepting.Load() {
		return ErrSchedulerNotRunning
	}

	item := task.entry
	single := task.job.Overlap.normalize() == SkipIfRunning
	if single {
		if !item.running.CompareAndSwap(0, 1) {
			item.stats.skipped.Add(1)
			s.hookSkipped(task.job, SkipOverlap)
			if task.trigger == TriggerManual {
				return ErrJobRunning
			}
			return nil
		}
	} else {
		item.running.Add(1)
	}

	select {
	case workers.queue <- task:
		return nil
	default:
		s.releaseRunning(item, single)
		item.stats.dropped.Add(1)
		s.hookSkipped(task.job, SkipQueueFull)
		if task.trigger == TriggerManual {
			return ErrQueueFull
		}
		return nil
	}
}

// releaseRunning clears the per-job guard or decrements the overlap counter. |
// releaseRunning 清除任务守卫或递减并发计数。
func (s *Scheduler) releaseRunning(item *entry, single bool) {
	if single {
		item.running.Store(0)
		return
	}
	item.running.Add(-1)
}

// hookSkipped reports a dropped fire without touching scheduler locks. |
// hookSkipped 在不持有调度器锁的情况下报告被丢弃的触发。
func (s *Scheduler) hookSkipped(job *Job, reason string) {
	if hook := s.options.Hooks.Skipped; hook != nil {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					s.log.Error("cron: Skipped hook panicked | Skipped Hook 发生 panic",
						ydlog.Str("job_id", job.ID),
						ydlog.Str("task", job.Task),
						ydlog.Any("panic", recovered),
						ydlog.Str("stack", string(debug.Stack())),
					)
				}
			}()
			hook(context.Background(), job, reason)
		}()
	}
	if s.log.Enabled(ydlog.DebugLevel) {
		s.log.Debug("cron: run skipped | 运行已跳过",
			ydlog.Str("job_id", job.ID),
			ydlog.Str("task", job.Task),
			ydlog.Str("reason", reason),
		)
	}
}

// execute runs one task to completion: it claims the distributed lock, runs the
// handler attempts with retries and timeout, and records the outcome. |
// execute 执行一个任务直至结束：抢占分布式锁，按超时与重试运行处理器，并记录结果。
func (s *Scheduler) execute(baseCtx context.Context, task runTask) {
	item, job := task.entry, task.job
	single := job.Overlap.normalize() == SkipIfRunning
	defer s.releaseRunning(item, single)

	started := s.now()
	ctx := s.beforeRun(baseCtx, job)
	// A manual or scheduled fire only needs its own cancelable context when a
	// distributed lock can be lost; otherwise the base context already carries
	// shutdown cancellation and this saves one allocation per run. |
	// 只有可能丢失分布式锁时才需要独立的可取消上下文；否则基础上下文已承载关闭取消，
	// 每次运行可省一次分配。
	fireCtx := ctx
	fireCancel := func() {}
	if job.Singleton && s.options.Locker != nil {
		var cancel context.CancelFunc
		fireCtx, cancel = context.WithCancel(ctx)
		fireCancel = cancel
	}
	defer fireCancel()

	if job.Singleton && s.options.Locker != nil {
		lock, acquired, err := s.claim(fireCtx, job, task.scheduled, task.trigger == TriggerManual)
		if err != nil {
			s.finish(item, job, task.trigger, started, 0, err, false)
			return
		}
		if !acquired {
			item.stats.skipped.Add(1)
			s.hookSkipped(job, SkipLocked)
			return
		}
		// A scheduled claim is deliberately not released at completion: its TTL
		// is the deduplication window, so a node that wakes late cannot run the
		// same fire again. A manual trigger uses a unique key and releases it. |
		// 计划触发的锁刻意不在完成时释放：TTL 就是去重窗口，晚醒的节点无法重复执行同一次触发。
		// 手动触发使用唯一键，运行结束后立即释放。
		if task.trigger == TriggerManual {
			defer s.unlock(lock)
		}
		stopRefresh := s.refreshLock(fireCtx, fireCancel, lock, job)
		defer stopRefresh()
	}

	attempts := 0
	maxAttempts := job.Retries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	retryDelay := job.RetryDelay
	if retryDelay <= 0 {
		retryDelay = time.Second
	}
	maxDelay := job.MaxRetryDelay
	if maxDelay <= 0 {
		maxDelay = time.Minute
	}
	backoff := normalizeBackoff(job.RetryBackoff)

	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attempts = attempt
		if attempt > 1 {
			if !sleepCtx(fireCtx, retryDelay) {
				err = fireCtx.Err()
				break
			}
			nextDelay := time.Duration(float64(retryDelay) * backoff)
			if nextDelay <= 0 || nextDelay > maxDelay {
				nextDelay = maxDelay
			}
			retryDelay = nextDelay
		}
		err = s.invoke(fireCtx, job)
		if err == nil {
			break
		}
		if attempt < maxAttempts {
			s.log.Warn("cron: job attempt failed, retrying | 任务尝试失败，准备重试",
				ydlog.Str("job_id", job.ID),
				ydlog.Str("task", job.Task),
				ydlog.Int("attempt", attempt),
				ydlog.Dur("retry_in", retryDelay),
				ydlog.Err(err),
			)
		}
	}
	s.finish(item, job, task.trigger, started, attempts, err, true)
}

// invoke runs one attempt with the job timeout. | invoke 按任务超时执行一次尝试。
func (s *Scheduler) invoke(parent context.Context, job *Job) error {
	ctx := parent
	if job.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, job.Timeout)
		defer cancel()
	}
	err := s.call(ctx, job)
	if err == nil && job.Timeout > 0 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	return err
}

// call invokes the handler and converts a panic into ErrJobPanic. |
// call 调用处理器并把 panic 转换为 ErrJobPanic。
func (s *Scheduler) call(ctx context.Context, job *Job) (err error) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		s.log.Error("cron: job panicked | 任务发生 panic",
			ydlog.Str("job_id", job.ID),
			ydlog.Str("task", job.Task),
			ydlog.Any("panic", recovered),
			ydlog.Str("stack", string(debug.Stack())),
		)
		err = errs.Wrap(&panicError{value: recovered}, ErrJobPanic)
	}()
	return job.Handler(ctx, job)
}

// finish records and logs one completed run. ran is false when the handler was
// never invoked (a lock failure), in which case the run counter is not bumped. |
// finish 记录并输出一次已完成运行；处理器未执行（锁失败）时 ran 为 false，此时不增加运行计数。
func (s *Scheduler) finish(item *entry, job *Job, trigger Trigger, started time.Time, attempts int, err error, ran bool) {
	finished := s.now()
	record := RunRecord{
		JobID:    job.ID,
		Trigger:  trigger,
		Started:  started,
		Finished: finished,
		Duration: finished.Sub(started),
		Attempts: attempts,
	}
	if err != nil {
		record.Err = err.Error()
	}
	if ran {
		item.stats.runs.Add(1)
	}
	if err != nil {
		item.stats.failures.Add(1)
	}
	item.stats.lastRun.Store(finished.UnixNano())
	item.stats.lastDuration.Store(int64(record.Duration))
	item.stats.addRecord(record, s.options.HistoryLimit)

	if err != nil {
		s.log.Error("cron: job failed | 任务失败",
			ydlog.Str("job_id", job.ID),
			ydlog.Str("task", job.Task),
			ydlog.Str("trigger", string(trigger)),
			ydlog.Int("attempts", attempts),
			ydlog.Dur("duration", record.Duration),
			ydlog.Err(err),
		)
	} else if s.log.Enabled(ydlog.DebugLevel) {
		s.log.Debug("cron: job completed | 任务完成",
			ydlog.Str("job_id", job.ID),
			ydlog.Str("task", job.Task),
			ydlog.Str("trigger", string(trigger)),
			ydlog.Int("attempts", attempts),
			ydlog.Dur("duration", record.Duration),
		)
	}
	s.afterRun(job, record)
}

// beforeRun applies the optional BeforeRun hook; a panic or a nil result leaves
// the incoming context untouched so a user hook cannot kill a worker. |
// beforeRun 应用可选的 BeforeRun Hook；panic 或返回 nil 时保持原上下文，用户 Hook 不会杀死工作协程。
func (s *Scheduler) beforeRun(ctx context.Context, job *Job) context.Context {
	hook := s.options.Hooks.BeforeRun
	if hook == nil {
		return ctx
	}
	out := ctx
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.log.Error("cron: BeforeRun hook panicked | BeforeRun Hook 发生 panic",
					ydlog.Str("job_id", job.ID),
					ydlog.Str("task", job.Task),
					ydlog.Any("panic", recovered),
					ydlog.Str("stack", string(debug.Stack())),
				)
			}
		}()
		if derived := hook(ctx, job); derived != nil {
			out = derived
		}
	}()
	return out
}

// afterRun applies the optional AfterRun hook with panic containment. |
// afterRun 在隔离 panic 的前提下应用可选的 AfterRun Hook。
func (s *Scheduler) afterRun(job *Job, record RunRecord) {
	hook := s.options.Hooks.AfterRun
	if hook == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			s.log.Error("cron: AfterRun hook panicked | AfterRun Hook 发生 panic",
				ydlog.Str("job_id", job.ID),
				ydlog.Str("task", job.Task),
				ydlog.Any("panic", recovered),
				ydlog.Str("stack", string(debug.Stack())),
			)
		}
	}()
	hook(context.Background(), job, record)
}

// claim acquires the distributed claim for one fire. A nil Lock with a nil
// error means another node owns the fire. | claim 为一次触发抢占分布式锁；
// Lock 为 nil 且错误为 nil 表示其它节点持有本次触发。
func (s *Scheduler) claim(ctx context.Context, job *Job, scheduled time.Time, manual bool) (Lock, bool, error) {
	key := s.lockKey(job.ID, scheduled, manual)
	lockCtx, cancel := context.WithTimeout(ctx, s.options.LockTimeout)
	defer cancel()
	lock, acquired, err := s.options.Locker.TryLock(lockCtx, key, s.options.LockTTL)
	if err != nil {
		return nil, false, errs.WrapDetail(err, ErrLockFailed, "%q", key)
	}
	if !acquired {
		return nil, false, nil
	}
	return lock, true, nil
}

// lockKey builds the per-fire claim key. Scheduled keys are identical on every
// node; manual keys add the node identity because a manual run has no shared
// scheduled instant. | lockKey 构建按次抢占的锁键。计划键在所有节点一致；手动触发的
// 运行没有共享计划时刻，因此额外带上节点标识。
func (s *Scheduler) lockKey(id string, scheduled time.Time, manual bool) string {
	key := s.options.Namespace + ":lock:" + id
	if manual {
		key += ":manual:" + s.options.NodeID
	}
	return key + ":" + strconv.FormatInt(scheduled.UTC().UnixNano(), 10)
}

// unlock releases a claim with its own timeout so shutdown cancellation does not
// skip the release. | unlock 用独立超时释放锁，避免关闭取消导致漏释放。
func (s *Scheduler) unlock(lock Lock) {
	if lock == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.options.LockTimeout)
	defer cancel()
	if err := lock.Unlock(ctx); err != nil {
		s.log.Warn("cron: unlock failed | 释放锁失败", ydlog.Err(err))
	}
}

// refreshLock extends a long-running claim and cancels the run when the claim is
// lost, preventing two nodes from executing the same fire. |
// refreshLock 为长运行续租，锁丢失时取消运行，避免两个节点执行同一次触发。
func (s *Scheduler) refreshLock(ctx context.Context, cancel context.CancelFunc, lock Lock, job *Job) func() {
	refresher, ok := lock.(LockRefresher)
	if !ok {
		return func() {}
	}
	interval := s.options.LockTTL / 3
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		failures := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				refreshCtx, refreshCancel := context.WithTimeout(ctx, s.options.LockTimeout)
				refreshed, err := refresher.Refresh(refreshCtx, s.options.LockTTL)
				refreshCancel()
				if err != nil {
					failures++
					s.log.Warn("cron: lock refresh failed | 锁续租失败",
						ydlog.Str("job_id", job.ID),
						ydlog.Int("failures", failures),
						ydlog.Err(err),
					)
					if failures >= 3 {
						cancel()
						return
					}
					continue
				}
				failures = 0
				if !refreshed {
					s.log.Error("cron: distributed lock lost | 分布式锁已丢失", ydlog.Str("job_id", job.ID))
					cancel()
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

// sleepCtx waits for delay or context cancellation. | sleepCtx 等待 delay 或上下文取消。
func sleepCtx(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		delay = time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// panicError carries a recovered panic value as an error. | panicError 把恢复到的 panic 取值承载为 error。
type panicError struct{ value any }

// Error renders the panic value the way fmt does. | Error 按 fmt 的方式渲染 panic 取值。
func (e *panicError) Error() string { return fmt.Sprint(e.value) }
