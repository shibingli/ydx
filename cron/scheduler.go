package cron

import (
	"container/heap"
	"context"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// idleWait is how long the event loop sleeps when the heap is empty; a new job
// or a stop signal wakes it earlier. | idleWait 是堆为空时事件循环的睡眠上限；
// 新任务或停止信号会提前唤醒它。
const idleWait = time.Hour

// Scheduler owns the job table, the timer heap and the worker pool. |
// Scheduler 拥有任务表、定时器堆与工作池。
type Scheduler struct {
	// log is the scheduler-scoped child logger. | log 是调度器级子日志器。
	log *ydlog.Logger
	// now is the injectable clock. | now 是可注入时钟。
	now func() time.Time

	// handlers maps a task name to its handler. | handlers 把任务名映射到处理器。
	handlers map[string]Handler

	// entries indexes scheduled jobs by id. | entries 按 ID 索引已调度任务。
	entries map[string]*entry

	// wake nudges the event loop after a mutation. | wake 在变更后唤醒事件循环。
	wake chan struct{}
	// loopDone closes when the event loop exits. | loopDone 在事件循环退出时关闭。
	loopDone chan struct{}
	// cancel stops the event loop. | cancel 停止事件循环。
	cancel context.CancelFunc
	// exec owns the workers and the run queue. | exec 拥有工作协程与运行队列。
	exec *executor
	// heap orders entries by next activation. | heap 按下次触发时刻排序。
	heap timerHeap
	// dueBuf reuses the due-fire slice on the event-loop goroutine. | dueBuf 在事件循环协程内复用到期切片。
	dueBuf []dueFire

	// sorted caches entry pointers ordered by job id. | sorted 缓存按 ID 排序的元素指针。
	sorted []*entry

	// options is normalized once by New. | options 由 New 规范化一次。
	options Options

	// version increments whenever the set of job ids changes. | version 在任务 ID 集合变化时递增。
	version uint64
	// cacheVersion is the version the sorted cache was built from. | cacheVersion 是有序缓存构建时的版本。
	cacheVersion uint64

	// handlersMu guards handlers. | handlersMu 保护 handlers。
	handlersMu sync.RWMutex

	// mu guards entries, heap and the lifecycle flags; readers take RLock. |
	// mu 保护 entries、heap 与生命周期标志；读取方使用 RLock。
	mu sync.RWMutex

	// lifecycleMu serializes Start and Stop. | lifecycleMu 串行化 Start 与 Stop。
	lifecycleMu sync.Mutex
	// opMu serializes mutations and their store writes. | opMu 串行化变更及其存储写入。
	opMu sync.Mutex
	// listMu serializes List and guards the sorted snapshot cache. |
	// listMu 串行化 List 并保护有序快照缓存。
	listMu sync.Mutex
	// active reports whether the event loop is running, so mutations before Start
	// do not pay for a wake that nobody can consume. | active 表示事件循环是否运行，
	// 使 Start 之前的变更不必付出无人消费的唤醒成本。
	active atomic.Bool
	// started reports whether Start succeeded. | started 表示 Start 是否成功。
	started bool
	// closed reports whether Stop ran. | closed 表示 Stop 是否已执行。
	closed bool
}

// New builds a scheduler; it performs no I/O and starts no goroutine. |
// New 构建调度器；不做 I/O，也不启动协程。
func New(o Options) *Scheduler {
	if o.Concurrency <= 0 {
		o.Concurrency = runtime.GOMAXPROCS(0)
		if o.Concurrency < 1 {
			o.Concurrency = 1
		}
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 1024
	}
	if o.Namespace == "" {
		o.Namespace = "cron"
	}
	if o.LockTTL <= 0 {
		o.LockTTL = 30 * time.Second
	}
	if o.LockTimeout <= 0 {
		o.LockTimeout = 5 * time.Second
	}
	if o.ShutdownTimeout <= 0 {
		o.ShutdownTimeout = 30 * time.Second
	}
	if o.HistoryLimit == 0 {
		o.HistoryLimit = 8
	}
	if o.Logger == nil {
		o.Logger = ydlog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.NodeID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "node"
		}
		o.NodeID = host + "-" + strconv.Itoa(os.Getpid())
	}
	return &Scheduler{
		options:  o,
		log:      o.Logger.Named("cron"),
		now:      o.Now,
		handlers: make(map[string]Handler),
		entries:  make(map[string]*entry),
		wake:     make(chan struct{}, 1),
		loopDone: make(chan struct{}),
	}
}

// Register binds a task name to a handler used when a job names Task. |
// Register 把任务名绑定到处理器，供以 Task 指定处理器的任务使用。
//
// Registering again replaces the previous handler. Registrations must exist
// before Start when persisted definitions refer to them. | 重复注册会替换旧处理器；
// 持久化定义引用任务名时，必须在 Start 前完成注册。
func (s *Scheduler) Register(task string, handler Handler) error {
	if task == "" {
		return ErrEmptyTask
	}
	if handler == nil {
		return ErrNilHandler
	}
	s.handlersMu.Lock()
	s.handlers[task] = handler
	s.handlersMu.Unlock()
	return nil
}

// Start loads persisted definitions, starts the workers and starts the event
// loop. | Start 加载持久化定义、启动工作协程并启动事件循环。
//
// It fails fast when the Store cannot list definitions or a stored definition
// has no registered handler, so a deployment never silently runs a partial job
// table. Cancelling ctx stops the event loop and cancels in-flight handler
// contexts; use Run for a graceful stop driven by ctx. | Store 无法列举定义，或某条
// 定义没有已注册处理器时快速失败，避免部署静默运行不完整的任务表。取消 ctx 会停止事件循环并取消
// 在途处理器上下文；由 ctx 驱动的优雅停止请使用 Run。
func (s *Scheduler) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrSchedulerClosed
	}
	if s.started {
		s.mu.Unlock()
		return ErrSchedulerStarted
	}
	s.mu.Unlock()

	s.opMu.Lock()
	if s.options.Store != nil {
		definitions, err := s.options.Store.List(ctx)
		if err != nil {
			s.opMu.Unlock()
			return errs.Wrap(err, ErrStoreFailed)
		}
		restored := make(map[string]jobDef, len(definitions))
		for _, definition := range definitions {
			job, restoreErr := s.restoreJob(definition)
			if restoreErr != nil {
				s.opMu.Unlock()
				return restoreErr
			}
			restored[job.ID] = jobDef{job: job, definition: definition}
		}
		now := s.now()
		s.mu.Lock()
		for id, wanted := range restored {
			if _, exists := s.entries[id]; !exists {
				item := newEntry(wanted.job, wanted.definition)
				s.entries[id] = item
				_ = s.armLocked(item, wanted.job.Schedule.Next(now), false)
				s.version++
			}
		}
		s.mu.Unlock()
	}
	s.opMu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	// Workers derive from the caller context, not the loop context: Stop cancels
	// the loop immediately but lets in-flight handlers use the shutdown budget. |
	// 工作协程派生自调用方上下文而非事件循环上下文：Stop 立即取消循环，但在途处理器仍可使用关闭预算。
	workers := newExecutor(s, s.options.Concurrency, s.options.QueueSize, ctx)
	workers.start()

	s.mu.Lock()
	s.cancel = cancel
	s.exec = workers
	s.started = true
	s.active.Store(true)
	s.mu.Unlock()

	go s.loop(runCtx)
	return nil
}

// Stop stops accepting fires and waits for in-flight runs until ctx expires. |
// Stop 停止接受触发，并等待在途运行直到 ctx 到期。
//
// Reaching the deadline cancels the run contexts and reports
// ErrShutdownTimeout once the workers exit; handlers that ignore ctx keep their
// goroutines alive, so they must honor cancellation. | 到达截止时间会取消运行上下文，
// 并在工作协程退出后返回 ErrShutdownTimeout；忽略 ctx 的处理器会让协程继续存活，因此必须响应取消。
func (s *Scheduler) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.opMu.Lock()
	s.mu.Lock()
	if !s.started || s.closed {
		s.mu.Unlock()
		s.opMu.Unlock()
		return nil
	}
	s.closed = true
	s.active.Store(false)
	cancel := s.cancel
	loopDone := s.loopDone
	workers := s.exec
	s.mu.Unlock()
	s.opMu.Unlock()

	if cancel != nil {
		cancel()
	}
	<-loopDone
	if workers != nil {
		return workers.stop(ctx, s.options.ShutdownTimeout)
	}
	return nil
}

// Run starts the scheduler and blocks until ctx is cancelled, then stops it with
// the configured shutdown budget. Cancellation is normal termination and
// in-flight handlers get the budget to finish; ctx values such as trace ids are
// preserved for those handlers. | Run 启动调度器并阻塞到 ctx 取消，随后按配置的关闭
// 预算停止；取消属于正常终止，在途处理器可在预算内完成，ctx 中的链路 ID 等取值会传给处理器。
func (s *Scheduler) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Start's contexts only carry values; Stop owns the lifecycle so the
	// shutdown budget is not pre-empted by the caller's cancellation. |
	// Start 的上下文只传递取值；生命周期由 Stop 掌握，因此关闭预算不会被调用方取消抢先。
	if err := s.Start(context.WithoutCancel(ctx)); err != nil {
		return err
	}
	<-ctx.Done()
	stopCtx, cancel := context.WithTimeout(context.Background(), s.options.ShutdownTimeout)
	defer cancel()
	return s.Stop(stopCtx)
}

// armLocked places an entry in the heap for next; the caller holds s.mu. |
// armLocked 按 next 把元素放入堆；调用方持有 s.mu。
func (s *Scheduler) armLocked(item *entry, next time.Time, strict bool) error {
	if item.job.Disabled {
		s.unarmLocked(item)
		return nil
	}
	if next.IsZero() {
		if strict {
			return ErrNoFutureRun
		}
		s.unarmLocked(item)
		return nil
	}
	item.next = next
	if item.index >= 0 {
		heap.Fix(&s.heap, item.index)
	} else {
		heap.Push(&s.heap, item)
	}
	return nil
}

// unarmLocked removes an entry from the heap; the caller holds s.mu. |
// unarmLocked 从堆中移除元素；调用方持有 s.mu。
func (s *Scheduler) unarmLocked(item *entry) {
	if item.index >= 0 {
		heap.Remove(&s.heap, item.index)
	}
	item.next = time.Time{}
}

// signal wakes the event loop without blocking; before Start there is no loop
// to wake, so the send is skipped entirely. | signal 非阻塞地唤醒事件循环；
// Start 之前没有可唤醒的循环，因此完全跳过发送。
func (s *Scheduler) signal() {
	if !s.active.Load() {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// loop is the single scheduling goroutine: it pops due entries, re-arms them and
// sleeps until the earliest next activation, a mutation or shutdown. |
// loop 是唯一的调度协程：取出到期元素、重新排程，并睡眠到最早的下次触发、变更或关闭。
func (s *Scheduler) loop(ctx context.Context) {
	defer close(s.loopDone)
	timer := time.NewTimer(idleWait)
	defer timer.Stop()

	for {
		s.mu.Lock()
		now := s.now()
		due := s.popDueLocked(now)
		wait := s.waitLocked(now)
		s.mu.Unlock()

		for index := range due {
			s.dispatch(&due[index])
		}
		// Clear the backing array so a removed job is not retained by the buffer. |
		// 清空底层数组，避免已删除任务被复用缓冲持有。
		clear(due)
		s.dueBuf = due[:0]

		resetTimer(timer, wait)
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-timer.C:
		}
	}
}

// popDueLocked removes every due entry, re-arms it at the first activation after
// now (skipping missed runs) and returns the fires to dispatch; the caller holds
// s.mu. | popDueLocked 取出所有到期元素，按 now 之后的第一个触发重新排程（跳过错过的运行），
// 并返回待派发的触发；调用方持有 s.mu。
func (s *Scheduler) popDueLocked(now time.Time) []dueFire {
	due := s.dueBuf[:0]
	for len(s.heap) > 0 {
		item := s.heap[0]
		if item.next.After(now) {
			break
		}
		heap.Pop(&s.heap)
		at := item.next
		item.next = time.Time{}
		if !item.job.Disabled {
			if next := item.job.Schedule.Next(now); !next.IsZero() {
				item.next = next
				heap.Push(&s.heap, item)
			}
		}
		due = append(due, dueFire{entry: item, job: item.job, at: at})
	}
	return due
}

// waitLocked returns how long the loop may sleep; the caller holds s.mu. |
// waitLocked 返回事件循环可睡眠的时长；调用方持有 s.mu。
func (s *Scheduler) waitLocked(now time.Time) time.Duration {
	if len(s.heap) == 0 {
		return idleWait
	}
	wait := s.heap[0].next.Sub(now)
	if wait <= 0 {
		return time.Millisecond
	}
	return wait
}

// resetTimer safely re-arms a timer. | resetTimer 安全地重新设置定时器。
func resetTimer(timer *time.Timer, wait time.Duration) {
	if wait <= 0 {
		wait = time.Millisecond
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(wait)
}
