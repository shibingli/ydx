package cron

import (
	"context"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// Declared sentinel errors, testable with errors.Is. | 已声明的哨兵错误，可用 errors.Is 判定。
var (
	// ErrNilJob indicates a nil job was passed to Add or Update. | ErrNilJob 表示传给 Add 或 Update 的任务为 nil。
	ErrNilJob = errs.New("cron: nil job | cron：任务为 nil")
	// ErrNilSchedule indicates a job without a schedule. | ErrNilSchedule 表示任务缺少调度表达式。
	ErrNilSchedule = errs.New("cron: nil schedule | cron：调度为空")
	// ErrNilHandler indicates a job without a handler and without a registered task. |
	// ErrNilHandler 表示任务既无处理器也未注册任务名。
	ErrNilHandler = errs.New("cron: nil handler | cron：处理器为 nil")
	// ErrEmptyTask indicates an empty task name where one is required. | ErrEmptyTask 表示需要任务名但传入空值。
	ErrEmptyTask = errs.New("cron: empty task name | cron：任务名为空")
	// ErrJobExists indicates the job id is already scheduled. | ErrJobExists 表示任务 ID 已存在。
	ErrJobExists = errs.New("cron: job already exists | cron：任务已存在")
	// ErrJobNotFound indicates the job id is unknown. | ErrJobNotFound 表示任务 ID 不存在。
	ErrJobNotFound = errs.New("cron: job not found | cron：任务不存在")
	// ErrHandlerNotFound indicates no handler is registered for the job task. |
	// ErrHandlerNotFound 表示任务名没有注册处理器。
	ErrHandlerNotFound = errs.New("cron: handler not found | cron：未找到处理器")
	// ErrNoFutureRun indicates a schedule that will never fire again. | ErrNoFutureRun 表示调度不会再次触发。
	ErrNoFutureRun = errs.New("cron: schedule has no future run | cron：调度没有未来触发时刻")
	// ErrSchedulerStarted indicates Start was called twice. | ErrSchedulerStarted 表示重复调用 Start。
	ErrSchedulerStarted = errs.New("cron: scheduler already started | cron：调度器已启动")
	// ErrSchedulerClosed indicates use after Stop. | ErrSchedulerClosed 表示 Stop 之后继续使用。
	ErrSchedulerClosed = errs.New("cron: scheduler closed | cron：调度器已关闭")
	// ErrSchedulerNotRunning indicates a manual trigger before Start. | ErrSchedulerNotRunning 表示启动前手动触发。
	ErrSchedulerNotRunning = errs.New("cron: scheduler is not running | cron：调度器未运行")
	// ErrShutdownTimeout indicates workers were still running at the shutdown deadline. |
	// ErrShutdownTimeout 表示关闭截止时仍有工作协程在运行。
	ErrShutdownTimeout = errs.New("cron: shutdown timed out | cron：关闭超时")
	// ErrJobPanic indicates a handler panicked; the recovered value is attached as detail. |
	// ErrJobPanic 表示处理器发生 panic，恢复到的取值作为细节附加。
	ErrJobPanic = errs.New("cron: job panicked | cron：任务发生 panic")
	// ErrStoreFailed indicates the configured Store rejected an operation. |
	// ErrStoreFailed 表示配置的 Store 拒绝操作。
	ErrStoreFailed = errs.New("cron: store operation failed | cron：存储操作失败")
	// ErrNoStore indicates Reload was called without a Store. | ErrNoStore 表示未配置 Store 时调用 Reload。
	ErrNoStore = errs.New("cron: store is required | cron：需要 Store")
	// ErrNilRouter indicates Mount was called with a nil ydx/router Router. |
	// ErrNilRouter 表示 Mount 收到了 nil 的 ydx/router Router。
	ErrNilRouter = errs.New("cron: nil router | cron：路由器为 nil")
	// ErrLockFailed indicates the configured Locker failed to acquire or refresh a claim. |
	// ErrLockFailed 表示配置的 Locker 获取或续租失败。
	ErrLockFailed = errs.New("cron: lock operation failed | cron：锁操作失败")
	// ErrInvalidDefinition indicates a definition cannot be scheduled. | ErrInvalidDefinition 表示定义无法被调度。
	ErrInvalidDefinition = errs.New("cron: invalid job definition | cron：任务定义非法")
	// ErrJobRunning indicates a manual trigger was skipped by the overlap policy. |
	// ErrJobRunning 表示手动触发因并发策略被跳过。
	ErrJobRunning = errs.New("cron: job is already running | cron：任务已在运行")
	// ErrQueueFull indicates the worker queue rejected a manual trigger. |
	// ErrQueueFull 表示工作队列拒绝了手动触发。
	ErrQueueFull = errs.New("cron: worker queue is full | cron：工作队列已满")
)

// Trigger identifies why a run happened. | Trigger 标识运行原因。
type Trigger string

const (
	// TriggerScheduled is a run caused by the schedule. | TriggerScheduled 表示按计划触发。
	TriggerScheduled Trigger = "scheduled"
	// TriggerManual is a run caused by Trigger. | TriggerManual 表示手动触发。
	TriggerManual Trigger = "manual"
)

// OverlapPolicy decides what happens when a job is already running or queued. |
// OverlapPolicy 决定任务已在运行或排队时的行为。
type OverlapPolicy string

const (
	// SkipIfRunning drops the new run; it is the zero-value policy. | SkipIfRunning 丢弃新的运行，是零值策略。
	SkipIfRunning OverlapPolicy = "skip"
	// AllowOverlap lets runs overlap. | AllowOverlap 允许运行重叠。
	AllowOverlap OverlapPolicy = "allow"
)

// normalize returns the effective overlap policy. | normalize 返回生效的并发策略。
func (p OverlapPolicy) normalize() OverlapPolicy {
	if p == AllowOverlap {
		return AllowOverlap
	}
	return SkipIfRunning
}

// Handler executes one run. A returned error is retried according to the job's
// retry policy; honoring ctx is what makes timeouts and shutdown effective. The
// job is shared by concurrent runs and snapshots, so it and its Metadata map
// must be treated as read-only. A handler must not call Stop from the goroutine
// it runs on, because Stop waits for that run. | Handler 执行一次运行。返回错误时按任务
// 重试策略重试；正确处理 ctx 才能让超时与关闭生效。任务对象与 Metadata 被并发运行和快照共享，
// 必须视为只读。处理器不得在自身运行协程上调用 Stop，因为 Stop 会等待该次运行。
type Handler func(ctx context.Context, job *Job) error

// Job is the runtime description of a scheduled task. | Job 是定时任务的运行期描述。
type Job struct {
	// Schedule computes activation instants; it must not be nil. | Schedule 计算触发时刻，不得为 nil。
	Schedule Schedule
	// Handler executes the job; when nil, the registered handler for Task is used. |
	// Handler 执行任务；为 nil 时使用 Task 注册的处理器。
	Handler Handler
	// Metadata is opaque data carried to handlers and persisted with the
	// definition; it is shared by concurrent runs and must be read-only. |
	// Metadata 是传给处理器并随定义持久化的不透明数据；它被并发运行共享，必须只读。
	Metadata map[string]string
	// ID uniquely identifies the job; Add generates one when it is empty. | ID 唯一标识任务；为空时 Add 自动生成。
	ID string
	// Name is a human-readable label shown in snapshots and logs. | Name 是快照与日志中展示的可读名称。
	Name string
	// Task names the registered handler, required for persisted jobs. | Task 是已注册处理器的名称，持久化任务必填。
	Task string
	// Overlap decides whether a run is skipped while the job is busy. | Overlap 决定任务繁忙时是否跳过新的运行。
	Overlap OverlapPolicy
	// Timeout bounds one attempt; <=0 means no deadline. | Timeout 限制单次尝试；<=0 表示不设截止时间。
	Timeout time.Duration
	// Retries is the number of extra attempts after the first failure; <0 is treated as 0. |
	// Retries 是首次失败后的额外尝试次数；<0 按 0 处理。
	Retries int
	// RetryDelay is the first retry delay; <=0 uses one second when Retries > 0. |
	// RetryDelay 是首次重试延迟；Retries > 0 时 <=0 使用一秒。
	RetryDelay time.Duration
	// RetryBackoff multiplies the delay after each failure; <=1 keeps a fixed delay. |
	// RetryBackoff 是每次失败后的延迟倍数；<=1 表示固定延迟。
	RetryBackoff float64
	// MaxRetryDelay caps one retry delay; <=0 uses one minute. | MaxRetryDelay 限制单次重试延迟；<=0 使用一分钟。
	MaxRetryDelay time.Duration
	// Jitter spreads scheduled runs over [0, Jitter) to avoid thundering herds.
	// For a Singleton job keep Jitter below Options.LockTTL so a late node still
	// sees the claim; larger values are clamped to half the TTL. |
	// Jitter 把计划运行分散到 [0, Jitter) 区间，避免惊群。Singleton 任务应让 Jitter 小于
	// Options.LockTTL，使晚到的节点仍能看到锁；更大的值会被钳制到 TTL 的一半。
	Jitter time.Duration
	// Singleton claims a distributed lock per fire when a Locker is configured. |
	// Singleton 在配置 Locker 时按次抢占分布式锁。
	Singleton bool
	// Disabled keeps the definition but stops scheduled activation. | Disabled 保留定义但停止计划触发。
	Disabled bool
}

// Definition is the serializable part of a Job. Store implementations persist it
// and Scheduler.Start restores from it; handlers stay in the process and are
// resolved through Register. A custom Schedule must render an expression ParseIn
// accepts and should be location-independent; a *Spec records its time zone in
// Timezone so restored wall-clock fields keep their meaning. | Definition 是 Job
// 的可序列化部分。Store 持久化它，Scheduler.Start 从它恢复；处理器留在进程内，通过 Register
// 解析。自定义 Schedule 必须渲染 ParseIn 可接受的表达式，并且应当与时区无关；*Spec 会把时区写入
// Timezone，使恢复后的墙上时间字段保持原意。
type Definition struct {
	Metadata      map[string]string `json:"metadata,omitempty"`
	ID            string            `json:"id"`
	Name          string            `json:"name,omitempty"`
	Task          string            `json:"task,omitempty"`
	Expression    string            `json:"expression"`
	Timezone      string            `json:"timezone,omitempty"`
	Overlap       OverlapPolicy     `json:"overlap,omitempty"`
	Timeout       time.Duration     `json:"timeout,omitempty"`
	Retries       int               `json:"retries,omitempty"`
	RetryDelay    time.Duration     `json:"retry_delay,omitempty"`
	RetryBackoff  float64           `json:"retry_backoff,omitempty"`
	MaxRetryDelay time.Duration     `json:"max_retry_delay,omitempty"`
	Jitter        time.Duration     `json:"jitter,omitempty"`
	Singleton     bool              `json:"singleton,omitempty"`
	Disabled      bool              `json:"disabled,omitempty"`
}

// RunRecord describes one completed run. | RunRecord 描述一次已完成的运行。
type RunRecord struct {
	Started  time.Time     `json:"started"`
	Finished time.Time     `json:"finished"`
	JobID    string        `json:"job_id"`
	Trigger  Trigger       `json:"trigger"`
	Err      string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
	Attempts int           `json:"attempts"`
}

// OK reports whether the run succeeded. | OK 报告运行是否成功。
func (r RunRecord) OK() bool { return r.Err == "" }

// Snapshot is a point-in-time view of a job and its statistics. | Snapshot 是任务及其统计的时刻视图。
type Snapshot struct {
	Next      time.Time `json:"next"`
	LastRun   time.Time `json:"last_run,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	Definition
	LastDuration time.Duration `json:"last_duration,omitempty"`
	Runs         uint64        `json:"runs"`
	Failures     uint64        `json:"failures"`
	Skipped      uint64        `json:"skipped"`
	Dropped      uint64        `json:"dropped"`
	Running      bool          `json:"running"`
}

// Stats aggregates scheduler-wide counters. | Stats 汇总调度器级计数器。
type Stats struct {
	Jobs     int    `json:"jobs"`
	Enabled  int    `json:"enabled"`
	Running  int    `json:"running"`
	Queued   int    `json:"queued"`
	Runs     uint64 `json:"runs"`
	Failures uint64 `json:"failures"`
	Skipped  uint64 `json:"skipped"`
	Dropped  uint64 `json:"dropped"`
}

// Hooks observes runs without owning them; every function may be nil, must not
// block, must treat the job and its Metadata as read-only, and must not call
// Stop from the goroutine it runs on. Panics are recovered and logged. |
// Hooks 观察运行但不拥有运行；每个函数都可为 nil，不得阻塞，必须把任务与 Metadata 视为只读，
// 也不得在自身运行协程上调用 Stop。panic 会被恢复并记录日志。
type Hooks struct {
	// BeforeRun may derive the context used by the handler (trace ids and so on). |
	// BeforeRun 可派生处理器使用的上下文（链路 ID 等）。
	BeforeRun func(ctx context.Context, job *Job) context.Context
	// AfterRun runs after the final attempt with the completed record. |
	// AfterRun 在最后一次尝试完成后以最终记录调用。
	AfterRun func(ctx context.Context, job *Job, record RunRecord)
	// Skipped runs when a fire is dropped; reason is overlap, locked or queue_full. |
	// Skipped 在丢弃触发时调用；reason 为 overlap、locked 或 queue_full。
	Skipped func(ctx context.Context, job *Job, reason string)
}

// Skip reasons passed to Hooks.Skipped. | 传给 Hooks.Skipped 的跳过原因。
const (
	// SkipOverlap means the job was already running or queued. | SkipOverlap 表示任务已在运行或排队。
	SkipOverlap = "overlap"
	// SkipLocked means another node owns the fire. | SkipLocked 表示其它节点持有本次触发。
	SkipLocked = "locked"
	// SkipQueueFull means the worker queue was full. | SkipQueueFull 表示工作队列已满。
	SkipQueueFull = "queue_full"
)

// Options configures a Scheduler. Every field has a usable zero value. |
// Options 配置 Scheduler；所有字段的零值都可用。
type Options struct {
	// Hooks observes runs; all callbacks are optional. | Hooks 观察运行；所有回调均可选。
	Hooks Hooks
	// Store persists definitions across restarts; nil keeps definitions in memory only. |
	// Store 跨重启持久化定义；nil 表示只保存在内存。
	Store Store
	// Locker coordinates Singleton jobs across nodes; nil means single-node execution. |
	// Locker 协调多节点的 Singleton 任务；nil 表示单机执行。
	Locker Locker
	// Logger receives scheduler records; nil uses log.Default(). | Logger 接收调度日志；nil 使用 log.Default()。
	Logger *ydlog.Logger
	// Now overrides the clock for tests; nil uses time.Now. | Now 为测试覆盖时钟；nil 使用 time.Now。
	Now func() time.Time
	// NodeID identifies this process in manual-trigger lock keys; empty uses
	// hostname and pid. Scheduled claims use the same key on every node. |
	// NodeID 在手动触发的锁键中标识本进程；为空时使用主机名与进程号。计划触发的锁键在所有节点一致。
	NodeID string
	// Namespace prefixes lock keys and stores; empty uses "cron". | Namespace 为锁键和存储加前缀；为空使用 "cron"。
	Namespace string
	// Concurrency is the number of job workers; <=0 uses GOMAXPROCS. | Concurrency 是工作协程数；<=0 取 GOMAXPROCS。
	Concurrency int
	// QueueSize is the pending-run buffer; <=0 uses 1024. When it fills, new runs are dropped and counted. |
	// QueueSize 是待运行队列容量；<=0 使用 1024。队列满时丢弃新运行并计数。
	QueueSize int
	// LockTTL is the initial distributed claim lifetime and the deduplication
	// window of a scheduled fire; <=0 uses 30s. | LockTTL 是分布式锁初始有效期，也是计划触发的
	// 去重窗口；<=0 使用 30 秒。
	LockTTL time.Duration
	// LockTimeout bounds one TryLock call; <=0 uses 5s. | LockTimeout 限制单次 TryLock；<=0 使用 5 秒。
	LockTimeout time.Duration
	// ShutdownTimeout is the graceful budget for in-flight runs; <=0 uses 30s. |
	// ShutdownTimeout 是在途运行的优雅预算；<=0 使用 30 秒。
	ShutdownTimeout time.Duration
	// HistoryLimit is the per-job run-record ring size; <=0 uses 8, negative disables records. |
	// HistoryLimit 是每个任务的运行记录环大小；<=0 使用 8，负数关闭记录。
	HistoryLimit int
}
