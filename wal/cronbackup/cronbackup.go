package cronbackup

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/cron"
	"github.com/shibingli/ydx/errs"
)

// Target is the WAL surface a scheduled backup needs. *wal.WAL implements it;
// this module deliberately does not import wal, so it can be versioned and
// built independently, following the same structural-interface pattern as
// wal/zstd. | Target 是定时备份所需的 WAL 接口；*wal.WAL 实现了它。本模块刻意
// 不 import wal，以便独立版本化与构建，沿用 wal/zstd 的结构化接口模式。
type Target interface {
	// BackupNow rotates the WAL, verifies the referenced segments, and publishes
	// a restore-complete backup set. | BackupNow 轮转 WAL、校验引用分段并发布
	// 可完整恢复的备份集。
	BackupNow(ctx context.Context) error
	// BackupConfigured reports whether a backup target was configured at Open. |
	// BackupConfigured 报告 Open 时是否配置了备份目标。
	BackupConfigured() bool
	// SupportsSnapshotBackup reports whether the target implements
	// SnapshotBackup, which BackupNow requires. | SupportsSnapshotBackup 报告
	// 目标是否实现 BackupNow 所需的 SnapshotBackup。
	SupportsSnapshotBackup() bool
}

// Config configures the scheduled backup job. The zero value is invalid only
// because Schedule is required. | Config 配置定时备份任务；只有 Schedule 必填，
// 因此零值无效。
type Config struct {
	// Schedule is a ydx/cron expression: five/six/seven fields, a descriptor such
	// as @daily, @every duration, or @once RFC3339. Required. |
	// Schedule 是 ydx/cron 表达式：五/六/七字段、@daily 等描述符、@every 时长或
	// @once RFC3339；必填。
	Schedule string
	// Timezone resolves wall-clock fields; nil uses time.Local. An inline
	// CRON_TZ=/TZ= prefix in Schedule takes precedence. | Timezone 解析墙上时间
	// 字段；nil 使用 time.Local。Schedule 中的 CRON_TZ=/TZ= 前缀优先。
	Timezone *time.Location
	// JobID is the scheduler job identifier. Default "wal-backup". Use a unique
	// value when attaching several WALs to one scheduler. | JobID 是调度任务 ID，
	// 默认 "wal-backup"；多个 WAL 共用一个调度器时必须唯一。
	JobID string
	// Task is the handler name persisted with the definition. Default
	// "wal-backup:<JobID>". Set a unique value per target when sharing a
	// scheduler. | Task 是随定义持久化的处理器名称，默认
	// "wal-backup:<JobID>"；共享调度器时每个目标应使用唯一值。
	Task string
	// Name is the human-readable job label. Default "WAL backup <JobID>". |
	// Name 是可读任务名称，默认 "WAL backup <JobID>"。
	Name string
	// Overlap controls concurrent fires. Empty means cron.SkipIfRunning, so a
	// backup that lasts longer than its interval is not duplicated. |
	// Overlap 控制并发触发；空值表示 cron.SkipIfRunning，长于间隔的备份不会重复
	// 启动。
	Overlap cron.OverlapPolicy
	// Timeout bounds one backup attempt; <=0 means no deadline. |
	// Timeout 限制单次备份；<=0 表示不设截止时间。
	Timeout time.Duration
	// Retries is the number of extra attempts after a failure; <0 is treated as
	// zero by cron. | Retries 是失败后的额外尝试次数；cron 将 <0 视为 0。
	Retries int
	// RetryDelay is the first retry delay; <=0 uses cron's one-second default. |
	// RetryDelay 是首次重试延迟；<=0 使用 cron 的一秒默认值。
	RetryDelay time.Duration
	// RetryBackoff multiplies the delay after each failure; <=1 is fixed. |
	// RetryBackoff 是每次失败后的延迟倍数；<=1 表示固定延迟。
	RetryBackoff float64
	// MaxRetryDelay caps one retry delay; <=0 uses cron's one-minute default. |
	// MaxRetryDelay 限制单次重试延迟；<=0 使用 cron 的一分钟默认值。
	MaxRetryDelay time.Duration
	// Jitter spreads scheduled fires over [0, Jitter) to avoid synchronized
	// backups. | Jitter 把计划触发分散到 [0, Jitter) 区间，避免备份同时启动。
	Jitter time.Duration
	// Singleton claims a distributed lock per fire when the scheduler has a
	// Locker. Each WAL directory normally has one writer, so leave it false
	// unless the backup target must be deduplicated across nodes. |
	// Singleton 在调度器配置 Locker 时按次抢占分布式锁。每个 WAL 目录通常只有
	// 一个写者，除非备份目标需要跨节点去重，否则保持 false。
	Singleton bool
	// Disabled adds the definition without scheduled activation; manual Trigger
	// still works. | Disabled 添加定义但不参与计划触发；手动 Trigger 仍可用。
	Disabled bool
}

// Sentinel errors returned by construction and validation. | 构造与校验返回的哨兵错误。
var (
	// ErrNilTarget reports an absent backup target. | ErrNilTarget 表示备份目标为空。
	ErrNilTarget = errs.New("cronbackup: nil target | cronbackup：备份目标为 nil")
	// ErrNoBackupTarget reports a WAL opened without WithBackup. | ErrNoBackupTarget
	// 表示 WAL 打开时未配置 WithBackup。
	ErrNoBackupTarget = errs.New("cronbackup: WAL has no backup target | cronbackup：WAL 未配置备份目标")
	// ErrSnapshotUnsupported reports a backup target that cannot publish a
	// restore-complete BackupSet. | ErrSnapshotUnsupported 表示备份目标无法发布
	// 可完整恢复的 BackupSet。
	ErrSnapshotUnsupported = errs.New("cronbackup: backup target does not implement SnapshotBackup | cronbackup：备份目标未实现 SnapshotBackup")
	// ErrInvalidSchedule reports an empty or unparsable cron expression. |
	// ErrInvalidSchedule 表示调度表达式为空或无法解析。
	ErrInvalidSchedule = errs.New("cronbackup: invalid schedule | cronbackup：调度表达式非法")
	// ErrNilScheduler reports an absent scheduler passed to Attach. |
	// ErrNilScheduler 表示传给 Attach 的调度器为空。
	ErrNilScheduler = errs.New("cronbackup: nil scheduler | cronbackup：调度器为 nil")
)

const (
	// defaultJobID keeps definitions stable across restarts when the caller does
	// not choose an identifier. | defaultJobID 在调用方未指定时保持定义跨重启稳定。
	defaultJobID = "wal-backup"
	// defaultTaskPrefix namespaces the handler by job identifier, so attaching
	// two WALs with distinct IDs does not overwrite each other's handler. |
	// defaultTaskPrefix 按任务 ID 隔离处理器，使两个不同 ID 的 WAL 不会互相覆盖。
	defaultTaskPrefix = "wal-backup:"
	// defaultJobName is used when Config.Name is empty. | defaultJobName 在
	// Config.Name 为空时使用。
	defaultJobName = "WAL backup"
)

// Scheduler owns a dedicated cron scheduler and one WAL backup job. Create it
// with New, then Start it, Run it, or drive it through Cron. | Scheduler 拥有一个
// 专用 cron 调度器与一个 WAL 备份任务；通过 New 创建，再 Start、Run 或经 Cron
// 操作。
type Scheduler struct {
	scheduler *cron.Scheduler
	jobID     string
}

// New validates target, creates a dedicated cron scheduler with opts, registers
// the backup handler, and adds the job. The scheduler is not started. |
// New 校验 target，使用 opts 创建专用 cron 调度器，注册备份处理器并加入任务；
// 调度器尚未启动。
func New(ctx context.Context, target Target, cfg Config, opts cron.Options) (*Scheduler, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	job, err := buildJob(cfg)
	if err != nil {
		return nil, err
	}
	scheduler := cron.New(opts)
	if err := scheduler.Register(job.Task, backupHandler(target)); err != nil {
		return nil, err
	}
	if err := scheduler.Add(ctx, job); err != nil {
		return nil, err
	}
	return &Scheduler{scheduler: scheduler, jobID: job.ID}, nil
}

// Start activates the scheduler's event loop. | Start 启动调度器事件循环。
func (s *Scheduler) Start(ctx context.Context) error {
	if s == nil || s.scheduler == nil {
		return ErrNilScheduler
	}
	return s.scheduler.Start(ctx)
}

// Run starts the scheduler and blocks until ctx is cancelled, then performs a
// graceful shutdown. | Run 启动调度器并阻塞到 ctx 取消，随后优雅关闭。
func (s *Scheduler) Run(ctx context.Context) error {
	if s == nil || s.scheduler == nil {
		return ErrNilScheduler
	}
	return s.scheduler.Run(ctx)
}

// Stop stops the scheduler and waits for in-flight backups until ctx expires.
// It is safe to call when the scheduler was never started. | Stop 停止调度器并
// 等待在途备份直到 ctx 到期；从未启动时调用也安全。
func (s *Scheduler) Stop(ctx context.Context) error {
	if s == nil || s.scheduler == nil {
		return ErrNilScheduler
	}
	return s.scheduler.Stop(ctx)
}

// Trigger runs the backup once through the scheduler, respecting the job's
// timeout, retry and overlap settings. The scheduler must be started. | Trigger
// 通过调度器立即执行一次备份，遵循任务的超时、重试与并发策略；调度器必须已启动。
func (s *Scheduler) Trigger() error {
	if s == nil || s.scheduler == nil {
		return ErrNilScheduler
	}
	return s.scheduler.Trigger(s.jobID)
}

// Cron returns the underlying scheduler for admin routes, extra jobs, or
// introspection. | Cron 返回底层调度器，用于管理路由、其它任务或查询。
func (s *Scheduler) Cron() *cron.Scheduler {
	if s == nil {
		return nil
	}
	return s.scheduler
}

// JobID returns the configured job identifier. | JobID 返回任务标识。
func (s *Scheduler) JobID() string {
	if s == nil {
		return ""
	}
	return s.jobID
}

// Job is a WAL backup job attached to an existing scheduler. | Job 是附加到既有
// 调度器的 WAL 备份任务。
type Job struct {
	scheduler *cron.Scheduler
	id        string
}

// attachMu serializes handler registration and Add in Attach. Without it two
// concurrent attachments could overwrite each other's handler before one Add
// fails, silently pointing the surviving job at the wrong WAL. |
// attachMu 串行化 Attach 中的处理器注册与 Add；否则两个并发附加可能在其中一个
// Add 失败前互相覆盖处理器，使存活任务静默指向错误的 WAL。
var attachMu sync.Mutex

// Attach validates target, registers the backup handler on scheduler, and adds
// the job. Attaching several WALs to one scheduler requires unique JobID and
// Task values. | Attach 校验 target，在 scheduler 上注册备份处理器并加入任务。
// 一个调度器附加多个 WAL 时，JobID 与 Task 必须唯一。
func Attach(ctx context.Context, scheduler *cron.Scheduler, target Target, cfg Config) (*Job, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if scheduler == nil {
		return nil, ErrNilScheduler
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	job, err := buildJob(cfg)
	if err != nil {
		return nil, err
	}
	attachMu.Lock()
	defer attachMu.Unlock()
	// Reject a duplicate ID before Register: cron has no unregister API, so an
	// overwritten handler could redirect the existing job to another WAL. |
	// 在 Register 前拒绝重复 ID：cron 没有反注册 API，覆盖处理器会把既有任务
	// 重定向到另一个 WAL。
	if _, exists := scheduler.Get(job.ID); exists {
		return nil, errs.Detail(cron.ErrJobExists, "%q", job.ID)
	}
	if err := scheduler.Register(job.Task, backupHandler(target)); err != nil {
		return nil, err
	}
	if err := scheduler.Add(ctx, job); err != nil {
		return nil, err
	}
	return &Job{scheduler: scheduler, id: job.ID}, nil
}

// Trigger runs the attached backup once. The scheduler must be started. |
// Trigger 立即执行一次附加的备份；调度器必须已启动。
func (j *Job) Trigger() error {
	if j == nil || j.scheduler == nil {
		return ErrNilScheduler
	}
	return j.scheduler.Trigger(j.id)
}

// Remove removes the job definition. The registered handler remains with the
// scheduler for its lifetime, matching ydx/cron's handler lifecycle. | Remove
// 删除任务定义；处理器会随调度器存续，符合 ydx/cron 的处理器生命周期。
func (j *Job) Remove(ctx context.Context) error {
	if j == nil || j.scheduler == nil {
		return ErrNilScheduler
	}
	return j.scheduler.Remove(ctx, j.id)
}

// ID returns the job identifier. | ID 返回任务标识。
func (j *Job) ID() string {
	if j == nil {
		return ""
	}
	return j.id
}

// nilTarget reports whether target is nil, including a typed nil pointer stored
// in the interface. Startup-time reflection keeps a nil *wal.WAL from panicking
// inside validateTarget. | nilTarget 判断 target 是否为 nil，包括接口中保存的
// typed-nil 指针；启动期反射避免 nil *wal.WAL 在 validateTarget 中触发 panic。
func nilTarget(target Target) bool {
	if target == nil {
		return true
	}
	v := reflect.ValueOf(target)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// validateTarget ensures the WAL can actually publish a backup on every fire. |
// validateTarget 确保 WAL 在每次触发时确实能发布备份。
func validateTarget(target Target) error {
	if nilTarget(target) {
		return ErrNilTarget
	}
	if !target.BackupConfigured() {
		return errs.Detail(ErrNoBackupTarget, "open the WAL with WithBackup(DirBackup(...)) or another target | 请使用 WithBackup(DirBackup(...)) 或其它目标打开 WAL")
	}
	if !target.SupportsSnapshotBackup() {
		return errs.Detail(ErrSnapshotUnsupported, "use a SnapshotBackup target such as DirBackup | 请使用 DirBackup 等 SnapshotBackup 目标")
	}
	return nil
}

// backupHandler returns the cron handler that performs one backup. | backupHandler
// 返回执行一次备份的 cron 处理器。
func backupHandler(target Target) cron.Handler {
	return func(ctx context.Context, _ *cron.Job) error {
		return target.BackupNow(ctx)
	}
}

// buildJob parses the schedule and applies defaults. | buildJob 解析调度表达式并应用默认值。
func buildJob(cfg Config) (*cron.Job, error) {
	expression := strings.TrimSpace(cfg.Schedule)
	if expression == "" {
		return nil, errs.Detail(ErrInvalidSchedule, "schedule is empty | 调度表达式为空")
	}
	schedule, err := cron.ParseIn(expression, cfg.Timezone)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidSchedule, "parse %q | 解析 %q 失败", expression, expression)
	}
	jobID := strings.TrimSpace(cfg.JobID)
	if jobID == "" {
		jobID = defaultJobID
	}
	task := strings.TrimSpace(cfg.Task)
	if task == "" {
		task = defaultTaskPrefix + jobID
	}
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = defaultJobName + " " + jobID
	}
	overlap := cfg.Overlap
	if overlap == "" {
		overlap = cron.SkipIfRunning
	}
	return &cron.Job{
		ID:            jobID,
		Name:          name,
		Task:          task,
		Schedule:      schedule,
		Overlap:       overlap,
		Timeout:       cfg.Timeout,
		Retries:       cfg.Retries,
		RetryDelay:    cfg.RetryDelay,
		RetryBackoff:  cfg.RetryBackoff,
		MaxRetryDelay: cfg.MaxRetryDelay,
		Jitter:        cfg.Jitter,
		Singleton:     cfg.Singleton,
		Disabled:      cfg.Disabled,
	}, nil
}
