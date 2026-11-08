package cronbackup

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/cron"
)

// fakeTarget is a controllable Target for scheduler tests. | fakeTarget 是用于
// 调度器测试的可控 Target。
type fakeTarget struct {
	mu         sync.Mutex
	err        error
	runCh      chan struct{}
	runs       int
	configured bool
	snapshot   bool
}

func newFakeTarget() *fakeTarget {
	return &fakeTarget{configured: true, snapshot: true, runCh: make(chan struct{}, 1)}
}

func (f *fakeTarget) BackupNow(ctx context.Context) error {
	f.mu.Lock()
	f.runs++
	err := f.err
	ch := f.runCh
	f.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return err
}

func (f *fakeTarget) BackupConfigured() bool { return f.configured }

func (f *fakeTarget) SupportsSnapshotBackup() bool { return f.snapshot }

func (f *fakeTarget) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

func waitRun(t *testing.T, target *fakeTarget) {
	t.Helper()
	select {
	case <-target.runCh:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduled backup did not run")
	}
}

func stopScheduler(t *testing.T, scheduler *Scheduler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := scheduler.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// TestNewValidatesTargetAndSchedule verifies construction-time validation. |
// 验证构造期校验。
func TestNewValidatesTargetAndSchedule(t *testing.T) {
	ctx := context.Background()
	cfg := Config{Schedule: "@daily"}
	if _, err := New(ctx, nil, cfg, cron.Options{}); !errors.Is(err, ErrNilTarget) {
		t.Fatalf("nil target err = %v, want ErrNilTarget", err)
	}
	// A typed nil pointer must be rejected instead of panicking in the first
	// Target method call. | typed-nil 指针必须被拒绝，而不是在首次 Target 方法
	// 调用时 panic。
	var typedNil *fakeTarget
	if _, err := New(ctx, typedNil, cfg, cron.Options{}); !errors.Is(err, ErrNilTarget) {
		t.Fatalf("typed-nil target err = %v, want ErrNilTarget", err)
	}
	unconfigured := newFakeTarget()
	unconfigured.configured = false
	if _, err := New(ctx, unconfigured, cfg, cron.Options{}); !errors.Is(err, ErrNoBackupTarget) {
		t.Fatalf("unconfigured target err = %v, want ErrNoBackupTarget", err)
	}
	segmentOnly := newFakeTarget()
	segmentOnly.snapshot = false
	if _, err := New(ctx, segmentOnly, cfg, cron.Options{}); !errors.Is(err, ErrSnapshotUnsupported) {
		t.Fatalf("segment-only target err = %v, want ErrSnapshotUnsupported", err)
	}
	if _, err := New(ctx, newFakeTarget(), Config{}, cron.Options{}); !errors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("empty schedule err = %v, want ErrInvalidSchedule", err)
	}
	if _, err := New(ctx, newFakeTarget(), Config{Schedule: "not a cron expression"}, cron.Options{}); !errors.Is(err, ErrInvalidSchedule) {
		t.Fatalf("bad schedule err = %v, want ErrInvalidSchedule", err)
	}
}

// TestNewAppliesConfig verifies defaults and job field wiring. | 验证默认值与任务
// 字段传递。
func TestNewAppliesConfig(t *testing.T) {
	ctx := context.Background()
	target := newFakeTarget()
	backup, err := New(ctx, target, Config{
		Schedule:      "@hourly",
		JobID:         "orders",
		Timeout:       2 * time.Minute,
		Retries:       2,
		RetryDelay:    time.Second,
		RetryBackoff:  2,
		MaxRetryDelay: 10 * time.Second,
		Jitter:        5 * time.Second,
		Singleton:     true,
	}, cron.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer stopScheduler(t, backup)
	if got := backup.JobID(); got != "orders" {
		t.Fatalf("JobID = %q, want orders", got)
	}
	snapshot, ok := backup.Cron().Get("orders")
	if !ok {
		t.Fatal("job is not registered")
	}
	if snapshot.Definition.Expression == "" ||
		snapshot.Definition.Task != "wal-backup:orders" ||
		snapshot.Definition.Name != "WAL backup orders" ||
		snapshot.Definition.Timeout != 2*time.Minute ||
		snapshot.Definition.Retries != 2 ||
		snapshot.Definition.RetryDelay != time.Second ||
		snapshot.Definition.RetryBackoff != 2 ||
		snapshot.Definition.MaxRetryDelay != 10*time.Second ||
		snapshot.Definition.Jitter != 5*time.Second ||
		!snapshot.Definition.Singleton {
		t.Fatalf("unexpected definition: %+v", snapshot.Definition)
	}
	if snapshot.Definition.Overlap != cron.SkipIfRunning {
		t.Fatalf("Overlap = %q, want skip", snapshot.Definition.Overlap)
	}
}

// TestTriggerRunsBackup verifies the manual trigger path and default job ID. |
// 验证手动触发路径与默认任务 ID。
func TestTriggerRunsBackup(t *testing.T) {
	ctx := context.Background()
	target := newFakeTarget()
	backup, err := New(ctx, target, Config{Schedule: "@daily"}, cron.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer stopScheduler(t, backup)
	if got := backup.JobID(); got != "wal-backup" {
		t.Fatalf("JobID = %q, want wal-backup", got)
	}
	if err := backup.Trigger(); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	waitRun(t, target)
	if got := target.runCount(); got != 1 {
		t.Fatalf("runs = %d, want 1", got)
	}
}

// TestScheduledBackupRuns verifies that the cron schedule actually fires. |
// 验证 cron 计划确实会触发备份。
func TestScheduledBackupRuns(t *testing.T) {
	ctx := context.Background()
	target := newFakeTarget()
	backup, err := New(ctx, target, Config{Schedule: "@every 200ms"}, cron.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer stopScheduler(t, backup)
	waitRun(t, target)
}

// TestBackupErrorIsRecorded verifies that BackupNow errors reach cron history. |
// 验证 BackupNow 错误进入 cron 运行历史。
func TestBackupErrorIsRecorded(t *testing.T) {
	ctx := context.Background()
	target := newFakeTarget()
	target.err = errors.New("backup target unavailable")
	backup, err := New(ctx, target, Config{Schedule: "@daily", Retries: 0}, cron.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer stopScheduler(t, backup)
	if err := backup.Trigger(); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	waitRun(t, target)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		history := backup.Cron().History(backup.JobID())
		if len(history) > 0 {
			if history[0].OK() || !strings.Contains(history[0].Err, "backup target unavailable") {
				t.Fatalf("history record = %+v, want failure containing target error", history[0])
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("backup failure did not appear in cron history")
}

// TestAttachAndRemove verifies attaching to an existing scheduler. | 验证附加到
// 既有调度器与移除。
func TestAttachAndRemove(t *testing.T) {
	ctx := context.Background()
	scheduler := cron.New(cron.Options{})
	target := newFakeTarget()
	job, err := Attach(ctx, scheduler, target, Config{Schedule: "@daily", JobID: "attached"})
	if err != nil {
		t.Fatal(err)
	}
	if got := job.ID(); got != "attached" {
		t.Fatalf("job ID = %q, want attached", got)
	}
	if err := scheduler.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := scheduler.Stop(stopCtx); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}()
	if err := job.Trigger(); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	waitRun(t, target)
	if _, ok := scheduler.Get("attached"); !ok {
		t.Fatal("attached job is missing")
	}
	if err := job.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := scheduler.Get("attached"); ok {
		t.Fatal("removed job is still present")
	}
	// Re-attaching after Remove is allowed. | Remove 之后可以重新附加。
	if _, err := Attach(ctx, scheduler, target, Config{Schedule: "@daily", JobID: "attached"}); err != nil {
		t.Fatalf("re-attach after Remove: %v", err)
	}
	if _, err := Attach(ctx, nil, target, Config{Schedule: "@daily"}); !errors.Is(err, ErrNilScheduler) {
		t.Fatalf("nil scheduler err = %v, want ErrNilScheduler", err)
	}
}

// TestAttachDuplicateKeepsHandler verifies that a rejected duplicate Attach does
// not redirect the existing job to another target. | 验证被拒绝的重复 Attach 不会
// 把既有任务重定向到另一个目标。
func TestAttachDuplicateKeepsHandler(t *testing.T) {
	ctx := context.Background()
	scheduler := cron.New(cron.Options{})
	first := newFakeTarget()
	job, err := Attach(ctx, scheduler, first, Config{Schedule: "@daily", JobID: "dup"})
	if err != nil {
		t.Fatal(err)
	}
	second := newFakeTarget()
	if _, err := Attach(ctx, scheduler, second, Config{Schedule: "@daily", JobID: "dup"}); !errors.Is(err, cron.ErrJobExists) {
		t.Fatalf("duplicate Attach err = %v, want cron.ErrJobExists", err)
	}
	if err := scheduler.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := scheduler.Stop(stopCtx); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}()
	if err := job.Trigger(); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	waitRun(t, first)
	if got := second.runCount(); got != 0 {
		t.Fatalf("duplicate target ran %d times, want 0", got)
	}
}
