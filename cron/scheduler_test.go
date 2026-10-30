package cron

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor polls cond until it is true or the deadline passes. | waitFor 轮询 cond 直到成立或超时。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout: %s | 超时：%s", message, message)
		}
		time.Sleep(time.Millisecond)
	}
}

// stopScheduler stops sch with a bounded context. | stopScheduler 用带超时的上下文停止 sch。
func stopScheduler(t *testing.T, sch *Scheduler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sch.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v | 停止失败", err)
	}
}

// TestLifecycle covers add, get, list, pause, resume, update and remove. |
// TestLifecycle 覆盖新增、查询、列举、暂停、恢复、更新与删除。
func TestLifecycle(t *testing.T) {
	fixed := utc(2026, time.January, 1, 0, 0, 0)
	sch := New(Options{Now: func() time.Time { return fixed }})
	ctx := context.Background()

	job := &Job{
		Name:     "hourly",
		Schedule: Interval(time.Hour),
		Handler:  func(context.Context, *Job) error { return nil },
	}
	if err := sch.Add(ctx, job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if job.ID == "" {
		t.Fatal("Add did not assign an ID | Add 未生成 ID")
	}

	snapshot, ok := sch.Get(job.ID)
	if !ok {
		t.Fatalf("Get(%q) not found | 未找到任务", job.ID)
	}
	if snapshot.Name != "hourly" || snapshot.Disabled {
		t.Fatalf("unexpected snapshot: %+v | 快照不符", snapshot)
	}
	if snapshot.Next.IsZero() {
		t.Fatal("Next is zero | 下次触发时间为零")
	}
	if got := sch.List(); len(got) != 1 {
		t.Fatalf("List length = %d, want 1 | 列表长度不符", len(got))
	}

	if err := sch.Pause(ctx, job.ID); err != nil {
		t.Fatalf("Pause: %v | 暂停失败", err)
	}
	snapshot, _ = sch.Get(job.ID)
	if !snapshot.Disabled || !snapshot.Next.IsZero() {
		t.Fatalf("paused snapshot = %+v | 暂停状态不符", snapshot)
	}
	if err := sch.Resume(ctx, job.ID); err != nil {
		t.Fatalf("Resume: %v | 恢复失败", err)
	}
	snapshot, _ = sch.Get(job.ID)
	if snapshot.Disabled || snapshot.Next.IsZero() {
		t.Fatalf("resumed snapshot = %+v | 恢复状态不符", snapshot)
	}

	job.Name = "every-two-hours"
	job.Schedule = Interval(2 * time.Hour)
	if err := sch.Update(ctx, job); err != nil {
		t.Fatalf("Update: %v | 更新失败", err)
	}
	snapshot, _ = sch.Get(job.ID)
	if snapshot.Name != "every-two-hours" {
		t.Fatalf("updated name = %q | 更新后名称不符", snapshot.Name)
	}

	if err := sch.Remove(ctx, job.ID); err != nil {
		t.Fatalf("Remove: %v | 删除失败", err)
	}
	if _, ok := sch.Get(job.ID); ok {
		t.Fatal("job still exists after Remove | 删除后任务仍存在")
	}
	if err := sch.Remove(ctx, job.ID); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("Remove missing = %v, want ErrJobNotFound | 删除不存在任务错误不符", err)
	}
}

// TestListSortedAndCacheInvalidated requires List to stay ordered by id and to
// observe adds and removes after the first call. | TestListSortedAndCacheInvalidated
// 要求 List 按 ID 排序，并在首次调用后仍能观察到新增与删除。
func TestListSortedAndCacheInvalidated(t *testing.T) {
	scheduler := New(Options{Concurrency: 1, HistoryLimit: -1})
	ctx := context.Background()
	handler := func(context.Context, *Job) error { return nil }
	for _, id := range []string{"b", "a", "c"} {
		if err := scheduler.Add(ctx, &Job{ID: id, Schedule: Interval(time.Hour), Handler: handler}); err != nil {
			t.Fatalf("Add(%q): %v | 新增失败", id, err)
		}
	}
	assertIDs := func(want ...string) {
		t.Helper()
		snapshots := scheduler.List()
		if len(snapshots) != len(want) {
			t.Fatalf("List length = %d, want %d | 列表长度不符", len(snapshots), len(want))
		}
		for index, id := range want {
			if snapshots[index].ID != id {
				t.Fatalf("List[%d] = %q, want %q | 列表顺序不符", index, snapshots[index].ID, id)
			}
		}
	}
	assertIDs("a", "b", "c")
	assertIDs("a", "b", "c")
	if err := scheduler.Remove(ctx, "b"); err != nil {
		t.Fatalf("Remove: %v | 删除失败", err)
	}
	assertIDs("a", "c")
	if err := scheduler.Add(ctx, &Job{ID: "aa", Schedule: Interval(time.Hour), Handler: handler}); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	assertIDs("a", "aa", "c")
}

// TestAddValidation covers the declared validation sentinels. | TestAddValidation 覆盖新增校验的哨兵错误。
func TestAddValidation(t *testing.T) {
	sch := New(Options{})
	ctx := context.Background()
	handler := func(context.Context, *Job) error { return nil }

	if err := sch.Add(ctx, nil); !errors.Is(err, ErrNilJob) {
		t.Fatalf("Add(nil) = %v, want ErrNilJob | nil 任务错误不符", err)
	}
	if err := sch.Add(ctx, &Job{Handler: handler}); !errors.Is(err, ErrNilSchedule) {
		t.Fatalf("Add(no schedule) = %v, want ErrNilSchedule | 缺少调度错误不符", err)
	}
	if err := sch.Add(ctx, &Job{Schedule: Interval(time.Hour)}); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("Add(no handler) = %v, want ErrNilHandler | 缺少处理器错误不符", err)
	}
	if err := sch.Add(ctx, &Job{Schedule: Once(time.Now().Add(-time.Second)), Handler: handler}); !errors.Is(err, ErrNoFutureRun) {
		t.Fatalf("Add(past once) = %v, want ErrNoFutureRun | 过去的一次性任务错误不符", err)
	}

	job := &Job{ID: "dup", Schedule: Interval(time.Hour), Handler: handler}
	if err := sch.Add(ctx, job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	duplicate := &Job{ID: "dup", Schedule: Interval(time.Hour), Handler: handler}
	if err := sch.Add(ctx, duplicate); !errors.Is(err, ErrJobExists) {
		t.Fatalf("duplicate Add = %v, want ErrJobExists | 重复任务错误不符", err)
	}
}

// TestScheduledExecution runs a job through the real timer loop. | TestScheduledExecution 通过真实定时器循环运行任务。
func TestScheduledExecution(t *testing.T) {
	var runs atomic.Int32
	sch := New(Options{Concurrency: 2})
	job := &Job{
		Schedule: Interval(10 * time.Millisecond),
		Handler: func(context.Context, *Job) error {
			runs.Add(1)
			return nil
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	waitFor(t, 2*time.Second, func() bool { return runs.Load() >= 3 }, "job did not run three times | 任务未运行三次")
	stopScheduler(t, sch)

	snapshot, ok := sch.Get(job.ID)
	if !ok || snapshot.Runs < 3 {
		t.Fatalf("snapshot = %+v, ok = %v | 运行统计不符", snapshot, ok)
	}
	if stats := sch.Stats(); stats.Runs < 3 {
		t.Fatalf("Stats.Runs = %d | 全局统计不符", stats.Runs)
	}
}

// TestPauseAndResume verifies a paused job stops firing until resumed. | TestPauseAndResume 验证暂停后停止触发、恢复后继续。
func TestPauseAndResume(t *testing.T) {
	var runs atomic.Int32
	sch := New(Options{Concurrency: 2})
	job := &Job{
		Schedule: Interval(5 * time.Millisecond),
		Handler: func(context.Context, *Job) error {
			runs.Add(1)
			return nil
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	waitFor(t, 2*time.Second, func() bool { return runs.Load() >= 2 }, "job did not start | 任务未启动")

	if err := sch.Pause(context.Background(), job.ID); err != nil {
		t.Fatalf("Pause: %v | 暂停失败", err)
	}
	time.Sleep(20 * time.Millisecond)
	before := runs.Load()
	time.Sleep(80 * time.Millisecond)
	if after := runs.Load(); after != before {
		t.Fatalf("paused job ran: %d -> %d | 暂停后仍在运行", before, after)
	}

	if err := sch.Resume(context.Background(), job.ID); err != nil {
		t.Fatalf("Resume: %v | 恢复失败", err)
	}
	waitFor(t, 2*time.Second, func() bool { return runs.Load() > before }, "resumed job did not run | 恢复后未运行")
	stopScheduler(t, sch)
}

// TestTrigger verifies a manual run works even while the job is paused. |
// TestTrigger 验证任务暂停时仍可手动触发。
func TestTrigger(t *testing.T) {
	var runs atomic.Int32
	sch := New(Options{Concurrency: 1})
	job := &Job{
		Schedule: Interval(time.Hour),
		Disabled: true,
		Handler: func(context.Context, *Job) error {
			runs.Add(1)
			return nil
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	if err := sch.Trigger(job.ID); err != nil {
		t.Fatalf("Trigger: %v | 手动触发失败", err)
	}
	waitFor(t, 2*time.Second, func() bool { return runs.Load() == 1 }, "manual run did not happen | 手动触发未执行")
	if err := sch.Trigger("missing"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("Trigger(missing) = %v, want ErrJobNotFound | 未知任务错误不符", err)
	}
	stopScheduler(t, sch)
}

// TestTimeout verifies a handler observes cancellation at the job deadline. |
// TestTimeout 验证处理器在任务超时时观察到取消。
func TestTimeout(t *testing.T) {
	canceled := make(chan struct{})
	sch := New(Options{Concurrency: 1})
	job := &Job{
		Schedule: Once(time.Now().Add(10 * time.Millisecond)),
		Timeout:  30 * time.Millisecond,
		Handler: func(ctx context.Context, _ *Job) error {
			<-ctx.Done()
			close(canceled)
			return ctx.Err()
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not canceled | 处理器未被取消")
	}
	waitFor(t, 2*time.Second, func() bool {
		history := sch.History(job.ID)
		return len(history) > 0 && history[0].Err != ""
	}, "timeout was not recorded | 超时未记录")
	stopScheduler(t, sch)
}

// TestRetry verifies retries run until success and the attempt count is recorded. |
// TestRetry 验证重试直到成功并记录尝试次数。
func TestRetry(t *testing.T) {
	var calls atomic.Int32
	sch := New(Options{Concurrency: 1})
	job := &Job{
		Schedule:     Once(time.Now().Add(10 * time.Millisecond)),
		Retries:      2,
		RetryDelay:   time.Millisecond,
		RetryBackoff: 1,
		Handler: func(context.Context, *Job) error {
			if calls.Add(1) < 3 {
				return errors.New("transient")
			}
			return nil
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		history := sch.History(job.ID)
		return len(history) > 0 && history[0].Err == "" && history[0].Attempts == 3
	}, "retry did not succeed on the third attempt | 重试未在第三次成功")
	if got := calls.Load(); got != 3 {
		t.Fatalf("handler calls = %d, want 3 | 处理器调用次数不符", got)
	}
	stopScheduler(t, sch)
}

// TestPanicRecovery verifies a panic becomes a retryable failure. | TestPanicRecovery 验证 panic 转为可重试失败。
func TestPanicRecovery(t *testing.T) {
	var calls atomic.Int32
	sch := New(Options{Concurrency: 1})
	job := &Job{
		Schedule:     Once(time.Now().Add(10 * time.Millisecond)),
		Retries:      1,
		RetryDelay:   time.Millisecond,
		RetryBackoff: 1,
		Handler: func(context.Context, *Job) error {
			if calls.Add(1) == 1 {
				panic("boom")
			}
			return nil
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		history := sch.History(job.ID)
		return len(history) > 0 && history[0].Err == "" && history[0].Attempts == 2
	}, "panic was not retried | panic 未重试")
	if got := calls.Load(); got != 2 {
		t.Fatalf("handler calls = %d, want 2 | 处理器调用次数不符", got)
	}
	stopScheduler(t, sch)
}

// TestOverlapSkip verifies the default policy never runs a job concurrently with itself. |
// TestOverlapSkip 验证默认策略不会让同一任务并发运行。
func TestOverlapSkip(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	sch := New(Options{Concurrency: 4})
	job := &Job{
		Schedule: Interval(5 * time.Millisecond),
		Handler: func(context.Context, *Job) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start | 处理器未启动")
	}
	time.Sleep(50 * time.Millisecond)
	snapshot, _ := sch.Get(job.ID)
	if snapshot.Skipped == 0 {
		t.Fatalf("Skipped = 0, want > 0 | 未记录跳过")
	}
	close(release)
	stopScheduler(t, sch)
}

// TestOverlapAllow verifies the allow policy permits concurrent runs. |
// TestOverlapAllow 验证允许策略支持并发运行。
func TestOverlapAllow(t *testing.T) {
	var concurrent atomic.Int32
	var peak atomic.Int32
	two := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	sch := New(Options{Concurrency: 4})
	job := &Job{
		Schedule: Interval(5 * time.Millisecond),
		Overlap:  AllowOverlap,
		Handler: func(context.Context, *Job) error {
			current := concurrent.Add(1)
			for {
				old := peak.Load()
				if current <= old || peak.CompareAndSwap(old, current) {
					break
				}
			}
			if current >= 2 {
				once.Do(func() { close(two) })
			}
			<-release
			concurrent.Add(-1)
			return nil
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	select {
	case <-two:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not run concurrently | 处理器未并发运行")
	}
	close(release)
	stopScheduler(t, sch)
}

// TestHistory verifies the bounded newest-first run records. | TestHistory 验证有界且最新的运行记录。
func TestHistory(t *testing.T) {
	sch := New(Options{Concurrency: 1, HistoryLimit: 3})
	job := &Job{
		Schedule: Interval(time.Hour),
		Handler:  func(context.Context, *Job) error { return nil },
	}
	ctx := context.Background()
	if err := sch.Add(ctx, job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(ctx); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	for i := 1; i <= 5; i++ {
		if err := sch.Trigger(job.ID); err != nil {
			t.Fatalf("Trigger: %v | 手动触发失败", err)
		}
		waitFor(t, 2*time.Second, func() bool {
			snapshot, _ := sch.Get(job.ID)
			return snapshot.Runs == uint64(i) && !snapshot.Running
		}, "run was not completed | 运行未完成")
	}
	history := sch.History(job.ID)
	if len(history) != 3 {
		t.Fatalf("history length = %d, want 3 | 历史长度不符", len(history))
	}
	for i := 1; i < len(history); i++ {
		if history[i].Started.After(history[i-1].Started) {
			t.Fatalf("history is not newest first | 历史未按最新优先排序")
		}
	}
	if history[0].JobID != job.ID || history[0].Trigger != TriggerManual {
		t.Fatalf("unexpected record: %+v | 运行记录不符", history[0])
	}
	if got := sch.History("missing"); got != nil {
		t.Fatalf("History(missing) = %v, want nil | 未知任务历史应返回 nil", got)
	}
	stopScheduler(t, sch)
}

// TestSnapshotLastError verifies the last error is visible after a failure and
// cleared by the next successful run. | TestSnapshotLastError 验证失败后可见最后错误，
// 并在下一次成功运行后清空。
func TestSnapshotLastError(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	sch := New(Options{Concurrency: 1, HistoryLimit: 2})
	job := &Job{
		Schedule: Interval(time.Hour),
		Handler: func(context.Context, *Job) error {
			if fail.Swap(false) {
				return errors.New("boom")
			}
			return nil
		},
	}
	ctx := context.Background()
	if err := sch.Add(ctx, job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(ctx); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	triggerAndWait := func(runs uint64) Snapshot {
		t.Helper()
		if err := sch.Trigger(job.ID); err != nil {
			t.Fatalf("Trigger: %v | 手动触发失败", err)
		}
		waitFor(t, 2*time.Second, func() bool {
			snapshot, _ := sch.Get(job.ID)
			return snapshot.Runs == runs && !snapshot.Running
		}, "run did not complete | 运行未完成")
		snapshot, _ := sch.Get(job.ID)
		return snapshot
	}
	if snapshot := triggerAndWait(1); snapshot.LastError != "boom" {
		t.Fatalf("LastError = %q, want boom | 最后错误不符", snapshot.LastError)
	}
	if snapshot := triggerAndWait(2); snapshot.LastError != "" {
		t.Fatalf("LastError = %q, want empty | 成功运行后最后错误未清空", snapshot.LastError)
	}
	stopScheduler(t, sch)
}

// TestDisabledHistory verifies a negative history limit disables record keeping. |
// TestDisabledHistory 验证负的历史上限关闭记录。
func TestDisabledHistory(t *testing.T) {
	sch := New(Options{Concurrency: 1, HistoryLimit: -1})
	job := &Job{
		Schedule: Interval(time.Hour),
		Handler:  func(context.Context, *Job) error { return nil },
	}
	ctx := context.Background()
	if err := sch.Add(ctx, job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(ctx); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	if err := sch.Trigger(job.ID); err != nil {
		t.Fatalf("Trigger: %v | 手动触发失败", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		snapshot, _ := sch.Get(job.ID)
		return snapshot.Runs == 1 && !snapshot.Running
	}, "run was not completed | 运行未完成")
	if got := sch.History(job.ID); got != nil {
		t.Fatalf("History = %v, want nil | 历史应被禁用", got)
	}
	stopScheduler(t, sch)
}

// TestRunGracefulShutdown verifies Run drains in-flight handlers instead of
// canceling them the moment the caller's context ends. |
// TestRunGracefulShutdown 验证 Run 会等待在途处理器，而不是在调用方上下文结束时立即取消。
func TestRunGracefulShutdown(t *testing.T) {
	var canceled, completed atomic.Bool
	started := make(chan struct{})
	var once sync.Once
	sch := New(Options{Concurrency: 1, ShutdownTimeout: time.Second})
	job := &Job{
		Schedule: Interval(10 * time.Millisecond),
		Handler: func(ctx context.Context, _ *Job) error {
			once.Do(func() { close(started) })
			select {
			case <-ctx.Done():
				canceled.Store(true)
				return ctx.Err()
			case <-time.After(30 * time.Millisecond):
				completed.Store(true)
				return nil
			}
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sch.Run(runCtx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start | 处理器未启动")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v | 运行返回错误", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return | Run 未返回")
	}
	if canceled.Load() {
		t.Fatal("Run canceled the handler instead of draining it | Run 未等待在途处理器")
	}
	if !completed.Load() {
		t.Fatal("handler did not complete | 处理器未完成")
	}
}

// TestStartStop verifies the scheduler lifecycle sentinels and graceful stop. |
// TestStartStop 验证调度器生命周期的哨兵错误与优雅停止。
func TestStartStop(t *testing.T) {
	sch := New(Options{ShutdownTimeout: 20 * time.Millisecond})
	if err := sch.Stop(context.Background()); err != nil {
		t.Fatalf("Stop before Start = %v, want nil | 启动前停止应无错误", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	if err := sch.Start(context.Background()); !errors.Is(err, ErrSchedulerStarted) {
		t.Fatalf("second Start = %v, want ErrSchedulerStarted | 重复启动错误不符", err)
	}

	blocked := make(chan struct{})
	var started sync.WaitGroup
	started.Add(1)
	job := &Job{
		Schedule: Interval(5 * time.Millisecond),
		Handler: func(ctx context.Context, _ *Job) error {
			started.Done()
			<-ctx.Done()
			close(blocked)
			return ctx.Err()
		},
	}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	started.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := sch.Stop(ctx); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Stop with blocked handler = %v, want ErrShutdownTimeout | 强制停止错误不符", err)
	}
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not canceled | 处理器未被取消")
	}
	if err := sch.Start(context.Background()); !errors.Is(err, ErrSchedulerClosed) {
		t.Fatalf("Start after Stop = %v, want ErrSchedulerClosed | 停止后启动错误不符", err)
	}
}
