package cron

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestMemoryLocker covers exclusivity, owner-safe unlock and expiry. |
// TestMemoryLocker 覆盖互斥、持有者安全释放与过期。
func TestMemoryLocker(t *testing.T) {
	locker := NewMemoryLocker()
	ctx := context.Background()

	first, ok, err := locker.TryLock(ctx, "key", time.Minute)
	if err != nil || !ok {
		t.Fatalf("TryLock = %v, %v | 首次加锁失败", ok, err)
	}
	if second, ok, _ := locker.TryLock(ctx, "key", time.Minute); ok {
		_ = second.Unlock(ctx)
		t.Fatal("second TryLock succeeded | 第二次加锁不应成功")
	}
	refresher, ok := first.(LockRefresher)
	if !ok {
		t.Fatal("memory lock does not implement LockRefresher | 内存锁未实现续租")
	}
	if refreshed, err := refresher.Refresh(ctx, time.Minute); err != nil || !refreshed {
		t.Fatalf("Refresh = %v, %v | 续租失败", refreshed, err)
	}
	if err := first.Unlock(ctx); err != nil {
		t.Fatalf("Unlock: %v | 释放失败", err)
	}
	third, ok, _ := locker.TryLock(ctx, "key", time.Minute)
	if !ok {
		t.Fatal("TryLock after Unlock failed | 释放后加锁失败")
	}
	_ = third.Unlock(ctx)

	expiring, ok, _ := locker.TryLock(ctx, "expiring", 20*time.Millisecond)
	if !ok {
		t.Fatal("TryLock(expiring) failed | 加锁失败")
	}
	time.Sleep(30 * time.Millisecond)
	expiringRefresher := expiring.(LockRefresher)
	if refreshed, _ := expiringRefresher.Refresh(ctx, 20*time.Millisecond); refreshed {
		t.Fatal("expired lock refreshed | 过期锁仍可续租")
	}
	replacement, ok, _ := locker.TryLock(ctx, "expiring", time.Minute)
	if !ok {
		t.Fatal("expired lock was not reclaimable | 过期锁未被回收")
	}
	// The stale owner must not release the replacement's claim. | 旧持有者不得释放新持有者的锁。
	if err := expiring.Unlock(ctx); err != nil {
		t.Fatalf("stale Unlock: %v | 旧锁释放出错", err)
	}
	if other, ok, _ := locker.TryLock(ctx, "expiring", time.Minute); ok {
		_ = other.Unlock(ctx)
		t.Fatal("stale Unlock removed the replacement | 旧锁释放影响了新锁")
	}
	_ = replacement.Unlock(ctx)
}

// denyLocker never grants a claim. | denyLocker 永不授予锁。
type denyLocker struct{}

// TryLock always reports a lost race. | TryLock 始终报告竞争失败。
func (denyLocker) TryLock(context.Context, string, time.Duration) (Lock, bool, error) {
	return nil, false, nil
}

// errorLocker fails every claim. | errorLocker 每次加锁都失败。
type errorLocker struct{}

// TryLock always returns an error. | TryLock 始终返回错误。
func (errorLocker) TryLock(context.Context, string, time.Duration) (Lock, bool, error) {
	return nil, false, errors.New("lock backend down")
}

// TestDistributedSingleton verifies one claim per fire across schedulers. |
// TestDistributedSingleton 验证多个调度器每次触发只有一个执行。
func TestDistributedSingleton(t *testing.T) {
	locker := NewMemoryLocker()
	at := time.Now().Add(80 * time.Millisecond)
	var calls atomic.Int32
	handler := func(context.Context, *Job) error {
		calls.Add(1)
		return nil
	}
	options := Options{Concurrency: 2, Locker: locker, Namespace: "cluster", LockTTL: time.Second}
	first := New(options)
	second := New(options)
	for _, sch := range []*Scheduler{first, second} {
		job := &Job{ID: "shared", Schedule: Once(at), Handler: handler, Singleton: true}
		if err := sch.Add(context.Background(), job); err != nil {
			t.Fatalf("Add: %v | 新增失败", err)
		}
		if err := sch.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v | 启动失败", err)
		}
	}
	waitFor(t, 3*time.Second, func() bool { return calls.Load() > 0 }, "singleton job did not run | Singleton 任务未运行")
	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("singleton ran %d times, want 1 | Singleton 运行次数不符", got)
	}
	stopScheduler(t, first)
	stopScheduler(t, second)
}

// TestDistributedBroadcast verifies non-singleton jobs run on every node. |
// TestDistributedBroadcast 验证非 Singleton 任务在每个节点运行。
func TestDistributedBroadcast(t *testing.T) {
	locker := NewMemoryLocker()
	at := time.Now().Add(80 * time.Millisecond)
	var calls atomic.Int32
	handler := func(context.Context, *Job) error {
		calls.Add(1)
		return nil
	}
	options := Options{Concurrency: 2, Locker: locker, Namespace: "broadcast", LockTTL: time.Second}
	first := New(options)
	second := New(options)
	for _, sch := range []*Scheduler{first, second} {
		job := &Job{ID: "shared", Schedule: Once(at), Handler: handler}
		if err := sch.Add(context.Background(), job); err != nil {
			t.Fatalf("Add: %v | 新增失败", err)
		}
		if err := sch.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v | 启动失败", err)
		}
	}
	waitFor(t, 3*time.Second, func() bool { return calls.Load() >= 2 }, "broadcast job did not run on both nodes | 广播任务未在两个节点运行")
	stopScheduler(t, first)
	stopScheduler(t, second)
}

// TestLockerDenied records a skipped fire when another node owns it. |
// TestLockerDenied 验证其它节点持锁时记录跳过。
func TestLockerDenied(t *testing.T) {
	var calls atomic.Int32
	sch := New(Options{Locker: denyLocker{}})
	job := &Job{
		ID:        "denied",
		Schedule:  Once(time.Now().Add(10 * time.Millisecond)),
		Singleton: true,
		Handler: func(context.Context, *Job) error {
			calls.Add(1)
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
		snapshot, _ := sch.Get(job.ID)
		return snapshot.Skipped > 0
	}, "denied fire was not counted | 未记录被拒绝的触发")
	if got := calls.Load(); got != 0 {
		t.Fatalf("handler ran %d times, want 0 | 处理器不应运行", got)
	}
	stopScheduler(t, sch)
}

// TestLockerError records an operational failure without running the handler. |
// TestLockerError 验证锁错误记录为运行失败且不执行处理器。
func TestLockerError(t *testing.T) {
	var calls atomic.Int32
	sch := New(Options{Locker: errorLocker{}, HistoryLimit: 2})
	job := &Job{
		ID:        "broken-lock",
		Schedule:  Once(time.Now().Add(10 * time.Millisecond)),
		Singleton: true,
		Handler: func(context.Context, *Job) error {
			calls.Add(1)
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
		snapshot, _ := sch.Get(job.ID)
		return snapshot.Failures > 0
	}, "lock error was not counted | 锁错误未计数")
	if got := calls.Load(); got != 0 {
		t.Fatalf("handler ran %d times, want 0 | 处理器不应运行", got)
	}
	history := sch.History(job.ID)
	if len(history) == 0 || history[0].Attempts != 0 {
		t.Fatalf("history = %+v, want an attempt-free failure | 失败记录不符", history)
	}
	var wrapped error = errors.New("cron: lock operation failed")
	_ = wrapped
	stopScheduler(t, sch)
}
