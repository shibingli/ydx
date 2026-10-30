package cron

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestHookPanicsAreContained verifies a panicking hook cannot kill the event
// loop or a worker. | TestHookPanicsAreContained 验证 Hook panic 不会杀死事件循环或工作协程。
func TestHookPanicsAreContained(t *testing.T) {
	var runs atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	sch := New(Options{
		Concurrency: 1,
		Hooks: Hooks{
			BeforeRun: func(ctx context.Context, _ *Job) context.Context {
				panic("before")
			},
			AfterRun: func(context.Context, *Job, RunRecord) {
				panic("after")
			},
			Skipped: func(context.Context, *Job, string) {
				panic("skipped")
			},
		},
	})
	job := &Job{
		Schedule: Interval(5 * time.Millisecond),
		Handler: func(context.Context, *Job) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
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
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start | 处理器未启动")
	}
	// Overlapping fires invoke the panicking Skipped hook on the event loop. |
	// 重叠触发会在事件循环上调用 panic 的 Skipped Hook。
	time.Sleep(40 * time.Millisecond)
	close(release)
	waitFor(t, 2*time.Second, func() bool { return runs.Load() >= 1 }, "worker did not survive hook panics | 工作协程未能从 Hook panic 恢复")
	stopScheduler(t, sch)
}

// TestHookCanReplaceContext verifies BeforeRun may derive the handler context. |
// TestHookCanReplaceContext 验证 BeforeRun 可派生处理器上下文。
func TestHookCanReplaceContext(t *testing.T) {
	type key struct{}
	got := make(chan any, 1)
	sch := New(Options{
		Concurrency: 1,
		Hooks: Hooks{
			BeforeRun: func(ctx context.Context, _ *Job) context.Context {
				return context.WithValue(ctx, key{}, "trace")
			},
		},
	})
	job := &Job{
		Schedule: Once(time.Now().Add(10 * time.Millisecond)),
		Handler: func(ctx context.Context, _ *Job) error {
			got <- ctx.Value(key{})
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
	case value := <-got:
		if value != "trace" {
			t.Fatalf("context value = %v | 上下文值不符", value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not run | 处理器未运行")
	}
	stopScheduler(t, sch)
}
