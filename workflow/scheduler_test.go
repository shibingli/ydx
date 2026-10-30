package workflow_test

import (
	"context"
	"errors"
	"testing"
	"time"

	ydcron "github.com/shibingli/ydx/cron"
	"github.com/shibingli/ydx/workflow"
)

// TestSchedulerLifecycle covers start/stop idempotency. | TestSchedulerLifecycle 覆盖启动与停止的幂等性。
func TestSchedulerLifecycle(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	scheduler := workflow.NewScheduler(f.svc, 10*time.Millisecond, nil)
	if scheduler == nil {
		t.Fatal("NewScheduler 返回 nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("启动调度器失败: %v", err)
	}
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("重复启动应幂等: %v", err)
	}
	if err := scheduler.Stop(time.Second); err != nil {
		t.Fatalf("停止调度器失败: %v", err)
	}
	if err := scheduler.Stop(time.Second); err != nil {
		t.Fatalf("重复停止应幂等: %v", err)
	}
}

// TestSchedulerScansDueTimers covers a due timer fired by the scheduler loop. |
// TestSchedulerScansDueTimers 覆盖调度循环触发到期定时器。
func TestSchedulerScansDueTimers(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	catch := workflow.Node{
		ID: "wait", Type: workflow.NodeCatch, Name: "等待 | Wait",
		WaitKind: workflow.WaitTimer, WaitFor: "1m", Position: workflow.Position{X: 300, Y: 200},
	}
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{startNode(), catch, endNode("end")}
	design.Edges = []workflow.Edge{edge("e1", "start", "wait", ""), edge("e2", "wait", "end", "")}
	f.publishDefinition(t, "scheduler-timer", design)
	inst := f.start(t, "scheduler-timer", nil)

	f.clock.Advance(2 * time.Minute)
	scheduler := workflow.NewScheduler(f.svc, 5*time.Millisecond, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("启动调度器失败: %v", err)
	}
	defer func() { _ = scheduler.Stop(time.Second) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := f.instance(t, inst.ID); got.Status == workflow.InstanceCompleted {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("调度器未在期限内触发定时事件: %s", f.instance(t, inst.ID).Status)
}

// waitForInstanceStatus polls until the instance reaches want. |
// waitForInstanceStatus 轮询直到实例到达期望状态。
func waitForInstanceStatus(t *testing.T, f *fixture, id, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.instance(t, id).Status == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("实例状态 = %s, 期望 %s", f.instance(t, id).Status, want)
}

// TestSchedulerSharedCron covers mounting the scan job on a caller-owned cron
// scheduler. | TestSchedulerSharedCron 覆盖把扫描任务挂到调用方拥有的 cron 调度器。
func TestSchedulerSharedCron(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	catch := workflow.Node{
		ID: "wait", Type: workflow.NodeCatch, Name: "等待 | Wait",
		WaitKind: workflow.WaitTimer, WaitFor: "1m", Position: workflow.Position{X: 300, Y: 200},
	}
	design := workflow.DefaultDesign()
	design.Nodes = []workflow.Node{startNode(), catch, endNode("end")}
	design.Edges = []workflow.Edge{edge("e1", "start", "wait", ""), edge("e2", "wait", "end", "")}
	f.publishDefinition(t, "shared-timer", design)
	inst := f.start(t, "shared-timer", nil)
	f.clock.Advance(2 * time.Minute)

	ctx := context.Background()
	shared := ydcron.New(ydcron.Options{Concurrency: 1, QueueSize: 1, HistoryLimit: -1})
	scheduler := workflow.NewScheduler(f.svc, 5*time.Millisecond, nil, workflow.WithCronScheduler(shared))
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("启动共享调度器失败: %v", err)
	}
	if _, ok := shared.Get("workflow-scan"); !ok {
		t.Fatal("扫描任务未注册到共享调度器")
	}
	if err := shared.Start(ctx); err != nil {
		t.Fatalf("启动共享 cron 调度器失败: %v", err)
	}
	waitForInstanceStatus(t, f, inst.ID, workflow.InstanceCompleted)

	if err := scheduler.Stop(time.Second); err != nil {
		t.Fatalf("停止共享调度失败: %v", err)
	}
	if _, ok := shared.Get("workflow-scan"); ok {
		t.Fatal("扫描任务未从共享调度器移除")
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shared.Stop(stopCtx); err != nil {
		t.Fatalf("停止共享 cron 调度器失败: %v", err)
	}
}

// TestSchedulerSharedOwnership proves Stop never stops the caller-owned
// scheduler. | TestSchedulerSharedOwnership 证明 Stop 不会停止调用方拥有的调度器。
func TestSchedulerSharedOwnership(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	ctx := context.Background()
	shared := ydcron.New(ydcron.Options{Concurrency: 1, QueueSize: 1, HistoryLimit: -1})
	scheduler := workflow.NewScheduler(f.svc, time.Second, nil, workflow.WithCronScheduler(shared))
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("启动共享调度器失败: %v", err)
	}
	if err := scheduler.Start(ctx); err != nil {
		t.Fatalf("重复启动应幂等: %v", err)
	}
	if err := scheduler.Stop(time.Second); err != nil {
		t.Fatalf("停止共享调度失败: %v", err)
	}
	if err := scheduler.Stop(time.Second); err != nil {
		t.Fatalf("重复停止应幂等: %v", err)
	}

	job := &ydcron.Job{
		ID:       "app-job",
		Schedule: ydcron.Interval(time.Hour),
		Handler:  func(context.Context, *ydcron.Job) error { return nil },
	}
	if err := shared.Add(ctx, job); err != nil {
		t.Fatalf("共享调度器已被误停: %v", err)
	}
	if err := shared.Start(ctx); err != nil {
		t.Fatalf("共享调度器无法启动: %v", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shared.Stop(stopCtx); err != nil {
		t.Fatalf("停止共享调度器失败: %v", err)
	}
}

// TestSchedulerSharedJobID covers job-id collisions and overrides. |
// TestSchedulerSharedJobID 覆盖任务 ID 冲突与覆盖。
func TestSchedulerSharedJobID(t *testing.T) {
	f := newFixture(t)
	defer f.close()

	ctx := context.Background()
	shared := ydcron.New(ydcron.Options{Concurrency: 1, QueueSize: 1, HistoryLimit: -1})
	first := workflow.NewScheduler(f.svc, time.Second, nil, workflow.WithCronScheduler(shared))
	if err := first.Start(ctx); err != nil {
		t.Fatalf("首个共享调度器启动失败: %v", err)
	}
	second := workflow.NewScheduler(f.svc, time.Second, nil, workflow.WithCronScheduler(shared))
	if err := second.Start(ctx); !errors.Is(err, ydcron.ErrJobExists) {
		t.Fatalf("重复任务 ID 错误 = %v, 期望 ErrJobExists", err)
	}
	third := workflow.NewScheduler(f.svc, time.Second, nil,
		workflow.WithCronScheduler(shared), workflow.WithScanJobID("workflow-scan-2"))
	if err := third.Start(ctx); err != nil {
		t.Fatalf("自定义任务 ID 启动失败: %v", err)
	}
	for _, scheduler := range []*workflow.Scheduler{first, third} {
		if err := scheduler.Stop(time.Second); err != nil {
			t.Fatalf("卸载共享任务失败: %v", err)
		}
	}
}
