package workflow

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	wf "github.com/shibingli/ydx/workflow"
	"github.com/shibingli/ydx/workflow/gormstore"
	gormlib "gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	// benchTenant is the tenant used by every benchmark. | benchTenant 是所有基准使用的租户。
	benchTenant = "bench"
	// benchActor is the initiator id. | benchActor 是发起人 ID。
	benchActor = "bench-user"
	// benchKey is the published definition key. | benchKey 是已发布定义的键。
	benchKey = "bench"
)

// newService builds a service backed by a temporary SQLite database. |
// newService 构建以临时 SQLite 数据库为存储的服务。
func newService(b *testing.B) (*wf.Service, func()) {
	b.Helper()
	dsn := fmt.Sprintf("file:%s?_txlock=immediate&_pragma=busy_timeout(5000)",
		filepath.Join(b.TempDir(), "bench.db"))
	db, err := gormlib.Open(sqlite.Open(dsn), &gormlib.Config{
		Logger:         logger.Discard,
		TranslateError: true,
	})
	if err != nil {
		b.Fatalf("open test database: %v", err)
	}
	if err := gormstore.Migrate(context.Background(), db); err != nil {
		b.Fatalf("migrate test database: %v", err)
	}
	store, err := gormstore.New(db)
	if err != nil {
		b.Fatalf("build store: %v", err)
	}
	svc, err := wf.New(store, wf.Deps{Options: wf.DefaultOptions()})
	if err != nil {
		b.Fatalf("build service: %v", err)
	}
	return svc, func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	}
}

// publish creates and publishes the smallest start → end design. |
// publish 创建并发布最小的开始 → 结束设计。
func publish(b *testing.B, svc *wf.Service) {
	b.Helper()
	ctx := context.Background()
	definition, err := svc.CreateDefinition(ctx, benchTenant, benchActor, wf.DefinitionInput{
		Key: benchKey, Name: "bench",
	})
	if err != nil {
		b.Fatalf("create definition: %v", err)
	}
	design := wf.DefaultDesign()
	design.Nodes = []wf.Node{
		{ID: "start", Type: wf.NodeStart, Name: "start", Position: wf.Position{X: 60, Y: 200}},
		{ID: "end", Type: wf.NodeEnd, Name: "end", Position: wf.Position{X: 700, Y: 200}},
	}
	design.Edges = []wf.Edge{{ID: "e1", Source: "start", Target: "end"}}
	version, err := svc.CreateVersion(ctx, benchTenant, definition.ID, benchActor, wf.VersionInput{
		Design: design,
	})
	if err != nil {
		b.Fatalf("create version: %v", err)
	}
	if _, err := svc.PublishVersion(ctx, benchTenant, version.ID, benchActor, "bench"); err != nil {
		b.Fatalf("publish version: %v", err)
	}
}

// BenchmarkSchedulerStartStop measures the lifecycle of a private cron-backed
// scheduler. | BenchmarkSchedulerStartStop 测量私有 cron 调度器的启停生命周期。
func BenchmarkSchedulerStartStop(b *testing.B) {
	svc, closeService := newService(b)
	defer closeService()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheduler := wf.NewScheduler(svc, time.Hour, nil)
		if err := scheduler.Start(ctx); err != nil {
			b.Fatalf("start scheduler: %v", err)
		}
		if err := scheduler.Stop(time.Second); err != nil {
			b.Fatalf("stop scheduler: %v", err)
		}
	}
}

// BenchmarkSchedulerRunOnce measures one empty due-work scan. |
// BenchmarkSchedulerRunOnce 测量一次没有到期工作的扫描。
func BenchmarkSchedulerRunOnce(b *testing.B) {
	svc, closeService := newService(b)
	defer closeService()
	scheduler := wf.NewScheduler(svc, time.Hour, nil)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scheduler.RunOnce(ctx); err != nil {
			b.Fatalf("run once: %v", err)
		}
	}
}

// BenchmarkStartInstance measures starting one start → end instance. |
// BenchmarkStartInstance 测量发起一个开始 → 结束实例。
func BenchmarkStartInstance(b *testing.B) {
	svc, closeService := newService(b)
	defer closeService()
	publish(b, svc)
	ctx := context.Background()
	actor := wf.Actor{ID: benchActor, Name: benchActor}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.Start(ctx, benchTenant, actor, wf.StartInput{
			DefinitionKey: benchKey,
			Title:         "bench",
		}); err != nil {
			b.Fatalf("start instance: %v", err)
		}
	}
}
