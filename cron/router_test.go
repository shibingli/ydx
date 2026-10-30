package cron

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/router"
)

// serveRouter runs one request through the ydx/router instance. |
// serveRouter 让一个请求经过 ydx/router 实例。
func serveRouter(handler http.Handler, method, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder
}

// TestMountYDXRouter covers the router-native entry point across the full
// administrative lifecycle. | TestMountYDXRouter 覆盖路由原生入口的完整管理生命周期。
func TestMountYDXRouter(t *testing.T) {
	var runs atomic.Int32
	scheduler := New(Options{Concurrency: 1, HistoryLimit: 2})
	job := &Job{
		ID:       "router-job",
		Name:     "router",
		Schedule: Interval(time.Hour),
		Handler: func(context.Context, *Job) error {
			runs.Add(1)
			return nil
		},
	}
	if err := scheduler.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	t.Cleanup(func() { stopScheduler(t, scheduler) })

	engine := router.New()
	if err := scheduler.Mount(engine, "cron/"); err != nil {
		t.Fatalf("Mount: %v | 挂载失败", err)
	}
	if err := engine.Validate(); err != nil {
		t.Fatalf("Validate: %v | 路由表校验失败", err)
	}

	if response := serveRouter(engine, http.MethodGet, "/cron/jobs"); response.Code != http.StatusOK {
		t.Fatalf("GET jobs = %d, want 200: %s | 列表状态码不符", response.Code, response.Body.String())
	}
	if response := serveRouter(engine, http.MethodGet, "/cron/jobs/router-job"); response.Code != http.StatusOK {
		t.Fatalf("GET job = %d, want 200 | 读取状态码不符", response.Code)
	}
	if response := serveRouter(engine, http.MethodPost, "/cron/jobs/router-job/pause"); response.Code != http.StatusOK {
		t.Fatalf("pause = %d, want 200 | 暂停状态码不符", response.Code)
	}
	if response := serveRouter(engine, http.MethodPost, "/cron/jobs/router-job/resume"); response.Code != http.StatusOK {
		t.Fatalf("resume = %d, want 200 | 恢复状态码不符", response.Code)
	}
	if response := serveRouter(engine, http.MethodPost, "/cron/jobs/router-job/trigger"); response.Code != http.StatusOK {
		t.Fatalf("trigger = %d, want 200 | 触发状态码不符", response.Code)
	}
	waitFor(t, 2*time.Second, func() bool { return runs.Load() == 1 }, "router trigger did not run | 路由触发未运行")
	if response := serveRouter(engine, http.MethodGet, "/cron/jobs/router-job/history"); response.Code != http.StatusOK {
		t.Fatalf("history = %d, want 200 | 历史状态码不符", response.Code)
	}
	if response := serveRouter(engine, http.MethodGet, "/cron/stats"); response.Code != http.StatusOK {
		t.Fatalf("stats = %d, want 200 | 统计状态码不符", response.Code)
	}
	if response := serveRouter(engine, http.MethodPost, "/cron/reload"); response.Code != http.StatusBadRequest {
		t.Fatalf("reload without store = %d, want 400 | 同步状态码不符", response.Code)
	}
	if response := serveRouter(engine, http.MethodDelete, "/cron/jobs/router-job"); response.Code != http.StatusOK {
		t.Fatalf("delete = %d, want 200 | 删除状态码不符", response.Code)
	}
	if response := serveRouter(engine, http.MethodGet, "/cron/jobs/missing"); response.Code != http.StatusNotFound {
		t.Fatalf("GET missing = %d, want 404 | 不存在任务状态码不符", response.Code)
	}

	if err := scheduler.Mount(nil, "/cron"); !errors.Is(err, ErrNilRouter) {
		t.Fatalf("Mount(nil) = %v, want ErrNilRouter | nil 路由器错误不符", err)
	}
}
