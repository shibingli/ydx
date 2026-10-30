package cron

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/json"
)

// newHTTPTestScheduler builds a started scheduler with one job. |
// newHTTPTestScheduler 构建带一个任务且已启动的调度器。
func newHTTPTestScheduler(t *testing.T) (*Scheduler, *Job) {
	t.Helper()
	var runs atomic.Int32
	sch := New(Options{Concurrency: 1, HistoryLimit: 4})
	if err := sch.Register("tick", func(context.Context, *Job) error {
		runs.Add(1)
		return nil
	}); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	job := &Job{ID: "job-1", Task: "tick", Name: "one", Schedule: Interval(time.Hour)}
	if err := sch.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	t.Cleanup(func() { stopScheduler(t, sch) })
	return sch, job
}

// serve runs one request against the scheduler handler. | serve 对调度器处理器执行一次请求。
func serve(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestHTTPListAndGet covers listing, reading, stats and missing ids. |
// TestHTTPListAndGet 覆盖列表、读取、统计与不存在的 ID。
func TestHTTPListAndGet(t *testing.T) {
	sch, job := newHTTPTestScheduler(t)
	handler := sch.HTTPHandler("/cron")

	response := serve(t, handler, http.MethodGet, "/cron/jobs", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET jobs = %d, want 200 | 列表状态码不符", response.Code)
	}
	var list struct {
		Jobs []Snapshot `json:"jobs"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v | 解码列表失败", err)
	}
	if len(list.Jobs) != 1 || list.Jobs[0].ID != job.ID {
		t.Fatalf("list = %+v | 列表内容不符", list.Jobs)
	}

	response = serve(t, handler, http.MethodGet, "/cron/jobs/"+job.ID, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET job = %d, want 200 | 读取状态码不符", response.Code)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode snapshot: %v | 解码快照失败", err)
	}
	if snapshot.ID != job.ID {
		t.Fatalf("snapshot = %+v | 快照内容不符", snapshot)
	}

	response = serve(t, handler, http.MethodGet, "/cron/jobs/missing", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("GET missing = %d, want 404 | 不存在任务状态码不符", response.Code)
	}

	response = serve(t, handler, http.MethodGet, "/cron/stats", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET stats = %d, want 200 | 统计状态码不符", response.Code)
	}
	var stats Stats
	if err := json.Unmarshal(response.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats: %v | 解码统计失败", err)
	}
	if stats.Jobs != 1 {
		t.Fatalf("stats = %+v | 统计内容不符", stats)
	}
}

// TestHTTPLifecycle covers pause, resume, trigger, history and delete. |
// TestHTTPLifecycle 覆盖暂停、恢复、触发、历史与删除。
func TestHTTPLifecycle(t *testing.T) {
	sch, job := newHTTPTestScheduler(t)
	handler := sch.HTTPHandler("/cron")

	if response := serve(t, handler, http.MethodPost, "/cron/jobs/"+job.ID+"/pause", ""); response.Code != http.StatusOK {
		t.Fatalf("pause = %d, want 200 | 暂停状态码不符", response.Code)
	}
	snapshot, _ := sch.Get(job.ID)
	if !snapshot.Disabled {
		t.Fatal("job was not paused | 任务未暂停")
	}
	if response := serve(t, handler, http.MethodPost, "/cron/jobs/"+job.ID+"/resume", ""); response.Code != http.StatusOK {
		t.Fatalf("resume = %d, want 200 | 恢复状态码不符", response.Code)
	}
	snapshot, _ = sch.Get(job.ID)
	if snapshot.Disabled {
		t.Fatal("job was not resumed | 任务未恢复")
	}

	if response := serve(t, handler, http.MethodPost, "/cron/jobs/"+job.ID+"/trigger", ""); response.Code != http.StatusOK {
		t.Fatalf("trigger = %d, want 200 | 触发状态码不符", response.Code)
	}
	waitFor(t, 2*time.Second, func() bool {
		current, _ := sch.Get(job.ID)
		return current.Runs == 1
	}, "triggered run did not complete | 手动触发未完成")

	response := serve(t, handler, http.MethodGet, "/cron/jobs/"+job.ID+"/history", "")
	if response.Code != http.StatusOK {
		t.Fatalf("history = %d, want 200 | 历史状态码不符", response.Code)
	}
	var history struct {
		History []RunRecord `json:"history"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil {
		t.Fatalf("decode history: %v | 解码历史失败", err)
	}
	if len(history.History) != 1 || history.History[0].Trigger != TriggerManual {
		t.Fatalf("history = %+v | 历史内容不符", history.History)
	}

	if response := serve(t, handler, http.MethodDelete, "/cron/jobs/"+job.ID, ""); response.Code != http.StatusOK {
		t.Fatalf("delete = %d, want 200 | 删除状态码不符", response.Code)
	}
	if response := serve(t, handler, http.MethodGet, "/cron/jobs/"+job.ID, ""); response.Code != http.StatusNotFound {
		t.Fatalf("GET deleted = %d, want 404 | 删除后状态码不符", response.Code)
	}
}

// TestHTTPCreateAndUpdate covers definition-driven create and update. |
// TestHTTPCreateAndUpdate 覆盖基于定义的创建与更新。
func TestHTTPCreateAndUpdate(t *testing.T) {
	sch, _ := newHTTPTestScheduler(t)
	handler := sch.HTTPHandler("/cron")

	create := `{"id":"job-2","name":"created","task":"tick","expression":"@every 1h"}`
	response := serve(t, handler, http.MethodPost, "/cron/jobs", create)
	if response.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201: %s | 创建状态码不符", response.Code, response.Body.String())
	}
	if _, ok := sch.Get("job-2"); !ok {
		t.Fatal("created job not scheduled | 创建的任务未调度")
	}

	if duplicate := serve(t, handler, http.MethodPost, "/cron/jobs", create); duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409 | 重复创建状态码不符", duplicate.Code)
	}

	update := `{"name":"updated","task":"tick","expression":"@every 2h"}`
	response = serve(t, handler, http.MethodPut, "/cron/jobs/job-2", update)
	if response.Code != http.StatusOK {
		t.Fatalf("update = %d, want 200: %s | 更新状态码不符", response.Code, response.Body.String())
	}
	snapshot, _ := sch.Get("job-2")
	if snapshot.Name != "updated" || snapshot.Expression != "@every 2h0m0s" {
		t.Fatalf("updated snapshot = %+v | 更新结果不符", snapshot)
	}
}

// TestHTTPErrors covers malformed bodies, wrong methods and unknown paths. |
// TestHTTPErrors 覆盖非法请求体、错误方法与未知路径。
func TestHTTPErrors(t *testing.T) {
	sch, _ := newHTTPTestScheduler(t)
	handler := sch.HTTPHandler("/cron")

	if response := serve(t, handler, http.MethodPost, "/cron/jobs", `{"task":"tick"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("missing expression = %d, want 400 | 缺少表达式状态码不符", response.Code)
	}
	if response := serve(t, handler, http.MethodPost, "/cron/jobs", `not json`); response.Code != http.StatusBadRequest {
		t.Fatalf("bad json = %d, want 400 | 非法 JSON 状态码不符", response.Code)
	}
	if response := serve(t, handler, http.MethodPost, "/cron/jobs", `{"task":"missing","expression":"@every 1h"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown task = %d, want 400 | 未知任务状态码不符", response.Code)
	}

	response := serve(t, handler, http.MethodPatch, "/cron/jobs", "")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH jobs = %d, want 405 | 方法不允许状态码不符", response.Code)
	}
	if allow := response.Header().Get("Allow"); !strings.Contains(allow, http.MethodGet) || !strings.Contains(allow, http.MethodPost) {
		t.Fatalf("Allow = %q | Allow 头不符", allow)
	}

	if response := serve(t, handler, http.MethodGet, "/cron/unknown", ""); response.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404 | 未知路径状态码不符", response.Code)
	}
	if response := serve(t, handler, http.MethodPost, "/cron/reload", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("reload without store = %d, want 400 | 缺少 Store 的同步状态码不符", response.Code)
	}
	if response := serve(t, handler, http.MethodGet, "/cron/reload", ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET reload = %d, want 405 | 同步方法状态码不符", response.Code)
	}

	if response := serve(t, handler, http.MethodPost, "/cron/jobs/job-1/trigger", ""); response.Code != http.StatusOK {
		t.Fatalf("trigger before stop = %d | 停止前触发失败", response.Code)
	}
	if response := serve(t, handler, http.MethodPost, "/cron/jobs/missing/trigger", ""); response.Code != http.StatusNotFound {
		t.Fatalf("trigger missing = %d, want 404 | 触发不存在任务状态码不符", response.Code)
	}
	if response := serve(t, handler, http.MethodGet, "/cron/jobs/missing/history", ""); response.Code != http.StatusNotFound {
		t.Fatalf("history missing = %d, want 404 | 不存在任务历史状态码不符", response.Code)
	}
}

// TestHTTPPrefixNormalization accepts a prefix without a leading slash. |
// TestHTTPPrefixNormalization 接受不带前导斜杠的前缀。
func TestHTTPPrefixNormalization(t *testing.T) {
	sch, _ := newHTTPTestScheduler(t)
	handler := sch.HTTPHandler("cron")
	response := serve(t, handler, http.MethodGet, "/cron/jobs", "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET with normalized prefix = %d, want 200 | 前缀规范化失败", response.Code)
	}
}
