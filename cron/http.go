package cron

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// maxAdminBody bounds one administrative request body. | maxAdminBody 限制单个管理请求体的大小。
const maxAdminBody = 1 << 20

// HTTPHandler returns the plain net/http adapter for the administrative API. |
// HTTPHandler 返回管理 API 的纯 net/http 适配器。
//
// The API itself is router-native: HTTPHandler builds a ydx/router instance and
// registers the same explicit routes as Mount, so both entry points share one
// implementation and one set of status codes. Use Mount when the application
// already owns a ydx/router Router; use HTTPHandler for http.ServeMux. |
// API 本身以 ydx/router 为原生实现：HTTPHandler 构建一个 ydx/router 实例并注册与 Mount
// 完全相同的显式路由，因此两个入口共享同一实现与状态码。应用已有 ydx/router Router 时用
// Mount；使用 http.ServeMux 时用 HTTPHandler。
//
// Routes | 路由：
//
//	GET    <prefix>/jobs               list snapshots | 列举快照
//	POST   <prefix>/jobs               create from a Definition | 按 Definition 创建
//	GET    <prefix>/jobs/{id}          read one snapshot | 读取单个快照
//	PUT    <prefix>/jobs/{id}          replace a definition | 替换定义
//	DELETE <prefix>/jobs/{id}          remove a job | 删除任务
//	POST   <prefix>/jobs/{id}/pause    pause scheduled runs | 暂停计划触发
//	POST   <prefix>/jobs/{id}/resume   resume scheduled runs | 恢复计划触发
//	POST   <prefix>/jobs/{id}/trigger  run once now | 立即运行一次
//	GET    <prefix>/jobs/{id}/history  newest-first run records | 最新在前的运行记录
//	GET    <prefix>/stats              scheduler counters | 调度器统计
//	POST   <prefix>/reload             reconcile with the Store | 与 Store 同步
//
// It performs no authentication: wrap it with the application's admin
// middleware before exposing it. Job ids must not contain "/", and PUT replaces
// the whole definition, so the body must include task and expression. |
// 该处理器不做认证：对外暴露前请套用应用的管理中间件。任务 ID 不得包含 "/"；PUT 会整体
// 替换定义，因此请求体必须包含 task 与 expression。
func (s *Scheduler) HTTPHandler(prefix string) http.Handler {
	engine := router.New()
	s.mountRoutes(engine, prefix)
	return engine
}

// mountRoutes registers the administrative routes on a ydx/router Router. |
// mountRoutes 把管理路由注册到 ydx/router 的 Router 上。
func (s *Scheduler) mountRoutes(engine *router.Router, prefix string) {
	base := normalizePrefix(prefix)
	engine.GET(base+"/jobs", s.handleJobsList)
	engine.POST(base+"/jobs", s.handleJobsCreate)
	engine.GET(base+"/jobs/:id", s.handleJobGet)
	engine.PUT(base+"/jobs/:id", s.handleJobUpdate)
	engine.DELETE(base+"/jobs/:id", s.handleJobDelete)
	engine.POST(base+"/jobs/:id/pause", s.handleJobPause)
	engine.POST(base+"/jobs/:id/resume", s.handleJobResume)
	engine.POST(base+"/jobs/:id/trigger", s.handleJobTrigger)
	engine.GET(base+"/jobs/:id/history", s.handleJobHistory)
	engine.GET(base+"/stats", s.handleStats)
	engine.POST(base+"/reload", s.handleReload)
}

// normalizePrefix makes a prefix start with one slash and never end with one. |
// normalizePrefix 让前缀以一个斜杠开头且不以斜杠结尾。
func normalizePrefix(prefix string) string {
	trimmed := strings.Trim(strings.TrimSpace(prefix), "/")
	if trimmed == "" {
		return ""
	}
	return "/" + trimmed
}

// handleJobsList answers GET <prefix>/jobs. | handleJobsList 应答 GET <prefix>/jobs。
func (s *Scheduler) handleJobsList(c *router.Ctx) {
	jobs := s.List()
	if jobs == nil {
		jobs = []Snapshot{}
	}
	writeJSON(c, http.StatusOK, struct {
		Jobs []Snapshot `json:"jobs"`
	}{Jobs: jobs})
}

// handleJobsCreate answers POST <prefix>/jobs. | handleJobsCreate 应答 POST <prefix>/jobs。
func (s *Scheduler) handleJobsCreate(c *router.Ctx) {
	definition, err := decodeDefinition(c)
	if err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	job, err := definition.Job()
	if err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if err := s.Add(c.Request.Context(), job); err != nil {
		writeError(c, errorStatus(err), err)
		return
	}
	if snapshot, ok := s.Get(job.ID); ok {
		writeJSON(c, http.StatusCreated, snapshot)
		return
	}
	writeJSON(c, http.StatusCreated, okResponse{OK: true})
}

// handleJobGet answers GET <prefix>/jobs/{id}. | handleJobGet 应答 GET <prefix>/jobs/{id}。
func (s *Scheduler) handleJobGet(c *router.Ctx) {
	id := c.Param("id")
	snapshot, ok := s.Get(id)
	if !ok {
		writeError(c, http.StatusNotFound, errs.Detail(ErrJobNotFound, "%q", id))
		return
	}
	writeJSON(c, http.StatusOK, snapshot)
}

// handleJobUpdate answers PUT <prefix>/jobs/{id}. | handleJobUpdate 应答 PUT <prefix>/jobs/{id}。
func (s *Scheduler) handleJobUpdate(c *router.Ctx) {
	id := c.Param("id")
	definition, err := decodeDefinition(c)
	if err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	definition.ID = id
	job, err := definition.Job()
	if err != nil {
		writeError(c, http.StatusBadRequest, err)
		return
	}
	if err := s.Update(c.Request.Context(), job); err != nil {
		writeError(c, errorStatus(err), err)
		return
	}
	if snapshot, ok := s.Get(id); ok {
		writeJSON(c, http.StatusOK, snapshot)
		return
	}
	writeJSON(c, http.StatusOK, okResponse{OK: true})
}

// handleJobDelete answers DELETE <prefix>/jobs/{id}. | handleJobDelete 应答 DELETE <prefix>/jobs/{id}。
func (s *Scheduler) handleJobDelete(c *router.Ctx) {
	if err := s.Remove(c.Request.Context(), c.Param("id")); err != nil {
		writeError(c, errorStatus(err), err)
		return
	}
	writeJSON(c, http.StatusOK, okResponse{OK: true})
}

// handleJobPause answers POST <prefix>/jobs/{id}/pause. | handleJobPause 应答 POST <prefix>/jobs/{id}/pause。
func (s *Scheduler) handleJobPause(c *router.Ctx) {
	if err := s.Pause(c.Request.Context(), c.Param("id")); err != nil {
		writeError(c, errorStatus(err), err)
		return
	}
	writeJSON(c, http.StatusOK, okResponse{OK: true})
}

// handleJobResume answers POST <prefix>/jobs/{id}/resume. | handleJobResume 应答 POST <prefix>/jobs/{id}/resume。
func (s *Scheduler) handleJobResume(c *router.Ctx) {
	if err := s.Resume(c.Request.Context(), c.Param("id")); err != nil {
		writeError(c, errorStatus(err), err)
		return
	}
	writeJSON(c, http.StatusOK, okResponse{OK: true})
}

// handleJobTrigger answers POST <prefix>/jobs/{id}/trigger. | handleJobTrigger 应答 POST <prefix>/jobs/{id}/trigger。
func (s *Scheduler) handleJobTrigger(c *router.Ctx) {
	if err := s.Trigger(c.Param("id")); err != nil {
		writeError(c, errorStatus(err), err)
		return
	}
	writeJSON(c, http.StatusOK, okResponse{OK: true})
}

// handleJobHistory answers GET <prefix>/jobs/{id}/history. | handleJobHistory 应答 GET <prefix>/jobs/{id}/history。
func (s *Scheduler) handleJobHistory(c *router.Ctx) {
	id := c.Param("id")
	if _, ok := s.Get(id); !ok {
		writeError(c, http.StatusNotFound, errs.Detail(ErrJobNotFound, "%q", id))
		return
	}
	history := s.History(id)
	if history == nil {
		history = []RunRecord{}
	}
	writeJSON(c, http.StatusOK, struct {
		History []RunRecord `json:"history"`
	}{History: history})
}

// handleStats answers GET <prefix>/stats. | handleStats 应答 GET <prefix>/stats。
func (s *Scheduler) handleStats(c *router.Ctx) {
	writeJSON(c, http.StatusOK, s.Stats())
}

// handleReload answers POST <prefix>/reload. | handleReload 应答 POST <prefix>/reload。
func (s *Scheduler) handleReload(c *router.Ctx) {
	if err := s.Reload(c.Request.Context()); err != nil {
		writeError(c, errorStatus(err), err)
		return
	}
	writeJSON(c, http.StatusOK, okResponse{OK: true})
}

// decodeDefinition reads and parses one definition body. | decodeDefinition 读取并解析一个定义请求体。
func decodeDefinition(c *router.Ctx) (Definition, error) {
	body := http.MaxBytesReader(c.Writer, c.Request.Body, maxAdminBody)
	raw, err := io.ReadAll(body)
	if err != nil {
		return Definition{}, errs.Wrap(err, ErrInvalidDefinition)
	}
	var definition Definition
	if err := json.Unmarshal(raw, &definition); err != nil {
		return Definition{}, errs.Wrap(err, ErrInvalidDefinition)
	}
	return definition, nil
}

// okResponse is the minimal success body. | okResponse 是最小成功响应体。
type okResponse struct {
	OK bool `json:"ok"`
}

// errorResponse is the error body. | errorResponse 是错误响应体。
type errorResponse struct {
	Error string `json:"error"`
}

// writeJSON writes one JSON response through the router context. |
// writeJSON 经路由上下文写出单个 JSON 响应。
func writeJSON(c *router.Ctx, status int, value any) {
	_ = c.JSON(status, value)
}

// writeError writes one JSON error response through the router context. |
// writeError 经路由上下文写出单个 JSON 错误响应。
func writeError(c *router.Ctx, status int, err error) {
	_ = c.JSON(status, errorResponse{Error: err.Error()})
}

// errorStatus maps declared errors to administrative status codes. |
// errorStatus 把已声明错误映射为管理状态码。
func errorStatus(err error) int {
	switch {
	case errors.Is(err, ErrJobNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrJobExists), errors.Is(err, ErrJobRunning):
		return http.StatusConflict
	case errors.Is(err, ErrQueueFull):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrSchedulerClosed), errors.Is(err, ErrSchedulerNotRunning):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrNilJob),
		errors.Is(err, ErrNilSchedule),
		errors.Is(err, ErrNilHandler),
		errors.Is(err, ErrHandlerNotFound),
		errors.Is(err, ErrEmptyTask),
		errors.Is(err, ErrNoStore),
		errors.Is(err, ErrNoFutureRun),
		errors.Is(err, ErrInvalidDefinition),
		errors.Is(err, ErrInvalidField),
		errors.Is(err, ErrInvalidValue),
		errors.Is(err, ErrUnsupportedSpec),
		errors.Is(err, ErrEmptySpec):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
