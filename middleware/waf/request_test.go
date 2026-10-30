package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shibingli/ydx/router"
)

func TestRequestBodyInspectionAndReplay(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleReqBody}})
	var reached atomic.Bool
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("读取正文失败: %v", err)
			return
		}
		_, _ = rw.Write(body)
	})

	rec := doNative(w, h, http.MethodPost, "/submit", "this is attack-body", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("被拦截请求状态 = %d，期望 403", rec.Code)
	}
	if reached.Load() {
		t.Fatal("被拦截请求不应进入业务处理器")
	}

	reached.Store(false)
	rec = doNative(w, h, http.MethodPost, "/submit", "this is harmless", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if rec.Code != http.StatusOK {
		t.Fatalf("正常请求状态 = %d，期望 200", rec.Code)
	}
	if got := rec.Body.String(); got != "this is harmless" {
		t.Fatalf("正文回放 = %q，期望完整原始正文", got)
	}
	if !reached.Load() {
		t.Fatal("正常请求未进入业务处理器")
	}
}

func TestRequestBodyReplayThroughYDRouter(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleReqBody}})
	r := router.New()
	r.Use(w.Middleware())
	r.POST("/submit", func(c *router.Ctx) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			_ = c.String(http.StatusInternalServerError, err.Error())
			return
		}
		_ = c.String(http.StatusOK, string(body))
	})
	rec := doRouter(r, http.MethodPost, "/submit", "payload attack-body here", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	rec = doRouter(r, http.MethodPost, "/submit", "harmless payload", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if rec.Code != http.StatusOK || rec.Body.String() != "harmless payload" {
		t.Fatalf("正文回放失败: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRequestBodyLimitRejects(t *testing.T) {
	w := newWAF(t, Options{
		Directives:       []string{ruleReqBody},
		RequestBodyLimit: 64,
	})
	rec := doNative(w, okHandler(), http.MethodPost, "/upload", strings.Repeat("x", 1024), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限状态 = %d，期望 413", rec.Code)
	}
	if got := w.Stats().Blocked; got != 1 {
		t.Fatalf("Blocked = %d，期望 1", got)
	}
}

func TestRequestBodyLimitDetectionDoesNotBlock(t *testing.T) {
	w := newWAF(t, Options{
		Directives:       []string{ruleReqBody},
		Mode:             ModeDetection,
		RequestBodyLimit: 64,
	})
	body := strings.Repeat("y", 1024)
	rec := doNative(w, echoHandler(), http.MethodPost, "/upload", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("检测模式超限状态 = %d，期望 200", rec.Code)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("检测模式正文长度 = %d，期望 %d", len(got), len(body))
	}
}

func TestRequestBodyReplayWithoutProcessor(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	body := "opaque\x00payload"
	rec := doNative(w, echoHandler(), http.MethodPost, "/submit", body, map[string]string{"Content-Type": "application/octet-stream"})
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("正文回放 = %q，期望 %q", got, body)
	}
}

func TestRouterBodyLimitMapsTo413(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleReqBody}})
	r := router.New(router.WithMaxBodySize(16))
	r.Use(w.Middleware())
	r.POST("/upload", func(c *router.Ctx) {
		_ = c.String(http.StatusOK, "should not run")
	})
	rec := doRouter(r, http.MethodPost, "/upload", strings.Repeat("a", 100), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("路由器正文超限状态 = %d，期望 413", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "should not run") {
		t.Fatal("超限请求不应进入业务处理器")
	}
}

type countingBody struct {
	reader io.Reader
	reads  atomic.Int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.reader.Read(p)
}

func (c *countingBody) Close() error { return nil }

func TestConnectBodyIsNotBuffered(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	body := &countingBody{reader: strings.NewReader("tunnel-bytes")}
	seen := make(chan int64, 1)
	payload := make(chan string, 1)
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		seen <- body.reads.Load()
		data, _ := io.ReadAll(r.Body)
		payload <- string(data)
		rw.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodConnect, "/tunnel", nil)
	req.Body = body
	rec := httptest.NewRecorder()
	w.HTTPMiddleware(h).ServeHTTP(rec, req)

	if got := <-seen; got != 0 {
		t.Fatalf("CONNECT 正文在业务处理器之前被读取了 %d 次", got)
	}
	if got := <-payload; got != "tunnel-bytes" {
		t.Fatalf("业务处理器读取正文 = %q，期望完整隧道字节", got)
	}
}

func TestConnectRequestHeadersAreInspected(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	req := httptest.NewRequest(http.MethodConnect, "/attack", nil)
	rec := httptest.NewRecorder()
	w.HTTPMiddleware(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("CONNECT 请求阶段状态 = %d，期望 403", rec.Code)
	}
}

func TestLimitsApplyWhenDirectivesReenableBodyAccess(t *testing.T) {
	w := newWAF(t, Options{
		Directives:               []string{ruleReqBody, "SecRequestBodyAccess On"},
		DisableRequestBodyAccess: true,
		RequestBodyLimit:         64,
	})
	rec := doNative(w, okHandler(), http.MethodPost, "/upload", strings.Repeat("x", 100), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("重新开启正文访问后状态 = %d，期望安全上限仍生效（413）", rec.Code)
	}
}

func TestHeaderOnlyRulesDoNotBufferBody(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}}) // phase 1 only
	body := &countingBody{reader: strings.NewReader("raw-body")}
	seen := make(chan int64, 1)
	payload := make(chan string, 1)
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		seen <- body.reads.Load()
		data, _ := io.ReadAll(r.Body)
		payload <- string(data)
		rw.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/safe", nil)
	req.Body = body
	rec := httptest.NewRecorder()
	w.HTTPMiddleware(h).ServeHTTP(rec, req)

	if got := <-seen; got != 0 {
		t.Fatalf("仅请求头规则时正文在处理器之前被读取了 %d 次", got)
	}
	if got := <-payload; got != "raw-body" {
		t.Fatalf("处理器读取正文 = %q，期望 raw-body", got)
	}
}

func TestRequestBodyMultiChunkInspection(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleReqBody}})
	body := strings.Repeat("a", 100<<10) + "attack-body"
	rec := doNative(w, okHandler(), http.MethodPost, "/submit", body, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("跨块正文规则未生效: %d", rec.Code)
	}
}

func TestRequestBodyMultiChunkReplay(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleReqBody}})
	body := strings.Repeat("b", 100<<10)
	rec := doNative(w, echoHandler(), http.MethodPost, "/submit", body, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("跨块正文回放长度 = %d，期望 %d", len(got), len(body))
	}
}

func TestDisableRequestBodyAccess(t *testing.T) {
	w := newWAF(t, Options{
		Directives:               []string{ruleReqBody},
		DisableRequestBodyAccess: true,
	})
	rec := doNative(w, echoHandler(), http.MethodPost, "/submit", "attack-body", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "attack-body" {
		t.Fatalf("关闭正文访问后请求异常: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestResponseBodyInspectionBlocks(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(rw, "leaking response-secret now")
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "response-secret") {
		t.Fatalf("响应泄漏了敏感正文: %q", rec.Body.String())
	}
	if got := w.Stats().Blocked; got != 1 {
		t.Fatalf("Blocked = %d，期望 1", got)
	}
}

func TestResponseBodyInspectionPassesCleanBody(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(rw, "clean response")
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "clean response" {
		t.Fatalf("正常响应异常: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestResponseBodySniffedContentType(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(rw, "leaking response-secret now")
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("未显式设置 Content-Type 时状态 = %d，期望 403", rec.Code)
	}
}

func TestResponseBodyLimitProcessPartialDeliversFullBody(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
		ResponseBodyLimit:  32,
	})
	body := strings.Repeat("z", 4096)
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, body)
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("响应正文长度 = %d，期望 %d", len(got), len(body))
	}
}

func TestResponseBodyNotInspectedWhenDisabled(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleResBody}})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "response-secret")
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "response-secret" {
		t.Fatalf("未开启响应检测时被误拦: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestResponseBodyLimitRejectMode(t *testing.T) {
	w := newWAF(t, Options{
		Directives: []string{
			ruleResBody,
			"SecResponseBodyLimitAction Reject",
		},
		ResponseBodyAccess: true,
		ResponseBodyLimit:  32,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, strings.Repeat("q", 1024))
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("响应体超限状态 = %d，期望 500", rec.Code)
	}
}
