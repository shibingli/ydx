package waf

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/router"
)

func TestResponseHeaderInspectionBlocks(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleResHeader}})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("X-Leak", "yes")
		_, _ = io.WriteString(rw, "leaked body")
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "leaked body") {
		t.Fatalf("响应泄漏了业务正文: %q", rec.Body.String())
	}
	if got := rec.Header().Get("X-Leak"); got != "" {
		t.Fatalf("被拦截响应仍带有 X-Leak=%q", got)
	}
}

func TestHandlerWithoutWriteDefaultsTo200(t *testing.T) {
	sink := &eventSink{}
	w := newWAF(t, Options{Directives: []string{ruleURI}, Observer: sink.observe})
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	rec := doNative(w, h, http.MethodGet, "/empty", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("正文 = %q，期望为空", rec.Body.String())
	}
	if ev := sink.only(t); ev.Status != http.StatusOK {
		t.Fatalf("事件状态 = %d，期望 200", ev.Status)
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (f *flushRecorder) Flush() {
	f.flushes++
	f.ResponseRecorder.Flush()
}

func TestFlushPropagatesForNonProcessableResponse(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(rw, "chunk")
		if f, ok := rw.(http.Flusher); ok {
			f.Flush()
		}
	})
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w.HTTPMiddleware(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "chunk" {
		t.Fatalf("流式响应异常: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec.flushes == 0 {
		t.Fatal("非可处理响应未向下游透传 Flush")
	}
}

func TestFlushWithheldForProcessableResponse(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "leaking response-secret")
		if f, ok := rw.(http.Flusher); ok {
			f.Flush()
		}
	})
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w.HTTPMiddleware(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "response-secret") {
		t.Fatalf("检测前正文已下发: %q", rec.Body.String())
	}
}

func TestYDResponseBodyBlock(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	r := router.New()
	r.Use(w.Middleware())
	r.GET("/data", func(c *router.Ctx) {
		c.SetHeader("Content-Type", "text/plain")
		_ = c.String(http.StatusOK, "response-secret")
	})
	rec := doRouter(r, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "response-secret") {
		t.Fatalf("响应正文泄漏: %q", rec.Body.String())
	}
}

func TestDetectionModeResponseBody(t *testing.T) {
	sink := &eventSink{}
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
		Mode:               ModeDetection,
		Observer:           sink.observe,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "response-secret")
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "response-secret" {
		t.Fatalf("检测模式不应拦截响应: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := w.Stats().Detected; got != 1 {
		t.Fatalf("Detected = %d，期望 1", got)
	}
	ev := sink.only(t)
	if !ev.Detected || ev.Blocked || ev.Phase != PhaseResponse {
		t.Fatalf("事件 Detected=%v Blocked=%v Phase=%v", ev.Detected, ev.Blocked, ev.Phase)
	}
}

func TestNativeResponseRecorderInterfaces(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	var flusher bool
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, flusher = rw.(http.Flusher)
		_, _ = io.WriteString(rw, "ok")
	})
	rec := doNative(w, h, http.MethodGet, "/safe", "", nil)
	if !flusher {
		t.Fatal("包装器未保留 http.Flusher")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
}

func TestHijackerPreserved(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	ack := make(chan bool, 1)
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, ok := rw.(http.Hijacker)
		ack <- ok
		rw.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(w.HTTPMiddleware(h))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET 失败: %v", err)
	}
	_ = resp.Body.Close()
	if !<-ack {
		t.Fatal("真实服务端包装器未保留 http.Hijacker")
	}
}

type readerFromRecorder struct {
	*httptest.ResponseRecorder
	used bool
}

func (r *readerFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	r.used = true
	return io.Copy(r.ResponseRecorder, src)
}

func TestReadFromDelegatesForStreamedResponse(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(rw, io.LimitReader(strings.NewReader("streamed-body"), 13))
	})
	rec := &readerFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/download", nil)
	w.HTTPMiddleware(h).ServeHTTP(rec, req)
	if !rec.used {
		t.Fatal("流式响应未委托底层 ReaderFrom")
	}
	if rec.Body.String() != "streamed-body" {
		t.Fatalf("正文 = %q，期望 streamed-body", rec.Body.String())
	}
}

func TestReadFromBuffersForInspectedResponse(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.Copy(rw, io.LimitReader(strings.NewReader("response-secret"), 15))
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "response-secret") {
		t.Fatalf("响应正文泄漏: %q", rec.Body.String())
	}
}

func TestConnectResponseIsNotInspected(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "response-secret")
	})
	req := httptest.NewRequest(http.MethodConnect, "/tunnel", nil)
	rec := httptest.NewRecorder()
	w.HTTPMiddleware(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "response-secret" {
		t.Fatalf("CONNECT 响应不应被正文检测: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHijackWorks(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	done := make(chan error, 1)
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		hijacker, ok := rw.(http.Hijacker)
		if !ok {
			done <- errors.New("missing http.Hijacker")
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if _, err := buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			done <- err
			return
		}
		done <- buf.Flush()
	})
	srv := httptest.NewServer(w.HTTPMiddleware(h))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET 失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("劫持响应正文 = %q，期望 ok", body)
	}
	if err := <-done; err != nil {
		t.Fatalf("劫持失败: %v", err)
	}
}

func TestResponseBodyAutoSkipsWithoutResponseRules(t *testing.T) {
	// ResponseBodyAccess is on, but the only rule is phase 1: no rule can observe the response
	// body, so the WAF must not buffer it and Flush must propagate. | 开启响应正文访问但只有
	// phase 1 规则时，没有规则能观察响应正文，因此不得缓冲，Flush 必须透传。
	w := newWAF(t, Options{
		Directives:         []string{ruleURI},
		ResponseBodyAccess: true,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "streamed")
		if f, ok := rw.(http.Flusher); ok {
			f.Flush()
		}
	})
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/data", nil)
	w.HTTPMiddleware(h).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "streamed" {
		t.Fatalf("响应异常: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec.flushes == 0 {
		t.Fatal("无响应规则的正文被错误缓冲，Flush 未透传")
	}
}

func TestResponsePhaseObservation(t *testing.T) {
	sink := &eventSink{}
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
		Observer:           sink.observe,
	})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "response-secret")
	})
	rec := doNative(w, h, http.MethodGet, "/data", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	ev := sink.only(t)
	if !ev.Blocked || ev.Phase != PhaseResponse {
		t.Fatalf("事件 Blocked=%v Phase=%v，期望 true/PhaseResponse", ev.Blocked, ev.Phase)
	}
	if ev.Interruption == nil || ev.Interruption.RuleID != 1005 {
		t.Fatalf("事件中断信息 = %+v，期望规则 1005", ev.Interruption)
	}
	if len(ev.Matches) == 0 {
		t.Fatal("响应阶段事件缺少命中规则")
	}
}
