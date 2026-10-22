package accesslog

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/middleware/requestid"
	"github.com/shibingli/ydx/router"
)

func TestAccessLogRecordsFields(t *testing.T) {
	logger, buf := newTestLogger()
	r := router.New()
	r.Use(requestid.RequestID(""), AccessLog(logger))
	r.GET("/hello", func(c *router.Ctx) { _ = c.String(http.StatusCreated, "hello world") })

	rec := doReq(r, http.MethodGet, "/hello", nil, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("code = %d, 期望 201", rec.Code)
	}

	entry := onlyRecord(t, buf)
	if entry["msg"] != "access | 访问日志" {
		t.Errorf("msg = %v, 期望中英同步的访问日志文案", entry["msg"])
	}
	if entry["method"] != http.MethodGet {
		t.Errorf("method = %v, 期望 GET", entry["method"])
	}
	if entry["path"] != "/hello" {
		t.Errorf("path = %v, 期望 /hello", entry["path"])
	}
	if got := numField(t, entry, "status"); got != http.StatusCreated {
		t.Errorf("status = %v, 期望 201", got)
	}
	if got := numField(t, entry, "bytes"); got != float64(len("hello world")) {
		t.Errorf("bytes = %v, 期望 %d", got, len("hello world"))
	}
	if got := numField(t, entry, "duration"); got < 0 {
		t.Errorf("duration = %v, 期望 >= 0", got)
	}
	if got, _ := entry["request_id"].(string); got != rec.Header().Get("X-Request-Id") {
		t.Errorf("request_id = %v, 期望 %q", entry["request_id"], rec.Header().Get("X-Request-Id"))
	}
}

// A handler that never writes is logged as 200 with zero bytes. | 从未写入的处理器按 200、
// 零字节记录。
func TestAccessLogDefaultsToOK(t *testing.T) {
	logger, buf := newTestLogger()
	r := router.New()
	r.Use(AccessLog(logger))
	r.GET("/silent", func(*router.Ctx) {})

	doReq(r, http.MethodGet, "/silent", nil, "")

	entry := onlyRecord(t, buf)
	if got := numField(t, entry, "status"); got != http.StatusOK {
		t.Errorf("status = %v, 期望 200", got)
	}
	if got := numField(t, entry, "bytes"); got != 0 {
		t.Errorf("bytes = %v, 期望 0", got)
	}
}

// Byte counting must not break chunked flushing. | 字节计数不得破坏分块 flush。
func TestAccessLogCountsChunksAndKeepsFlush(t *testing.T) {
	logger, buf := newTestLogger()
	r := router.New()
	r.Use(AccessLog(logger))
	r.GET("/stream", func(c *router.Ctx) {
		c.SetHeader("Content-Type", "text/plain; charset=utf-8")
		c.WriteHeader(http.StatusOK)
		for _, chunk := range []string{"one", "two", "three"} {
			_, _ = c.Writer.Write([]byte(chunk))
			c.Flush()
		}
	})

	rec := doReq(r, http.MethodGet, "/stream", nil, "")
	if !rec.Flushed {
		t.Fatal("the underlying writer never saw a Flush")
	}
	if rec.Body.String() != "onetwothree" {
		t.Fatalf("body = %q, 期望 onetwothree", rec.Body.String())
	}
	entry := onlyRecord(t, buf)
	if got := numField(t, entry, "bytes"); got != float64(len("onetwothree")) {
		t.Errorf("bytes = %v, 期望 %d", got, len("onetwothree"))
	}
}

// syncBuffer is a mutex-guarded log sink for parallel access-log tests. | syncBuffer 是并行
// 访问日志测试所使用的互斥锁保护日志接收器。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestAccessLogConcurrentReuseIsIsolated drives many requests through the pooled capture and
// asserts every log record still carries its own status and byte count. | TestAccessLogConcurrentReuseIsIsolated
// 让大量请求复用池化捕获器，断言每条日志仍携带自身的状态码与字节数。
func TestAccessLogConcurrentReuseIsIsolated(t *testing.T) {
	type routeCase struct {
		path   string
		body   string
		status int
	}
	routes := []routeCase{
		{"/r0", "", http.StatusOK},
		{"/r1", "a", http.StatusOK},
		{"/r2", "bb", http.StatusCreated},
		{"/r3", strings.Repeat("c", 37), http.StatusAccepted},
		{"/r4", strings.Repeat("d", 129), http.StatusNonAuthoritativeInfo},
	}
	byPath := make(map[string]routeCase, len(routes))

	sink := &syncBuffer{}
	logger := log.New(log.Options{Writer: sink, Level: log.DebugLevel})
	r := router.New()
	r.Use(AccessLog(logger))
	for _, rt := range routes {
		rt := rt
		byPath[rt.path] = rt
		r.GET(rt.path, func(c *router.Ctx) { _ = c.String(rt.status, rt.body) })
	}

	const (
		workers    = 16
		iterations = 100
	)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rt := routes[(w+i)%len(routes)]
				rec := doReq(r, http.MethodGet, rt.path, nil, "")
				if rec.Code != rt.status {
					t.Errorf("%s: code = %d, 期望 %d", rt.path, rec.Code, rt.status)
				}
				if rec.Body.String() != rt.body {
					t.Errorf("%s: body = %q, 期望 %q", rt.path, rec.Body.String(), rt.body)
				}
			}
		}(w)
	}
	wg.Wait()

	counts := make(map[string]int, len(routes))
	for _, line := range strings.Split(strings.TrimSpace(sink.String()), "\n") {
		if line == "" {
			continue
		}
		entry := map[string]any{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("日志行不是合法 JSON: %v (行内容 %q)", err, line)
		}
		path, _ := entry["path"].(string)
		want, ok := byPath[path]
		if !ok {
			t.Fatalf("日志中的 path = %q 不属于任何测试路由", path)
		}
		counts[path]++
		if got := numField(t, entry, "status"); got != float64(want.status) {
			t.Errorf("%s: 日志 status = %v, 期望 %d", path, got, want.status)
		}
		if got := numField(t, entry, "bytes"); got != float64(len(want.body)) {
			t.Errorf("%s: 日志 bytes = %v, 期望 %d", path, got, len(want.body))
		}
	}
	for _, rt := range routes {
		if counts[rt.path] == 0 {
			t.Errorf("%s: 没有对应的日志记录", rt.path)
		}
	}
}

// Upgrade requests must keep a writable Hijacker. | 升级请求必须保持可用的 Hijacker。
func TestAccessLogKeepsHijackerOnUpgrade(t *testing.T) {
	logger, _ := newTestLogger()
	hijackable := false
	r := router.New()
	r.Use(AccessLog(logger))
	r.GET("/ws", func(c *router.Ctx) {
		_, hijackable = c.Writer.(http.Hijacker)
		_ = c.NoContent()
	})

	hj := &hijackRecorder{ResponseRecorder: newRecorder()}
	r.ServeHTTP(hj, newUpgradeRequest("/ws"))
	if !hijackable {
		t.Fatal("the upgraded request lost http.Hijacker on c.Writer")
	}
}

// TestAccessLogRemoteIPFollowsClientIPTrust requires remote_ip to follow the trusted-proxy
// model. | TestAccessLogRemoteIPFollowsClientIPTrust 要求 remote_ip 采用可信代理模型。
func TestAccessLogRemoteIPFollowsClientIPTrust(t *testing.T) {
	const peer = "203.0.113.9:443"
	const forwarded = "198.51.100.7, 203.0.113.10"
	tests := []struct {
		name    string
		trusted []netip.Prefix
		want    string
	}{
		{name: "default ignores the header", want: "203.0.113.9"},
		{
			name:    "trusted peer walks the chain from the right",
			trusted: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			want:    "198.51.100.7",
		},
		{
			name:    "untrusted peer ignores the header",
			trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			want:    "203.0.113.9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, buf := newTestLogger()
			r := router.New()
			r.Use(AccessLog(logger, AccessLogOptions{TrustedProxies: tt.trusted}))
			r.GET("/ip", func(c *router.Ctx) { _ = c.NoContent() })

			doReqFrom(r, http.MethodGet, "/ip", peer, map[string]string{"X-Forwarded-For": forwarded})
			if got := onlyRecord(t, buf)["remote_ip"]; got != tt.want {
				t.Fatalf("remote_ip = %v, want %q", got, tt.want)
			}
		})
	}
}

// TestMiddlewareWrapsPlainHandler proves the native entry point logs a plain handler. |
// TestMiddlewareWrapsPlainHandler 证明原生入口能为普通处理器记录日志。
func TestMiddlewareWrapsPlainHandler(t *testing.T) {
	logger, buf := newTestLogger()
	h := Middleware(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/plain", nil))

	entry := onlyRecord(t, buf)
	if got := numField(t, entry, "status"); got != http.StatusCreated {
		t.Fatalf("status = %v, want 201", got)
	}
	if got := numField(t, entry, "bytes"); got != 5 {
		t.Fatalf("bytes = %v, want 5", got)
	}
	if entry["path"] != "/plain" {
		t.Fatalf("path = %v, want /plain", entry["path"])
	}
}

// TestNativeChainSharesRequestID proves a single router.Adapt chain shares the request id
// between requestid and accesslog. | TestNativeChainSharesRequestID 证明单条 router.Adapt 链
// 能在 requestid 与 accesslog 之间共享请求 ID。
func TestNativeChainSharesRequestID(t *testing.T) {
	logger, buf := newTestLogger()
	h := router.Adapt(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), requestid.RequestID(""), AccessLog(logger))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/native", nil))

	entry := onlyRecord(t, buf)
	if got, _ := entry["request_id"].(string); got == "" {
		t.Fatal("request_id was empty in the native chain")
	}
	if got, _ := entry["request_id"].(string); got != rec.Header().Get("X-Request-Id") {
		t.Fatalf("request_id = %q, header = %q", got, rec.Header().Get("X-Request-Id"))
	}
}
