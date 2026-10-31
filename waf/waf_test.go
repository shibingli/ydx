package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// newTestWAF builds an instance or fails the test. | newTestWAF 构建实例，失败则终止测试。
func newTestWAF(t *testing.T, directives []string, mutate func(*Options)) *WAF {
	t.Helper()
	options := Options{
		Directives: directives,
		Logger:     log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
	}
	if mutate != nil {
		mutate(&options)
	}
	instance, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	return instance
}

// httptestNewRequest builds a GET request for tests. | httptestNewRequest 为测试构建 GET 请求。
func httptestNewRequest(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// serveTest runs one request through an HTTP handler that writes a plain body. | serveTest 通过写
// 纯文本正文的处理器运行一个请求。
func serveTest(t *testing.T, instance *WAF, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(rw, "business-body")
	}))
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestBlockRequestURI(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains /etc/passwd" "id:9001,phase:1,deny,status:403,msg:'path traversal'"`,
	}, nil)
	response := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/download?file=/etc/passwd", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", response.Code, response.Body.String())
	}
	stats := instance.Stats()
	if stats.Blocked != 1 || stats.Inspected != 1 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestBlockQueryArgument(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS:q "@rx select\s+from" "id:9002,phase:2,deny,status:403,t:lowercase"`,
	}, nil)
	response := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/search?q=SELECT%20FROM%20users", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", response.Code, response.Body.String())
	}
}

func TestBlockFormBody(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:payload "@contains union select" "id:9003,phase:2,deny,status:403,t:lowercase"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader("payload=UNION+SELECT+1"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", response.Code, response.Body.String())
	}
}

func TestDetectionModeDoesNotBlock(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains attack" "id:9004,phase:1,deny,status:403"`,
	}, func(options *Options) { options.Mode = ModeDetection })
	response := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/attack", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if body := response.Body.String(); body != "business-body" {
		t.Fatalf("body = %q", body)
	}
	if stats := instance.Stats(); stats.Detected != 1 || stats.Blocked != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestRuleChain(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains /admin" "id:9010,phase:1,chain,deny,status:403"`,
		`SecRule REQUEST_METHOD "@rx ^POST$" "id:9011,phase:1"`,
	}, nil)
	blocked := serveTest(t, instance, httptest.NewRequest(http.MethodPost, "/admin", nil))
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("post status = %d, want 403", blocked.Code)
	}
	allowed := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if allowed.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", allowed.Code)
	}
}

func TestSetVarAnomalyScoring(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecAction "id:9020,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5"`,
		`SecAction "id:9021,phase:1,pass,nolog,setvar:tx.anomaly_score_pl1=0"`,
		`SecRule ARGS:q "@contains attack" "id:9022,phase:2,pass,nolog,setvar:tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}"`,
		`SecRule TX:anomaly_score_pl1 "@ge 5" "id:9023,phase:2,deny,status:403"`,
	}, nil)
	response := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/?q=attack", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", response.Code, response.Body.String())
	}
}

func TestSkipAfter(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains skip" "id:9030,phase:1,pass,nolog,skipAfter:END"`,
		`SecRule REQUEST_URI "@contains skip" "id:9031,phase:1,deny,status:403"`,
		`SecMarker END`,
	}, nil)
	response := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/skip", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", response.Code, response.Body.String())
	}
}

func TestBlockResponseBody(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains leaked-secret" "id:9040,phase:4,deny,status:403,msg:'secret leak'"`,
	}, func(options *Options) { options.ResponseBodyAccess = true })
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(rw, "prefix leaked-secret suffix")
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestBlockResponseHeaders(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_HEADERS:Content-Type "@contains text/plain" "id:9041,phase:3,deny,status:403"`,
	}, nil)
	response := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", response.Code, response.Body.String())
	}
}

func TestExcludeBypassesInspection(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains health" "id:9050,phase:1,deny,status:403"`,
	}, func(options *Options) {
		options.Exclude = func(r *http.Request) bool { return r.URL.Path == "/healthz" }
	})
	response := serveTest(t, instance, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if stats := instance.Stats(); stats.Bypassed != 1 || stats.Inspected != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestRequestBodyReplayedToHandler(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains nothing" "id:9060,phase:1,deny,status:403"`,
	}, nil)
	payload := "payload=hello"
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if string(body) != payload {
			t.Errorf("body = %q, want %q", body, payload)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestRouterIntegration(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains /forbidden" "id:9070,phase:1,deny,status:403"`,
	}, nil)
	engine := router.New()
	engine.Use(instance.Middleware())
	engine.GET("/forbidden", func(c *router.Ctx) {
		c.String(http.StatusOK, "unreachable")
	})
	engine.GET("/allowed", func(c *router.Ctx) {
		c.String(http.StatusOK, "allowed")
	})
	blocked := httptest.NewRecorder()
	engine.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/forbidden", nil))
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("blocked status = %d", blocked.Code)
	}
	allowed := httptest.NewRecorder()
	engine.ServeHTTP(allowed, httptest.NewRequest(http.MethodGet, "/allowed", nil))
	if allowed.Code != http.StatusOK || allowed.Body.String() != "allowed" {
		t.Fatalf("allowed = %d %q", allowed.Code, allowed.Body.String())
	}
}
