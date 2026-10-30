package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// TestMain silences the process default logger so rule failures do not flood the test output.
// | TestMain 关闭进程默认日志，避免规则失败记录淹没测试输出。
func TestMain(m *testing.M) {
	log.SetDefault(log.New(log.Options{Writer: io.Discard}))
	os.Exit(m.Run())
}

// Common SecLang rules shared by the tests. | 测试共用的 SecLang 规则。
const (
	ruleURI       = `SecRule REQUEST_URI "@contains attack" "id:1001,phase:1,deny,status:403,msg:'uri attack',severity:'CRITICAL',tag:'attack'"`
	ruleUA        = `SecRule REQUEST_HEADERS:User-Agent "@contains evil-bot" "id:1002,phase:1,deny,status:403,msg:'bad bot',severity:'WARNING'"`
	ruleReqBody   = `SecRule REQUEST_BODY "@contains attack-body" "id:1003,phase:2,deny,status:403,msg:'body attack',severity:'CRITICAL'"`
	ruleResHeader = `SecRule RESPONSE_HEADERS:X-Leak "@streq yes" "id:1004,phase:3,deny,status:403,msg:'leaky header',severity:'ERROR'"`
	ruleResBody   = `SecRule RESPONSE_BODY "@contains response-secret" "id:1005,phase:4,deny,status:403,msg:'leaky body',severity:'CRITICAL'"`
	ruleRedirect  = `SecRule REQUEST_URI "@contains redirect-me" "id:1006,phase:1,redirect:'https://example.com/blocked',status:302,msg:'redirected'"`
	ruleRemoteIP  = `SecRule REMOTE_ADDR "@streq 203.0.113.9" "id:1007,phase:1,deny,status:403,msg:'bad client'"`
)

// newWAF builds a WAF and registers cleanup. | newWAF 构造 WAF 并注册清理。
func newWAF(t *testing.T, o Options) *WAF {
	t.Helper()
	w, err := New(o)
	if err != nil {
		t.Fatalf("New() 失败: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// okHandler answers 200 ok. | okHandler 返回 200 ok。
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
}

// echoHandler writes the request body back. | echoHandler 回显请求正文。
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	})
}

// doNative runs one request through the native middleware. | doNative 通过原生中间件执行一次请求。
func doNative(w *WAF, h http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	w.HTTPMiddleware(h).ServeHTTP(rec, req)
	return rec
}

// doRouter runs one request through a YD router. | doRouter 通过 YD 路由执行一次请求。
func doRouter(r *router.Router, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// eventSink records observed events. | eventSink 记录观察到的事件。
type eventSink struct {
	mu     sync.Mutex
	events []Event
}

// observe implements Options.Observer. | observe 实现 Options.Observer。
func (s *eventSink) observe(ev Event) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

// only returns the single recorded event. | only 返回唯一记录的事件。
func (s *eventSink) only(t *testing.T) Event {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) != 1 {
		t.Fatalf("观察到 %d 个事件，期望 1 个: %+v", len(s.events), s.events)
	}
	return s.events[0]
}

// count returns the number of recorded events. | count 返回记录的事件数。
func (s *eventSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}
