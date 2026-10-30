package waf

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/shibingli/ydx/router"
)

func TestNewRejectsEmptyRuleSet(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrNoRules) {
		t.Fatalf("New() 错误 = %v，期望 ErrNoRules", err)
	}
	if _, err := New(Options{Mode: ModeOff}); !errors.Is(err, ErrNoRules) {
		t.Fatalf("New(ModeOff) 错误 = %v，期望 ErrNoRules", err)
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want error
	}{
		{"非法模式", Options{Directives: []string{ruleURI}, Mode: Mode(99)}, ErrInvalidMode},
		{"负数请求体上限", Options{Directives: []string{ruleURI}, RequestBodyLimit: -1}, ErrInvalidLimit},
		{"负数内存上限", Options{Directives: []string{ruleURI}, RequestBodyInMemoryLimit: -1}, ErrInvalidLimit},
		{"负数响应体上限", Options{Directives: []string{ruleURI}, ResponseBodyLimit: -1}, ErrInvalidLimit},
		{"非法 MIME", Options{Directives: []string{ruleURI}, ResponseBodyAccess: true, ResponseBodyMimeTypes: []string{"text/plain extra"}}, ErrInvalidMimeType},
		{"空规则文件", Options{RuleFiles: []string{" "}}, ErrInvalidOption},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("New() 错误 = %v，期望 %v", err, tc.want)
			}
		})
	}
}

func TestNewWrapsBuildError(t *testing.T) {
	_, err := New(Options{Directives: []string{"SecRule THIS_IS_INVALID"}})
	if !errors.Is(err, ErrBuild) {
		t.Fatalf("New() 错误 = %v，期望 ErrBuild", err)
	}
}

func TestRulesCount(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI, ruleUA}})
	if got := w.RulesCount(); got != 2 {
		t.Fatalf("RulesCount() = %d，期望 2", got)
	}
}

func TestYDMiddlewareBlocksRequest(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	var reached atomic.Bool
	r := router.New()
	r.Use(w.Middleware())
	r.GET("/attack", func(c *router.Ctx) {
		reached.Store(true)
		_ = c.String(http.StatusOK, "should not run")
	})
	r.GET("/safe", func(c *router.Ctx) { _ = c.String(http.StatusOK, "ok") })

	rec := doRouter(r, http.MethodGet, "/attack", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("被拦截请求状态 = %d，期望 403", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q，期望 no-store", got)
	}
	if reached.Load() {
		t.Fatal("被拦截请求不应进入业务处理器")
	}
	if strings.Contains(rec.Body.String(), "should not run") {
		t.Fatalf("响应泄漏了业务内容: %q", rec.Body.String())
	}
	if rec := doRouter(r, http.MethodGet, "/safe", "", nil); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("安全请求被误拦: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestNativeMiddlewareBlocksHeader(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleUA}})
	rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", map[string]string{"User-Agent": "evil-bot/1.0"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	rec = doNative(w, okHandler(), http.MethodGet, "/safe", "", map[string]string{"User-Agent": "good-bot/1.0"})
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("正常请求被误拦: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestCustomErrorHandler(t *testing.T) {
	w := newWAF(t, Options{
		Directives: []string{ruleURI},
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, it *Interruption) {
			if it.Status != http.StatusForbidden {
				t.Errorf("回调状态 = %d，期望 403", it.Status)
			}
			if it.RuleID != 1001 {
				t.Errorf("回调规则 ID = %d，期望 1001", it.RuleID)
			}
			rw.Header().Set("X-Blocked", "yes")
			rw.WriteHeader(http.StatusTeapot)
			_, _ = rw.Write([]byte("custom block"))
		},
	})
	rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("状态 = %d，期望 418", rec.Code)
	}
	if got := rec.Header().Get("X-Blocked"); got != "yes" {
		t.Fatalf("X-Blocked = %q，期望 yes", got)
	}
	if rec.Body.String() != "custom block" {
		t.Fatalf("正文 = %q，期望 custom block", rec.Body.String())
	}
}

func TestExcludeBypassesInspection(t *testing.T) {
	var excluded atomic.Int64
	sink := &eventSink{}
	w := newWAF(t, Options{
		Directives: []string{ruleURI},
		Observer:   sink.observe,
		Exclude: func(r *http.Request) bool {
			if r.URL.Path == "/health" {
				excluded.Add(1)
				return true
			}
			return false
		},
	})
	rec := doNative(w, okHandler(), http.MethodGet, "/health?q=attack", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("排除路径状态 = %d，期望 200", rec.Code)
	}
	if excluded.Load() != 1 {
		t.Fatalf("排除回调次数 = %d，期望 1", excluded.Load())
	}
	if got := w.Stats().Bypassed; got != 1 {
		t.Fatalf("Bypassed = %d，期望 1", got)
	}
	if got := w.Stats().Inspected; got != 0 {
		t.Fatalf("Inspected = %d，期望 0", got)
	}
	if got := sink.count(); got != 0 {
		t.Fatalf("旁路请求不应产生 Observer 事件，实际 %d 个", got)
	}
}

func TestDetectionModeReportsWithoutBlocking(t *testing.T) {
	sink := &eventSink{}
	w := newWAF(t, Options{
		Directives: []string{ruleURI},
		Mode:       ModeDetection,
		Observer:   sink.observe,
	})
	rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("检测模式不应拦截: code=%d body=%q", rec.Code, rec.Body.String())
	}
	stats := w.Stats()
	if stats.Detected != 1 || stats.Blocked != 0 {
		t.Fatalf("Detected=%d Blocked=%d，期望 1/0", stats.Detected, stats.Blocked)
	}
	ev := sink.only(t)
	if !ev.Detected || ev.Blocked {
		t.Fatalf("事件 Detected=%v Blocked=%v，期望 true/false", ev.Detected, ev.Blocked)
	}
	if ev.Interruption == nil || ev.Interruption.RuleID != 1001 {
		t.Fatalf("事件中断信息 = %+v，期望规则 1001", ev.Interruption)
	}
	if ev.Phase != PhaseRequest {
		t.Fatalf("事件阶段 = %v，期望 PhaseRequest", ev.Phase)
	}
	if len(ev.Matches) == 0 {
		t.Fatal("事件 Matches 为空，期望包含命中规则")
	}
}

func TestModeOffPassesThrough(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}, Mode: ModeOff})
	rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("关闭模式不应拦截: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := w.Stats().Bypassed; got != 1 {
		t.Fatalf("Bypassed = %d，期望 1", got)
	}
}

func TestRedirectInterruption(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleRedirect}})
	rec := doNative(w, okHandler(), http.MethodGet, "/redirect-me", "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("状态 = %d，期望 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://example.com/blocked" {
		t.Fatalf("Location = %q，期望重定向目标", got)
	}
}

func TestClientIPOverride(t *testing.T) {
	sink := &eventSink{}
	w := newWAF(t, Options{
		Directives: []string{ruleRemoteIP},
		ClientIP:   func(*http.Request) string { return "203.0.113.9" },
		Observer:   sink.observe,
	})
	rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
	if ev := sink.only(t); ev.ClientIP != "203.0.113.9" {
		t.Fatalf("事件 ClientIP = %q，期望 203.0.113.9", ev.ClientIP)
	}
}

func TestObserverReportsNormalRequest(t *testing.T) {
	sink := &eventSink{}
	w := newWAF(t, Options{Directives: []string{ruleURI}, Observer: sink.observe})
	rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	ev := sink.only(t)
	if ev.Blocked || ev.Detected || ev.Interruption != nil {
		t.Fatalf("正常请求事件异常: %+v", ev)
	}
	if ev.Status != http.StatusOK || ev.Method != http.MethodGet || ev.Path != "/safe" {
		t.Fatalf("事件字段异常: %+v", ev)
	}
	if ev.ID == "" {
		t.Fatal("事件事务 ID 为空")
	}
	if ev.Duration < 0 {
		t.Fatalf("事件耗时为负: %v", ev.Duration)
	}
}

func TestRootFSRules(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/main.conf": &fstest.MapFile{Data: []byte(ruleURI)},
	}
	w := newWAF(t, Options{RootFS: fsys, RuleFiles: []string{"rules/main.conf"}})
	rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("状态 = %d，期望 403", rec.Code)
	}
}

func TestRootFSGlobRules(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/a.conf": &fstest.MapFile{Data: []byte(ruleURI)},
		"rules/b.conf": &fstest.MapFile{Data: []byte(ruleUA)},
	}
	w := newWAF(t, Options{RootFS: fsys, RuleFiles: []string{"rules/*.conf"}})
	if got := w.RulesCount(); got != 2 {
		t.Fatalf("RulesCount = %d，期望 2", got)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("glob 规则未生效: %d", rec.Code)
	}
}

func TestRootFSIncludeRules(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/main.conf":  &fstest.MapFile{Data: []byte("Include extra.conf\n")},
		"rules/extra.conf": &fstest.MapFile{Data: []byte(ruleURI)},
	}
	w := newWAF(t, Options{RootFS: fsys, RuleFiles: []string{"rules/main.conf"}})
	if rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("Include 规则未生效: %d", rec.Code)
	}
}

func TestOSGlobRules(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, filepath.Join(dir, "a.conf"), ruleURI)
	writeRuleFile(t, filepath.Join(dir, "b.conf"), ruleUA)
	w := newWAF(t, Options{RuleFiles: []string{filepath.Join(dir, "*.conf")}})
	if got := w.RulesCount(); got != 2 {
		t.Fatalf("RulesCount = %d，期望 2", got)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("glob 规则未生效: %d", rec.Code)
	}
}

func TestRuleFilesCannotWeakenBaseline(t *testing.T) {
	fsys := fstest.MapFS{
		"rules.conf": &fstest.MapFile{Data: []byte("SecRuleEngine Off\n" + ruleURI + "\n")},
	}
	w := newWAF(t, Options{RootFS: fsys, RuleFiles: []string{"rules.conf"}, Mode: ModeBlock})
	rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("规则文件关闭引擎后状态 = %d，期望基线仍拦截", rec.Code)
	}
}

func TestDirectivesOverrideBaseline(t *testing.T) {
	w := newWAF(t, Options{
		Directives: []string{ruleURI, "SecRuleEngine Off"},
		Mode:       ModeBlock,
	})
	rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("内联指令关闭引擎后状态 = %d，期望放行", rec.Code)
	}
	if got := w.Stats().Bypassed; got != 1 {
		t.Fatalf("Bypassed = %d，期望 1", got)
	}
}

func TestStatsInFlightReturnsToZero(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	stats := w.Stats()
	if stats.Inspected != 1 || stats.InFlight != 0 {
		t.Fatalf("Inspected=%d InFlight=%d，期望 1/0", stats.Inspected, stats.InFlight)
	}
}

func TestPhaseIntrospectionFlags(t *testing.T) {
	headerOnly := newWAF(t, Options{Directives: []string{ruleURI}}).current.Load()
	if headerOnly.readRequestBody {
		t.Fatal("仅 phase 1 规则不应缓冲请求正文")
	}
	if headerOnly.inspectResponse.headers || headerOnly.inspectResponse.body {
		t.Fatal("仅 phase 1 规则不应处理响应头/正文")
	}

	requestBody := newWAF(t, Options{Directives: []string{ruleReqBody}}).current.Load()
	if !requestBody.readRequestBody {
		t.Fatal("phase 2 规则必须缓冲请求正文")
	}
	if requestBody.inspectResponse.headers || requestBody.inspectResponse.body {
		t.Fatal("仅请求规则不应处理响应头/正文")
	}

	response := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
	}).current.Load()
	if !response.inspectResponse.headers || !response.inspectResponse.body {
		t.Fatal("phase 4 规则必须处理响应头与正文")
	}
}

func TestAuditConfigured(t *testing.T) {
	if !auditConfigured([]string{"SecAuditEngine RelevantOnly"}) {
		t.Fatal("应识别 SecAuditEngine 指令")
	}
	if !auditConfigured([]string{`SecRule REQUEST_URI "@contains x" "id:1,phase:1,pass,ctl:auditEngine=On"`}) {
		t.Fatal("应识别 ctl:auditEngine")
	}
	if auditConfigured([]string{"SecRuleEngine On"}) {
		t.Fatal("无关指令不应触发审计保护")
	}
}

func TestAuditRuleKeepsBodyInspection(t *testing.T) {
	// The audit engine is enabled by a rule in a RuleFile, not by Directives; the raw-rule scan
	// must still prevent the automatic body/response skips. | 审计由 RuleFile 中的规则通过 ctl
	// 开启；原始规则扫描必须阻止自动跳过正文与响应。
	fsys := fstest.MapFS{
		"rules.conf": &fstest.MapFile{Data: []byte(
			`SecRule REQUEST_URI "@contains audit-me" "id:920001,phase:1,pass,ctl:auditEngine=On"` + "\n" + ruleURI + "\n",
		)},
	}
	w := newWAF(t, Options{
		RootFS:             fsys,
		RuleFiles:          []string{"rules.conf"},
		ResponseBodyAccess: true,
	})
	e := w.current.Load()
	if !e.readRequestBody {
		t.Fatal("审计规则存在时必须保留请求正文")
	}
	if !e.inspectResponse.headers || !e.inspectResponse.body {
		t.Fatal("审计规则存在时必须保留响应头与正文处理")
	}
}

func TestDebugLogWriter(t *testing.T) {
	var buf bytes.Buffer
	w := newWAF(t, Options{Directives: []string{ruleURI}, DebugLogWriter: &buf})
	rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	if buf.Len() == 0 {
		t.Fatal("DebugLogWriter 未收到 Coraza 调试输出")
	}
}

func TestNativeMiddlewareNilNext(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	req := httptest.NewRequest(http.MethodGet, "/safe", nil)
	rec := httptest.NewRecorder()
	w.HTTPMiddleware(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nil next 状态 = %d，期望 404", rec.Code)
	}
}
