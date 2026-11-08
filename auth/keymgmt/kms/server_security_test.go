package kms

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// securedRequest performs one request with custom headers. | securedRequest 用自定义头执行一次请求。
func securedRequest(t *testing.T, handler http.Handler, method, target string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		payload = encoded
	}
	request := httptest.NewRequest(method, target, strings.NewReader(string(payload)))
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestServerSecurityOriginPolicy verifies cross-origin rejection, allowlisting and no-Origin
// requests. | TestServerSecurityOriginPolicy 校验跨域拒绝、允许列表与无 Origin 请求。
func TestServerSecurityOriginPolicy(t *testing.T) {
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{AllowedOrigins: []string{"https://console.example.com"}})
	handler := server.HTTPHandler("")
	create := createKeyJSON{Type: KeyTypeAES, Bits: 256}

	denied := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Origin": "https://evil.example.com"})
	expectStatus(t, denied, http.StatusForbidden)
	expectErrorCode(t, denied, "forbidden")

	nullOrigin := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Origin": "null"})
	expectStatus(t, nullOrigin, http.StatusForbidden)

	allowed := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Origin": "https://console.example.com"})
	expectStatus(t, allowed, http.StatusCreated)
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if !strings.Contains(allowed.Header().Get("Vary"), "Origin") {
		t.Fatalf("Vary = %q, want Origin", allowed.Header().Get("Vary"))
	}

	read := securedRequest(t, handler, http.MethodGet, "http://kms.example.com/keys", nil, map[string]string{"Origin": "https://console.example.com"})
	expectStatus(t, read, http.StatusOK)
	if got := read.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Fatalf("GET Access-Control-Allow-Origin = %q", got)
	}

	sameOrigin := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Origin": "http://kms.example.com"})
	expectStatus(t, sameOrigin, http.StatusCreated)

	noOrigin := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, nil)
	expectStatus(t, noOrigin, http.StatusCreated)
}

// TestServerSecuritySameOriginEnforcement verifies RequireSameOrigin evidence rules. | TestServerSecuritySameOriginEnforcement
// 校验 RequireSameOrigin 的证据规则。
func TestServerSecuritySameOriginEnforcement(t *testing.T) {
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{RequireSameOrigin: true})
	handler := server.HTTPHandler("")
	create := createKeyJSON{Type: KeyTypeAES, Bits: 256}

	same := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Origin": "http://kms.example.com"})
	expectStatus(t, same, http.StatusCreated)

	missing := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, nil)
	expectStatus(t, missing, http.StatusForbidden)

	noFetchSite := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Sec-Fetch-Site": "same-origin"})
	expectStatus(t, noFetchSite, http.StatusCreated)

	direct := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Sec-Fetch-Site": "none"})
	expectStatus(t, direct, http.StatusCreated)

	crossSite := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"Sec-Fetch-Site": "cross-site"})
	expectStatus(t, crossSite, http.StatusForbidden)

	safeRead := securedRequest(t, handler, http.MethodGet, "http://kms.example.com/keys", nil, nil)
	expectStatus(t, safeRead, http.StatusOK)
}

// TestServerSecurityCSRFHook verifies the cookie-auth CSRF hook contract. | TestServerSecurityCSRFHook
// 校验 Cookie 认证的 CSRF 钩子契约。
func TestServerSecurityCSRFHook(t *testing.T) {
	var calls int
	hook := func(r *http.Request) error {
		calls++
		if r.Header.Get("X-CSRF-Token") != "expected-token" {
			return errs.New("missing CSRF token | 缺少 CSRF 令牌")
		}
		return nil
	}
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{
		CookieAuth:     true,
		AllowedOrigins: []string{"https://console.example.com"},
		CSRFCheck:      hook,
	})
	handler := server.HTTPHandler("")
	create := createKeyJSON{Type: KeyTypeAES, Bits: 256}

	missing := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, nil)
	expectStatus(t, missing, http.StatusForbidden)
	if calls != 1 {
		t.Fatalf("hook calls = %d, want 1", calls)
	}

	valid := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{"X-CSRF-Token": "expected-token"})
	expectStatus(t, valid, http.StatusCreated)

	cross := securedRequest(t, handler, http.MethodPost, "http://kms.example.com/keys", create, map[string]string{
		"Origin":         "https://console.example.com",
		"X-CSRF-Token":   "expected-token",
		"Sec-Fetch-Site": "cross-site",
	})
	expectStatus(t, cross, http.StatusCreated)
	if got := cross.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Fatalf("cross-origin ACAO = %q", got)
	}
	if got := cross.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q", got)
	}

	calls = 0
	safe := securedRequest(t, handler, http.MethodGet, "http://kms.example.com/keys", nil, nil)
	expectStatus(t, safe, http.StatusOK)
	if calls != 0 {
		t.Fatalf("hook calls for safe method = %d, want 0", calls)
	}

	// A wildcard origin is rejected at construction time for cookie deployments. | Cookie 部署在构建时拒绝通配来源。
	if _, err := NewServer(server.Service(), ServerConfig{CookieAuth: true, AllowedOrigins: []string{"*"}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("wildcard CookieAuth err = %v", err)
	}
}

// TestServerSecurityCrossOriginNeedsCSRF verifies that a cross-origin state change is denied with
// only an origin allowlist and same-origin enforcement. | TestServerSecurityCrossOriginNeedsCSRF
// 校验仅有来源允许列表与同源强制时跨域状态变更被拒绝。
func TestServerSecurityCrossOriginNeedsCSRF(t *testing.T) {
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{
		RequireSameOrigin: true,
		AllowedOrigins:    []string{"https://console.example.com"},
	})
	recorder := securedRequest(t, server.HTTPHandler(""), http.MethodPost, "http://kms.example.com/keys",
		createKeyJSON{Type: KeyTypeAES, Bits: 256}, map[string]string{"Origin": "https://console.example.com"})
	expectStatus(t, recorder, http.StatusForbidden)
}

// TestServerSecurityHostValidation verifies the Host allowlist. | TestServerSecurityHostValidation
// 校验 Host 允许列表。
func TestServerSecurityHostValidation(t *testing.T) {
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{AllowedHosts: []string{"kms.example.com", "internal.example.com:8443"}})
	handler := server.HTTPHandler("")
	create := createKeyJSON{Type: KeyTypeAES, Bits: 256}

	bad := securedRequest(t, handler, http.MethodPost, "http://evil.example.com/keys", create, nil)
	expectStatus(t, bad, http.StatusForbidden)

	good := securedRequest(t, handler, http.MethodPost, "http://KMS.Example.com:80/keys", create, nil)
	expectStatus(t, good, http.StatusCreated)

	portedGood := securedRequest(t, handler, http.MethodPost, "http://internal.example.com:8443/keys", create, nil)
	expectStatus(t, portedGood, http.StatusCreated)

	portedBad := securedRequest(t, handler, http.MethodPost, "http://internal.example.com:9443/keys", create, nil)
	expectStatus(t, portedBad, http.StatusForbidden)
}

// TestServerSecurityPreflight verifies CORS preflight responses on both entry points. | TestServerSecurityPreflight
// 校验两个入口上的 CORS 预检响应。
func TestServerSecurityPreflight(t *testing.T) {
	server, _, _ := newTestHTTPPair(t, Config{}, ServerConfig{AllowedOrigins: []string{"https://console.example.com"}})
	handler := server.HTTPHandler("")
	headers := map[string]string{
		"Origin":                         "https://console.example.com",
		"Access-Control-Request-Method":  http.MethodPost,
		"Access-Control-Request-Headers": "content-type, x-csrf-token",
	}
	recorder := securedRequest(t, handler, http.MethodOptions, "http://kms.example.com/keys", nil, headers)
	expectStatus(t, recorder, http.StatusNoContent)
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Fatalf("preflight ACAO = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, http.MethodPost) {
		t.Fatalf("preflight ACAM = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "x-csrf-token") {
		t.Fatalf("preflight ACAH = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Max-Age"); got == "" {
		t.Fatal("preflight missing Access-Control-Max-Age")
	}

	plain := securedRequest(t, handler, http.MethodOptions, "http://kms.example.com/keys", nil, nil)
	expectStatus(t, plain, http.StatusNoContent)
	if got := plain.Header().Get("Allow"); !strings.Contains(got, http.MethodPost) {
		t.Fatalf("OPTIONS Allow = %q", got)
	}

	deniedHeaders := map[string]string{
		"Origin":                        "https://evil.example.com",
		"Access-Control-Request-Method": http.MethodPost,
	}
	denied := securedRequest(t, handler, http.MethodOptions, "http://kms.example.com/keys", nil, deniedHeaders)
	expectStatus(t, denied, http.StatusForbidden)

	r := router.New()
	server.Register(r, "kms")
	routerRecorder := securedRequest(t, r, http.MethodOptions, "http://kms.example.com/kms/keys", nil, headers)
	expectStatus(t, routerRecorder, http.StatusNoContent)
	if got := routerRecorder.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Fatalf("router preflight ACAO = %q", got)
	}

	routerDenied := securedRequest(t, r, http.MethodPost, "http://kms.example.com/kms/keys",
		createKeyJSON{Type: KeyTypeAES, Bits: 256}, map[string]string{"Origin": "https://evil.example.com"})
	expectStatus(t, routerDenied, http.StatusForbidden)

	wildcard, err := NewServer(server.Service(), ServerConfig{AllowedOrigins: []string{"*"}})
	if err != nil {
		t.Fatalf("NewServer wildcard: %v", err)
	}
	wildcardRecorder := securedRequest(t, wildcard.HTTPHandler(""), http.MethodOptions, "http://kms.example.com/keys", nil, deniedHeaders)
	expectStatus(t, wildcardRecorder, http.StatusNoContent)
	if got := wildcardRecorder.Header().Get("Access-Control-Allow-Origin"); got != "https://evil.example.com" {
		t.Fatalf("wildcard preflight ACAO = %q", got)
	}
}

// TestNewServerSecurityValidation verifies configuration validation. | TestNewServerSecurityValidation
// 校验配置校验。
func TestNewServerSecurityValidation(t *testing.T) {
	service, _ := newServiceForTest(t, Config{})
	cases := []struct {
		name   string
		config ServerConfig
	}{
		{"bad scheme", ServerConfig{AllowedOrigins: []string{"ftp://app.example.com"}}},
		{"origin path", ServerConfig{AllowedOrigins: []string{"https://app.example.com/path"}}},
		{"origin userinfo", ServerConfig{AllowedOrigins: []string{"https://user@app.example.com"}}},
		{"opaque origin", ServerConfig{AllowedOrigins: []string{"null"}}},
		{"wildcard cookie auth", ServerConfig{AllowedOrigins: []string{"*"}, CookieAuth: true}},
		{"host path", ServerConfig{AllowedHosts: []string{"app.example.com/path"}}},
		{"host whitespace", ServerConfig{AllowedHosts: []string{"app example.com"}}},
	}
	for _, tc := range cases {
		if _, err := NewServer(service, tc.config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s: err = %v, want ErrInvalidConfig", tc.name, err)
		}
	}
	valid := ServerConfig{
		AllowedOrigins:    []string{"https://app.example.com:443", "https://app.example.com"},
		AllowedHosts:      []string{"app.example.com:443", "*"},
		RequireSameOrigin: true,
		CookieAuth:        true,
		CSRFCheck:         func(*http.Request) error { return nil },
	}
	if _, err := NewServer(service, valid); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}
