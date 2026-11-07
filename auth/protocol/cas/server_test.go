package cas

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/router"
)

// rejectingCSRF fails every verification. | rejectingCSRF 拒绝所有校验。
type rejectingCSRF struct{}

// Token implements CSRFProtector. | Token 实现 CSRFProtector。
func (rejectingCSRF) Token(*http.Request) string { return "csrf-rejected" }

// Verify implements CSRFProtector. | Verify 实现 CSRFProtector。
func (rejectingCSRF) Verify(*http.Request) bool { return false }

// headerCSRF verifies the csrf_token form field against a fixed value. | headerCSRF 用固定值校验
// csrf_token 表单字段。
type headerCSRF struct{ token string }

// Token implements CSRFProtector. | Token 实现 CSRFProtector。
func (c headerCSRF) Token(*http.Request) string { return c.token }

// Verify implements CSRFProtector. | Verify 实现 CSRFProtector。
func (c headerCSRF) Verify(r *http.Request) bool { return r.FormValue(csrfField) == c.token }

func TestLoginPageRendersForm(t *testing.T) {
	server, _, _ := newTestServer(t, func(config *ServerConfig) {
		config.CSRFProtector = headerCSRF{token: "csrf-value"}
	})
	handler := newTestRouter(t, server)
	target := "/cas/login?service=" + url.QueryEscape(testAppService) + "&renew=true&warn=true"
	recorder := serve(t, handler, http.MethodGet, target, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	body := recorder.Body.String()
	for _, fragment := range []string{
		`name="username"`,
		`name="password"`,
		`name="service"`,
		`value="` + testAppService + `"`,
		`name="renew"`,
		`name="warn"`,
		`name="csrf_token" value="csrf-value"`,
		`name="rememberMe"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("login page missing %q; body: %s", fragment, body)
		}
	}
	if recorder.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", recorder.Header().Get("X-Frame-Options"))
	}
}

func TestLoginRejectsUnregisteredService(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	recorder := serve(t, handler, http.MethodGet, "/cas/login?service="+url.QueryEscape("https://evil.example.net/"), nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestLoginPOSTIssuesTicketAndTGC(t *testing.T) {
	server, store, clock := newTestServer(t)
	handler := newTestRouter(t, server)
	recorder := loginForm(t, handler, "alice", "secret", testAppService, nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body: %s", recorder.Code, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Location %q: %v", location, err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != testAppService {
		t.Fatalf("Location = %q, want service %q", location, testAppService)
	}
	stID := parsed.Query().Get("ticket")
	if !strings.HasPrefix(stID, TicketPrefixST) {
		t.Fatalf("ticket = %q, want ST prefix", stID)
	}
	cookie := tgcFrom(t, recorder)
	if !cookie.HttpOnly {
		t.Fatalf("TGC cookie is not HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("TGC SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Fatalf("TGC Path = %q, want /", cookie.Path)
	}
	if cookie.Secure {
		t.Fatalf("TGC Secure = true for a plain-HTTP test server")
	}
	if cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		t.Fatalf("non-remembered TGC is persistent: MaxAge=%d Expires=%v", cookie.MaxAge, cookie.Expires)
	}
	tgtID := cookie.Value
	if !strings.HasPrefix(tgtID, TicketPrefixTGT) {
		t.Fatalf("TGC value = %q, want TGT prefix", tgtID)
	}
	tgt, err := store.Get(t.Context(), tgtID)
	if err != nil {
		t.Fatalf("stored TGT: %v", err)
	}
	if tgt.UserID != "user-1" || tgt.Principal == nil || tgt.Principal.Username != "alice" {
		t.Fatalf("TGT user = %q/%#v", tgt.UserID, tgt.Principal)
	}
	st, err := store.Get(t.Context(), stID)
	if err != nil {
		t.Fatalf("stored ST: %v", err)
	}
	if st.Service != testAppService || st.ParentID != tgtID || st.RootTGTID != tgtID {
		t.Fatalf("ST binding = %#v", st)
	}
	if !st.IssuedAt.Equal(clock.Now()) {
		t.Fatalf("ST IssuedAt = %v, want %v", st.IssuedAt, clock.Now())
	}
}

func TestLoginPOSTRejectsBadCredentials(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cases := []struct {
		username string
		password string
		fragment string
	}{
		{"alice", "wrong", "Invalid username or password"},
		{"unknown", "secret", "Invalid username or password"},
		{"", "", "Invalid username or password"},
		{"locked", "secret", "Account is locked"},
		{"mfa", "secret", "Multi-factor authentication is not available"},
	}
	for _, tc := range cases {
		recorder := loginForm(t, handler, tc.username, tc.password, "", nil)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d, want 401", tc.username, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), tc.fragment) {
			t.Fatalf("%s body = %q, want %q", tc.username, recorder.Body.String(), tc.fragment)
		}
		if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
			t.Fatalf("%s set cookies on failure: %v", tc.username, cookies)
		}
	}
}

func TestLoginRememberMePersistsCookie(t *testing.T) {
	server, _, clock := newTestServer(t)
	handler := newTestRouter(t, server)
	extra := url.Values{}
	extra.Set("rememberMe", "true")
	recorder := loginForm(t, handler, "alice", "secret", "", extra)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", recorder.Code)
	}
	cookie := tgcFrom(t, recorder)
	if cookie.MaxAge <= 0 {
		t.Fatalf("remembered TGC MaxAge = %d, want > 0", cookie.MaxAge)
	}
	if !cookie.Expires.After(clock.Now()) {
		t.Fatalf("remembered TGC Expires = %v, want after %v", cookie.Expires, clock.Now())
	}
}

func TestLoginSSOReusesTGC(t *testing.T) {
	server, store, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cookie := loginTGC(t, handler)
	recorder := serve(t, handler, http.MethodGet, "/cas/login?service="+url.QueryEscape(testOtherService), nil, cookie)
	if recorder.Code != http.StatusFound {
		t.Fatalf("SSO login status = %d, want 302; body: %s", recorder.Code, recorder.Body.String())
	}
	stID := ticketFromLocation(t, recorder)
	if !strings.HasPrefix(stID, TicketPrefixST) {
		t.Fatalf("SSO ticket = %q", stID)
	}
	st, err := store.Get(t.Context(), stID)
	if err != nil {
		t.Fatalf("stored SSO ticket: %v", err)
	}
	if st.Service != testOtherService || st.RootTGTID != cookie.Value {
		t.Fatalf("SSO ticket binding = %#v", st)
	}
}

func TestLoginLoggedInPageWithoutService(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cookie := loginTGC(t, handler)
	recorder := serve(t, handler, http.MethodGet, "/cas/login", nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Signed in") || !strings.Contains(body, "Alice") {
		t.Fatalf("logged-in page = %q", body)
	}
}

func TestLoginGateway(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	recorder := serve(t, handler, http.MethodGet, "/cas/login?gateway=true&service="+url.QueryEscape(testAppService), nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("gateway status = %d, want 302", recorder.Code)
	}
	location := recorder.Header().Get("Location")
	if location != testAppService {
		t.Fatalf("gateway Location = %q, want the bare service", location)
	}
	if strings.Contains(location, "ticket=") {
		t.Fatalf("gateway Location carries a ticket: %q", location)
	}
	cookie := loginTGC(t, handler)
	recorder = serve(t, handler, http.MethodGet, "/cas/login?gateway=true&service="+url.QueryEscape(testAppService), nil, cookie)
	if recorder.Code != http.StatusFound {
		t.Fatalf("authenticated gateway status = %d, want 302", recorder.Code)
	}
	if ticket := ticketFromLocation(t, recorder); !strings.HasPrefix(ticket, TicketPrefixST) {
		t.Fatalf("authenticated gateway ticket = %q", ticket)
	}
	recorder = serve(t, handler, http.MethodGet, "/cas/login?gateway=true&renew=true&service="+url.QueryEscape(testAppService), nil, cookie)
	if recorder.Code != http.StatusFound {
		t.Fatalf("gateway renew status = %d, want 302", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != testAppService {
		t.Fatalf("gateway renew Location = %q, want the bare service", location)
	}
	recorder = serve(t, handler, http.MethodGet, "/cas/login?gateway=true", nil)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Sign in") {
		t.Fatalf("gateway without service status = %d, want the login form", recorder.Code)
	}
}

func TestLoginRenewForcesReauthentication(t *testing.T) {
	server, store, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cookie := loginTGC(t, handler)
	oldTGT := cookie.Value
	recorder := serve(t, handler, http.MethodGet, "/cas/login?renew=true&service="+url.QueryEscape(testAppService), nil, cookie)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `name="renew"`) {
		t.Fatalf("renew GET status = %d, want the login form", recorder.Code)
	}
	extra := url.Values{}
	extra.Set("renew", "true")
	recorder = loginForm(t, handler, "alice", "secret", testAppService, extra, cookie)
	if recorder.Code != http.StatusFound {
		t.Fatalf("renew POST status = %d, want 302; body: %s", recorder.Code, recorder.Body.String())
	}
	newCookie := tgcFrom(t, recorder)
	if newCookie.Value == oldTGT {
		t.Fatalf("renew reused the old TGT")
	}
	if _, err := store.Get(t.Context(), oldTGT); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("old TGT still present after renew: %v", err)
	}
	st, err := store.Get(t.Context(), ticketFromLocation(t, recorder))
	if err != nil {
		t.Fatalf("renew ST: %v", err)
	}
	if !st.Renewal {
		t.Fatalf("renew ST does not carry the renewal flag")
	}
}

func TestLoginCSRF(t *testing.T) {
	server, _, _ := newTestServer(t, func(config *ServerConfig) {
		config.CSRFProtector = rejectingCSRF{}
	})
	handler := newTestRouter(t, server)
	recorder := loginForm(t, handler, "alice", "secret", "", nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "form expired") {
		t.Fatalf("body = %q", recorder.Body.String())
	}

	server, _, _ = newTestServer(t, func(config *ServerConfig) {
		config.CSRFProtector = headerCSRF{token: "expected"}
	})
	handler = newTestRouter(t, server)
	recorder = loginForm(t, handler, "alice", "secret", "", nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing token status = %d, want 403", recorder.Code)
	}
	extra := url.Values{}
	extra.Set(csrfField, "expected")
	recorder = loginForm(t, handler, "alice", "secret", "", extra)
	if recorder.Code != http.StatusFound {
		t.Fatalf("valid token status = %d, want 302", recorder.Code)
	}
}

func TestLogoutDestroysTicketFamily(t *testing.T) {
	server, store, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cookie, stID := loginAndTicket(t, handler, testAppService)
	recorder := serve(t, handler, http.MethodGet, "/cas/logout?service="+url.QueryEscape(testOtherService), nil, cookie)
	if recorder.Code != http.StatusFound {
		t.Fatalf("logout status = %d, want 302", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != testOtherService {
		t.Fatalf("logout Location = %q", location)
	}
	cleared := false
	for _, setCookie := range recorder.Result().Cookies() {
		if setCookie.Name == CookieNameTGC && setCookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("logout did not expire the TGC cookie")
	}
	if _, err := store.Get(t.Context(), cookie.Value); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("TGT survived logout: %v", err)
	}
	if _, err := store.Get(t.Context(), stID); !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("derived ST survived logout: %v", err)
	}
}

func TestLogoutIgnoresUnregisteredRedirect(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	cookie := loginTGC(t, handler)
	recorder := serve(t, handler, http.MethodGet, "/cas/logout?service="+url.QueryEscape("https://evil.example.net/"), nil, cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Signed out") {
		t.Fatalf("body = %q, want the sign-out page", recorder.Body.String())
	}
}

func TestRouterMiddleware(t *testing.T) {
	server, _, _ := newTestServer(t)
	tgt, _ := issueTestTickets(t, server, testAppService)
	middleware := server.Middleware(MiddlewareOptions{RequireTGT: true, LoginPath: "/cas/login"})

	protected := router.New()
	protected.Use(middleware)
	protected.GET("/private", func(c *router.Ctx) {
		principal, ok := auth.PrincipalFromCtx(c)
		if !ok {
			_, _ = c.Writer.Write([]byte("anonymous"))
			return
		}
		_, _ = c.Writer.Write([]byte(principal.Username))
	})
	recorder := serve(t, protected, http.MethodGet, "/private", nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("unauthenticated status = %d, want 302", recorder.Code)
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, "/cas/login?") || !strings.Contains(location, url.QueryEscape("http://example.com/private")) {
		t.Fatalf("redirect Location = %q", location)
	}
	cookie := &http.Cookie{Name: CookieNameTGC, Value: tgt.ID}
	recorder = serve(t, protected, http.MethodGet, "/private", nil, cookie)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "alice" {
		t.Fatalf("authenticated response = %d %q, want alice", recorder.Code, recorder.Body.String())
	}

	optional := router.New()
	optional.Use(server.Middleware(MiddlewareOptions{}))
	optional.GET("/public", func(c *router.Ctx) {
		if _, ok := auth.PrincipalFromCtx(c); ok {
			_, _ = c.Writer.Write([]byte("principal"))
			return
		}
		_, _ = c.Writer.Write([]byte("anonymous"))
	})
	recorder = serve(t, optional, http.MethodGet, "/public", nil)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "anonymous" {
		t.Fatalf("optional middleware response = %d %q", recorder.Code, recorder.Body.String())
	}

	api := router.New()
	api.Use(server.Middleware(MiddlewareOptions{RequireTGT: true}))
	api.GET("/api", func(c *router.Ctx) {})
	recorder = serve(t, api, http.MethodGet, "/api", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("API middleware status = %d, want 401", recorder.Code)
	}
}

func TestHTTPMiddleware(t *testing.T) {
	server, _, _ := newTestServer(t)
	tgt, _ := issueTestTickets(t, server, testAppService)
	handler := server.HTTPMiddleware(MiddlewareOptions{RequireTGT: true, LoginPath: "/cas/login"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromRequest(r)
		if !ok {
			_, _ = w.Write([]byte("anonymous"))
			return
		}
		_, _ = w.Write([]byte(principal.Username))
	}))
	recorder := serve(t, handler, http.MethodGet, "/private", nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("unauthenticated status = %d, want 302", recorder.Code)
	}
	cookie := &http.Cookie{Name: CookieNameTGC, Value: tgt.ID}
	recorder = serve(t, handler, http.MethodGet, "/private", nil, cookie)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "alice" {
		t.Fatalf("authenticated response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestHTTPHandler(t *testing.T) {
	server, _, _ := newTestServer(t)
	httpServer := httptest.NewServer(server.HTTPHandler("/cas"))
	defer httpServer.Close()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Get(httpServer.URL + "/cas/login?service=" + url.QueryEscape(testAppService))
	if err != nil {
		t.Fatalf("GET login: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in") {
		t.Fatalf("login = %d %q", response.StatusCode, body)
	}
	response, err = client.PostForm(httpServer.URL+"/cas/login", url.Values{
		"username": {"alice"},
		"password": {"secret"},
		"service":  {testAppService},
	})
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("POST login status = %d, want 302", response.StatusCode)
	}
	if !strings.Contains(response.Header.Get("Location"), "ticket=ST-") {
		t.Fatalf("POST login Location = %q", response.Header.Get("Location"))
	}
}

func TestEndpointURL(t *testing.T) {
	server, _, _ := newTestServer(t)
	if got := server.EndpointURL("/cas", "/login"); got != testIssuer+"/cas/login" {
		t.Fatalf("EndpointURL = %q", got)
	}
	if got := server.EndpointURL("", "/login"); got != testIssuer+"/login" {
		t.Fatalf("EndpointURL without prefix = %q", got)
	}
}

func TestNewServerConfigValidation(t *testing.T) {
	if _, err := NewServer(ServerConfig{Issuer: testIssuer}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing authenticator error = %v", err)
	}
	if _, err := NewServer(ServerConfig{Authenticator: AuthenticatorFunc(testAuthenticator)}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing issuer error = %v", err)
	}
	if _, err := NewServer(ServerConfig{
		Issuer:        testIssuer,
		Authenticator: AuthenticatorFunc(testAuthenticator),
		CookieConfig:  CookieConfig{SameSite: http.SameSiteNoneMode},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("SameSite=None without Secure error = %v", err)
	}
}

// TestServiceURLValidation checks that non-http(s), protocol-relative, relative and
// credential-bearing service URLs can never receive a ticket even when the registry allows
// everything. | TestServiceURLValidation 检查即使注册表允许全部，非 http(s)、协议相对、相对以及
// 携带凭据的服务 URL 也永远无法获得票据。
func TestServiceURLValidation(t *testing.T) {
	server, _, _ := newTestServer(t, func(config *ServerConfig) {
		config.ServiceRegistry = NewAllowAllServiceRegistry()
	})
	handler := newTestRouter(t, server)
	invalid := []string{
		"javascript:alert(1)",
		"data:text/html,hello",
		"//evil.example.com/path",
		"/relative/path",
		"https://user:pass@app.example.com/callback",
		"https://",
		"mailto:alice@example.com",
	}
	for _, service := range invalid {
		t.Run(service, func(t *testing.T) {
			recorder := serve(t, handler, http.MethodGet, "/cas/login?service="+url.QueryEscape(service), nil)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("login service %q status = %d, want 400", service, recorder.Code)
			}
			recorder = loginForm(t, handler, "alice", "secret", service, nil)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("login POST service %q status = %d, want 400", service, recorder.Code)
			}
			recorder = serve(t, handler, http.MethodGet, "/cas/logout?service="+url.QueryEscape(service), nil)
			if recorder.Code != http.StatusOK || recorder.Header().Get("Location") != "" {
				t.Fatalf("logout service %q = %d %q, want the signed-out page", service, recorder.Code, recorder.Header().Get("Location"))
			}
			recorder = serve(t, handler, http.MethodGet, "/cas/proxy?pgt=PGT-x&targetService="+url.QueryEscape(service), nil)
			if !strings.Contains(recorder.Body.String(), `code="INVALID_SERVICE"`) {
				t.Fatalf("proxy service %q body = %s", service, recorder.Body.String())
			}
		})
	}

	valid := "HTTPS://app.example.com/callback?x=1"
	target, err := withTicket(valid, "ST-test")
	if err != nil {
		t.Fatalf("withTicket(valid) error = %v", err)
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "app.example.com" || parsed.Query().Get("ticket") != "ST-test" || parsed.Query().Get("x") != "1" {
		t.Fatalf("withTicket(valid) = %q, err = %v", target, err)
	}
	for _, service := range invalid {
		if _, err := withTicket(service, "ST-test"); !errors.Is(err, ErrInvalidService) {
			t.Errorf("withTicket(%q) error = %v, want ErrInvalidService", service, err)
		}
	}
}

// TestRequestURLForwardedProto checks that only http and https survive X-Forwarded-Proto. |
// TestRequestURLForwardedProto 检查只有 http 与 https 会保留 X-Forwarded-Proto。
func TestRequestURLForwardedProto(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://cas.example.com/private?x=1", nil)
	request.Header.Set("X-Forwarded-Proto", "javascript")
	if got := requestURL(request); got != "http://cas.example.com/private?x=1" {
		t.Fatalf("forged scheme requestURL = %q", got)
	}
	request.Header.Set("X-Forwarded-Proto", "HTTPS, http")
	if got := requestURL(request); got != "https://cas.example.com/private?x=1" {
		t.Fatalf("first forwarded scheme requestURL = %q", got)
	}
	request.Header.Set("X-Forwarded-Proto", "gopher")
	request.TLS = &tls.ConnectionState{}
	if got := requestURL(request); got != "https://cas.example.com/private?x=1" {
		t.Fatalf("invalid forwarded scheme over TLS requestURL = %q", got)
	}
}

// TestMiddlewareRejectsForgedForwardedProto checks the login redirect never carries a forged
// scheme from X-Forwarded-Proto. | TestMiddlewareRejectsForgedForwardedProto 检查登录重定向绝不会
// 携带来自 X-Forwarded-Proto 的伪造协议。
func TestMiddlewareRejectsForgedForwardedProto(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := server.HTTPMiddleware(MiddlewareOptions{RequireTGT: true, LoginPath: "/cas/login"})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodGet, "http://cas.example.com/private", nil)
	request.Header.Set("X-Forwarded-Proto", "javascript")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	location := recorder.Header().Get("Location")
	if strings.Contains(strings.ToLower(location), "javascript") || !strings.Contains(location, url.QueryEscape("http://cas.example.com/private")) {
		t.Fatalf("redirect Location = %q", location)
	}
}
