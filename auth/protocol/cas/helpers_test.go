package cas

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/router"
)

const (
	testIssuer       = "https://cas.example.com"
	testAppService   = "https://app.example.com/callback"
	testOtherService = "https://other.example.com/home"
	testAPIEndpoint  = "https://api.example.com/data"
)

// testClock is a concurrency-safe manually advanced clock. | testClock 是并发安全、可手动推进的时钟。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current test time. | Now 返回当前测试时间。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward. | Advance 向前推进时钟。
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// testAuthenticator accepts alice/secret and bob/secret and maps the special logins "locked" and
// "mfa" to the corresponding auth failures. | testAuthenticator 接受 alice/secret 与 bob/secret，
// 并把特殊登录名 "locked" 与 "mfa" 映射到对应认证失败。
func testAuthenticator(_ context.Context, req *LoginRequest) (*auth.Principal, error) {
	switch {
	case req.Username == "alice" && req.Password == "secret":
		return testPrincipal(), nil
	case req.Username == "bob" && req.Password == "secret":
		return &auth.Principal{Subject: "user-2", Username: "bob", DisplayName: "Bob"}, nil
	case req.Username == "locked":
		return nil, auth.ErrAccountLocked
	case req.Username == "mfa":
		return nil, auth.ErrMFARequired
	default:
		return nil, auth.ErrInvalidCredentials
	}
}

// newTestServer builds a CAS server backed by a fresh memory store and test clock. | newTestServer
// 构建由新的内存存储与测试时钟支撑的 CAS 服务器。
func newTestServer(t *testing.T, options ...func(*ServerConfig)) (*Server, *MemoryTicketStore, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)}
	store := NewMemoryTicketStore()
	config := ServerConfig{
		Issuer:          testIssuer,
		ServiceRegistry: NewStaticServiceRegistry(testAppService, testOtherService, testAPIEndpoint, "https://proxy.example.com/*"),
		TicketStore:     store,
		Authenticator:   AuthenticatorFunc(testAuthenticator),
		Clock:           clock.Now,
	}
	for _, option := range options {
		option(&config)
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	return server, store, clock
}

// newTestRouter mounts the server at /cas. | newTestRouter 把服务器挂载到 /cas。
func newTestRouter(t *testing.T, server *Server) *router.Router {
	t.Helper()
	r := router.New()
	server.Register(r, "/cas")
	return r
}

// serve performs an in-process request. | serve 执行进程内请求。
func serve(t *testing.T, handler http.Handler, method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, target, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// loginForm performs a login POST and returns the recorder. | loginForm 执行登录 POST 并返回记录器。
func loginForm(t *testing.T, handler http.Handler, username, password, service string, extra url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	if service != "" {
		form.Set("service", service)
	}
	for key, values := range extra {
		for _, value := range values {
			form.Set(key, value)
		}
	}
	return serve(t, handler, http.MethodPost, "/cas/login", form, cookies...)
}

// tgcFrom returns the TGC cookie set by a response. | tgcFrom 返回响应设置的 TGC Cookie。
func tgcFrom(t *testing.T, recorder *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == CookieNameTGC && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatalf("response has no TGC cookie; headers: %v", recorder.Header())
	return nil
}

// ticketFromLocation extracts the ticket query parameter of a redirect location. | ticketFromLocation
// 从重定向 Location 提取 ticket 查询参数。
func ticketFromLocation(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	location := recorder.Header().Get("Location")
	if location == "" {
		t.Fatalf("response has no Location header")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Location %q: %v", location, err)
	}
	return parsed.Query().Get("ticket")
}

// loginAndTicket logs in and returns the TGC cookie and the issued ST. | loginAndTicket 登录并返回
// TGC Cookie 与已签发的 ST。
func loginAndTicket(t *testing.T, handler http.Handler, service string) (*http.Cookie, string) {
	t.Helper()
	recorder := loginForm(t, handler, "alice", "secret", service, nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302; body: %s", recorder.Code, recorder.Body.String())
	}
	ticket := ticketFromLocation(t, recorder)
	if !strings.HasPrefix(ticket, TicketPrefixST) {
		t.Fatalf("login ticket = %q, want ST prefix", ticket)
	}
	return tgcFrom(t, recorder), ticket
}

// loginTGC performs a service-less login and returns the TGC cookie. | loginTGC 执行无服务的登录并
// 返回 TGC Cookie。
func loginTGC(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	recorder := loginForm(t, handler, "alice", "secret", "", nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302; body: %s", recorder.Code, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/cas/login" {
		t.Fatalf("service-less login Location = %q, want /cas/login", location)
	}
	return tgcFrom(t, recorder)
}

// issueTestTickets creates a TGT and an ST directly in the store. | issueTestTickets 直接在存储中创建 TGT 与 ST。
func issueTestTickets(t *testing.T, server *Server, service string) (*Ticket, *Ticket) {
	t.Helper()
	principal := testPrincipal()
	tgt, err := server.issueTicket(context.Background(), TicketTGT, principal, principal.Subject, "", nil, server.config.TGTTimeout, false, false)
	if err != nil {
		t.Fatalf("issue TGT: %v", err)
	}
	st, err := server.issueTicket(context.Background(), TicketST, principal, principal.Subject, service, tgt, server.config.ServiceTicketTimeout, false, false)
	if err != nil {
		t.Fatalf("issue ST: %v", err)
	}
	return tgt, st
}

// elementText returns the text content of the first cas:<element> element in body. | elementText
// 返回 body 中第一个 cas:<element> 元素的文本内容。
func elementText(t *testing.T, body, element string) string {
	t.Helper()
	open := "<cas:" + element + ">"
	closeTag := "</cas:" + element + ">"
	start := strings.Index(body, open)
	if start < 0 {
		t.Fatalf("response has no %s element: %s", element, body)
	}
	start += len(open)
	end := strings.Index(body[start:], closeTag)
	if end < 0 {
		t.Fatalf("response has no closing %s element: %s", element, body)
	}
	return body[start : start+end]
}

// validateURL builds a protocol endpoint target. | validateURL 构建协议端点目标。
func validateURL(endpoint, ticket, service string, extra url.Values) string {
	query := url.Values{}
	query.Set("ticket", ticket)
	query.Set("service", service)
	for key, values := range extra {
		for _, value := range values {
			query.Set(key, value)
		}
	}
	return "/cas/" + endpoint + "?" + query.Encode()
}
