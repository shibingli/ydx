package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/router"
)

// testClock is a concurrency-safe clock for deterministic tests. | testClock 是用于确定性测试的并发安全时钟。
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current fake time. | Now 返回当前假时间。
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the fake clock. | Advance 推进假时钟。
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestSessionManager(t *testing.T, clock *testClock, config SessionConfig) (*SessionManager, *MemoryUserStore) {
	t.Helper()
	users := NewMemoryUserStore()
	manager, err := NewSessionManager(NewMemorySessionStore(), users, config)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	if clock != nil {
		manager.SetClock(clock.Now)
	}
	return manager, users
}

func createTestUser(t *testing.T, users UserStore, id string) *User {
	t.Helper()
	user := &User{ID: id, Username: id, Status: UserActive, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := users.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return user
}

func TestNewSessionManagerValidationAndDefaults(t *testing.T) {
	users := NewMemoryUserStore()
	if _, err := NewSessionManager(nil, users, SessionConfig{}); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := NewSessionManager(NewMemorySessionStore(), nil, SessionConfig{}); err == nil {
		t.Fatal("nil users accepted")
	}
	if _, err := NewSessionManager(NewMemorySessionStore(), users, SessionConfig{SameSite: http.SameSiteNoneMode}); err == nil {
		t.Fatal("SameSite=None without Secure accepted")
	}
	manager, err := NewSessionManager(NewMemorySessionStore(), users, SessionConfig{HTTPOnly: false, SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	config := manager.Config()
	if config.CookieName != "ydx_session" || config.Path != "/" || !config.HTTPOnly {
		t.Fatalf("defaults = %+v", config)
	}
	if config.CSRFHeader != "X-CSRF-Token" || config.CSRFParam != "csrf_token" {
		t.Fatalf("csrf defaults = %+v", config)
	}
	if config.AbsoluteTimeout != 24*time.Hour || config.TouchInterval != 30*time.Second {
		t.Fatalf("timeouts = %+v", config)
	}
}

func TestSessionMaxSessionsRevokesOldest(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	manager, users := newTestSessionManager(t, clock, SessionConfig{MaxSessions: 2, AbsoluteTimeout: time.Hour})
	createTestUser(t, users, "user-max")
	ctx := context.Background()

	first, err := manager.Create(ctx, "user-max", "app", nil, []string{"pwd"}, "")
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	clock.Advance(time.Second)
	second, err := manager.Create(ctx, "user-max", "app", nil, []string{"pwd"}, "")
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	clock.Advance(time.Second)
	third, err := manager.Create(ctx, "user-max", "app", nil, []string{"pwd"}, "")
	if err != nil {
		t.Fatalf("create third: %v", err)
	}

	if _, err := manager.Validate(ctx, first.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("oldest session = %v, want ErrSessionRevoked", err)
	}
	if _, err := manager.Validate(ctx, second.ID); err != nil {
		t.Fatalf("second session: %v", err)
	}
	if _, err := manager.Validate(ctx, third.ID); err != nil {
		t.Fatalf("third session: %v", err)
	}
	stored, err := manager.Get(ctx, first.ID)
	if err != nil {
		t.Fatalf("get first: %v", err)
	}
	if stored.RevokeReason != "max_sessions" {
		t.Fatalf("reason = %q", stored.RevokeReason)
	}
}

func TestSessionValidateSlidingAndAbsoluteExpiry(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)}
	manager, users := newTestSessionManager(t, clock, SessionConfig{
		IdleTimeout: 10 * time.Minute, AbsoluteTimeout: time.Hour, TouchInterval: time.Minute,
	})
	createTestUser(t, users, "user-expiry")
	ctx := context.Background()
	session, err := manager.Create(ctx, "user-expiry", "", nil, nil, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	clock.Advance(5 * time.Minute)
	validated, err := manager.Validate(ctx, session.ID)
	if err != nil {
		t.Fatalf("validate within idle: %v", err)
	}
	if !validated.LastSeenAt.Equal(clock.Now()) {
		t.Fatalf("last seen = %v, want %v", validated.LastSeenAt, clock.Now())
	}
	clock.Advance(2 * time.Minute)
	if _, err := manager.Validate(ctx, session.ID); err != nil {
		t.Fatalf("validate after touch interval: %v", err)
	}
	clock.Advance(11 * time.Minute)
	if _, err := manager.Validate(ctx, session.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("idle expiry = %v, want ErrSessionExpired", err)
	}

	// A fresh manager isolates the absolute deadline check. | 新管理器隔离绝对期限检查。
	clock2 := &testClock{now: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}
	manager2, users2 := newTestSessionManager(t, clock2, SessionConfig{IdleTimeout: time.Hour, AbsoluteTimeout: 15 * time.Minute})
	createTestUser(t, users2, "user-abs")
	absSession, err := manager2.Create(ctx, "user-abs", "", nil, nil, "")
	if err != nil {
		t.Fatalf("create absolute: %v", err)
	}
	clock2.Advance(16 * time.Minute)
	if _, err := manager2.Validate(ctx, absSession.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("absolute expiry = %v, want ErrSessionExpired", err)
	}

	expired := &Session{ID: "expired-session", UserID: "user-abs", ExpiresAt: clock2.Now().Add(-time.Minute)}
	if err := manager2.store.CreateSession(ctx, expired); err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	removed, err := manager2.store.DeleteExpiredSessions(ctx, clock2.Now())
	if err != nil || removed != 2 {
		t.Fatalf("DeleteExpiredSessions = %d %v", removed, err)
	}
}

func TestSessionRotateRevokeAndList(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)}
	manager, users := newTestSessionManager(t, clock, SessionConfig{AbsoluteTimeout: time.Hour})
	createTestUser(t, users, "user-rotate")
	ctx := context.Background()
	session, err := manager.Create(ctx, "user-rotate", "client", nil, []string{"pwd", "otp"}, "acr")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	clock.Advance(time.Second)
	rotated, err := manager.Rotate(ctx, session.ID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.ID == session.ID || rotated.CSRFSecret == session.CSRFSecret {
		t.Fatalf("rotation reused identifiers")
	}
	if rotated.UserID != session.UserID || rotated.ClientID != "client" || rotated.ACR != "acr" {
		t.Fatalf("rotated attributes = %+v", rotated)
	}
	if len(rotated.AMR) != 2 || rotated.AMR[1] != "otp" {
		t.Fatalf("rotated AMR = %v", rotated.AMR)
	}
	if _, err := manager.Validate(ctx, session.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("old session = %v, want ErrSessionRevoked", err)
	}
	if _, err := manager.Validate(ctx, rotated.ID); err != nil {
		t.Fatalf("rotated session: %v", err)
	}
	if _, err := manager.Rotate(ctx, "missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("rotate missing = %v", err)
	}
	if _, err := manager.Rotate(ctx, session.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("rotate revoked = %v, want ErrSessionExpired", err)
	}

	if err := manager.Revoke(ctx, rotated.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := manager.Revoke(ctx, rotated.ID, "again"); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if err := manager.Revoke(ctx, "missing", "test"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("revoke missing = %v", err)
	}
	first, _ := manager.Create(ctx, "user-rotate", "", nil, nil, "")
	second, _ := manager.Create(ctx, "user-rotate", "", nil, nil, "")
	revoked, err := manager.RevokeUser(ctx, "user-rotate", "bulk")
	if err != nil || revoked != 2 {
		t.Fatalf("RevokeUser = %d %v", revoked, err)
	}
	if revoked, err := manager.RevokeUser(ctx, "user-rotate", "bulk"); err != nil || revoked != 0 {
		t.Fatalf("second RevokeUser = %d %v", revoked, err)
	}
	all, err := manager.List(ctx, "user-rotate")
	if err != nil || len(all) < 2 {
		t.Fatalf("List = %d %v", len(all), err)
	}
	if first.ID == "" || second.ID == "" {
		t.Fatal("create returned empty id")
	}
}

func TestSessionCookieCSRFAndPrincipal(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	manager, users := newTestSessionManager(t, clock, SessionConfig{
		AbsoluteTimeout: time.Hour, CookieName: "sid", Path: "/app", Domain: "example.com", Secure: true,
		SameSite: http.SameSiteStrictMode,
	})
	user := createTestUser(t, users, "user-cookie")
	ctx := context.Background()
	session, err := manager.Create(ctx, user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cookie := manager.Cookie(session)
	if cookie.Name != "sid" || cookie.Path != "/app" || cookie.Domain != "example.com" || !cookie.Secure {
		t.Fatalf("cookie = %+v", cookie)
	}
	if cookie.MaxAge != 3600 {
		t.Fatalf("MaxAge = %d, want 3600", cookie.MaxAge)
	}
	clock.Advance(2 * time.Hour)
	if cookie := manager.Cookie(session); cookie.MaxAge != -1 {
		t.Fatalf("expired MaxAge = %d, want -1", cookie.MaxAge)
	}
	if cookie := manager.Cookie(nil); cookie.MaxAge != -1 || cookie.Value != "" {
		t.Fatalf("nil cookie = %+v", cookie)
	}
	cleared := manager.ClearCookie()
	if cleared.MaxAge != -1 || !cleared.Expires.Before(time.Now()) {
		t.Fatalf("clear cookie = %+v", cleared)
	}

	if !manager.VerifyCSRF(session, session.CSRFSecret) {
		t.Fatal("valid CSRF rejected")
	}
	if manager.VerifyCSRF(nil, "x") || manager.VerifyCSRF(session, "") || manager.VerifyCSRF(session, "wrong") {
		t.Fatal("invalid CSRF accepted")
	}
	if manager.CSRFToken(nil) != "" {
		t.Fatal("nil session CSRF token not empty")
	}

	headerReq := httptest.NewRequest(http.MethodPost, "/", nil)
	headerReq.Header.Set(manager.Config().CSRFHeader, "header-token")
	if got := manager.csrfFromRequest(headerReq); got != "header-token" {
		t.Fatalf("header csrf = %q", got)
	}
	form := url.Values{manager.Config().CSRFParam: {"form-token"}}
	formReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := manager.csrfFromRequest(formReq); got != "form-token" {
		t.Fatalf("form csrf = %q", got)
	}
	if got := manager.csrfFromRequest(nil); got != "" {
		t.Fatalf("nil csrf = %q", got)
	}

	principal, err := manager.Principal(ctx, session)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	if principal.Subject != user.ID || principal.SessionID != session.ID {
		t.Fatalf("principal = %+v", principal)
	}
	manager.SetPrincipalBuilder(func(_ context.Context, _ *User, _ *Session) (*Principal, error) {
		return &Principal{Subject: user.ID, Issuer: "custom"}, nil
	})
	custom, err := manager.Principal(ctx, session)
	if err != nil || custom.Issuer != "custom" {
		t.Fatalf("custom principal = %+v %v", custom, err)
	}

	withoutSession := DefaultPrincipal(user, nil)
	if withoutSession == nil || withoutSession.SessionID != "" || !withoutSession.AuthTime.IsZero() {
		t.Fatalf("DefaultPrincipal without session = %+v", withoutSession)
	}
	if DefaultPrincipal(nil, session) != nil {
		t.Fatal("nil user did not yield nil principal")
	}

	if _, err := manager.Principal(ctx, &Session{UserID: "missing-user"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing principal user = %v", err)
	}
}

func TestSessionMiddlewareCSRFAndAnonymous(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	manager, users := newTestSessionManager(t, clock, SessionConfig{AbsoluteTimeout: time.Hour})
	user := createTestUser(t, users, "user-middleware")
	ctx := context.Background()
	session, err := manager.Create(ctx, user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var customErr error
	r := router.New()
	r.Use(manager.Middleware(SessionMiddlewareOptions{RequireSession: true, EnforceCSRF: true, ErrorHandler: func(c *router.Ctx, err error) {
		customErr = err
		_ = c.JSON(http.StatusTeapot, "custom")
	}}))
	r.GET("/me", func(c *router.Ctx) {
		p, ok := PrincipalFromCtx(c)
		if !ok {
			_ = c.JSON(http.StatusInternalServerError, "missing")
			return
		}
		s, ok := SessionFromCtx(c)
		if !ok || s.ID != session.ID {
			_ = c.JSON(http.StatusInternalServerError, "missing session")
			return
		}
		_ = c.JSON(http.StatusOK, map[string]string{"sub": p.Subject})
	})
	r.POST("/change", func(c *router.Ctx) { _ = c.JSON(http.StatusOK, "changed") })

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(manager.Cookie(session))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d body=%s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/change", nil)
	req.AddCookie(manager.Cookie(session))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTeapot || !errors.Is(customErr, ErrForbidden) {
		t.Fatalf("CSRF failure = %d %v", w.Code, customErr)
	}

	req = httptest.NewRequest(http.MethodPost, "/change", nil)
	req.AddCookie(manager.Cookie(session))
	req.Header.Set(manager.Config().CSRFHeader, session.CSRFSecret)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST with CSRF = %d body=%s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTeapot || !errors.Is(customErr, ErrSessionNotFound) {
		t.Fatalf("anonymous status = %d %v", w.Code, customErr)
	}

	// A disabled account behind an existing session is rejected. | 已有会话背后的禁用账号会被拒绝。
	user, _ = users.GetUser(ctx, user.ID)
	user.Status = UserDisabled
	if err := users.UpdateUser(ctx, user); err != nil {
		t.Fatalf("disable: %v", err)
	}
	r2 := router.New()
	r2.Use(manager.Middleware(SessionMiddlewareOptions{RequireSession: true}))
	r2.GET("/me", func(c *router.Ctx) { _ = c.JSON(http.StatusOK, "ok") })
	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(manager.Cookie(session))
	w = httptest.NewRecorder()
	r2.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled status = %d", w.Code)
	}

	// Anonymous requests pass through when RequireSession is off. | RequireSession 关闭时匿名请求放行。
	r3 := router.New()
	r3.Use(manager.Middleware(SessionMiddlewareOptions{}))
	r3.GET("/public", func(c *router.Ctx) {
		_, ok := PrincipalFromCtx(c)
		_ = c.JSON(http.StatusOK, ok)
	})
	req = httptest.NewRequest(http.MethodGet, "/public", nil)
	w = httptest.NewRecorder()
	r3.ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "true") {
		t.Fatalf("anonymous public = %d %s", w.Code, w.Body.String())
	}
}

func TestSessionHTTPMiddleware(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	manager, users := newTestSessionManager(t, clock, SessionConfig{AbsoluteTimeout: time.Hour})
	user := createTestUser(t, users, "user-http")
	ctx := context.Background()
	session, err := manager.Create(ctx, user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	handler := manager.HTTPMiddleware(SessionMiddlewareOptions{RequireSession: true, EnforceCSRF: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromRequest(r)
		if !ok || principal.Subject != user.ID {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(manager.Cookie(session))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("GET status = %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	req.AddCookie(manager.Cookie(session))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("DELETE without CSRF = %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous DELETE = %d", w.Code)
	}
}

func TestSessionHelpers(t *testing.T) {
	if !isUnsafeMethod(http.MethodPost) || !isUnsafeMethod("put") || !isUnsafeMethod(http.MethodPatch) || !isUnsafeMethod(http.MethodDelete) {
		t.Fatal("unsafe method not detected")
	}
	if isUnsafeMethod(http.MethodGet) || isUnsafeMethod(http.MethodHead) || isUnsafeMethod(http.MethodOptions) {
		t.Fatal("safe method flagged unsafe")
	}
	if !errorsIsSessionExpired(ErrSessionExpired) || !errorsIsSessionExpired(ErrSessionRevoked) || !errorsIsSessionExpired(ErrSessionNotFound) {
		t.Fatal("session expiry sentinel not detected")
	}
	if errorsIsSessionExpired(ErrInvalidRequest) {
		t.Fatal("unrelated error treated as expiry")
	}
	hash := CSRFHash("key", "value")
	if len(hash) != 64 || hash != CSRFHash("key", "value") || hash == CSRFHash("other", "value") {
		t.Fatalf("CSRFHash = %q", hash)
	}
	if got := hexLower([]byte{0x00, 0xab, 0xff}); got != "00abff" {
		t.Fatalf("hexLower = %q", got)
	}
	w := httptest.NewRecorder()
	writeHTTPError(w, http.StatusTeapot, "oops")
	if w.Code != http.StatusTeapot || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "oops") {
		t.Fatalf("writeHTTPError response = %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	if p, ok := PrincipalFromCtx(nil); ok || p != nil {
		t.Fatal("nil router context reported principal")
	}
	if _, ok := SessionFromCtx(nil); ok {
		t.Fatal("nil router context reported session")
	}
	if _, ok := PrincipalFromRequest(nil); ok {
		t.Fatal("nil request reported principal")
	}
}

func TestSessionMiddlewareDenialAbortsRouterChain(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	manager, users := newTestSessionManager(t, clock, SessionConfig{AbsoluteTimeout: time.Hour})
	user := createTestUser(t, users, "user-abort")
	session, err := manager.Create(context.Background(), user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	reached := 0
	newRouter := func(opts SessionMiddlewareOptions) *router.Router {
		r := router.New()
		r.Use(manager.Middleware(opts))
		handler := func(c *router.Ctx) {
			reached++
			_ = c.JSON(http.StatusOK, "protected")
		}
		r.GET("/protected", handler)
		r.POST("/protected", handler)
		return r
	}

	// A rejected anonymous request must never reach the protected handler. | 被拒绝的匿名请求不得进入受保护处理器。
	w := httptest.NewRecorder()
	newRouter(SessionMiddlewareOptions{RequireSession: true}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if w.Code != http.StatusUnauthorized || reached != 0 {
		t.Fatalf("anonymous denial: status=%d reached=%d", w.Code, reached)
	}

	// CSRF failures, including ones rendered by a custom error handler, must abort the chain. | CSRF
	// 失败（包括自定义错误处理器渲染的失败）必须终止调用链。
	options := []SessionMiddlewareOptions{
		{RequireSession: true, EnforceCSRF: true},
		{RequireSession: true, EnforceCSRF: true, ErrorHandler: func(c *router.Ctx, _ error) {
			_ = c.JSON(http.StatusTeapot, "custom")
		}},
	}
	for i, opts := range options {
		reached = 0
		r := newRouter(opts)
		req := httptest.NewRequest(http.MethodPost, "/protected", nil)
		req.AddCookie(manager.Cookie(session))
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if reached != 0 {
			t.Fatalf("CSRF denial %d reached protected handler", i)
		}
		if i == 0 && w.Code != http.StatusForbidden {
			t.Fatalf("CSRF denial %d status = %d", i, w.Code)
		}
		if i == 1 && w.Code != http.StatusTeapot {
			t.Fatalf("custom CSRF denial %d status = %d", i, w.Code)
		}
	}
}

func TestSessionValidatePersistsIdleDeadlineNearExpiry(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	// A touch interval longer than the idle timeout means the stored sliding deadline can lapse
	// before the interval-based touch ever runs. | 触碰间隔长于空闲超时时，基于间隔的触碰可能尚未执行，
	// 存储的滑动期限就已失效。
	manager, users := newTestSessionManager(t, clock, SessionConfig{
		AbsoluteTimeout: time.Hour,
		IdleTimeout:     10 * time.Minute,
		TouchInterval:   15 * time.Minute,
	})
	user := createTestUser(t, users, "user-sliding")
	session, err := manager.Create(context.Background(), user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	clock.Advance(9 * time.Minute)
	validated, err := manager.Validate(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("validate at 9m: %v", err)
	}
	wantIdle := clock.Now().Add(10 * time.Minute)
	if !validated.IdleExpiresAt.Equal(wantIdle) {
		t.Fatalf("returned idle deadline = %v, want %v", validated.IdleExpiresAt, wantIdle)
	}
	stored, err := manager.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("get stored session: %v", err)
	}
	if !stored.IdleExpiresAt.Equal(wantIdle) {
		t.Fatalf("persisted idle deadline = %v, want %v", stored.IdleExpiresAt, wantIdle)
	}

	clock.Advance(90 * time.Second)
	if _, err := manager.Validate(context.Background(), session.ID); err != nil {
		t.Fatalf("validate at 10m30s after an earlier active request: %v", err)
	}
}

func TestSessionCookieWithoutAbsoluteDeadline(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}
	manager, _ := newTestSessionManager(t, clock, SessionConfig{})
	session := &Session{
		ID:        "session-without-absolute-deadline",
		UserID:    "user",
		CreatedAt: clock.Now(),
		UpdatedAt: clock.Now(),
	}
	if !session.Active(clock.Now()) {
		t.Fatal("session without absolute deadline should be active")
	}
	cookie := manager.Cookie(session)
	if cookie.MaxAge != 0 {
		t.Fatalf("cookie MaxAge = %d for a session without absolute deadline", cookie.MaxAge)
	}
	if !cookie.Expires.IsZero() {
		t.Fatalf("cookie Expires = %v for a session without absolute deadline", cookie.Expires)
	}
	if strings.Contains(cookie.String(), "Max-Age") {
		t.Fatalf("cookie %q carries a deletion Max-Age for a valid session", cookie.String())
	}
}
