package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/router"
)

// rotatedCookie returns the named cookie from a recorded response. | rotatedCookie 从记录的响应中
// 返回指定名称的 Cookie。
func rotatedCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func TestSessionMiddlewareAutoRotates(t *testing.T) {
	base := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	manager, users := newTestSessionManager(t, clock, SessionConfig{
		AbsoluteTimeout: time.Hour,
		IdleTimeout:     30 * time.Minute,
		RotateAfter:     10 * time.Minute,
		TouchInterval:   30 * time.Second,
	})
	user := createTestUser(t, users, "user-rotate-router")
	ctx := context.Background()
	session, err := manager.Create(ctx, user.ID, "app", nil, []string{"pwd"}, "urn:acr:1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	oldCSRF := session.CSRFSecret
	clock.Advance(11 * time.Minute)
	now := clock.Now()

	var handlerSession *Session
	r := router.New()
	r.Use(manager.Middleware(SessionMiddlewareOptions{RequireSession: true}))
	r.GET("/me", func(c *router.Ctx) {
		stored, ok := SessionFromCtx(c)
		if !ok {
			t.Error("session missing from router context")
			return
		}
		principal, ok := PrincipalFromCtx(c)
		if !ok {
			t.Error("principal missing from router context")
			return
		}
		handlerSession = stored
		if stored.ID == session.ID {
			t.Errorf("handler saw the old session id %q", stored.ID)
		}
		if principal.SessionID != stored.ID {
			t.Errorf("principal session = %q, context session = %q", principal.SessionID, stored.ID)
		}
		if !principal.AuthTime.Equal(base) {
			t.Errorf("auth time = %v, want %v", principal.AuthTime, base)
		}
		if !principal.IssuedAt.Equal(now) {
			t.Errorf("issued at = %v, want %v", principal.IssuedAt, now)
		}
		if stored.CSRFSecret != oldCSRF {
			t.Errorf("automatic rotation changed the CSRF secret")
		}
		if !stored.AuthenticatedAt.Equal(base) {
			t.Errorf("authenticated at = %v, want %v", stored.AuthenticatedAt, base)
		}
		_ = c.JSON(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(manager.Cookie(session))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	cookie := rotatedCookie(w, manager.Config().CookieName)
	if cookie == nil {
		t.Fatal("automatic rotation did not set a cookie")
	}
	if cookie.Value == session.ID || cookie.Value == "" {
		t.Fatalf("cookie value = %q, want a fresh id", cookie.Value)
	}
	if cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure {
		t.Fatalf("cookie attributes = %+v", cookie)
	}
	if cookie.MaxAge <= 0 || cookie.Expires.IsZero() {
		t.Fatalf("cookie lifetime = MaxAge %d Expires %v", cookie.MaxAge, cookie.Expires)
	}
	if !cookie.Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("cookie expires = %v, want %v", cookie.Expires, now.Add(time.Hour))
	}
	if handlerSession == nil || handlerSession.ID != cookie.Value {
		t.Fatalf("handler session = %+v, cookie = %q", handlerSession, cookie.Value)
	}

	if _, err := manager.Validate(ctx, session.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("old session = %v, want ErrSessionRevoked", err)
	}
	rotated, err := manager.Validate(ctx, cookie.Value)
	if err != nil {
		t.Fatalf("rotated session: %v", err)
	}
	if rotated.CSRFSecret != oldCSRF || !rotated.AuthenticatedAt.Equal(base) || !rotated.CreatedAt.Equal(now) {
		t.Fatalf("rotated session = %+v", rotated)
	}

	// Explicit rotation keeps its historical behavior and issues a fresh CSRF secret. | 显式轮换保持
	// 既有行为并生成新的 CSRF 密钥。
	explicit, err := manager.Rotate(ctx, rotated.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if explicit.CSRFSecret == oldCSRF {
		t.Fatal("explicit rotation reused the CSRF secret")
	}
	if !explicit.AuthenticatedAt.Equal(base) {
		t.Fatalf("explicit rotation lost auth time: %v", explicit.AuthenticatedAt)
	}
}

func TestSessionHTTPMiddlewareAutoRotates(t *testing.T) {
	base := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	manager, users := newTestSessionManager(t, clock, SessionConfig{
		AbsoluteTimeout: time.Hour,
		RotateAfter:     10 * time.Minute,
		TouchInterval:   time.Hour,
	})
	user := createTestUser(t, users, "user-rotate-http")
	ctx := context.Background()
	session, err := manager.Create(ctx, user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock.Advance(11 * time.Minute)

	var seenID string
	handler := manager.HTTPMiddleware(SessionMiddlewareOptions{RequireSession: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromRequest(r)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		seenID = principal.SessionID
		if !principal.AuthTime.Equal(base) {
			t.Errorf("auth time = %v, want %v", principal.AuthTime, base)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(manager.Cookie(session))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	cookie := rotatedCookie(w, manager.Config().CookieName)
	if cookie == nil || cookie.Value == session.ID {
		t.Fatalf("rotation cookie = %+v", cookie)
	}
	if seenID != cookie.Value {
		t.Fatalf("principal session = %q, cookie = %q", seenID, cookie.Value)
	}

	// A request carrying the new cookie within the rotation window is stable. | 在轮换窗口内携带新
	// Cookie 的请求保持稳定。
	clock.Advance(time.Second)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("second status = %d", w.Code)
	}
	if extra := rotatedCookie(w, manager.Config().CookieName); extra != nil {
		t.Fatalf("second request rotated again: %+v", extra)
	}
}

func TestSessionAutoRotationDisabled(t *testing.T) {
	base := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	manager, users := newTestSessionManager(t, clock, SessionConfig{
		AbsoluteTimeout: 24 * time.Hour,
		IdleTimeout:     2 * time.Hour,
		RotateAfter:     0,
		TouchInterval:   time.Hour,
	})
	user := createTestUser(t, users, "user-rotate-off")
	session, err := manager.Create(context.Background(), user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock.Advance(90 * time.Minute)

	handler := manager.HTTPMiddleware(SessionMiddlewareOptions{RequireSession: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(manager.Cookie(session))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	if cookie := rotatedCookie(w, manager.Config().CookieName); cookie != nil {
		t.Fatalf("rotation disabled but got cookie %+v", cookie)
	}
}

// rotateFailStore fails every session update. | rotateFailStore 让每次会话更新失败。
type rotateFailStore struct {
	SessionStore
	err error
}

// UpdateSession returns the injected failure. | UpdateSession 返回注入的失败。
func (s *rotateFailStore) UpdateSession(context.Context, *Session) error { return s.err }

func TestSessionAutoRotationFailureContinues(t *testing.T) {
	base := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	users := NewMemoryUserStore()
	injected := errors.New("session update failed")
	store := &rotateFailStore{SessionStore: NewMemorySessionStore(), err: injected}
	manager, err := NewSessionManager(store, users, SessionConfig{
		AbsoluteTimeout: time.Hour,
		RotateAfter:     10 * time.Minute,
		TouchInterval:   time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	manager.SetClock(clock.Now)
	user := createTestUser(t, users, "user-rotate-fail")
	ctx := context.Background()
	session, err := manager.Create(ctx, user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock.Advance(11 * time.Minute)

	var reported error
	var seenID string
	handler := manager.HTTPMiddleware(SessionMiddlewareOptions{
		RequireSession: true,
		RotateErrorHandler: func(err error) {
			reported = err
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := PrincipalFromRequest(r)
		seenID = principal.SessionID
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(manager.Cookie(session))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	if !errors.Is(reported, injected) {
		t.Fatalf("rotate error = %v, want injected", reported)
	}
	if seenID != session.ID {
		t.Fatalf("principal session = %q, want %q", seenID, session.ID)
	}
	if cookie := rotatedCookie(w, manager.Config().CookieName); cookie != nil {
		t.Fatalf("failed rotation set cookie %+v", cookie)
	}
	if _, err := manager.Validate(ctx, session.ID); err != nil {
		t.Fatalf("validated session was lost after failed rotation: %v", err)
	}
}

func TestSessionHTTPMiddlewareConcurrentRotation(t *testing.T) {
	base := time.Date(2026, 9, 5, 8, 0, 0, 0, time.UTC)
	clock := &testClock{now: base}
	manager, users := newTestSessionManager(t, clock, SessionConfig{
		AbsoluteTimeout: time.Hour,
		RotateAfter:     10 * time.Minute,
		TouchInterval:   time.Hour,
	})
	user := createTestUser(t, users, "user-rotate-race")
	ctx := context.Background()
	session, err := manager.Create(ctx, user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock.Advance(11 * time.Minute)

	handler := manager.HTTPMiddleware(SessionMiddlewareOptions{RequireSession: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	const requests = 24
	start := make(chan struct{})
	statuses := make([]int, requests)
	cookies := make([]string, requests)
	var wg sync.WaitGroup
	wg.Add(requests)
	for i := 0; i < requests; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(manager.Cookie(session))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			statuses[i] = w.Code
			if c := rotatedCookie(w, manager.Config().CookieName); c != nil {
				cookies[i] = c.Value
			}
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	unique := make(map[string]bool)
	for i := range statuses {
		if statuses[i] == http.StatusNoContent {
			successes++
		} else if statuses[i] != http.StatusUnauthorized {
			t.Fatalf("request %d status = %d", i, statuses[i])
		}
		if cookies[i] != "" {
			unique[cookies[i]] = true
		}
	}
	if successes == 0 {
		t.Fatal("no concurrent request succeeded")
	}
	if len(unique) != 1 {
		t.Fatalf("concurrent rotation produced %d replacement cookies: %v", len(unique), unique)
	}
	if _, err := manager.Validate(ctx, session.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("old session = %v, want ErrSessionRevoked", err)
	}
	sessions, err := manager.List(ctx, user.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	active := 0
	for _, candidate := range sessions {
		if candidate.Active(clock.Now()) {
			active++
		}
	}
	if active != 1 || len(sessions) != 2 {
		t.Fatalf("sessions after concurrent rotation = %d active, %d total", active, len(sessions))
	}
}
