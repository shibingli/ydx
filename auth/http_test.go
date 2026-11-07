package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/router"
)

func principalMiddleware(principal *Principal) router.Middleware {
	return func(c *router.Ctx) {
		c.Request = c.Request.WithContext(ContextWithPrincipal(c.Request.Context(), principal))
		c.Next()
	}
}

func TestRequireAccessRouter(t *testing.T) {
	r := router.New()
	r.Use(RequireAccess(AccessOptions{Permissions: []string{"user:read"}}))
	r.GET("/", func(c *router.Ctx) { _ = c.JSON(http.StatusNoContent, nil) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", w.Code)
	}

	allowed := router.New()
	allowed.Use(principalMiddleware(&Principal{Subject: "user-1", Permissions: []string{"user:read"}}))
	allowed.Use(RequireAccess(AccessOptions{Permissions: []string{"user:read"}}))
	allowed.GET("/", func(c *router.Ctx) { _ = c.JSON(http.StatusNoContent, nil) })
	w = httptest.NewRecorder()
	allowed.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("allowed status = %d", w.Code)
	}

	forbidden := router.New()
	forbidden.Use(principalMiddleware(&Principal{Subject: "user-1", Permissions: []string{"user:read"}}))
	forbidden.Use(RequirePermission("user:write"))
	forbidden.GET("/", func(c *router.Ctx) { _ = c.JSON(http.StatusOK, "should not run") })
	w = httptest.NewRecorder()
	forbidden.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "should not run") {
		t.Fatalf("forbidden status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestRequireAccessAnyAndCustomHandler(t *testing.T) {
	var seen error
	r := router.New()
	r.Use(principalMiddleware(&Principal{Subject: "user-1", Roles: []string{"support"}, Scopes: []string{"openid"}}))
	r.Use(RequireAccess(AccessOptions{
		Permissions: []string{"admin:read"}, Roles: []string{"staff"}, Scopes: []string{"openid"},
		Any: true, ErrorHandler: func(c *router.Ctx, err error) {
			seen = err
			_ = c.JSON(http.StatusTeapot, "custom")
		},
	}))
	r.GET("/", func(c *router.Ctx) { _ = c.JSON(http.StatusOK, "allowed") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("any match status = %d body=%s", w.Code, w.Body.String())
	}

	r = router.New()
	r.Use(principalMiddleware(&Principal{Subject: "user-1", Roles: []string{"support"}, Scopes: []string{"openid"}}))
	r.Use(RequireAccess(AccessOptions{
		Permissions: []string{"admin:read"}, Roles: []string{"staff"}, Scopes: []string{"openid"},
		ErrorHandler: func(c *router.Ctx, err error) {
			seen = err
			_ = c.JSON(http.StatusTeapot, "custom")
		},
	}))
	r.GET("/", func(c *router.Ctx) { _ = c.JSON(http.StatusOK, "allowed") })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTeapot || !errors.Is(seen, ErrForbidden) {
		t.Fatalf("all match status = %d err=%v", w.Code, seen)
	}

	r = router.New()
	r.Use(RequireAccess(AccessOptions{ErrorHandler: func(c *router.Ctx, err error) {
		seen = err
		_ = c.JSON(http.StatusTeapot, "custom")
	}}))
	r.GET("/", func(c *router.Ctx) { _ = c.JSON(http.StatusOK, "allowed") })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTeapot || !errors.Is(seen, ErrUnauthorized) {
		t.Fatalf("anonymous custom status = %d err=%v", w.Code, seen)
	}
}

func TestRequireAccessHTTP(t *testing.T) {
	handler := RequireAccessHTTP(AccessOptions{Permissions: []string{"user:read"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ContextWithPrincipal(req.Context(), &Principal{Permissions: []string{"user:write"}}))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("forbidden status = %d", w.Code)
	}

	req = req.WithContext(ContextWithPrincipal(req.Context(), &Principal{Permissions: []string{"user:read"}}))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("allowed status = %d", w.Code)
	}

	permissionHandler := RequirePermissionHTTP("user:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	w = httptest.NewRecorder()
	permissionHandler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("permission handler status = %d", w.Code)
	}
}

func TestPrincipalSatisfies(t *testing.T) {
	principal := &Principal{Permissions: []string{"user:read"}, Roles: []string{"admin"}, Scopes: []string{"openid"}}
	if !principalSatisfies(principal, AccessOptions{}) {
		t.Fatal("empty requirements rejected")
	}
	if !principalSatisfies(principal, AccessOptions{Permissions: []string{"user:read"}, Roles: []string{"admin"}, Scopes: []string{"openid"}}) {
		t.Fatal("all requirements rejected")
	}
	if principalSatisfies(principal, AccessOptions{Permissions: []string{"user:read"}, Roles: []string{"staff"}}) {
		t.Fatal("missing role accepted")
	}
	if !principalSatisfies(principal, AccessOptions{Permissions: []string{"user:read"}, Roles: []string{"staff"}, Any: true}) {
		t.Fatal("any requirement rejected")
	}
	if principalSatisfies(principal, AccessOptions{Permissions: []string{"user:write"}, Roles: []string{"staff"}, Any: true}) {
		t.Fatal("no requirement matched")
	}
}

func TestBearerToken(t *testing.T) {
	if _, err := BearerToken(nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nil request = %v", err)
	}
	cases := []struct {
		header string
		token  string
		ok     bool
	}{
		{"", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Basic abc", "", false},
		{"Bearer token-1", "token-1", true},
		{"bearer token-2", "token-2", true},
		{"BEARER token-3", "token-3", true},
		{"Bearer   token-4  ", "token-4", true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		token, err := BearerToken(req)
		if tc.ok {
			if err != nil || token != tc.token {
				t.Fatalf("BearerToken(%q) = %q %v", tc.header, token, err)
			}
		} else if !errors.Is(err, ErrUnauthorized) || token != "" {
			t.Fatalf("BearerToken(%q) = %q %v", tc.header, token, err)
		}
	}
}

func TestRequireBearer(t *testing.T) {
	var sawHeader string
	var sawCookie string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("Authorization")
		sawCookie = r.Header.Get("X-Cookie")
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RequireBearer(func(r *http.Request) string {
		return r.Header.Get("X-Cookie")
	})(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Cookie", "cookie-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if sawHeader != "Bearer cookie-token" || sawCookie != "cookie-token" {
		t.Fatalf("header = %q cookie = %q", sawHeader, sawCookie)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer explicit")
	req.Header.Set("X-Cookie", "cookie-token")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if sawHeader != "Bearer explicit" {
		t.Fatalf("explicit bearer overwritten: %q", sawHeader)
	}

	sawHeader = ""
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if sawHeader != "" {
		t.Fatalf("empty source produced header %q", sawHeader)
	}

	RequireBearer(nil)(next).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if sawHeader != "" {
		t.Fatalf("nil source produced header %q", sawHeader)
	}
}

func TestPrincipalOrError(t *testing.T) {
	if _, err := PrincipalOrError(nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nil request = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := PrincipalOrError(req); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("anonymous request = %v", err)
	}
	principal := &Principal{Subject: "subject"}
	req = req.WithContext(ContextWithPrincipal(req.Context(), principal))
	got, err := PrincipalOrError(req)
	if err != nil || got.Subject != "subject" {
		t.Fatalf("request principal = %+v %v", got, err)
	}

	if _, err := CtxPrincipalOrError(nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nil router context = %v", err)
	}
	var seen *Principal
	r := router.New()
	r.Use(principalMiddleware(principal))
	r.GET("/", func(c *router.Ctx) {
		seen, _ = CtxPrincipalOrError(c)
		_ = c.JSON(http.StatusNoContent, nil)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusNoContent || seen == nil || seen.Subject != "subject" {
		t.Fatalf("router principal = %+v", seen)
	}

	r = router.New()
	r.GET("/", func(c *router.Ctx) {
		_, err = CtxPrincipalOrError(c)
		_ = c.JSON(http.StatusNoContent, nil)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("anonymous router principal = %v", err)
	}
}

func TestPrincipalContextRoundTrip(t *testing.T) {
	principal := &Principal{Subject: "ctx"}
	ctx := ContextWithPrincipal(context.Background(), principal)
	if got, ok := PrincipalFromContext(ctx); !ok || got.Subject != "ctx" {
		t.Fatalf("round trip = %+v %v", got, ok)
	}
}
