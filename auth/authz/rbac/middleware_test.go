package rbac

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/router"
)

// injectPrincipal attaches principal to the request context for PrincipalFromCtx. | injectPrincipal
// 把主体附加到请求上下文，供 PrincipalFromCtx 读取。
func injectPrincipal(principal *auth.Principal) router.Middleware {
	return func(c *router.Ctx) {
		c.Request = c.Request.WithContext(auth.ContextWithPrincipal(c.Request.Context(), principal))
		c.Next()
	}
}

// okRouterHandler writes 200 OK. | okRouterHandler 写出 200 OK。
func okRouterHandler(c *router.Ctx) {
	_ = c.String(http.StatusOK, "ok")
}

// newRouterWithPrincipal returns a router that optionally injects principal. | newRouterWithPrincipal
// 返回可选注入主体的路由。
func newRouterWithPrincipal(principal *auth.Principal) *router.Router {
	r := router.New()
	if principal != nil {
		r.Use(injectPrincipal(principal))
	}
	return r
}

// serveRouter runs one router request. | serveRouter 执行一次路由请求。
func serveRouter(r *router.Router, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	return recorder
}

func TestRequireRouterMiddleware(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})
	mustAddPolicy(t, engine, Policy{ID: "api-read", Effect: EffectPermit, Resource: "/api/*", Action: "read"})
	mustAddPolicy(t, engine, Policy{
		ID:     "named-profile",
		Effect: EffectPermit,
		Action: "profile:read",
		Conditions: []Condition{
			{Key: "subject.username", Operator: OperatorEquals, Value: "alice"},
		},
	})

	cases := []struct {
		name       string
		principal  *auth.Principal
		middleware func() router.Middleware
		target     string
		want       int
	}{
		{
			name:       "missing principal",
			middleware: func() router.Middleware { return Require(engine, "post:read", nil) },
			target:     "/api/posts",
			want:       http.StatusUnauthorized,
		},
		{
			name:       "allowed",
			principal:  &auth.Principal{Subject: "alice"},
			middleware: func() router.Middleware { return Require(engine, "post:read", nil) },
			target:     "/api/posts",
			want:       http.StatusOK,
		},
		{
			name:       "denied",
			principal:  &auth.Principal{Subject: "bob"},
			middleware: func() router.Middleware { return Require(engine, "post:read", nil) },
			target:     "/api/posts",
			want:       http.StatusForbidden,
		},
		{
			name:      "resource callback allows",
			principal: &auth.Principal{Subject: "alice"},
			middleware: func() router.Middleware {
				return Require(engine, "read", func(c *router.Ctx) string { return c.Request.URL.Path })
			},
			target: "/api/posts",
			want:   http.StatusOK,
		},
		{
			name:      "resource callback denies",
			principal: &auth.Principal{Subject: "alice"},
			middleware: func() router.Middleware {
				return Require(engine, "read", func(c *router.Ctx) string { return c.Request.URL.Path })
			},
			target: "/other",
			want:   http.StatusForbidden,
		},
		{
			name:      "principal attributes satisfy policy condition",
			principal: &auth.Principal{Subject: "alice", Username: "alice"},
			middleware: func() router.Middleware {
				return Require(engine, "profile:read", nil)
			},
			target: "/api/posts",
			want:   http.StatusOK,
		},
		{
			name:      "other principal fails policy condition",
			principal: &auth.Principal{Subject: "bob", Username: "bobby"},
			middleware: func() router.Middleware {
				return Require(engine, "profile:read", nil)
			},
			target: "/api/posts",
			want:   http.StatusForbidden,
		},
		{
			name:      "require any",
			principal: &auth.Principal{Subject: "alice"},
			middleware: func() router.Middleware {
				return RequireAny(engine, []string{"post:write", "post:read"}, nil)
			},
			target: "/api/posts",
			want:   http.StatusOK,
		},
		{
			name:      "require all denied",
			principal: &auth.Principal{Subject: "alice"},
			middleware: func() router.Middleware {
				return RequireAll(engine, []string{"post:read", "post:write"}, nil)
			},
			target: "/api/posts",
			want:   http.StatusForbidden,
		},
		{
			name:      "require all empty denied",
			principal: &auth.Principal{Subject: "alice"},
			middleware: func() router.Middleware {
				return RequireAll(engine, nil, nil)
			},
			target: "/api/posts",
			want:   http.StatusForbidden,
		},
		{
			name:      "nil engine",
			principal: &auth.Principal{Subject: "alice"},
			middleware: func() router.Middleware {
				return Require(nil, "post:read", nil)
			},
			target: "/api/posts",
			want:   http.StatusInternalServerError,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			r := newRouterWithPrincipal(testCase.principal)
			r.GET(testCase.target, okRouterHandler, testCase.middleware())
			recorder := serveRouter(r, testCase.target)
			if recorder.Code != testCase.want {
				t.Fatalf("status = %d want %d body=%s", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}

func TestRequireRouterPrincipalRoles(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "editor", Permissions: []string{"post:write"}})
	r := newRouterWithPrincipal(&auth.Principal{Subject: "eve", Roles: []string{"editor"}})
	r.GET("/posts", okRouterHandler, Require(engine, "post:write", nil))
	if recorder := serveRouter(r, "/posts"); recorder.Code != http.StatusOK {
		t.Fatalf("role from principal status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRequireRouterCustomErrorHandler(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})

	var captured error
	r := newRouterWithPrincipal(&auth.Principal{Subject: "alice"})
	r.GET("/posts", okRouterHandler, Require(engine, "post:write", nil, WithErrorHandler(func(c *router.Ctx, err error) {
		captured = err
		_ = c.JSON(http.StatusTeapot, map[string]string{"error": "custom"})
	})))
	recorder := serveRouter(r, "/posts")
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("status = %d want %d", recorder.Code, http.StatusTeapot)
	}
	if !errors.Is(captured, auth.ErrForbidden) {
		t.Fatalf("captured error = %v want auth.ErrForbidden", captured)
	}
}

func TestRequireHTTPMiddleware(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})
	mustAddPolicy(t, engine, Policy{ID: "api-read", Effect: EffectPermit, Resource: "/api/*", Action: "read"})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/posts", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/other", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name      string
		principal *auth.Principal
		handler   func() http.Handler
		target    string
		want      int
	}{
		{
			name:    "missing principal",
			handler: func() http.Handler { return RequireHTTP(engine, "post:read", nil)(mux) },
			target:  "/api/posts",
			want:    http.StatusUnauthorized,
		},
		{
			name:      "allowed",
			principal: &auth.Principal{Subject: "alice"},
			handler:   func() http.Handler { return RequireHTTP(engine, "post:read", nil)(mux) },
			target:    "/api/posts",
			want:      http.StatusOK,
		},
		{
			name:      "denied",
			principal: &auth.Principal{Subject: "bob"},
			handler:   func() http.Handler { return RequireHTTP(engine, "post:read", nil)(mux) },
			target:    "/api/posts",
			want:      http.StatusForbidden,
		},
		{
			name:      "resource callback allows",
			principal: &auth.Principal{Subject: "alice"},
			handler: func() http.Handler {
				return RequireHTTP(engine, "read", func(r *http.Request) string { return r.URL.Path })(mux)
			},
			target: "/api/posts",
			want:   http.StatusOK,
		},
		{
			name:      "resource callback denies",
			principal: &auth.Principal{Subject: "alice"},
			handler: func() http.Handler {
				return RequireHTTP(engine, "read", func(r *http.Request) string { return r.URL.Path })(mux)
			},
			target: "/other",
			want:   http.StatusForbidden,
		},
		{
			name:      "require any",
			principal: &auth.Principal{Subject: "alice"},
			handler: func() http.Handler {
				return RequireAnyHTTP(engine, []string{"post:write", "post:read"}, nil)(mux)
			},
			target: "/api/posts",
			want:   http.StatusOK,
		},
		{
			name:      "require all denied",
			principal: &auth.Principal{Subject: "alice"},
			handler: func() http.Handler {
				return RequireAllHTTP(engine, []string{"post:read", "post:write"}, nil)(mux)
			},
			target: "/api/posts",
			want:   http.StatusForbidden,
		},
		{
			name:      "nil engine",
			principal: &auth.Principal{Subject: "alice"},
			handler: func() http.Handler {
				return RequireHTTP(nil, "post:read", nil)(mux)
			},
			target: "/api/posts",
			want:   http.StatusInternalServerError,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, testCase.target, nil)
			if testCase.principal != nil {
				request = request.WithContext(auth.ContextWithPrincipal(request.Context(), testCase.principal))
			}
			recorder := httptest.NewRecorder()
			testCase.handler().ServeHTTP(recorder, request)
			if recorder.Code != testCase.want {
				t.Fatalf("status = %d want %d body=%s", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}

func TestRequireHTTPCustomErrorHandler(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})

	var captured error
	mux := http.NewServeMux()
	mux.HandleFunc("/posts", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RequireHTTP(engine, "post:write", nil, WithHTTPErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		captured = err
		w.WriteHeader(http.StatusTeapot)
	}))(mux)

	request := httptest.NewRequest(http.MethodGet, "/posts", nil)
	request = request.WithContext(auth.ContextWithPrincipal(request.Context(), &auth.Principal{Subject: "alice"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("status = %d want %d", recorder.Code, http.StatusTeapot)
	}
	if !errors.Is(captured, auth.ErrForbidden) {
		t.Fatalf("captured error = %v want auth.ErrForbidden", captured)
	}
}

func TestEnvironmentOperandsInMiddleware(t *testing.T) {
	engine := New()
	mustAddPolicy(t, engine, Policy{
		ID:     "api-get",
		Effect: EffectPermit,
		Action: "read",
		Conditions: []Condition{
			{Key: "env.method", Operator: OperatorEquals, Value: http.MethodGet},
			{Key: "env.path", Operator: OperatorEquals, Value: "/api/posts"},
		},
	})

	r := newRouterWithPrincipal(&auth.Principal{Subject: "alice"})
	r.GET("/api/posts", okRouterHandler, Require(engine, "read", nil))
	if recorder := serveRouter(r, "/api/posts"); recorder.Code != http.StatusOK {
		t.Fatalf("environment condition status = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

// serveRouterContext runs one router request with ctx. | serveRouterContext 使用 ctx 执行一次路由请求。
func serveRouterContext(r *router.Router, target string, ctx context.Context) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, request)
	return recorder
}

// canceledContext returns an already canceled context. | canceledContext 返回已取消的上下文。
func canceledContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, func() {}
}

// expiredContext returns a context whose deadline has already passed. | expiredContext 返回截止时间已过的上下文。
func expiredContext() (context.Context, context.CancelFunc) {
	return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
}

// TestRequireRouterPropagatesRequestCancellation verifies the router middlewares authorize with
// the incoming request context instead of a detached background context. | TestRequireRouterPropagatesRequestCancellation
// 验证路由中间件使用传入的请求上下文而非脱离的后台上下文进行授权。
func TestRequireRouterPropagatesRequestCancellation(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read", "post:write"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})
	principal := &auth.Principal{Subject: "alice"}

	cases := []struct {
		name       string
		middleware func(handler ErrorHandler) router.Middleware
		context    func() (context.Context, context.CancelFunc)
		want       error
	}{
		{
			name: "require canceled",
			middleware: func(handler ErrorHandler) router.Middleware {
				return Require(engine, "post:read", nil, WithErrorHandler(handler))
			},
			context: canceledContext,
			want:    context.Canceled,
		},
		{
			name: "require any canceled",
			middleware: func(handler ErrorHandler) router.Middleware {
				return RequireAny(engine, []string{"post:read", "post:write"}, nil, WithErrorHandler(handler))
			},
			context: canceledContext,
			want:    context.Canceled,
		},
		{
			name: "require all canceled",
			middleware: func(handler ErrorHandler) router.Middleware {
				return RequireAll(engine, []string{"post:read", "post:write"}, nil, WithErrorHandler(handler))
			},
			context: canceledContext,
			want:    context.Canceled,
		},
		{
			name: "require deadline exceeded",
			middleware: func(handler ErrorHandler) router.Middleware {
				return Require(engine, "post:read", nil, WithErrorHandler(handler))
			},
			context: expiredContext,
			want:    context.DeadlineExceeded,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var captured error
			nextCalled := false
			r := newRouterWithPrincipal(principal)
			r.GET("/posts", func(c *router.Ctx) {
				nextCalled = true
				_ = c.String(http.StatusOK, "ok")
			}, testCase.middleware(func(c *router.Ctx, err error) {
				captured = err
				_ = c.JSON(http.StatusTeapot, map[string]string{"error": "canceled"})
			}))
			ctx, cancel := testCase.context()
			defer cancel()
			recorder := serveRouterContext(r, "/posts", ctx)
			if nextCalled {
				t.Fatal("protected handler ran for a canceled request | 已取消的请求仍执行了受保护处理器")
			}
			if recorder.Code != http.StatusTeapot {
				t.Fatalf("status = %d want %d", recorder.Code, http.StatusTeapot)
			}
			if !errors.Is(captured, ErrCanceled) {
				t.Fatalf("captured error = %v want ErrCanceled", captured)
			}
			if !errors.Is(captured, testCase.want) {
				t.Fatalf("captured error = %v want %v", captured, testCase.want)
			}
		})
	}
}

// TestRequireHTTPPropagatesRequestCancellation verifies the net/http middlewares authorize with
// the incoming request context. | TestRequireHTTPPropagatesRequestCancellation 验证 net/http
// 中间件使用传入的请求上下文进行授权。
func TestRequireHTTPPropagatesRequestCancellation(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read", "post:write"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})
	principal := &auth.Principal{Subject: "alice"}

	cases := []struct {
		name    string
		handler func(HTTPErrorHandler, http.Handler) http.Handler
		context func() (context.Context, context.CancelFunc)
		want    error
	}{
		{
			name: "require canceled",
			handler: func(handler HTTPErrorHandler, next http.Handler) http.Handler {
				return RequireHTTP(engine, "post:read", nil, WithHTTPErrorHandler(handler))(next)
			},
			context: canceledContext,
			want:    context.Canceled,
		},
		{
			name: "require any canceled",
			handler: func(handler HTTPErrorHandler, next http.Handler) http.Handler {
				return RequireAnyHTTP(engine, []string{"post:read", "post:write"}, nil, WithHTTPErrorHandler(handler))(next)
			},
			context: canceledContext,
			want:    context.Canceled,
		},
		{
			name: "require all canceled",
			handler: func(handler HTTPErrorHandler, next http.Handler) http.Handler {
				return RequireAllHTTP(engine, []string{"post:read", "post:write"}, nil, WithHTTPErrorHandler(handler))(next)
			},
			context: canceledContext,
			want:    context.Canceled,
		},
		{
			name: "require deadline exceeded",
			handler: func(handler HTTPErrorHandler, next http.Handler) http.Handler {
				return RequireHTTP(engine, "post:read", nil, WithHTTPErrorHandler(handler))(next)
			},
			context: expiredContext,
			want:    context.DeadlineExceeded,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var captured error
			nextCalled := false
			next := nextOKHandler(&nextCalled)
			ctx, cancel := testCase.context()
			defer cancel()
			principalCtx := auth.ContextWithPrincipal(ctx, principal)
			request := httptest.NewRequest(http.MethodGet, "/posts", nil).WithContext(principalCtx)
			recorder := httptest.NewRecorder()
			testCase.handler(func(w http.ResponseWriter, _ *http.Request, err error) {
				captured = err
				w.WriteHeader(http.StatusTeapot)
			}, next).ServeHTTP(recorder, request)
			if nextCalled {
				t.Fatal("protected handler ran for a canceled request | 已取消的请求仍执行了受保护处理器")
			}
			if recorder.Code != http.StatusTeapot {
				t.Fatalf("status = %d want %d", recorder.Code, http.StatusTeapot)
			}
			if !errors.Is(captured, ErrCanceled) {
				t.Fatalf("captured error = %v want ErrCanceled", captured)
			}
			if !errors.Is(captured, testCase.want) {
				t.Fatalf("captured error = %v want %v", captured, testCase.want)
			}
		})
	}
}

// nextOKHandler returns a handler that records whether it ran. | nextOKHandler 返回记录是否执行的处理器。
func nextOKHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if called != nil {
			*called = true
		}
		w.WriteHeader(http.StatusOK)
	})
}

// TestRequireRouterAbortsDeniedChain verifies a rejected request never reaches the protected
// handler. ydx/router continues the dispatch loop after a middleware returns, so the middleware
// must abort explicitly. | TestRequireRouterAbortsDeniedChain 验证被拒绝的请求绝不会到达受保护
// 处理器。ydx/router 在中间件返回后会继续调度循环，因此中间件必须显式中止。
func TestRequireRouterAbortsDeniedChain(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})

	cases := []struct {
		name      string
		principal *auth.Principal
		build     func() router.Middleware
		want      int
	}{
		{
			name:  "missing principal",
			build: func() router.Middleware { return Require(engine, "post:read", nil) },
			want:  http.StatusUnauthorized,
		},
		{
			name:      "denied principal",
			principal: &auth.Principal{Subject: "bob"},
			build:     func() router.Middleware { return Require(engine, "post:read", nil) },
			want:      http.StatusForbidden,
		},
		{
			name:      "require any denied",
			principal: &auth.Principal{Subject: "bob"},
			build: func() router.Middleware {
				return RequireAny(engine, []string{"post:write", "post:delete"}, nil)
			},
			want: http.StatusForbidden,
		},
		{
			name:      "require all denied",
			principal: &auth.Principal{Subject: "alice"},
			build: func() router.Middleware {
				return RequireAll(engine, []string{"post:read", "post:write"}, nil)
			},
			want: http.StatusForbidden,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			called := false
			r := newRouterWithPrincipal(testCase.principal)
			r.GET("/posts", func(c *router.Ctx) {
				called = true
				_ = c.String(http.StatusOK, "ok")
			}, testCase.build())
			recorder := serveRouter(r, "/posts")
			if called {
				t.Fatal("protected handler ran after authorization was denied | 授权被拒绝后仍执行了受保护处理器")
			}
			if recorder.Code != testCase.want {
				t.Fatalf("status = %d want %d body=%s", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}
