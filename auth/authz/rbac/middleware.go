package rbac

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/router"
)

// ErrorHandler renders an authorization failure for ydx/router. | ErrorHandler 为 ydx/router 渲染授权失败。
type ErrorHandler func(c *router.Ctx, err error)

// HTTPErrorHandler renders an authorization failure for net/http. | HTTPErrorHandler 为 net/http 渲染授权失败。
type HTTPErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// MiddlewareOption configures the authorization middlewares. | MiddlewareOption 配置授权中间件。
type MiddlewareOption func(*middlewareConfig)

// middlewareConfig holds the optional transport-specific error renderers. | middlewareConfig 保存可选的传输层错误渲染器。
type middlewareConfig struct {
	errorHandler     ErrorHandler
	httpErrorHandler HTTPErrorHandler
}

// WithErrorHandler installs a custom ydx/router failure renderer. | WithErrorHandler 安装自定义 ydx/router 失败渲染器。
func WithErrorHandler(handler ErrorHandler) MiddlewareOption {
	return func(config *middlewareConfig) {
		if handler != nil {
			config.errorHandler = handler
		}
	}
}

// WithHTTPErrorHandler installs a custom net/http failure renderer. | WithHTTPErrorHandler 安装自定义 net/http 失败渲染器。
func WithHTTPErrorHandler(handler HTTPErrorHandler) MiddlewareOption {
	return func(config *middlewareConfig) {
		if handler != nil {
			config.httpErrorHandler = handler
		}
	}
}

// newMiddlewareConfig applies opts. | newMiddlewareConfig 应用 opts。
func newMiddlewareConfig(opts []MiddlewareOption) middlewareConfig {
	var config middlewareConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}
	return config
}

// routerFailure renders a router failure. | routerFailure 渲染路由失败。
func (c middlewareConfig) routerFailure(ctx *router.Ctx, err error) {
	if ctx == nil {
		return
	}
	if c.errorHandler != nil {
		c.errorHandler(ctx, err)
		return
	}
	defaultRouterFailure(ctx, err)
}

// routerDenied aborts the remaining ydx/router chain and renders err. ydx/router's dispatch loop
// continues past a middleware that merely returns, so every denial must abort explicitly. |
// routerDenied 终止后续 ydx/router 调用链并渲染 err。ydx/router 的调度循环会越过仅返回的中间件
// 继续执行，因此每次拒绝都必须显式中止。
func (c middlewareConfig) routerDenied(ctx *router.Ctx, err error) {
	if ctx != nil {
		ctx.Abort()
	}
	c.routerFailure(ctx, err)
}

// httpFailure renders a net/http failure. | httpFailure 渲染 net/http 失败。
func (c middlewareConfig) httpFailure(w http.ResponseWriter, r *http.Request, err error) {
	if c.httpErrorHandler != nil {
		c.httpErrorHandler(w, r, err)
		return
	}
	defaultHTTPFailure(w, err)
}

// defaultRouterFailure writes a status derived from err. | defaultRouterFailure 写出由 err 推导的状态码。
func defaultRouterFailure(c *router.Ctx, err error) {
	status := statusForError(err)
	_ = c.JSON(status, map[string]string{"error": http.StatusText(status)})
}

// defaultHTTPFailure writes a status derived from err. | defaultHTTPFailure 写出由 err 推导的状态码。
func defaultHTTPFailure(w http.ResponseWriter, err error) {
	status := statusForError(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + http.StatusText(status) + `"}`))
}

// statusForError maps an authorization error to an HTTP status. | statusForError 把授权错误映射为 HTTP 状态码。
func statusForError(err error) int {
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, auth.ErrForbidden):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// forbiddenError attaches the decision reason to auth.ErrForbidden. | forbiddenError 把决策原因附加到 auth.ErrForbidden。
func forbiddenError(permission string, decision Decision) error {
	reason := decision.Reason
	if reason == "" {
		reason = "denied"
	}
	return errs.Detail(auth.ErrForbidden, "permission %q denied: %s | 权限 %q 被拒绝：%s",
		permission, reason, permission, reason)
}

// principalAttributes projects principal claims into condition attributes. | principalAttributes 把主体声明投影为条件属性。
func principalAttributes(principal *auth.Principal) map[string]string {
	if principal == nil {
		return nil
	}
	if len(principal.Attributes) == 0 && principal.Username == "" && principal.Email == "" && principal.DisplayName == "" {
		return nil
	}
	attributes := make(map[string]string, len(principal.Attributes)+3)
	for key, value := range principal.Attributes {
		attributes[key] = value
	}
	putDefault(attributes, "username", principal.Username)
	putDefault(attributes, "email", principal.Email)
	putDefault(attributes, "display_name", principal.DisplayName)
	return attributes
}

// putDefault stores value under key when the key is absent and the value is non-empty. | putDefault
// 在键缺失且值非空时把 value 存入 key。
func putDefault(attributes map[string]string, key, value string) {
	if value == "" {
		return
	}
	if _, exists := attributes[key]; exists {
		return
	}
	attributes[key] = value
}

// environmentForRequest builds the environment operand map of an HTTP request. | environmentForRequest
// 构建 HTTP 请求的环境操作数映射。
func environmentForRequest(r *http.Request) map[string]string {
	if r == nil {
		return nil
	}
	environment := make(map[string]string, 4)
	if r.Method != "" {
		environment["method"] = r.Method
	}
	if r.URL != nil {
		if r.URL.Path != "" {
			environment["path"] = r.URL.Path
		}
		if r.URL.Host != "" {
			environment["host"] = r.URL.Host
		}
	}
	if r.RemoteAddr != "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
			environment["ip"] = host
		} else {
			environment["ip"] = r.RemoteAddr
		}
	}
	if userAgent := r.UserAgent(); userAgent != "" {
		environment["user_agent"] = userAgent
	}
	return environment
}

// requestContext returns the incoming request context, falling back to context.Background only
// when the router context has no request attached. | requestContext 返回传入的请求上下文，仅当
// 路由上下文没有关联请求时回退到 context.Background。
func requestContext(c *router.Ctx) context.Context {
	if c == nil || c.Request == nil {
		return context.Background()
	}
	return c.Request.Context()
}

// authorizeRequest performs one engine call for an authenticated principal. | authorizeRequest 为已认证主体执行一次引擎调用。
func authorizeRequest(ctx context.Context, engine *Engine, principal *auth.Principal, permission, resource string, environment map[string]string) (Decision, error) {
	return engine.Authorize(ctx, Request{
		Subject:     principal.Subject,
		Roles:       append([]string(nil), principal.Roles...),
		Action:      permission,
		Resource:    resource,
		Attributes:  principalAttributes(principal),
		Environment: environment,
	})
}

// authorizeAny returns the first allowing decision or the last denying decision. | authorizeAny 返回首个允许决策或最后一个拒绝决策。
func authorizeAny(ctx context.Context, engine *Engine, principal *auth.Principal, permissions []string, resource string, environment map[string]string) (Decision, error) {
	var firstErr error
	decision := Decision{Reason: "no permissions configured"}
	for _, permission := range permissions {
		current, err := authorizeRequest(ctx, engine, principal, permission, resource, environment)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if current.Allowed {
			return current, nil
		}
		decision = current
	}
	if firstErr != nil {
		return Decision{}, firstErr
	}
	return decision, nil
}

// authorizeAll returns the first denying or failing decision, otherwise an allowing one. | authorizeAll
// 返回首个拒绝或失败决策，否则返回允许决策。
func authorizeAll(ctx context.Context, engine *Engine, principal *auth.Principal, permissions []string, resource string, environment map[string]string) (Decision, error) {
	if len(permissions) == 0 {
		return Decision{Reason: "no permissions configured"}, nil
	}
	var decision Decision
	for _, permission := range permissions {
		current, err := authorizeRequest(ctx, engine, principal, permission, resource, environment)
		if err != nil {
			return Decision{}, err
		}
		decision = current
		if !current.Allowed {
			return current, nil
		}
	}
	return decision, nil
}

// Require returns a native ydx/router middleware enforcing one permission. | Require 返回强制单个权限的原生 ydx/router 中间件。
//
// The principal is read with auth.PrincipalFromCtx. A missing principal yields 401 and a denied
// decision yields 403; unexpected errors yield 500. The resource callback may be nil. | 主体经
// auth.PrincipalFromCtx 读取。缺少主体返回 401，拒绝决策返回 403，意外错误返回 500。resource 回调
// 可以为空。
func Require(engine *Engine, permission string, resource func(*router.Ctx) string, opts ...MiddlewareOption) router.Middleware {
	config := newMiddlewareConfig(opts)
	if engine == nil {
		return func(c *router.Ctx) { config.routerDenied(c, ErrNilEngine) }
	}
	return func(c *router.Ctx) {
		if c == nil {
			return
		}
		principal, ok := auth.PrincipalFromCtx(c)
		if !ok || principal == nil {
			config.routerDenied(c, auth.ErrUnauthorized)
			return
		}
		var target string
		if resource != nil {
			target = resource(c)
		}
		requestCtx := requestContext(c)
		decision, err := authorizeRequest(requestCtx, engine, principal, permission, target, environmentForRequest(c.Request))
		if err != nil {
			config.routerDenied(c, err)
			return
		}
		if !decision.Allowed {
			config.routerDenied(c, forbiddenError(permission, decision))
			return
		}
		c.Next()
	}
}

// RequireAny returns a router middleware accepting any one of permissions. | RequireAny 返回接受
// permissions 中任意一个的路由中间件。
func RequireAny(engine *Engine, permissions []string, resource func(*router.Ctx) string, opts ...MiddlewareOption) router.Middleware {
	config := newMiddlewareConfig(opts)
	if engine == nil {
		return func(c *router.Ctx) { config.routerDenied(c, ErrNilEngine) }
	}
	return func(c *router.Ctx) {
		if c == nil {
			return
		}
		principal, ok := auth.PrincipalFromCtx(c)
		if !ok || principal == nil {
			config.routerDenied(c, auth.ErrUnauthorized)
			return
		}
		var target string
		if resource != nil {
			target = resource(c)
		}
		requestCtx := requestContext(c)
		decision, err := authorizeAny(requestCtx, engine, principal, permissions, target, environmentForRequest(c.Request))
		if err != nil {
			config.routerDenied(c, err)
			return
		}
		if !decision.Allowed {
			config.routerDenied(c, forbiddenError(strings.Join(permissions, ","), decision))
			return
		}
		c.Next()
	}
}

// RequireAll returns a router middleware requiring every permission. | RequireAll 返回要求全部权限的路由中间件。
func RequireAll(engine *Engine, permissions []string, resource func(*router.Ctx) string, opts ...MiddlewareOption) router.Middleware {
	config := newMiddlewareConfig(opts)
	if engine == nil {
		return func(c *router.Ctx) { config.routerDenied(c, ErrNilEngine) }
	}
	return func(c *router.Ctx) {
		if c == nil {
			return
		}
		principal, ok := auth.PrincipalFromCtx(c)
		if !ok || principal == nil {
			config.routerDenied(c, auth.ErrUnauthorized)
			return
		}
		var target string
		if resource != nil {
			target = resource(c)
		}
		requestCtx := requestContext(c)
		decision, err := authorizeAll(requestCtx, engine, principal, permissions, target, environmentForRequest(c.Request))
		if err != nil {
			config.routerDenied(c, err)
			return
		}
		if !decision.Allowed {
			config.routerDenied(c, forbiddenError(strings.Join(permissions, ","), decision))
			return
		}
		c.Next()
	}
}

// RequireHTTP returns the standard net/http equivalent of Require. | RequireHTTP 返回 Require 的标准 net/http 等价物。
func RequireHTTP(engine *Engine, permission string, resource func(*http.Request) string, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	config := newMiddlewareConfig(opts)
	return func(next http.Handler) http.Handler {
		if next == nil {
			next = http.NotFoundHandler()
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if engine == nil {
				config.httpFailure(w, r, ErrNilEngine)
				return
			}
			principal, ok := auth.PrincipalFromRequest(r)
			if !ok || principal == nil {
				config.httpFailure(w, r, auth.ErrUnauthorized)
				return
			}
			var target string
			if resource != nil {
				target = resource(r)
			}
			decision, err := authorizeRequest(r.Context(), engine, principal, permission, target, environmentForRequest(r))
			if err != nil {
				config.httpFailure(w, r, err)
				return
			}
			if !decision.Allowed {
				config.httpFailure(w, r, forbiddenError(permission, decision))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyHTTP returns the standard net/http equivalent of RequireAny. | RequireAnyHTTP 返回 RequireAny 的标准 net/http 等价物。
func RequireAnyHTTP(engine *Engine, permissions []string, resource func(*http.Request) string, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	config := newMiddlewareConfig(opts)
	return func(next http.Handler) http.Handler {
		if next == nil {
			next = http.NotFoundHandler()
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if engine == nil {
				config.httpFailure(w, r, ErrNilEngine)
				return
			}
			principal, ok := auth.PrincipalFromRequest(r)
			if !ok || principal == nil {
				config.httpFailure(w, r, auth.ErrUnauthorized)
				return
			}
			var target string
			if resource != nil {
				target = resource(r)
			}
			decision, err := authorizeAny(r.Context(), engine, principal, permissions, target, environmentForRequest(r))
			if err != nil {
				config.httpFailure(w, r, err)
				return
			}
			if !decision.Allowed {
				config.httpFailure(w, r, forbiddenError(strings.Join(permissions, ","), decision))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllHTTP returns the standard net/http equivalent of RequireAll. | RequireAllHTTP 返回 RequireAll 的标准 net/http 等价物。
func RequireAllHTTP(engine *Engine, permissions []string, resource func(*http.Request) string, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	config := newMiddlewareConfig(opts)
	return func(next http.Handler) http.Handler {
		if next == nil {
			next = http.NotFoundHandler()
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if engine == nil {
				config.httpFailure(w, r, ErrNilEngine)
				return
			}
			principal, ok := auth.PrincipalFromRequest(r)
			if !ok || principal == nil {
				config.httpFailure(w, r, auth.ErrUnauthorized)
				return
			}
			var target string
			if resource != nil {
				target = resource(r)
			}
			decision, err := authorizeAll(r.Context(), engine, principal, permissions, target, environmentForRequest(r))
			if err != nil {
				config.httpFailure(w, r, err)
				return
			}
			if !decision.Allowed {
				config.httpFailure(w, r, forbiddenError(strings.Join(permissions, ","), decision))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
