package cas

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/router"
)

// MiddlewareOptions configures the CAS session middleware. | MiddlewareOptions 配置 CAS 会话中间件。
type MiddlewareOptions struct {
	// LoginPath is the login endpoint unauthenticated browsers are redirected to. Empty answers 401
	// instead of redirecting, which is appropriate for APIs. | LoginPath 是未认证浏览器被重定向到的
	// 登录端点。空值改为返回 401，适合 API。
	LoginPath string
	// RequireTGT rejects requests without a valid TGT instead of passing them through. | RequireTGT
	// 在没有有效 TGT 时拒绝请求，而不是放行。
	RequireTGT bool
}

// Middleware returns a ydx/router middleware that reads the TGC cookie and exposes the principal
// through auth.PrincipalFromCtx. | Middleware 返回读取 TGC Cookie 并经 auth.PrincipalFromCtx 暴露
// 主体的 ydx/router 中间件。
//
// The principal is injected into the request context, so handlers can also use
// auth.PrincipalFromRequest. The TGT itself is never handed to downstream handlers. | 主体被注入请求
// 上下文，处理器也可使用 auth.PrincipalFromRequest。TGT 本身绝不会交给下游处理器。
func (s *Server) Middleware(options MiddlewareOptions) router.Middleware {
	return func(c *router.Ctx) {
		if c == nil || c.Request == nil {
			return
		}
		tgt, ok := s.ticketFromRequest(c.Request)
		if ok {
			principal := tgt.Principal.Clone()
			c.Request = c.Request.WithContext(auth.ContextWithPrincipal(c.Request.Context(), principal))
			c.Set(principalContextKey, principal)
			c.Next()
			return
		}
		if !options.RequireTGT {
			c.Next()
			return
		}
		s.rejectUnauthenticated(c.Writer, c.Request, options)
	}
}

// HTTPMiddleware returns the net/http equivalent of Middleware. | HTTPMiddleware 返回 Middleware 的
// net/http 等价物。
func (s *Server) HTTPMiddleware(options MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tgt, ok := s.ticketFromRequest(r)
			if ok {
				principal := tgt.Principal.Clone()
				r = r.WithContext(auth.ContextWithPrincipal(r.Context(), principal))
				next.ServeHTTP(w, r)
				return
			}
			if !options.RequireTGT {
				next.ServeHTTP(w, r)
				return
			}
			s.rejectUnauthenticated(w, r, options)
		})
	}
}

// principalContextKey mirrors the private auth router context key so that auth.PrincipalFromCtx
// finds the principal directly. | principalContextKey 镜像 auth 的私有路由上下文键，使
// auth.PrincipalFromCtx 可以直接找到主体。
const principalContextKey = "auth.principal"

// rejectUnauthenticated redirects to the login endpoint or answers 401. | rejectUnauthenticated
// 重定向到登录端点或返回 401。
func (s *Server) rejectUnauthenticated(w http.ResponseWriter, r *http.Request, options MiddlewareOptions) {
	loginPath := strings.TrimSpace(options.LoginPath)
	if loginPath == "" {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	target := loginPath
	if service := requestURL(r); service != "" {
		if parsed, err := url.Parse(loginPath); err == nil {
			query := parsed.Query()
			query.Set("service", service)
			parsed.RawQuery = query.Encode()
			target = parsed.String()
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// requestURL rebuilds the absolute URL of r. X-Forwarded-Proto is honored for deployments behind a
// trusted TLS-terminating proxy; values other than http and https are ignored so a forged header
// cannot inject an arbitrary scheme into the login redirect. | requestURL 重建 r 的绝对 URL。为部署
// 在可信 TLS 终止代理之后的场景识别 X-Forwarded-Proto；http 与 https 之外的值会被忽略，避免伪造
// 头把任意协议注入登录重定向。
func requestURL(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		if comma := strings.IndexByte(forwarded, ','); comma >= 0 {
			forwarded = forwarded[:comma]
		}
		forwarded = strings.ToLower(strings.TrimSpace(forwarded))
		if forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host + r.URL.RequestURI()
}
