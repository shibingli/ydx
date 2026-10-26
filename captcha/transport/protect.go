package transport

import (
	"net/http"
	"strings"

	"github.com/shibingli/ydx/router"
)

// TokenHeader is the default verification-token request header. | TokenHeader 是默认验证令牌请求头。
const TokenHeader = "X-Captcha-Token"

// ProtectOptions configures token middleware. | ProtectOptions 配置令牌中间件。
type ProtectOptions struct {
	// Header overrides the token header name. | Header 覆盖令牌请求头名。
	Header string
	// Reusable verifies without consuming the one-time marker. | Reusable 验证但不消费一次性标记。
	Reusable bool
}

// NewProtect returns YD middleware that requires a valid token for action. | NewProtect 返回要求 action 有效令牌的 YD 中间件。
//
// By default a token is consumed once; use Reusable when the same request may
// be checked by several handlers. | 默认令牌只消费一次；同一请求可能被多个处理器检查时使用
// Reusable。
func NewProtect(m Manager, action string, options ProtectOptions) router.Middleware {
	header := strings.TrimSpace(options.Header)
	if header == "" {
		header = TokenHeader
	}
	return func(c *router.Ctx) {
		if c == nil || c.Request == nil {
			return
		}
		if c.Method() == http.MethodOptions {
			c.Next()
			return
		}
		token := tokenFromHeader(c.Request, header)
		if token == "" {
			writeAPIErrorWith(c.Writer, ErrTokenInvalid, m.ErrorMessage(localeFromRequest(m, c.Request), ErrTokenInvalid))
			c.Abort()
			return
		}
		var claims *TokenClaims
		var err error
		if options.Reusable {
			claims, err = m.VerifyToken(c.Request.Context(), token, action)
		} else {
			claims, err = m.ConsumeToken(c.Request.Context(), token, action)
		}
		if err != nil {
			writeAPIErrorWith(c.Writer, err, m.ErrorMessage(localeFromRequest(m, c.Request), err))
			c.Abort()
			return
		}
		c.Request = c.Request.WithContext(contextWithClaims(c.Request.Context(), claims))
		c.Next()
	}
}

// NewHTTPMiddleware returns native net/http token middleware. | NewHTTPMiddleware 返回原生 net/http 令牌中间件。
func NewHTTPMiddleware(m Manager, action string, options ProtectOptions) func(http.Handler) http.Handler {
	middleware := NewProtect(m, action, options)
	return func(next http.Handler) http.Handler {
		return router.Adapt(next, middleware)
	}
}

// TokenFromRequest returns a token from the default header or Bearer scheme. | TokenFromRequest 从默认头或 Bearer 方案返回令牌。
func TokenFromRequest(r *http.Request) string {
	return tokenFromHeader(r, TokenHeader)
}

// tokenFromHeader extracts a token from an explicit header or Authorization. | tokenFromHeader 从显式头部或 Authorization 提取令牌。
func tokenFromHeader(r *http.Request, header string) string {
	if r == nil {
		return ""
	}
	if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
		return value
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authorization) > 7 && strings.EqualFold(authorization[:7], "Bearer ") {
		return strings.TrimSpace(authorization[7:])
	}
	return ""
}
