package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/router"
)

// AccessOptions configures RequireAccess. | AccessOptions 配置 RequireAccess。
type AccessOptions struct {
	// Permissions are checked against Principal.Permissions. | Permissions 对 Principal.Permissions 检查。
	Permissions []string
	// Roles are checked against Principal.Roles. | Roles 对 Principal.Roles 检查。
	Roles []string
	// Scopes are checked against Principal.Scopes. | Scopes 对 Principal.Scopes 检查。
	Scopes []string
	// Any requires any listed item instead of all of them. | Any 要求任一列出的项，而不是全部。
	Any bool
	// ErrorHandler renders failures for ydx/router. | ErrorHandler 为 ydx/router 渲染失败响应。
	ErrorHandler func(c *router.Ctx, err error)
}

// RequireAccess returns a native ydx/router middleware that enforces access requirements. | RequireAccess
// 返回强制执行访问要求的原生 ydx/router 中间件。
//
// An absent principal is rejected with 401; a principal lacking the requirement is rejected with 403. | 缺少主体时以 401 拒绝；主体不满足要求时以 403 拒绝。
func RequireAccess(opts AccessOptions) router.Middleware {
	return func(c *router.Ctx) {
		principal, ok := PrincipalFromCtx(c)
		if !ok || principal == nil {
			failAccess(c, opts.ErrorHandler, ErrUnauthorized)
			return
		}
		if !principalSatisfies(principal, opts) {
			failAccess(c, opts.ErrorHandler, ErrForbidden)
			return
		}
		c.Next()
	}
}

// RequireAccessHTTP returns the standard net/http equivalent of RequireAccess. | RequireAccessHTTP 返回与 RequireAccess 等价的标准 net/http 中间件。
func RequireAccessHTTP(opts AccessOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromRequest(r)
			if !ok || principal == nil {
				writeHTTPError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !principalSatisfies(principal, opts) {
				writeHTTPError(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns a middleware for one permission. | RequirePermission 返回单个权限的中间件。
func RequirePermission(permission string) router.Middleware {
	return RequireAccess(AccessOptions{Permissions: []string{permission}})
}

// RequirePermissionHTTP returns the net/http equivalent of RequirePermission. | RequirePermissionHTTP 返回 RequirePermission 的 net/http 等价物。
func RequirePermissionHTTP(permission string) func(http.Handler) http.Handler {
	return RequireAccessHTTP(AccessOptions{Permissions: []string{permission}})
}

// principalSatisfies applies the access requirements. | principalSatisfies 应用访问要求。
func principalSatisfies(p *Principal, opts AccessOptions) bool {
	checks := make([]bool, 0, len(opts.Permissions)+len(opts.Roles)+len(opts.Scopes))
	for _, permission := range opts.Permissions {
		checks = append(checks, p.HasPermission(permission))
	}
	for _, role := range opts.Roles {
		checks = append(checks, p.HasRole(role))
	}
	for _, scope := range opts.Scopes {
		checks = append(checks, p.HasScope(scope))
	}
	if len(checks) == 0 {
		return true
	}
	if opts.Any {
		for _, ok := range checks {
			if ok {
				return true
			}
		}
		return false
	}
	for _, ok := range checks {
		if !ok {
			return false
		}
	}
	return true
}

// failAccess renders an access failure and aborts the remaining chain. | failAccess 渲染访问失败并终止后续调用链。
//
// Aborting is required by ydx/router: returning from a middleware without calling Next still lets the
// outer dispatch loop run the remaining handlers, so a denied request would reach the protected
// handler after the error response was written. | ydx/router 要求终止调用链：中间件不调用 Next 直接返回时，
// 外层调度循环仍会执行剩余处理器，被拒绝的请求会在写出错误响应后继续进入受保护处理器。
func failAccess(c *router.Ctx, handler func(*router.Ctx, error), err error) {
	if c != nil {
		c.Abort()
	}
	if handler != nil {
		handler(c, err)
		return
	}
	status := http.StatusUnauthorized
	if errors.Is(err, ErrForbidden) {
		status = http.StatusForbidden
	}
	_ = c.JSON(status, map[string]string{"error": http.StatusText(status)})
}

// PrincipalOrError returns the request principal or ErrUnauthorized. | PrincipalOrError 返回请求主体或 ErrUnauthorized。
func PrincipalOrError(r *http.Request) (*Principal, error) {
	if p, ok := PrincipalFromRequest(r); ok {
		return p, nil
	}
	return nil, ErrUnauthorized
}

// CtxPrincipalOrError returns the router principal or ErrUnauthorized. | CtxPrincipalOrError 返回路由主体或 ErrUnauthorized。
func CtxPrincipalOrError(c *router.Ctx) (*Principal, error) {
	if p, ok := PrincipalFromCtx(c); ok {
		return p, nil
	}
	return nil, ErrUnauthorized
}

// BearerToken extracts an RFC 6750 bearer token from the Authorization header. | BearerToken 从
// Authorization 头提取 RFC 6750 承载令牌。
//
// The scheme match is case-insensitive and the scheme must be followed by one space; leading and
// trailing whitespace around the token is removed. An empty token returns ErrUnauthorized. | 方案匹配
// 不区分大小写且方案后必须有一个空格；令牌前后的空白会被移除。令牌为空时返回 ErrUnauthorized。
func BearerToken(r *http.Request) (string, error) {
	if r == nil {
		return "", ErrUnauthorized
	}
	header := r.Header.Get("Authorization")
	if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
		return "", ErrUnauthorized
	}
	token := strings.TrimSpace(header[7:])
	if token == "" {
		return "", ErrUnauthorized
	}
	return token, nil
}

// RequireBearer returns a middleware that copies a bearer token into the request header and continues. | RequireBearer
// 返回把承载令牌复制到请求头并继续的中间件。
//
// It is useful when a resource server also accepts the token from a cookie or a query parameter; the
// caller's authenticator can then always read Authorization. | 当资源服务器还接受来自 Cookie 或查询
// 参数的令牌时，它很有用；调用方的认证器随后总可以读取 Authorization。
func RequireBearer(source func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if source != nil && r.Header.Get("Authorization") == "" {
				if token := source(r); token != "" {
					r = r.Clone(r.Context())
					r.Header.Set("Authorization", "Bearer "+token)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ErrInvalidAccessToken is returned by resource-server helpers when a token is malformed or expired. | ErrInvalidAccessToken 在令牌格式非法或过期时由资源服务器辅助函数返回。
var ErrInvalidAccessToken = errs.New("auth: invalid access token | auth：访问令牌无效")

// IntrospectedToken is the minimal resource-server view of a token. | IntrospectedToken 是资源服务器看到的令牌最小视图。
type IntrospectedToken struct {
	// Active reports whether the token is currently valid. | Active 报告令牌当前是否有效。
	Active bool `json:"active"`
	// Scope is the space-delimited scope string. | Scope 是空格分隔的作用域字符串。
	Scope string `json:"scope,omitempty"`
	// ClientID, Username, TokenType, Sub, Aud, Iss, JTI mirror RFC 7662 fields. | ClientID、Username、
	// TokenType、Sub、Aud、Iss、JTI 对应 RFC 7662 字段。
	ClientID string `json:"client_id,omitempty"`
	// Username is the resource owner login name. | Username 是资源所有者登录名。
	Username string `json:"username,omitempty"`
	// TokenType is the token type such as "Bearer". | TokenType 是令牌类型，例如 "Bearer"。
	TokenType string `json:"token_type,omitempty"`
	// Sub is the subject identifier. | Sub 是主体标识。
	Sub string `json:"sub,omitempty"`
	// Aud is the audience value or array. | Aud 是受众值或数组。
	Aud any `json:"aud,omitempty"`
	// Iss is the issuer identifier. | Iss 是签发方标识。
	Iss string `json:"iss,omitempty"`
	// JTI is the token identifier. | JTI 是令牌标识。
	JTI string `json:"jti,omitempty"`
	// Exp is the expiration NumericDate. | Exp 是过期 NumericDate。
	Exp int64 `json:"exp,omitempty"`
	// Iat is the issue NumericDate. | Iat 是签发 NumericDate。
	Iat int64 `json:"iat,omitempty"`
	// Nbf is the not-before NumericDate. | Nbf 是生效前 NumericDate。
	Nbf int64 `json:"nbf,omitempty"`
	// CNF is the confirmation claim, for example {"jkt": "..."} for DPoP. | CNF 是确认声明，例如 DPoP 的 {"jkt": "..."}。
	CNF map[string]any `json:"cnf,omitempty"`
}
