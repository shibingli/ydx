package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/router"
)

// SessionConfig configures cookie-backed session management. | SessionConfig 配置 Cookie 会话管理。
type SessionConfig struct {
	// CookieName is the cookie name; defaults to "ydx_session". | CookieName 是 Cookie 名；默认 "ydx_session"。
	CookieName string
	// Domain and Path scope the cookie; Path defaults to "/". | Domain 与 Path 限定 Cookie 范围；Path 默认 "/"。
	Domain string
	Path   string
	// Secure marks the cookie HTTPS-only; production deployments must set it. | Secure 标记 Cookie 仅 HTTPS；生产部署必须设置。
	Secure bool
	// HTTPOnly prevents script access; it defaults to true and should only be disabled for a
	// deliberate double-submit CSRF scheme. | HTTPOnly 阻止脚本访问；默认 true，仅在有意的双提交 CSRF 方案中才应关闭。
	HTTPOnly bool
	// SameSite controls cross-site sending; it defaults to Lax. | SameSite 控制跨站发送；默认 Lax。
	SameSite http.SameSite
	// IdleTimeout is the sliding inactivity deadline; zero disables idle expiry. | IdleTimeout 是滑动空闲期限；零值禁用空闲过期。
	IdleTimeout time.Duration
	// AbsoluteTimeout is the fixed session lifetime; zero means 24 hours. | AbsoluteTimeout 是固定会话寿命；零值表示 24 小时。
	AbsoluteTimeout time.Duration
	// RotateAfter rotates the session identifier after the given age; zero disables rotation. | RotateAfter 在给定年龄后轮换会话标识；零值禁用轮换。
	RotateAfter time.Duration
	// TouchInterval throttles LastSeenAt writes; zero means 30 seconds. | TouchInterval 限制 LastSeenAt 写入频率；零值表示 30 秒。
	TouchInterval time.Duration
	// MaxSessions is the per-user active session cap; zero means unlimited. | MaxSessions 是每用户活跃会话上限；零值表示不限。
	MaxSessions int
	// CSRFHeader is the request header carrying the CSRF token; defaults to "X-CSRF-Token". | CSRFHeader 是携带 CSRF 令牌的请求头；默认 "X-CSRF-Token"。
	CSRFHeader string
	// CSRFParam is the form field carrying the CSRF token; defaults to "csrf_token". | CSRFParam 是携带 CSRF 令牌的表单字段；默认 "csrf_token"。
	CSRFParam string
}

// DefaultSessionConfig returns a conservative session configuration. | DefaultSessionConfig 返回保守的会话配置。
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		CookieName:      "ydx_session",
		Path:            "/",
		HTTPOnly:        true,
		SameSite:        http.SameSiteLaxMode,
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 24 * time.Hour,
		TouchInterval:   30 * time.Second,
		CSRFHeader:      "X-CSRF-Token",
		CSRFParam:       "csrf_token",
	}
}

// SessionManager creates, validates and revokes login sessions. | SessionManager 创建、校验与撤销登录会话。
//
// It is safe for concurrent use. The primary HTTP entry point is Middleware for ydx/router;
// HTTPMiddleware exposes the same behavior through the standard net/http middleware shape. | 它可并发
// 安全使用。首选 HTTP 入口是面向 ydx/router 的 Middleware；HTTPMiddleware 以标准 net/http 中间件
// 形态暴露相同行为。
type SessionManager struct {
	// store persists sessions. | store 持久化会话。
	store SessionStore
	// users resolves the session owner. | users 解析会话属主。
	users UserStore
	// config is the normalized configuration. | config 是规范化后的配置。
	config SessionConfig
	// clock overrides time for tests. | clock 为测试替换时间。
	clock func() time.Time
	// buildPrincipal projects a user and session into a principal. | buildPrincipal 把用户与会话投影为主体。
	buildPrincipal func(ctx context.Context, user *User, session *Session) (*Principal, error)
}

// NewSessionManager returns a session manager. | NewSessionManager 返回会话管理器。
func NewSessionManager(store SessionStore, users UserStore, config SessionConfig) (*SessionManager, error) {
	if store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "session store is nil | 会话存储为空")
	}
	if users == nil {
		return nil, errs.Detail(ErrInvalidConfig, "user store is nil | 用户存储为空")
	}
	def := DefaultSessionConfig()
	if config.CookieName == "" {
		config.CookieName = def.CookieName
	}
	if config.Path == "" {
		config.Path = def.Path
	}
	if config.CSRFHeader == "" {
		config.CSRFHeader = def.CSRFHeader
	}
	if config.CSRFParam == "" {
		config.CSRFParam = def.CSRFParam
	}
	if config.AbsoluteTimeout <= 0 {
		config.AbsoluteTimeout = def.AbsoluteTimeout
	}
	if config.TouchInterval <= 0 {
		config.TouchInterval = def.TouchInterval
	}
	if !config.HTTPOnly && config.SameSite != http.SameSiteNoneMode {
		// HTTPOnly is the safe default; an explicit false is preserved only for a deliberate scheme. | HTTPOnly
		// 是安全默认值；只有有意的方案才保留显式 false。
		config.HTTPOnly = true
	}
	if config.SameSite == http.SameSiteNoneMode && !config.Secure {
		return nil, errs.Detail(ErrInvalidConfig, "SameSite=None requires Secure | SameSite=None 需要 Secure")
	}
	return &SessionManager{store: store, users: users, config: config}, nil
}

// Config returns the normalized session configuration. | Config 返回规范化后的会话配置。
func (m *SessionManager) Config() SessionConfig { return m.config }

// SetClock replaces the time source; it is intended for deterministic tests. | SetClock 替换时间源；用于确定性测试。
func (m *SessionManager) SetClock(clock func() time.Time) { m.clock = clock }

// SetPrincipalBuilder replaces the projection from user and session to principal. | SetPrincipalBuilder 替换用户与会话到主体的投影。
func (m *SessionManager) SetPrincipalBuilder(fn func(ctx context.Context, user *User, session *Session) (*Principal, error)) {
	m.buildPrincipal = fn
}

// now returns the current UTC time. | now 返回当前 UTC 时间。
func (m *SessionManager) now() time.Time { return Now(m.clock) }

// Create starts a new session for userID. | Create 为 userID 创建新会话。
func (m *SessionManager) Create(ctx context.Context, userID, clientID string, r *http.Request, amr []string, acr string) (*Session, error) {
	if userID == "" {
		return nil, errs.Detail(ErrInvalidRequest, "user id is empty | 用户 ID 为空")
	}
	now := m.now()
	id, err := RandomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := RandomToken(32)
	if err != nil {
		return nil, err
	}
	session := &Session{
		ID:         id,
		UserID:     userID,
		ClientID:   clientID,
		CreatedAt:  now,
		UpdatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(m.config.AbsoluteTimeout),
		CSRFSecret: csrf,
		AMR:        append([]string(nil), amr...),
		ACR:        acr,
		Data:       make(map[string]string),
	}
	if m.config.IdleTimeout > 0 {
		session.IdleExpiresAt = now.Add(m.config.IdleTimeout)
	}
	if r != nil {
		session.IP = requestIP(r)
		session.UserAgent = r.UserAgent()
		session.DeviceID = r.Header.Get("X-Device-ID")
	}
	if m.config.MaxSessions > 0 {
		if err := m.enforceMaxSessions(ctx, userID, now); err != nil {
			return nil, err
		}
	}
	if err := m.store.CreateSession(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

// enforceMaxSessions revokes the oldest active sessions above the configured cap. | enforceMaxSessions 撤销超过配置上限的最旧活跃会话。
func (m *SessionManager) enforceMaxSessions(ctx context.Context, userID string, now time.Time) error {
	sessions, err := m.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return err
	}
	active := make([]*Session, 0, len(sessions))
	for _, session := range sessions {
		if session.Active(now) {
			active = append(active, session)
		}
	}
	// Stores do not promise an ordering, so sort by creation time and revoke from the oldest end. | 存储
	// 不保证顺序，因此按创建时间排序并从最旧的一端撤销。
	sort.SliceStable(active, func(i, j int) bool {
		return active[i].CreatedAt.Before(active[j].CreatedAt)
	})
	// Reserve one slot for the session being created; otherwise the cap is exceeded by one. | 为正在
	// 创建的会话预留一个槽位，否则会超出上限一个。
	excess := len(active) - m.config.MaxSessions + 1
	if excess > len(active) {
		excess = len(active)
	}
	for i := 0; i < excess; i++ {
		session := active[i]
		revoked := now
		session.RevokedAt = &revoked
		session.RevokeReason = "max_sessions"
		session.UpdatedAt = now
		if err := m.store.UpdateSession(ctx, session); err != nil {
			return err
		}
	}
	return nil
}

// Get returns a stored session without validating it. | Get 返回已存会话但不校验。
func (m *SessionManager) Get(ctx context.Context, id string) (*Session, error) {
	return m.store.GetSession(ctx, id)
}

// Validate returns a session when it is active at now and refreshes its sliding deadline. | Validate
// 在会话于 now 时刻活跃时返回它，并刷新滑动期限。
func (m *SessionManager) Validate(ctx context.Context, id string) (*Session, error) {
	now := m.now()
	session, err := m.store.GetSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if session.RevokedAt != nil {
		return nil, errs.Detail(ErrSessionRevoked, "id %[1]q | ID %[1]q", id)
	}
	if !session.Active(now) {
		return nil, errs.Detail(ErrSessionExpired, "id %[1]q | ID %[1]q", id)
	}
	session.LastSeenAt = now
	if m.config.IdleTimeout > 0 {
		session.IdleExpiresAt = now.Add(m.config.IdleTimeout)
	}
	if now.Sub(session.UpdatedAt) >= m.config.TouchInterval {
		session.UpdatedAt = now
		if err := m.store.UpdateSession(ctx, session); err != nil {
			return nil, err
		}
	}
	return session, nil
}

// ValidateRequest validates the session cookie of r. | ValidateRequest 校验 r 的会话 Cookie。
func (m *SessionManager) ValidateRequest(ctx context.Context, r *http.Request) (*Session, error) {
	if r == nil {
		return nil, ErrSessionNotFound
	}
	cookie, err := r.Cookie(m.config.CookieName)
	if err != nil || cookie.Value == "" {
		return nil, ErrSessionNotFound
	}
	return m.Validate(ctx, cookie.Value)
}

// Rotate replaces oldID with a fresh session identifier, preserving the user and attributes. | Rotate
// 用新的会话标识替换 oldID，保留用户与属性。
//
// Callers must set the returned cookie; the old identifier is revoked immediately. | 调用方必须设置
// 返回的 Cookie；旧标识立即被撤销。
func (m *SessionManager) Rotate(ctx context.Context, oldID string) (*Session, error) {
	now := m.now()
	old, err := m.store.GetSession(ctx, oldID)
	if err != nil {
		return nil, err
	}
	if old.RevokedAt != nil || !old.Active(now) {
		return nil, ErrSessionExpired
	}
	newID, err := RandomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := RandomToken(32)
	if err != nil {
		return nil, err
	}
	revoked := now
	old.RevokedAt = &revoked
	old.RevokeReason = "rotated"
	old.UpdatedAt = now
	if err := m.store.UpdateSession(ctx, old); err != nil {
		return nil, err
	}
	rotated := old.Clone()
	rotated.ID = newID
	rotated.CSRFSecret = csrf
	rotated.CreatedAt = now
	rotated.UpdatedAt = now
	rotated.LastSeenAt = now
	rotated.RevokedAt = nil
	rotated.RevokeReason = ""
	rotated.ExpiresAt = now.Add(m.config.AbsoluteTimeout)
	if m.config.IdleTimeout > 0 {
		rotated.IdleExpiresAt = now.Add(m.config.IdleTimeout)
	}
	if err := m.store.CreateSession(ctx, rotated); err != nil {
		return nil, err
	}
	return rotated, nil
}

// Revoke marks a session revoked. | Revoke 标记会话已撤销。
func (m *SessionManager) Revoke(ctx context.Context, id, reason string) error {
	session, err := m.store.GetSession(ctx, id)
	if err != nil {
		return err
	}
	if session.RevokedAt != nil {
		return nil
	}
	now := m.now()
	session.RevokedAt = &now
	session.RevokeReason = reason
	session.UpdatedAt = now
	return m.store.UpdateSession(ctx, session)
}

// RevokeUser revokes every session of a user. | RevokeUser 撤销用户的全部会话。
func (m *SessionManager) RevokeUser(ctx context.Context, userID, reason string) (int, error) {
	sessions, err := m.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	now := m.now()
	n := 0
	for _, session := range sessions {
		if session.RevokedAt != nil {
			continue
		}
		session.RevokedAt = &now
		session.RevokeReason = reason
		session.UpdatedAt = now
		if err := m.store.UpdateSession(ctx, session); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// List returns every session of a user. | List 返回用户的全部会话。
func (m *SessionManager) List(ctx context.Context, userID string) ([]*Session, error) {
	return m.store.ListSessionsByUser(ctx, userID)
}

// Cookie returns the Set-Cookie value for session. | Cookie 返回 session 的 Set-Cookie 值。
func (m *SessionManager) Cookie(session *Session) *http.Cookie {
	if session == nil {
		return m.ClearCookie()
	}
	maxAge := int(session.ExpiresAt.Sub(m.now()).Seconds())
	if maxAge <= 0 {
		maxAge = -1
	}
	return &http.Cookie{
		Name:     m.config.CookieName,
		Value:    session.ID,
		Path:     m.config.Path,
		Domain:   m.config.Domain,
		Expires:  session.ExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: m.config.HTTPOnly,
		Secure:   m.config.Secure,
		SameSite: m.config.SameSite,
	}
}

// ClearCookie returns an expired cookie that removes the session from the browser. | ClearCookie 返回使浏览器删除会话的过期 Cookie。
func (m *SessionManager) ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     m.config.CookieName,
		Value:    "",
		Path:     m.config.Path,
		Domain:   m.config.Domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
		HttpOnly: m.config.HTTPOnly,
		Secure:   m.config.Secure,
		SameSite: m.config.SameSite,
	}
}

// CSRFToken returns the synchronizer token of session. | CSRFToken 返回 session 的同步器令牌。
func (m *SessionManager) CSRFToken(session *Session) string {
	if session == nil {
		return ""
	}
	return session.CSRFSecret
}

// VerifyCSRF reports whether token matches the session CSRF secret in constant time. | VerifyCSRF 以常量时间报告 token 是否匹配会话 CSRF 密钥。
func (m *SessionManager) VerifyCSRF(session *Session, token string) bool {
	if session == nil || session.CSRFSecret == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(session.CSRFSecret), []byte(token)) == 1
}

// csrfFromRequest extracts the CSRF token from the configured header or form field. | csrfFromRequest 从配置的请求头或表单字段提取 CSRF 令牌。
func (m *SessionManager) csrfFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if token := r.Header.Get(m.config.CSRFHeader); token != "" {
		return token
	}
	if r.Form != nil {
		return r.Form.Get(m.config.CSRFParam)
	}
	if err := r.ParseForm(); err == nil {
		return r.Form.Get(m.config.CSRFParam)
	}
	return ""
}

// Principal returns the principal for a validated session. | Principal 返回已校验会话的主体。
func (m *SessionManager) Principal(ctx context.Context, session *Session) (*Principal, error) {
	user, err := m.users.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if err := user.CanLogin(m.now()); err != nil {
		return nil, err
	}
	if m.buildPrincipal != nil {
		return m.buildPrincipal(ctx, user, session)
	}
	return DefaultPrincipal(user, session), nil
}

// DefaultPrincipal projects user and session into a principal. | DefaultPrincipal 把用户与会话投影为主体。
func DefaultPrincipal(user *User, session *Session) *Principal {
	if user == nil {
		return nil
	}
	p := &Principal{
		Subject:       user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Username:      user.Username,
		DisplayName:   user.DisplayName,
	}
	if session != nil {
		p.AuthTime = session.CreatedAt
		p.SessionID = session.ID
		p.AMR = append([]string(nil), session.AMR...)
		p.ACR = session.ACR
		p.ClientID = session.ClientID
		p.ExpiresAt = session.ExpiresAt
		p.IssuedAt = session.CreatedAt
	}
	return p
}

// requestIP extracts the direct peer address of r without trusting forwarding headers. | requestIP
// 提取 r 的直接对端地址，不信任转发头。
func requestIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// SessionMiddlewareOptions configures the session middleware. | SessionMiddlewareOptions 配置会话中间件。
type SessionMiddlewareOptions struct {
	// RequireSession rejects anonymous requests with 401 when true. | RequireSession 为 true 时以 401 拒绝匿名请求。
	RequireSession bool
	// EnforceCSRF rejects unsafe methods without a matching CSRF token. | EnforceCSRF 拒绝缺少匹配 CSRF 令牌的非安全方法。
	EnforceCSRF bool
	// ErrorHandler renders failures for ydx/router. | ErrorHandler 为 ydx/router 渲染失败响应。
	ErrorHandler func(c *router.Ctx, err error)
}

// Middleware returns a native ydx/router middleware that resolves the session cookie. | Middleware
// 返回解析会话 Cookie 的原生 ydx/router 中间件。
//
// The principal is stored in the request context and in the router context under a private key, so
// handlers can use PrincipalFromRequest or PrincipalFromCtx. | 主体存入请求上下文，并以私有键存入
// 路由上下文，处理器可用 PrincipalFromRequest 或 PrincipalFromCtx 读取。
func (m *SessionManager) Middleware(opts SessionMiddlewareOptions) router.Middleware {
	return func(c *router.Ctx) {
		session, err := m.ValidateRequest(c.Request.Context(), c.Request)
		if err != nil {
			if !opts.RequireSession && (err == ErrSessionNotFound || errorsIsSessionExpired(err)) {
				c.Next()
				return
			}
			m.failRouter(c, opts, err)
			return
		}
		if opts.EnforceCSRF && isUnsafeMethod(c.Request.Method) && !m.VerifyCSRF(session, m.csrfFromRequest(c.Request)) {
			m.failRouter(c, opts, ErrForbidden)
			return
		}
		principal, err := m.Principal(c.Request.Context(), session)
		if err != nil {
			m.failRouter(c, opts, err)
			return
		}
		c.Request = c.Request.WithContext(ContextWithPrincipal(c.Request.Context(), principal))
		c.Set(sessionContextKey, session)
		c.Set(principalContextKey, principal)
		c.Next()
	}
}

// HTTPMiddleware returns the standard net/http middleware equivalent of Middleware. | HTTPMiddleware
// 返回与 Middleware 等价的标准 net/http 中间件。
func (m *SessionManager) HTTPMiddleware(opts SessionMiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := m.ValidateRequest(r.Context(), r)
			if err != nil {
				if !opts.RequireSession && (err == ErrSessionNotFound || errorsIsSessionExpired(err)) {
					next.ServeHTTP(w, r)
					return
				}
				writeHTTPError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if opts.EnforceCSRF && isUnsafeMethod(r.Method) && !m.VerifyCSRF(session, m.csrfFromRequest(r)) {
				writeHTTPError(w, http.StatusForbidden, "forbidden")
				return
			}
			principal, err := m.Principal(r.Context(), session)
			if err != nil {
				writeHTTPError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithPrincipal(r.Context(), principal)))
		})
	}
}

// failRouter renders a middleware failure. | failRouter 渲染中间件失败。
func (m *SessionManager) failRouter(c *router.Ctx, opts SessionMiddlewareOptions, err error) {
	if opts.ErrorHandler != nil {
		opts.ErrorHandler(c, err)
		return
	}
	status := http.StatusUnauthorized
	switch {
	case errors.Is(err, ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, ErrAccountDisabled), errors.Is(err, ErrAccountPending):
		status = http.StatusUnauthorized
	}
	_ = c.JSON(status, map[string]string{"error": http.StatusText(status)})
}

// errorsIsSessionExpired reports whether err is an expiry or revocation failure. | errorsIsSessionExpired 报告 err 是否为过期或撤销失败。
func errorsIsSessionExpired(err error) bool {
	return errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionRevoked) || errors.Is(err, ErrSessionNotFound)
}

// isUnsafeMethod reports whether method changes state. | isUnsafeMethod 报告 method 是否改变状态。
func isUnsafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// sessionContextKey and principalContextKey are the router context keys used by Middleware. | sessionContextKey
// 与 principalContextKey 是 Middleware 使用的路由上下文键。
const (
	sessionContextKey   = "auth.session"
	principalContextKey = "auth.principal"
)

// PrincipalFromCtx returns the principal stored by Middleware. | PrincipalFromCtx 返回 Middleware 存储的主体。
func PrincipalFromCtx(c *router.Ctx) (*Principal, bool) {
	if c == nil {
		return nil, false
	}
	if value, ok := c.Get(principalContextKey); ok {
		if p, ok := value.(*Principal); ok && p != nil {
			return p, true
		}
	}
	return PrincipalFromRequest(c.Request)
}

// SessionFromCtx returns the session stored by Middleware. | SessionFromCtx 返回 Middleware 存储的会话。
func SessionFromCtx(c *router.Ctx) (*Session, bool) {
	if c == nil {
		return nil, false
	}
	value, ok := c.Get(sessionContextKey)
	if !ok {
		return nil, false
	}
	session, ok := value.(*Session)
	return session, ok && session != nil
}

// CSRFHash returns a stable HMAC of value under key; it is useful for binding CSRF tokens to a
// session without storing the raw secret in cookies. | CSRFHash 返回 key 下 value 的稳定 HMAC；
// 用于在不把原始密钥写入 Cookie 的前提下把 CSRF 令牌绑定到会话。
func CSRFHash(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(value))
	return hexLower(mac.Sum(nil))
}

// hexLower encodes b as lowercase hexadecimal without importing encoding/hex callers might not
// expect. | hexLower 把 b 编码为小写十六进制。
func hexLower(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

// writeHTTPError writes a compact JSON error body. | writeHTTPError 写入紧凑 JSON 错误体。
func writeHTTPError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + message + `"}`))
}
