package cas

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// CookieConfig configures the TGC cookie that carries the Ticket Granting Ticket identifier. |
// CookieConfig 配置携带票据授予票据标识的 TGC Cookie。
type CookieConfig struct {
	// Name is the cookie name; it defaults to "TGC". | Name 是 Cookie 名；默认 "TGC"。
	Name string
	// Path scopes the cookie; it defaults to "/". | Path 限定 Cookie 范围；默认 "/"。
	Path string
	// Domain scopes the cookie to a parent domain; empty uses the request host. | Domain 把 Cookie 限定到父域；空值使用请求主机。
	Domain string
	// Secure marks the cookie HTTPS-only. Production deployments must set it. | Secure 标记 Cookie 仅 HTTPS。生产部署必须设置。
	Secure bool
	// SameSite controls cross-site sending; the zero value selects Lax. | SameSite 控制跨站发送；零值选择 Lax。
	SameSite http.SameSite
}

// DefaultCookieConfig returns the conservative TGC cookie configuration. | DefaultCookieConfig
// 返回保守的 TGC Cookie 配置。
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     CookieNameTGC,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
}

// ErrorHandler renders non-protocol failures such as a rejected login form. Protocol endpoints
// (validate, serviceValidate, proxyValidate, proxy and samlValidate) always answer with their
// protocol body instead. Implementations must not write ticket identifiers or credentials. |
// ErrorHandler 渲染登录表单被拒绝等非协议失败。协议端点（validate、serviceValidate、
// proxyValidate、proxy 与 samlValidate）始终以协议正文回答。实现不得写入票据标识或凭据。
type ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, err error)

// LoginPageData is the view model passed to a LoginPageRenderer. | LoginPageData 是传递给
// LoginPageRenderer 的视图模型。
type LoginPageData struct {
	// Principal is the authenticated principal when LoggedIn is true. | Principal 在 LoggedIn 为 true 时是已认证主体。
	Principal *auth.Principal
	// Action is the login form target; empty means the current request path. | Action 是登录表单目标；空值表示当前请求路径。
	Action string
	// Service is the service URL that receives the ticket. | Service 是接收票据的服务 URL。
	Service string
	// Username is echoed after a failed attempt. | Username 在失败尝试后回显。
	Username string
	// Error is a human-readable failure summary. | Error 是人类可读的失败摘要。
	Error string
	// CSRF is the token to embed as the csrf_token form field. | CSRF 是作为 csrf_token 表单字段嵌入的令牌。
	CSRF string
	// Issuer is the configured CAS issuer. | Issuer 是配置的 CAS 签发方。
	Issuer string
	// Status is the HTTP status the renderer should send. | Status 是渲染器应发送的 HTTP 状态。
	Status int
	// Renew reports a forced re-authentication request. | Renew 表示强制重新认证请求。
	Renew bool
	// Gateway reports a gateway request, which never shows the login form. | Gateway 表示 gateway
	// 请求，它绝不显示登录表单。
	Gateway bool
	// Warn reports the warn parameter of the CAS protocol. | Warn 表示 CAS 协议的 warn 参数。
	Warn bool
	// RememberMe reports a persistent login request. | RememberMe 表示持久登录请求。
	RememberMe bool
	// LoggedIn reports an existing authenticated session without a service. | LoggedIn 表示存在已认证会话但没有服务。
	LoggedIn bool
}

// LoginPageRenderer renders the login and signed-in pages. | LoginPageRenderer 渲染登录与已登录页面。
type LoginPageRenderer func(w http.ResponseWriter, data *LoginPageData)

// CSRFProtector guards the login POST against cross-site request forgery. | CSRFProtector 保护登录
// POST 免受跨站请求伪造。
//
// Token is called while rendering the form; Verify is called before credentials are read. The
// default is nil, which disables the check for deployments that rely on SameSite cookies. | 渲染表单
// 时调用 Token；读取凭据前调用 Verify。默认值为 nil，适用于依赖 SameSite Cookie 的部署。
type CSRFProtector interface {
	// Token returns the token for r. | Token 返回 r 的令牌。
	Token(r *http.Request) string
	// Verify reports whether r carries a valid token. | Verify 报告 r 是否携带有效令牌。
	Verify(r *http.Request) bool
}

// ServerConfig configures a CAS server. | ServerConfig 配置 CAS 服务端。
type ServerConfig struct {
	// ServiceRegistry restricts service URLs. Nil allows every non-empty URL; production
	// deployments should always configure it. | ServiceRegistry 限制服务 URL。空值允许每个非空
	// URL；生产部署应始终配置它。
	ServiceRegistry ServiceRegistry
	// TicketStore persists tickets. Nil creates an owned MemoryTicketStore with a janitor that
	// Server.Close stops. | TicketStore 持久化票据。空值创建由 Server 持有的 MemoryTicketStore，
	// 其清理器由 Server.Close 停止。
	TicketStore TicketStore
	// SessionRegistry records validated service sessions for back-channel Single Logout. Nil creates
	// an owned MemoryServiceSessionRegistry when TicketStore is also nil; with a caller-supplied
	// TicketStore, nil disables session tracking and back-channel logout, and local TGT/ST/PT
	// revocation still works. A multi-node deployment needs a shared implementation. | SessionRegistry
	// 记录已校验的服务会话以支持后端单点登出。TicketStore 也为空时，空值创建由 Server 持有的
	// MemoryServiceSessionRegistry；调用方提供 TicketStore 时，空值禁用会话跟踪与后端登出，本地
	// TGT/ST/PT 撤销仍然有效。多节点部署需要共享实现。
	SessionRegistry ServiceSessionRegistry
	// Authenticator verifies login credentials and is required. | Authenticator 校验登录凭据，必填。
	Authenticator Authenticator
	// PrincipalProvider optionally refreshes principals on every validation. | PrincipalProvider
	// 可选地在每次校验时刷新主体。
	PrincipalProvider PrincipalProvider
	// CSRFProtector guards the login POST. | CSRFProtector 保护登录 POST。
	CSRFProtector CSRFProtector
	// Clock overrides the time source for deterministic tests. | Clock 为确定性测试替换时间源。
	Clock func() time.Time
	// Logger receives operational warnings. It never receives ticket identifiers. | Logger 接收
	// 运行告警。它绝不会收到票据标识。
	Logger *log.Logger
	// ErrorHandler renders non-protocol failures. | ErrorHandler 渲染非协议失败。
	ErrorHandler ErrorHandler
	// LoginPageRenderer replaces the built-in login and signed-in pages. | LoginPageRenderer
	// 替换内置登录与已登录页面。
	LoginPageRenderer LoginPageRenderer
	// HTTPClient performs PGT callbacks and back-channel logout deliveries. Nil uses a client with
	// a 10 second timeout that refuses redirects, so an HTTPS callback cannot be downgraded to plain
	// HTTP. | HTTPClient 执行 PGT 回调与后端登出投递。空值使用超时 10 秒且拒绝重定向的客户端，避免
	// HTTPS 回调被降级为明文 HTTP。
	HTTPClient *http.Client
	// LogoutObserver receives every back-channel logout delivery result. It is advisory: a failed
	// delivery is never returned to the logging-out user. | LogoutObserver 接收每个后端登出投递结果。
	// 它只用于观测：投递失败绝不会返回给执行登出的用户。
	LogoutObserver LogoutObserver
	// SAMLResponseBuilder replaces the default unsigned SAML 1.1 response. | SAMLResponseBuilder
	// 替换默认的不签名 SAML 1.1 响应。
	SAMLResponseBuilder SAMLResponseBuilder
	// Issuer identifies the CAS server, for example "https://cas.example.com". It is used as the
	// SAML assertion issuer and as the default BaseURL. | Issuer 标识 CAS 服务端，例如
	// "https://cas.example.com"。它用作 SAML 断言签发方与默认 BaseURL。
	Issuer string
	// BaseURL is the public base URL used to build absolute links. It defaults to Issuer. | BaseURL
	// 是用于构建绝对链接的公开基础 URL。默认取 Issuer。
	BaseURL string
	// LoginURL overrides the login form action. Empty uses the request path, which keeps the
	// server correct under any mount prefix. | LoginURL 覆盖登录表单 action。空值使用请求路径，使
	// 服务端在任意挂载前缀下都正确。
	LoginURL string
	// CookieConfig configures the TGC cookie. | CookieConfig 配置 TGC Cookie。
	CookieConfig CookieConfig
	// LogoutCallbackTimeout bounds one back-channel logout POST; zero uses
	// DefaultLogoutCallbackTimeout. | LogoutCallbackTimeout 限定单次后端登出 POST；零值使用
	// DefaultLogoutCallbackTimeout。
	LogoutCallbackTimeout time.Duration
	// TGTTimeout is the Ticket Granting Ticket lifetime; zero uses DefaultTGTTimeout. | TGTTimeout
	// 是票据授予票据寿命；零值使用 DefaultTGTTimeout。
	TGTTimeout time.Duration
	// ServiceTicketTimeout is the ST lifetime; zero uses DefaultServiceTicketTimeout. |
	// ServiceTicketTimeout 是 ST 寿命；零值使用 DefaultServiceTicketTimeout。
	ServiceTicketTimeout time.Duration
	// ProxyGrantingTicketTimeout is the PGT lifetime; zero uses DefaultProxyGrantingTicketTimeout. |
	// ProxyGrantingTicketTimeout 是 PGT 寿命；零值使用 DefaultProxyGrantingTicketTimeout。
	ProxyGrantingTicketTimeout time.Duration
	// ProxyTicketTimeout is the PT lifetime; zero uses DefaultProxyTicketTimeout. | ProxyTicketTimeout
	// 是 PT 寿命；零值使用 DefaultProxyTicketTimeout。
	ProxyTicketTimeout time.Duration
	// ClockSkew tolerates small clock differences when checking ticket expiry. | ClockSkew 在检查
	// 票据过期时容忍少量时钟差异。
	ClockSkew time.Duration
	// AllowInsecurePGTCallback permits http:// pgtUrl callbacks. It exists for local tests and
	// must not be enabled in production. | AllowInsecurePGTCallback 允许 http:// 的 pgtUrl 回调。
	// 它用于本地测试，不得在生产启用。
	AllowInsecurePGTCallback bool
}

// Server is a CAS 1.0/2.0/3.0 authentication server. | Server 是 CAS 1.0/2.0/3.0 认证服务器。
//
// A Server is safe for concurrent use after construction. Every exported handler method has the
// router.HandlerFuncRaw signature and is also a valid net/http handler. | Server 构造后可并发安全
// 使用。每个导出的处理器方法都具有 router.HandlerFuncRaw 签名，同时也是合法的 net/http 处理器。
type Server struct {
	store         TicketStore
	sessions      ServiceSessionRegistry
	ownedStore    *MemoryTicketStore
	ownedSessions *MemoryServiceSessionRegistry
	now           func() time.Time
	httpClient    *http.Client
	config        ServerConfig
}

// NewServer validates config and returns a CAS server. | NewServer 校验 config 并返回 CAS 服务端。
func NewServer(config ServerConfig) (*Server, error) {
	if config.Authenticator == nil {
		return nil, errs.Detail(ErrInvalidConfig, "authenticator is required | authenticator 必填")
	}
	if config.Issuer == "" && config.BaseURL == "" {
		// An issuer is not strictly required for the core protocol, but SAML assertions and any
		// absolute links need a stable identity. | 核心协议不强制要求签发方，但 SAML 断言与任何绝对
		// 链接都需要稳定标识。
		return nil, errs.Detail(ErrInvalidConfig, "issuer or base URL is required | issuer 或 base URL 必填")
	}
	if config.BaseURL == "" {
		config.BaseURL = config.Issuer
	}
	if config.Issuer == "" {
		config.Issuer = config.BaseURL
	}
	if config.TGTTimeout <= 0 {
		config.TGTTimeout = DefaultTGTTimeout
	}
	if config.ServiceTicketTimeout <= 0 {
		config.ServiceTicketTimeout = DefaultServiceTicketTimeout
	}
	if config.ProxyGrantingTicketTimeout <= 0 {
		config.ProxyGrantingTicketTimeout = DefaultProxyGrantingTicketTimeout
	}
	if config.ProxyTicketTimeout <= 0 {
		config.ProxyTicketTimeout = DefaultProxyTicketTimeout
	}
	if config.ClockSkew < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "clock skew must not be negative | 时钟偏移不得为负")
	}
	cookie := config.CookieConfig
	defaults := DefaultCookieConfig()
	if cookie.Name == "" {
		cookie.Name = defaults.Name
	}
	if cookie.Path == "" {
		cookie.Path = defaults.Path
	}
	if cookie.SameSite == 0 {
		cookie.SameSite = http.SameSiteLaxMode
	}
	if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
		return nil, errs.Detail(ErrInvalidConfig, "SameSite=None requires Secure | SameSite=None 需要 Secure")
	}
	// HttpOnly is not configurable: a TGC must never be readable from script. | HttpOnly 不可配置：
	// TGC 绝不能从脚本读取。
	config.CookieConfig = cookie
	server := &Server{
		config: config,
		now:    func() time.Time { return auth.Now(config.Clock) },
	}
	if config.TicketStore == nil {
		store := NewMemoryTicketStore()
		store.StartGC(DefaultTicketStoreGCInterval)
		server.store = store
		server.ownedStore = store
	} else {
		server.store = config.TicketStore
	}
	if config.SessionRegistry != nil {
		server.sessions = config.SessionRegistry
	} else if config.TicketStore == nil {
		// The server already owns the in-process ticket state; owning a matching in-memory session
		// registry makes Single Logout work out of the box for the same single-node scope. | 服务端
		// 已持有进程内票据状态；配套持有内存会话注册表，使单点登出在同一单节点范围内开箱即用。
		registry := NewMemoryServiceSessionRegistry()
		registry.StartGC(DefaultServiceSessionGCInterval)
		server.sessions = registry
		server.ownedSessions = registry
	}
	server.httpClient = config.HTTPClient
	if server.httpClient == nil {
		server.httpClient = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return server, nil
}

// Config returns a copy of the normalized server configuration. | Config 返回规范化后的服务端配置副本。
func (s *Server) Config() ServerConfig { return s.config }

// Store returns the ticket store in use. | Store 返回正在使用的票据存储。
func (s *Server) Store() TicketStore { return s.store }

// Sessions returns the service session registry in use, or nil when session tracking is disabled. |
// Sessions 返回正在使用的服务会话注册表；会话跟踪禁用时返回 nil。
func (s *Server) Sessions() ServiceSessionRegistry { return s.sessions }

// Close stops the janitors of owned memory stores. Caller-supplied stores are left untouched. |
// Close 停止自有内存存储的清理器。调用方提供的存储不会被处理。
func (s *Server) Close() error {
	if s.ownedStore != nil {
		s.ownedStore.Stop()
	}
	if s.ownedSessions != nil {
		s.ownedSessions.Stop()
	}
	return nil
}

// EndpointURL returns the absolute URL of a protocol endpoint when Issuer or BaseURL is configured,
// or the prefixed relative path otherwise. | EndpointURL 在配置了 Issuer 或 BaseURL 时返回协议端点的
// 绝对 URL，否则返回带前缀的相对路径。
func (s *Server) EndpointURL(prefix, path string) string {
	relative := normalizePrefix(prefix) + path
	base := strings.TrimRight(s.config.BaseURL, "/")
	if base == "" {
		return relative
	}
	return base + relative
}

// Register mounts every protocol endpoint on r under prefix. | Register 在 prefix 下把全部协议端点挂载到 r。
//
// The prefix may be empty, "cas" or "/cas"; it is normalized to "" or "/cas". | prefix 可以为空、
// "cas" 或 "/cas"，会被规范化为 "" 或 "/cas"。
func (s *Server) Register(r *router.Router, prefix string) {
	if r == nil {
		return
	}
	p := normalizePrefix(prefix)
	r.HandleRaw(http.MethodGet, p+"/login", s.Login)
	r.HandleRaw(http.MethodPost, p+"/login", s.Login)
	r.HandleRaw(http.MethodGet, p+"/logout", s.Logout)
	r.HandleRaw(http.MethodPost, p+"/logout", s.Logout)
	r.HandleRaw(http.MethodGet, p+"/serviceValidate", s.ServiceValidate)
	r.HandleRaw(http.MethodGet, p+"/p3/serviceValidate", s.P3ServiceValidate)
	r.HandleRaw(http.MethodGet, p+"/proxyValidate", s.ProxyValidate)
	r.HandleRaw(http.MethodGet, p+"/p3/proxyValidate", s.P3ProxyValidate)
	r.HandleRaw(http.MethodGet, p+"/proxy", s.Proxy)
	r.HandleRaw(http.MethodGet, p+"/validate", s.Validate)
	r.HandleRaw(http.MethodGet, p+"/samlValidate", s.SAMLValidate)
	r.HandleRaw(http.MethodPost, p+"/samlValidate", s.SAMLValidate)
}

// HTTPHandler returns a net/http multiplexer with every protocol endpoint mounted under prefix. |
// HTTPHandler 返回在 prefix 下挂载全部协议端点的 net/http 多路复用器。
func (s *Server) HTTPHandler(prefix string) http.Handler {
	p := normalizePrefix(prefix)
	mux := http.NewServeMux()
	mux.HandleFunc(p+"/login", s.Login)
	mux.HandleFunc(p+"/logout", s.Logout)
	mux.HandleFunc(p+"/serviceValidate", s.ServiceValidate)
	mux.HandleFunc(p+"/p3/serviceValidate", s.P3ServiceValidate)
	mux.HandleFunc(p+"/proxyValidate", s.ProxyValidate)
	mux.HandleFunc(p+"/p3/proxyValidate", s.P3ProxyValidate)
	mux.HandleFunc(p+"/proxy", s.Proxy)
	mux.HandleFunc(p+"/validate", s.Validate)
	mux.HandleFunc(p+"/samlValidate", s.SAMLValidate)
	return mux
}

// nowTime returns the current UTC time from the configured clock. | nowTime 返回配置时钟的当前 UTC 时间。
func (s *Server) nowTime() time.Time { return auth.Now(s.now) }

// expiryNow returns the time used for expiry checks, moved back by ClockSkew so a slightly slow
// server clock does not reject a fresh ticket. | expiryNow 返回用于过期检查的时间，按 ClockSkew
// 前移，避免稍慢的服务端时钟拒绝新票据。
func (s *Server) expiryNow() time.Time { return s.nowTime().Add(-s.config.ClockSkew) }

// allowsService reports whether service may receive a ticket. | allowsService 报告 service 是否可以接收票据。
func (s *Server) allowsService(ctx context.Context, service string) bool {
	if !validServiceURL(service) {
		return false
	}
	if s.config.ServiceRegistry == nil {
		return true
	}
	return s.config.ServiceRegistry.Allows(ctx, service)
}

// validServiceURL reports whether service is an absolute http or https URL with a host and no
// embedded user information. Restricting the scheme keeps javascript:, data: and protocol-relative
// URLs out of ticket redirects. | validServiceURL 报告 service 是否为带主机、不含内嵌用户信息的
// 绝对 http 或 https URL。限制协议可阻止把 javascript:、data: 与协议相对 URL 用于票据重定向。
func validServiceURL(service string) bool {
	parsed, err := url.Parse(service)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return parsed.Host != "" && parsed.User == nil && (scheme == "http" || scheme == "https")
}

// servicesMatch reports whether requested may validate a ticket bound to bound. | servicesMatch
// 报告 requested 是否可以校验绑定到 bound 的票据。
func (s *Server) servicesMatch(bound, requested string) bool {
	if bound == "" || requested == "" {
		return false
	}
	if s.config.ServiceRegistry == nil {
		return bound == requested
	}
	return s.config.ServiceRegistry.Matches(bound, requested)
}

// principalFor returns the principal that answers a validation for ticket. | principalFor 返回回答
// ticket 校验的主体。
func (s *Server) principalFor(ctx context.Context, ticket *Ticket) (*auth.Principal, error) {
	if s.config.PrincipalProvider != nil && ticket.UserID != "" {
		principal, err := s.config.PrincipalProvider.Principal(ctx, ticket.UserID)
		if err != nil {
			return nil, errs.Wrap(err, ErrPrincipalMissing)
		}
		if principal != nil {
			return principal.Clone(), nil
		}
	}
	if ticket.Principal == nil {
		return nil, errs.Detail(ErrPrincipalMissing, "ticket has no principal snapshot | 票据没有主体快照")
	}
	return ticket.Principal.Clone(), nil
}

// ticketFromRequest returns the valid TGT carried by the TGC cookie. | ticketFromRequest 返回 TGC
// Cookie 携带的有效 TGT。
func (s *Server) ticketFromRequest(r *http.Request) (*Ticket, bool) {
	if r == nil {
		return nil, false
	}
	cookie, err := r.Cookie(s.config.CookieConfig.Name)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	ticket, err := s.store.Get(r.Context(), cookie.Value)
	if err != nil || ticket.Type != TicketTGT {
		return nil, false
	}
	if !ticket.ActiveWithSkew(s.expiryNow(), 0) {
		return nil, false
	}
	return ticket, true
}

// tgcCookie returns the Set-Cookie value for a TGT. | tgcCookie 返回 TGT 的 Set-Cookie 值。
func (s *Server) tgcCookie(tgt *Ticket, rememberMe bool) *http.Cookie {
	cookie := &http.Cookie{
		Name:     s.config.CookieConfig.Name,
		Value:    tgt.ID,
		Path:     s.config.CookieConfig.Path,
		Domain:   s.config.CookieConfig.Domain,
		HttpOnly: true,
		Secure:   s.config.CookieConfig.Secure,
		SameSite: s.config.CookieConfig.SameSite,
	}
	if rememberMe {
		ttl := tgt.ExpiresAt.Sub(s.nowTime())
		if ttl > 0 {
			cookie.Expires = tgt.ExpiresAt
			cookie.MaxAge = int(ttl.Seconds())
		}
	}
	return cookie
}

// clearTGCCookie returns a cookie that removes the TGC from the browser. | clearTGCCookie 返回从浏览器删除 TGC 的 Cookie。
func (s *Server) clearTGCCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.config.CookieConfig.Name,
		Value:    "",
		Path:     s.config.CookieConfig.Path,
		Domain:   s.config.CookieConfig.Domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0).UTC(),
		HttpOnly: true,
		Secure:   s.config.CookieConfig.Secure,
		SameSite: s.config.CookieConfig.SameSite,
	}
}

// destroyTGT removes a TGT and every ticket derived from it. | destroyTGT 删除 TGT 及其派生的全部票据。
// destroyTGT removes a TGT family and its service sessions, returning the removed sessions so the
// caller can send back-channel logout requests. | destroyTGT 删除 TGT 族及其服务会话，并返回被删除的
// 会话，供调用方发送后端登出请求。
func (s *Server) destroyTGT(ctx context.Context, tgtID string) []*ServiceSession {
	if tgtID == "" {
		return nil
	}
	var sessions []*ServiceSession
	if s.sessions != nil {
		removed, err := s.sessions.DeleteByTGT(ctx, tgtID)
		if err != nil {
			s.logWarn("cas: service session cleanup failed | cas：服务会话清理失败", err)
		} else {
			sessions = removed
		}
	}
	if _, err := s.store.DeleteByRootTGT(ctx, tgtID); err != nil && s.config.Logger != nil {
		s.config.Logger.Warn("cas: ticket cleanup failed | cas：票据清理失败", log.Err(err))
	}
	return sessions
}

// fail renders a non-protocol failure through ErrorHandler or the built-in plain-text response. |
// fail 通过 ErrorHandler 或内置纯文本响应渲染非协议失败。
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, err error) {
	if s.config.ErrorHandler != nil {
		s.config.ErrorHandler(w, r, status, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(http.StatusText(status) + "\n"))
}

// methodAllowed reports whether m is one of the accepted methods and fails otherwise. | methodAllowed
// 报告 m 是否为可接受方法之一，否则写失败响应。
func (s *Server) methodAllowed(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	if r.Method == http.MethodHead {
		for _, method := range methods {
			if method == http.MethodGet {
				return true
			}
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	s.fail(w, r, http.StatusMethodNotAllowed, errs.Detail(ErrInvalidRequest, "method %s is not allowed | 方法 %s 不允许", r.Method, r.Method))
	return false
}

// redirectToService sends a 302 with the ticket query parameter attached to service. | redirectToService
// 发送 302，并把 ticket 查询参数附加到 service。
func (s *Server) redirectToService(w http.ResponseWriter, r *http.Request, service, ticket string) {
	target, err := withTicket(service, ticket)
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// withTicket returns service with its ticket query parameter set to ticket. | withTicket 返回把
// ticket 查询参数设为 ticket 的 service。
func withTicket(service, ticket string) (string, error) {
	parsed, err := url.Parse(service)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidService, "service %[1]q is not a URL | 服务 %[1]q 不是 URL", service)
	}
	if !validServiceURL(service) {
		return "", errs.Detail(ErrInvalidService, "service %[1]q is not an absolute http(s) URL without credentials | 服务 %[1]q 不是不含凭据的绝对 http(s) URL", service)
	}
	query := parsed.Query()
	query.Set("ticket", ticket)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// isAuthFailure reports whether err is one of the account-state login failures. | isAuthFailure
// 报告 err 是否为账号状态类登录失败。
func isAuthFailure(err error) bool {
	return errors.Is(err, auth.ErrInvalidCredentials) ||
		errors.Is(err, auth.ErrAccountLocked) ||
		errors.Is(err, auth.ErrAccountDisabled) ||
		errors.Is(err, auth.ErrAccountPending) ||
		errors.Is(err, auth.ErrMFARequired)
}

// loginErrorMessage maps an authentication failure to a user-facing message. It deliberately never
// reveals whether the account exists. | loginErrorMessage 把认证失败映射为用户可见文案。它刻意
// 从不泄露账号是否存在。
func loginErrorMessage(err error) string {
	switch {
	case errors.Is(err, auth.ErrAccountLocked):
		return "Account is locked | 账号已锁定"
	case errors.Is(err, auth.ErrAccountDisabled):
		return "Account is disabled | 账号已禁用"
	case errors.Is(err, auth.ErrAccountPending):
		return "Account is pending activation | 账号待激活"
	case errors.Is(err, auth.ErrMFARequired):
		return "Multi-factor authentication is not available on this login form | 此登录表单不支持多因素认证"
	default:
		return "Invalid username or password | 用户名或密码错误"
	}
}

// logWarn writes a warning without ticket identifiers or credentials. | logWarn 在不含票据标识或凭据的前提下写告警。
func (s *Server) logWarn(message string, err error) {
	if s.config.Logger == nil {
		return
	}
	s.config.Logger.Warn(message, log.Err(err))
}

// issueTicket mints, saves and returns a ticket of typ. A nil parent starts a new ticket family
// rooted at the new TGT; a non-nil parent inherits the root TGT and proxy chain. | issueTicket
// 签发、保存并返回 typ 类型的票据。parent 为空时以新 TGT 为根开启新票据族；非空时继承根 TGT 与代理链。
func (s *Server) issueTicket(ctx context.Context, typ TicketType, principal *auth.Principal, userID, service string, parent *Ticket, ttl time.Duration, renewal, rememberMe bool) (*Ticket, error) {
	id, err := NewTicketID(typ)
	if err != nil {
		return nil, err
	}
	now := s.nowTime()
	ticket := &Ticket{
		ID:         id,
		Type:       typ,
		UserID:     userID,
		Principal:  principal.Clone(),
		Service:    service,
		Renewal:    renewal,
		RememberMe: rememberMe,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
	}
	if parent != nil {
		ticket.ParentID = parent.ID
		ticket.RootTGTID = parent.RootTGTID
		if ticket.RootTGTID == "" {
			ticket.RootTGTID = parent.ID
		}
		ticket.ProxyChain = append([]string(nil), parent.ProxyChain...)
	} else {
		ticket.RootTGTID = id
	}
	if err := s.store.Save(ctx, ticket); err != nil {
		return nil, errs.Wrap(err, ErrTicketGeneration)
	}
	if (typ == TicketST || typ == TicketPT) && s.sessions != nil {
		s.registerServiceSession(ctx, ticket, parent)
	}
	return ticket, nil
}

// registerServiceSession records the service session behind an ST or PT. The session outlives the
// single-use ticket by following the parent TGT/PGT expiry, so back-channel logout can still reach a
// service long after the ticket was consumed. A registry failure is logged and never fails ticket
// issuance. | registerServiceSession 记录 ST 或 PT 背后的服务会话。会话按父 TGT/PGT 的有效期存活，
// 因此票据被消费很久之后后端登出仍能到达服务。注册表失败只记录日志，绝不会使票据签发失败。
func (s *Server) registerServiceSession(ctx context.Context, ticket *Ticket, parent *Ticket) {
	expiresAt := ticket.ExpiresAt
	if parent != nil && parent.ExpiresAt.After(expiresAt) {
		expiresAt = parent.ExpiresAt
	}
	session := &ServiceSession{
		SessionIndex: ticket.ID,
		TicketID:     ticket.ID,
		TicketType:   ticket.Type,
		User:         userIdentifier(ticket.Principal),
		UserID:       ticket.UserID,
		Service:      ticket.Service,
		TGTID:        ticket.RootTGTID,
		IssuedAt:     ticket.IssuedAt,
		ExpiresAt:    expiresAt,
		Renewal:      ticket.Renewal,
		RememberMe:   ticket.RememberMe,
	}
	if session.User == "" {
		session.User = ticket.UserID
	}
	if err := s.sessions.Register(ctx, session); err != nil {
		s.logWarn("cas: service session registration failed | cas：服务会话注册失败", err)
	}
}
