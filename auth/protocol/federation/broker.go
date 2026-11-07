package federation

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/router"
)

// LoginResult is the successful federated login outcome passed to custom success
// handlers. | LoginResult 是传给自定义成功处理器的联合登录成功结果。
type LoginResult struct {
	// Provider is the registered provider name. | Provider 是注册的提供方名称。
	Provider string
	// Identity is the normalized upstream identity. | Identity 是规范化上游身份。
	Identity *Identity
	// User is the linked or just-in-time provisioned local account. | User 是已关联或即时预配的本地账号。
	User *auth.User
	// Session is the newly created local session. | Session 是新建的本地会话。
	Session *auth.Session
}

// SuccessHandler handles a completed federated login. | SuccessHandler 处理已完成的联合登录。
type SuccessHandler func(w http.ResponseWriter, r *http.Request, result *LoginResult)

// FailureHandler handles a rejected or failed federated login. The error is already
// free of client secrets and raw tokens. | FailureHandler 处理被拒绝或失败的联合登录。错误中已
// 不含客户端密钥或原始令牌。
type FailureHandler func(w http.ResponseWriter, r *http.Request, err error)

// BrokerConfig configures a Broker. | BrokerConfig 配置 Broker。
type BrokerConfig struct {
	// Service is the ydx auth service. | Service 是 ydx auth 服务。
	Service *auth.Service
	// Providers maps route names to providers. | Providers 把路由名称映射到提供方。
	Providers map[string]*Provider
	// StateStore stores authorization state; the default is a MemoryStateStore.
	// StateStore 保存授权 state；默认是 MemoryStateStore。
	StateStore StateStore
	// HTTPClient is the fallback provider HTTP client. | HTTPClient 是提供方 HTTP 回退客户端。
	HTTPClient *http.Client
	// StateTTL is the authorization state lifetime. | StateTTL 是授权 state 有效期。
	StateTTL time.Duration
	// LinkByEmail enables account linking by verified upstream email only.
	// LinkByEmail 仅启用按已验证上游邮箱关联账号。
	LinkByEmail bool
	// SuccessRedirect is the post-login redirect target. | SuccessRedirect 是登录后重定向目标。
	SuccessRedirect string
	// ClientID is recorded on created sessions; the default is "federation".
	// ClientID 记录在新建会话上，默认值为 "federation"。
	ClientID string
	// SuccessHandler overrides the default success redirect. | SuccessHandler 覆盖默认成功重定向。
	SuccessHandler SuccessHandler
	// FailureHandler overrides the default JSON failure response. | FailureHandler 覆盖默认 JSON 失败响应。
	FailureHandler FailureHandler
	// Now overrides the broker clock. | Now 替换代理时钟。
	Now func() time.Time
	// DiscoveryTTL is the default OIDC discovery cache lifetime for providers that do
	// not set their own. Zero disables periodic refresh. | DiscoveryTTL 是未单独配置的
	// 提供方默认 OIDC 发现缓存有效期。零值禁用周期性刷新。
	DiscoveryTTL time.Duration
	// DiscoveryTTLMin and DiscoveryTTLMax clamp the effective discovery cache lifetime.
	// Zero disables the corresponding bound. | DiscoveryTTLMin 与 DiscoveryTTLMax 限制
	// 生效的发现缓存有效期；零值禁用对应边界。
	DiscoveryTTLMin time.Duration
	DiscoveryTTLMax time.Duration
	// DiscoveryJitter randomizes each cache lifetime by +/- this fraction. | DiscoveryJitter
	// 按该比例正负随机化每次缓存有效期。
	DiscoveryJitter float64
	// DiscoveryMaxStale bounds stale fallback after a failed refresh. Zero means one
	// effective TTL; a negative value disables stale fallback. | DiscoveryMaxStale
	// 限制刷新失败后的过期回退。零值表示一个生效 TTL；负值禁用过期回退。
	DiscoveryMaxStale time.Duration
}

// Broker implements the provider-neutral authorization-code login flow and mounts
// both ydx/router and native net/http handlers. Configure exported fields before
// serving requests; concurrent configuration is not supported. | Broker 实现提供方无关的
// 授权码登录流程，并同时挂载 ydx/router 与原生 net/http 处理器。请在开始服务前配置导出字段；
// 不支持并发修改配置。
type Broker struct {
	// Service is the ydx auth service. | Service 是 ydx auth 服务。
	Service *auth.Service
	// Providers maps route names to providers. | Providers 把路由名称映射到提供方。
	Providers map[string]*Provider
	// StateStore stores authorization state. | StateStore 保存授权 state。
	StateStore StateStore
	// HTTPClient is the fallback provider HTTP client. | HTTPClient 是提供方 HTTP 回退客户端。
	HTTPClient *http.Client
	// LinkByEmail enables account linking by verified upstream email only.
	// LinkByEmail 仅启用按已验证上游邮箱关联账号。
	LinkByEmail bool
	// SuccessRedirect is the post-login redirect target. | SuccessRedirect 是登录后重定向目标。
	SuccessRedirect string
	// ClientID is recorded on created sessions. | ClientID 记录在新建会话上。
	ClientID string
	// SuccessHandler overrides the default success redirect. | SuccessHandler 覆盖默认成功重定向。
	SuccessHandler SuccessHandler
	// FailureHandler overrides the default JSON failure response. | FailureHandler 覆盖默认 JSON 失败响应。
	FailureHandler FailureHandler
	// StateTTL is the authorization state lifetime. | StateTTL 是授权 state 有效期。
	StateTTL time.Duration
	// Now overrides the broker clock. | Now 替换代理时钟。
	Now func() time.Time
	// DiscoveryTTL is the default OIDC discovery cache lifetime. | DiscoveryTTL 是默认
	// OIDC 发现缓存有效期。
	DiscoveryTTL time.Duration
	// DiscoveryTTLMin and DiscoveryTTLMax clamp the effective discovery cache lifetime.
	// DiscoveryTTLMin 与 DiscoveryTTLMax 限制生效的发现缓存有效期。
	DiscoveryTTLMin time.Duration
	DiscoveryTTLMax time.Duration
	// DiscoveryJitter randomizes each cache lifetime by +/- this fraction. | DiscoveryJitter
	// 按该比例正负随机化每次缓存有效期。
	DiscoveryJitter float64
	// DiscoveryMaxStale bounds stale fallback after a failed refresh. | DiscoveryMaxStale
	// 限制刷新失败后的过期回退。
	DiscoveryMaxStale time.Duration

	mu       sync.RWMutex
	adapters map[string]ProviderAdapter
}

// NewBroker validates config and returns a broker. | NewBroker 校验配置并返回代理。
func NewBroker(config BrokerConfig) (*Broker, error) {
	if config.Service == nil {
		return nil, errs.Detail(ErrInvalidConfig, "auth service is nil | auth 服务为空")
	}
	if en, zh := discoverySettingsProblem(config.DiscoveryTTL, config.DiscoveryTTLMin, config.DiscoveryTTLMax, config.DiscoveryJitter); en != "" {
		return nil, errs.Detail(ErrInvalidConfig, "broker has invalid discovery settings: %s | 代理的发现配置非法：%s", en, zh)
	}
	ttl := config.StateTTL
	if ttl <= 0 {
		ttl = DefaultStateTTL
	}
	clientID := strings.TrimSpace(config.ClientID)
	if clientID == "" {
		clientID = "federation"
	}
	successRedirect := config.SuccessRedirect
	if successRedirect == "" {
		successRedirect = "/"
	}
	broker := &Broker{
		Service:           config.Service,
		Providers:         make(map[string]*Provider, len(config.Providers)),
		StateStore:        config.StateStore,
		HTTPClient:        config.HTTPClient,
		LinkByEmail:       config.LinkByEmail,
		SuccessRedirect:   successRedirect,
		ClientID:          clientID,
		SuccessHandler:    config.SuccessHandler,
		FailureHandler:    config.FailureHandler,
		StateTTL:          ttl,
		Now:               config.Now,
		DiscoveryTTL:      config.DiscoveryTTL,
		DiscoveryTTLMin:   config.DiscoveryTTLMin,
		DiscoveryTTLMax:   config.DiscoveryTTLMax,
		DiscoveryJitter:   config.DiscoveryJitter,
		DiscoveryMaxStale: config.DiscoveryMaxStale,
		adapters:          make(map[string]ProviderAdapter),
	}
	if broker.Now == nil {
		broker.Now = time.Now
	}
	if broker.StateStore == nil {
		broker.StateStore = NewMemoryStateStore(ttl, WithStateClock(broker.Now))
	}
	if broker.HTTPClient == nil {
		broker.HTTPClient = defaultHTTPClient()
	}
	for name, provider := range config.Providers {
		if err := broker.RegisterProvider(name, provider); err != nil {
			return nil, err
		}
	}
	return broker, nil
}

// RegisterProvider registers or replaces a provider under name. The provider Name is
// set to name so sessions and identity links use the route name consistently. | RegisterProvider
// 在 name 下注册或替换提供方。提供方 Name 会被设为 name，使会话与身份关联始终使用路由名称。
func (b *Broker) RegisterProvider(name string, provider *Provider) error {
	if b == nil {
		return errs.Detail(ErrInvalidConfig, "broker is nil | 代理为空")
	}
	if provider == nil {
		return errs.Detail(ErrProviderConfig, "provider is nil | 提供方为空")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = strings.TrimSpace(provider.Name)
	}
	if name == "" {
		return errs.Detail(ErrProviderConfig, "provider name is empty | 提供方名称为空")
	}
	provider.Name = name
	if err := provider.Validate(); err != nil {
		return err
	}
	policy := discoveryPolicyFor(b, provider)
	if en, zh := policy.problem(); en != "" {
		return errs.Detail(ErrProviderConfig, "provider %s has invalid discovery settings: %s | 提供方 %s 的发现配置非法：%s", name, en, name, zh)
	}
	if policy.enabled() && provider.UseOIDC && strings.TrimSpace(provider.Issuer) == "" && provider.Adapter == nil {
		return errs.Detail(ErrProviderConfig, "provider %s needs an issuer to refresh discovery | 提供方 %s 需要 issuer 才能刷新发现", name, name)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Providers == nil {
		b.Providers = make(map[string]*Provider)
	}
	if b.adapters == nil {
		b.adapters = make(map[string]ProviderAdapter)
	}
	b.Providers[name] = provider
	delete(b.adapters, name)
	return nil
}

// LoginHandler returns a net/http handler for one provider's login redirect. | LoginHandler
// 返回单个提供方登录重定向的 net/http 处理器。
func (b *Broker) LoginHandler(provider string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		if err := b.login(w, r, provider); err != nil {
			b.fail(w, r, provider, err)
		}
	})
}

// CallbackHandler returns a net/http handler for one provider's callback. | CallbackHandler
// 返回单个提供方回调的 net/http 处理器。
func (b *Broker) CallbackHandler(provider string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
			return
		}
		if err := b.callback(w, r, provider); err != nil {
			b.fail(w, r, provider, err)
		}
	})
}

// Login handles a ydx/router login request with a :provider path parameter. | Login
// 处理带 :provider 路径参数的 ydx/router 登录请求。
func (b *Broker) Login(c *router.Ctx) {
	if c == nil || c.Request == nil {
		return
	}
	provider := c.Param("provider")
	if err := b.login(c.Writer, c.Request, provider); err != nil {
		b.fail(c.Writer, c.Request, provider, err)
	}
}

// Callback handles a ydx/router callback request with a :provider path parameter.
// Callback 处理带 :provider 路径参数的 ydx/router 回调请求。
func (b *Broker) Callback(c *router.Ctx) {
	if c == nil || c.Request == nil {
		return
	}
	provider := c.Param("provider")
	if err := b.callback(c.Writer, c.Request, provider); err != nil {
		b.fail(c.Writer, c.Request, provider, err)
	}
}

// Register mounts {prefix}/:provider/login and {prefix}/:provider/callback on a
// ydx/router router. Both GET and POST callbacks are registered for providers such
// as Apple that use response_mode=form_post. | Register 在 ydx/router 路由上挂载
// / {prefix}/:provider/login 与 {prefix}/:provider/callback。为 Apple 等使用
// response_mode=form_post 的提供方同时注册 GET 与 POST 回调。
func (b *Broker) Register(r *router.Router, prefix string) {
	if r == nil || b == nil {
		return
	}
	base := normalizePrefix(prefix)
	r.GET(base+"/:provider/login", b.Login)
	r.GET(base+"/:provider/callback", b.Callback)
	r.POST(base+"/:provider/callback", b.Callback)
}

// HTTPHandler returns a native net/http handler mounting the same routes as
// Register under prefix. | HTTPHandler 返回在 prefix 下挂载与 Register 相同路由的原生 net/http 处理器。
func (b *Broker) HTTPHandler(prefix string) http.Handler {
	base := normalizePrefix(prefix)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider, action, ok := matchHTTPRoute(base, r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch action {
		case "login":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				methodNotAllowed(w, http.MethodGet)
				return
			}
			if err := b.login(w, r, provider); err != nil {
				b.fail(w, r, provider, err)
			}
		case "callback":
			if r.Method != http.MethodGet && r.Method != http.MethodPost {
				methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
				return
			}
			if err := b.callback(w, r, provider); err != nil {
				b.fail(w, r, provider, err)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

// login creates state and redirects to the provider authorization endpoint. | login
// 创建 state 并重定向到提供方授权端点。
func (b *Broker) login(w http.ResponseWriter, r *http.Request, providerName string) error {
	providerName = strings.TrimSpace(providerName)
	if providerName == "" {
		return errs.Detail(ErrProviderNotFound, "provider name is empty | 提供方名称为空")
	}
	provider, adapter, err := b.adapter(providerName)
	if err != nil {
		return err
	}
	if provider.RedirectURL == "" {
		return errs.Detail(ErrProviderConfig, "provider %s has no redirect URL | 提供方 %s 缺少重定向 URL", providerName, providerName)
	}
	if b.StateStore == nil {
		return errs.Detail(ErrInvalidConfig, "state store is nil | state 存储为空")
	}
	state, err := auth.RandomToken(32)
	if err != nil {
		return errs.Detail(ErrInvalidRequest, "cannot generate state | 无法生成 state")
	}
	verifier := ""
	if provider.PKCE {
		verifier, err = oauth2.GenerateCodeVerifier()
		if err != nil {
			return errs.Detail(ErrInvalidRequest, "cannot generate PKCE verifier | 无法生成 PKCE verifier")
		}
	}
	nonce := ""
	if provider.Nonce {
		nonce, err = auth.RandomToken(32)
		if err != nil {
			return errs.Detail(ErrInvalidRequest, "cannot generate nonce | 无法生成 nonce")
		}
	}
	now := b.now()
	record := &StateRecord{
		State:       state,
		Provider:    providerName,
		Nonce:       nonce,
		Verifier:    verifier,
		RedirectURL: provider.RedirectURL,
		CreatedAt:   now,
		ExpiresAt:   now.Add(b.stateTTL()),
	}
	if err := b.StateStore.Save(r.Context(), record); err != nil {
		return err
	}
	target, err := adapter.AuthCodeURL(state, nonce, verifier)
	if err != nil {
		return errs.Wrap(err, ErrProviderConfig)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

// callback validates state, exchanges the code, links or provisions a user and creates
// a local session. | callback 校验 state、兑换授权码、关联或预配用户并创建本地会话。
func (b *Broker) callback(w http.ResponseWriter, r *http.Request, providerName string) error {
	providerName = strings.TrimSpace(providerName)
	if providerName == "" {
		return errs.Detail(ErrProviderNotFound, "provider name is empty | 提供方名称为空")
	}
	provider, adapter, err := b.adapter(providerName)
	if err != nil {
		return err
	}
	values, err := callbackValues(w, r)
	if err != nil {
		return err
	}
	providerError := values.Get("error")
	state := values.Get("state")
	if state == "" {
		if providerError != "" {
			return providerDeniedError(providerError)
		}
		return ErrStateMismatch
	}
	if b.StateStore == nil {
		return errs.Detail(ErrInvalidConfig, "state store is nil | state 存储为空")
	}
	record, err := b.StateStore.Consume(r.Context(), state)
	if err != nil {
		return err
	}
	if record == nil || subtle.ConstantTimeCompare([]byte(record.Provider), []byte(providerName)) != 1 {
		return ErrStateMismatch
	}
	if providerError != "" {
		return providerDeniedError(providerError)
	}
	code := values.Get("code")
	if code == "" {
		return ErrMissingCode
	}
	token, err := adapter.Exchange(r.Context(), code, record.Verifier)
	if err != nil {
		return err
	}
	if err := verifyNonce(provider, record, token); err != nil {
		return err
	}
	identity, err := adapter.UserInfo(r.Context(), token)
	if err != nil {
		return err
	}
	if identity == nil {
		return errs.Detail(ErrUserInfo, "provider %s returned an empty identity | 提供方 %s 返回空身份", providerName, providerName)
	}
	identity.Provider = providerName
	if identity.Subject == "" {
		return errs.Detail(ErrUserInfo, "provider %s identity has no subject | 提供方 %s 身份缺少主体", providerName, providerName)
	}
	localIdentity := toAuthIdentity(identity)
	user, err := b.Service.EnsureUserFromIdentity(r.Context(), localIdentity, b.LinkByEmail)
	if err != nil {
		if errors.Is(err, auth.ErrIdentityExists) || errors.Is(err, auth.ErrUserExists) || errors.Is(err, auth.ErrConflict) {
			return errs.Wrap(err, ErrAccountLinkConflict)
		}
		return err
	}
	if err := user.CanLogin(b.now()); err != nil {
		return err
	}
	clientID := b.ClientID
	if strings.TrimSpace(clientID) == "" {
		clientID = "federation"
	}
	session, err := b.Service.Sessions().Create(r.Context(), user.ID, clientID, r, []string{"federated", providerName}, "")
	if err != nil {
		return err
	}
	http.SetCookie(w, b.Service.Sessions().Cookie(session))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	b.Service.Audit(r.Context(), &auth.AuditEvent{
		Type:      "federation.login.succeeded",
		ActorID:   user.ID,
		UserID:    user.ID,
		SessionID: session.ID,
		ClientID:  clientID,
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Outcome:   "success",
		Detail:    map[string]string{"provider": providerName},
		At:        b.now(),
	})
	result := &LoginResult{Provider: providerName, Identity: identity, User: user, Session: session}
	if b.SuccessHandler != nil {
		b.SuccessHandler(w, r, result)
		return nil
	}
	target := b.SuccessRedirect
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

// adapter returns a provider and its cached adapter. | adapter 返回提供方及其缓存适配器。
func (b *Broker) adapter(name string) (*Provider, ProviderAdapter, error) {
	b.mu.RLock()
	provider := b.Providers[name]
	cached := b.adapters[name]
	b.mu.RUnlock()
	if provider == nil {
		return nil, nil, errs.Detail(ErrProviderNotFound, "provider %s is not registered | 提供方 %s 未注册", name, name)
	}
	if provider.Adapter != nil {
		return provider, provider.Adapter, nil
	}
	if cached != nil {
		return provider, cached, nil
	}
	created := newAdapterWithPolicy(provider, b.HTTPClient, discoveryPolicyFor(b, provider), b.now)
	b.mu.Lock()
	if b.adapters == nil {
		b.adapters = make(map[string]ProviderAdapter)
	}
	if existing := b.adapters[name]; existing != nil {
		created = existing
	} else {
		b.adapters[name] = created
	}
	b.mu.Unlock()
	if created == nil {
		return nil, nil, errs.Detail(ErrProviderConfig, "provider %s has no adapter | 提供方 %s 没有适配器", name, name)
	}
	return provider, created, nil
}

// fail records a safe audit event and invokes the configured or default failure handler.
// fail 记录安全审计事件并调用已配置或默认失败处理器。
func (b *Broker) fail(w http.ResponseWriter, r *http.Request, providerName string, err error) {
	reason := failureReason(err)
	detail := map[string]string{"reason": reason}
	if safe := safeProviderName(providerName); safe != "" {
		detail["provider"] = safe
	}
	if b.Service != nil {
		b.Service.Audit(r.Context(), &auth.AuditEvent{
			Type:      "federation.login.failed",
			IP:        r.RemoteAddr,
			UserAgent: r.UserAgent(),
			Outcome:   "failure",
			Detail:    detail,
			At:        b.now(),
		})
	}
	if b.FailureHandler != nil {
		b.FailureHandler(w, r, err)
		return
	}
	status := failureStatus(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": failureCode(err)})
	_, _ = w.Write(body)
}

// now returns the broker clock. | now 返回代理时钟。
func (b *Broker) now() time.Time {
	if b != nil && b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// stateTTL returns the effective state lifetime. | stateTTL 返回生效的 state 有效期。
func (b *Broker) stateTTL() time.Duration {
	if b != nil && b.StateTTL > 0 {
		return b.StateTTL
	}
	return DefaultStateTTL
}

// callbackValues parses query and bounded form values. | callbackValues 解析查询与受限表单值。
func callbackValues(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r == nil {
		return nil, ErrInvalidRequest
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxProviderResponse)
	}
	if err := r.ParseForm(); err != nil {
		return nil, errs.Detail(ErrInvalidRequest, "cannot parse callback form | 无法解析回调表单")
	}
	return r.Form, nil
}

// verifyNonce verifies the OIDC nonce recorded for the state. | verifyNonce 校验 state 中记录的 OIDC nonce。
func verifyNonce(provider *Provider, record *StateRecord, token *Token) error {
	if provider == nil || !provider.Nonce {
		return nil
	}
	if record == nil || record.Nonce == "" || token == nil || len(token.Claims) == 0 {
		return ErrNonceMismatch
	}
	got := token.Claims["nonce"]
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(record.Nonce)) != 1 {
		return ErrNonceMismatch
	}
	return nil
}

// providerDeniedError returns a safe provider-denial error. | providerDeniedError 返回安全的提供方拒绝错误。
func providerDeniedError(code string) error {
	code = sanitizeProviderCode(code)
	return errs.Detail(ErrProviderDenied, "provider returned %s | 提供方返回 %s", code, code)
}

// toAuthIdentity converts a federation identity into an auth identity. | toAuthIdentity
// 把 federation 身份转换为 auth 身份。
func toAuthIdentity(identity *Identity) *auth.Identity {
	if identity == nil {
		return nil
	}
	return &auth.Identity{
		Provider:      identity.Provider,
		Subject:       identity.Subject,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,
		Username:      identity.Username,
		Name:          identity.Name,
		AvatarURL:     identity.AvatarURL,
		Raw:           cloneMap(identity.Raw),
	}
}

// failureReason maps an error to a stable audit reason. | failureReason 把错误映射为稳定审计原因。
func failureReason(err error) string {
	switch {
	case errors.Is(err, ErrProviderDenied):
		return "provider_denied"
	case errors.Is(err, ErrStateExpired):
		return "state_expired"
	case errors.Is(err, ErrStateMismatch):
		return "state_mismatch"
	case errors.Is(err, ErrMissingCode):
		return "missing_code"
	case errors.Is(err, ErrNonceMismatch):
		return "nonce_mismatch"
	case errors.Is(err, ErrTokenExchange):
		return "token_exchange"
	case errors.Is(err, ErrUserInfo):
		return "user_info"
	case errors.Is(err, ErrAccountLinkConflict):
		return "account_link_conflict"
	case errors.Is(err, ErrProviderNotFound):
		return "provider_not_found"
	case errors.Is(err, auth.ErrAccountDisabled):
		return "account_disabled"
	case errors.Is(err, auth.ErrAccountLocked):
		return "account_locked"
	case errors.Is(err, auth.ErrAccountPending):
		return "account_pending"
	default:
		return "internal_error"
	}
}

// failureCode returns a stable machine-readable failure code. | failureCode 返回稳定机器可读失败码。
func failureCode(err error) string {
	switch {
	case errors.Is(err, ErrProviderDenied):
		return "provider_denied"
	case errors.Is(err, ErrStateExpired), errors.Is(err, ErrStateMismatch):
		return "invalid_state"
	case errors.Is(err, ErrMissingCode):
		return "missing_code"
	case errors.Is(err, ErrNonceMismatch):
		return "nonce_mismatch"
	case errors.Is(err, ErrAccountLinkConflict):
		return "account_link_conflict"
	case errors.Is(err, ErrProviderNotFound):
		return "provider_not_found"
	case errors.Is(err, auth.ErrAccountDisabled), errors.Is(err, auth.ErrAccountLocked), errors.Is(err, auth.ErrAccountPending):
		return "account_unavailable"
	default:
		return "login_failed"
	}
}

// failureStatus maps an error to an HTTP status without leaking provider details.
// failureStatus 把错误映射为 HTTP 状态，且不泄露提供方细节。
func failureStatus(err error) int {
	switch {
	case errors.Is(err, ErrProviderDenied):
		return http.StatusUnauthorized
	case errors.Is(err, ErrStateExpired), errors.Is(err, ErrStateMismatch), errors.Is(err, ErrMissingCode), errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrNonceMismatch):
		return http.StatusBadRequest
	case errors.Is(err, ErrProviderNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrAccountLinkConflict):
		return http.StatusConflict
	case errors.Is(err, auth.ErrAccountDisabled), errors.Is(err, auth.ErrAccountLocked), errors.Is(err, auth.ErrAccountPending):
		return http.StatusForbidden
	case errors.Is(err, ErrProviderConfig):
		return http.StatusInternalServerError
	case errors.Is(err, ErrTokenExchange), errors.Is(err, ErrUserInfo), errors.Is(err, ErrTransport):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// methodNotAllowed writes a 405 response with an Allow header. | methodNotAllowed 写入带 Allow 头的 405 响应。
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write([]byte(`{"error":"method_not_allowed"}`))
}

// normalizePrefix normalizes an application route prefix. | normalizePrefix 规范应用路由前缀。
func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
}

// matchHTTPRoute extracts provider and action from a native handler path. | matchHTTPRoute
// 从原生处理器路径提取提供方与动作。
func matchHTTPRoute(base, path string) (string, string, bool) {
	var rest string
	if base == "" {
		if !strings.HasPrefix(path, "/") {
			return "", "", false
		}
		rest = strings.TrimPrefix(path, "/")
	} else {
		if !strings.HasPrefix(path, base+"/") {
			return "", "", false
		}
		rest = strings.TrimPrefix(path, base+"/")
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	switch parts[1] {
	case "login", "callback":
		return parts[0], parts[1], true
	default:
		return "", "", false
	}
}

// safeProviderName limits untrusted route text stored in audit details. | safeProviderName
// 限制写入审计详情的不可信路由文本。
func safeProviderName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 64 {
		value = value[:64]
	}
	return sanitizeProviderCode(value)
}
