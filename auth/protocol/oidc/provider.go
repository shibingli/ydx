package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/log"
)

// ClaimsProvider supplies ID-token and UserInfo claims. | ClaimsProvider 提供 ID 令牌与 UserInfo 声明。
type ClaimsProvider interface {
	// IDTokenClaims returns claims for an ID token. | IDTokenClaims 返回 ID 令牌声明。
	IDTokenClaims(ctx context.Context, principal *auth.Principal, scopes []string) (*Claims, error)
	// UserInfoClaims returns the UserInfo response object. | UserInfoClaims 返回 UserInfo 响应对象。
	UserInfoClaims(ctx context.Context, principal *auth.Principal, scopes []string) (map[string]any, error)
}

// ClaimsProviderFunc adapts functions to ClaimsProvider. | ClaimsProviderFunc 把函数适配为 ClaimsProvider。
type ClaimsProviderFunc struct {
	// IDToken is called by IDTokenClaims. | IDToken 由 IDTokenClaims 调用。
	IDToken func(ctx context.Context, principal *auth.Principal, scopes []string) (*Claims, error)
	// UserInfo is called by UserInfoClaims. | UserInfo 由 UserInfoClaims 调用。
	UserInfo func(ctx context.Context, principal *auth.Principal, scopes []string) (map[string]any, error)
}

// IDTokenClaims calls f.IDToken. | IDTokenClaims 调用 f.IDToken。
func (f ClaimsProviderFunc) IDTokenClaims(ctx context.Context, principal *auth.Principal, scopes []string) (*Claims, error) {
	if f.IDToken == nil {
		return DefaultClaimsProvider{}.IDTokenClaims(ctx, principal, scopes)
	}
	return f.IDToken(ctx, principal, scopes)
}

// UserInfoClaims calls f.UserInfo. | UserInfoClaims 调用 f.UserInfo。
func (f ClaimsProviderFunc) UserInfoClaims(ctx context.Context, principal *auth.Principal, scopes []string) (map[string]any, error) {
	if f.UserInfo == nil {
		return DefaultClaimsProvider{}.UserInfoClaims(ctx, principal, scopes)
	}
	return f.UserInfo(ctx, principal, scopes)
}

// DefaultClaimsProvider projects a principal into the standard scope-filtered claims. | DefaultClaimsProvider
// 把主体投影为按作用域过滤的标准声明。
type DefaultClaimsProvider struct{}

// IDTokenClaims returns standard claims filtered by scopes. | IDTokenClaims 返回按作用域过滤的标准声明。
func (DefaultClaimsProvider) IDTokenClaims(_ context.Context, principal *auth.Principal, scopes []string) (*Claims, error) {
	claims := claimsFromPrincipal(principal, scopes)
	filterClaims(claims, scopes)
	return claims, nil
}

// UserInfoClaims returns standard claims as a map filtered by scopes. | UserInfoClaims 返回按作用域过滤的映射形式标准声明。
func (DefaultClaimsProvider) UserInfoClaims(_ context.Context, principal *auth.Principal, scopes []string) (map[string]any, error) {
	claims := claimsFromPrincipal(principal, scopes)
	filterClaims(claims, scopes)
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	out := make(map[string]any)
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	if principal != nil {
		out["sub"] = principal.Subject
	}
	if claims.Extra != nil {
		for key, value := range claims.Extra {
			out[key] = value
		}
	}
	return out, nil
}

// filterClaims clears claims outside the granted scopes. | filterClaims 清除授予作用域之外的声明。
func filterClaims(claims *Claims, scopes []string) {
	if claims == nil {
		return
	}
	if !scopeGranted(scopes, ScopeProfile) {
		claims.Name = ""
		claims.GivenName = ""
		claims.FamilyName = ""
		claims.MiddleName = ""
		claims.Nickname = ""
		claims.PreferredUsername = ""
		claims.Profile = ""
		claims.Picture = ""
		claims.Website = ""
		claims.Gender = ""
		claims.Birthdate = ""
		claims.Zoneinfo = ""
		claims.Locale = ""
		claims.UpdatedAt = 0
	}
	if !scopeGranted(scopes, ScopeEmail) {
		claims.Email = ""
		claims.EmailVerified = nil
	}
	if !scopeGranted(scopes, ScopePhone) {
		claims.PhoneNumber = ""
		claims.PhoneNumberVerified = nil
	}
	if !scopeGranted(scopes, ScopeAddress) {
		claims.Address = nil
	}
}

// scopeGranted reports whether scopes contains name. | scopeGranted 报告 scopes 是否包含 name。
func scopeGranted(scopes []string, name string) bool {
	for _, scope := range scopes {
		if scope == name {
			return true
		}
	}
	return false
}

// ProviderConfig configures an OpenID Provider. | ProviderConfig 配置 OpenID 提供方。
type ProviderConfig struct {
	// Issuer is the OP issuer; empty uses the OAuth server issuer. It must equal the OAuth issuer. | Issuer 是 OP 签发方；空值使用 OAuth 服务器签发方。它必须等于 OAuth 签发方。
	Issuer string
	// OAuth is the underlying OAuth authorization server. | OAuth 是底层 OAuth 授权服务器。
	OAuth *oauth2.Server
	// Keys is the published JWK Set. | Keys 是发布的 JWK Set。
	Keys *jose.KeySet
	// SigningKey is the ID-token signing key. When nil, the first sig key in Keys is used, or a
	// fresh RSA-2048 key is generated. | SigningKey 是 ID 令牌签名密钥。空值时使用 Keys 中第一个
	// sig 密钥，或生成新的 RSA-2048 密钥。
	SigningKey *jose.Key
	// SigningAlg is the ID-token JWS algorithm; empty uses the key Alg or RS256. | SigningAlg 是 ID
	// 令牌 JWS 算法；空值使用密钥 Alg 或 RS256。
	SigningAlg string
	// IDTokenTTL is the ID-token lifetime; zero means five minutes. | IDTokenTTL 是 ID 令牌寿命；零值表示 5 分钟。
	IDTokenTTL time.Duration
	// ClaimsProvider supplies claims; nil uses DefaultClaimsProvider. | ClaimsProvider 提供声明；空值使用 DefaultClaimsProvider。
	ClaimsProvider ClaimsProvider
	// Sessions manages OP browser sessions for logout and session management. | Sessions 管理登出与会话管理使用的 OP 浏览器会话。
	Sessions *auth.SessionManager
	// PathPrefix overrides the OAuth mount prefix. | PathPrefix 覆盖 OAuth 挂载前缀。
	PathPrefix string
	// DiscoveryPath overrides the discovery document path. | DiscoveryPath 覆盖发现文档路径。
	DiscoveryPath string
	// JWKSPath overrides the JWKS endpoint path. | JWKSPath 覆盖 JWKS 端点路径。
	JWKSPath string
	// UserInfoPath overrides the UserInfo endpoint path. | UserInfoPath 覆盖 UserInfo 端点路径。
	UserInfoPath string
	// EndSessionPath overrides the RP-initiated logout path. | EndSessionPath 覆盖 RP 发起登出路径。
	EndSessionPath string
	// RegistrationPath overrides the dynamic registration path. | RegistrationPath 覆盖动态注册路径。
	RegistrationPath string
	// CheckSessionPath overrides the session-management iframe path. | CheckSessionPath 覆盖会话管理 iframe 路径。
	CheckSessionPath string
	// FrontchannelLogoutPath overrides the front-channel logout path. | FrontchannelLogoutPath 覆盖前端通道登出路径。
	FrontchannelLogoutPath string
	// BackchannelLogoutPath overrides the back-channel logout path. | BackchannelLogoutPath 覆盖后端通道登出路径。
	BackchannelLogoutPath string
	// EnableRegistration enables RFC 7591 dynamic client registration. | EnableRegistration 启用 RFC 7591 动态客户端注册。
	EnableRegistration bool
	// RegistrationInitialAccessToken, when set, is the bearer token required to register. | RegistrationInitialAccessToken 设置时是注册所需的承载令牌。
	RegistrationInitialAccessToken string
	// EnableLogout enables RP-initiated logout. | EnableLogout 启用 RP 发起登出。
	EnableLogout bool
	// LogoutReplay, when non-nil, rejects a logout token whose jti was already accepted. Replay
	// protection is opt-in: replaying a logout token only repeats an idempotent session
	// revocation, while deployments with non-idempotent side effects should enable it. Use
	// NewMemoryLogoutReplayStore for a single process or a shared implementation for multiple
	// instances. | LogoutReplay 非空时拒绝 jti 已被接受的登出令牌。重放保护为选择性启用：
	// 重放登出令牌只会重复幂等的会话撤销，而带非幂等副作用的部署应启用它。单进程可使用
	// NewMemoryLogoutReplayStore，多实例应使用共享实现。
	LogoutReplay LogoutReplayStore
	// FrontchannelLogout enables front-channel logout. | FrontchannelLogout 启用前端通道登出。
	FrontchannelLogout bool
	// BackchannelLogout enables back-channel logout. | BackchannelLogout 启用后端通道登出。
	BackchannelLogout bool
	// BackchannelLogoutClientID is the OAuth client_id this deployment uses when acting as an RP
	// that receives back-channel logout tokens. The receiver validates that aud contains this value
	// and that azp equals it when required; without it the receiver fails closed. An OP that only
	// sends logout tokens may leave it empty. | BackchannelLogoutClientID 是部署作为接收后端登出
	// 令牌的 RP 时使用的 OAuth client_id。接收端校验 aud 包含该值，并在需要时校验 azp 等于该值；
	// 未设置时接收端按失败关闭处理。仅发送登出令牌的 OP 可留空。
	BackchannelLogoutClientID string
	// SessionManagement enables the check_session_iframe endpoint. | SessionManagement 启用 check_session_iframe 端点。
	SessionManagement bool
	// SubjectType is "public" (default) or "pairwise". | SubjectType 取值为 "public"（默认）或 "pairwise"。
	SubjectType string
	// PairwiseSalt seeds pairwise subject derivation; it must be stable for the deployment. | PairwiseSalt 为假名主体派生提供种子；部署内必须稳定。
	PairwiseSalt string
	// SectorIdentifier returns the pairwise sector for a client; nil uses SectorIdentifierURI or client ID. | SectorIdentifier 返回客户端的假名扇区；空值使用 SectorIdentifierURI 或客户端 ID。
	SectorIdentifier func(client *oauth2.Client) string
	// ClaimsSupported is published in discovery; nil uses the standard set. | ClaimsSupported 在发现文档中发布；空值使用标准集。
	ClaimsSupported []string
	// HTTPClient performs back-channel logout delivery and client JWKS fetches. | HTTPClient 执行后端登出投递与客户端 JWKS 获取。
	HTTPClient *http.Client
	// Logger receives operational warnings. | Logger 接收运行告警。
	Logger *log.Logger
	// Clock overrides time for tests. | Clock 为测试替换时间。
	Clock func() time.Time
}

// Provider is an OpenID Provider. | Provider 是 OpenID 提供方。
type Provider struct {
	config     ProviderConfig
	oauth      *oauth2.Server
	keys       *jose.KeySet
	signingKey *jose.Key
	signingAlg string
	claims     ClaimsProvider
	pathPrefix string
	httpClient *http.Client
	now        func() time.Time
	// issuerOrigin is the scheme and authority of Issuer, used so Endpoint does not repeat an
	// issuer path that already became the mount prefix. | issuerOrigin 是 Issuer 的协议与主机部分，
	// 使 Endpoint 不会重复已成为挂载前缀的 issuer 路径。
	issuerOrigin string
}

// NewProvider returns a Provider and installs it on the OAuth server. | NewProvider 返回 Provider 并安装到 OAuth 服务器。
func NewProvider(config ProviderConfig) (*Provider, error) {
	if config.OAuth == nil {
		return nil, errs.Detail(ErrInvalidConfig, "OAuth server is nil | OAuth 服务器为空")
	}
	issuer := config.Issuer
	if issuer == "" {
		issuer = config.OAuth.Issuer()
	}
	if issuer != config.OAuth.Issuer() {
		return nil, errs.Detail(ErrInvalidConfig, "OIDC issuer must equal the OAuth issuer | OIDC issuer 必须等于 OAuth issuer")
	}
	config.Issuer = issuer
	config.BackchannelLogoutClientID = strings.TrimSpace(config.BackchannelLogoutClientID)
	keys := config.Keys
	if keys == nil {
		keys = &jose.KeySet{}
	}
	signingKey := config.SigningKey
	if signingKey == nil {
		for _, key := range keys.Keys {
			if key != nil && (key.Use == "sig" || key.Use == "") {
				signingKey = key
				break
			}
		}
	}
	if signingKey == nil {
		generated, err := jose.GenerateKey("RS256", 2048)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		signingKey = generated
	}
	if signingKey.Kid == "" {
		signingKey.Kid = "default"
	}
	alg := config.SigningAlg
	if alg == "" {
		alg = signingKey.Alg
	}
	if alg == "" {
		alg = "RS256"
	}
	if signingKey.Alg == "" {
		signingKey.Alg = alg
	}
	signingKey.Use = "sig"
	if _, exists := keys.Key(signingKey.Kid); !exists {
		if err := keys.Add(signingKey); err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
	}
	claims := config.ClaimsProvider
	if claims == nil {
		claims = DefaultClaimsProvider{}
	}
	prefix := config.PathPrefix
	if prefix == "" {
		prefix = config.OAuth.Config().PathPrefix
	}
	config.PathPrefix = strings.TrimRight(prefix, "/")
	if config.PathPrefix != "" && !strings.HasPrefix(config.PathPrefix, "/") {
		// Keep the mount prefix absolute so Path cannot emit "idpauthorize". | 保持挂载前缀为
		// 绝对路径，避免 Path 生成 "idpauthorize"。
		config.PathPrefix = "/" + config.PathPrefix
	}
	setPath(&config.DiscoveryPath, DiscoveryPath)
	setPath(&config.JWKSPath, JWKSPath)
	setPath(&config.UserInfoPath, UserInfoPath)
	setPath(&config.EndSessionPath, EndSessionPath)
	setPath(&config.RegistrationPath, RegistrationPath)
	setPath(&config.CheckSessionPath, CheckSessionPath)
	setPath(&config.FrontchannelLogoutPath, FrontchannelLogoutPath)
	setPath(&config.BackchannelLogoutPath, BackchannelLogoutPath)
	if config.SubjectType == "" {
		config.SubjectType = SubjectTypePublic
	}
	if config.SubjectType != SubjectTypePublic && config.SubjectType != SubjectTypePairwise {
		return nil, errs.Detail(ErrInvalidConfig, "unknown subject type %[1]q | 未知主体类型 %[1]q", config.SubjectType)
	}
	if config.SubjectType == SubjectTypePairwise && config.PairwiseSalt == "" {
		return nil, errs.Detail(ErrInvalidConfig, "pairwise subjects need a salt | 假名主体需要盐")
	}
	if config.IDTokenTTL <= 0 {
		config.IDTokenTTL = 5 * time.Minute
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	issuerURL, err := url.Parse(config.Issuer)
	if err != nil || issuerURL.Scheme == "" || issuerURL.Host == "" {
		return nil, errs.Detail(ErrInvalidConfig, "issuer must be an absolute URL | issuer 必须是绝对 URL")
	}
	provider := &Provider{
		config:       config,
		oauth:        config.OAuth,
		keys:         keys,
		signingKey:   signingKey,
		signingAlg:   alg,
		claims:       claims,
		pathPrefix:   config.PathPrefix,
		httpClient:   httpClient,
		now:          config.Clock,
		issuerOrigin: issuerURL.Scheme + "://" + issuerURL.Host,
	}
	if provider.now == nil {
		provider.now = time.Now
	}
	provider.oauth.SetTokenEnricher(provider)
	provider.oauth.SetAuthorizationEnricher(provider)
	provider.oauth.SetAuthorizationResponseSigner(provider)
	provider.oauth.SetJWKSURI(provider.Endpoint(provider.config.JWKSPath))
	if config.EnableRegistration {
		provider.oauth.SetRegistrationEndpoint(provider.Endpoint(provider.config.RegistrationPath))
	}
	return provider, nil
}

// setPath fills an empty path and ensures a leading slash. | setPath 填充空路径并保证前导斜杠。
func setPath(target *string, fallback string) {
	if *target == "" {
		*target = fallback
	}
	if !strings.HasPrefix(*target, "/") {
		*target = "/" + *target
	}
}

// Config returns the normalized configuration. | Config 返回规范化配置。
func (p *Provider) Config() ProviderConfig { return p.config }

// OAuth returns the underlying OAuth server. | OAuth 返回底层 OAuth 服务器。
func (p *Provider) OAuth() *oauth2.Server { return p.oauth }

// Keys returns the published key set. | Keys 返回发布的密钥集。
func (p *Provider) Keys() *jose.KeySet { return p.keys }

// Path returns the mounted path for path. | Path 返回 path 的挂载路径。
func (p *Provider) Path(path string) string {
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return p.pathPrefix + path
}

// Endpoint returns the absolute URL for an endpoint path that does not include the mount prefix.
// It combines the issuer scheme and host with Path(path); Path returns the mounted path, so callers
// must pass a configured path such as ProviderConfig.JWKSPath and must never call
// Endpoint(Path(path)), which would apply the prefix twice. | Endpoint 返回未包含挂载前缀的端点路径
// 的绝对 URL。它把 issuer 的协议与主机部分与 Path(path) 组合；Path 返回挂载后的路径，因此调用方
// 必须传入配置路径（例如 ProviderConfig.JWKSPath），且绝不能调用 Endpoint(Path(path))，否则前缀
// 会被应用两次。
func (p *Provider) Endpoint(path string) string { return p.issuerOrigin + p.Path(path) }

// Now returns the current time. | Now 返回当前时间。
func (p *Provider) Now() time.Time { return p.now().UTC() }

// signingKeyFor returns a signing key suitable for alg. | signingKeyFor 返回适合 alg 的签名密钥。
func (p *Provider) signingKeyFor(alg string) (*jose.Key, error) {
	if alg == "" || alg == p.signingAlg || p.signingKey.Alg == alg {
		return p.signingKey, nil
	}
	for _, key := range p.keys.Keys {
		if key == nil || key.Use == "enc" {
			continue
		}
		if key.Alg == alg || (key.Alg == "" && keyMatchesAlg(key, alg)) {
			return key, nil
		}
	}
	return nil, errs.Detail(ErrInvalidConfig, "no signing key for alg %[1]q | 没有适用于 alg %[1]q 的签名密钥", alg)
}

// keyMatchesAlg reports whether key material fits alg. | keyMatchesAlg 报告密钥材料是否适合 alg。
func keyMatchesAlg(key *jose.Key, alg string) bool {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return key.Kty == jose.KeyTypeRSA
	case strings.HasPrefix(alg, "ES"):
		return key.Kty == jose.KeyTypeEC
	case alg == "EdDSA":
		return key.Kty == jose.KeyTypeOKP && key.Crv == jose.CurveEd25519
	default:
		return false
	}
}

// EnrichToken adds an ID token to a token response when openid was granted. | EnrichToken 在授予 openid 时向令牌响应添加 ID 令牌。
func (p *Provider) EnrichToken(ctx context.Context, grant *oauth2.Grant, response *oauth2.TokenResponse) error {
	if grant == nil || grant.Client == nil || response == nil {
		return nil
	}
	if !scopeGranted(grant.Scopes, ScopeOpenID) {
		return nil
	}
	idToken, err := p.buildIDToken(ctx, grant, response.AccessToken, "")
	if err != nil {
		return err
	}
	response.IDToken = idToken
	return nil
}

// EnrichAuthorization adds an ID token and session_state to an authorization response. | EnrichAuthorization
// 向授权响应添加 ID 令牌与 session_state。
func (p *Provider) EnrichAuthorization(ctx context.Context, grant *oauth2.Grant, params url.Values) error {
	if grant == nil || grant.Client == nil || params == nil {
		return nil
	}
	if !scopeGranted(grant.Scopes, ScopeOpenID) {
		return nil
	}
	if !strings.Contains(" "+grant.ResponseType+" ", " id_token ") {
		return nil
	}
	// An id_token may already have been signed by the token enricher (implicit flows with an
	// access token) or generic enrichers. Never sign it twice. | 令牌增强器（带访问令牌的隐式
	// 流程）或通用增强器可能已经签发 id_token；不得重复签名。
	if params.Get("id_token") == "" {
		idToken, err := p.buildIDToken(ctx, grant, params.Get("access_token"), params.Get("code"))
		if err != nil {
			return err
		}
		params.Set("id_token", idToken)
	}
	if p.config.SessionManagement && grant.SessionID != "" {
		params.Set("session_state", p.SessionState(grant.Client.ID, grant.SessionID))
	}
	return nil
}

// buildIDToken creates a signed, optionally encrypted ID token. | buildIDToken 创建已签名、可选加密的 ID 令牌。
func (p *Provider) buildIDToken(ctx context.Context, grant *oauth2.Grant, accessToken, code string) (string, error) {
	now := p.Now()
	claims, err := p.claims.IDTokenClaims(ctx, grant.Principal, grant.Scopes)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidConfig)
	}
	if claims == nil {
		claims = &Claims{}
	}
	claims.Issuer = p.config.Issuer
	claims.Subject = p.subjectForClient(grant.Client, grant.Subject)
	claims.Audience = Audience{grant.Client.ID}
	claims.AZP = ""
	claims.Expiry = now.Add(p.config.IDTokenTTL).Unix()
	claims.IssuedAt = now.Unix()
	claims.Nonce = grant.Nonce
	if !grant.AuthTime.IsZero() {
		claims.AuthTime = grant.AuthTime.Unix()
	}
	claims.ACR = grant.ACR
	claims.AMR = append([]string(nil), grant.AMR...)
	claims.SID = grant.SessionID
	claims.JTI = auth.NewID("idt")
	signingAlg := p.signingAlg
	if grant.Client.IDTokenSignedResponseAlg != "" {
		signingAlg = grant.Client.IDTokenSignedResponseAlg
	}
	if accessToken != "" {
		hash, hashErr := halfHash(signingAlg, accessToken)
		if hashErr != nil {
			return "", errs.Wrap(hashErr, ErrInvalidConfig)
		}
		claims.AccessTokenHash = hash
	}
	if code != "" {
		hash, hashErr := halfHash(signingAlg, code)
		if hashErr != nil {
			return "", errs.Wrap(hashErr, ErrInvalidConfig)
		}
		claims.CodeHash = hash
	}
	payload, err := claimsPayload(claims)
	if err != nil {
		return "", err
	}
	signingKey, err := p.signingKeyFor(signingAlg)
	if err != nil {
		return "", err
	}
	signed, err := jose.Sign(payload, signingKey, jose.SignOptions{
		Alg: signingAlg,
		Kid: signingKey.Kid,
		Typ: "JWT",
	})
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidConfig)
	}
	if grant.Client.IDTokenEncryptedResponseAlg == "" {
		return signed, nil
	}
	enc := grant.Client.IDTokenEncryptedResponseEnc
	if enc == "" {
		enc = "A256GCM"
	}
	key, err := p.clientEncryptionKey(ctx, grant.Client)
	if err != nil {
		return "", err
	}
	encrypted, err := jose.Encrypt([]byte(signed), key, jose.EncryptOptions{
		Alg: grant.Client.IDTokenEncryptedResponseAlg,
		Enc: enc,
		Typ: "JWT",
		Cty: "JWT",
	})
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidConfig)
	}
	return encrypted, nil
}

// claimsPayload merges the typed claims and Extra into one JSON object. | claimsPayload 把类型化声明与 Extra 合并为一个 JSON 对象。
func claimsPayload(claims *Claims) ([]byte, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	if len(claims.Extra) == 0 {
		return raw, nil
	}
	out := make(map[string]any)
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	for key, value := range claims.Extra {
		if _, exists := out[key]; !exists {
			out[key] = value
		}
	}
	return json.Marshal(out)
}

// clientEncryptionKey resolves an RP encryption key from its registered JWKS or jwks_uri. | clientEncryptionKey
// 从客户端注册的 JWKS 或 jwks_uri 解析 RP 加密密钥。
func (p *Provider) clientEncryptionKey(ctx context.Context, client *oauth2.Client) (*jose.Key, error) {
	var set *jose.KeySet
	if len(client.JWKS) > 0 {
		parsed, err := jose.ParseKeySet(client.JWKS)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		set = parsed
	} else if client.JWKSURI != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, client.JWKSURI, nil)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		resp, err := p.httpClient.Do(req)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		parsed, err := jose.ParseKeySet(body)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidConfig)
		}
		set = parsed
	}
	if set == nil {
		return nil, errs.Detail(ErrInvalidConfig, "client has no encryption key set | 客户端没有加密密钥集")
	}
	for _, key := range set.Keys {
		if key == nil {
			continue
		}
		if key.Use == "enc" || key.Use == "" {
			return key, nil
		}
	}
	return nil, errs.Detail(ErrInvalidConfig, "client has no encryption key | 客户端没有加密密钥")
}

// subjectForClient returns the public or pairwise subject for client. | subjectForClient 返回客户端的主体，公开或假名。
func (p *Provider) subjectForClient(client *oauth2.Client, local string) string {
	subjectType := p.config.SubjectType
	if client != nil && client.SubjectType != "" {
		subjectType = client.SubjectType
	}
	if subjectType != SubjectTypePairwise {
		return local
	}
	sector := client.ID
	if client.SectorIdentifierURI != "" {
		sector = sectorHost(client.SectorIdentifierURI)
	} else if len(client.RedirectURIs) > 0 {
		// Without an explicit sector identifier, the host of the redirect URI is the
		// sector (OIDC Core section 8.1). | 未显式提供扇区标识时，按 OIDC Core 第 8.1 节
		// 使用重定向 URI 的主机作为扇区。
		sector = sectorHost(client.RedirectURIs[0])
	}
	if p.config.SectorIdentifier != nil {
		sector = p.config.SectorIdentifier(client)
	}
	return PairwiseSubject(local, sector, p.config.PairwiseSalt)
}

// sectorHost returns the lowercase host of raw, falling back to raw itself. | sectorHost 返回 raw
// 的小写主机，无法解析时回退为 raw 本身。
func sectorHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return raw
	}
	return strings.ToLower(parsed.Hostname())
}

// PairwiseSubject derives a stable pseudonymous subject from a local subject, sector and salt. | PairwiseSubject
// 从本地主体、扇区与盐派生稳定的假名主体。
func PairwiseSubject(local, sector, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(sector))
	mac.Write([]byte{0})
	mac.Write([]byte(local))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
