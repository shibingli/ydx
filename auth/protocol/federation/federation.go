package federation

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Provider kinds understood by the built-in adapters. | 内置适配器识别的提供方类型。
const (
	// KindOIDC marks an OpenID Connect provider. | KindOIDC 表示 OpenID Connect 提供方。
	KindOIDC = "oidc"
	// KindOAuth2 marks a plain OAuth 2.0 provider. | KindOAuth2 表示普通 OAuth 2.0 提供方。
	KindOAuth2 = "oauth2"
	// KindWeChat marks WeChat Open Platform or Official Account. | KindWeChat 表示微信开放平台或公众号。
	KindWeChat = "wechat"
	// KindAlipay marks Alipay. | KindAlipay 表示支付宝。
	KindAlipay = "alipay"
	// KindDingTalk marks DingTalk. | KindDingTalk 表示钉钉。
	KindDingTalk = "dingtalk"
	// KindFeishu marks Feishu / Lark. | KindFeishu 表示飞书 / Lark。
	KindFeishu = "feishu"
	// KindWeCom marks WeCom. | KindWeCom 表示企业微信。
	KindWeCom = "wecom"
	// KindQQ marks QQ Connect. | KindQQ 表示 QQ 互联。
	KindQQ = "qq"
	// KindWeibo marks Sina Weibo. | KindWeibo 表示新浪微博。
	KindWeibo = "weibo"
	// KindBaidu marks Baidu Passport. | KindBaidu 表示百度账号。
	KindBaidu = "baidu"
	// KindGitee marks Gitee. | KindGitee 表示 Gitee。
	KindGitee = "gitee"
)

// Token endpoint authentication styles. | 令牌端点认证方式。
const (
	// AuthStylePost sends client_id and client_secret in the form body.
	// AuthStylePost 在表单体中发送 client_id 与 client_secret。
	AuthStylePost = "post"
	// AuthStyleBasic sends HTTP Basic credentials and only puts client_id in the body.
	// AuthStyleBasic 使用 HTTP Basic 凭据，仅在表单体中放 client_id。
	AuthStyleBasic = "basic"
	// AuthStyleAuto uses Basic when a client secret exists and POST otherwise.
	// AuthStyleAuto 在存在客户端密钥时使用 Basic，否则使用 POST。
	AuthStyleAuto = "auto"
)

// Federation sentinel errors. Callers should classify failures with errors.Is;
// provider responses and raw tokens are never embedded in these errors. | 联合登录哨兵错误。
// 调用方应使用 errors.Is 判定；提供方响应与原始令牌绝不会写入这些错误。
var (
	// ErrInvalidConfig reports an incomplete broker or provider configuration.
	// ErrInvalidConfig 表示代理或提供方配置不完整。
	ErrInvalidConfig = errs.New("federation: invalid configuration | federation：配置非法")
	// ErrInvalidRequest reports malformed HTTP input. | ErrInvalidRequest 表示 HTTP 输入非法。
	ErrInvalidRequest = errs.New("federation: invalid request | federation：请求非法")
	// ErrProviderNotFound reports an unregistered provider name. | ErrProviderNotFound 表示提供方未注册。
	ErrProviderNotFound = errs.New("federation: provider not found | federation：提供方不存在")
	// ErrProviderConfig reports an unusable provider definition. | ErrProviderConfig 表示提供方定义不可用。
	ErrProviderConfig = errs.New("federation: invalid provider configuration | federation：提供方配置非法")
	// ErrProviderDenied reports that the provider rejected or cancelled authorization.
	// ErrProviderDenied 表示提供方拒绝或取消了授权。
	ErrProviderDenied = errs.New("federation: authorization denied | federation：授权被拒绝")
	// ErrStateMismatch reports an unknown, forged or already consumed state.
	// ErrStateMismatch 表示 state 未知、伪造或已被使用。
	ErrStateMismatch = errs.New("federation: state mismatch | federation：state 不匹配")
	// ErrStateExpired reports an expired state record. | ErrStateExpired 表示 state 记录已过期。
	ErrStateExpired = errs.New("federation: state expired | federation：state 已过期")
	// ErrMissingCode reports a callback without an authorization code.
	// ErrMissingCode 表示回调缺少授权码。
	ErrMissingCode = errs.New("federation: missing authorization code | federation：缺少授权码")
	// ErrTokenExchange reports a failed token endpoint exchange or ID token check.
	// ErrTokenExchange 表示令牌端点兑换或 ID 令牌校验失败。
	ErrTokenExchange = errs.New("federation: token exchange failed | federation：令牌兑换失败")
	// ErrUserInfo reports a failed or malformed UserInfo response. | ErrUserInfo 表示 UserInfo 响应失败或格式非法。
	ErrUserInfo = errs.New("federation: user info failed | federation：用户信息获取失败")
	// ErrAccountLinkConflict reports an identity that could not be linked safely.
	// ErrAccountLinkConflict 表示身份无法安全关联。
	ErrAccountLinkConflict = errs.New("federation: account link conflict | federation：账号关联冲突")
	// ErrNonceMismatch reports a missing or mismatched OIDC nonce. | ErrNonceMismatch 表示 OIDC nonce 缺失或不匹配。
	ErrNonceMismatch = errs.New("federation: nonce mismatch | federation：nonce 不匹配")
	// ErrTransport reports a network or HTTP transport failure without exposing URLs.
	// ErrTransport 表示网络或 HTTP 传输失败，且不暴露 URL。
	ErrTransport = errs.New("federation: provider transport failed | federation：提供方传输失败")
	// ErrSigning reports a provider request signing failure. | ErrSigning 表示提供方请求签名失败。
	ErrSigning = errs.New("federation: request signing failed | federation：请求签名失败")
)

// Identity is the normalized upstream identity returned by a provider adapter. | Identity 是
// 提供方适配器返回的规范化上游身份。
type Identity struct {
	// Provider is the registered provider name. | Provider 是注册的提供方名称。
	Provider string
	// Subject is the stable provider-specific user identifier, preferring a union
	// identifier when the provider exposes one. | Subject 是提供方侧稳定用户标识，提供方暴露联合标识时优先使用。
	Subject string
	// Email is the upstream email address. | Email 是上游邮箱地址。
	Email string
	// EmailVerified reports whether the provider explicitly verified the email. It is
	// false unless the provider returns an affirmative verification claim. | EmailVerified
	// 表示提供方是否明确验证了邮箱；除非提供方返回肯定验证声明，否则为 false。
	EmailVerified bool
	// Username is a provider login name when it is globally meaningful. | Username 是提供方登录名，且仅在其具有全局意义时填写。
	Username string
	// Name is the human-readable display name. | Name 是人类可读展示名。
	Name string
	// AvatarURL is the profile image URL. | AvatarURL 是头像 URL。
	AvatarURL string
	// Raw holds scalar provider attributes for user metadata. It must never contain
	// access tokens, refresh tokens or client secrets. | Raw 保存用于用户元数据的提供方标量属性，
	// 绝不能包含访问令牌、刷新令牌或客户端密钥。
	Raw map[string]string
}

// Token is a normalized OAuth token response. | Token 是规范化的 OAuth 令牌响应。
type Token struct {
	// AccessToken is the access token. | AccessToken 是访问令牌。
	AccessToken string
	// TokenType is the token type, normally Bearer. | TokenType 是令牌类型，通常是 Bearer。
	TokenType string
	// RefreshToken is the optional refresh token. | RefreshToken 是可选刷新令牌。
	RefreshToken string
	// Scope is the granted scope string. | Scope 是已授予的作用域字符串。
	Scope string
	// IDToken is the raw compact OIDC ID token, if any. | IDToken 是原始紧凑 OIDC ID 令牌（如有）。
	IDToken string
	// ExpiresIn is the lifetime in seconds as reported by the provider. | ExpiresIn 是提供方报告的秒级有效期。
	ExpiresIn int64
	// Expiry is the absolute expiry time. | Expiry 是绝对过期时间。
	Expiry time.Time
	// OpenID is the WeChat/QQ-style openid when separately exposed. | OpenID 是微信/QQ 风格的 openid（如单独暴露）。
	OpenID string
	// UnionID is the WeChat unionid when separately exposed. | UnionID 是微信 unionid（如单独暴露）。
	UnionID string
	// Claims holds verified ID token claims as scalar strings. | Claims 保存已校验 ID 令牌的标量字符串声明。
	Claims map[string]string
	// Raw holds scalar token response fields. It is never included in errors.
	// Raw 保存令牌响应的标量字段，且绝不会写入错误。
	Raw map[string]string
}

// SetExpiry records the absolute expiry derived from ExpiresIn. | SetExpiry 依据 ExpiresIn 记录绝对过期时间。
func (t *Token) SetExpiry(now time.Time) {
	if t == nil {
		return
	}
	if t.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(t.ExpiresIn) * time.Second)
	}
}

// Valid reports whether the token has a non-empty access token and has not expired.
// Valid 报告令牌是否具有非空访问令牌且尚未过期。
func (t *Token) Valid() bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	return t.Expiry.IsZero() || time.Now().Before(t.Expiry)
}

// AuthURLHook builds a provider-specific authorization URL. | AuthURLHook 构建提供方专用授权 URL。
type AuthURLHook func(p *Provider, state, nonce, verifier string) (string, error)

// ExchangeHook redeems an authorization code with provider-specific transport and
// response handling. | ExchangeHook 使用提供方专用传输与响应处理兑换授权码。
type ExchangeHook func(ctx context.Context, p *Provider, client *http.Client, code, verifier string) (*Token, error)

// UserInfoHook fetches and maps a provider-specific UserInfo response. | UserInfoHook
// 获取并映射提供方专用 UserInfo 响应。
type UserInfoHook func(ctx context.Context, p *Provider, client *http.Client, token *Token) (*Identity, error)

// ProviderAdapter implements one provider's authorization flow. Built-in adapters are
// selected automatically; a Provider may instead install a complete custom adapter.
// ProviderAdapter 实现单个提供方的授权流程。内置适配器自动选择；Provider 也可以安装完整的自定义适配器。
type ProviderAdapter interface {
	// AuthCodeURL builds the authorization redirect URL. | AuthCodeURL 构建授权重定向 URL。
	AuthCodeURL(state, nonce, verifier string) (string, error)
	// Exchange redeems an authorization code. | Exchange 兑换授权码。
	Exchange(ctx context.Context, code, verifier string) (*Token, error)
	// UserInfo returns the normalized upstream identity. | UserInfo 返回规范化上游身份。
	UserInfo(ctx context.Context, token *Token) (*Identity, error)
}

// Provider describes one registered external identity provider. | Provider 描述一个已注册的外部身份提供方。
type Provider struct {
	// Name is the route name and identity provider key. | Name 是路由名称与身份提供方键。
	Name string
	// DisplayName is the name shown by applications. | DisplayName 是应用展示名称。
	DisplayName string
	// Kind selects provider-specific presets and quirks. | Kind 选择提供方专用预设与特殊处理。
	Kind string
	// ClientID is the OAuth client identifier (appid for Chinese providers).
	// ClientID 是 OAuth 客户端标识（中国提供方通常为 appid）。
	ClientID string
	// ClientSecret is the OAuth client secret. It is never logged or included in errors.
	// ClientSecret 是 OAuth 客户端密钥，绝不记录或在错误中输出。
	ClientSecret string
	// RedirectURL is the registered callback URL. | RedirectURL 是已注册回调 URL。
	RedirectURL string
	// Scopes are the default authorization scopes. | Scopes 是默认授权作用域。
	Scopes []string
	// ScopeSeparator separates scopes in the authorization URL; an empty value means a space.
	// ScopeSeparator 是授权 URL 中的作用域分隔符，空值表示空格。
	ScopeSeparator string
	// AuthURL is the authorization endpoint. | AuthURL 是授权端点。
	AuthURL string
	// TokenURL is the token endpoint. | TokenURL 是令牌端点。
	TokenURL string
	// UserInfoURL is the UserInfo endpoint. | UserInfoURL 是 UserInfo 端点。
	UserInfoURL string
	// JWKSURL is the JWKS endpoint used for OIDC ID token verification. | JWKSURL 是用于 OIDC ID 令牌校验的 JWKS 端点。
	JWKSURL string
	// Issuer is the expected OIDC issuer. | Issuer 是期望的 OIDC 签发方。
	Issuer string
	// UseOIDC enables discovery and ID token verification. | UseOIDC 启用发现与 ID 令牌校验。
	UseOIDC bool
	// DiscoveryTTL is the OIDC discovery cache lifetime. Zero disables periodic refresh
	// and keeps the first document for the adapter lifetime. | DiscoveryTTL 是 OIDC 发现
	// 缓存有效期。零值禁用周期性刷新，并在适配器生命周期内保留首次文档。
	DiscoveryTTL time.Duration
	// DiscoveryTTLMin and DiscoveryTTLMax clamp the effective discovery cache lifetime.
	// Zero disables the corresponding bound. | DiscoveryTTLMin 与 DiscoveryTTLMax 限制
	// 生效的发现缓存有效期；零值禁用对应边界。
	DiscoveryTTLMin time.Duration
	DiscoveryTTLMax time.Duration
	// DiscoveryJitter randomizes each cache lifetime by +/- this fraction of the
	// effective TTL. It must be between 0 and 1; zero disables jitter. | DiscoveryJitter
	// 按生效 TTL 的正负比例随机化每次缓存有效期。取值必须介于 0 与 1 之间；零值禁用抖动。
	DiscoveryJitter float64
	// DiscoveryMaxStale bounds how long an expired discovery document may still be
	// served after a failed refresh. Zero means one effective TTL; a negative value
	// disables stale fallback. | DiscoveryMaxStale 限制刷新失败后过期发现文档仍可被
	// 提供的最长时间。零值表示一个生效 TTL；负值禁用过期回退。
	DiscoveryMaxStale time.Duration
	// PKCE enables PKCE S256 for the authorization-code flow. | PKCE 为授权码流程启用 PKCE S256。
	PKCE bool
	// Nonce enables OIDC nonce generation and verification. | Nonce 启用 OIDC nonce 生成与校验。
	Nonce bool
	// AuthStyle selects client authentication at the token endpoint. Empty means POST.
	// AuthStyle 选择令牌端点的客户端认证方式，空值表示 POST。
	AuthStyle string
	// AuthParams are additional authorization query parameters. | AuthParams 是附加授权查询参数。
	AuthParams map[string]string
	// TokenParams are additional token exchange form parameters. | TokenParams 是附加令牌兑换表单参数。
	TokenParams map[string]string
	// UserInfoHeaders are additional UserInfo request headers. | UserInfoHeaders 是附加 UserInfo 请求头。
	UserInfoHeaders map[string]string
	// Extra carries provider-specific settings such as tenant, account type or keys.
	// Extra 保存提供方专用设置，例如租户、账号类型或密钥。
	Extra map[string]string
	// PrivateKey is a PEM or base64 DER private key used by request-signing providers
	// such as Alipay. | PrivateKey 是用于请求签名提供方（如支付宝）的 PEM 或 base64 DER 私钥。
	PrivateKey string
	// HTTPClient overrides the broker HTTP client for this provider. | HTTPClient 为此提供方覆盖代理 HTTP 客户端。
	HTTPClient *http.Client
	// AuthURLHook overrides authorization URL construction. | AuthURLHook 覆盖授权 URL 构建。
	AuthURLHook AuthURLHook
	// ExchangeHook overrides token exchange. | ExchangeHook 覆盖令牌兑换。
	ExchangeHook ExchangeHook
	// UserInfoHook overrides UserInfo retrieval and decoding. | UserInfoHook 覆盖 UserInfo 获取与解码。
	UserInfoHook UserInfoHook
	// Adapter, when set, replaces the built-in adapter completely. | Adapter 设置时完全替换内置适配器。
	Adapter ProviderAdapter
}

// ProviderConfig is the common constructor input used by built-in presets. | ProviderConfig
// 是内置预设使用的通用构造输入。
type ProviderConfig struct {
	// Name is the provider route name. | Name 是提供方路由名称。
	Name string
	// DisplayName is the application-facing name. | DisplayName 是面向应用的名称。
	DisplayName string
	// Kind is the provider kind. | Kind 是提供方类型。
	Kind string
	// ClientID and ClientSecret are the registered credentials. | ClientID 与 ClientSecret 是已注册凭据。
	ClientID     string
	ClientSecret string
	// RedirectURL is the registered callback URL. | RedirectURL 是已注册回调 URL。
	RedirectURL string
	// Scopes overrides preset default scopes. | Scopes 覆盖预设默认作用域。
	Scopes []string
	// AuthURL, TokenURL, UserInfoURL, JWKSURL and Issuer override preset endpoints.
	// AuthURL、TokenURL、UserInfoURL、JWKSURL 与 Issuer 覆盖预设端点。
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	JWKSURL     string
	Issuer      string
	// UseOIDC, PKCE and Nonce override preset flow switches. | UseOIDC、PKCE 与 Nonce 覆盖预设流程开关。
	UseOIDC bool
	PKCE    bool
	Nonce   bool
	// DiscoveryTTL, DiscoveryTTLMin, DiscoveryTTLMax, DiscoveryJitter and
	// DiscoveryMaxStale override preset discovery cache settings. | DiscoveryTTL、
	// DiscoveryTTLMin、DiscoveryTTLMax、DiscoveryJitter 与 DiscoveryMaxStale 覆盖预设发现缓存设置。
	DiscoveryTTL      time.Duration
	DiscoveryTTLMin   time.Duration
	DiscoveryTTLMax   time.Duration
	DiscoveryJitter   float64
	DiscoveryMaxStale time.Duration
	// AuthStyle overrides token endpoint client authentication. | AuthStyle 覆盖令牌端点客户端认证。
	AuthStyle string
	// PrivateKey is used by request-signing providers. | PrivateKey 供请求签名提供方使用。
	PrivateKey string
	// HTTPClient overrides the broker HTTP client. | HTTPClient 覆盖代理 HTTP 客户端。
	HTTPClient *http.Client
	// Extra carries provider-specific settings. | Extra 保存提供方专用设置。
	Extra map[string]string
	// AuthParams, TokenParams and UserInfoHeaders are additional request parameters.
	// AuthParams、TokenParams 与 UserInfoHeaders 是附加请求参数。
	AuthParams      map[string]string
	TokenParams     map[string]string
	UserInfoHeaders map[string]string
}

// ProviderOption mutates a provider while a preset is constructed. | ProviderOption 在构建预设时修改提供方。
type ProviderOption func(*Provider)

// Endpoints overrides provider endpoints, usually with httptest servers. | Endpoints
// 覆盖提供方端点，通常用于 httptest 服务器。
type Endpoints struct {
	// AuthURL overrides the authorization endpoint. | AuthURL 覆盖授权端点。
	AuthURL string
	// TokenURL overrides the token endpoint. | TokenURL 覆盖令牌端点。
	TokenURL string
	// UserInfoURL overrides the UserInfo endpoint. | UserInfoURL 覆盖 UserInfo 端点。
	UserInfoURL string
	// JWKSURL overrides the JWKS endpoint. | JWKSURL 覆盖 JWKS 端点。
	JWKSURL string
	// Issuer overrides the OIDC issuer. | Issuer 覆盖 OIDC 签发方。
	Issuer string
	// Extra merges provider-specific settings. | Extra 合并提供方专用设置。
	Extra map[string]string
}

// WithEndpoints returns an option overriding non-empty endpoints and merging Extra.
// WithEndpoints 返回覆盖非空端点并合并 Extra 的选项。
func WithEndpoints(endpoints Endpoints) ProviderOption {
	return func(p *Provider) {
		if p == nil {
			return
		}
		if endpoints.AuthURL != "" {
			p.AuthURL = endpoints.AuthURL
		}
		if endpoints.TokenURL != "" {
			p.TokenURL = endpoints.TokenURL
		}
		if endpoints.UserInfoURL != "" {
			p.UserInfoURL = endpoints.UserInfoURL
		}
		if endpoints.JWKSURL != "" {
			p.JWKSURL = endpoints.JWKSURL
		}
		if endpoints.Issuer != "" {
			p.Issuer = endpoints.Issuer
		}
		mergeExtra(p, endpoints.Extra)
	}
}

// WithHTTPClient returns an option replacing the provider HTTP client. | WithHTTPClient
// 返回替换提供方 HTTP 客户端的选项。
func WithHTTPClient(client *http.Client) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.HTTPClient = client
		}
	}
}

// WithScopes returns an option replacing the default scopes. | WithScopes 返回替换默认作用域的选项。
func WithScopes(scopes ...string) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.Scopes = append([]string(nil), scopes...)
		}
	}
}

// WithPKCE returns an option enabling or disabling PKCE. | WithPKCE 返回启用或禁用 PKCE 的选项。
func WithPKCE(enabled bool) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.PKCE = enabled
		}
	}
}

// WithNonce returns an option enabling or disabling OIDC nonce checks. | WithNonce
// 返回启用或禁用 OIDC nonce 校验的选项。
func WithNonce(enabled bool) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.Nonce = enabled
		}
	}
}

// WithExtra returns an option setting one provider-specific value. | WithExtra 返回设置单个提供方专用值的选项。
func WithExtra(key, value string) ProviderOption {
	return func(p *Provider) {
		if p == nil {
			return
		}
		if p.Extra == nil {
			p.Extra = make(map[string]string)
		}
		p.Extra[key] = value
	}
}

// WithAuthParams returns an option merging additional authorization parameters. | WithAuthParams
// 返回合并附加授权参数的选项。
func WithAuthParams(params map[string]string) ProviderOption {
	return func(p *Provider) {
		if p == nil {
			return
		}
		if p.AuthParams == nil {
			p.AuthParams = make(map[string]string)
		}
		for key, value := range params {
			p.AuthParams[key] = value
		}
	}
}

// WithAuthURLHook returns an option installing a custom authorization URL builder.
// WithAuthURLHook 返回安装自定义授权 URL 构建器的选项。
func WithAuthURLHook(hook AuthURLHook) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.AuthURLHook = hook
		}
	}
}

// WithExchangeHook returns an option installing a custom token exchange hook.
// WithExchangeHook 返回安装自定义令牌兑换钩子的选项。
func WithExchangeHook(hook ExchangeHook) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.ExchangeHook = hook
		}
	}
}

// WithUserInfoHook returns an option installing a custom UserInfo hook. | WithUserInfoHook
// 返回安装自定义 UserInfo 钩子的选项。
func WithUserInfoHook(hook UserInfoHook) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.UserInfoHook = hook
		}
	}
}

// WithAdapter returns an option installing a complete custom adapter. | WithAdapter
// 返回安装完整自定义适配器的选项。
func WithAdapter(adapter ProviderAdapter) ProviderOption {
	return func(p *Provider) {
		if p != nil {
			p.Adapter = adapter
		}
	}
}

// NewProvider builds a generic provider from config. | NewProvider 依据配置构建通用提供方。
func NewProvider(config ProviderConfig) *Provider {
	p := &Provider{
		Name:              strings.TrimSpace(config.Name),
		DisplayName:       config.DisplayName,
		Kind:              config.Kind,
		ClientID:          config.ClientID,
		ClientSecret:      config.ClientSecret,
		RedirectURL:       config.RedirectURL,
		Scopes:            append([]string(nil), config.Scopes...),
		AuthURL:           config.AuthURL,
		TokenURL:          config.TokenURL,
		UserInfoURL:       config.UserInfoURL,
		JWKSURL:           config.JWKSURL,
		Issuer:            config.Issuer,
		UseOIDC:           config.UseOIDC,
		PKCE:              config.PKCE,
		Nonce:             config.Nonce,
		DiscoveryTTL:      config.DiscoveryTTL,
		DiscoveryTTLMin:   config.DiscoveryTTLMin,
		DiscoveryTTLMax:   config.DiscoveryTTLMax,
		DiscoveryJitter:   config.DiscoveryJitter,
		DiscoveryMaxStale: config.DiscoveryMaxStale,
		AuthStyle:         config.AuthStyle,
		PrivateKey:        config.PrivateKey,
		HTTPClient:        config.HTTPClient,
		AuthParams:        cloneMap(config.AuthParams),
		TokenParams:       cloneMap(config.TokenParams),
		UserInfoHeaders:   cloneMap(config.UserInfoHeaders),
		Extra:             cloneMap(config.Extra),
	}
	if p.Kind == "" {
		if p.UseOIDC {
			p.Kind = KindOIDC
		} else {
			p.Kind = KindOAuth2
		}
	}
	return p
}

// Validate checks that a provider has the minimum fields needed by the broker. | Validate
// 检查提供方是否具有代理所需的最小字段。
func (p *Provider) Validate() error {
	if p == nil {
		return errs.Detail(ErrProviderConfig, "provider is nil | 提供方为空")
	}
	if strings.TrimSpace(p.Name) == "" {
		return errs.Detail(ErrProviderConfig, "provider name is empty | 提供方名称为空")
	}
	if p.Adapter != nil {
		return nil
	}
	if en, zh := discoverySettingsProblem(p.DiscoveryTTL, p.DiscoveryTTLMin, p.DiscoveryTTLMax, p.DiscoveryJitter); en != "" {
		return errs.Detail(ErrProviderConfig, "provider %s has invalid discovery settings: %s | 提供方 %s 的发现配置非法：%s", p.Name, en, p.Name, zh)
	}
	if p.DiscoveryTTL > 0 && p.UseOIDC && strings.TrimSpace(p.Issuer) == "" {
		return errs.Detail(ErrProviderConfig, "provider %s needs an issuer to refresh discovery | 提供方 %s 需要 issuer 才能刷新发现", p.Name, p.Name)
	}
	if p.ClientID == "" {
		return errs.Detail(ErrProviderConfig, "provider %s has no client id | 提供方 %s 缺少客户端标识", p.Name, p.Name)
	}
	discovery := p.UseOIDC && strings.TrimSpace(p.Issuer) != ""
	if p.AuthURL == "" && p.AuthURLHook == nil && !discovery {
		return errs.Detail(ErrProviderConfig, "provider %s has no authorization endpoint | 提供方 %s 缺少授权端点", p.Name, p.Name)
	}
	if p.TokenURL == "" && p.ExchangeHook == nil && !discovery {
		return errs.Detail(ErrProviderConfig, "provider %s has no token endpoint | 提供方 %s 缺少令牌端点", p.Name, p.Name)
	}
	if p.UserInfoURL == "" && p.UserInfoHook == nil && !p.UseOIDC {
		return errs.Detail(ErrProviderConfig, "provider %s has no user info endpoint | 提供方 %s 缺少用户信息端点", p.Name, p.Name)
	}
	switch p.AuthStyle {
	case "", AuthStylePost, AuthStyleBasic, AuthStyleAuto:
	default:
		return errs.Detail(ErrProviderConfig, "provider %s has invalid auth style | 提供方 %s 的认证方式非法", p.Name, p.Name)
	}
	return nil
}

// mergeExtra merges values into a provider's Extra map. | mergeExtra 把值合并到提供方的 Extra 映射。
func mergeExtra(p *Provider, values map[string]string) {
	if p == nil || len(values) == 0 {
		return
	}
	if p.Extra == nil {
		p.Extra = make(map[string]string, len(values))
	}
	for key, value := range values {
		p.Extra[key] = value
	}
}

// cloneMap returns a shallow copy of a string map. | cloneMap 返回字符串映射的浅拷贝。
func cloneMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

// applyOptions applies provider options in order. | applyOptions 按顺序应用提供方选项。
func applyOptions(p *Provider, options []ProviderOption) {
	for _, option := range options {
		if option != nil {
			option(p)
		}
	}
}
