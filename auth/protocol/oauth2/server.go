package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// Default endpoint paths. | 默认端点路径。
const (
	defaultAuthorizationPath    = "/authorize"
	defaultTokenPath            = "/token"
	defaultIntrospectionPath    = "/introspect"
	defaultRevocationPath       = "/revoke"
	defaultDeviceAuthPath       = "/device_authorization"
	defaultDeviceVerifyPath     = "/device"
	defaultPARPath              = "/par"
	defaultMetadataPath         = "/.well-known/oauth-authorization-server"
	defaultAccessTokenTTL       = 15 * time.Minute
	defaultRefreshTokenTTL      = 30 * 24 * time.Hour
	defaultDeviceCodeTTL        = 10 * time.Minute
	defaultDeviceInterval       = 5 * time.Second
	defaultPARTTL               = 60 * time.Second
	defaultAuthorizationCodeTTL = 5 * time.Minute
)

// AccessTokenClaims is the RFC 9068 JWT access-token claim set. | AccessTokenClaims 是 RFC 9068 JWT 访问令牌声明集。
type AccessTokenClaims struct {
	// Issuer is the iss claim. | Issuer 是 iss 声明。
	Issuer string `json:"iss"`
	// Subject is the sub claim. | Subject 是 sub 声明。
	Subject string `json:"sub"`
	// Audience is the aud claim. | Audience 是 aud 声明。
	Audience []string `json:"aud,omitempty"`
	// ExpiresAt is the expiry NumericDate. | ExpiresAt 是过期 NumericDate。
	ExpiresAt int64 `json:"exp"`
	// IssuedAt is the issue NumericDate. | IssuedAt 是签发 NumericDate。
	IssuedAt int64 `json:"iat"`
	// NotBefore is the not-before NumericDate. | NotBefore 是生效前 NumericDate。
	NotBefore int64 `json:"nbf,omitempty"`
	// JTI is the token identifier. | JTI 是令牌标识。
	JTI string `json:"jti"`
	// ClientID is the client_id claim. | ClientID 是 client_id 声明。
	ClientID string `json:"client_id"`
	// Scope is the space-delimited scope. | Scope 是空格分隔作用域。
	Scope string `json:"scope,omitempty"`
	// AuthTime is the end-user authentication time. | AuthTime 是最终用户认证时间。
	AuthTime int64 `json:"auth_time,omitempty"`
	// ACR is the authentication context class reference. | ACR 是认证上下文类引用。
	ACR string `json:"acr,omitempty"`
	// AMR lists the authentication methods. | AMR 列出认证方法。
	AMR []string `json:"amr,omitempty"`
	// CNF is the confirmation claim for sender-constrained tokens. | CNF 是发送方约束令牌的确认声明。
	CNF map[string]any `json:"cnf,omitempty"`
}

// JWTIssuer signs RFC 9068 access tokens. | JWTIssuer 签发 RFC 9068 访问令牌。
type JWTIssuer interface {
	// SignAccessToken returns a compact JWS for claims. | SignAccessToken 返回 claims 的紧凑 JWS。
	SignAccessToken(ctx context.Context, claims *AccessTokenClaims) (string, error)
}

// AccessTokenVerifier verifies RFC 9068 access tokens. | AccessTokenVerifier 校验 RFC 9068 访问令牌。
type AccessTokenVerifier interface {
	// VerifyAccessToken returns the verified claim set. | VerifyAccessToken 返回已校验声明集。
	VerifyAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error)
}

// ClientAssertionVerifier verifies RFC 7523 private_key_jwt assertions. client_secret_jwt is
// verified separately by ClientSecretJWTVerifier through ServerConfig.ClientSecretJWT, because
// clients store only a secret hash and the plaintext must come from a deployment resolver. |
// ClientAssertionVerifier 校验 RFC 7523 private_key_jwt 断言。client_secret_jwt 由
// ClientSecretJWTVerifier 经 ServerConfig.ClientSecretJWT 单独校验，因为客户端只保存密钥哈希，
// 明文必须来自部署方解析器。
type ClientAssertionVerifier interface {
	// VerifyClientAssertion verifies assertion for client at audience. | VerifyClientAssertion 在 audience 处为 client 校验 assertion。
	VerifyClientAssertion(ctx context.Context, client *Client, assertion, audience string) error
}

// DPoPVerifier verifies RFC 9449 proofs. | DPoPVerifier 校验 RFC 9449 证明。
type DPoPVerifier interface {
	// VerifyProof validates proof for method and target, returning the JWK thumbprint. | VerifyProof 为 method 与 target 校验 proof，返回 JWK 指纹。
	VerifyProof(ctx context.Context, proof, method, target, accessToken string) (string, error)
}

// PasswordAuthenticator verifies resource-owner credentials for the legacy password grant. | PasswordAuthenticator
// 为旧式口令授权校验资源所有者凭据。
type PasswordAuthenticator interface {
	// AuthenticatePassword returns the principal for username and password. | AuthenticatePassword 返回 username 与 password 的主体。
	AuthenticatePassword(ctx context.Context, username, password string) (*auth.Principal, error)
}

// SubjectTokenValidator validates RFC 8693 subject tokens. | SubjectTokenValidator 校验 RFC 8693 主体令牌。
type SubjectTokenValidator interface {
	// ValidateSubjectToken returns the principal represented by token. | ValidateSubjectToken 返回 token 代表的主体。
	ValidateSubjectToken(ctx context.Context, tokenType, token string) (*auth.Principal, error)
}

// JWTBearerValidator validates RFC 7523 JWT bearer assertions. | JWTBearerValidator 校验 RFC 7523 JWT 承载断言。
type JWTBearerValidator interface {
	// ValidateJWTBearer returns the principal represented by assertion. | ValidateJWTBearer 返回 assertion 代表的主体。
	ValidateJWTBearer(ctx context.Context, assertion string) (*auth.Principal, error)
}

// Grant is the normalized authorization context shared by token issuance and enrichers. | Grant
// 是令牌签发与增强器共享的规范化授权上下文。
type Grant struct {
	// Client is the requesting client. | Client 是请求客户端。
	Client *Client
	// Principal is the resource owner; nil for client-credentials grants. | Principal 是资源所有者；客户端凭据授权为空。
	Principal *auth.Principal
	// UserID is the local resource-owner identifier. | UserID 是本地资源所有者标识。
	UserID string
	// Subject is the authorization-server subject. | Subject 是授权服务器主体。
	Subject string
	// Scopes are the granted scopes. | Scopes 是已授予作用域。
	Scopes []string
	// Audience lists the resource indicators. | Audience 列出资源指示器。
	Audience []string
	// AuthTime is the authentication time. | AuthTime 是认证时间。
	AuthTime time.Time
	// ACR is the authentication context class reference. | ACR 是认证上下文类引用。
	ACR string
	// AMR lists the authentication methods. | AMR 列出认证方法。
	AMR []string
	// SessionID identifies the authentication session. | SessionID 标识认证会话。
	SessionID string
	// Nonce is the OpenID Connect nonce. | Nonce 是 OpenID Connect nonce。
	Nonce string
	// ResponseType is the authorization response type. | ResponseType 是授权响应类型。
	ResponseType string
	// Code is the redeemed authorization code, when any. | Code 是已兑换的授权码（如有）。
	Code *AuthorizationCode
	// RefreshToken is the redeemed refresh token, when any. | RefreshToken 是已兑换的刷新令牌（如有）。
	RefreshToken *RefreshToken
	// DPoPJKT binds the issued tokens to a DPoP key. | DPoPJKT 把签发的令牌绑定到 DPoP 密钥。
	DPoPJKT string
	// CertThumbprint binds the issued tokens to a client certificate. | CertThumbprint 把签发的令牌绑定到客户端证书。
	CertThumbprint string
	// GrantID identifies the authorization grant family. | GrantID 标识授权许可家族。
	GrantID string
	// IssuedAt is the issuance time. | IssuedAt 是签发时间。
	IssuedAt time.Time
	// Claims is the OpenID Connect claims request. | Claims 是 OpenID Connect 声明请求。
	Claims string
	// Extra carries extension data between the server and enrichers. | Extra 在服务器与增强器之间携带扩展数据。
	Extra map[string]any
}

// TokenEnricher adds protocol-specific token response fields such as an ID token. | TokenEnricher
// 添加 ID 令牌等协议相关令牌响应字段。
type TokenEnricher interface {
	// EnrichToken is called after access and refresh tokens are issued. | EnrichToken 在访问与刷新令牌签发后调用。
	EnrichToken(ctx context.Context, grant *Grant, response *TokenResponse) error
}

// AuthorizationEnricher adds protocol-specific authorization response parameters. | AuthorizationEnricher
// 添加协议相关的授权响应参数。
type AuthorizationEnricher interface {
	// EnrichAuthorization is called before the authorization response is written. | EnrichAuthorization 在写入授权响应前调用。
	EnrichAuthorization(ctx context.Context, grant *Grant, params url.Values) error
}

// ServerConfig configures Server. | ServerConfig 配置 Server。
type ServerConfig struct {
	// Issuer is the absolute authorization-server identifier; a path component becomes the default
	// mount prefix. | Issuer 是绝对授权服务器标识；路径部分会成为默认挂载前缀。
	Issuer string
	// PathPrefix is the mount prefix; empty derives it from Issuer's path. | PathPrefix 是挂载前缀；空值从 Issuer 路径推导。
	PathPrefix string
	// AuthorizationPath overrides the authorization endpoint path. | AuthorizationPath 覆盖授权端点路径。
	AuthorizationPath string
	// TokenPath overrides the token endpoint path. | TokenPath 覆盖令牌端点路径。
	TokenPath string
	// IntrospectionPath overrides the introspection endpoint path. | IntrospectionPath 覆盖自省端点路径。
	IntrospectionPath string
	// RevocationPath overrides the revocation endpoint path. | RevocationPath 覆盖撤销端点路径。
	RevocationPath string
	// DeviceAuthorizationPath overrides the device authorization endpoint path. | DeviceAuthorizationPath 覆盖设备授权端点路径。
	DeviceAuthorizationPath string
	// DeviceVerificationPath overrides the device verification page path. | DeviceVerificationPath 覆盖设备验证页路径。
	DeviceVerificationPath string
	// PARPath overrides the pushed authorization request endpoint path. | PARPath 覆盖推送授权请求端点路径。
	PARPath string
	// MetadataPath overrides the authorization-server metadata path. | MetadataPath 覆盖授权服务器元数据路径。
	MetadataPath string
	// JWKSURI is published in metadata for JWT access tokens and ID tokens. | JWKSURI 在元数据中发布，用于 JWT 访问令牌与 ID 令牌。
	JWKSURI string
	// RegistrationEndpoint is published when dynamic registration exists. | RegistrationEndpoint 在存在动态注册时发布。
	RegistrationEndpoint string
	// Clients stores client registrations. | Clients 存储客户端注册。
	Clients ClientStore
	// Store stores grants and tokens. | Store 存储许可与令牌。
	Store Store
	// Scopes is the scope registry; nil uses DefaultScopes. | Scopes 是作用域注册表；空值使用 DefaultScopes。
	Scopes ScopeRegistry
	// Authenticator resolves the resource owner. | Authenticator 解析资源所有者。
	Authenticator Authenticator
	// Consent decides scope grants; nil grants the requested scopes automatically. | Consent 决定作用域授予；空值自动授予请求作用域。
	Consent ConsentHandler
	// LoginURL receives an unauthenticated browser with a return_to parameter. | LoginURL 接收带 return_to 参数的未认证浏览器。
	LoginURL string
	// LoginHandler can render a login page directly instead of redirecting. | LoginHandler 可直接渲染登录页而无需跳转。
	LoginHandler http.HandlerFunc
	// TokenFormat selects opaque or JWT access tokens. | TokenFormat 选择不透明或 JWT 访问令牌。
	TokenFormat string
	// AccessTokenTTL overrides the access-token lifetime. | AccessTokenTTL 覆盖访问令牌寿命。
	AccessTokenTTL time.Duration
	// RefreshTokenTTL overrides the refresh-token lifetime. | RefreshTokenTTL 覆盖刷新令牌寿命。
	RefreshTokenTTL time.Duration
	// AuthorizationCodeTTL overrides the authorization-code lifetime. | AuthorizationCodeTTL 覆盖授权码寿命。
	AuthorizationCodeTTL time.Duration
	// DeviceCodeTTL overrides the device-code lifetime. | DeviceCodeTTL 覆盖设备码寿命。
	DeviceCodeTTL time.Duration
	// DeviceInterval overrides the device polling interval. | DeviceInterval 覆盖设备轮询间隔。
	DeviceInterval time.Duration
	// PARTTL overrides the pushed authorization request lifetime. | PARTTL 覆盖推送授权请求寿命。
	PARTTL time.Duration
	// DisableIssuerParameter suppresses the RFC 9207 iss response parameter. | DisableIssuerParameter 关闭 RFC 9207 iss 响应参数。
	DisableIssuerParameter bool
	// AllowImplicit enables response_type=token. | AllowImplicit 启用 response_type=token。
	AllowImplicit bool
	// AllowPasswordGrant enables the deprecated password grant. | AllowPasswordGrant 启用已弃用的口令授权。
	AllowPasswordGrant bool
	// DisableDeviceFlow disables the RFC 8628 endpoints. | DisableDeviceFlow 禁用 RFC 8628 端点。
	DisableDeviceFlow bool
	// EnableTokenExchange enables RFC 8693. | EnableTokenExchange 启用 RFC 8693。
	EnableTokenExchange bool
	// EnableJWTBearer enables RFC 7523. | EnableJWTBearer 启用 RFC 7523。
	EnableJWTBearer bool
	// DisablePKCEEnforcement allows authorization-code requests without PKCE. | DisablePKCEEnforcement 允许无 PKCE 的授权码请求。
	DisablePKCEEnforcement bool
	// AllowPKCEPlain permits the deprecated plain code-challenge method. | AllowPKCEPlain 允许已弃用的明文挑战方法。
	AllowPKCEPlain bool
	// RefreshTokenRotationDisabled issues reusable refresh tokens instead of rotating them. | RefreshTokenRotationDisabled 签发可重复使用的刷新令牌而不轮换。
	RefreshTokenRotationDisabled bool
	// DPoPRequired rejects tokens that are not DPoP-bound. | DPoPRequired 拒绝未绑定 DPoP 的令牌。
	DPoPRequired bool
	// DPoPVerifier verifies proofs; required when DPoPRequired is set or a client sends DPoP. | DPoPVerifier 校验证明；DPoPRequired 或客户端发送 DPoP 时必填。
	DPoPVerifier DPoPVerifier
	// DPoPNonceStore issues nonces for successful DPoP token responses and is pruned by periodic
	// cleanup. When nil, a DPoPVerifier implementing DPoPNonceIssuer (including
	// *DPoPProofVerifier) supplies and prunes its own nonces. | DPoPNonceStore 为成功的 DPoP 令牌
	// 响应签发 nonce，并由周期清理剪除。空值时，实现了 DPoPNonceIssuer 的 DPoPVerifier（包括
	// *DPoPProofVerifier）自行签发与剪除 nonce。
	DPoPNonceStore DPoPNonceStore
	// ClientAssertionVerifier verifies private_key_jwt authentication. | ClientAssertionVerifier
	// 校验 private_key_jwt 认证。
	ClientAssertionVerifier ClientAssertionVerifier
	// ClientSecretJWT enables RFC 7523 client_secret_jwt authentication when non-nil. The
	// verifier needs a ClientSecretResolver because Client.SecretHash only stores a one-way hash.
	// A nil value keeps client_secret_jwt rejected. | ClientSecretJWT 非空时启用 RFC 7523
	// client_secret_jwt 认证。校验器需要 ClientSecretResolver，因为 Client.SecretHash 只保存
	// 单向哈希。空值继续拒绝 client_secret_jwt。
	ClientSecretJWT *ClientSecretJWTConfig
	// AccessTokenIssuer signs JWT access tokens. | AccessTokenIssuer 签发 JWT 访问令牌。
	AccessTokenIssuer JWTIssuer
	// AccessTokenVerifier verifies JWT access tokens for resource-server helpers. | AccessTokenVerifier 为资源服务器辅助函数校验 JWT 访问令牌。
	AccessTokenVerifier AccessTokenVerifier
	// TokenEnricher adds ID tokens and other response fields. | TokenEnricher 添加 ID 令牌等响应字段。
	TokenEnricher TokenEnricher
	// AuthorizationEnricher adds authorization response parameters. | AuthorizationEnricher 添加授权响应参数。
	AuthorizationEnricher AuthorizationEnricher
	// RequestObjects enables RFC 9101 signed request objects at the authorization and PAR
	// endpoints. | RequestObjects 在授权与 PAR 端点启用 RFC 9101 已签名请求对象。
	RequestObjects RequestObjectConfig
	// RequestURIs enables RFC 9101 by-reference request objects. | RequestURIs 启用 RFC 9101 按引用
	// 传递的请求对象。
	RequestURIs RequestURIConfig
	// AuthorizationResponseSigner enables the JARM response modes (RFC 9101 companion document).
	// | AuthorizationResponseSigner 启用 JARM 响应模式（RFC 9101 配套文档）。
	AuthorizationResponseSigner AuthorizationResponseSigner
	// PasswordAuthenticator verifies the legacy password grant. | PasswordAuthenticator 校验旧式口令授权。
	PasswordAuthenticator PasswordAuthenticator
	// SubjectTokenValidator validates token-exchange subject tokens. | SubjectTokenValidator 校验令牌交换主体令牌。
	SubjectTokenValidator SubjectTokenValidator
	// JWTBearerValidator validates JWT-bearer assertions. | JWTBearerValidator 校验 JWT 承载断言。
	JWTBearerValidator JWTBearerValidator
	// AllowedResources restricts resource indicators; empty allows every validated absolute URI. | AllowedResources 限制资源指示器；空值允许每个合法绝对 URI。
	AllowedResources []string
	// DefaultAudience is used when a request carries no resource indicator. | DefaultAudience 在请求无资源指示器时使用。
	DefaultAudience []string
	// AllowCrossClientIntrospection lets a client inspect tokens issued to other clients. | AllowCrossClientIntrospection 允许客户端自省签发给其他客户端的令牌。
	AllowCrossClientIntrospection bool
	// ErrorHandler renders unexpected handler failures. | ErrorHandler 渲染处理器意外失败。
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
	// Logger receives operational warnings. | Logger 接收运行告警。
	Logger *log.Logger
	// Clock overrides time for tests. | Clock 为测试替换时间。
	Clock func() time.Time
}

// Server is an OAuth 2.1 authorization server. | Server 是 OAuth 2.1 授权服务器。
type Server struct {
	config         ServerConfig
	now            func() time.Time
	requestObjects *requestObjectVerifier
	requestURIs    *requestURICache
	// issuerOrigin is the scheme and authority of Issuer, used to build endpoint URLs without
	// repeating an issuer path that already became PathPrefix. | issuerOrigin 是 Issuer 的协议与
	// 主机部分，用于构建端点 URL 时不重复已成为 PathPrefix 的 issuer 路径。
	issuerOrigin string
	// clientSecretJWT verifies RFC 7523 client_secret_jwt assertions; nil keeps the method
	// disabled. | clientSecretJWT 校验 RFC 7523 client_secret_jwt 断言；空值使该方法保持禁用。
	clientSecretJWT *ClientSecretJWTVerifier
	// cleanupMu guards the cleanup scheduler handles below. | cleanupMu 保护下方的清理调度句柄。
	cleanupMu sync.Mutex
	// cleanupCancel stops the periodic cleanup goroutine. | cleanupCancel 停止周期清理协程。
	cleanupCancel context.CancelFunc
	// cleanupDone closes when the periodic cleanup goroutine exits. | cleanupDone 在周期清理协程退出时关闭。
	cleanupDone chan struct{}
}

// NewServer returns a Server. | NewServer 返回 Server。
func NewServer(config ServerConfig) (*Server, error) {
	issuer := strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	if issuer == "" {
		return nil, errs.Detail(ErrInvalidConfig, "issuer is empty | issuer 为空")
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
		return nil, errs.Detail(ErrInvalidConfig, "issuer must be an absolute URL | issuer 必须是绝对 URL")
	}
	config.Issuer = issuer
	if config.PathPrefix == "" && parsed.Path != "" && parsed.Path != "/" {
		config.PathPrefix = strings.TrimRight(parsed.Path, "/")
	}
	config.PathPrefix = strings.TrimRight(config.PathPrefix, "/")
	if config.PathPrefix != "" && !strings.HasPrefix(config.PathPrefix, "/") {
		// A relative-looking prefix would otherwise concatenate into a host-like mux pattern. |
		// 相对形式的挂载前缀会拼接成类似主机名的多路复用模式。
		config.PathPrefix = "/" + config.PathPrefix
	}
	if config.Clients == nil {
		return nil, errs.Detail(ErrInvalidConfig, "client store is nil | 客户端存储为空")
	}
	if config.Store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "store is nil | 存储为空")
	}
	if config.Scopes == nil {
		config.Scopes = DefaultScopes()
	}
	if config.TokenFormat == "" {
		config.TokenFormat = TokenFormatOpaque
	}
	if config.TokenFormat != TokenFormatOpaque && config.TokenFormat != TokenFormatJWT {
		return nil, errs.Detail(ErrInvalidConfig, "unknown token format %[1]q | 未知令牌格式 %[1]q", config.TokenFormat)
	}
	if config.TokenFormat == TokenFormatJWT && (config.AccessTokenIssuer == nil || config.AccessTokenVerifier == nil) {
		return nil, errs.Detail(ErrInvalidConfig, "JWT token format needs an issuer and verifier | JWT 令牌格式需要签发器与校验器")
	}
	if config.DPoPRequired && config.DPoPVerifier == nil {
		return nil, errs.Detail(ErrInvalidConfig, "DPoP required without verifier | 要求 DPoP 但未提供校验器")
	}
	if config.AccessTokenTTL <= 0 {
		config.AccessTokenTTL = defaultAccessTokenTTL
	}
	if config.RefreshTokenTTL <= 0 {
		config.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if config.AuthorizationCodeTTL <= 0 {
		config.AuthorizationCodeTTL = defaultAuthorizationCodeTTL
	}
	if config.DeviceCodeTTL <= 0 {
		config.DeviceCodeTTL = defaultDeviceCodeTTL
	}
	if config.DeviceInterval <= 0 {
		config.DeviceInterval = defaultDeviceInterval
	}
	if config.PARTTL <= 0 {
		config.PARTTL = defaultPARTTL
	}
	setDefaultPath(&config.AuthorizationPath, defaultAuthorizationPath)
	setDefaultPath(&config.TokenPath, defaultTokenPath)
	setDefaultPath(&config.IntrospectionPath, defaultIntrospectionPath)
	setDefaultPath(&config.RevocationPath, defaultRevocationPath)
	setDefaultPath(&config.DeviceAuthorizationPath, defaultDeviceAuthPath)
	setDefaultPath(&config.DeviceVerificationPath, defaultDeviceVerifyPath)
	setDefaultPath(&config.PARPath, defaultPARPath)
	setDefaultPath(&config.MetadataPath, defaultMetadataPath)
	if config.RequestURIs.Enabled && !config.RequestURIs.RequireRegistration && len(config.RequestURIs.AllowedHosts) == 0 {
		// Without registration or an allow list any host could be fetched, which turns the
		// authorization endpoint into an SSRF primitive. | 没有注册或白名单时可抓取任意主机，
		// 会把授权端点变成 SSRF 原语。
		return nil, errs.Detail(ErrInvalidConfig, "external request_uri needs request_uris registration or allowed hosts | 外部 request_uri 需要注册或主机白名单")
	}
	var clientSecretJWT *ClientSecretJWTVerifier
	if config.ClientSecretJWT != nil {
		secretConfig := *config.ClientSecretJWT
		if secretConfig.Now == nil && config.Clock != nil {
			secretConfig.Now = config.Clock
		}
		verifier, err := NewClientSecretJWTVerifier(secretConfig)
		if err != nil {
			return nil, err
		}
		clientSecretJWT = verifier
	}
	server := &Server{config: config, now: config.Clock, issuerOrigin: parsed.Scheme + "://" + parsed.Host, clientSecretJWT: clientSecretJWT}
	if server.now == nil {
		server.now = time.Now
	}
	server.requestObjects = newRequestObjectVerifier(config.RequestObjects, nil, server.now)
	server.requestURIs = newRequestURICache(config.RequestURIs, server.now)
	return server, nil
}

// SetAuthorizationResponseSigner installs the JARM signer after construction. | SetAuthorizationResponseSigner
// 在构造后安装 JARM 签名器。
func (s *Server) SetAuthorizationResponseSigner(signer AuthorizationResponseSigner) {
	if s == nil {
		return
	}
	s.config.AuthorizationResponseSigner = signer
}

// setDefaultPath fills an empty path and ensures a leading slash. | setDefaultPath 填充空路径并保证前导斜杠。
func setDefaultPath(target *string, fallback string) {
	if *target == "" {
		*target = fallback
	}
	if !strings.HasPrefix(*target, "/") {
		*target = "/" + *target
	}
}

// Config returns the normalized configuration. | Config 返回规范化配置。
func (s *Server) Config() ServerConfig { return s.config }

// SetTokenEnricher installs a token-response enricher. | SetTokenEnricher 安装令牌响应增强器。
//
// It is intended for protocol composition during startup, before the server serves requests. | 它用于
// 启动期的协议组合，应在服务器开始处理请求前调用。
func (s *Server) SetTokenEnricher(enricher TokenEnricher) { s.config.TokenEnricher = enricher }

// SetAuthorizationEnricher installs an authorization-response enricher. | SetAuthorizationEnricher 安装授权响应增强器。
func (s *Server) SetAuthorizationEnricher(enricher AuthorizationEnricher) {
	s.config.AuthorizationEnricher = enricher
}

// SetAuthenticator replaces the resource-owner authenticator. | SetAuthenticator 替换资源所有者认证器。
func (s *Server) SetAuthenticator(authenticator Authenticator) {
	s.config.Authenticator = authenticator
}

// SetConsentHandler replaces the consent handler. | SetConsentHandler 替换同意处理器。
func (s *Server) SetConsentHandler(consent ConsentHandler) { s.config.Consent = consent }

// SetDPoPVerifier replaces the DPoP proof verifier. | SetDPoPVerifier 替换 DPoP 证明校验器。
func (s *Server) SetDPoPVerifier(verifier DPoPVerifier) { s.config.DPoPVerifier = verifier }

// SetJWKSURI publishes a JWK Set URI in metadata. | SetJWKSURI 在元数据中发布 JWK Set URI。
func (s *Server) SetJWKSURI(uri string) { s.config.JWKSURI = uri }

// SetRegistrationEndpoint publishes a dynamic-registration endpoint in metadata. | SetRegistrationEndpoint
// 在元数据中发布动态注册端点。
func (s *Server) SetRegistrationEndpoint(endpoint string) {
	s.config.RegistrationEndpoint = endpoint
}

// Now returns the current time in UTC. | Now 返回当前 UTC 时间。
func (s *Server) Now() time.Time { return s.now().UTC() }

// Issuer returns the issuer identifier. | Issuer 返回签发方标识。
func (s *Server) Issuer() string { return s.config.Issuer }

// Path returns the mounted path for the unprefixed endpoint path p. | Path 返回未加前缀的端点路径 p
// 的挂载路径。
func (s *Server) Path(p string) string {
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if s.config.PathPrefix == "" {
		return p
	}
	return s.config.PathPrefix + p
}

// Endpoint returns the absolute URL for an endpoint path that does not include the mount prefix.
// It combines the issuer scheme and host with Path(p). Path returns the mounted path, so callers
// must pass a configured endpoint path such as ServerConfig.TokenPath and must never call
// Endpoint(Path(p)), which would apply the prefix twice. | Endpoint 返回未包含挂载前缀的端点路径的
// 绝对 URL。它把 issuer 的协议与主机部分与 Path(p) 组合。Path 返回挂载后的路径，因此调用方必须
// 传入配置中的端点路径（例如 ServerConfig.TokenPath），且绝不能调用 Endpoint(Path(p))，否则前缀
// 会被应用两次。
func (s *Server) Endpoint(p string) string { return s.issuerOrigin + s.Path(p) }

// ClientSecretJWTEnabled reports whether RFC 7523 client_secret_jwt authentication is enabled. |
// ClientSecretJWTEnabled 报告是否启用 RFC 7523 client_secret_jwt 认证。
func (s *Server) ClientSecretJWTEnabled() bool {
	return s != nil && s.clientSecretJWT != nil
}

// ClientSecretJWTRegistrarEnabled reports whether dynamic registration can persist an issued
// client_secret_jwt secret. It is false when the method is disabled or no registrar is
// configured. | ClientSecretJWTRegistrarEnabled 报告动态注册能否保存签发的 client_secret_jwt
// 密钥。方法被禁用或未配置注册器时为 false。
func (s *Server) ClientSecretJWTRegistrarEnabled() bool {
	return s != nil && s.clientSecretJWT != nil && s.clientSecretJWT.config.Registrar != nil
}

// ClientSecretJWTSigningAlgs returns the accepted client_secret_jwt signing algorithms, or nil
// when the method is disabled. | ClientSecretJWTSigningAlgs 返回接受的 client_secret_jwt 签名算法；
// 方法被禁用时返回空。
func (s *Server) ClientSecretJWTSigningAlgs() []string {
	if s == nil || s.clientSecretJWT == nil {
		return nil
	}
	return s.clientSecretJWT.SigningAlgs()
}

// RegisterClientSecret persists a secret issued by dynamic registration through the configured
// ClientSecretRegistrar. It returns ErrClientSecretJWTDisabled when the method is disabled and an
// ErrInvalidConfig detail when no registrar is configured. | RegisterClientSecret 通过已配置的
// ClientSecretRegistrar 保存动态注册签发的密钥。方法被禁用时返回 ErrClientSecretJWTDisabled，
// 未配置注册器时返回 ErrInvalidConfig 细节。
func (s *Server) RegisterClientSecret(ctx context.Context, clientID, secret string) error {
	if s == nil || s.clientSecretJWT == nil {
		return ErrClientSecretJWTDisabled
	}
	registrar := s.clientSecretJWT.config.Registrar
	if registrar == nil {
		return errs.Detail(ErrInvalidConfig, "client_secret_jwt registration needs a secret registrar | client_secret_jwt 注册需要密钥注册器")
	}
	if err := registrar.RegisterClientSecret(ctx, clientID, secret); err != nil {
		return errs.WrapDetail(err, ErrServerError, "client secret registrar failed | 客户端密钥注册器失败")
	}
	return nil
}

// maxFormBodyBytes limits form-encoded endpoint bodies. | maxFormBodyBytes 限制表单编码的端点正文。
const maxFormBodyBytes = 1 << 20

// limitFormBody caps the request body before ParseForm reads it. | limitFormBody 在 ParseForm 读取之前
// 限制请求正文大小。
func limitFormBody(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Body == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
}

// Register mounts every endpoint on a ydx/router Router. | Register 把所有端点挂载到 ydx/router Router。
func (s *Server) Register(r *router.Router) {
	if r == nil {
		return
	}
	r.HandleRaw(http.MethodGet, s.Path(s.config.AuthorizationPath), s.Authorize)
	r.HandleRaw(http.MethodPost, s.Path(s.config.AuthorizationPath), s.Authorize)
	r.HandleRaw(http.MethodPost, s.Path(s.config.TokenPath), s.Token)
	r.HandleRaw(http.MethodPost, s.Path(s.config.IntrospectionPath), s.Introspect)
	r.HandleRaw(http.MethodPost, s.Path(s.config.RevocationPath), s.Revoke)
	r.HandleRaw(http.MethodGet, s.Path(s.config.MetadataPath), s.Metadata)
	if !s.config.DisableDeviceFlow {
		r.HandleRaw(http.MethodPost, s.Path(s.config.DeviceAuthorizationPath), s.DeviceAuthorization)
		r.HandleRaw(http.MethodGet, s.Path(s.config.DeviceVerificationPath), s.DeviceVerification)
		r.HandleRaw(http.MethodPost, s.Path(s.config.DeviceVerificationPath), s.DeviceVerification)
	}
	r.HandleRaw(http.MethodPost, s.Path(s.config.PARPath), s.PAR)
}

// HTTPHandler returns a complete net/http handler for every endpoint. | HTTPHandler 返回包含所有端点的 net/http 处理器。
func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.Path(s.config.AuthorizationPath), s.Authorize)
	mux.HandleFunc(s.Path(s.config.TokenPath), s.Token)
	mux.HandleFunc(s.Path(s.config.IntrospectionPath), s.Introspect)
	mux.HandleFunc(s.Path(s.config.RevocationPath), s.Revoke)
	mux.HandleFunc(s.Path(s.config.MetadataPath), s.Metadata)
	if !s.config.DisableDeviceFlow {
		mux.HandleFunc(s.Path(s.config.DeviceAuthorizationPath), s.DeviceAuthorization)
		mux.HandleFunc(s.Path(s.config.DeviceVerificationPath), s.DeviceVerification)
	}
	mux.HandleFunc(s.Path(s.config.PARPath), s.PAR)
	return mux
}

// writeJSON writes a no-store JSON response. | writeJSON 写入禁止缓存的 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// writeOAuthError renders an OAuth error. | writeOAuthError 渲染 OAuth 错误。
func (s *Server) writeOAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var nonceErr *DPoPNonceRequiredError
	if errors.As(err, &nonceErr) {
		if nonceErr.Nonce != "" {
			w.Header().Set(DPoPNonceHeader, nonceErr.Nonce)
		}
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		writeJSON(w, http.StatusBadRequest, NewError(ErrorUseDPoPNonce, "a fresh DPoP nonce is required | 需要新的 DPoP nonce"))
		return
	}
	if s.config.ErrorHandler != nil && !isOAuthError(err) {
		s.config.ErrorHandler(w, r, err)
		return
	}
	oauthErr := normalizeError(err)
	if oauthErr.Code == ErrorInvalidClient {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
	}
	writeJSON(w, oauthErr.Status, oauthErr)
}

// isOAuthError reports whether err is an *Error. | isOAuthError 报告 err 是否为 *Error。
func isOAuthError(err error) bool {
	var target *Error
	return errors.As(err, &target)
}

// normalizeError maps any error to an *Error without leaking internals. | normalizeError 把任意错误映射为不泄露内部细节的 *Error。
func normalizeError(err error) *Error {
	if err == nil {
		return NewError(ErrorServerError, "server error | 服务器错误")
	}
	var oauthErr *Error
	if errors.As(err, &oauthErr) {
		return oauthErr
	}
	switch {
	case errors.Is(err, ErrInvalidRequest):
		return NewError(ErrorInvalidRequest, "invalid request | 请求非法")
	case errors.Is(err, ErrInvalidGrant):
		// Credential rejections wrapped as invalid_grant (for example the password grant) must win
		// over the generic auth.ErrUnauthorized bucket below. | 被包装为 invalid_grant 的凭据拒绝
		// （例如口令授权）必须优先于下面通用的 auth.ErrUnauthorized 分支。
		return NewError(ErrorInvalidGrant, "invalid grant | 授权许可无效")
	case errors.Is(err, ErrInvalidClient), errors.Is(err, auth.ErrUnauthorized):
		return NewError(ErrorInvalidClient, "client authentication failed | 客户端认证失败")
	case errors.Is(err, auth.ErrSessionExpired), errors.Is(err, auth.ErrSessionRevoked):
		return NewError(ErrorInvalidGrant, "invalid grant | 授权许可无效")
	case errors.Is(err, ErrUnauthorizedClient):
		return NewError(ErrorUnauthorizedClient, "client is not authorized for this grant | 客户端无权使用该授权")
	case errors.Is(err, ErrUnsupportedGrantType):
		return NewError(ErrorUnsupportedGrantType, "unsupported grant type | 不支持的授权类型")
	case errors.Is(err, ErrUnsupportedResponseType):
		return NewError(ErrorUnsupportedResponseType, "unsupported response type | 不支持的响应类型")
	case errors.Is(err, ErrInvalidScope):
		return NewError(ErrorInvalidScope, "invalid scope | 作用域无效")
	case errors.Is(err, ErrAccessDenied):
		return NewError(ErrorAccessDenied, "access denied | 访问被拒绝")
	case errors.Is(err, ErrLoginRequired):
		return NewError(ErrorLoginRequired, "login is required | 需要登录")
	case errors.Is(err, ErrConsentRequired):
		return NewError(ErrorConsentRequired, "consent is required | 需要授权同意")
	case errors.Is(err, ErrDPoPNonceRequired):
		return NewError(ErrorUseDPoPNonce, "a fresh DPoP nonce is required | 需要新的 DPoP nonce")
	case errors.Is(err, ErrInvalidDPoPProof):
		return NewError(ErrorInvalidDPoPProof, "invalid DPoP proof | DPoP 证明无效")
	case errors.Is(err, ErrInvalidTarget):
		return NewError(ErrorInvalidTarget, "invalid target resource | 目标资源无效")
	default:
		return NewError(ErrorServerError, "server error | 服务器错误")
	}
}

// ValidateAccessToken validates an opaque or JWT access token. | ValidateAccessToken 校验不透明或 JWT 访问令牌。
func (s *Server) ValidateAccessToken(ctx context.Context, raw string) (*AccessToken, error) {
	if raw == "" {
		return nil, ErrInvalidGrant
	}
	if s.config.TokenFormat == TokenFormatJWT {
		claims, err := s.config.AccessTokenVerifier.VerifyAccessToken(ctx, raw)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidGrant)
		}
		stored, err := s.config.Store.GetAccessToken(ctx, auth.HashToken(raw))
		switch {
		case err == nil:
			if stored == nil || stored.Revoked {
				return nil, ErrInvalidGrant
			}
		case errors.Is(err, ErrInvalidGrant):
			// A verified JWT that the store never tracked stays valid, matching stateless issuers.
			// Any other store failure must fail closed so a revoked token cannot survive an outage. |
			// 存储从未记录但已校验的 JWT 保持有效，以兼容无状态签发方。其他存储故障必须失败关闭，
			// 避免撤销的令牌在故障期间继续有效。
		default:
			return nil, errs.Wrap(err, ErrInvalidGrant)
		}
		token := &AccessToken{
			TokenHash:      auth.HashToken(raw),
			ClientID:       claims.ClientID,
			Subject:        claims.Subject,
			Scopes:         ParseScope(claims.Scope),
			Audience:       append([]string(nil), claims.Audience...),
			ACR:            claims.ACR,
			AMR:            append([]string(nil), claims.AMR...),
			IssuedAt:       time.Unix(claims.IssuedAt, 0).UTC(),
			ExpiresAt:      time.Unix(claims.ExpiresAt, 0).UTC(),
			JTI:            claims.JTI,
			DPoPJKT:        cnfString(claims.CNF, "jkt"),
			CertThumbprint: cnfString(claims.CNF, "x5t#S256"),
		}
		if claims.AuthTime > 0 {
			token.AuthTime = time.Unix(claims.AuthTime, 0).UTC()
		}
		return token, nil
	}
	token, err := s.config.Store.GetAccessToken(ctx, auth.HashToken(raw))
	if err != nil {
		return nil, err
	}
	if token.Revoked || (!token.ExpiresAt.IsZero() && !s.Now().Before(token.ExpiresAt)) {
		return nil, ErrInvalidGrant
	}
	return token, nil
}

// cnfString reads a string member from a confirmation claim. | cnfString 从确认声明读取字符串成员。
func cnfString(cnf map[string]any, key string) string {
	if cnf == nil {
		return ""
	}
	value, _ := cnf[key].(string)
	return value
}

// ValidateAccessTokenRequest validates a token and its sender constraint from an HTTP request. | ValidateAccessTokenRequest
// 校验令牌及其在 HTTP 请求中的发送方约束。
func (s *Server) ValidateAccessTokenRequest(ctx context.Context, r *http.Request, raw string) (*AccessToken, error) {
	token, err := s.ValidateAccessToken(ctx, raw)
	if err != nil {
		return nil, err
	}
	if token.DPoPJKT != "" {
		if s.config.DPoPVerifier == nil {
			return nil, ErrInvalidDPoPProof
		}
		proof := ""
		if r != nil {
			proof = r.Header.Get("DPoP")
		}
		if proof == "" {
			return nil, ErrInvalidDPoPProof
		}
		jkt, err := s.config.DPoPVerifier.VerifyProof(ctx, proof, r.Method, requestTarget(r), raw)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidDPoPProof)
		}
		if jkt != token.DPoPJKT {
			return nil, ErrInvalidDPoPProof
		}
	}
	if s.config.DPoPRequired && token.DPoPJKT == "" {
		return nil, ErrInvalidDPoPProof
	}
	return token, nil
}

// requestTarget returns the normalized htu target of r. | requestTarget 返回 r 的规范化 htu 目标。
func requestTarget(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}

// issueDPoPNonce returns a fresh nonce from the configured issuer, or an empty string when nonce
// mode is disabled. | issueDPoPNonce 从配置的签发器返回新 nonce；未启用 nonce 模式时返回空字符串。
func (s *Server) issueDPoPNonce(ctx context.Context) string {
	if s == nil {
		return ""
	}
	now := s.Now()
	if issuer, ok := s.config.DPoPVerifier.(DPoPNonceIssuer); ok {
		nonce, err := issuer.IssueDPoPNonce(ctx, now)
		if err != nil {
			s.warnDPoPNonce(err)
			return ""
		}
		if nonce != "" {
			return nonce
		}
	}
	if store := s.config.DPoPNonceStore; store != nil {
		nonce, err := store.Issue(ctx, now, defaultDPoPNonceTTL)
		if err != nil {
			s.warnDPoPNonce(err)
			return ""
		}
		return nonce
	}
	return ""
}

// warnDPoPNonce logs a nonce issuance failure without failing the token response. | warnDPoPNonce
// 记录 nonce 签发失败，但不使令牌响应失败。
func (s *Server) warnDPoPNonce(err error) {
	if s != nil && s.config.Logger != nil {
		s.config.Logger.Warn("oauth2: DPoP nonce issuance failed | oauth2：DPoP nonce 签发失败", log.Err(err))
	}
}
