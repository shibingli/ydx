// Package oauth2 implements OAuth 2.1 authorization-server and client behavior.
// | Package oauth2 实现 OAuth 2.1 授权服务器与客户端行为。
//
// The package covers RFC 6749 authorization code, client credentials and refresh grants; RFC 7636
// PKCE; RFC 6750 bearer tokens; RFC 7009 revocation; RFC 7662 introspection; RFC 8414 metadata;
// RFC 8628 device authorization; RFC 8693 token exchange; RFC 8705 mutual-TLS client
// authentication and certificate-bound tokens; RFC 8707 resource indicators; RFC 9126 pushed
// authorization requests; RFC 9207 issuer identification; RFC 9449 DPoP; and RFC 9068 JWT access
// tokens. The implicit and resource-owner-password grants are implemented for compatibility but are
// disabled by default. | 本包覆盖 RFC 6749 授权码、客户端凭据与刷新授权；RFC 7636 PKCE；
// RFC 6750 承载令牌；RFC 7009 撤销；RFC 7662 自省；RFC 8414 元数据；RFC 8628 设备授权；
// RFC 8693 令牌交换；RFC 8705 双向 TLS 客户端认证与证书绑定令牌；RFC 8707 资源指示器；
// RFC 9126 推送授权请求；RFC 9207 签发方标识；RFC 9449 DPoP；以及 RFC 9068 JWT 访问令牌。
// 隐式授权与资源所有者口令授权为兼容而实现，但默认关闭。
//
// # HTTP entries | HTTP 入口
//
// Server handlers have the router.HandlerFuncRaw signature, so they mount directly on ydx/router:
//
//	r.HandleRaw(http.MethodGet, "/oauth/authorize", server.Authorize)
//	r.HandleRaw(http.MethodPost, "/oauth/token", server.Token)
//
// The same methods are valid net/http handlers and Server.HTTPHandler() returns a complete mux. |
// Server 处理器具有 router.HandlerFuncRaw 签名，因此可直接挂载到 ydx/router；同样的方法也是合法的
// net/http 处理器，Server.HTTPHandler() 返回完整 mux。
package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Grant type identifiers. | 授权类型标识。
const (
	// GrantAuthorizationCode is the RFC 6749 authorization-code grant. | GrantAuthorizationCode 是 RFC 6749 授权码授权。
	GrantAuthorizationCode = "authorization_code"
	// GrantClientCredentials is the RFC 6749 client-credentials grant. | GrantClientCredentials 是 RFC 6749 客户端凭据授权。
	GrantClientCredentials = "client_credentials"
	// GrantRefreshToken is the RFC 6749 refresh-token grant. | GrantRefreshToken 是 RFC 6749 刷新令牌授权。
	GrantRefreshToken = "refresh_token"
	// GrantPassword is the deprecated RFC 6749 resource-owner-password grant. | GrantPassword 是已弃用的 RFC 6749 资源所有者口令授权。
	GrantPassword = "password"
	// GrantDeviceCode is the RFC 8628 device-code grant. | GrantDeviceCode 是 RFC 8628 设备码授权。
	GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	// GrantJWTBearer is the RFC 7523 JWT-bearer grant. | GrantJWTBearer 是 RFC 7523 JWT 承载授权。
	GrantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// GrantTokenExchange is the RFC 8693 token-exchange grant. | GrantTokenExchange 是 RFC 8693 令牌交换授权。
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// Response type identifiers. | 响应类型标识。
const (
	// ResponseCode requests an authorization code. | ResponseCode 请求授权码。
	ResponseCode = "code"
	// ResponseToken requests an access token (implicit). | ResponseToken 请求访问令牌（隐式）。
	ResponseToken = "token"
	// ResponseIDToken requests an OpenID Connect ID token. | ResponseIDToken 请求 OpenID Connect ID 令牌。
	ResponseIDToken = "id_token"
	// ResponseNone requests no authorization result. | ResponseNone 不请求授权结果。
	ResponseNone = "none"
)

// Response modes. | 响应模式。
const (
	// ResponseModeQuery returns parameters in the query string. | ResponseModeQuery 在查询串返回参数。
	ResponseModeQuery = "query"
	// ResponseModeFragment returns parameters in the fragment. | ResponseModeFragment 在片段返回参数。
	ResponseModeFragment = "fragment"
	// ResponseModeFormPost returns parameters as an auto-submitted form. | ResponseModeFormPost 以自动提交表单返回参数。
	ResponseModeFormPost = "form_post"
	// ResponseModeJWT selects the JARM default encoding for the response type. | ResponseModeJWT
	// 为响应类型选择 JARM 默认编码。
	ResponseModeJWT = "jwt"
	// ResponseModeQueryJWT returns a signed JWT in the query string. | ResponseModeQueryJWT 在查询串返回签名 JWT。
	ResponseModeQueryJWT = "query.jwt"
	// ResponseModeFragmentJWT returns a signed JWT in the fragment. | ResponseModeFragmentJWT 在片段返回签名 JWT。
	ResponseModeFragmentJWT = "fragment.jwt"
	// ResponseModeFormPostJWT returns a signed JWT in an auto-submitted form. | ResponseModeFormPostJWT 以自动提交表单返回签名 JWT。
	ResponseModeFormPostJWT = "form_post.jwt"
)

// RFC 8693 token type identifiers. | RFC 8693 令牌类型标识。
const (
	// SubjectTokenAccessToken identifies an OAuth access token. | SubjectTokenAccessToken 标识 OAuth 访问令牌。
	SubjectTokenAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	// SubjectTokenJWT identifies a JWT. | SubjectTokenJWT 标识 JWT。
	SubjectTokenJWT = "urn:ietf:params:oauth:token-type:jwt"
	// SubjectTokenIDToken identifies an OpenID Connect ID token. | SubjectTokenIDToken 标识 OpenID Connect ID 令牌。
	SubjectTokenIDToken = "urn:ietf:params:oauth:token-type:id_token"
	// SubjectTokenSAML1 identifies a SAML 1.1 assertion. | SubjectTokenSAML1 标识 SAML 1.1 断言。
	SubjectTokenSAML1 = "urn:ietf:params:oauth:token-type:saml1"
	// SubjectTokenSAML2 identifies a SAML 2.0 assertion. | SubjectTokenSAML2 标识 SAML 2.0 断言。
	SubjectTokenSAML2 = "urn:ietf:params:oauth:token-type:saml2"
)

// Client authentication methods. | 客户端认证方法。
const (
	// ClientSecretBasic is HTTP Basic client authentication. | ClientSecretBasic 是 HTTP Basic 客户端认证。
	ClientSecretBasic = "client_secret_basic"
	// ClientSecretPost is form-body client authentication. | ClientSecretPost 是表单体客户端认证。
	ClientSecretPost = "client_secret_post"
	// ClientSecretJWT is HMAC-signed JWT client authentication. | ClientSecretJWT 是 HMAC 签名 JWT 客户端认证。
	ClientSecretJWT = "client_secret_jwt"
	// PrivateKeyJWT is asymmetric JWT client authentication. | PrivateKeyJWT 是非对称 JWT 客户端认证。
	PrivateKeyJWT = "private_key_jwt"
	// TLSClientAuth is RFC 8705 mutual-TLS client authentication. | TLSClientAuth 是 RFC 8705 双向 TLS 客户端认证。
	TLSClientAuth = "tls_client_auth"
	// SelfSignedTLSClientAuth is RFC 8705 self-signed mutual-TLS authentication. | SelfSignedTLSClientAuth 是 RFC 8705 自签名双向 TLS 认证。
	SelfSignedTLSClientAuth = "self_signed_tls_client_auth"
	// ClientAuthNone is a public client without a secret. | ClientAuthNone 是无密钥的公共客户端。
	ClientAuthNone = "none"
)

// Token types. | 令牌类型。
const (
	// TokenTypeBearer is the RFC 6750 bearer token type. | TokenTypeBearer 是 RFC 6750 承载令牌类型。
	TokenTypeBearer = "Bearer"
	// TokenTypeDPoP is the RFC 9449 DPoP token type. | TokenTypeDPoP 是 RFC 9449 DPoP 令牌类型。
	TokenTypeDPoP = "DPoP"
	// AccessTokenTypeJWT is the RFC 9068 "at+jwt" type. | AccessTokenTypeJWT 是 RFC 9068 "at+jwt" 类型。
	AccessTokenTypeJWT = "at+jwt"
)

// Token format values for ServerConfig. | ServerConfig 的令牌格式取值。
const (
	// TokenFormatOpaque issues random opaque access tokens. | TokenFormatOpaque 签发随机不透明访问令牌。
	TokenFormatOpaque = "opaque"
	// TokenFormatJWT issues RFC 9068 JWT access tokens. | TokenFormatJWT 签发 RFC 9068 JWT 访问令牌。
	TokenFormatJWT = "jwt"
)

// The OAuth error code identifiers. | OAuth 错误码标识。
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorAccessDenied            = "access_denied"
	ErrorServerError             = "server_error"
	ErrorTemporarilyUnavailable  = "temporarily_unavailable"
	ErrorAuthorizationPending    = "authorization_pending"
	ErrorSlowDown                = "slow_down"
	ErrorExpiredToken            = "expired_token"
	ErrorInvalidDPoPProof        = "invalid_dpop_proof"
	ErrorInvalidTarget           = "invalid_target"
	// RFC 9101 request-object errors, returned when request objects are not supported. | 不支持
	// 请求对象时返回的 RFC 9101 请求对象错误。
	ErrorRequestNotSupported    = "request_not_supported"
	ErrorRequestURINotSupported = "request_uri_not_supported"
	// RFC 9101 errors for a malformed or unreachable request object. | RFC 9101 请求对象非法或
	// 无法获取时使用的错误。
	ErrorInvalidRequestObject = "invalid_request_object"
	ErrorInvalidRequestURI    = "invalid_request_uri"
	// OpenID Connect interaction errors, also used by the authorization endpoint. | OpenID Connect 交互错误，授权端点同样使用。
	ErrorLoginRequired            = "login_required"
	ErrorConsentRequired          = "consent_required"
	ErrorInteractionRequired      = "interaction_required"
	ErrorAccountSelectionRequired = "account_selection_required"
)

// Sentinel errors for errors.Is classification. | 用于 errors.Is 分类的哨兵错误。
var (
	// ErrInvalidConfig reports a missing or contradictory server or client configuration. | ErrInvalidConfig 表示服务器或客户端配置缺失或矛盾。
	ErrInvalidConfig = errs.New("oauth2: invalid configuration | oauth2：配置非法")
	// ErrInvalidRequest reports a malformed or missing parameter. | ErrInvalidRequest 表示参数缺失或非法。
	ErrInvalidRequest = errs.New("oauth2: invalid request | oauth2：请求非法")
	// ErrInvalidClient reports failed client authentication. | ErrInvalidClient 表示客户端认证失败。
	ErrInvalidClient = errs.New("oauth2: invalid client | oauth2：客户端无效")
	// ErrInvalidGrant reports an invalid authorization grant. | ErrInvalidGrant 表示授权许可无效。
	ErrInvalidGrant = errs.New("oauth2: invalid grant | oauth2：授权许可无效")
	// ErrUnauthorizedClient reports a client not allowed to use a grant. | ErrUnauthorizedClient 表示客户端无权使用该授权类型。
	ErrUnauthorizedClient = errs.New("oauth2: unauthorized client | oauth2：客户端未授权")
	// ErrUnsupportedGrantType reports an unknown or disabled grant type. | ErrUnsupportedGrantType 表示授权类型未知或未启用。
	ErrUnsupportedGrantType = errs.New("oauth2: unsupported grant type | oauth2：不支持的授权类型")
	// ErrUnsupportedResponseType reports an unknown or disabled response type. | ErrUnsupportedResponseType 表示响应类型未知或未启用。
	ErrUnsupportedResponseType = errs.New("oauth2: unsupported response type | oauth2：不支持的响应类型")
	// ErrInvalidScope reports an unknown or disallowed scope. | ErrInvalidScope 表示作用域未知或不允许。
	ErrInvalidScope = errs.New("oauth2: invalid scope | oauth2：作用域无效")
	// ErrAccessDenied reports resource-owner or policy denial. | ErrAccessDenied 表示资源所有者或策略拒绝。
	ErrAccessDenied = errs.New("oauth2: access denied | oauth2：访问被拒绝")
	// ErrServerError reports an internal failure. | ErrServerError 表示内部故障。
	ErrServerError = errs.New("oauth2: server error | oauth2：服务器错误")
	// ErrLoginRequired reports that the authorization endpoint needs an authenticated user. | ErrLoginRequired 表示授权端点需要已认证用户。
	ErrLoginRequired = errs.New("oauth2: login required | oauth2：需要登录")
	// ErrConsentRequired reports that the authorization endpoint needs consent. | ErrConsentRequired 表示授权端点需要同意。
	ErrConsentRequired = errs.New("oauth2: consent required | oauth2：需要授权同意")
	// ErrInvalidDPoPProof reports a failed DPoP proof. | ErrInvalidDPoPProof 表示 DPoP 证明失败。
	ErrInvalidDPoPProof = errs.New("oauth2: invalid DPoP proof | oauth2：DPoP 证明无效")
	// ErrInvalidTarget reports a resource indicator not allowed for the client. | ErrInvalidTarget 表示资源指示器对客户端不允许。
	ErrInvalidTarget = errs.New("oauth2: invalid target resource | oauth2：目标资源无效")
	// ErrInvalidRequestObject reports an invalid RFC 9101 request object. | ErrInvalidRequestObject
	// 表示 RFC 9101 请求对象非法。
	ErrInvalidRequestObject = errs.New("oauth2: invalid request object | oauth2：请求对象非法")
	// ErrInvalidRequestURI reports an unreachable or invalid request_uri. | ErrInvalidRequestURI
	// 表示 request_uri 无法获取或非法。
	ErrInvalidRequestURI = errs.New("oauth2: invalid request URI | oauth2：请求 URI 非法")
)

// Error is an RFC 6749 error response with a stable code. | Error 是带稳定错误码的 RFC 6749 错误响应。
type Error struct {
	// Code is the RFC 6749 error code. | Code 是 RFC 6749 错误码。
	Code string `json:"error"`
	// Description is the human-readable error description. | Description 是人类可读错误描述。
	Description string `json:"error_description,omitempty"`
	// URI is an absolute documentation URI. | URI 是绝对文档 URI。
	URI string `json:"error_uri,omitempty"`
	// Status is the HTTP status, defaulting to 400. | Status 是 HTTP 状态码，默认 400。
	Status int `json:"-"`
	// Sentinel is the matching package sentinel, used by errors.Is. | Sentinel 是对应的包哨兵，供 errors.Is 使用。
	Sentinel error `json:"-"`
}

// NewError constructs an OAuth error with the package sentinel for code. | NewError 构造带包哨兵的 OAuth 错误。
func NewError(code, description string) *Error {
	return &Error{Code: code, Description: description, Status: statusForCode(code), Sentinel: sentinelForCode(code)}
}

// Error returns the code and description. | Error 返回错误码与描述。
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Description == "" {
		return "oauth2: " + e.Code
	}
	return "oauth2: " + e.Code + ": " + e.Description
}

// Unwrap returns the matching sentinel. | Unwrap 返回对应哨兵。
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Sentinel
}

// statusForCode maps an OAuth error code to its HTTP status. | statusForCode 把 OAuth 错误码映射为 HTTP 状态。
func statusForCode(code string) int {
	switch code {
	case ErrorInvalidClient:
		return http.StatusUnauthorized
	case ErrorServerError, ErrorTemporarilyUnavailable:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// sentinelForCode maps an OAuth error code to a package sentinel. | sentinelForCode 把 OAuth 错误码映射为包哨兵。
func sentinelForCode(code string) error {
	switch code {
	case ErrorInvalidRequest:
		return ErrInvalidRequest
	case ErrorInvalidClient:
		return ErrInvalidClient
	case ErrorInvalidGrant:
		return ErrInvalidGrant
	case ErrorUnauthorizedClient:
		return ErrUnauthorizedClient
	case ErrorUnsupportedGrantType:
		return ErrUnsupportedGrantType
	case ErrorUnsupportedResponseType:
		return ErrUnsupportedResponseType
	case ErrorInvalidScope:
		return ErrInvalidScope
	case ErrorAccessDenied:
		return ErrAccessDenied
	case ErrorInvalidDPoPProof:
		return ErrInvalidDPoPProof
	case ErrorInvalidTarget:
		return ErrInvalidTarget
	case ErrorInvalidRequestObject:
		return ErrInvalidRequestObject
	case ErrorInvalidRequestURI:
		return ErrInvalidRequestURI
	default:
		return ErrServerError
	}
}

// Client is an OAuth client registration. | Client 是 OAuth 客户端注册。
type Client struct {
	// ID is the client identifier. | ID 是客户端标识。
	ID string `json:"client_id"`
	// Name is a human-readable application name. | Name 是人类可读应用名。
	Name string `json:"client_name,omitempty"`
	// SecretHash is the SHA-256 hash of the client secret; empty for public clients. | SecretHash 是客户端密钥的 SHA-256 哈希；公共客户端为空。
	SecretHash string `json:"-"`
	// RedirectURIs are the exact allowed redirect URIs. | RedirectURIs 是允许的精确重定向 URI。
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	// GrantTypes are the allowed grant types. | GrantTypes 是允许的授权类型。
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes are the allowed response types. | ResponseTypes 是允许的响应类型。
	ResponseTypes []string `json:"response_types,omitempty"`
	// Scopes are the allowed scopes; empty means the server scope registry decides. | Scopes 是允许的作用域；为空表示由服务器作用域注册表决定。
	Scopes []string `json:"scopes,omitempty"`
	// Public marks a client without a usable secret. | Public 标记没有可用密钥的客户端。
	Public bool `json:"public,omitempty"`
	// TokenEndpointAuthMethod is the registered authentication method. | TokenEndpointAuthMethod 是注册的认证方法。
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// RequirePKCE forces PKCE even for confidential clients. | RequirePKCE 强制机密客户端也使用 PKCE。
	RequirePKCE bool `json:"require_pkce,omitempty"`
	// AccessTokenTTL, RefreshTokenTTL and AuthorizationCodeTTL override server defaults. | AccessTokenTTL、RefreshTokenTTL 与 AuthorizationCodeTTL 覆盖服务器默认值。
	AccessTokenTTL       time.Duration `json:"-"`
	RefreshTokenTTL      time.Duration `json:"-"`
	AuthorizationCodeTTL time.Duration `json:"-"`
	// JWKSURI points to the client's public keys for private_key_jwt. | JWKSURI 指向客户端 private_key_jwt 公钥。
	JWKSURI string `json:"jwks_uri,omitempty"`
	// JWKS is an inline client key set in JSON form. | JWKS 是 JSON 形式的内联客户端密钥集。
	JWKS []byte `json:"jwks,omitempty"`
	// TLSClientAuthSubjectDN is the allowed subject DN for tls_client_auth. | TLSClientAuthSubjectDN 是 tls_client_auth 允许的主体 DN。
	TLSClientAuthSubjectDN string `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSClientAuthSANs are allowed DNS/IP SANs for tls_client_auth. | TLSClientAuthSANs 是 tls_client_auth 允许的 DNS/IP SAN。
	TLSClientAuthSANs []string `json:"tls_client_auth_san_dns,omitempty"`
	// SkipConsent marks first-party clients that do not need a consent screen. | SkipConsent 标记无需同意页的第一方客户端。
	SkipConsent bool `json:"skip_consent,omitempty"`
	// The following fields are OpenID Connect client metadata (RFC 7591 / OIDC Registration). |
	// 以下字段是 OpenID Connect 客户端元数据（RFC 7591 / OIDC Registration）。
	PostLogoutRedirectURIs            []string `json:"post_logout_redirect_uris,omitempty"`
	SubjectType                       string   `json:"subject_type,omitempty"`
	SectorIdentifierURI               string   `json:"sector_identifier_uri,omitempty"`
	IDTokenSignedResponseAlg          string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg       string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc       string   `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignedResponseAlg         string   `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoEncryptedResponseAlg      string   `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoEncryptedResponseEnc      string   `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg           string   `json:"request_object_signing_alg,omitempty"`
	RequestURIs                       []string `json:"request_uris,omitempty"`
	AuthorizationSignedResponseAlg    string   `json:"authorization_signed_response_alg,omitempty"`
	TokenEndpointAuthSigningAlg       string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	ApplicationType                   string   `json:"application_type,omitempty"`
	Contacts                          []string `json:"contacts,omitempty"`
	LogoURI                           string   `json:"logo_uri,omitempty"`
	PolicyURI                         string   `json:"policy_uri,omitempty"`
	TOSURI                            string   `json:"tos_uri,omitempty"`
	ClientURI                         string   `json:"client_uri,omitempty"`
	FrontchannelLogoutURI             string   `json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool     `json:"frontchannel_logout_session_required,omitempty"`
	BackchannelLogoutURI              string   `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool     `json:"backchannel_logout_session_required,omitempty"`
	// RegistrationAccessTokenHash protects the dynamic-registration management endpoint. | RegistrationAccessTokenHash 保护动态注册管理端点。
	RegistrationAccessTokenHash string `json:"-"`
	// RegistrationClientURI is the management endpoint returned to the client. | RegistrationClientURI 是返回给客户端的管理端点。
	RegistrationClientURI string `json:"-"`
	// Metadata holds application-defined scalar attributes. | Metadata 保存应用自定义标量属性。
	Metadata map[string]string `json:"metadata,omitempty"`
	// CreatedAt and UpdatedAt are UTC timestamps. | CreatedAt 与 UpdatedAt 是 UTC 时间戳。
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SetSecret stores the hash of plain. | SetSecret 保存 plain 的哈希。
func (c *Client) SetSecret(plain string) {
	if c == nil {
		return
	}
	c.SecretHash = auth.HashToken(plain)
	c.Public = false
}

// VerifySecret reports whether plain matches the stored secret hash in constant time. | VerifySecret 以常量时间报告 plain 是否匹配存储的密钥哈希。
func (c *Client) VerifySecret(plain string) bool {
	if c == nil || c.SecretHash == "" || plain == "" {
		return false
	}
	return auth.TokenHashMatches(c.SecretHash, plain)
}

// AllowsGrant reports whether the client registered grant. | AllowsGrant 报告客户端是否注册了 grant。
func (c *Client) AllowsGrant(grant string) bool {
	if c == nil {
		return false
	}
	for _, g := range c.GrantTypes {
		if g == grant {
			return true
		}
	}
	return false
}

// AllowsResponseType reports whether the client registered responseType. | AllowsResponseType 报告客户端是否注册了 responseType。
func (c *Client) AllowsResponseType(responseType string) bool {
	if c == nil {
		return false
	}
	for _, registered := range c.ResponseTypes {
		if registered == responseType {
			return true
		}
	}
	return false
}

// AllowsScope reports whether scope is registered, or true when the client has no scope allow list. | AllowsScope 报告 scope 是否已注册；客户端没有作用域白名单时返回 true。
func (c *Client) AllowsScope(scope string) bool {
	if c == nil {
		return false
	}
	if len(c.Scopes) == 0 {
		return true
	}
	for _, allowed := range c.Scopes {
		if allowed == scope || allowed == "*" {
			return true
		}
	}
	return false
}

// AllowsRedirect reports whether uri is an exact registered redirect URI, honouring RFC 8252
// loopback port wildcards. | AllowsRedirect 报告 uri 是否为精确注册的重定向 URI，并支持 RFC 8252
// 回环地址端口通配。
func (c *Client) AllowsRedirect(uri string) bool {
	if c == nil || uri == "" {
		return false
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Fragment != "" {
		return false
	}
	for _, registered := range c.RedirectURIs {
		if registered == uri {
			return true
		}
		candidate, err := url.Parse(registered)
		if err != nil {
			continue
		}
		// RFC 8252 section 7.3 relaxes only the port for loopback redirects; the host itself
		// must stay identical so localhost cannot be swapped for a literal address. | RFC 8252
		// 第 7.3 节仅放宽回环重定向的端口；主机必须完全一致，不能让 localhost 被换成字面地址。
		if isLoopbackHost(candidate.Hostname()) && isLoopbackHost(parsed.Hostname()) &&
			strings.EqualFold(candidate.Hostname(), parsed.Hostname()) &&
			candidate.Scheme == parsed.Scheme && candidate.Path == parsed.Path &&
			candidate.RawQuery == parsed.RawQuery {
			return true
		}
	}
	return false
}

// AllowsPostLogoutRedirect reports whether uri is an exact registered post-logout redirect URI. | AllowsPostLogoutRedirect
// 报告 uri 是否为精确注册的登出后重定向 URI。
func (c *Client) AllowsPostLogoutRedirect(uri string) bool {
	if c == nil || uri == "" {
		return false
	}
	for _, registered := range c.PostLogoutRedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether host is a loopback literal. | isLoopbackHost 报告 host 是否为回环字面量。
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// AuthorizationCode is a single-use authorization-code grant. | AuthorizationCode 是单次授权码许可。
type AuthorizationCode struct {
	// CodeHash is the hash of the raw code sent to the client. | CodeHash 是发给客户端原始授权码的哈希。
	CodeHash string
	// ClientID identifies the client. | ClientID 标识客户端。
	ClientID string
	// RedirectURI is the redirect URI bound to the code. | RedirectURI 是绑定到授权码的重定向 URI。
	RedirectURI string
	// RedirectURIProvided reports whether the authorization request carried redirect_uri, in which
	// case RFC 6749 section 4.1.3 requires the token request to repeat it. | RedirectURIProvided
	// 报告授权请求是否携带 redirect_uri；若是，RFC 6749 第 4.1.3 节要求令牌请求重复该值。
	RedirectURIProvided bool
	// Scopes are the granted scopes. | Scopes 是已授予作用域。
	Scopes []string
	// UserID is the local user identifier. | UserID 是本地用户标识。
	UserID string
	// Subject is the authorization-server subject. | Subject 是授权服务器主体。
	Subject string
	// Nonce is the OpenID Connect nonce. | Nonce 是 OpenID Connect nonce。
	Nonce string
	// CodeChallenge and CodeChallengeMethod carry PKCE state. | CodeChallenge 与 CodeChallengeMethod 携带 PKCE 状态。
	CodeChallenge       string
	CodeChallengeMethod string
	// AuthTime, ACR, AMR and SessionID describe the authentication event. | AuthTime、ACR、AMR 与 SessionID 描述认证事件。
	AuthTime  time.Time
	ACR       string
	AMR       []string
	SessionID string
	// Resource lists RFC 8707 resource indicators. | Resource 列出 RFC 8707 资源指示器。
	Resource []string
	// Claims carries the OpenID Connect claims request. | Claims 携带 OpenID Connect claims 请求。
	Claims string
	// Principal is a snapshot of the authenticated principal for protocol enrichers. | Principal 是供协议增强器使用的已认证主体快照。
	Principal *auth.Principal
	// DPoPJKT and CertThumbprint bind the future token to a key or certificate. | DPoPJKT 与 CertThumbprint 把未来令牌绑定到密钥或证书。
	DPoPJKT        string
	CertThumbprint string
	// CreatedAt and ExpiresAt bound the code lifetime. | CreatedAt 与 ExpiresAt 限定授权码生命周期。
	CreatedAt time.Time
	ExpiresAt time.Time
	// Used marks a consumed code. | Used 标记已消费授权码。
	Used bool
}

// RefreshToken is a rotating refresh-token grant. | RefreshToken 是轮换刷新令牌许可。
type RefreshToken struct {
	// TokenHash is the hash of the raw refresh token. | TokenHash 是原始刷新令牌的哈希。
	TokenHash string
	// FamilyID groups tokens from one authorization grant for reuse detection. | FamilyID 把同一授权许可的令牌分组，用于重用检测。
	FamilyID string
	// ParentHash links a rotated child to its parent. | ParentHash 把轮换子令牌链接到父令牌。
	ParentHash string
	// ClientID identifies the client. | ClientID 标识客户端。
	ClientID string
	// UserID and Subject identify the resource owner. | UserID 与 Subject 标识资源所有者。
	UserID  string
	Subject string
	// Principal is a snapshot of the authenticated principal. | Principal 是已认证主体快照。
	Principal *auth.Principal
	// Scopes are the granted scopes. | Scopes 是已授予作用域。
	Scopes []string
	// Audience lists the resource indicators. | Audience 列出资源指示器。
	Audience []string
	// AuthTime, ACR, AMR and SessionID describe the authentication event. | AuthTime、ACR、AMR 与 SessionID 描述认证事件。
	AuthTime  time.Time
	ACR       string
	AMR       []string
	SessionID string
	// DPoPJKT and CertThumbprint bind the token to a key or certificate. | DPoPJKT 与 CertThumbprint 把令牌绑定到密钥或证书。
	DPoPJKT        string
	CertThumbprint string
	// CreatedAt and ExpiresAt bound the token lifetime. | CreatedAt 与 ExpiresAt 限定令牌生命周期。
	CreatedAt time.Time
	ExpiresAt time.Time
	// Used marks a rotated or consumed token. | Used 标记已轮换或消费的令牌。
	Used bool
	// Revoked marks an explicitly revoked token. | Revoked 标记显式撤销的令牌。
	Revoked bool
}

// AccessToken is a stored opaque access token. | AccessToken 是已存储的不透明访问令牌。
type AccessToken struct {
	// TokenHash is the hash of the raw access token. | TokenHash 是原始访问令牌的哈希。
	TokenHash string
	// ClientID identifies the client. | ClientID 标识客户端。
	ClientID string
	// UserID and Subject identify the resource owner. | UserID 与 Subject 标识资源所有者。
	UserID  string
	Subject string
	// Principal is a snapshot of the authenticated principal. | Principal 是已认证主体快照。
	Principal *auth.Principal
	// Scopes are the granted scopes. | Scopes 是已授予作用域。
	Scopes []string
	// Audience lists the resource indicators. | Audience 列出资源指示器。
	Audience []string
	// AuthTime, ACR, AMR and SessionID describe the authentication event. | AuthTime、ACR、AMR 与 SessionID 描述认证事件。
	AuthTime  time.Time
	ACR       string
	AMR       []string
	SessionID string
	// IssuedAt and ExpiresAt bound the token lifetime. | IssuedAt 与 ExpiresAt 限定令牌生命周期。
	IssuedAt  time.Time
	ExpiresAt time.Time
	// JTI is the token identifier. | JTI 是令牌标识。
	JTI string
	// DPoPJKT and CertThumbprint bind the token to a key or certificate. | DPoPJKT 与 CertThumbprint 把令牌绑定到密钥或证书。
	DPoPJKT        string
	CertThumbprint string
	// GrantID links the token to its authorization grant. | GrantID 把令牌链接到授权许可。
	GrantID string
	// Revoked marks an explicitly revoked token. | Revoked 标记显式撤销的令牌。
	Revoked bool
}

// DeviceCode is an RFC 8628 device authorization grant. | DeviceCode 是 RFC 8628 设备授权许可。
type DeviceCode struct {
	// DeviceCodeHash is the hash of the device code. | DeviceCodeHash 是设备码的哈希。
	DeviceCodeHash string
	// UserCode is the short human-entered code. | UserCode 是供人工输入的短码。
	UserCode string
	// ClientID identifies the client. | ClientID 标识客户端。
	ClientID string
	// Scopes are the requested scopes. | Scopes 是请求的作用域。
	Scopes []string
	// Audience lists the resource indicators. | Audience 列出资源指示器。
	Audience []string
	// UserID and Subject are filled after approval. | UserID 与 Subject 在批准后填充。
	UserID  string
	Subject string
	// Principal is a snapshot filled after approval. | Principal 是批准后填充的主体快照。
	Principal *auth.Principal
	// Status is pending, approved, denied, used or expired. | Status 取值为 pending、approved、denied、used 或 expired。
	Status string
	// DPoPJKT and CertThumbprint bind the future token to a key or certificate. | DPoPJKT 与 CertThumbprint 把未来令牌绑定到密钥或证书。
	DPoPJKT        string
	CertThumbprint string
	// Interval is the minimum polling interval. | Interval 是最小轮询间隔。
	Interval time.Duration
	// LastPolledAt is the last token-endpoint poll. | LastPolledAt 是最后一次令牌端点轮询。
	LastPolledAt time.Time
	// CreatedAt and ExpiresAt bound the grant lifetime. | CreatedAt 与 ExpiresAt 限定许可生命周期。
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PARRequest is a pushed authorization request. | PARRequest 是推送授权请求。
type PARRequest struct {
	// RequestURI is the urn:ietf:params:oauth:request_uri value. | RequestURI 是 urn:ietf:params:oauth:request_uri 取值。
	RequestURI string
	// ClientID identifies the client. | ClientID 标识客户端。
	ClientID string
	// Params are the pushed authorization parameters. | Params 是推送的授权参数。
	Params url.Values
	// CreatedAt and ExpiresAt bound the request lifetime. | CreatedAt 与 ExpiresAt 限定请求生命周期。
	CreatedAt time.Time
	ExpiresAt time.Time
	// Used marks a consumed request URI. | Used 标记已消费的请求 URI。
	Used bool
}

// AuthorizationRequest is a normalized authorization-endpoint request. | AuthorizationRequest 是规范化后的授权端点请求。
type AuthorizationRequest struct {
	// ClientID is the requested client. | ClientID 是请求的客户端。
	ClientID string
	// ResponseType is the space-delimited response_type. | ResponseType 是空格分隔的 response_type。
	ResponseType string
	// RedirectURI is the requested redirect URI. | RedirectURI 是请求的重定向 URI。
	RedirectURI string
	// Scopes are the requested scopes. | Scopes 是请求的作用域。
	Scopes []string
	// State is the opaque client state. | State 是客户端不透明状态。
	State string
	// Nonce is the OpenID Connect nonce. | Nonce 是 OpenID Connect nonce。
	Nonce string
	// CodeChallenge and CodeChallengeMethod carry PKCE state. | CodeChallenge 与 CodeChallengeMethod 携带 PKCE 状态。
	CodeChallenge       string
	CodeChallengeMethod string
	// ResponseMode is query, fragment or form_post. | ResponseMode 取值为 query、fragment 或 form_post。
	ResponseMode string
	// Prompt is the normalized prompt list. | Prompt 是规范化后的 prompt 列表。
	Prompt []string
	// MaxAge is the OpenID Connect max_age, when present. | MaxAge 是 OpenID Connect max_age（存在时）。
	MaxAge *int
	// LoginHint, IDTokenHint, ACRValues, UILocales and Claims are OpenID Connect parameters. | LoginHint、IDTokenHint、ACRValues、UILocales 与 Claims 是 OpenID Connect 参数。
	LoginHint   string
	IDTokenHint string
	ACRValues   []string
	UILocales   []string
	Claims      string
	// Resource lists RFC 8707 resource indicators. | Resource 列出 RFC 8707 资源指示器。
	Resource []string
	// Request and RequestURI carry RFC 9101 request objects. | Request 与 RequestURI 携带 RFC 9101 请求对象。
	Request    string
	RequestURI string
	// Raw holds every original parameter for extension processing. | Raw 保存原始参数，供扩展处理。
	Raw url.Values
	// Client is the resolved client registration. | Client 是解析后的客户端注册。
	Client *Client
}

// ScopeString returns the space-delimited scope value. | ScopeString 返回空格分隔的作用域值。
func (r *AuthorizationRequest) ScopeString() string { return strings.Join(r.Scopes, " ") }

// HasPrompt reports whether prompt contains value. | HasPrompt 报告 prompt 是否包含 value。
func (r *AuthorizationRequest) HasPrompt(value string) bool {
	for _, p := range r.Prompt {
		if p == value {
			return true
		}
	}
	return false
}

// TokenResponse is a successful token-endpoint response. | TokenResponse 是成功的令牌端点响应。
type TokenResponse struct {
	// AccessToken is the issued access token. | AccessToken 是签发的访问令牌。
	AccessToken string `json:"access_token"`
	// TokenType is Bearer or DPoP. | TokenType 取值为 Bearer 或 DPoP。
	TokenType string `json:"token_type"`
	// ExpiresIn is the access-token lifetime in seconds. | ExpiresIn 是访问令牌寿命（秒）。
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// RefreshToken is the optional refresh token. | RefreshToken 是可选刷新令牌。
	RefreshToken string `json:"refresh_token,omitempty"`
	// Scope is the granted scope value. | Scope 是已授予作用域值。
	Scope string `json:"scope,omitempty"`
	// IDToken is the OpenID Connect ID token. | IDToken 是 OpenID Connect ID 令牌。
	IDToken string `json:"id_token,omitempty"`
	// IssuedTokenType is the RFC 8693 issued token type. | IssuedTokenType 是 RFC 8693 签发令牌类型。
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	// Extra carries extension response parameters such as cnf. | Extra 携带 cnf 等扩展响应参数。
	Extra map[string]any `json:"-"`
}

// MarshalJSON includes extension fields from Extra in the token response. | MarshalJSON 把 Extra 中的扩展字段包含进令牌响应。
func (t *TokenResponse) MarshalJSON() ([]byte, error) {
	if t == nil {
		return []byte("null"), nil
	}
	out := make(map[string]any, 8+len(t.Extra))
	if t.AccessToken != "" {
		out["access_token"] = t.AccessToken
	}
	if t.TokenType != "" {
		out["token_type"] = t.TokenType
	}
	if t.ExpiresIn > 0 {
		out["expires_in"] = t.ExpiresIn
	}
	if t.RefreshToken != "" {
		out["refresh_token"] = t.RefreshToken
	}
	if t.Scope != "" {
		out["scope"] = t.Scope
	}
	if t.IDToken != "" {
		out["id_token"] = t.IDToken
	}
	if t.IssuedTokenType != "" {
		out["issued_token_type"] = t.IssuedTokenType
	}
	for key, value := range t.Extra {
		if _, exists := out[key]; !exists {
			out[key] = value
		}
	}
	return json.Marshal(out)
}

// ServerMetadata is the RFC 8414 authorization-server metadata document. | ServerMetadata 是 RFC 8414 授权服务器元数据文档。
type ServerMetadata struct {
	// Issuer is the authorization-server issuer. | Issuer 是授权服务器签发方。
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint and TokenEndpoint are the core endpoints. | AuthorizationEndpoint 与 TokenEndpoint 是核心端点。
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	// JWKSURI points to the signing key set. | JWKSURI 指向签名密钥集。
	JWKSURI string `json:"jwks_uri,omitempty"`
	// RegistrationEndpoint is the dynamic registration endpoint. | RegistrationEndpoint 是动态注册端点。
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	// ScopesSupported lists the server scopes. | ScopesSupported 列出服务器作用域。
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// ResponseTypesSupported lists the response types. | ResponseTypesSupported 列出响应类型。
	ResponseTypesSupported []string `json:"response_types_supported"`
	// ResponseModesSupported lists the response modes. | ResponseModesSupported 列出响应模式。
	ResponseModesSupported []string `json:"response_modes_supported"`
	// RequestParameterSupported reports RFC 9101 request-object support. | RequestParameterSupported
	// 报告 RFC 9101 请求对象支持。
	RequestParameterSupported bool `json:"request_parameter_supported,omitempty"`
	// RequestURIParameterSupported reports whether request_uri values are accepted. |
	// RequestURIParameterSupported 报告是否接受 request_uri。
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported,omitempty"`
	// RequireRequestURIRegistration reports whether external request_uri values must be registered. |
	// RequireRequestURIRegistration 报告外部 request_uri 是否必须预注册。
	RequireRequestURIRegistration bool `json:"require_request_uri_registration,omitempty"`
	// RequestObjectSigningAlgValuesSupported lists accepted request-object algorithms. |
	// RequestObjectSigningAlgValuesSupported 列出接受的请求对象算法。
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
	// AuthorizationSigningAlgValuesSupported lists JARM signing algorithms. |
	// AuthorizationSigningAlgValuesSupported 列出 JARM 签名算法。
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`
	// GrantTypesSupported lists the grant types. | GrantTypesSupported 列出授权类型。
	GrantTypesSupported []string `json:"grant_types_supported"`
	// TokenEndpointAuthMethodsSupported lists client authentication methods. | TokenEndpointAuthMethodsSupported 列出客户端认证方法。
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// TokenEndpointAuthSigningAlgValuesSupported lists JWT client-auth algorithms. | TokenEndpointAuthSigningAlgValuesSupported 列出 JWT 客户端认证算法。
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	// RevocationEndpointAuthMethodsSupported lists client authentication methods accepted at the revocation endpoint. | RevocationEndpointAuthMethodsSupported 列出撤销端点接受的客户端认证方法。
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	// IntrospectionEndpointAuthMethodsSupported lists client authentication methods accepted at the introspection endpoint. | IntrospectionEndpointAuthMethodsSupported 列出自省端点接受的客户端认证方法。
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	// RevocationEndpoint and IntrospectionEndpoint are the management endpoints. | RevocationEndpoint 与 IntrospectionEndpoint 是管理端点。
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	// DeviceAuthorizationEndpoint is the RFC 8628 endpoint. | DeviceAuthorizationEndpoint 是 RFC 8628 端点。
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`
	// PushedAuthorizationRequestEndpoint is the RFC 9126 endpoint. | PushedAuthorizationRequestEndpoint 是 RFC 9126 端点。
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	// CodeChallengeMethodsSupported lists PKCE methods. | CodeChallengeMethodsSupported 列出 PKCE 方法。
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// DPoPSigningAlgValuesSupported lists DPoP proof algorithms. | DPoPSigningAlgValuesSupported 列出 DPoP 证明算法。
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
	// DPoPBoundAccessTokensRequired reports a DPoP-only deployment. | DPoPBoundAccessTokensRequired 表示仅允许 DPoP 的部署。
	DPoPBoundAccessTokensRequired bool `json:"dpop_bound_access_tokens_required,omitempty"`
	// MTLSEndpointAliases is the RFC 8705 mTLS endpoint alias map. | MTLSEndpointAliases 是 RFC 8705 mTLS 端点别名映射。
	MTLSEndpointAliases map[string]string `json:"mtls_endpoint_aliases,omitempty"`
	// AuthorizationResponseIssParameterSupported reports RFC 9207 support. | AuthorizationResponseIssParameterSupported 表示 RFC 9207 支持。
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	// AccessTokenSigningAlgValuesSupported lists JWT access-token algorithms. | AccessTokenSigningAlgValuesSupported 列出 JWT 访问令牌算法。
	AccessTokenSigningAlgValuesSupported []string `json:"access_token_signing_alg_values_supported,omitempty"`
}

// Authenticator resolves the resource owner at the authorization endpoint. | Authenticator 在授权端点解析资源所有者。
//
// Returning ErrLoginRequired makes the server redirect to ServerConfig.LoginURL, or call
// ServerConfig.LoginHandler when set. | 返回 ErrLoginRequired 会让服务器跳转到 ServerConfig.LoginURL，
// 或在设置了 ServerConfig.LoginHandler 时调用它。
type Authenticator interface {
	// Authenticate returns the current principal, ErrLoginRequired or another error. | Authenticate 返回当前主体、ErrLoginRequired 或其他错误。
	Authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) (*auth.Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator. | AuthenticatorFunc 把函数适配为 Authenticator。
type AuthenticatorFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) (*auth.Principal, error)

// Authenticate calls f. | Authenticate 调用 f。
func (f AuthenticatorFunc) Authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest) (*auth.Principal, error) {
	return f(ctx, w, r, req)
}

// ConsentHandler decides whether a principal authorizes a client's scopes. | ConsentHandler 决定主体是否授权客户端的作用域。
//
// The returned scopes are the granted subset; an empty slice denies the request. | 返回的作用域是授予的子集；空切片表示拒绝。
type ConsentHandler interface {
	// Consent returns the granted scopes, or ErrAccessDenied. | Consent 返回授予的作用域，或 ErrAccessDenied。
	Consent(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, principal *auth.Principal) ([]string, error)
}

// ConsentFunc adapts a function to ConsentHandler. | ConsentFunc 把函数适配为 ConsentHandler。
type ConsentFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, principal *auth.Principal) ([]string, error)

// Consent calls f. | Consent 调用 f。
func (f ConsentFunc) Consent(ctx context.Context, w http.ResponseWriter, r *http.Request, req *AuthorizationRequest, principal *auth.Principal) ([]string, error) {
	return f(ctx, w, r, req, principal)
}
