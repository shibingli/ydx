// Package oidc implements OpenID Connect Core 1.0, Discovery, Dynamic Client Registration,
// RP-Initiated Logout, Front-Channel and Back-Channel Logout, Session Management, and a relying
// party that validates ID tokens and calls UserInfo. | Package oidc 实现 OpenID Connect Core 1.0、
// Discovery、动态客户端注册、RP 发起登出、前端与后端登出、会话管理，以及校验 ID 令牌并调用
// UserInfo 的依赖方。
//
// The provider builds on auth/protocol/oauth2: it installs itself as the OAuth server's token and
// authorization enricher, so an application only mounts both servers once. | 提供方建立在
// auth/protocol/oauth2 之上：它把自己安装为 OAuth 服务器的令牌与授权增强器，因此应用只需挂载两个服务器一次。
package oidc

import (
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Default endpoint paths. | 默认端点路径。
const (
	// DiscoveryPath is the OpenID Connect discovery path. | DiscoveryPath 是 OpenID Connect 发现路径。
	DiscoveryPath = "/.well-known/openid-configuration"
	// OAuthDiscoveryPath is the RFC 8414 authorization-server metadata path. | OAuthDiscoveryPath 是 RFC 8414 授权服务器元数据路径。
	OAuthDiscoveryPath = "/.well-known/oauth-authorization-server"
	// JWKSPath is the JWK Set path. | JWKSPath 是 JWK Set 路径。
	JWKSPath = "/jwks"
	// UserInfoPath is the UserInfo endpoint path. | UserInfoPath 是 UserInfo 端点路径。
	UserInfoPath = "/userinfo"
	// EndSessionPath is the RP-initiated logout path. | EndSessionPath 是 RP 发起登出路径。
	EndSessionPath = "/logout"
	// RegistrationPath is the dynamic client registration path. | RegistrationPath 是动态客户端注册路径。
	RegistrationPath = "/register"
	// CheckSessionPath is the OP iframe path for session management. | CheckSessionPath 是会话管理的 OP iframe 路径。
	CheckSessionPath = "/check_session"
	// FrontchannelLogoutPath is the front-channel logout path. | FrontchannelLogoutPath 是前端登出路径。
	FrontchannelLogoutPath = "/frontchannel_logout"
	// BackchannelLogoutPath is the back-channel logout path. | BackchannelLogoutPath 是后端登出路径。
	BackchannelLogoutPath = "/backchannel_logout"
)

// Subject types. | 主体类型。
const (
	// SubjectTypePublic uses the local subject identifier directly. | SubjectTypePublic 直接使用本地主体标识。
	SubjectTypePublic = "public"
	// SubjectTypePairwise derives a per-sector pseudonymous subject. | SubjectTypePairwise 派生按扇区隔离的假名主体。
	SubjectTypePairwise = "pairwise"
)

// Standard scope values. | 标准作用域取值。
const (
	// ScopeOpenID is the OpenID Connect scope. | ScopeOpenID 是 OpenID Connect 作用域。
	ScopeOpenID = "openid"
	// ScopeProfile requests profile claims. | ScopeProfile 请求资料声明。
	ScopeProfile = "profile"
	// ScopeEmail requests email claims. | ScopeEmail 请求邮箱声明。
	ScopeEmail = "email"
	// ScopeAddress requests the address claim. | ScopeAddress 请求地址声明。
	ScopeAddress = "address"
	// ScopePhone requests phone claims. | ScopePhone 请求电话声明。
	ScopePhone = "phone"
	// ScopeOfflineAccess requests a refresh token. | ScopeOfflineAccess 请求刷新令牌。
	ScopeOfflineAccess = "offline_access"
)

// Token endpoint authentication methods. | 令牌端点认证方法。
const (
	// AuthMethodBasic is client_secret_basic. | AuthMethodBasic 是 client_secret_basic。
	AuthMethodBasic = "client_secret_basic"
	// AuthMethodPost is client_secret_post. | AuthMethodPost 是 client_secret_post。
	AuthMethodPost = "client_secret_post"
	// AuthMethodPrivateKeyJWT is private_key_jwt. | AuthMethodPrivateKeyJWT 是 private_key_jwt。
	AuthMethodPrivateKeyJWT = "private_key_jwt"
	// AuthMethodNone is the public-client method. | AuthMethodNone 是公共客户端方法。
	AuthMethodNone = "none"
)

// The declared sentinels of this package. | 本包的哨兵错误声明。
var (
	// ErrInvalidConfig reports a missing or contradictory provider or relying-party configuration. | ErrInvalidConfig 表示提供方或依赖方配置缺失或矛盾。
	ErrInvalidConfig = errs.New("oidc: invalid configuration | oidc：配置非法")
	// ErrInvalidRequest reports malformed caller input. | ErrInvalidRequest 表示调用方输入非法。
	ErrInvalidRequest = errs.New("oidc: invalid request | oidc：请求非法")
	// ErrInvalidToken reports a malformed or unverifiable ID token. | ErrInvalidToken 表示 ID 令牌格式非法或无法校验。
	ErrInvalidToken = errs.New("oidc: invalid ID token | oidc：ID 令牌无效")
	// ErrInvalidIssuer reports an issuer mismatch. | ErrInvalidIssuer 表示签发方不匹配。
	ErrInvalidIssuer = errs.New("oidc: issuer mismatch | oidc：签发方不匹配")
	// ErrInvalidAudience reports an audience or authorized-party mismatch. | ErrInvalidAudience 表示受众或授权方不匹配。
	ErrInvalidAudience = errs.New("oidc: audience mismatch | oidc：受众不匹配")
	// ErrInvalidNonce reports a nonce mismatch. | ErrInvalidNonce 表示 nonce 不匹配。
	ErrInvalidNonce = errs.New("oidc: nonce mismatch | oidc：nonce 不匹配")
	// ErrTokenExpired reports an expired ID token. | ErrTokenExpired 表示 ID 令牌已过期。
	ErrTokenExpired = errs.New("oidc: token expired | oidc：令牌已过期")
	// ErrTokenNotYetValid reports an ID token used before nbf. | ErrTokenNotYetValid 表示 ID 令牌在 nbf 前被使用。
	ErrTokenNotYetValid = errs.New("oidc: token not yet valid | oidc：令牌尚未生效")
	// ErrInvalidAtHash reports an at_hash mismatch. | ErrInvalidAtHash 表示 at_hash 不匹配。
	ErrInvalidAtHash = errs.New("oidc: at_hash mismatch | oidc：at_hash 不匹配")
	// ErrInvalidCHash reports a c_hash mismatch. | ErrInvalidCHash 表示 c_hash 不匹配。
	ErrInvalidCHash = errs.New("oidc: c_hash mismatch | oidc：c_hash 不匹配")
	// ErrDiscoveryFailed reports a failed discovery document fetch or parse. | ErrDiscoveryFailed 表示发现文档获取或解析失败。
	ErrDiscoveryFailed = errs.New("oidc: discovery failed | oidc：发现失败")
	// ErrRegistrationFailed reports a failed dynamic client registration. | ErrRegistrationFailed 表示动态客户端注册失败。
	ErrRegistrationFailed = errs.New("oidc: registration failed | oidc：注册失败")
	// ErrInvalidRedirect reports an unregistered logout redirect URI. | ErrInvalidRedirect 表示登出重定向 URI 未注册。
	ErrInvalidRedirect = errs.New("oidc: invalid redirect URI | oidc：重定向 URI 无效")
	// ErrSessionNotFound reports an unknown or expired session. | ErrSessionNotFound 表示会话不存在或已过期。
	ErrSessionNotFound = errs.New("oidc: session not found | oidc：会话不存在")
	// ErrLogoutFailed reports a failed logout token delivery. | ErrLogoutFailed 表示登出令牌投递失败。
	ErrLogoutFailed = errs.New("oidc: logout failed | oidc：登出失败")
)

// Address is the OpenID Connect address claim. | Address 是 OpenID Connect address 声明。
type Address struct {
	// Formatted is the full mailing address. | Formatted 是完整邮寄地址。
	Formatted string `json:"formatted,omitempty"`
	// StreetAddress is the street-address component. | StreetAddress 是街道地址组成部分。
	StreetAddress string `json:"street_address,omitempty"`
	// Locality is the locality component. | Locality 是城市组成部分。
	Locality string `json:"locality,omitempty"`
	// Region is the region component. | Region 是省区组成部分。
	Region string `json:"region,omitempty"`
	// PostalCode is the postal-code component. | PostalCode 是邮政编码组成部分。
	PostalCode string `json:"postal_code,omitempty"`
	// Country is the country component. | Country 是国家组成部分。
	Country string `json:"country,omitempty"`
}

// Audience is the aud claim, accepting both a string and an array. | Audience 是 aud 声明，接受字符串与数组两种形式。
type Audience []string

// UnmarshalJSON accepts a JSON string or array of strings. | UnmarshalJSON 接受 JSON 字符串或字符串数组。
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = Audience(many)
	return nil
}

// Contains reports whether audience contains value. | Contains 报告 audience 是否包含 value。
func (a Audience) Contains(value string) bool {
	for _, item := range a {
		if item == value {
			return true
		}
	}
	return false
}

// Claims is the OpenID Connect claim set used by ID tokens and UserInfo. | Claims 是 ID 令牌与
// UserInfo 使用的 OpenID Connect 声明集。
type Claims struct {
	// Issuer is the iss claim. | Issuer 是 iss 声明。
	Issuer string `json:"iss,omitempty"`
	// Subject is the sub claim. | Subject 是 sub 声明。
	Subject string `json:"sub,omitempty"`
	// Audience is the aud claim. | Audience 是 aud 声明。
	Audience Audience `json:"aud,omitempty"`
	// Expiry is the expiry NumericDate. | Expiry 是过期 NumericDate。
	Expiry int64 `json:"exp,omitempty"`
	// IssuedAt is the issue NumericDate. | IssuedAt 是签发 NumericDate。
	IssuedAt int64 `json:"iat,omitempty"`
	// NotBefore is the not-before NumericDate. | NotBefore 是生效前 NumericDate。
	NotBefore int64 `json:"nbf,omitempty"`
	// Nonce is the OIDC nonce. | Nonce 是 OIDC nonce。
	Nonce string `json:"nonce,omitempty"`
	// AuthTime is the end-user authentication time. | AuthTime 是最终用户认证时间。
	AuthTime int64 `json:"auth_time,omitempty"`
	// ACR is the authentication context class reference. | ACR 是认证上下文类引用。
	ACR string `json:"acr,omitempty"`
	// AMR lists the authentication methods. | AMR 列出认证方法。
	AMR []string `json:"amr,omitempty"`
	// AZP is the authorized party. | AZP 是授权方。
	AZP string `json:"azp,omitempty"`
	// JTI is the token identifier. | JTI 是令牌标识。
	JTI string `json:"jti,omitempty"`
	// SID is the session identifier used by logout and session management. | SID 是登出与会话管理使用的会话标识。
	SID string `json:"sid,omitempty"`
	// AccessTokenHash binds the ID token to an access token. | AccessTokenHash 把 ID 令牌绑定到访问令牌。
	AccessTokenHash string `json:"at_hash,omitempty"`
	// CodeHash binds the ID token to an authorization code. | CodeHash 把 ID 令牌绑定到授权码。
	CodeHash string `json:"c_hash,omitempty"`
	// StateHash binds the ID token to the OAuth state in FAPI-style profiles. | StateHash 在 FAPI 类配置中把 ID 令牌绑定到 OAuth state。
	StateHash string `json:"s_hash,omitempty"`
	// Name is the full display name. | Name 是完整显示名。
	Name string `json:"name,omitempty"`
	// GivenName is the given name. | GivenName 是名字。
	GivenName string `json:"given_name,omitempty"`
	// FamilyName is the family name. | FamilyName 是姓氏。
	FamilyName string `json:"family_name,omitempty"`
	// MiddleName is the middle name. | MiddleName 是中间名。
	MiddleName string `json:"middle_name,omitempty"`
	// Nickname is the casual name. | Nickname 是昵称。
	Nickname string `json:"nickname,omitempty"`
	// PreferredUsername is the preferred user name. | PreferredUsername 是首选用户名。
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Profile is the profile page URL. | Profile 是资料页 URL。
	Profile string `json:"profile,omitempty"`
	// Picture is the profile picture URL. | Picture 是头像 URL。
	Picture string `json:"picture,omitempty"`
	// Website is the website URL. | Website 是网站 URL。
	Website string `json:"website,omitempty"`
	// Gender is the gender value. | Gender 是性别取值。
	Gender string `json:"gender,omitempty"`
	// Birthdate is the birthday in ISO 8601 date form. | Birthdate 是 ISO 8601 日期形式的生日。
	Birthdate string `json:"birthdate,omitempty"`
	// Zoneinfo is the time-zone identifier. | Zoneinfo 是时区标识。
	Zoneinfo string `json:"zoneinfo,omitempty"`
	// Locale is the locale identifier. | Locale 是区域设置标识。
	Locale string `json:"locale,omitempty"`
	// UpdatedAt is the profile last-update NumericDate. | UpdatedAt 是资料最后更新 NumericDate。
	UpdatedAt int64 `json:"updated_at,omitempty"`
	// Email is the email address. | Email 是邮箱地址。
	Email string `json:"email,omitempty"`
	// EmailVerified reports whether the email address was verified. | EmailVerified 报告邮箱地址是否已验证。
	EmailVerified *bool `json:"email_verified,omitempty"`
	// PhoneNumber is the telephone number. | PhoneNumber 是电话号码。
	PhoneNumber string `json:"phone_number,omitempty"`
	// PhoneNumberVerified reports whether the phone number was verified. | PhoneNumberVerified 报告电话号码是否已验证。
	PhoneNumberVerified *bool `json:"phone_number_verified,omitempty"`
	// Address is the address claim. | Address 是地址声明。
	Address *Address `json:"address,omitempty"`
	// Extra carries additional claims that are not in the standard set. | Extra 携带标准集之外的附加声明。
	Extra map[string]any `json:"-"`
}

// IDToken is a verified ID token. | IDToken 是已校验的 ID 令牌。
type IDToken struct {
	// Claims is the decoded claim set. | Claims 是解码后的声明集。
	Claims Claims
	// Raw is the full claim map, including extension claims. | Raw 是完整声明映射，包含扩展声明。
	Raw map[string]any
	// Header is the JOSE protected header. | Header 是 JOSE 受保护头部。
	Header map[string]any
	// RawToken is the compact token as received. | RawToken 是收到的紧凑令牌。
	RawToken string
}

// Claim returns a raw claim value. | Claim 返回原始声明值。
func (t *IDToken) Claim(name string) (any, bool) {
	if t == nil {
		return nil, false
	}
	value, ok := t.Raw[name]
	return value, ok
}
