package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// The declared sentinels of the core package. | 核心包的哨兵错误声明。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers can
// classify errors with errors.Is instead of matching text. | 所有失败路径都直接返回其中之一，或经由
// errs.Detail / errs.Wrap 包装，因此调用方可用 errors.Is 分类错误而无需匹配文案。
var (
	// ErrInvalidConfig reports a missing or contradictory service configuration. | ErrInvalidConfig 表示服务配置缺失或互相矛盾。
	ErrInvalidConfig = errs.New("auth: invalid configuration | auth：配置非法")
	// ErrInvalidRequest reports malformed caller input. | ErrInvalidRequest 表示调用方输入非法。
	ErrInvalidRequest = errs.New("auth: invalid request | auth：请求非法")
	// ErrUnauthorized reports a missing or invalid authentication context. | ErrUnauthorized 表示缺少或无效的认证上下文。
	ErrUnauthorized = errs.New("auth: unauthorized | auth：未认证")
	// ErrForbidden reports an authenticated principal without the required permission. | ErrForbidden 表示主体已认证但缺少所需权限。
	ErrForbidden = errs.New("auth: forbidden | auth：禁止访问")
	// ErrUserNotFound reports an unknown user. | ErrUserNotFound 表示用户不存在。
	ErrUserNotFound = errs.New("auth: user not found | auth：用户不存在")
	// ErrUserExists reports a duplicate username, email or phone. | ErrUserExists 表示用户名、邮箱或手机号重复。
	ErrUserExists = errs.New("auth: user already exists | auth：用户已存在")
	// ErrInvalidCredentials reports a failed password or credential check. | ErrInvalidCredentials 表示口令或凭据校验失败。
	ErrInvalidCredentials = errs.New("auth: invalid credentials | auth：凭据无效")
	// ErrAccountLocked reports a temporarily locked account. | ErrAccountLocked 表示账号被临时锁定。
	ErrAccountLocked = errs.New("auth: account locked | auth：账号已锁定")
	// ErrAccountDisabled reports an administratively disabled account. | ErrAccountDisabled 表示账号已被管理员禁用。
	ErrAccountDisabled = errs.New("auth: account disabled | auth：账号已禁用")
	// ErrAccountPending reports an account that has not completed activation. | ErrAccountPending 表示账号尚未完成激活。
	ErrAccountPending = errs.New("auth: account pending | auth：账号待激活")
	// ErrEmailNotVerified reports a policy that requires a verified email address. | ErrEmailNotVerified 表示策略要求邮箱已验证。
	ErrEmailNotVerified = errs.New("auth: email not verified | auth：邮箱未验证")
	// ErrPasswordExpired reports a password older than the configured maximum age. | ErrPasswordExpired 表示口令超过配置的最长有效期。
	ErrPasswordExpired = errs.New("auth: password expired | auth：口令已过期")
	// ErrPasswordPolicy reports a password that violates the configured policy. | ErrPasswordPolicy 表示口令违反配置的策略。
	ErrPasswordPolicy = errs.New("auth: password policy violation | auth：口令不符合策略")
	// ErrPasswordReused reports a password found in the configured history. | ErrPasswordReused 表示口令出现在历史记录中。
	ErrPasswordReused = errs.New("auth: password reused | auth：口令重复使用")
	// ErrSessionNotFound reports an unknown session identifier. | ErrSessionNotFound 表示会话标识不存在。
	ErrSessionNotFound = errs.New("auth: session not found | auth：会话不存在")
	// ErrSessionExpired reports a session past its idle or absolute deadline. | ErrSessionExpired 表示会话超过空闲或绝对期限。
	ErrSessionExpired = errs.New("auth: session expired | auth：会话已过期")
	// ErrSessionRevoked reports a session revoked explicitly. | ErrSessionRevoked 表示会话已被显式撤销。
	ErrSessionRevoked = errs.New("auth: session revoked | auth：会话已撤销")
	// ErrMFARequired reports that a second factor is required to finish authentication. | ErrMFARequired 表示需要第二因素才能完成认证。
	ErrMFARequired = errs.New("auth: MFA required | auth：需要多因素认证")
	// ErrMFAInvalid reports a failed second-factor challenge. | ErrMFAInvalid 表示第二因素挑战失败。
	ErrMFAInvalid = errs.New("auth: invalid MFA response | auth：多因素响应无效")
	// ErrMFAAlreadyEnabled reports enabling MFA when a factor already exists. | ErrMFAAlreadyEnabled 表示已存在第二因素时再次启用。
	ErrMFAAlreadyEnabled = errs.New("auth: MFA already enabled | auth：多因素认证已启用")
	// ErrMFANotEnabled reports a second-factor operation without an enrolled factor. | ErrMFANotEnabled 表示未登记第二因素却执行相关操作。
	ErrMFANotEnabled = errs.New("auth: MFA not enabled | auth：多因素认证未启用")
	// ErrCredentialNotFound reports an unknown credential. | ErrCredentialNotFound 表示凭据不存在。
	ErrCredentialNotFound = errs.New("auth: credential not found | auth：凭据不存在")
	// ErrCredentialExists reports a duplicate credential identifier. | ErrCredentialExists 表示凭据标识重复。
	ErrCredentialExists = errs.New("auth: credential already exists | auth：凭据已存在")
	// ErrIdentityNotFound reports an unknown external identity link. | ErrIdentityNotFound 表示外部身份关联不存在。
	ErrIdentityNotFound = errs.New("auth: identity not found | auth：身份关联不存在")
	// ErrIdentityExists reports a duplicate external identity link. | ErrIdentityExists 表示外部身份关联重复。
	ErrIdentityExists = errs.New("auth: identity already linked | auth：身份关联已存在")
	// ErrTokenInvalid reports an invalid one-time token. | ErrTokenInvalid 表示一次性令牌无效。
	ErrTokenInvalid = errs.New("auth: invalid token | auth：令牌无效")
	// ErrTokenExpired reports an expired one-time token. | ErrTokenExpired 表示一次性令牌已过期。
	ErrTokenExpired = errs.New("auth: token expired | auth：令牌已过期")
	// ErrTokenUsed reports an already consumed one-time token. | ErrTokenUsed 表示一次性令牌已被使用。
	ErrTokenUsed = errs.New("auth: token already used | auth：令牌已被使用")
	// ErrTooManyAttempts reports a rate or attempt limit. | ErrTooManyAttempts 表示超过速率或尝试次数限制。
	ErrTooManyAttempts = errs.New("auth: too many attempts | auth：尝试次数过多")
	// ErrStoreUnavailable reports a store backend failure. | ErrStoreUnavailable 表示存储后端故障。
	ErrStoreUnavailable = errs.New("auth: store unavailable | auth：存储不可用")
	// ErrConflict reports an optimistic-concurrency conflict. | ErrConflict 表示乐观并发冲突。
	ErrConflict = errs.New("auth: conflict | auth：冲突")
	// ErrNotSupported reports an operation the active backend does not implement. | ErrNotSupported 表示当前后端不支持该操作。
	ErrNotSupported = errs.New("auth: not supported | auth：不支持")
)

// UserStatus is the lifecycle state of a user account. | UserStatus 是用户账号的生命周期状态。
type UserStatus string

const (
	// UserPending is an account created but not yet activated. | UserPending 表示账号已创建但尚未激活。
	UserPending UserStatus = "pending"
	// UserActive is a normally usable account. | UserActive 表示正常可用的账号。
	UserActive UserStatus = "active"
	// UserLocked is a temporarily locked account. | UserLocked 表示被临时锁定的账号。
	UserLocked UserStatus = "locked"
	// UserDisabled is an administratively disabled account. | UserDisabled 表示被管理员禁用的账号。
	UserDisabled UserStatus = "disabled"
)

// User is the canonical account record shared by every protocol module. | User 是各协议模块共享的规范账号记录。
type User struct {
	// ID is the immutable internal identifier. | ID 是不可变的内部标识。
	ID string `json:"id"`
	// Username is the unique login name. | Username 是唯一登录名。
	Username string `json:"username,omitempty"`
	// Email is the primary email address. | Email 是主邮箱地址。
	Email string `json:"email,omitempty"`
	// EmailVerified reports a completed email verification. | EmailVerified 表示邮箱验证已完成。
	EmailVerified bool `json:"emailVerified,omitempty"`
	// Phone is the primary phone number in E.164 form when possible. | Phone 是主手机号，尽量使用 E.164 形式。
	Phone string `json:"phone,omitempty"`
	// PhoneVerified reports a completed phone verification. | PhoneVerified 表示手机号验证已完成。
	PhoneVerified bool `json:"phoneVerified,omitempty"`
	// DisplayName is the human-readable name. | DisplayName 是展示名称。
	DisplayName string `json:"displayName,omitempty"`
	// GivenName and FamilyName follow the OIDC profile claim names. | GivenName 与 FamilyName 对应 OIDC profile 声明。
	GivenName string `json:"givenName,omitempty"`
	// FamilyName is the family name. | FamilyName 是姓氏。
	FamilyName string `json:"familyName,omitempty"`
	// MiddleName, Nickname, Profile, Picture, Website, Gender, Birthdate, Zoneinfo and Locale are
	// optional OIDC profile attributes. | MiddleName、Nickname、Profile、Picture、Website、Gender、
	// Birthdate、Zoneinfo 与 Locale 是可选的 OIDC profile 属性。
	MiddleName string `json:"middleName,omitempty"`
	// Nickname is the casual name. | Nickname 是常用昵称。
	Nickname string `json:"nickname,omitempty"`
	// Profile is the URL of the profile page. | Profile 是个人资料页 URL。
	Profile string `json:"profile,omitempty"`
	// Picture is the URL of the profile picture. | Picture 是头像 URL。
	Picture string `json:"picture,omitempty"`
	// Website is the URL of the user's web page. | Website 是用户网页 URL。
	Website string `json:"website,omitempty"`
	// Gender is the OIDC gender claim. | Gender 是 OIDC gender 声明。
	Gender string `json:"gender,omitempty"`
	// Birthdate is the OIDC birthdate claim in ISO 8601 form. | Birthdate 是 ISO 8601 形式的 OIDC birthdate 声明。
	Birthdate string `json:"birthdate,omitempty"`
	// Zoneinfo is the time zone name. | Zoneinfo 是时区名称。
	Zoneinfo string `json:"zoneinfo,omitempty"`
	// Locale is the BCP 47 locale tag. | Locale 是 BCP 47 语言区域标签。
	Locale string `json:"locale,omitempty"`
	// Address is the OIDC address claim in its JSON form. | Address 是 JSON 形式的 OIDC address 声明。
	Address map[string]string `json:"address,omitempty"`
	// Status is the lifecycle state. | Status 是生命周期状态。
	Status UserStatus `json:"status"`
	// PasswordHash is the encoded password hash; an empty value means password login is disabled. | PasswordHash 是编码后的口令哈希；空值表示禁用口令登录。
	PasswordHash string `json:"-"`
	// PasswordChangedAt is the time the password was last changed. | PasswordChangedAt 是口令最后修改时间。
	PasswordChangedAt time.Time `json:"passwordChangedAt,omitempty"`
	// PasswordHistory holds previous encoded hashes used for reuse prevention. | PasswordHistory 保存用于防止复用的历史编码哈希。
	PasswordHistory []string `json:"-"`
	// MFAEnabled reports whether at least one enabled second factor exists. | MFAEnabled 表示至少存在一个已启用的第二因素。
	MFAEnabled bool `json:"mfaEnabled,omitempty"`
	// FailedLoginAttempts counts consecutive failures since the last success. | FailedLoginAttempts 是上次成功以来的连续失败次数。
	FailedLoginAttempts int `json:"-"`
	// LockedUntil is the end of a temporary lockout. | LockedUntil 是临时锁定的结束时间。
	LockedUntil time.Time `json:"lockedUntil,omitempty"`
	// LastLoginAt is the last successful authentication time. | LastLoginAt 是最后一次成功认证时间。
	LastLoginAt time.Time `json:"lastLoginAt,omitempty"`
	// LastLoginIP is the last successful authentication source address. | LastLoginIP 是最后一次成功认证来源地址。
	LastLoginIP string `json:"lastLoginIp,omitempty"`
	// CreatedAt is the creation time. | CreatedAt 是创建时间。
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the last modification time. | UpdatedAt 是最后修改时间。
	UpdatedAt time.Time `json:"updatedAt"`
	// ExternalID is an optional provisioning identifier from an upstream directory. | ExternalID 是可选的上级目录预配标识。
	ExternalID string `json:"externalId,omitempty"`
	// Metadata holds application-defined scalar attributes. | Metadata 保存应用自定义的标量属性。
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Clone returns a deep copy of u. | Clone 返回 u 的深拷贝。
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	c := *u
	if len(u.PasswordHistory) > 0 {
		c.PasswordHistory = append([]string(nil), u.PasswordHistory...)
	}
	if len(u.Address) > 0 {
		c.Address = make(map[string]string, len(u.Address))
		for k, v := range u.Address {
			c.Address[k] = v
		}
	}
	if len(u.Metadata) > 0 {
		c.Metadata = make(map[string]string, len(u.Metadata))
		for k, v := range u.Metadata {
			c.Metadata[k] = v
		}
	}
	return &c
}

// DisplayNameOrUsername returns DisplayName, falling back to Username then Email. | DisplayNameOrUsername 返回 DisplayName，缺失时回退到 Username 再回退到 Email。
func (u *User) DisplayNameOrUsername() string {
	if u == nil {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Username != "" {
		return u.Username
	}
	return u.Email
}

// CanLogin reports whether the account may start an interactive login at now. | CanLogin 报告账号在 now 时刻是否可开始交互式登录。
func (u *User) CanLogin(now time.Time) error {
	if u == nil {
		return ErrUserNotFound
	}
	switch u.Status {
	case UserActive:
	case UserDisabled:
		return ErrAccountDisabled
	case UserPending:
		return ErrAccountPending
	case UserLocked:
		if u.LockedUntil.IsZero() || now.Before(u.LockedUntil) {
			return ErrAccountLocked
		}
	default:
		return ErrAccountDisabled
	}
	if !u.LockedUntil.IsZero() && now.Before(u.LockedUntil) {
		return ErrAccountLocked
	}
	return nil
}

// Principal is an authenticated subject as seen by a resource server. | Principal 是资源服务器看到的已认证主体。
//
// The field names follow the JWT and OIDC registered claims so a principal can be projected into a
// token or a SCIM resource without a lossy intermediate model. | 字段名沿用 JWT 与 OIDC 登记声明，
// 因此主体可以直接投影为令牌或 SCIM 资源，无需经过有损的中间模型。
type Principal struct {
	// Subject is the stable identifier of the authenticated subject. | Subject 是已认证主体的稳定标识。
	Subject string `json:"sub"`
	// Issuer identifies the authority that authenticated the subject. | Issuer 标识认证该主体的签发方。
	Issuer string `json:"iss,omitempty"`
	// Audience lists the intended resource servers. | Audience 列出目标资源服务器。
	Audience []string `json:"aud,omitempty"`
	// ClientID identifies the OAuth client or relying party. | ClientID 标识 OAuth 客户端或依赖方。
	ClientID string `json:"client_id,omitempty"`
	// Scopes are the granted OAuth scopes. | Scopes 是已授予的 OAuth 作用域。
	Scopes []string `json:"scope,omitempty"`
	// Roles are the granted RBAC roles. | Roles 是已授予的 RBAC 角色。
	Roles []string `json:"roles,omitempty"`
	// Permissions are the effective permissions when the authority resolves them eagerly. | Permissions 是签发方提前解析后的有效权限。
	Permissions []string `json:"permissions,omitempty"`
	// Groups are directory group identifiers. | Groups 是目录组标识。
	Groups []string `json:"groups,omitempty"`
	// Attributes carry protocol-specific scalar claims. | Attributes 保存协议相关的标量声明。
	Attributes map[string]string `json:"attributes,omitempty"`
	// AuthTime is the time the end user actually authenticated. | AuthTime 是最终用户实际完成认证的时间。
	AuthTime time.Time `json:"auth_time,omitempty"`
	// ACR is the authentication context class reference. | ACR 是认证上下文类引用。
	ACR string `json:"acr,omitempty"`
	// AMR lists the authentication methods used. | AMR 列出使用的认证方法。
	AMR []string `json:"amr,omitempty"`
	// SessionID links the principal to a server-side session. | SessionID 把主体关联到服务端会话。
	SessionID string `json:"sid,omitempty"`
	// ExpiresAt is the credential expiry; the zero value means no expiry. | ExpiresAt 是凭据过期时间；零值表示不过期。
	ExpiresAt time.Time `json:"exp,omitempty"`
	// IssuedAt is the credential issue time. | IssuedAt 是凭据签发时间。
	IssuedAt time.Time `json:"iat,omitempty"`
	// Email and EmailVerified mirror the OIDC email claims. | Email 与 EmailVerified 对应 OIDC email 声明。
	Email string `json:"email,omitempty"`
	// EmailVerified reports a verified email address. | EmailVerified 表示邮箱地址已验证。
	EmailVerified bool `json:"email_verified,omitempty"`
	// Username is the login name when one exists. | Username 是登录名（存在时）。
	Username string `json:"preferred_username,omitempty"`
	// DisplayName is the human-readable name. | DisplayName 是展示名称。
	DisplayName string `json:"name,omitempty"`
}

// Clone returns a deep copy of p. | Clone 返回 p 的深拷贝。
func (p *Principal) Clone() *Principal {
	if p == nil {
		return nil
	}
	c := *p
	c.Audience = append([]string(nil), p.Audience...)
	c.Scopes = append([]string(nil), p.Scopes...)
	c.Roles = append([]string(nil), p.Roles...)
	c.Permissions = append([]string(nil), p.Permissions...)
	c.Groups = append([]string(nil), p.Groups...)
	c.AMR = append([]string(nil), p.AMR...)
	if len(p.Attributes) > 0 {
		c.Attributes = make(map[string]string, len(p.Attributes))
		for k, v := range p.Attributes {
			c.Attributes[k] = v
		}
	}
	return &c
}

// HasScope reports whether want is present in Scopes. | HasScope 报告 want 是否存在于 Scopes。
func (p *Principal) HasScope(want string) bool {
	if p == nil {
		return false
	}
	for _, s := range p.Scopes {
		if s == want {
			return true
		}
	}
	return false
}

// HasRole reports whether want is present in Roles. | HasRole 报告 want 是否存在于 Roles。
func (p *Principal) HasRole(want string) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Roles {
		if r == want {
			return true
		}
	}
	return false
}

// HasPermission reports whether the principal holds permission, honouring "*", "prefix:*" and
// generic trailing "*" wildcards. | HasPermission 报告主体是否持有 permission，支持 "*"、"prefix:*"
// 与通用尾部 "*" 通配。
func (p *Principal) HasPermission(permission string) bool {
	if p == nil {
		return false
	}
	for _, held := range p.Permissions {
		if MatchPermission(held, permission) {
			return true
		}
	}
	return false
}

// Expired reports whether the principal credential expired at now. | Expired 报告主体凭据在 now 时刻是否已过期。
func (p *Principal) Expired(now time.Time) bool {
	return p == nil || (!p.ExpiresAt.IsZero() && !now.Before(p.ExpiresAt))
}

// MatchPermission reports whether held grants want. A held value of "*" grants every permission;
// a held value ending in ":*" grants every permission in that namespace; any other trailing "*"
// grants every permission with the preceding prefix. | MatchPermission 报告 held 是否授予 want。
// held 为 "*" 时授予全部权限；以 ":*" 结尾时授予该命名空间下的全部权限；其它尾部 "*" 授予以
// 其前缀开头的全部权限。
func MatchPermission(held, want string) bool {
	if held == "" || want == "" {
		return false
	}
	if held == want || held == "*" {
		return true
	}
	if strings.HasSuffix(held, ":*") {
		prefix := strings.TrimSuffix(held, "*")
		return strings.HasPrefix(want, prefix)
	}
	if strings.HasSuffix(held, "*") {
		return strings.HasPrefix(want, strings.TrimSuffix(held, "*"))
	}
	return false
}

// Identity is an external account linked to a local user. | Identity 是关联到本地用户的外部账号。
type Identity struct {
	// Provider is the provider key, for example "google" or "azuread". | Provider 是提供方键，例如 "google" 或 "azuread"。
	Provider string `json:"provider"`
	// Subject is the provider's stable identifier for the account. | Subject 是提供方对该账号的稳定标识。
	Subject string `json:"subject"`
	// UserID is the local user identifier. | UserID 是本地用户标识。
	UserID string `json:"userId"`
	// Email and EmailVerified mirror the provider's claim when available. | Email 与 EmailVerified 在可用时镜像提供方声明。
	Email string `json:"email,omitempty"`
	// EmailVerified reports whether the provider verified the email address. | EmailVerified 表示提供方是否已验证邮箱地址。
	EmailVerified bool `json:"emailVerified,omitempty"`
	// Username, Name and AvatarURL are display attributes. | Username、Name 与 AvatarURL 是展示属性。
	Username string `json:"username,omitempty"`
	// Name is the provider display name. | Name 是提供方展示名称。
	Name string `json:"name,omitempty"`
	// AvatarURL is the provider avatar URL. | AvatarURL 是提供方头像 URL。
	AvatarURL string `json:"avatarUrl,omitempty"`
	// Raw holds provider-specific scalar attributes. | Raw 保存提供方相关的标量属性。
	Raw map[string]string `json:"raw,omitempty"`
	// CreatedAt is the creation time. | CreatedAt 是创建时间。
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the last modification time. | UpdatedAt 是最后修改时间。
	UpdatedAt time.Time `json:"updatedAt"`
}

// Clone returns a deep copy of i. | Clone 返回 i 的深拷贝。
func (i *Identity) Clone() *Identity {
	if i == nil {
		return nil
	}
	c := *i
	if len(i.Raw) > 0 {
		c.Raw = make(map[string]string, len(i.Raw))
		for k, v := range i.Raw {
			c.Raw[k] = v
		}
	}
	return &c
}

// Session is a server-side login session. | Session 是服务端登录会话。
type Session struct {
	// ID is the opaque bearer value carried by the session cookie. | ID 是会话 Cookie 携带的不透明承载值。
	ID string `json:"id"`
	// UserID is the authenticated user. | UserID 是已认证用户。
	UserID string `json:"userId"`
	// ClientID is the application or OAuth client that created the session. | ClientID 是创建会话的应用或 OAuth 客户端。
	ClientID string `json:"clientId,omitempty"`
	// DeviceID is an optional stable device identifier. | DeviceID 是可选的稳定设备标识。
	DeviceID string `json:"deviceId,omitempty"`
	// IP is the source address at creation time. | IP 是创建时的来源地址。
	IP string `json:"ip,omitempty"`
	// UserAgent is the source user agent at creation time. | UserAgent 是创建时的来源 User-Agent。
	UserAgent string `json:"userAgent,omitempty"`
	// CreatedAt is the creation time. | CreatedAt 是创建时间。
	CreatedAt time.Time `json:"createdAt"`
	// AuthenticatedAt is when the end user actually authenticated. Rotation advances CreatedAt but
	// preserves AuthenticatedAt, so the OIDC auth_time stays stable. The zero value means CreatedAt. |
	// AuthenticatedAt 是最终用户实际完成认证的时间。轮换会推进 CreatedAt 但保留 AuthenticatedAt，
	// 因此 OIDC auth_time 保持稳定。零值表示使用 CreatedAt。
	AuthenticatedAt time.Time `json:"authenticatedAt,omitempty"`
	// UpdatedAt is the last persisted update time. | UpdatedAt 是最后持久化更新时间。
	UpdatedAt time.Time `json:"updatedAt"`
	// LastSeenAt is the last validation time. | LastSeenAt 是最后一次校验时间。
	LastSeenAt time.Time `json:"lastSeenAt"`
	// IdleExpiresAt and ExpiresAt are the idle and absolute deadlines. | IdleExpiresAt 与 ExpiresAt 是空闲与绝对期限。
	IdleExpiresAt time.Time `json:"idleExpiresAt"`
	// ExpiresAt is the absolute deadline; the zero value means no absolute deadline. | ExpiresAt 是绝对期限；零值表示没有绝对期限。
	ExpiresAt time.Time `json:"expiresAt"`
	// RevokedAt is set when the session is revoked. | RevokedAt 在会话被撤销时设置。
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	// RevokeReason is a diagnostic reason for revocation. | RevokeReason 是撤销的诊断原因。
	RevokeReason string `json:"revokeReason,omitempty"`
	// AMR lists the authentication methods used. | AMR 列出使用的认证方法。
	AMR []string `json:"amr,omitempty"`
	// ACR is the authentication context class reference. | ACR 是认证上下文类引用。
	ACR string `json:"acr,omitempty"`
	// CSRFSecret is the per-session CSRF secret. | CSRFSecret 是每会话的 CSRF 密钥。
	CSRFSecret string `json:"-"`
	// Data holds application-defined scalar attributes. | Data 保存应用自定义的标量属性。
	Data map[string]string `json:"data,omitempty"`
}

// Active reports whether the session may be used at now. | Active 报告会话在 now 时刻是否可用。
func (s *Session) Active(now time.Time) bool {
	if s == nil || s.RevokedAt != nil || s.ID == "" {
		return false
	}
	if !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt) {
		return false
	}
	if !s.IdleExpiresAt.IsZero() && !now.Before(s.IdleExpiresAt) {
		return false
	}
	return true
}

// Clone returns a deep copy of s. | Clone 返回 s 的深拷贝。
func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	c := *s
	if s.RevokedAt != nil {
		t := *s.RevokedAt
		c.RevokedAt = &t
	}
	c.AMR = append([]string(nil), s.AMR...)
	if len(s.Data) > 0 {
		c.Data = make(map[string]string, len(s.Data))
		for k, v := range s.Data {
			c.Data[k] = v
		}
	}
	return &c
}

// CredentialType names an authentication factor. | CredentialType 命名一种认证因素。
type CredentialType string

const (
	// CredentialPassword is a password record. | CredentialPassword 是口令记录。
	CredentialPassword CredentialType = "password"
	// CredentialTOTP is an RFC 6238 time-based one-time password. | CredentialTOTP 是 RFC 6238 基于时间的一次性口令。
	CredentialTOTP CredentialType = "totp"
	// CredentialHOTP is an RFC 4226 counter-based one-time password. | CredentialHOTP 是 RFC 4226 基于计数器的一次性口令。
	CredentialHOTP CredentialType = "hotp"
	// CredentialWebAuthn is a WebAuthn public-key credential. | CredentialWebAuthn 是 WebAuthn 公钥凭据。
	CredentialWebAuthn CredentialType = "webauthn"
	// CredentialRecoveryCode is a single-use recovery code. | CredentialRecoveryCode 是单次恢复码。
	CredentialRecoveryCode CredentialType = "recovery_code"
	// CredentialOIDC is a federated OpenID Connect identity. | CredentialOIDC 是联邦 OpenID Connect 身份。
	CredentialOIDC CredentialType = "oidc"
	// CredentialSAML is a federated SAML identity. | CredentialSAML 是联邦 SAML 身份。
	CredentialSAML CredentialType = "saml"
)

// Credential is an enrolled authentication factor. | Credential 是已登记的认证因素。
type Credential struct {
	// ID is the immutable credential identifier. | ID 是不可变凭据标识。
	ID string `json:"id"`
	// UserID is the owning user. | UserID 是所属用户。
	UserID string `json:"userId"`
	// Type is the factor type. | Type 是因素类型。
	Type CredentialType `json:"type"`
	// Name is a user-visible label. | Name 是用户可见的标签。
	Name string `json:"name,omitempty"`
	// Secret is the encoded secret or public-key record. | Secret 是编码后的密钥或公钥记录。
	Secret string `json:"-"`
	// Data holds factor-specific scalar attributes. | Data 保存因素相关的标量属性。
	Data map[string]string `json:"data,omitempty"`
	// Disabled excludes the factor from authentication. | Disabled 表示该因素不参与认证。
	Disabled bool `json:"disabled,omitempty"`
	// CreatedAt is the creation time. | CreatedAt 是创建时间。
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the last modification time. | UpdatedAt 是最后修改时间。
	UpdatedAt time.Time `json:"updatedAt"`
	// LastUsedAt is the last successful verification time. | LastUsedAt 是最后一次成功校验时间。
	LastUsedAt time.Time `json:"lastUsedAt,omitempty"`
}

// Clone returns a deep copy of c. | Clone 返回 c 的深拷贝。
func (c *Credential) Clone() *Credential {
	if c == nil {
		return nil
	}
	out := *c
	if len(c.Data) > 0 {
		out.Data = make(map[string]string, len(c.Data))
		for k, v := range c.Data {
			out.Data[k] = v
		}
	}
	return &out
}

// MFAVerifier verifies one enrolled second factor. | MFAVerifier 校验一个已登记的第二因素。
//
// Implementations are provided by the otp and webauthn subpackages and registered on Service with
// RegisterMFAVerifier. | 实现由 otp 与 webauthn 子包提供，并通 Service.RegisterMFAVerifier 注册。
type MFAVerifier interface {
	// Verify reports whether response proves possession of credential for user. | Verify 报告 response 是否证明 user 持有 credential。
	Verify(ctx context.Context, user *User, credential *Credential, response string) (bool, error)
}

// AuditEvent is an append-only security-relevant event. | AuditEvent 是只追加的安全相关事件。
type AuditEvent struct {
	// ID is the event identifier. | ID 是事件标识。
	ID string `json:"id"`
	// Type is a stable event name such as "login.succeeded". | Type 是稳定事件名，例如 "login.succeeded"。
	Type string `json:"type"`
	// ActorID is the user or client that caused the event. | ActorID 是触发事件的用户或客户端。
	ActorID string `json:"actorId,omitempty"`
	// UserID is the affected user. | UserID 是受影响的用户。
	UserID string `json:"userId,omitempty"`
	// SessionID and ClientID identify the session and client context. | SessionID 与 ClientID 标识会话与客户端上下文。
	SessionID string `json:"sessionId,omitempty"`
	// ClientID is the application or OAuth client involved in the event. | ClientID 是事件涉及的应用或 OAuth 客户端。
	ClientID string `json:"clientId,omitempty"`
	// IP and UserAgent describe the request source. | IP 与 UserAgent 描述请求来源。
	IP string `json:"ip,omitempty"`
	// UserAgent is the request User-Agent. | UserAgent 是请求 User-Agent。
	UserAgent string `json:"userAgent,omitempty"`
	// Outcome is "success", "failure" or "denied". | Outcome 取值为 "success"、"failure" 或 "denied"。
	Outcome string `json:"outcome,omitempty"`
	// Detail holds event-specific scalar attributes and must never contain secrets. | Detail 保存事件相关的标量属性，绝不能包含密钥。
	Detail map[string]string `json:"detail,omitempty"`
	// At is the event time. | At 是事件时间。
	At time.Time `json:"at"`
}

// Clone returns a deep copy of e. | Clone 返回 e 的深拷贝。
func (e *AuditEvent) Clone() *AuditEvent {
	if e == nil {
		return nil
	}
	c := *e
	if len(e.Detail) > 0 {
		c.Detail = make(map[string]string, len(e.Detail))
		for k, v := range e.Detail {
			c.Detail[k] = v
		}
	}
	return &c
}

// AuditQuery filters audit records. | AuditQuery 过滤审计记录。
type AuditQuery struct {
	// Type filters by event type. | Type 按事件类型过滤。
	Type string
	// UserID filters by affected user. | UserID 按受影响用户过滤。
	UserID string
	// ActorID filters by actor. | ActorID 按触发者过滤。
	ActorID string
	// Outcome filters by outcome. | Outcome 按结果过滤。
	Outcome string
	// Since and Until bound the event time. | Since 与 Until 限定事件时间。
	Since time.Time
	// Until is the inclusive upper time bound when non-zero. | Until 是非零时的包含式时间上限。
	Until time.Time
	// Offset and Limit paginate the result; Limit 0 means the store default. | Offset 与 Limit 分页；Limit 为 0 表示存储默认值。
	Offset int
	// Limit is the maximum page size; 0 means the store default. | Limit 是最大页大小；0 表示存储默认值。
	Limit int
	// Descending reverses the chronological order. | Descending 反转时间顺序。
	Descending bool
}

// UserQuery filters user listings. | UserQuery 过滤用户列表。
type UserQuery struct {
	// Query is a case-insensitive prefix substring applied to username, email and display name. | Query 是应用于用户名、邮箱与展示名的大小写不敏感子串。
	Query string
	// Status filters by lifecycle state. | Status 按生命周期状态过滤。
	Status UserStatus
	// Offset and Limit paginate the result. | Offset 与 Limit 分页。
	Offset int
	// Limit is the maximum page size; 0 means the store default. | Limit 是最大页大小；0 表示存储默认值。
	Limit int
}

type principalKey struct{}

// ContextWithPrincipal returns a child context carrying p. | ContextWithPrincipal 返回携带 p 的子上下文。
func ContextWithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext returns the principal stored by ContextWithPrincipal. | PrincipalFromContext 返回 ContextWithPrincipal 存储的主体。
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}

// PrincipalFromRequest returns the principal attached to r by HTTPMiddleware. | PrincipalFromRequest 返回 HTTPMiddleware 附加到 r 的主体。
func PrincipalFromRequest(r *http.Request) (*Principal, bool) {
	if r == nil {
		return nil, false
	}
	return PrincipalFromContext(r.Context())
}

// Now returns the UTC time from clock, or time.Now when clock is nil. | Now 返回 clock 提供的 UTC 时间；clock 为空时返回 time.Now。
func Now(clock func() time.Time) time.Time {
	if clock == nil {
		return time.Now().UTC()
	}
	return clock().UTC()
}

// errDetailConfig attaches context to ErrInvalidConfig. | errDetailConfig 为 ErrInvalidConfig 附加上下文。
func errDetailConfig(format string, args ...any) error {
	return errs.Detail(ErrInvalidConfig, format, args...)
}
