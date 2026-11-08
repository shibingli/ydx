package auth

import (
	"context"
	"time"
)

// UserStore persists user accounts. | UserStore 持久化用户账号。
//
// Implementations must treat username, email and phone lookups case-insensitively, must return
// ErrUserNotFound for an absent record, and must not mutate the values they receive. | 实现必须把
// 用户名、邮箱与手机号查询视为大小写不敏感，记录缺失时返回 ErrUserNotFound，且不得修改收到的值。
type UserStore interface {
	// CreateUser stores a new user and returns ErrUserExists on a duplicate identifier. | CreateUser 保存新用户，标识重复时返回 ErrUserExists。
	CreateUser(ctx context.Context, user *User) error
	// GetUser returns a user by internal identifier. | GetUser 按内部标识返回用户。
	GetUser(ctx context.Context, id string) (*User, error)
	// GetUserByUsername returns a user by login name. | GetUserByUsername 按登录名返回用户。
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	// GetUserByEmail returns a user by email address. | GetUserByEmail 按邮箱地址返回用户。
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// GetUserByPhone returns a user by phone number. | GetUserByPhone 按手机号返回用户。
	GetUserByPhone(ctx context.Context, phone string) (*User, error)
	// UpdateUser replaces an existing user and returns ErrUserNotFound when it is absent. | UpdateUser 替换已有用户，用户缺失时返回 ErrUserNotFound。
	UpdateUser(ctx context.Context, user *User) error
	// DeleteUser removes a user by internal identifier. | DeleteUser 按内部标识删除用户。
	DeleteUser(ctx context.Context, id string) error
	// ListUsers returns a filtered page and the total number of matching records. | ListUsers 返回过滤后的一页与匹配总数。
	ListUsers(ctx context.Context, query UserQuery) ([]*User, int, error)
}

// SessionStore persists login sessions. | SessionStore 持久化登录会话。
type SessionStore interface {
	// CreateSession stores a new session. | CreateSession 保存新会话。
	CreateSession(ctx context.Context, session *Session) error
	// GetSession returns a session by identifier or ErrSessionNotFound. | GetSession 按标识返回会话，缺失时返回 ErrSessionNotFound。
	GetSession(ctx context.Context, id string) (*Session, error)
	// UpdateSession replaces an existing session. | UpdateSession 替换已有会话。
	UpdateSession(ctx context.Context, session *Session) error
	// DeleteSession removes a session. | DeleteSession 删除会话。
	DeleteSession(ctx context.Context, id string) error
	// ListSessionsByUser returns every session of a user, including revoked ones. | ListSessionsByUser 返回用户的全部会话，包括已撤销的。
	ListSessionsByUser(ctx context.Context, userID string) ([]*Session, error)
	// DeleteSessionsByUser removes every session of a user and returns the number removed. | DeleteSessionsByUser 删除用户的全部会话并返回删除数量。
	DeleteSessionsByUser(ctx context.Context, userID string) (int, error)
	// DeleteExpiredSessions removes sessions whose absolute deadline passed at now. | DeleteExpiredSessions 删除绝对期限已过的会话。
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error)
}

// IdentityStore persists external identity links. | IdentityStore 持久化外部身份关联。
type IdentityStore interface {
	// CreateIdentity stores a new link and returns ErrIdentityExists on a duplicate provider/subject pair. | CreateIdentity 保存新关联，provider/subject 重复时返回 ErrIdentityExists。
	CreateIdentity(ctx context.Context, identity *Identity) error
	// GetIdentity returns a link by provider and subject. | GetIdentity 按提供方与 subject 返回关联。
	GetIdentity(ctx context.Context, provider, subject string) (*Identity, error)
	// ListIdentitiesByUser returns every link of a user. | ListIdentitiesByUser 返回用户的全部关联。
	ListIdentitiesByUser(ctx context.Context, userID string) ([]*Identity, error)
	// UpdateIdentity replaces an existing link. | UpdateIdentity 替换已有链接。
	UpdateIdentity(ctx context.Context, identity *Identity) error
	// DeleteIdentity removes a link. | DeleteIdentity 删除关联。
	DeleteIdentity(ctx context.Context, provider, subject string) error
}

// CredentialStore persists enrolled authentication factors. | CredentialStore 持久化已登记的认证因素。
type CredentialStore interface {
	// CreateCredential stores a new factor and returns ErrCredentialExists on a duplicate ID. | CreateCredential 保存新因素，ID 重复时返回 ErrCredentialExists。
	CreateCredential(ctx context.Context, credential *Credential) error
	// GetCredential returns a factor by ID. | GetCredential 按 ID 返回因素。
	GetCredential(ctx context.Context, id string) (*Credential, error)
	// UpdateCredential replaces an existing factor. | UpdateCredential 替换已有因素。
	UpdateCredential(ctx context.Context, credential *Credential) error
	// DeleteCredential removes a factor. | DeleteCredential 删除因素。
	DeleteCredential(ctx context.Context, id string) error
	// ListCredentialsByUser returns every factor of a user. | ListCredentialsByUser 返回用户的全部因素。
	ListCredentialsByUser(ctx context.Context, userID string) ([]*Credential, error)
	// ListCredentialsByUserType returns the factors of a user with one type. | ListCredentialsByUserType 返回用户某一类型的因素。
	ListCredentialsByUserType(ctx context.Context, userID string, typ CredentialType) ([]*Credential, error)
}

// AuditStore persists append-only audit events. | AuditStore 持久化只追加的审计事件。
type AuditStore interface {
	// RecordAudit appends an event. | RecordAudit 追加事件。
	RecordAudit(ctx context.Context, event *AuditEvent) error
	// ListAudit returns a filtered page and the total number of matching records. | ListAudit 返回过滤后的一页与匹配总数。
	ListAudit(ctx context.Context, query AuditQuery) ([]*AuditEvent, int, error)
}

// OneTimeToken is a hashed, single-use token for email verification, password reset or
// invitation flows. | OneTimeToken 是用于邮箱验证、口令重置或邀请流程的哈希化单次令牌。
type OneTimeToken struct {
	// Hash is HashToken(raw token); the raw token is never stored. | Hash 是 HashToken(原始令牌)；原始令牌永不存储。
	Hash string
	// UserID is the affected user. | UserID 是受影响的用户。
	UserID string
	// Purpose separates token namespaces such as "reset_password". | Purpose 区分令牌命名空间，例如 "reset_password"。
	Purpose string
	// Metadata holds flow-specific scalar attributes. | Metadata 保存流程相关的标量属性。
	Metadata map[string]string
	// CreatedAt and ExpiresAt bound the token lifetime. | CreatedAt 与 ExpiresAt 限定令牌生命周期。
	CreatedAt time.Time
	// ExpiresAt is the time at which the token expires. | ExpiresAt 是令牌过期时间。
	ExpiresAt time.Time
	// UsedAt is non-zero once the token has been consumed. | UsedAt 在令牌被消费后非零。
	UsedAt time.Time
}

// Clone returns a deep copy of t. | Clone 返回 t 的深拷贝。
func (t *OneTimeToken) Clone() *OneTimeToken {
	if t == nil {
		return nil
	}
	c := *t
	if len(t.Metadata) > 0 {
		c.Metadata = make(map[string]string, len(t.Metadata))
		for k, v := range t.Metadata {
			c.Metadata[k] = v
		}
	}
	return &c
}

// TokenStore persists one-time tokens. | TokenStore 持久化一次性令牌。
type TokenStore interface {
	// CreateToken stores a new token, replacing any token with the same purpose and hash. | CreateToken
	// 保存新令牌，并替换相同用途与哈希的令牌。
	CreateToken(ctx context.Context, token *OneTimeToken) error
	// ConsumeToken atomically marks a token used and returns it; it returns ErrTokenInvalid,
	// ErrTokenExpired or ErrTokenUsed when the token cannot be consumed. | ConsumeToken 原子地标记令牌已用并返回；
	// 令牌无法消费时返回 ErrTokenInvalid、ErrTokenExpired 或 ErrTokenUsed。
	ConsumeToken(ctx context.Context, hash, purpose string, now time.Time) (*OneTimeToken, error)
	// PeekToken returns a token without consuming it. | PeekToken 返回令牌但不消费。
	PeekToken(ctx context.Context, hash, purpose string, now time.Time) (*OneTimeToken, error)
	// DeleteTokensByUser removes every token of a user and purpose. | DeleteTokensByUser 删除用户某用途的全部令牌。
	DeleteTokensByUser(ctx context.Context, userID, purpose string) (int, error)
}

// Stores groups the persistence ports used by Service. | Stores 汇总 Service 使用的持久化端口。
type Stores struct {
	// Users stores user accounts. | Users 存储用户账号。
	Users UserStore
	// Sessions stores login sessions. | Sessions 存储登录会话。
	Sessions SessionStore
	// Identities stores external identity links. | Identities 存储外部身份关联。
	Identities IdentityStore
	// Credentials stores enrolled factors. | Credentials 存储已登记因素。
	Credentials CredentialStore
	// Audits stores audit events. | Audits 存储审计事件。
	Audits AuditStore
	// Tokens stores one-time tokens. | Tokens 存储一次性令牌。
	Tokens TokenStore
}

// Validate reports whether every required store is present. | Validate 报告每个必需存储是否齐全。
func (s Stores) Validate() error {
	switch {
	case s.Users == nil:
		return errDetailConfig("Users store is nil | Users 存储为空")
	case s.Sessions == nil:
		return errDetailConfig("Sessions store is nil | Sessions 存储为空")
	case s.Identities == nil:
		return errDetailConfig("Identities store is nil | Identities 存储为空")
	case s.Credentials == nil:
		return errDetailConfig("Credentials store is nil | Credentials 存储为空")
	case s.Audits == nil:
		return errDetailConfig("Audits store is nil | Audits 存储为空")
	case s.Tokens == nil:
		return errDetailConfig("Tokens store is nil | Tokens 存储为空")
	}
	return nil
}
