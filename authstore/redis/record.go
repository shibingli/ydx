package redis

import (
	"strconv"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// userRecord is the persisted form of auth.User. PasswordHash, PasswordHistory and
// FailedLoginAttempts are tagged json:"-" on auth.User, so they are carried explicitly outside the
// embedded record. | userRecord 是 auth.User 的持久化形态。PasswordHash、PasswordHistory 与
// FailedLoginAttempts 在 auth.User 上标记为 json:"-"，因此在嵌入记录之外显式携带。
type userRecord struct {
	// User is the serialized user. | User 是序列化后的用户。
	User auth.User `json:"user"`
	// PasswordHash is the hidden password hash omitted by auth.User JSON tags. | PasswordHash 是
	// auth.User JSON 标签隐藏的口令哈希。
	PasswordHash string `json:"passwordHash,omitempty"`
	// PasswordHistory is the hidden password history. | PasswordHistory 是隐藏的口令历史。
	PasswordHistory []string `json:"passwordHistory,omitempty"`
	// FailedLoginAttempts is the hidden lockout counter. | FailedLoginAttempts 是隐藏的失败登录计数。
	FailedLoginAttempts int `json:"failedLoginAttempts,omitempty"`
}

// sessionRecord is the persisted form of auth.Session. | sessionRecord 是 auth.Session 的持久化形态。
type sessionRecord struct {
	// Session is the serialized session. | Session 是序列化后的会话。
	Session auth.Session `json:"session"`
	// CSRFSecret is the hidden CSRF secret omitted by auth.Session JSON tags. | CSRFSecret 是
	// auth.Session JSON 标签隐藏的 CSRF 密钥。
	CSRFSecret string `json:"csrfSecret,omitempty"`
}

// credentialRecord is the persisted form of auth.Credential. | credentialRecord 是 auth.Credential 的持久化形态。
type credentialRecord struct {
	// Credential is the serialized credential. | Credential 是序列化后的凭据。
	Credential auth.Credential `json:"credential"`
	// Secret is the hidden credential secret. | Secret 是隐藏的凭据密钥。
	Secret string `json:"secret,omitempty"`
}

// encodeUser serializes user and its hidden fields. | encodeUser 序列化 user 及其隐藏字段。
func encodeUser(user *auth.User) ([]byte, error) {
	c := user.Clone()
	normalizeUserTimes(c)
	rec := userRecord{
		User:                *c,
		PasswordHash:        c.PasswordHash,
		PasswordHistory:     append([]string(nil), c.PasswordHistory...),
		FailedLoginAttempts: c.FailedLoginAttempts,
	}
	return marshalRecord(rec, "user")
}

// decodeUser deserializes a user record. | decodeUser 反序列化用户记录。
func decodeUser(data []byte) (*auth.User, error) {
	var rec userRecord
	if err := unmarshalRecord(data, &rec, "user"); err != nil {
		return nil, err
	}
	user := rec.User.Clone()
	user.PasswordHash = rec.PasswordHash
	user.PasswordHistory = append([]string(nil), rec.PasswordHistory...)
	user.FailedLoginAttempts = rec.FailedLoginAttempts
	normalizeUserTimes(user)
	return user, nil
}

// encodeSession serializes session and its hidden CSRF secret. | encodeSession 序列化 session 及其隐藏 CSRF 密钥。
func encodeSession(session *auth.Session) ([]byte, error) {
	c := session.Clone()
	normalizeSessionTimes(c)
	rec := sessionRecord{Session: *c, CSRFSecret: c.CSRFSecret}
	return marshalRecord(rec, "session")
}

// decodeSession deserializes a session record. | decodeSession 反序列化会话记录。
func decodeSession(data []byte) (*auth.Session, error) {
	var rec sessionRecord
	if err := unmarshalRecord(data, &rec, "session"); err != nil {
		return nil, err
	}
	session := rec.Session.Clone()
	session.CSRFSecret = rec.CSRFSecret
	normalizeSessionTimes(session)
	return session, nil
}

// encodeCredential serializes credential and its hidden secret. | encodeCredential 序列化 credential 及其隐藏密钥。
func encodeCredential(credential *auth.Credential) ([]byte, error) {
	c := credential.Clone()
	normalizeCredentialTimes(c)
	rec := credentialRecord{Credential: *c, Secret: c.Secret}
	return marshalRecord(rec, "credential")
}

// decodeCredential deserializes a credential record. | decodeCredential 反序列化凭据记录。
func decodeCredential(data []byte) (*auth.Credential, error) {
	var rec credentialRecord
	if err := unmarshalRecord(data, &rec, "credential"); err != nil {
		return nil, err
	}
	credential := rec.Credential.Clone()
	credential.Secret = rec.Secret
	normalizeCredentialTimes(credential)
	return credential, nil
}

// encodeIdentity serializes an identity link. | encodeIdentity 序列化身份关联。
func encodeIdentity(identity *auth.Identity) ([]byte, error) {
	c := identity.Clone()
	c.CreatedAt = utcTime(c.CreatedAt)
	c.UpdatedAt = utcTime(c.UpdatedAt)
	return marshalRecord(c, "identity")
}

// decodeIdentity deserializes an identity link. | decodeIdentity 反序列化身份关联。
func decodeIdentity(data []byte) (*auth.Identity, error) {
	var identity auth.Identity
	if err := unmarshalRecord(data, &identity, "identity"); err != nil {
		return nil, err
	}
	identity.CreatedAt = utcTime(identity.CreatedAt)
	identity.UpdatedAt = utcTime(identity.UpdatedAt)
	return &identity, nil
}

// encodeAudit serializes one audit event. | encodeAudit 序列化单个审计事件。
func encodeAudit(event *auth.AuditEvent) ([]byte, error) {
	c := event.Clone()
	c.At = utcTime(c.At)
	return marshalRecord(c, "audit event")
}

// decodeAudit deserializes one audit event. | decodeAudit 反序列化单个审计事件。
func decodeAudit(data []byte) (*auth.AuditEvent, error) {
	var event auth.AuditEvent
	if err := unmarshalRecord(data, &event, "audit event"); err != nil {
		return nil, err
	}
	event.At = utcTime(event.At)
	return &event, nil
}

// encodeToken serializes one one-time token. | encodeToken 序列化单个一次性令牌。
func encodeToken(token *auth.OneTimeToken) ([]byte, error) {
	c := token.Clone()
	normalizeTokenTimes(c)
	return marshalRecord(c, "token")
}

// decodeToken deserializes one one-time token. | decodeToken 反序列化单个一次性令牌。
func decodeToken(data []byte) (*auth.OneTimeToken, error) {
	var token auth.OneTimeToken
	if err := unmarshalRecord(data, &token, "token"); err != nil {
		return nil, err
	}
	normalizeTokenTimes(&token)
	return &token, nil
}

// marshalRecord converts one record and maps encoding failures to auth.ErrInvalidRequest without
// exposing library internals. | marshalRecord 转换一条记录，并把编码失败映射为
// auth.ErrInvalidRequest，且不暴露库内部信息。
func marshalRecord(value any, kind string) ([]byte, error) {
	data, err := ydxjson.Marshal(value)
	if err != nil {
		return nil, errs.Detail(auth.ErrInvalidRequest, "%s cannot be encoded | %s 无法编码", kind, kind)
	}
	return data, nil
}

// unmarshalRecord converts one stored record and maps corruption to auth.ErrStoreUnavailable.
// | unmarshalRecord 转换一条已存记录，并把损坏映射为 auth.ErrStoreUnavailable。
func unmarshalRecord(data []byte, out any, kind string) error {
	if len(data) == 0 {
		return errs.Detail(auth.ErrStoreUnavailable, "stored %s is empty | 存储的 %s 为空", kind, kind)
	}
	if err := ydxjson.Unmarshal(data, out); err != nil {
		return errs.Detail(auth.ErrStoreUnavailable, "stored %s is corrupt | 存储的 %s 数据损坏", kind, kind)
	}
	return nil
}

// utcTime normalizes non-zero times to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}

// utcTimePtr normalizes an optional time. | utcTimePtr 规范化可选时间。
func utcTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := utcTime(*t)
	return &v
}

// normalizeUserTimes normalizes every time carried by a user. | normalizeUserTimes 规范化用户携带的每个时间。
func normalizeUserTimes(user *auth.User) {
	user.PasswordChangedAt = utcTime(user.PasswordChangedAt)
	user.LockedUntil = utcTime(user.LockedUntil)
	user.LastLoginAt = utcTime(user.LastLoginAt)
	user.CreatedAt = utcTime(user.CreatedAt)
	user.UpdatedAt = utcTime(user.UpdatedAt)
}

// normalizeSessionTimes normalizes every time carried by a session. | normalizeSessionTimes 规范化会话携带的每个时间。
func normalizeSessionTimes(session *auth.Session) {
	session.CreatedAt = utcTime(session.CreatedAt)
	session.AuthenticatedAt = utcTime(session.AuthenticatedAt)
	session.UpdatedAt = utcTime(session.UpdatedAt)
	session.LastSeenAt = utcTime(session.LastSeenAt)
	session.IdleExpiresAt = utcTime(session.IdleExpiresAt)
	session.ExpiresAt = utcTime(session.ExpiresAt)
	session.RevokedAt = utcTimePtr(session.RevokedAt)
}

// normalizeCredentialTimes normalizes every time carried by a credential. | normalizeCredentialTimes 规范化凭据携带的每个时间。
func normalizeCredentialTimes(credential *auth.Credential) {
	credential.CreatedAt = utcTime(credential.CreatedAt)
	credential.UpdatedAt = utcTime(credential.UpdatedAt)
	credential.LastUsedAt = utcTime(credential.LastUsedAt)
}

// normalizeTokenTimes normalizes every time carried by a one-time token. | normalizeTokenTimes 规范化一次性令牌携带的每个时间。
func normalizeTokenTimes(token *auth.OneTimeToken) {
	token.CreatedAt = utcTime(token.CreatedAt)
	token.ExpiresAt = utcTime(token.ExpiresAt)
	token.UsedAt = utcTime(token.UsedAt)
}

// expiryFields encodes an optional deadline as a flag plus whole seconds and nanoseconds.
// The split keeps exact nanosecond comparisons possible inside Redis Lua, whose numbers cannot
// represent a Unix nanosecond timestamp without precision loss.
// | expiryFields 把可选期限编码为标志、整秒与纳秒。拆分使 Redis Lua 内可以进行精确纳秒比较，
// 因为 Lua 数字无法无损表示 Unix 纳秒时间戳。
func expiryFields(t time.Time) (flag, sec, nsec string) {
	if t.IsZero() {
		return "0", "0", "0"
	}
	t = t.UTC()
	return "1", strconv.FormatInt(t.Unix(), 10), strconv.FormatInt(int64(t.Nanosecond()), 10)
}

// clockFields encodes an instant as whole seconds and nanoseconds. | clockFields 把时刻编码为整秒与纳秒。
func clockFields(t time.Time) (sec, nsec string) {
	t = t.UTC()
	return strconv.FormatInt(t.Unix(), 10), strconv.FormatInt(int64(t.Nanosecond()), 10)
}

// expired reports whether a stored deadline has passed at now. | expired 报告存储的期限在 now 时是否已过。
func expired(hasExpiry bool, sec, nsec int64, now time.Time) bool {
	if !hasExpiry {
		return false
	}
	return !now.Before(time.Unix(sec, nsec))
}
