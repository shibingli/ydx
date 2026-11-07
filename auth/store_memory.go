package auth

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// NewMemoryStores returns a complete in-memory persistence set. | NewMemoryStores 返回完整的内存持久化集合。
//
// It is intended for tests, embedded single-process deployments and examples. A multi-process or
// durable deployment must provide its own implementations of the interfaces in store.go. | 它用于测试、
// 单进程嵌入式部署与示例。多进程或需要持久化的部署必须自行实现 store.go 中的接口。
func NewMemoryStores() Stores {
	return Stores{
		Users:       NewMemoryUserStore(),
		Sessions:    NewMemorySessionStore(),
		Identities:  NewMemoryIdentityStore(),
		Credentials: NewMemoryCredentialStore(),
		Audits:      NewMemoryAuditStore(),
		Tokens:      NewMemoryTokenStore(),
	}
}

// MemoryUserStore is a concurrency-safe in-memory UserStore. | MemoryUserStore 是并发安全的内存 UserStore。
type MemoryUserStore struct {
	// mu guards every map below. | mu 保护下面的每个映射。
	mu sync.RWMutex
	// users indexes records by internal identifier. | users 按内部标识索引记录。
	users map[string]*User
	// usernames, emails and phones map normalized identifiers to user IDs. | usernames、emails 与 phones 把规范化标识映射到用户 ID。
	usernames map[string]string
	emails    map[string]string
	phones    map[string]string
}

// NewMemoryUserStore returns an empty in-memory user store. | NewMemoryUserStore 返回空的内存用户存储。
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users:     make(map[string]*User),
		usernames: make(map[string]string),
		emails:    make(map[string]string),
		phones:    make(map[string]string),
	}
}

// CreateUser stores a new user. | CreateUser 保存新用户。
func (s *MemoryUserStore) CreateUser(_ context.Context, user *User) error {
	if user == nil || user.ID == "" {
		return errs.Detail(ErrInvalidRequest, "user or id is empty | 用户或 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.ID]; ok {
		return errs.Detail(ErrUserExists, "id %[1]q | ID %[1]q", user.ID)
	}
	if id, key, ok := s.lookupUsername(user.Username); ok && id != "" {
		return errs.Detail(ErrUserExists, "username %[1]q | 用户名 %[1]q", key)
	}
	if id, key, ok := s.lookupEmail(user.Email); ok && id != "" {
		return errs.Detail(ErrUserExists, "email %[1]q | 邮箱 %[1]q", key)
	}
	if id, key, ok := s.lookupPhone(user.Phone); ok && id != "" {
		return errs.Detail(ErrUserExists, "phone %[1]q | 手机号 %[1]q", key)
	}
	c := user.Clone()
	s.users[c.ID] = c
	s.index(c)
	return nil
}

// lookupUsername returns the existing owner of a normalized username. | lookupUsername 返回规范化用户名的现有属主。
func (s *MemoryUserStore) lookupUsername(username string) (id, key string, ok bool) {
	key = SanitizeIdentifier(username)
	if key == "" {
		return "", "", false
	}
	id, ok = s.usernames[key]
	return id, key, ok
}

// lookupEmail returns the existing owner of a normalized email. | lookupEmail 返回规范化邮箱的现有属主。
func (s *MemoryUserStore) lookupEmail(email string) (id, key string, ok bool) {
	key = SanitizeIdentifier(email)
	if key == "" {
		return "", "", false
	}
	id, ok = s.emails[key]
	return id, key, ok
}

// lookupPhone returns the existing owner of a normalized phone. | lookupPhone 返回规范化手机号的现有属主。
func (s *MemoryUserStore) lookupPhone(phone string) (id, key string, ok bool) {
	key, valid := normalizePhone(phone)
	if !valid {
		return "", "", false
	}
	id, ok = s.phones[key]
	return id, key, ok
}

// index adds the unique indexes of u. | index 添加 u 的唯一索引。
func (s *MemoryUserStore) index(u *User) {
	if key := SanitizeIdentifier(u.Username); key != "" {
		s.usernames[key] = u.ID
	}
	if key := SanitizeIdentifier(u.Email); key != "" {
		s.emails[key] = u.ID
	}
	if key, ok := normalizePhone(u.Phone); ok {
		s.phones[key] = u.ID
	}
}

// unindex removes the unique indexes of u. | unindex 移除 u 的唯一索引。
func (s *MemoryUserStore) unindex(u *User) {
	if key := SanitizeIdentifier(u.Username); key != "" && s.usernames[key] == u.ID {
		delete(s.usernames, key)
	}
	if key := SanitizeIdentifier(u.Email); key != "" && s.emails[key] == u.ID {
		delete(s.emails, key)
	}
	if key, ok := normalizePhone(u.Phone); ok && s.phones[key] == u.ID {
		delete(s.phones, key)
	}
}

// GetUser returns a user by ID. | GetUser 按 ID 返回用户。
func (s *MemoryUserStore) GetUser(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, errs.Detail(ErrUserNotFound, "id %[1]q | ID %[1]q", id)
	}
	return u.Clone(), nil
}

// GetUserByUsername returns a user by login name. | GetUserByUsername 按登录名返回用户。
func (s *MemoryUserStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, _, ok := s.lookupUsername(username)
	if !ok {
		return nil, errs.Detail(ErrUserNotFound, "username %[1]q | 用户名 %[1]q", username)
	}
	return s.users[id].Clone(), nil
}

// GetUserByEmail returns a user by email address. | GetUserByEmail 按邮箱地址返回用户。
func (s *MemoryUserStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, _, ok := s.lookupEmail(email)
	if !ok {
		return nil, errs.Detail(ErrUserNotFound, "email %[1]q | 邮箱 %[1]q", email)
	}
	return s.users[id].Clone(), nil
}

// GetUserByPhone returns a user by phone number. | GetUserByPhone 按手机号返回用户。
func (s *MemoryUserStore) GetUserByPhone(_ context.Context, phone string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, _, ok := s.lookupPhone(phone)
	if !ok {
		return nil, errs.Detail(ErrUserNotFound, "phone %[1]q | 手机号 %[1]q", phone)
	}
	return s.users[id].Clone(), nil
}

// UpdateUser replaces an existing user. | UpdateUser 替换已有用户。
func (s *MemoryUserStore) UpdateUser(_ context.Context, user *User) error {
	if user == nil || user.ID == "" {
		return errs.Detail(ErrInvalidRequest, "user or id is empty | 用户或 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[user.ID]
	if !ok {
		return errs.Detail(ErrUserNotFound, "id %[1]q | ID %[1]q", user.ID)
	}
	if key := SanitizeIdentifier(user.Username); key != "" {
		if owner, exists := s.usernames[key]; exists && owner != user.ID {
			return errs.Detail(ErrUserExists, "username %[1]q | 用户名 %[1]q", key)
		}
	}
	if key := SanitizeIdentifier(user.Email); key != "" {
		if owner, exists := s.emails[key]; exists && owner != user.ID {
			return errs.Detail(ErrUserExists, "email %[1]q | 邮箱 %[1]q", key)
		}
	}
	if key, valid := normalizePhone(user.Phone); valid {
		if owner, exists := s.phones[key]; exists && owner != user.ID {
			return errs.Detail(ErrUserExists, "phone %[1]q | 手机号 %[1]q", key)
		}
	}
	s.unindex(old)
	c := user.Clone()
	s.users[c.ID] = c
	s.index(c)
	return nil
}

// DeleteUser removes a user. | DeleteUser 删除用户。
func (s *MemoryUserStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return errs.Detail(ErrUserNotFound, "id %[1]q | ID %[1]q", id)
	}
	s.unindex(u)
	delete(s.users, id)
	return nil
}

// ListUsers returns a filtered page. | ListUsers 返回过滤后的一页。
func (s *MemoryUserStore) ListUsers(_ context.Context, query UserQuery) ([]*User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	needle := strings.ToLower(strings.TrimSpace(query.Query))
	for _, u := range s.users {
		if query.Status != "" && u.Status != query.Status {
			continue
		}
		if needle != "" {
			haystack := strings.ToLower(u.Username + "\x00" + u.Email + "\x00" + u.DisplayName)
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		out = append(out, u.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	total := len(out)
	start, end := pageBounds(query.Offset, query.Limit, total)
	return out[start:end], total, nil
}

// pageBounds applies a zero-based offset and a positive limit to total. | pageBounds 把从零开始的偏移与正数上限应用到 total。
func pageBounds(offset, limit, total int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit <= 0 {
		return offset, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return offset, end
}

// MemorySessionStore is a concurrency-safe in-memory SessionStore. | MemorySessionStore 是并发安全的内存 SessionStore。
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemorySessionStore returns an empty in-memory session store. | NewMemorySessionStore 返回空的内存会话存储。
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]*Session)}
}

// CreateSession stores a new session. | CreateSession 保存新会话。
func (s *MemorySessionStore) CreateSession(_ context.Context, session *Session) error {
	if session == nil || session.ID == "" {
		return errs.Detail(ErrInvalidRequest, "session or id is empty | 会话或 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; ok {
		return errs.Detail(ErrConflict, "session id %[1]q | 会话 ID %[1]q", session.ID)
	}
	s.sessions[session.ID] = session.Clone()
	return nil
}

// GetSession returns a session by ID. | GetSession 按 ID 返回会话。
func (s *MemorySessionStore) GetSession(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, errs.Detail(ErrSessionNotFound, "id %[1]q | ID %[1]q", id)
	}
	return session.Clone(), nil
}

// UpdateSession replaces an existing session. | UpdateSession 替换已有会话。
func (s *MemorySessionStore) UpdateSession(_ context.Context, session *Session) error {
	if session == nil || session.ID == "" {
		return errs.Detail(ErrInvalidRequest, "session or id is empty | 会话或 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; !ok {
		return errs.Detail(ErrSessionNotFound, "id %[1]q | ID %[1]q", session.ID)
	}
	s.sessions[session.ID] = session.Clone()
	return nil
}

// DeleteSession removes a session. | DeleteSession 删除会话。
func (s *MemorySessionStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return errs.Detail(ErrSessionNotFound, "id %[1]q | ID %[1]q", id)
	}
	delete(s.sessions, id)
	return nil
}

// ListSessionsByUser returns every session of a user. | ListSessionsByUser 返回用户的全部会话。
func (s *MemorySessionStore) ListSessionsByUser(_ context.Context, userID string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, 4)
	for _, session := range s.sessions {
		if session.UserID == userID {
			out = append(out, session.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// DeleteSessionsByUser removes every session of a user. | DeleteSessionsByUser 删除用户的全部会话。
func (s *MemorySessionStore) DeleteSessionsByUser(_ context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

// DeleteExpiredSessions removes sessions whose absolute deadline passed. | DeleteExpiredSessions 删除绝对期限已过的会话。
func (s *MemorySessionStore) DeleteExpiredSessions(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, session := range s.sessions {
		if !session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt) {
			delete(s.sessions, id)
			n++
		}
	}
	return n, nil
}

// MemoryIdentityStore is a concurrency-safe in-memory IdentityStore. | MemoryIdentityStore 是并发安全的内存 IdentityStore。
type MemoryIdentityStore struct {
	mu         sync.RWMutex
	identities map[string]*Identity
}

// NewMemoryIdentityStore returns an empty in-memory identity store. | NewMemoryIdentityStore 返回空的内存身份关联存储。
func NewMemoryIdentityStore() *MemoryIdentityStore {
	return &MemoryIdentityStore{identities: make(map[string]*Identity)}
}

// identityKey joins provider and subject without ambiguity. | identityKey 无歧义地拼接提供方与 subject。
func identityKey(provider, subject string) string {
	return provider + "\x00" + subject
}

// CreateIdentity stores a new link. | CreateIdentity 保存新关联。
func (s *MemoryIdentityStore) CreateIdentity(_ context.Context, identity *Identity) error {
	if identity == nil || identity.Provider == "" || identity.Subject == "" || identity.UserID == "" {
		return errs.Detail(ErrInvalidRequest, "identity fields are empty | 身份字段为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := identityKey(identity.Provider, identity.Subject)
	if _, ok := s.identities[key]; ok {
		return errs.Detail(ErrIdentityExists, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q", identity.Provider, identity.Subject)
	}
	s.identities[key] = identity.Clone()
	return nil
}

// GetIdentity returns a link by provider and subject. | GetIdentity 按提供方与 subject 返回关联。
func (s *MemoryIdentityStore) GetIdentity(_ context.Context, provider, subject string) (*Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	identity, ok := s.identities[identityKey(provider, subject)]
	if !ok {
		return nil, errs.Detail(ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q", provider, subject)
	}
	return identity.Clone(), nil
}

// ListIdentitiesByUser returns every link of a user. | ListIdentitiesByUser 返回用户的全部关联。
func (s *MemoryIdentityStore) ListIdentitiesByUser(_ context.Context, userID string) ([]*Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Identity, 0, 4)
	for _, identity := range s.identities {
		if identity.UserID == userID {
			out = append(out, identity.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider == out[j].Provider {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Provider < out[j].Provider
	})
	return out, nil
}

// UpdateIdentity replaces an existing link. | UpdateIdentity 替换已有链接。
func (s *MemoryIdentityStore) UpdateIdentity(_ context.Context, identity *Identity) error {
	if identity == nil || identity.Provider == "" || identity.Subject == "" {
		return errs.Detail(ErrInvalidRequest, "identity fields are empty | 身份字段为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := identityKey(identity.Provider, identity.Subject)
	if _, ok := s.identities[key]; !ok {
		return errs.Detail(ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q", identity.Provider, identity.Subject)
	}
	s.identities[key] = identity.Clone()
	return nil
}

// DeleteIdentity removes a link. | DeleteIdentity 删除关联。
func (s *MemoryIdentityStore) DeleteIdentity(_ context.Context, provider, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := identityKey(provider, subject)
	if _, ok := s.identities[key]; !ok {
		return errs.Detail(ErrIdentityNotFound, "provider %[1]q subject %[2]q | 提供方 %[1]q subject %[2]q", provider, subject)
	}
	delete(s.identities, key)
	return nil
}

// MemoryCredentialStore is a concurrency-safe in-memory CredentialStore. | MemoryCredentialStore 是并发安全的内存 CredentialStore。
type MemoryCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]*Credential
}

// NewMemoryCredentialStore returns an empty in-memory credential store. | NewMemoryCredentialStore 返回空的内存凭据存储。
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{credentials: make(map[string]*Credential)}
}

// CreateCredential stores a new factor. | CreateCredential 保存新因素。
func (s *MemoryCredentialStore) CreateCredential(_ context.Context, credential *Credential) error {
	if credential == nil || credential.ID == "" || credential.UserID == "" {
		return errs.Detail(ErrInvalidRequest, "credential fields are empty | 凭据字段为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[credential.ID]; ok {
		return errs.Detail(ErrCredentialExists, "id %[1]q | ID %[1]q", credential.ID)
	}
	s.credentials[credential.ID] = credential.Clone()
	return nil
}

// GetCredential returns a factor by ID. | GetCredential 按 ID 返回因素。
func (s *MemoryCredentialStore) GetCredential(_ context.Context, id string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	credential, ok := s.credentials[id]
	if !ok {
		return nil, errs.Detail(ErrCredentialNotFound, "id %[1]q | ID %[1]q", id)
	}
	return credential.Clone(), nil
}

// UpdateCredential replaces an existing factor. | UpdateCredential 替换已有因素。
func (s *MemoryCredentialStore) UpdateCredential(_ context.Context, credential *Credential) error {
	if credential == nil || credential.ID == "" {
		return errs.Detail(ErrInvalidRequest, "credential or id is empty | 凭据或 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[credential.ID]; !ok {
		return errs.Detail(ErrCredentialNotFound, "id %[1]q | ID %[1]q", credential.ID)
	}
	s.credentials[credential.ID] = credential.Clone()
	return nil
}

// DeleteCredential removes a factor. | DeleteCredential 删除因素。
func (s *MemoryCredentialStore) DeleteCredential(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[id]; !ok {
		return errs.Detail(ErrCredentialNotFound, "id %[1]q | ID %[1]q", id)
	}
	delete(s.credentials, id)
	return nil
}

// ListCredentialsByUser returns every factor of a user. | ListCredentialsByUser 返回用户的全部因素。
func (s *MemoryCredentialStore) ListCredentialsByUser(_ context.Context, userID string) ([]*Credential, error) {
	return s.list(func(c *Credential) bool { return c.UserID == userID }), nil
}

// ListCredentialsByUserType returns the factors of a user with one type. | ListCredentialsByUserType 返回用户某一类型的因素。
func (s *MemoryCredentialStore) ListCredentialsByUserType(_ context.Context, userID string, typ CredentialType) ([]*Credential, error) {
	return s.list(func(c *Credential) bool { return c.UserID == userID && c.Type == typ }), nil
}

// list returns cloned credentials matching keep, ordered by creation time. | list 按创建时间返回匹配 keep 的凭据副本。
func (s *MemoryCredentialStore) list(keep func(*Credential) bool) []*Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Credential, 0, 4)
	for _, credential := range s.credentials {
		if keep(credential) {
			out = append(out, credential.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// MemoryAuditStore is a concurrency-safe in-memory AuditStore. | MemoryAuditStore 是并发安全的内存 AuditStore。
type MemoryAuditStore struct {
	mu     sync.RWMutex
	events []*AuditEvent
}

// NewMemoryAuditStore returns an empty in-memory audit store. | NewMemoryAuditStore 返回空的内存审计存储。
func NewMemoryAuditStore() *MemoryAuditStore {
	return &MemoryAuditStore{}
}

// RecordAudit appends an event. | RecordAudit 追加事件。
func (s *MemoryAuditStore) RecordAudit(_ context.Context, event *AuditEvent) error {
	if event == nil {
		return errs.Detail(ErrInvalidRequest, "event is nil | 事件为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event.Clone())
	return nil
}

// ListAudit returns a filtered page ordered by time. | ListAudit 返回按时间排序的过滤后一页。
func (s *MemoryAuditStore) ListAudit(_ context.Context, query AuditQuery) ([]*AuditEvent, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*AuditEvent, 0, len(s.events))
	for _, event := range s.events {
		if query.Type != "" && event.Type != query.Type {
			continue
		}
		if query.UserID != "" && event.UserID != query.UserID {
			continue
		}
		if query.ActorID != "" && event.ActorID != query.ActorID {
			continue
		}
		if query.Outcome != "" && event.Outcome != query.Outcome {
			continue
		}
		if !query.Since.IsZero() && event.At.Before(query.Since) {
			continue
		}
		if !query.Until.IsZero() && event.At.After(query.Until) {
			continue
		}
		out = append(out, event.Clone())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At.Equal(out[j].At) {
			return out[i].ID < out[j].ID
		}
		return out[i].At.Before(out[j].At)
	})
	if query.Descending {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	total := len(out)
	start, end := pageBounds(query.Offset, query.Limit, total)
	return out[start:end], total, nil
}

// MemoryTokenStore is a concurrency-safe in-memory TokenStore. | MemoryTokenStore 是并发安全的内存 TokenStore。
type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*OneTimeToken
}

// NewMemoryTokenStore returns an empty in-memory one-time token store. | NewMemoryTokenStore 返回空的内存一次性令牌存储。
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{tokens: make(map[string]*OneTimeToken)}
}

// tokenKey joins a token hash and purpose. | tokenKey 拼接令牌哈希与用途。
func tokenKey(hash, purpose string) string {
	return purpose + "\x00" + hash
}

// CreateToken stores a new token. | CreateToken 保存新令牌。
func (s *MemoryTokenStore) CreateToken(_ context.Context, token *OneTimeToken) error {
	if token == nil || token.Hash == "" || token.Purpose == "" {
		return errs.Detail(ErrInvalidRequest, "token fields are empty | 令牌字段为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenKey(token.Hash, token.Purpose)] = token.Clone()
	return nil
}

// ConsumeToken atomically marks a token used. | ConsumeToken 原子地标记令牌已用。
func (s *MemoryTokenStore) ConsumeToken(_ context.Context, hash, purpose string, now time.Time) (*OneTimeToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[tokenKey(hash, purpose)]
	if !ok {
		return nil, ErrTokenInvalid
	}
	if !token.UsedAt.IsZero() {
		return nil, ErrTokenUsed
	}
	if !token.ExpiresAt.IsZero() && !now.Before(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	token.UsedAt = now
	return token.Clone(), nil
}

// PeekToken returns a token without consuming it. | PeekToken 返回令牌但不消费。
func (s *MemoryTokenStore) PeekToken(_ context.Context, hash, purpose string, now time.Time) (*OneTimeToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, ok := s.tokens[tokenKey(hash, purpose)]
	if !ok {
		return nil, ErrTokenInvalid
	}
	if !token.UsedAt.IsZero() {
		return nil, ErrTokenUsed
	}
	if !token.ExpiresAt.IsZero() && !now.Before(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	return token.Clone(), nil
}

// DeleteTokensByUser removes every token of a user and purpose. | DeleteTokensByUser 删除用户某用途的全部令牌。
func (s *MemoryTokenStore) DeleteTokensByUser(_ context.Context, userID, purpose string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for key, token := range s.tokens {
		if token.UserID == userID && token.Purpose == purpose {
			delete(s.tokens, key)
			n++
		}
	}
	return n, nil
}
