package saml

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// RequestState tracks an outstanding AuthnRequest or LogoutRequest. | RequestState 跟踪未完成的
// AuthnRequest 或 LogoutRequest。
type RequestState struct {
	// ID is the request identifier. | ID 是请求标识。
	ID string
	// SPEntityID is the service-provider entity ID. | SPEntityID 是服务提供方实体标识。
	SPEntityID string
	// IDPEntityID is the identity-provider entity ID. | IDPEntityID 是身份提供方实体标识。
	IDPEntityID string
	// ACSURL is the expected assertion consumer URL. | ACSURL 是期望的断言消费 URL。
	ACSURL string
	// RelayState is the opaque state returned to the SP. | RelayState 是返回给 SP 的不透明状态。
	RelayState string
	// NameIDFormat is the requested NameID format. | NameIDFormat 是请求的 NameID 格式。
	NameIDFormat string
	// CreatedAt is the request creation time. | CreatedAt 是请求创建时间。
	CreatedAt time.Time
	// ExpiresAt is the request expiry time. | ExpiresAt 是请求过期时间。
	ExpiresAt time.Time
	// Used marks a consumed request. | Used 标记已消费请求。
	Used bool
}

// Clone returns a deep copy of the request. | Clone 返回请求深拷贝。
func (r *RequestState) Clone() *RequestState {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// Session tracks an IdP session for single logout. | Session 跟踪用于单点登出的 IdP 会话。
type Session struct {
	// ID is the session index. | ID 是会话索引。
	ID string
	// NameID is the subject identifier. | NameID 是主体标识。
	NameID string
	// SPEntityID is the service-provider entity ID. | SPEntityID 是服务提供方实体标识。
	SPEntityID string
	// IDPEntityID is the identity-provider entity ID. | IDPEntityID 是身份提供方实体标识。
	IDPEntityID string
	// CreatedAt is the session creation time. | CreatedAt 是会话创建时间。
	CreatedAt time.Time
	// ExpiresAt is the session expiry time. | ExpiresAt 是会话过期时间。
	ExpiresAt time.Time
	// Attributes are the session attributes. | Attributes 是会话属性。
	Attributes map[string][]string
}

// Clone returns a deep copy of the session. | Clone 返回会话深拷贝。
func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	c := *s
	if len(s.Attributes) > 0 {
		c.Attributes = make(map[string][]string, len(s.Attributes))
		for key, values := range s.Attributes {
			c.Attributes[key] = append([]string(nil), values...)
		}
	}
	return &c
}

// ArtifactRecord stores the protocol message addressed by an HTTP-Artifact binding artifact. | ArtifactRecord
// 保存 HTTP-Artifact 绑定工件所指向的协议消息。
type ArtifactRecord struct {
	// Artifact is the issued artifact, including its endpoint index. | Artifact 是签发的工件，包含
	// 端点索引。
	Artifact Artifact
	// Message is the raw SAML protocol message returned to the service provider. | Message 是返回给
	// 服务提供方的原始 SAML 协议消息。
	Message []byte
	// SPEntityID is the service-provider entity ID. | SPEntityID 是服务提供方实体标识。
	SPEntityID string
	// IDPEntityID is the identity-provider entity ID. | IDPEntityID 是身份提供方实体标识。
	IDPEntityID string
	// IssuedAt is the artifact issue time. | IssuedAt 是工件签发时间。
	IssuedAt time.Time
	// ExpiresAt is the artifact expiry time. | ExpiresAt 是工件过期时间。
	ExpiresAt time.Time
	// Used marks a resolved artifact; a used record is retained until expiry so replays are
	// reported as such. | Used 标记已解析工件；已用记录保留到过期，以便报告重放。
	Used bool
}

// Clone returns a deep copy of the record. | Clone 返回记录深拷贝。
func (r *ArtifactRecord) Clone() *ArtifactRecord {
	if r == nil {
		return nil
	}
	c := *r
	if len(r.Message) > 0 {
		c.Message = append([]byte(nil), r.Message...)
	}
	return &c
}

// ArtifactStore persists HTTP-Artifact binding artifacts and their protocol messages. It is an
// optional extension of Store: providers discover it by type assertion on the configured Store.
// Implementations must store records by Artifact.storeKey() and enforce single use. | ArtifactStore
// 持久化 HTTP-Artifact 绑定工件及其协议消息。它是 Store 的可选扩展：提供方通过类型断言已配置的
// Store 发现它。实现必须按 Artifact.storeKey() 存储记录并保证一次性使用。
type ArtifactStore interface {
	// SaveArtifact stores an artifact record. Saving an existing artifact reports ErrReplay. |
	// SaveArtifact 保存工件记录。保存已存在的工件返回 ErrReplay。
	SaveArtifact(ctx context.Context, record *ArtifactRecord, now time.Time) error
	// TakeArtifact atomically consumes an artifact. Unknown artifacts report ErrArtifactInvalid,
	// expired artifacts report ErrResponseExpired and replays report ErrReplay. | TakeArtifact 原子
	// 消费工件。未知工件返回 ErrArtifactInvalid，过期工件返回 ErrResponseExpired，重放返回 ErrReplay。
	TakeArtifact(ctx context.Context, artifact Artifact, now time.Time) (*ArtifactRecord, error)
}

// artifactStoreOf returns the ArtifactStore view of store. | artifactStoreOf 返回 store 的
// ArtifactStore 视图。
func artifactStoreOf(store Store) (ArtifactStore, error) {
	if store == nil {
		return nil, errs.Detail(ErrInvalidConfig, "artifact store is not configured | 未配置工件存储")
	}
	artifactStore, ok := store.(ArtifactStore)
	if !ok {
		return nil, errs.Detail(ErrUnsupported, "store does not implement ArtifactStore | 存储未实现 ArtifactStore")
	}
	return artifactStore, nil
}

// AssertionReplayStore records assertion identifiers to enforce Conditions/OneTimeUse. It is an
// optional extension of Store: providers discover it by type assertion on the configured Store and
// also accept it directly through ResponseValidationOptions and ServiceProviderConfig. |
// AssertionReplayStore 记录断言标识以强制 Conditions/OneTimeUse。它是 Store 的可选扩展：提供方通过
// 类型断言已配置的 Store 发现它，也可通过 ResponseValidationOptions 与 ServiceProviderConfig 直接配置。
type AssertionReplayStore interface {
	// SeenAndStore atomically records assertionID until expiresAt and reports whether the identifier
	// was already recorded. A true result means the assertion is a replay. | SeenAndStore 原子记录
	// assertionID 直到 expiresAt，并报告该标识是否已被记录。返回 true 表示断言重放。
	SeenAndStore(ctx context.Context, assertionID string, expiresAt, now time.Time) (seen bool, err error)
}

// Store persists request correlation, assertion replay and IdP sessions. | Store 持久化请求关联、
// 断言重放与 IdP 会话。
type Store interface {
	// SaveRequest stores an outstanding request. | SaveRequest 保存未完成请求。
	SaveRequest(ctx context.Context, request *RequestState) error
	// ConsumeRequest atomically consumes a request by ID. | ConsumeRequest 按 ID 原子消费请求。
	ConsumeRequest(ctx context.Context, id string, now time.Time) (*RequestState, error)
	// SaveAssertion records an assertion ID and reports whether it was fresh. | SaveAssertion 记录断言 ID 并报告是否新鲜。
	SaveAssertion(ctx context.Context, id string, expiresAt time.Time, now time.Time) (bool, error)
	// SaveSession stores an IdP session. | SaveSession 保存 IdP 会话。
	SaveSession(ctx context.Context, session *Session) error
	// GetSession returns an IdP session. | GetSession 返回 IdP 会话。
	GetSession(ctx context.Context, id string) (*Session, error)
	// DeleteSession removes an IdP session. | DeleteSession 删除 IdP 会话。
	DeleteSession(ctx context.Context, id string) error
	// ListSessions returns the sessions of a subject. | ListSessions 返回主体会话。
	ListSessions(ctx context.Context, nameID string) ([]*Session, error)
	// Cleanup removes expired requests, assertions and sessions. | Cleanup 删除过期请求、断言与会话。
	Cleanup(ctx context.Context, now time.Time) error
}

// MemoryStore is a concurrency-safe in-memory SAML Store. | MemoryStore 是并发安全的内存 SAML Store。
type MemoryStore struct {
	mu         sync.RWMutex
	requests   map[string]*RequestState
	assertions map[string]time.Time
	sessions   map[string]*Session
	artifacts  map[string]*ArtifactRecord
}

// NewMemoryStore returns an empty in-memory store. | NewMemoryStore 返回空内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		requests:   make(map[string]*RequestState),
		assertions: make(map[string]time.Time),
		sessions:   make(map[string]*Session),
		artifacts:  make(map[string]*ArtifactRecord),
	}
}

// SaveRequest stores an outstanding request. | SaveRequest 保存未完成请求。
func (s *MemoryStore) SaveRequest(_ context.Context, request *RequestState) error {
	if request == nil || request.ID == "" {
		return errs.Detail(ErrInvalidRequest, "request id is empty | 请求标识为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.requests[request.ID]; exists {
		return errs.Detail(ErrReplay, "request id already exists | 请求标识已存在")
	}
	s.requests[request.ID] = request.Clone()
	return nil
}

// ConsumeRequest atomically consumes a request. | ConsumeRequest 原子消费请求。
func (s *MemoryStore) ConsumeRequest(_ context.Context, id string, now time.Time) (*RequestState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok || request.Used {
		return nil, errs.Detail(ErrInvalidRequest, "unknown or used request %[1]q | 未知或已用请求 %[1]q", id)
	}
	if !request.ExpiresAt.IsZero() && !now.Before(request.ExpiresAt) {
		return nil, errs.Detail(ErrResponseExpired, "request expired | 请求已过期")
	}
	request.Used = true
	return request.Clone(), nil
}

// SaveAssertion records an assertion ID. | SaveAssertion 记录断言 ID。
func (s *MemoryStore) SaveAssertion(ctx context.Context, id string, expiresAt, now time.Time) (bool, error) {
	seen, err := s.SeenAndStore(ctx, id, expiresAt, now)
	if err != nil {
		return false, err
	}
	return !seen, nil
}

// SeenAndStore atomically records an assertion ID for one-time-use enforcement. | SeenAndStore
// 原子记录断言标识以强制一次性使用。
func (s *MemoryStore) SeenAndStore(_ context.Context, id string, expiresAt, now time.Time) (bool, error) {
	if id == "" {
		return false, errs.Detail(ErrInvalidResponse, "assertion id is empty | 断言标识为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.assertions[id]; ok && now.Before(existing) {
		return true, nil
	}
	s.assertions[id] = expiresAt
	return false, nil
}

// SaveArtifact stores an artifact record. | SaveArtifact 保存工件记录。
func (s *MemoryStore) SaveArtifact(_ context.Context, record *ArtifactRecord, now time.Time) error {
	if record == nil || len(record.Message) == 0 {
		return errs.Detail(ErrArtifactInvalid, "artifact record is empty | 工件记录为空")
	}
	if record.Artifact.Type != ArtifactTypeHTTP {
		return errs.Detail(ErrArtifactInvalid, "artifact type 0x%04x | 工件类型 0x%04x", record.Artifact.Type, record.Artifact.Type)
	}
	if !record.ExpiresAt.IsZero() && !now.Before(record.ExpiresAt) {
		return errs.Detail(ErrResponseExpired, "artifact already expired | 工件已过期")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := record.Artifact.storeKey()
	if existing, ok := s.artifacts[key]; ok && (existing.ExpiresAt.IsZero() || now.Before(existing.ExpiresAt)) {
		return errs.Detail(ErrReplay, "artifact already exists | 工件已存在")
	}
	s.artifacts[key] = record.Clone()
	return nil
}

// TakeArtifact atomically consumes an artifact. | TakeArtifact 原子消费工件。
func (s *MemoryStore) TakeArtifact(_ context.Context, artifact Artifact, now time.Time) (*ArtifactRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := artifact.storeKey()
	record, ok := s.artifacts[key]
	if !ok {
		return nil, errs.Detail(ErrArtifactInvalid, "unknown artifact | 未知工件")
	}
	if !record.ExpiresAt.IsZero() && !now.Before(record.ExpiresAt) {
		delete(s.artifacts, key)
		return nil, errs.Detail(ErrResponseExpired, "artifact expired | 工件已过期")
	}
	if record.Used {
		return nil, errs.Detail(ErrReplay, "artifact already resolved | 工件已解析")
	}
	record.Used = true
	return record.Clone(), nil
}

// SaveSession stores an IdP session. | SaveSession 保存 IdP 会话。
func (s *MemoryStore) SaveSession(_ context.Context, session *Session) error {
	if session == nil || session.ID == "" {
		return errs.Detail(ErrInvalidRequest, "session id is empty | 会话标识为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session.Clone()
	return nil
}

// GetSession returns an IdP session. | GetSession 返回 IdP 会话。
func (s *MemoryStore) GetSession(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return nil, errs.Detail(ErrInvalidRequest, "unknown session %[1]q | 未知会话 %[1]q", id)
	}
	return session.Clone(), nil
}

// DeleteSession removes an IdP session. | DeleteSession 删除 IdP 会话。
func (s *MemoryStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

// ListSessions returns the sessions of a subject. | ListSessions 返回主体会话。
func (s *MemoryStore) ListSessions(_ context.Context, nameID string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, 0, 4)
	for _, session := range s.sessions {
		if session.NameID == nameID {
			out = append(out, session.Clone())
		}
	}
	return out, nil
}

// Cleanup removes expired records. | Cleanup 删除过期记录。
func (s *MemoryStore) Cleanup(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, request := range s.requests {
		if !request.ExpiresAt.IsZero() && !now.Before(request.ExpiresAt) {
			delete(s.requests, id)
		}
	}
	for id, expiresAt := range s.assertions {
		if !now.Before(expiresAt) {
			delete(s.assertions, id)
		}
	}
	for id, session := range s.sessions {
		if !session.ExpiresAt.IsZero() && !now.Before(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	for key, record := range s.artifacts {
		if !record.ExpiresAt.IsZero() && !now.Before(record.ExpiresAt) {
			delete(s.artifacts, key)
		}
	}
	return nil
}
