package federation

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DefaultStateTTL is the default lifetime of an authorization state record. | DefaultStateTTL
// 是授权 state 记录的默认有效期。
const DefaultStateTTL = 10 * time.Minute

// StateRecord is one pending authorization request. | StateRecord 是一个待完成的授权请求。
type StateRecord struct {
	// State is the opaque anti-forgery value sent to the provider. | State 是发送给提供方的不透明防伪值。
	State string
	// Provider is the registered provider name. | Provider 是注册的提供方名称。
	Provider string
	// Nonce is the OIDC nonce to verify in the ID token. | Nonce 是需要在 ID 令牌中校验的 OIDC nonce。
	Nonce string
	// Verifier is the PKCE code verifier. | Verifier 是 PKCE code verifier。
	Verifier string
	// RedirectURL is the callback URL used for the authorization request. | RedirectURL 是授权请求使用的回调 URL。
	RedirectURL string
	// CreatedAt is the creation time. | CreatedAt 是创建时间。
	CreatedAt time.Time
	// ExpiresAt is the absolute expiry time. | ExpiresAt 是绝对过期时间。
	ExpiresAt time.Time
}

// StateStore persists short-lived authorization state. Implementations must make
// Consume single-use and safe for concurrent callers. | StateStore 持久化短时授权 state。
// 实现必须保证 Consume 单次使用且并发安全。
type StateStore interface {
	// Save stores a state record. | Save 保存 state 记录。
	Save(ctx context.Context, record *StateRecord) error
	// Consume removes and returns a state record. | Consume 删除并返回 state 记录。
	Consume(ctx context.Context, state string) (*StateRecord, error)
}

// MemoryStateStore is an in-process StateStore with TTL cleanup. | MemoryStateStore 是带 TTL
// 清理的进程内 StateStore。
type MemoryStateStore struct {
	mu      sync.Mutex
	records map[string]*StateRecord
	ttl     time.Duration
	now     func() time.Time
}

// MemoryStateStoreOption configures a MemoryStateStore. | MemoryStateStoreOption 配置
// MemoryStateStore。
type MemoryStateStoreOption func(*MemoryStateStore)

// WithStateClock overrides the state store clock. | WithStateClock 替换 state 存储时钟。
func WithStateClock(now func() time.Time) MemoryStateStoreOption {
	return func(store *MemoryStateStore) {
		if store != nil && now != nil {
			store.now = now
		}
	}
}

// NewMemoryStateStore returns an in-memory state store with the given TTL. A
// non-positive TTL uses DefaultStateTTL. | NewMemoryStateStore 返回指定 TTL 的进程内 state
// 存储；非正 TTL 使用 DefaultStateTTL。
func NewMemoryStateStore(ttl time.Duration, options ...MemoryStateStoreOption) *MemoryStateStore {
	if ttl <= 0 {
		ttl = DefaultStateTTL
	}
	store := &MemoryStateStore{
		records: make(map[string]*StateRecord),
		ttl:     ttl,
		now:     time.Now,
	}
	for _, option := range options {
		if option != nil {
			option(store)
		}
	}
	return store
}

// Save stores a state record, rejecting duplicates and purging expired records.
// Save 保存 state 记录，拒绝重复值并清理过期记录。
func (s *MemoryStateStore) Save(ctx context.Context, record *StateRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if record == nil || record.State == "" {
		return errs.Detail(ErrStateMismatch, "state record is empty | state 记录为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, existing := range s.records {
		if !existing.ExpiresAt.IsZero() && !now.Before(existing.ExpiresAt) {
			delete(s.records, key)
		}
	}
	if _, exists := s.records[record.State]; exists {
		return errs.Detail(ErrStateMismatch, "state already exists | state 已存在")
	}
	copied := cloneStateRecord(record)
	if copied.CreatedAt.IsZero() {
		copied.CreatedAt = now
	}
	if copied.ExpiresAt.IsZero() {
		copied.ExpiresAt = copied.CreatedAt.Add(s.ttl)
	}
	if !now.Before(copied.ExpiresAt) {
		return errs.Detail(ErrStateExpired, "state record is already expired | state 记录已过期")
	}
	s.records[copied.State] = copied
	return nil
}

// Consume removes a state record and reports missing, reused and expired values.
// Consume 删除 state 记录，并报告缺失、重复使用与过期情况。
func (s *MemoryStateStore) Consume(ctx context.Context, state string) (*StateRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == "" {
		return nil, ErrStateMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.records[state]
	if !exists {
		return nil, ErrStateMismatch
	}
	delete(s.records, state)
	if !record.ExpiresAt.IsZero() && !s.now().Before(record.ExpiresAt) {
		return nil, ErrStateExpired
	}
	return cloneStateRecord(record), nil
}

// cloneStateRecord returns a deep copy of a state record. | cloneStateRecord 返回 state 记录的深拷贝。
func cloneStateRecord(record *StateRecord) *StateRecord {
	if record == nil {
		return nil
	}
	copied := *record
	return &copied
}
