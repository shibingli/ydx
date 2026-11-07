package oidc

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// defaultLogoutReplayCapacity bounds the default in-memory replay store. | defaultLogoutReplayCapacity
// 限定默认内存重放存储的容量。
const defaultLogoutReplayCapacity = 8192

// LogoutReplayStore records logout-token identifiers so a replayed token can be rejected. |
// LogoutReplayStore 记录登出令牌标识，从而拒绝重放的令牌。
type LogoutReplayStore interface {
	// Accept records jti until expiresAt and reports whether the identifier was unseen. A store
	// error is treated as a validation failure, never as a fresh token. | Accept 记录 jti 至
	// expiresAt，并报告该标识此前是否未见。存储错误会被视为校验失败，绝不会视为新令牌。
	Accept(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
}

// MemoryLogoutReplayStore is a bounded, concurrency-safe in-memory LogoutReplayStore. | MemoryLogoutReplayStore
// 是有界、并发安全的内存 LogoutReplayStore。
type MemoryLogoutReplayStore struct {
	mu       sync.Mutex
	entries  map[string]time.Time
	capacity int
	now      func() time.Time
}

// NewMemoryLogoutReplayStore returns a store holding at most capacity identifiers; a non-positive
// capacity uses the default bound. | NewMemoryLogoutReplayStore 返回最多保存 capacity 个标识的存储；
// 非正容量使用默认上限。
func NewMemoryLogoutReplayStore(capacity int) *MemoryLogoutReplayStore {
	return NewMemoryLogoutReplayStoreWithClock(capacity, time.Now)
}

// NewMemoryLogoutReplayStoreWithClock is NewMemoryLogoutReplayStore with an explicit clock so tests
// and providers can share one time source. | NewMemoryLogoutReplayStoreWithClock 是带显式时钟的
// NewMemoryLogoutReplayStore，使测试与提供方共用同一时间源。
func NewMemoryLogoutReplayStoreWithClock(capacity int, now func() time.Time) *MemoryLogoutReplayStore {
	if capacity <= 0 {
		capacity = defaultLogoutReplayCapacity
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryLogoutReplayStore{
		entries:  make(map[string]time.Time, capacity),
		capacity: capacity,
		now:      now,
	}
}

// Accept records jti and reports whether it was fresh. | Accept 记录 jti 并报告是否为首次出现。
func (s *MemoryLogoutReplayStore) Accept(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	if s == nil {
		return false, errs.Detail(ErrInvalidToken, "logout replay store is nil | 登出重放存储为空")
	}
	if jti == "" {
		return false, errs.Detail(ErrInvalidToken, "logout replay jti is empty | 登出重放 jti 为空")
	}
	now := s.now().UTC()
	if expiresAt.IsZero() || !expiresAt.After(now) {
		// A retained identifier must outlive the acceptance window; never store an already
		// elapsed deadline because it could be pruned immediately. | 保留的标识必须长于接受窗口；
		// 不得保存已经过去的期限，否则可能被立即清除。
		expiresAt = now.Add(5 * time.Minute)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	if _, exists := s.entries[jti]; exists {
		return false, nil
	}
	if len(s.entries) >= s.capacity {
		s.evictSoonest()
	}
	s.entries[jti] = expiresAt
	return true, nil
}

// prune removes elapsed identifiers; the caller holds the mutex. | prune 清除已到期标识；调用方持有互斥锁。
func (s *MemoryLogoutReplayStore) prune(now time.Time) {
	for jti, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, jti)
		}
	}
}

// evictSoonest removes the identifier with the earliest deadline; the caller holds the mutex. |
// evictSoonest 移除最早到期的标识；调用方持有互斥锁。
func (s *MemoryLogoutReplayStore) evictSoonest() {
	var oldestJTI string
	var oldest time.Time
	for jti, expiry := range s.entries {
		if oldestJTI == "" || expiry.Before(oldest) {
			oldestJTI = jti
			oldest = expiry
		}
	}
	if oldestJTI != "" {
		delete(s.entries, oldestJTI)
	}
}
