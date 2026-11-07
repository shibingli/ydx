package webauthn

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// MemoryChallengeStore is a process-local ChallengeStore. | MemoryChallengeStore 是进程内 ChallengeStore。
//
// Entries are removed on consumption; expired entries are rejected and discarded lazily. | 条目在消费时
// 移除；过期条目会被拒绝并惰性清理。
type MemoryChallengeStore struct {
	mu      sync.Mutex
	entries map[string]*Ceremony
	now     func() time.Time
}

// NewMemoryChallengeStore returns an empty store using time.Now for expiry. | NewMemoryChallengeStore 返回使用 time.Now 判断过期的空存储。
func NewMemoryChallengeStore() *MemoryChallengeStore {
	return NewMemoryChallengeStoreWithClock(time.Now)
}

// NewMemoryChallengeStoreWithClock returns a store using now for expiry checks. | NewMemoryChallengeStoreWithClock 返回使用 now 判断过期的存储。
func NewMemoryChallengeStoreWithClock(now func() time.Time) *MemoryChallengeStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryChallengeStore{entries: make(map[string]*Ceremony), now: now}
}

// Put implements ChallengeStore. | Put 实现 ChallengeStore。
func (s *MemoryChallengeStore) Put(ctx context.Context, ceremony *Ceremony) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ceremony == nil || len(ceremony.Challenge) == 0 {
		return errs.Detail(ErrInvalidRequest, "ceremony has no challenge | 流程缺少挑战")
	}
	key := base64.RawURLEncoding.EncodeToString(ceremony.Challenge)
	copy := cloneCeremony(ceremony)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= 1024 {
		now := s.now()
		for existingKey, existing := range s.entries {
			if !existing.ExpiresAt.IsZero() && now.After(existing.ExpiresAt) {
				delete(s.entries, existingKey)
			}
		}
	}
	s.entries[key] = copy
	return nil
}

// Consume implements ChallengeStore. | Consume 实现 ChallengeStore。
func (s *MemoryChallengeStore) Consume(ctx context.Context, challenge string) (*Ceremony, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	ceremony, ok := s.entries[challenge]
	if ok {
		delete(s.entries, challenge)
	}
	s.mu.Unlock()
	if !ok {
		return nil, errs.Detail(ErrChallengeNotFound, "challenge %q | 挑战 %q", challenge, challenge)
	}
	if !ceremony.ExpiresAt.IsZero() && s.now().After(ceremony.ExpiresAt) {
		return nil, errs.Detail(ErrChallengeExpired, "challenge %q expired at %s | 挑战 %q 于 %s 过期",
			challenge, ceremony.ExpiresAt.UTC().Format(time.RFC3339), challenge, ceremony.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return cloneCeremony(ceremony), nil
}

// Len returns the number of stored ceremonies. | Len 返回已存流程数量。
func (s *MemoryChallengeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// MemoryCredentialStore is a process-local CredentialStore. | MemoryCredentialStore 是进程内 CredentialStore。
type MemoryCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]*Credential
}

// NewMemoryCredentialStore returns an empty in-memory credential store. | NewMemoryCredentialStore 返回空的内存凭据存储。
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{credentials: make(map[string]*Credential)}
}

func credentialStoreKey(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

// GetByCredentialID implements CredentialStore. | GetByCredentialID 实现 CredentialStore。
func (s *MemoryCredentialStore) GetByCredentialID(ctx context.Context, credentialID []byte) (*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := credentialStoreKey(credentialID)
	s.mu.RLock()
	credential, ok := s.credentials[key]
	if !ok {
		s.mu.RUnlock()
		return nil, errs.Detail(ErrCredentialNotFound, "credential %q | 凭据 %q", key, key)
	}
	clone := credential.Clone()
	s.mu.RUnlock()
	return clone, nil
}

// Save implements CredentialStore. | Save 实现 CredentialStore。
func (s *MemoryCredentialStore) Save(ctx context.Context, credential *Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCredential(credential); err != nil {
		return err
	}
	key := credentialStoreKey(credential.ID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.credentials[key]; ok {
		return errs.Detail(ErrCredentialExists, "credential %q already exists | 凭据 %q 已存在", key, key)
	}
	s.credentials[key] = credential.Clone()
	return nil
}

// UpdateSignCount implements CredentialStore. | UpdateSignCount 实现 CredentialStore。
func (s *MemoryCredentialStore) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := credentialStoreKey(credentialID)
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[key]
	if !ok {
		return errs.Detail(ErrCredentialNotFound, "credential %q | 凭据 %q", key, key)
	}
	credential.SignCount = signCount
	return nil
}

// UpdateBackupState implements BackupStateUpdater. | UpdateBackupState 实现 BackupStateUpdater。
func (s *MemoryCredentialStore) UpdateBackupState(ctx context.Context, credentialID []byte, backupState bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := credentialStoreKey(credentialID)
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[key]
	if !ok {
		return errs.Detail(ErrCredentialNotFound, "credential %q | 凭据 %q", key, key)
	}
	credential.BackupState = backupState
	return nil
}

// ListByUser implements CredentialStore. | ListByUser 实现 CredentialStore。
func (s *MemoryCredentialStore) ListByUser(ctx context.Context, userID string) ([]*Credential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	out := make([]*Credential, 0)
	for _, credential := range s.credentials {
		if credential.UserID == userID {
			out = append(out, credential.Clone())
		}
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return string(out[i].ID) < string(out[j].ID)
	})
	return out, nil
}
