package kms

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// MemoryStore is a concurrency-safe in-memory Store. | MemoryStore 是并发安全的内存 Store。
//
// It is intended for tests, embedded single-process deployments and examples. Every operation
// stores and returns deep copies. | 它用于测试、单进程嵌入式部署与示例。每个操作都保存并返回深拷贝。
type MemoryStore struct {
	// mu guards every field below. | mu 保护下面的每个字段。
	mu sync.RWMutex
	// keys indexes records by identifier. | keys 按标识索引记录。
	keys map[string]*Key
	// aliases maps alias to key identifier. | aliases 把别名映射到密钥标识。
	aliases map[string]string
	// audits is the append-only audit log. | audits 是只追加审计日志。
	audits []*AuditEvent
}

// NewMemoryStore returns an empty in-memory store. | NewMemoryStore 返回空的内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		keys:    make(map[string]*Key),
		aliases: make(map[string]string),
	}
}

// CreateKey stores a new key. | CreateKey 保存新密钥。
func (s *MemoryStore) CreateKey(_ context.Context, key *Key) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	if key == nil || key.ID == "" {
		return errs.Detail(ErrInvalidRequest, "key or id is empty | 密钥或 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[key.ID]; ok {
		return errs.Detail(ErrKeyExists, "id %[1]q | ID %[1]q", key.ID)
	}
	if key.Alias != "" {
		if owner, ok := s.aliases[key.Alias]; ok && owner != key.ID {
			return errs.Detail(ErrAliasExists, "alias %[1]q is bound to %[2]q | 别名 %[1]q 已绑定到 %[2]q", key.Alias, owner)
		}
	}
	c := key.Clone()
	if c.Revision == 0 {
		c.Revision = 1
	}
	s.keys[c.ID] = c
	if c.Alias != "" {
		s.aliases[c.Alias] = c.ID
	}
	return nil
}

// GetKey returns a deep copy of the key. | GetKey 返回密钥的深拷贝。
func (s *MemoryStore) GetKey(_ context.Context, id string) (*Key, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[id]
	if !ok {
		return nil, errs.Detail(ErrNotFound, "id %[1]q | ID %[1]q", id)
	}
	return key.Clone(), nil
}

// UpdateKey replaces a key under optimistic concurrency. | UpdateKey 在乐观并发控制下替换密钥。
func (s *MemoryStore) UpdateKey(_ context.Context, key *Key) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	if key == nil || key.ID == "" {
		return errs.Detail(ErrInvalidRequest, "key or id is empty | 密钥或 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.keys[key.ID]
	if !ok {
		return errs.Detail(ErrNotFound, "id %[1]q | ID %[1]q", key.ID)
	}
	if key.Revision != stored.Revision {
		return errs.Detail(ErrConflict, "revision %[1]d, stored %[2]d | 修订号 %[1]d，存储为 %[2]d", key.Revision, stored.Revision)
	}
	if key.Alias != stored.Alias {
		if key.Alias != "" {
			if owner, bound := s.aliases[key.Alias]; bound && owner != key.ID {
				return errs.Detail(ErrAliasExists, "alias %[1]q is bound to %[2]q | 别名 %[1]q 已绑定到 %[2]q", key.Alias, owner)
			}
		}
		if stored.Alias != "" {
			delete(s.aliases, stored.Alias)
		}
		if key.Alias != "" {
			s.aliases[key.Alias] = key.ID
		}
	}
	c := key.Clone()
	c.Revision = stored.Revision + 1
	s.keys[key.ID] = c
	return nil
}

// DeleteKey physically removes a key and every alias bound to it. | DeleteKey 物理删除密钥及其全部绑定别名。
func (s *MemoryStore) DeleteKey(_ context.Context, id string) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok {
		return errs.Detail(ErrNotFound, "id %[1]q | ID %[1]q", id)
	}
	delete(s.keys, id)
	for alias, owner := range s.aliases {
		if owner == id {
			delete(s.aliases, alias)
		}
	}
	return nil
}

// ListKeys returns deep copies of the matching keys, ordered by creation time then identifier. | ListKeys
// 返回匹配密钥的深拷贝，按创建时间再按标识排序。
func (s *MemoryStore) ListKeys(_ context.Context, filter KeyFilter) ([]*Key, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.RLock()
	matched := make([]*Key, 0, len(s.keys))
	for _, key := range s.keys {
		if filter.matches(key) {
			matched = append(matched, key.Clone())
		}
	}
	s.mu.RUnlock()
	sortKeys(matched)
	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return []*Key{}, nil
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(matched) {
		matched = matched[:filter.Limit]
	}
	return matched, nil
}

// ResolveAlias returns the key identifier bound to alias. | ResolveAlias 返回绑定到别名的密钥标识。
func (s *MemoryStore) ResolveAlias(_ context.Context, alias string) (string, error) {
	if s == nil {
		return "", ErrStoreUnavailable
	}
	if alias == "" {
		return "", errs.Detail(ErrInvalidRequest, "empty alias | 别名为空")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.aliases[alias]
	if !ok {
		return "", errs.Detail(ErrAliasNotFound, "alias %[1]q | 别名 %[1]q", alias)
	}
	return id, nil
}

// SetAlias binds alias to keyID. | SetAlias 把别名绑定到 keyID。
func (s *MemoryStore) SetAlias(_ context.Context, alias, keyID string) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	if alias == "" || keyID == "" {
		return errs.Detail(ErrInvalidRequest, "empty alias or key id | 别名或密钥 ID 为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[keyID]; !ok {
		return errs.Detail(ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	}
	if owner, ok := s.aliases[alias]; ok && owner != keyID {
		return errs.Detail(ErrAliasExists, "alias %[1]q is bound to %[2]q | 别名 %[1]q 已绑定到 %[2]q", alias, owner)
	}
	s.aliases[alias] = keyID
	return nil
}

// DeleteAlias removes alias. | DeleteAlias 删除别名。
func (s *MemoryStore) DeleteAlias(_ context.Context, alias string) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.aliases[alias]; !ok {
		return errs.Detail(ErrAliasNotFound, "alias %[1]q | 别名 %[1]q", alias)
	}
	delete(s.aliases, alias)
	return nil
}

// SaveVersion appends version to an existing key and increments its revision. | SaveVersion 向已有
// 密钥追加版本并递增其修订号。
func (s *MemoryStore) SaveVersion(_ context.Context, keyID string, version *KeyVersion) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	if version == nil {
		return errs.Detail(ErrInvalidRequest, "nil key version | 密钥版本为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[keyID]
	if !ok {
		return errs.Detail(ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	}
	for _, existing := range key.Versions {
		if existing != nil && existing.Version == version.Version {
			return errs.Detail(ErrVersionExists, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", keyID, version.Version)
		}
	}
	key.Versions = append(key.Versions, version.Clone())
	sort.Slice(key.Versions, func(i, j int) bool { return key.Versions[i].Version < key.Versions[j].Version })
	key.Revision++
	return nil
}

// GetVersion returns a deep copy of one key version. | GetVersion 返回一个密钥版本的深拷贝。
func (s *MemoryStore) GetVersion(_ context.Context, keyID string, version uint32) (*KeyVersion, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[keyID]
	if !ok {
		return nil, errs.Detail(ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	}
	for _, candidate := range key.Versions {
		if candidate != nil && candidate.Version == version {
			return candidate.Clone(), nil
		}
	}
	return nil, errs.Detail(ErrVersionNotFound, "key %[1]q version %[2]d | 密钥 %[1]q 版本 %[2]d", keyID, version)
}

// ListVersions returns deep copies of every retained version, ascending. | ListVersions 按升序返回保留的全部版本的深拷贝。
func (s *MemoryStore) ListVersions(_ context.Context, keyID string) ([]*KeyVersion, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[keyID]
	if !ok {
		return nil, errs.Detail(ErrNotFound, "id %[1]q | ID %[1]q", keyID)
	}
	out := make([]*KeyVersion, 0, len(key.Versions))
	for _, version := range key.Versions {
		out = append(out, version.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// AppendAudit stores one audit event. | AppendAudit 保存一个审计事件。
func (s *MemoryStore) AppendAudit(_ context.Context, event *AuditEvent) error {
	if s == nil {
		return ErrStoreUnavailable
	}
	if event == nil {
		return errAuditNilEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := event.Clone()
	if c.ID == "" {
		id, err := randomID()
		if err != nil {
			return err
		}
		c.ID = id
	}
	if c.At.IsZero() {
		c.At = time.Now().UTC()
	}
	s.audits = append(s.audits, c)
	return nil
}

// ListAudit returns deep copies of the matching events. | ListAudit 返回匹配事件的深拷贝。
func (s *MemoryStore) ListAudit(_ context.Context, filter AuditFilter) ([]*AuditEvent, error) {
	if s == nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.RLock()
	matched := make([]*AuditEvent, 0, len(s.audits))
	for _, event := range s.audits {
		if filter.matches(event) {
			matched = append(matched, event)
		}
	}
	s.mu.RUnlock()
	sortAudit(matched, filter.Descending)
	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return []*AuditEvent{}, nil
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(matched) {
		matched = matched[:filter.Limit]
	}
	// Clone only the page that is returned; events are append-only and immutable, so sharing the
	// stored pointers during filtering and sorting is safe. | 只克隆返回页；事件只追加且不可变，
	// 因此在过滤与排序期间共享存储指针是安全的。
	out := make([]*AuditEvent, 0, len(matched))
	for _, event := range matched {
		out = append(out, event.Clone())
	}
	return out, nil
}
