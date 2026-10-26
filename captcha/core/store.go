package core

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// storeShards is the number of independently locked session shards. | storeShards 是相互独立加锁的会话分片数。
const storeShards = 16

// defaultStoreTTL is the fallback lifetime for a non-positive TTL. | defaultStoreTTL 是非正 TTL 的回退存活时间。
const defaultStoreTTL = 2 * time.Minute

// defaultStoreSweep is the lazy expiry sweep interval. | defaultStoreSweep 是惰性过期清理间隔。
const defaultStoreSweep = time.Minute

// memoryEntry is one stored session value. | memoryEntry 是一个会话值。
type memoryEntry struct {
	expires time.Time
	value   []byte
}

// memoryShard is one independently locked session map. | memoryShard 是一个独立加锁的会话映射。
type memoryShard struct {
	entries   map[string]memoryEntry
	lastSweep time.Time
	mu        sync.Mutex
}

// MemoryStore is the default single-process session store. | MemoryStore 是默认的单进程会话存储。
//
// It owns no goroutine and needs no Close: expired entries are swept lazily on
// access. | 它不占用协程也不需要 Close：过期条目在访问时惰性清理。
type MemoryStore struct {
	now    func() time.Time
	shards [storeShards]memoryShard
	mask   uint32
}

// NewMemoryStore builds a sharded in-memory store. | NewMemoryStore 构建分片内存存储。
func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{mask: storeShards - 1, now: time.Now}
	for i := range s.shards {
		s.shards[i].entries = make(map[string]memoryEntry, 8)
	}
	return s
}

// Put implements Store. | Put 实现 Store。
func (s *MemoryStore) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := storeContextErr(ctx); err != nil {
		return err
	}
	if key == "" {
		return errs.Detail(ErrStore, "empty key | 空键")
	}
	if ttl <= 0 {
		ttl = defaultStoreTTL
	}
	now := s.now()
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s.sweepLocked(shard, now)
	shard.entries[key] = memoryEntry{value: value, expires: now.Add(ttl)}
	return nil
}

// PutIfAbsent implements Store. | PutIfAbsent 实现 Store。
func (s *MemoryStore) PutIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := storeContextErr(ctx); err != nil {
		return false, err
	}
	if key == "" {
		return false, errs.Detail(ErrStore, "empty key | 空键")
	}
	if ttl <= 0 {
		ttl = defaultStoreTTL
	}
	now := s.now()
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s.sweepLocked(shard, now)
	if entry, ok := shard.entries[key]; ok && entry.expires.After(now) {
		return false, nil
	}
	shard.entries[key] = memoryEntry{value: value, expires: now.Add(ttl)}
	return true, nil
}

// DeleteIf deletes a key only while it still holds value. | DeleteIf 仅在键仍保存 value 时删除。
//
// Cooldown reservation release uses it so a failed send cannot delete a
// newer request's reservation. | 冷却预占释放使用它，避免发送失败时误删新请求的预占。
func (s *MemoryStore) DeleteIf(ctx context.Context, key string, value []byte) (bool, error) {
	if err := storeContextErr(ctx); err != nil {
		return false, err
	}
	now := s.now()
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s.sweepLocked(shard, now)
	entry, ok := shard.entries[key]
	if !ok {
		return false, nil
	}
	if !entry.expires.After(now) {
		delete(shard.entries, key)
		return false, nil
	}
	if !bytes.Equal(entry.value, value) {
		return false, nil
	}
	delete(shard.entries, key)
	return true, nil
}

// Get implements Store and returns a copy of the stored bytes. | Get 实现 Store 并返回存储字节的副本。
func (s *MemoryStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if err := storeContextErr(ctx); err != nil {
		return nil, false, err
	}
	now := s.now()
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s.sweepLocked(shard, now)
	entry, ok := shard.entries[key]
	if !ok {
		return nil, false, nil
	}
	if !entry.expires.After(now) {
		delete(shard.entries, key)
		return nil, false, nil
	}
	out := make([]byte, len(entry.value))
	copy(out, entry.value)
	return out, true, nil
}

// Take implements Store: the value is removed under the shard lock. | Take 实现 Store：值在分片锁内删除。
func (s *MemoryStore) Take(ctx context.Context, key string) ([]byte, bool, error) {
	if err := storeContextErr(ctx); err != nil {
		return nil, false, err
	}
	now := s.now()
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s.sweepLocked(shard, now)
	entry, ok := shard.entries[key]
	if !ok {
		return nil, false, nil
	}
	if !entry.expires.After(now) {
		delete(shard.entries, key)
		return nil, false, nil
	}
	delete(shard.entries, key)
	return entry.value, true, nil
}

// Delete implements Store. | Delete 实现 Store。
func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	if err := storeContextErr(ctx); err != nil {
		return err
	}
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.entries, key)
	return nil
}

// shard returns the shard that owns key. | shard 返回 key 所属的分片。
func (s *MemoryStore) shard(key string) *memoryShard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &s.shards[h&s.mask]
}

// sweepLocked drops expired entries from one shard. | sweepLocked 清理一个分片中的过期条目。
func (s *MemoryStore) sweepLocked(shard *memoryShard, now time.Time) {
	if now.Sub(shard.lastSweep) < defaultStoreSweep {
		return
	}
	for key, entry := range shard.entries {
		if !entry.expires.After(now) {
			delete(shard.entries, key)
		}
	}
	shard.lastSweep = now
}

// storeContextErr returns a cancelled context error. | storeContextErr 返回已取消的上下文错误。
func storeContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
