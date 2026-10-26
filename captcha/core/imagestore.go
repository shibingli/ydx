package core

import (
	"context"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// imageShards is the number of independently locked image shards. | imageShards 是相互独立加锁的图片分片数。
const imageShards = 16

// imageEntry is one stored image blob. | imageEntry 是一个已存储的图片。
type imageEntry struct {
	expires time.Time
	mime    string
	data    []byte
}

// imageShard is one independently locked image map. | imageShard 是一个独立加锁的图片映射。
type imageShard struct {
	entries   map[string]imageEntry
	lastSweep time.Time
	mu        sync.Mutex
}

// MemoryImageStore is the default single-process image store. | MemoryImageStore 是默认的单进程图片存储。
type MemoryImageStore struct {
	now    func() time.Time
	shards [imageShards]imageShard
	mask   uint32
}

// NewMemoryImageStore builds a sharded in-memory image store. | NewMemoryImageStore 构建分片内存图片存储。
func NewMemoryImageStore() *MemoryImageStore {
	s := &MemoryImageStore{mask: imageShards - 1, now: time.Now}
	for i := range s.shards {
		s.shards[i].entries = make(map[string]imageEntry, 8)
	}
	return s
}

// Put implements ImageStore. | Put 实现 ImageStore。
func (s *MemoryImageStore) Put(ctx context.Context, key string, data []byte, mime string, ttl time.Duration) error {
	if err := storeContextErr(ctx); err != nil {
		return err
	}
	if key == "" {
		return errs.Detail(ErrStore, "empty image key | 空图片键")
	}
	if ttl <= 0 {
		ttl = defaultStoreTTL
	}
	now := s.now()
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s.sweepLocked(shard, now)
	shard.entries[key] = imageEntry{data: data, mime: mime, expires: now.Add(ttl)}
	return nil
}

// Get implements ImageStore. | Get 实现 ImageStore。
func (s *MemoryImageStore) Get(ctx context.Context, key string) ([]byte, string, bool, error) {
	if err := storeContextErr(ctx); err != nil {
		return nil, "", false, err
	}
	now := s.now()
	shard := s.shard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	s.sweepLocked(shard, now)
	entry, ok := shard.entries[key]
	if !ok {
		return nil, "", false, nil
	}
	if !entry.expires.After(now) {
		delete(shard.entries, key)
		return nil, "", false, nil
	}
	out := make([]byte, len(entry.data))
	copy(out, entry.data)
	return out, entry.mime, true, nil
}

// Delete implements ImageStore. | Delete 实现 ImageStore。
func (s *MemoryImageStore) Delete(ctx context.Context, key string) error {
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
func (s *MemoryImageStore) shard(key string) *imageShard {
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &s.shards[h&s.mask]
}

// sweepLocked drops expired images from one shard. | sweepLocked 清理一个分片中的过期图片。
func (s *MemoryImageStore) sweepLocked(shard *imageShard, now time.Time) {
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
