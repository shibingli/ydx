package kerberos

import (
	"sync"
	"time"
)

// DefaultReplayCacheEntries is the maximum number of authenticators retained by
// one ReplayCache before the earliest expiring entry is evicted. | DefaultReplayCacheEntries
// 是一个 ReplayCache 在淘汰最早过期条目之前保留的认证器数量上限。
const DefaultReplayCacheEntries = 1 << 16

// ReplayCache remembers accepted AP-REQ authenticators so a captured
// authenticator cannot be presented twice inside its validity window. It is safe
// for concurrent use. | ReplayCache 记录已接受的 AP-REQ 认证器，使被截获的认证器在其有效
// 窗口内不能被再次提交。它可以安全并发使用。
type ReplayCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]time.Time
}

// NewReplayCache returns a cache retaining entries for ttl. A ttl of zero
// selects DefaultReplayCacheTTL; negative values are raised to it. | NewReplayCache
// 返回按 ttl 保留条目的缓存。ttl 为零时选择 DefaultReplayCacheTTL；负值提升为该值。
func NewReplayCache(ttl time.Duration) *ReplayCache {
	if ttl <= 0 {
		ttl = DefaultReplayCacheTTL
	}
	return &ReplayCache{
		ttl:     ttl,
		max:     DefaultReplayCacheEntries,
		entries: make(map[string]time.Time),
	}
}

// Add records key if it is not already retained and reports whether the key was
// new. now is the current time and expiry is the last instant a replay must be
// rejected; an expiry in the past is replaced by now plus the cache TTL. | Add
// 在 key 尚未保留时记录它，并报告 key 是否为新值。now 是当前时间，expiry 是必须拒绝重放的
// 最后时刻；早于现在的 expiry 会被替换为 now 加缓存 TTL。
func (c *ReplayCache) Add(key string, now, expiry time.Time) bool {
	if c == nil {
		return true
	}
	if expiry.Before(now) {
		expiry = now.Add(c.ttl)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if heldUntil, ok := c.entries[key]; ok && heldUntil.After(now) {
		return false
	}
	c.pruneLocked(now)
	if len(c.entries) >= c.max {
		c.evictEarliestLocked()
	}
	c.entries[key] = expiry
	return true
}

// Len returns the number of retained entries. | Len 返回保留的条目数。
func (c *ReplayCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// pruneLocked removes entries whose retention period elapsed. | pruneLocked 删除保留期已过
// 的条目。
func (c *ReplayCache) pruneLocked(now time.Time) {
	for key, expiry := range c.entries {
		if !expiry.After(now) {
			delete(c.entries, key)
		}
	}
}

// evictEarliestLocked removes the entry with the earliest expiry. | evictEarliestLocked
// 删除最早过期的条目。
func (c *ReplayCache) evictEarliestLocked() {
	var (
		haveEarliest bool
		earliestKey  string
		earliest     time.Time
	)
	for key, expiry := range c.entries {
		if !haveEarliest || expiry.Before(earliest) {
			haveEarliest = true
			earliestKey = key
			earliest = expiry
		}
	}
	if haveEarliest {
		delete(c.entries, earliestKey)
	}
}
