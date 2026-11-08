package radius

import (
	"crypto/sha256"
	"net"
	"sync"
	"time"
)

// Accounting duplicate-cache defaults. | 计费重复缓存默认值。
const (
	// DefaultAccountingDuplicateWindow is how long a signed Accounting-Response is replayed for an
	// identical retransmission. | DefaultAccountingDuplicateWindow 是为完全相同的重传重放已签名
	// Accounting-Response 的时长。
	DefaultAccountingDuplicateWindow = 30 * time.Second
	// DefaultAccountingDuplicateCacheSize is the default maximum number of cached responses. |
	// DefaultAccountingDuplicateCacheSize 是缓存响应的默认最大数量。
	DefaultAccountingDuplicateCacheSize = 1024
)

// accountingDuplicateKey identifies an identical Accounting-Request from one peer. | accountingDuplicateKey
// 标识来自同一对端的完全相同 Accounting-Request。
type accountingDuplicateKey [sha256.Size]byte

// accountingDuplicateEntry is one cached signed Accounting-Response. | accountingDuplicateEntry 是一个
// 已缓存的已签名 Accounting-Response。
type accountingDuplicateEntry struct {
	response []byte
	expires  time.Time
	sequence uint64
}

// accountingDuplicateCache suppresses duplicate accounting records and replays the signed response.
// It is safe for concurrent use. | accountingDuplicateCache 抑制重复计费记录并重放已签名响应。它可
// 并发使用。
type accountingDuplicateCache struct {
	entries      map[accountingDuplicateKey]accountingDuplicateEntry
	window       time.Duration
	nextSequence uint64
	max          int
	mu           sync.Mutex
}

// newAccountingDuplicateCache returns a cache, or nil when suppression is disabled. A zero window
// selects DefaultAccountingDuplicateWindow, a zero size selects DefaultAccountingDuplicateCacheSize,
// and a non-positive window or size disables suppression. | newAccountingDuplicateCache 返回缓存；
// 抑制被禁用时返回 nil。window 为零选择 DefaultAccountingDuplicateWindow，size 为零选择
// DefaultAccountingDuplicateCacheSize，非正的 window 或 size 禁用抑制。
func newAccountingDuplicateCache(size int, window time.Duration) *accountingDuplicateCache {
	if window <= 0 || size <= 0 {
		return nil
	}
	return &accountingDuplicateCache{
		entries: make(map[accountingDuplicateKey]accountingDuplicateEntry),
		window:  window,
		max:     size,
	}
}

// lookup returns a copy of the cached response for this exact request and peer. | lookup 返回此完全
// 相同请求与对端对应的缓存响应副本。
func (c *accountingDuplicateCache) lookup(remote net.Addr, raw []byte, now time.Time) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	key := accountingDuplicateDigest(remote, raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !entry.expires.After(now) {
		delete(c.entries, key)
		return nil, false
	}
	return append([]byte(nil), entry.response...), true
}

// store caches a signed response for this exact request and peer, evicting expired and then the
// oldest entry when the cache is full. | store 缓存此完全相同请求与对端对应的已签名响应；缓存已满时
// 先清除过期项，再淘汰最旧项。
func (c *accountingDuplicateCache) store(remote net.Addr, raw, response []byte, now time.Time) {
	if c == nil || len(response) == 0 {
		return
	}
	key := accountingDuplicateDigest(remote, raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	if len(c.entries) >= c.max {
		c.evictOldestLocked()
	}
	c.nextSequence++
	c.entries[key] = accountingDuplicateEntry{
		response: append([]byte(nil), response...),
		expires:  now.Add(c.window),
		sequence: c.nextSequence,
	}
}

// pruneLocked removes expired entries. The caller must hold c.mu. | pruneLocked 移除过期项。调用方
// 必须持有 c.mu。
func (c *accountingDuplicateCache) pruneLocked(now time.Time) {
	for key, entry := range c.entries {
		if !entry.expires.After(now) {
			delete(c.entries, key)
		}
	}
}

// evictOldestLocked removes the entry inserted earliest. The caller must hold c.mu. |
// evictOldestLocked 移除最早插入的项。调用方必须持有 c.mu。
func (c *accountingDuplicateCache) evictOldestLocked() {
	var oldestKey accountingDuplicateKey
	var oldestSequence uint64
	first := true
	for key, entry := range c.entries {
		if first || entry.sequence < oldestSequence {
			oldestKey = key
			oldestSequence = entry.sequence
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}

// accountingDuplicateDigest returns the peer-bound digest of an incoming request. The peer is bound
// by host rather than by source port because a NAS may retransmit a byte-identical request from a
// new UDP source port, and RFC 2866 duplicate detection is keyed by the NAS and the packet bytes. |
// accountingDuplicateDigest 返回入站请求与对端绑定的摘要。对端按主机而非源端口绑定，因为 NAS 可能
// 从新的 UDP 源端口重传字节完全相同的请求，而 RFC 2866 的重复检测以 NAS 与报文本身为键。
func accountingDuplicateDigest(remote net.Addr, raw []byte) accountingDuplicateKey {
	digest := sha256.New()
	if peer := accountingDuplicatePeer(remote); peer != "" {
		_, _ = digest.Write([]byte(peer))
		_, _ = digest.Write([]byte{0})
	}
	_, _ = digest.Write(raw)
	var key accountingDuplicateKey
	digest.Sum(key[:0])
	return key
}

// accountingDuplicatePeer returns the host portion of a remote address. | accountingDuplicatePeer
// 返回远端地址的主机部分。
func accountingDuplicatePeer(remote net.Addr) string {
	if remote == nil {
		return ""
	}
	address := remote.String()
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}
	return address
}
