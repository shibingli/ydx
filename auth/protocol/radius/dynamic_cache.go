package radius

import (
	"container/list"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Dynamic duplicate cache defaults. | 动态授权重复缓存默认值。
const (
	// DefaultDynamicDuplicateTTL is the default duplicate-detection window. RFC 5176 section 3.6
	// recommends that the window match the stale-timestamp window; thirty seconds covers the
	// retransmission budgets of typical dynamic authorization clients. | DefaultDynamicDuplicateTTL
	// 是默认的重复检测窗口。RFC 5176 第 3.6 节建议该窗口与过期时间戳窗口一致；三十秒足以覆盖典型
	// 动态授权客户端的重传预算。
	DefaultDynamicDuplicateTTL = 30 * time.Second
	// DefaultDynamicDuplicateCapacity is the default maximum number of cached responses. |
	// DefaultDynamicDuplicateCapacity 是缓存响应的默认最大条数。
	DefaultDynamicDuplicateCapacity = 1024
)

// DynamicDuplicateKey identifies one authenticated dynamic authorization request for duplicate
// detection. | DynamicDuplicateKey 标识一个已认证的动态授权请求，用于重复检测。
//
// RFC 5176 section 3.6 detects duplicates by source IP address, source UDP port and Identifier. The
// key also carries the request code and Request Authenticator: a retransmission is byte-identical,
// so a changed authenticator describes a different request even when the identifier is reused. |
// RFC 5176 第 3.6 节按源 IP 地址、源 UDP 端口与 Identifier 检测重复。键还携带请求类型与 Request
// Authenticator：重传字节完全相同，因此认证符变化即表示不同请求，即使标识符被复用。
type DynamicDuplicateKey struct {
	// Source is the peer address, normally "ip:port". | Source 是对端地址，通常为 "ip:port"。
	Source string
	// Code is the CoA-Request or Disconnect-Request code. | Code 是 CoA-Request 或
	// Disconnect-Request 类型码。
	Code Code
	// Identifier is the packet identifier. | Identifier 是报文标识符。
	Identifier uint8
	// Authenticator is the validated Request Authenticator. | Authenticator 是已校验的 Request
	// Authenticator。
	Authenticator [16]byte
}

// DynamicDuplicateCacheConfig configures a DynamicDuplicateCache. | DynamicDuplicateCacheConfig
// 配置 DynamicDuplicateCache。
type DynamicDuplicateCacheConfig struct {
	// Capacity is the maximum number of cached responses; zero selects
	// DefaultDynamicDuplicateCapacity and negative values are rejected. | Capacity 是缓存响应的
	// 最大条数；零值选择 DefaultDynamicDuplicateCapacity，负值会被拒绝。
	Capacity int
	// TTL is how long a cached response stays valid; zero selects DefaultDynamicDuplicateTTL and
	// negative values are rejected. | TTL 是缓存响应的有效期；零值选择
	// DefaultDynamicDuplicateTTL，负值会被拒绝。
	TTL time.Duration
	// Clock overrides the time source; nil uses time.Now. | Clock 替换时间源；nil 使用 time.Now。
	Clock func() time.Time
}

// DynamicDuplicateCache caches authenticated CoA-ACK, CoA-NAK, Disconnect-ACK and Disconnect-NAK
// responses by DynamicDuplicateKey. | DynamicDuplicateCache 按 DynamicDuplicateKey 缓存已认证的
// CoA-ACK、CoA-NAK、Disconnect-ACK 与 Disconnect-NAK 响应。
//
// A DynamicServer replays the cached bytes for a retransmitted request without invoking the handler
// again, as RFC 5176 section 3.6 requires. Entries expire after TTL and the oldest entry is evicted
// when Capacity would be exceeded, so memory use is bounded. The cache is safe for concurrent use.
// Get returns a copy and Put copies the response, so callers can never mutate cached bytes. | 对重传
// 的请求，DynamicServer 会重放缓存的字节而不再调用处理器，符合 RFC 5176 第 3.6 节要求。条目在
// TTL 后过期，超出 Capacity 时淘汰最旧条目，因此内存占用有界。缓存可并发使用。Get 返回副本，
// Put 复制响应，调用方永远无法修改缓存字节。
type DynamicDuplicateCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	clock    func() time.Time
	entries  map[DynamicDuplicateKey]*list.Element
	order    *list.List
}

// dynamicDuplicateEntry is one cached response in insertion order. | dynamicDuplicateEntry 是按插入
// 顺序保存的一条缓存响应。
type dynamicDuplicateEntry struct {
	key       DynamicDuplicateKey
	response  []byte
	expiresAt time.Time
}

// NewDynamicDuplicateCache validates config and returns a cache. | NewDynamicDuplicateCache 校验
// config 并返回缓存。
func NewDynamicDuplicateCache(config DynamicDuplicateCacheConfig) (*DynamicDuplicateCache, error) {
	if config.Capacity < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "duplicate cache capacity %d must not be negative", config.Capacity)
	}
	if config.Capacity == 0 {
		config.Capacity = DefaultDynamicDuplicateCapacity
	}
	if config.TTL < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "duplicate cache TTL %s must not be negative", config.TTL)
	}
	if config.TTL == 0 {
		config.TTL = DefaultDynamicDuplicateTTL
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &DynamicDuplicateCache{
		capacity: config.Capacity,
		ttl:      config.TTL,
		clock:    config.Clock,
		entries:  make(map[DynamicDuplicateKey]*list.Element, config.Capacity),
		order:    list.New(),
	}, nil
}

// Get returns a copy of the cached response for key and reports whether an unexpired entry exists.
// | Get 返回 key 对应缓存响应的副本，并报告是否存在未过期条目。
func (c *DynamicDuplicateCache) Get(key DynamicDuplicateKey) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(*dynamicDuplicateEntry)
	out := make([]byte, len(entry.response))
	copy(out, entry.response)
	return out, true
}

// Put stores a copy of response for key, refreshing its TTL. When the cache is full the oldest entry
// is evicted first. | Put 为 key 保存 response 的副本并刷新其 TTL。缓存已满时先淘汰最旧条目。
func (c *DynamicDuplicateCache) Put(key DynamicDuplicateKey, response []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	c.purgeLocked()
	if element, ok := c.entries[key]; ok {
		entry := element.Value.(*dynamicDuplicateEntry)
		entry.response = append(entry.response[:0], response...)
		entry.expiresAt = now.Add(c.ttl)
		c.order.MoveToBack(element)
		return
	}
	for c.order.Len() >= c.capacity {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*dynamicDuplicateEntry).key)
	}
	entry := &dynamicDuplicateEntry{
		key:       key,
		response:  append([]byte(nil), response...),
		expiresAt: now.Add(c.ttl),
	}
	c.entries[key] = c.order.PushBack(entry)
}

// Len returns the number of unexpired entries. | Len 返回未过期条目数。
func (c *DynamicDuplicateCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	return len(c.entries)
}

// Reset removes every cached response. | Reset 移除全部缓存响应。
func (c *DynamicDuplicateCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[DynamicDuplicateKey]*list.Element, c.capacity)
	c.order.Init()
}

// purgeLocked removes expired entries from the oldest end. Entries are inserted and refreshed in
// TTL order, so a single pass is sufficient. The caller must hold c.mu. | purgeLocked 从最旧一端
// 删除过期条目。条目按 TTL 顺序插入与刷新，因此单次遍历即可。调用方必须持有 c.mu。
func (c *DynamicDuplicateCache) purgeLocked() {
	now := c.clock()
	for {
		front := c.order.Front()
		if front == nil {
			return
		}
		entry := front.Value.(*dynamicDuplicateEntry)
		if now.Before(entry.expiresAt) {
			return
		}
		c.order.Remove(front)
		delete(c.entries, entry.key)
	}
}
