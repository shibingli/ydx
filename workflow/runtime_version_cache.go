package workflow

import "sync"

const (
	// runtimeVersionCacheEntries bounds the number of parsed published versions kept in memory. |
	// runtimeVersionCacheEntries 限制内存中保留的已解析已发布版本数量。
	runtimeVersionCacheEntries = 128
	// runtimeVersionCacheBytes bounds the estimated bytes of the version cache. The estimate counts
	// the stored design JSON, the derived BPMN, the parsed node/edge/rule structures and the parsed
	// strings produced by unmarshalling, which several times exceeds the source size. |
	// runtimeVersionCacheBytes 限制版本缓存的估算字节数。估算计入存储的设计 JSON、派生 BPMN、
	// 解析后的节点/连线/规则结构以及反序列化产生的字符串，后者往往是源码体积的数倍。
	runtimeVersionCacheBytes = 16 << 20
)

// runtimeVersionKey identifies one tenant's version. Published versions are immutable, so the id
// alone would suffice; the tenant is part of the key so a caller can never read another tenant's
// cached row even if an id leaks. | runtimeVersionKey 标识某个租户的一个版本。已发布版本不可变，
// 仅凭 ID 就足够；把租户放进键里，即使 ID 泄漏，调用方也读不到其它租户的缓存行。
type runtimeVersionKey struct {
	// TenantID is the owning tenant. | TenantID 是归属租户。
	TenantID string
	// VersionID is the version primary key. | VersionID 是版本主键。
	VersionID string
}

// runtimeVersionValue is one parsed version. | runtimeVersionValue 是一个已解析版本。
type runtimeVersionValue struct {
	// version is the immutable published row. | version 是不可变的已发布行。
	version Version
	// design is the parsed design document. | design 是解析后的设计文档。
	design Design
	// size estimates the memory held by this entry. | size 估算该条目占用的内存。
	size int
}

// runtimeVersionCache keeps parsed published versions so task actions do not re-read the design
// and BPMN columns and re-unmarshal the design on every request. It is a bounded FIFO: entries
// are immutable, so eviction never affects correctness. | runtimeVersionCache 缓存已解析的已发布
// 版本，使任务动作不再在每个请求上重读设计与 BPMN 列并重新反序列化设计。它是有界 FIFO：条目不可变，
// 淘汰永远不会影响正确性。
type runtimeVersionCache struct {
	// entries maps a key onto its parsed value. | entries 把键映射到已解析值。
	entries map[runtimeVersionKey]runtimeVersionValue
	// order is the insertion order used for FIFO eviction. | order 是 FIFO 淘汰使用的插入顺序。
	order []runtimeVersionKey
	// bytes is the estimated total size. | bytes 是估算总大小。
	bytes int
	// maxEntries and maxBytes are the configured ceilings. | maxEntries 与 maxBytes 是配置上限。
	maxEntries int
	maxBytes   int
	// mu guards entries, order and bytes. | mu 保护 entries、order 与 bytes。
	mu sync.RWMutex
}

// newRuntimeVersionCache builds the bounded cache. | newRuntimeVersionCache 构建有界缓存。
func newRuntimeVersionCache() *runtimeVersionCache {
	return &runtimeVersionCache{
		entries:    make(map[runtimeVersionKey]runtimeVersionValue, runtimeVersionCacheEntries),
		order:      make([]runtimeVersionKey, 0, runtimeVersionCacheEntries),
		maxEntries: runtimeVersionCacheEntries,
		maxBytes:   runtimeVersionCacheBytes,
	}
}

// get returns one parsed version. | get 返回一个已解析版本。
func (c *runtimeVersionCache) get(key runtimeVersionKey) (Version, Design, bool) {
	if c == nil {
		return Version{}, Design{}, false
	}
	c.mu.RLock()
	value, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return Version{}, Design{}, false
	}
	return value.version, value.design, true
}

// put stores one parsed version and evicts oldest entries until both ceilings hold. |
// put 保存一个已解析版本，并持续淘汰最旧条目直到两个上限都满足。
func (c *runtimeVersionCache) put(key runtimeVersionKey, version Version, design Design) {
	if c == nil || version.Status != VersionPublished {
		return
	}
	size := len(version.Design)*2 + len(version.BPMN) +
		len(design.Nodes)*1024 + len(design.Edges)*512 + len(design.Rules)*512 + 4096
	if size > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.entries[key]; ok {
		c.bytes -= existing.size
	} else {
		c.order = append(c.order, key)
	}
	c.entries[key] = runtimeVersionValue{version: version, design: design, size: size}
	c.bytes += size
	for (len(c.entries) > c.maxEntries || c.bytes > c.maxBytes) && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		if entry, ok := c.entries[oldest]; ok {
			delete(c.entries, oldest)
			c.bytes -= entry.size
		}
	}
}
