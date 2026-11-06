package wal

import (
	"container/list"
	"sync"
)

// indexEntry is one cached sparse/Key index. | indexEntry 是一个缓存的稀疏/Key 索引。
type indexEntry struct {
	seq              uint64
	sparse           []sparseEntry
	keyIndex         map[string][]uint64
	keyIndexOverflow bool
	hasKeyIndex      bool
	size             int64
	refs             int
	evict            bool
	elem             *list.Element
	cache            *indexCache
}

// release drops one cache lease. | release 释放一个缓存租约。
func (e *indexEntry) release() { e.cache.release(e) }

// indexCache is the bounded sparse-index LRU. | indexCache 是有界稀疏索引 LRU。
type indexCache struct {
	mu      sync.Mutex
	max     int64
	size    int64
	entries map[uint64]*indexEntry
	lru     *list.List
}

// newIndexCache builds a cache with a byte budget. | newIndexCache 构建带字节预算的缓存。
func newIndexCache(max int64) *indexCache {
	return &indexCache{max: max, entries: make(map[uint64]*indexEntry), lru: list.New()}
}

// acquire returns the cached index, calling load on a miss. | acquire 返回缓存索引，未命中时调用 load。
func (c *indexCache) acquire(seq uint64, load func() (*indexEntry, error)) (*indexEntry, func(), error) {
	c.mu.Lock()
	if e, ok := c.entries[seq]; ok {
		e.refs++
		c.lru.MoveToFront(e.elem)
		c.mu.Unlock()
		return e, e.release, nil
	}
	c.mu.Unlock()
	e, err := load()
	if err != nil {
		return nil, nil, err
	}
	if e == nil {
		return nil, func() {}, nil
	}
	e.seq = seq
	e.cache = c
	e.size = e.estimateSize()
	if c.max <= 0 {
		return e, func() {}, nil
	}
	c.mu.Lock()
	if existing, ok := c.entries[seq]; ok {
		existing.refs++
		c.lru.MoveToFront(existing.elem)
		c.mu.Unlock()
		return existing, existing.release, nil
	}
	e.refs = 1
	e.elem = c.lru.PushFront(e)
	c.entries[seq] = e
	c.size += e.size
	c.evictLocked()
	c.mu.Unlock()
	return e, e.release, nil
}

// release drops one lease and removes evicted idle entries. | release 释放一个租约并移除已淘汰的空闲条目。
func (c *indexCache) release(e *indexEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.refs > 0 {
		e.refs--
	}
	if e.refs == 0 && e.evict {
		c.removeLocked(e)
	}
}

// evictLocked keeps the cache under its byte budget. | evictLocked 保持缓存低于字节预算。
func (c *indexCache) evictLocked() {
	for c.size > c.max && c.lru.Len() > 0 {
		back := c.lru.Back()
		if back == nil {
			return
		}
		e := back.Value.(*indexEntry)
		if e.refs > 0 {
			found := false
			for el := back.Prev(); el != nil; el = el.Prev() {
				cand := el.Value.(*indexEntry)
				if cand.refs == 0 {
					c.removeLocked(cand)
					found = true
					break
				}
			}
			if !found {
				return
			}
			continue
		}
		c.removeLocked(e)
	}
}

// removeLocked removes one entry from the cache. | removeLocked 从缓存移除一个条目。
func (c *indexCache) removeLocked(e *indexEntry) {
	if e.elem != nil {
		c.lru.Remove(e.elem)
		e.elem = nil
	}
	delete(c.entries, e.seq)
	c.size -= e.size
	if c.size < 0 {
		c.size = 0
	}
}

// evict marks one segment index for removal. | evict 标记一个分段索引待移除。
func (c *indexCache) evict(seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[seq]; ok {
		e.evict = true
		if e.refs == 0 {
			c.removeLocked(e)
		}
	}
}

// closeAll drops every idle index. | closeAll 丢弃全部空闲索引。
func (c *indexCache) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		if e.refs == 0 {
			c.removeLocked(e)
		} else {
			e.evict = true
		}
	}
}

// stats returns entry and byte counts. | stats 返回条目数与字节数。
func (c *indexCache) stats() (int64, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int64(len(c.entries)), c.size
}

// estimateSize approximates the retained memory. | estimateSize 估算保留内存。
func (e *indexEntry) estimateSize() int64 {
	n := int64(len(e.sparse)) * 24
	for k, lsns := range e.keyIndex {
		n += int64(len(k)) + int64(len(lsns))*8
	}
	if n < 1 {
		n = 1
	}
	return n
}
