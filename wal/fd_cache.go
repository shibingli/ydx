package wal

import (
	"container/list"
	"os"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// fdEntry is one cached read-only file handle. | fdEntry 是一个缓存的只读文件句柄。
type fdEntry struct {
	seq   uint64
	f     *os.File
	refs  int
	evict bool
	elem  *list.Element
	cache *fdCache
}

// release decrements the handle lease. | release 减少句柄租约。
func (e *fdEntry) release() {
	e.cache.release(e)
}

// fdCache is the bounded read-only fd LRU. | fdCache 是有界只读 fd LRU。
type fdCache struct {
	mu      sync.Mutex
	dir     string
	max     int
	entries map[uint64]*fdEntry
	lru     *list.List
	closed  bool
}

// newFDCache builds a new cache. | newFDCache 构建新缓存。
func newFDCache(dir string, max int) *fdCache {
	return &fdCache{dir: dir, max: max, entries: make(map[uint64]*fdEntry), lru: list.New()}
}

// acquire opens or reuses a read-only handle. The returned entry must be
// released with (*fdEntry).release. | acquire 打开或复用只读句柄；返回的条目必须
// 通过 (*fdEntry).release 释放。
func (c *fdCache) acquire(seq uint64) (*fdEntry, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	if e, ok := c.entries[seq]; ok {
		e.refs++
		c.lru.MoveToFront(e.elem)
		c.mu.Unlock()
		return e, nil
	}
	c.mu.Unlock()

	f, err := os.Open(segmentPath(c.dir, seq))
	if err != nil {
		return nil, errs.WrapDetail(err, ErrStorage, "open segment %d | 打开分段 %d 失败", seq, seq)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = f.Close()
		return nil, ErrClosed
	}
	if e, ok := c.entries[seq]; ok {
		// Another goroutine won the race; use its handle. | 另一个协程赢得竞争，复用其句柄。
		_ = f.Close()
		e.refs++
		c.lru.MoveToFront(e.elem)
		c.mu.Unlock()
		return e, nil
	}
	e := &fdEntry{seq: seq, f: f, refs: 1, cache: c}
	e.elem = c.lru.PushFront(e)
	c.entries[seq] = e
	c.evictLocked()
	c.mu.Unlock()
	return e, nil
}

// release drops one lease and closes evicted idle entries. | release 释放一个租约并关闭已淘汰的空闲条目。
func (c *fdCache) release(e *fdEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.refs > 0 {
		e.refs--
	}
	if e.refs == 0 && e.evict {
		c.closeEntryLocked(e)
	}
}

// evict marks one segment handle for eviction. | evict 标记一个分段句柄待淘汰。
func (c *fdCache) evict(seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[seq]; ok {
		e.evict = true
		if e.refs == 0 {
			c.closeEntryLocked(e)
		}
	}
}

// closeAll drops every idle handle and marks busy handles for later close. | closeAll
// 关闭全部空闲句柄，并标记繁忙句柄稍后关闭。
func (c *fdCache) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for _, e := range c.entries {
		e.evict = true
		if e.refs == 0 {
			c.closeEntryLocked(e)
		}
	}
}

// evictLocked trims the LRU to max entries. | evictLocked 把 LRU 裁剪到 max 条目。
func (c *fdCache) evictLocked() {
	for len(c.entries) > c.max && c.lru.Len() > 0 {
		back := c.lru.Back()
		if back == nil {
			return
		}
		e := back.Value.(*fdEntry)
		if e.refs > 0 {
			// Walk forward from the back until an idle entry is found. | 从尾部向前寻找空闲条目。
			found := false
			for el := back.Prev(); el != nil; el = el.Prev() {
				cand := el.Value.(*fdEntry)
				if cand.refs == 0 {
					c.closeEntryLocked(cand)
					found = true
					break
				}
			}
			if !found {
				return
			}
			continue
		}
		c.closeEntryLocked(e)
	}
}

// closeEntryLocked closes and removes one entry. | closeEntryLocked 关闭并移除一个条目。
func (c *fdCache) closeEntryLocked(e *fdEntry) {
	if e.f != nil {
		_ = e.f.Close()
		e.f = nil
	}
	if e.elem != nil {
		c.lru.Remove(e.elem)
		e.elem = nil
	}
	delete(c.entries, e.seq)
}

// count returns the cached entry count. | count 返回缓存条目数。
func (c *fdCache) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
