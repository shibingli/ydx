package wal

import (
	"sync/atomic"
	"time"
)

// dedupTable maps a content digest to a record offset in the active segment. | dedupTable
// 把内容摘要映射到活动段内的记录偏移。
type dedupTable struct {
	entries  map[[32]byte]uint64
	max      int
	overflow atomic.Uint64
}

// newDedupTable builds a bounded in-segment dedup table. | newDedupTable 构建有界段内去重表。
func newDedupTable(max int) *dedupTable {
	return &dedupTable{entries: make(map[[32]byte]uint64), max: max}
}

// lookup returns the target offset for a digest. | lookup 返回摘要对应的目标偏移。
func (d *dedupTable) lookup(digest [32]byte) (uint64, bool) {
	if d == nil {
		return 0, false
	}
	off, ok := d.entries[digest]
	return off, ok
}

// add records a new ordinary record. | add 记录一条新的普通记录。
func (d *dedupTable) add(digest [32]byte, off uint64) {
	if d == nil {
		return
	}
	if _, ok := d.entries[digest]; ok {
		return
	}
	if len(d.entries) >= d.max {
		d.overflow.Add(1)
		return
	}
	d.entries[digest] = off
}

// clear drops every entry at rotation. | clear 在轮转时清空全部条目。
func (d *dedupTable) clear() {
	if d == nil {
		return
	}
	clear(d.entries)
}

// idemEntry is one AppendOnce window entry. | idemEntry 是一个 AppendOnce 幂等窗口条目。
type idemEntry struct {
	key     [32]byte
	content [32]byte
	lsn     uint64
	at      int64
	prev    *idemEntry
	next    *idemEntry
}

// idemTable is a true LRU with an optional TTL. | idemTable 是带可选 TTL 的真 LRU。
type idemTable struct {
	m    map[[32]byte]*idemEntry
	head *idemEntry
	tail *idemEntry
	max  int
	ttl  time.Duration
}

// newIdemTable builds a bounded idempotency LRU. | newIdemTable 构建有界幂等 LRU。
func newIdemTable(max int, ttl time.Duration) *idemTable {
	return &idemTable{m: make(map[[32]byte]*idemEntry, max), max: max, ttl: ttl}
}

// lookup classifies one idempotency key. | lookup 对一个幂等键分类。
func (t *idemTable) lookup(key, content [32]byte, now time.Time) (*idemEntry, bool, bool) {
	if t == nil {
		return nil, false, false
	}
	e, ok := t.m[key]
	if !ok {
		return nil, false, false
	}
	if t.ttl > 0 && now.UnixNano()-e.at > int64(t.ttl) {
		t.remove(e)
		return nil, false, false
	}
	t.moveFront(e)
	if e.content == content {
		return e, true, false
	}
	return e, false, true
}

// put inserts or refreshes an entry. | put 插入或刷新一个条目。
func (t *idemTable) put(key, content [32]byte, lsn uint64, now time.Time) {
	if t == nil {
		return
	}
	if e, ok := t.m[key]; ok {
		e.content = content
		e.lsn = lsn
		e.at = now.UnixNano()
		t.moveFront(e)
		return
	}
	e := &idemEntry{key: key, content: content, lsn: lsn, at: now.UnixNano()}
	t.m[key] = e
	t.pushFront(e)
	for len(t.m) > t.max && t.tail != nil {
		t.remove(t.tail)
	}
}

// dropIfBefore removes a hit whose LSN was truncated. | dropIfBefore 删除 LSN 已被截断的命中项。
func (t *idemTable) dropIfBefore(key [32]byte, firstLSN uint64) {
	if t == nil {
		return
	}
	if e, ok := t.m[key]; ok && e.lsn < firstLSN {
		t.remove(e)
	}
}

// remove unlinks an entry. | remove 解除一个条目。
func (t *idemTable) remove(e *idemEntry) {
	if e == nil {
		return
	}
	if e.prev != nil {
		e.prev.next = e.next
	} else if t.head == e {
		t.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if t.tail == e {
		t.tail = e.prev
	}
	e.prev, e.next = nil, nil
	delete(t.m, e.key)
}

// pushFront inserts at the MRU end. | pushFront 插入到 MRU 端。
func (t *idemTable) pushFront(e *idemEntry) {
	e.prev = nil
	e.next = t.head
	if t.head != nil {
		t.head.prev = e
	}
	t.head = e
	if t.tail == nil {
		t.tail = e
	}
}

// moveFront promotes a hit. | moveFront 把命中项提升到 MRU。
func (t *idemTable) moveFront(e *idemEntry) {
	if t.head == e {
		return
	}
	if e.prev != nil {
		e.prev.next = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		t.tail = e.prev
	}
	e.prev = nil
	e.next = t.head
	if t.head != nil {
		t.head.prev = e
	}
	t.head = e
}

// clear drops the window. | clear 清空窗口。
func (t *idemTable) clear() {
	if t == nil {
		return
	}
	t.m = make(map[[32]byte]*idemEntry, t.max)
	t.head, t.tail = nil, nil
}
