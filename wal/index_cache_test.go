package wal

import "testing"

// TestIndexCacheEvictsOversizedBusyEntry verifies that a single index larger
// than the whole budget is retired when its lease ends, so the configured
// memory bound is eventually enforced. | 验证单个超过全部预算的索引在租约结束后
// 被移除，最终执行配置的内存上限。
func TestIndexCacheEvictsOversizedBusyEntry(t *testing.T) {
	c := newIndexCache(10)
	entry, release, err := c.acquire(1, func() (*indexEntry, error) {
		return &indexEntry{sparse: make([]sparseEntry, 100)}, nil
	})
	if err != nil || entry == nil {
		t.Fatalf("acquire = %v/%v", entry, err)
	}
	if entries, _ := c.stats(); entries != 1 {
		t.Fatalf("entries while leased = %d, want 1", entries)
	}
	release()
	if entries, size := c.stats(); entries != 0 || size != 0 {
		t.Fatalf("oversized entry survived release: entries=%d size=%d", entries, size)
	}
}

// TestIndexCacheKeepsUnderBudgetEntry verifies that an index within budget
// remains cached after its lease ends. | 验证预算内的索引在租约结束后保留缓存。
func TestIndexCacheKeepsUnderBudgetEntry(t *testing.T) {
	c := newIndexCache(1 << 20)
	entry, release, err := c.acquire(1, func() (*indexEntry, error) {
		return &indexEntry{sparse: make([]sparseEntry, 1)}, nil
	})
	if err != nil || entry == nil {
		t.Fatalf("acquire = %v/%v", entry, err)
	}
	release()
	if entries, _ := c.stats(); entries != 1 {
		t.Fatalf("under-budget entry entries = %d, want 1", entries)
	}
}

// TestIndexCacheAdoptLeasesRebuiltIndex verifies that a rebuilt index is
// registered under the byte budget, that a duplicate-seq adoption replaces the
// map owner, and that releasing the replaced lease cannot remove the newer
// entry. | 验证内存重建索引按字节预算登记；同序号重复登记替换映射归属，释放旧
// 租约不会移除新条目。
func TestIndexCacheAdoptLeasesRebuiltIndex(t *testing.T) {
	c := newIndexCache(1)
	var seg segment
	seg.seq = 7
	a := &indexEntry{sparse: []sparseEntry{{lsn: 1}}}
	releaseA := c.adopt(a, &seg, 1)
	if entries, size := c.stats(); entries != 1 || size <= 0 {
		t.Fatalf("adopted entry not registered: entries=%d size=%d", entries, size)
	}
	b := &indexEntry{sparse: []sparseEntry{{lsn: 2}, {lsn: 3}}}
	releaseB := c.adopt(b, &seg, 2)
	if entries, _ := c.stats(); entries != 1 {
		t.Fatalf("duplicate-seq adopt entries = %d, want 1", entries)
	}
	releaseA()
	if entries, _ := c.stats(); entries != 1 {
		t.Fatal("releasing the replaced lease removed the newer entry")
	}
	releaseB()
	if entries, size := c.stats(); entries != 0 || size != 0 {
		t.Fatalf("adopted entry survived release: entries=%d size=%d", entries, size)
	}
}

// TestIndexCacheRemovalRespectsIndexGeneration verifies that evicting an entry
// built for an older segment generation does not clear newer segment fields. |
// 验证淘汰旧分段代次的条目不会清除更新的分段索引字段。
func TestIndexCacheRemovalRespectsIndexGeneration(t *testing.T) {
	c := newIndexCache(1 << 20)
	var seg segment
	seg.seq = 3
	old := &indexEntry{sparse: []sparseEntry{{lsn: 1}}}
	release := c.adopt(old, &seg, 1)
	seg.metaMu.Lock()
	seg.indexGen = 2
	seg.sparse = []sparseEntry{{lsn: 9}}
	seg.sparseLoaded = true
	seg.metaMu.Unlock()
	c.evict(seg.seq)
	release()
	if entries, _ := c.stats(); entries != 0 {
		t.Fatalf("evicted entry entries = %d, want 0", entries)
	}
	seg.metaMu.RLock()
	defer seg.metaMu.RUnlock()
	if seg.sparse == nil || !seg.sparseLoaded {
		t.Fatal("stale generation removal cleared newer segment fields")
	}
}
