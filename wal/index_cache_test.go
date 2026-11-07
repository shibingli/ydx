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
