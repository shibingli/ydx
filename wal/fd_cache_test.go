package wal

import (
	"os"
	"testing"
)

// TestFDCacheClosesBusyOverBudgetHandles verifies that a concurrent burst above
// the fd budget marks leased handles for close, so the cache returns to its
// bound once leases end. | 验证超过 fd 预算的并发突发会把租用中的句柄标记为关闭，
// 使租约结束后缓存回到上限。
func TestFDCacheClosesBusyOverBudgetHandles(t *testing.T) {
	dir := t.TempDir()
	for seq := uint64(1); seq <= 2; seq++ {
		if err := os.WriteFile(segmentPath(dir, seq), []byte{0}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := newFDCache(dir, 1)
	e1, err := c.acquire(1)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := c.acquire(2)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.count(); got != 2 {
		t.Fatalf("leased handles = %d, want 2", got)
	}
	e1.release()
	e2.release()
	if got := c.count(); got != 0 {
		t.Fatalf("handles after release = %d, want 0 (budget pressure must evict)", got)
	}
	if c.closed {
		t.Fatal("unexpected closed cache")
	}
}
