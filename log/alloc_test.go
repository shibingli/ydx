package log

import (
	"io"
	"testing"
)

// TestDisabledPathIsAllocationFree is a regression guard: a call at a disabled level must not
// allocate any heap memory. | TestDisabledPathIsAllocationFree 是回归护栏：禁用级别下调用不得
// 产生任何堆分配。
func TestDisabledPathIsAllocationFree(t *testing.T) {
	l := New(Options{Writer: io.Discard, Level: ErrorLevel})
	allocs := testing.AllocsPerRun(1000, func() {
		l.Info("request handled", Str("method", "GET"), Int("status", 200))
	})
	if allocs != 0 {
		t.Fatalf("禁用级别路径分配数 = %v，期望 0", allocs)
	}
}
