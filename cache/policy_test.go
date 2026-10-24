package cache

import (
	"context"
	"io"
	"testing"

	"github.com/shibingli/ydx/log"
)

// TestPolicyFlagsAreIndependent proves bypass and deferred invalidation compose
// without overwriting each other. | TestPolicyFlagsAreIndependent 证明旁路与延迟失效可以组合，
// 不会互相覆盖。
func TestPolicyFlagsAreIndependent(t *testing.T) {
	ctx := context.Background()
	if Bypass(ctx) || DeferredInvalidation(ctx) {
		t.Fatal("background context has a policy | 背景上下文带有策略")
	}
	bypass := WithBypass(ctx)
	if !Bypass(bypass) || DeferredInvalidation(bypass) {
		t.Fatal("bypass policy is wrong | 旁路策略不符")
	}
	both := WithDeferredInvalidation(bypass)
	if !Bypass(both) || !DeferredInvalidation(both) {
		t.Fatal("combined policy lost a flag | 组合策略丢失标记")
	}
	deferred := WithDeferredInvalidation(ctx)
	if Bypass(deferred) || !DeferredInvalidation(deferred) {
		t.Fatal("deferred policy is wrong | 延迟策略不符")
	}
	// Nil contexts are accepted and never panic. | nil 上下文可用且不会 panic。
	if Bypass(nil) || DeferredInvalidation(nil) {
		t.Fatal("nil context reported a policy | nil 上下文报告了策略")
	}
	if !Bypass(WithBypass(nil)) {
		t.Fatal("WithBypass(nil) lost the flag | WithBypass(nil) 丢失标记")
	}
}

// TestBypassSkipsRawCacheReadsAndWrites proves a bypass read misses and a bypass
// load does not populate the cache. | TestBypassSkipsRawCacheReadsAndWrites 证明旁路读取
// 会未命中，且旁路加载不会回填缓存。
func TestBypassSkipsRawCacheReadsAndWrites(t *testing.T) {
	m, err := NewManager(WithLogger(log.New(log.Options{Writer: io.Discard})))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = m.Close() }()
	raw, err := m.Raw("policy")
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	ctx := context.Background()
	if err := raw.Set(ctx, "k", []byte("cached")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok, err := raw.Get(ctx, "k"); err != nil || !ok {
		t.Fatalf("normal Get = ok:%v err:%v", ok, err)
	}
	bypass := WithBypass(ctx)
	if _, ok, err := raw.Get(bypass, "k"); err != nil || ok {
		t.Fatalf("bypass Get = ok:%v err:%v, want miss", ok, err)
	}
	loads := 0
	for i := 0; i < 2; i++ {
		_, err := raw.GetOrLoad(bypass, "loaded", func(context.Context) ([]byte, error) {
			loads++
			return []byte("fresh"), nil
		})
		if err != nil {
			t.Fatalf("bypass GetOrLoad: %v", err)
		}
	}
	if loads != 2 {
		t.Fatalf("bypass loader ran %d times, want 2", loads)
	}
	if _, ok, err := raw.Get(ctx, "loaded"); err != nil || ok {
		t.Fatalf("bypass load populated cache: ok=%v err=%v", ok, err)
	}
}
