package cache

import (
	"context"
	"testing"
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
