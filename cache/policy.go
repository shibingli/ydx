package cache

import "context"

// policyKey carries per-request cache policy through a context. | policyKey 通过上下文携带每请求缓存策略。
type policyKey struct{}

// policy holds the independent flags a request may set. | policy 保存请求可以设置的独立标记。
type policy struct {
	bypass   bool
	deferred bool
}

// WithBypass marks ctx so infrastructure caches skip reads for this request. Writes
// still invalidate. Use it for high-security and classified endpoints where stale
// data is unacceptable. | WithBypass 标记 ctx，使基础设施缓存在本次请求中跳过读取；写入仍然
// 失效。用于不能接受陈旧数据的高安全与涉密端点。
func WithBypass(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	value, _ := ctx.Value(policyKey{}).(policy)
	value.bypass = true
	return context.WithValue(ctx, policyKey{}, value)
}

// Bypass reports whether reads must skip the cache. | Bypass 报告读取是否必须跳过缓存。
func Bypass(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(policyKey{}).(policy)
	return value.bypass
}

// WithDeferredInvalidation marks ctx so write callbacks do not bump generations
// inside the transaction. The caller must call Invalidate after commit. | WithDeferredInvalidation
// 标记 ctx，使写回调不在事务内推进代际；调用方必须在提交后调用 Invalidate。
func WithDeferredInvalidation(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	value, _ := ctx.Value(policyKey{}).(policy)
	value.deferred = true
	return context.WithValue(ctx, policyKey{}, value)
}

// DeferredInvalidation reports whether write callbacks must leave invalidation to
// the caller after commit. | DeferredInvalidation 报告写回调是否必须把失效留给调用方在提交后
// 执行。
func DeferredInvalidation(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(policyKey{}).(policy)
	return value.deferred
}
