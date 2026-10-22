// Package requestid assigns every request a unique id and exposes it to downstream
// middleware and handlers. | Package requestid 为每个请求分配唯一 ID，并提供给下游中间件与
// 处理器。
//
// The id is taken from the configured header — X-Request-Id by default — and a fresh UUIDv4
// is generated when the header is absent. It is stored in the router context under
// RequestIDKey and echoed in the same response header. FromContext reads it without exposing
// the context key to callers. | 若请求携带配置的头（默认 X-Request-Id）则沿用其值，否则生成新的
// UUIDv4。ID 以 RequestIDKey 存入路由上下文，并通过同名响应头回显。FromContext 让调用方无需
// 直接接触上下文键即可读取。
//
// Both entry points share the middleware implementation: RequestID returns a
// router.Middleware, Middleware returns the native net/http wrapper. | 两个入口共享同一份
// 中间件实现：RequestID 返回 router.Middleware，Middleware 返回原生 net/http 包装器。
//
// Typical usage | 典型用法：
//
//	r.Use(requestid.RequestID(""))
//
//	// plain net/http | 原生 net/http
//	handler := requestid.Middleware("")(mux)
package requestid
