// Package accesslog logs one structured record per request. | Package accesslog 为每个请求记录
// 一条结构化日志。
//
// The middleware wraps the response writer with the pooled capture from
// middleware/reqlog, so it records the final status code and byte count without an
// allocation per request. Upgrade requests are never wrapped, which keeps http.Hijacker
// usable for the WebSocket handshake. remote_ip follows router.Ctx.ClientIP and therefore
// uses the explicit TrustedProxies model rather than trusting X-Forwarded-For blindly. |
// 该中间件用 middleware/reqlog 的池化捕获包装响应写入器，因此能记录最终状态码与
// 字节数而无需每请求分配。升级请求绝不包装，保证 WebSocket 握手仍有可用的 http.Hijacker。
// remote_ip 遵循 router.Ctx.ClientIP，因此使用显式的 TrustedProxies 模型，而不是盲信
// X-Forwarded-For。
//
// Both entry points share the same implementation: AccessLog returns a router.Middleware,
// Middleware returns the native net/http wrapper. | 两个入口共享同一份实现：AccessLog 返回
// router.Middleware，Middleware 返回原生 net/http 包装器。
//
// Typical usage | 典型用法：
//
//	r.Use(requestid.RequestID(""), accesslog.AccessLog(logger))
//
//	// plain net/http | 原生 net/http
//	handler := accesslog.Middleware(logger)(mux)
package accesslog
