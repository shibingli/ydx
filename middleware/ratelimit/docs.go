// Package ratelimit enforces per-key token-bucket limits. | Package ratelimit 执行按键的
// 令牌桶限流。
//
// Over-limit requests are answered with 429 plus Retry-After and the X-RateLimit-Limit,
// X-RateLimit-Remaining and X-RateLimit-Reset headers. A store failure follows FailClosed:
// by default the request is allowed and a warning is logged; with FailClosed it is answered
// with 503. Multi-instance deployments use RedisStore, whose Lua script performs the whole
// read/refill/decide/write cycle atomically against the Redis server clock. | 超限请求返回 429
// 并带上 Retry-After 与 X-RateLimit-Limit、X-RateLimit-Remaining、X-RateLimit-Reset；存储故障
// 遵循 FailClosed：默认放行并记录告警，开启 FailClosed 时返回 503。多实例部署使用 RedisStore，
// 其 Lua 脚本以 Redis 服务器时钟原子完成读取、补充、判定与写回。
//
// Both entry points share the same implementation: RateLimit returns a router.Middleware,
// Middleware returns the native net/http wrapper. | 两个入口共享同一份实现：RateLimit 返回
// router.Middleware，Middleware 返回原生 net/http 包装器。
//
// Typical usage | 典型用法：
//
//	r.Use(ratelimit.RateLimit(ratelimit.RateLimitOptions{Rate: 10, Burst: 20, KeyFunc: ratelimit.KeyRemoteIP(nil)}))
//
//	// plain net/http | 原生 net/http
//	handler := ratelimit.Middleware(o)(mux)
package ratelimit
