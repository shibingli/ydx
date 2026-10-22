package accesslog

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/middleware/reqlog"
	"github.com/shibingli/ydx/middleware/requestid"
	"github.com/shibingli/ydx/router"
)

// AccessLogOptions configures the access log middleware. | AccessLogOptions 配置访问日志中间件。
//
// It is an alias of the shared reqlog.Options so the synchronous and asynchronous plugins
// accept exactly the same value. | 它是共享 reqlog.Options 的别名，使同步与异步插件接受完全
// 相同的取值。
type AccessLogOptions = reqlog.Options

// AccessLog returns a middleware that logs one record per request. | AccessLog 返回每个请求记录
// 一条日志的中间件。
//
// Recorded fields are method, path, query, status, bytes, remote_ip, duration — milliseconds in
// JSON output — and request_id, which is filled when RequestID runs earlier in the chain. |
// 记录字段包括 method、path、query、status、bytes、remote_ip、duration（JSON 中为毫秒）以及
// request_id（RequestID 位于链上更早位置时才有值）。
// remote_ip comes from ClientIP: it is the peer address unless TrustedProxies says the peer is a
// proxy, so a forged X-Forwarded-For can never choose the logged address. | remote_ip 取自
// ClientIP：除非 TrustedProxies 声明对端是代理，否则它就是对端地址，因此伪造的
// X-Forwarded-For 无法决定日志中的地址。
// Upgrade requests are not wrapped so the WebSocket handshake keeps a usable http.Hijacker. |
// 升级请求不做包装，以保证 WebSocket 握手仍有可用的 http.Hijacker。
// A nil logger turns the middleware into a pass-through. | 日志器为 nil 时该中间件退化为直通。
func AccessLog(l *log.Logger, opts ...AccessLogOptions) router.Middleware {
	var trusted []netip.Prefix
	if len(opts) > 0 {
		trusted = opts[0].TrustedProxies
	}
	return func(c *router.Ctx) {
		if l == nil || reqlog.IsUpgradeRequest(c.Request) {
			c.Next()
			return
		}
		start := time.Now()
		capture := reqlog.Begin(c)

		defer func() {
			rec := recover()
			status := capture.Status()
			if status == 0 {
				status = c.StatusCode()
			}
			if status == 0 {
				if rec != nil {
					// A panic that escaped us becomes a 500 upstream. | 逃逸到上层的 panic 最终会成为 500。
					status = http.StatusInternalServerError
				} else {
					status = http.StatusOK
				}
			}
			bytes := capture.Bytes()
			// Every field has been consumed and the context no longer points at the wrapper,
			// so it can safely serve another request. | 所有字段都已消费，上下文也不再指向
			// 该包装器，因此可以安全地服务下一个请求。
			reqlog.End(c, capture)
			l.Info("access | 访问日志",
				log.Str("request_id", requestid.FromContext(c)),
				log.Str("method", c.Request.Method),
				log.Str("path", c.Request.URL.Path),
				log.Str("query", c.Request.URL.RawQuery),
				log.Int("status", status),
				log.Int64("bytes", bytes),
				log.Str("remote_ip", c.ClientIP(trusted)),
				log.Dur("duration", time.Since(start)),
			)
			if rec != nil {
				// Re-raise instead of swallowing: the request must not continue after a panic,
				// and the outer Recover middleware owns the final response. | 重新抛出而不是吞掉
				// panic：请求不得在 panic 之后继续执行，最终响应由更外层的 Recover 中间件负责。
				panic(rec)
			}
		}()

		c.Next()
	}
}

// Middleware returns the native net/http form of AccessLog. | Middleware 返回 AccessLog 的
// 原生 net/http 形态。
//
// It wraps next with router.Adapt, so the native path shares the exact AccessLog
// implementation and only pays the adapter cost once per request. | 它用 router.Adapt 包裹
// next，因此原生路径共享同一份 AccessLog 实现，每请求只支付一次适配开销。
func Middleware(l *log.Logger, opts ...AccessLogOptions) func(http.Handler) http.Handler {
	mw := AccessLog(l, opts...)
	return func(next http.Handler) http.Handler {
		return router.Adapt(next, mw)
	}
}
