package middleware

import (
	"net/http"

	"github.com/shibingli/ydx/cache"
	"github.com/shibingli/ydx/router"
)

// CacheBypass marks matching requests so infrastructure caches skip reads for the
// whole request. Writes still invalidate. Put it before the authentication
// middleware, otherwise the auth lookup has already read the cache. |
// CacheBypass 标记匹配的请求，使基础设施缓存在整个请求中跳过读取；写入仍然失效。它必须位于
// 鉴权中间件之前，否则鉴权查询已经读过缓存。
//
// A nil match disables the middleware. The middleware replaces the request with
// one carrying the bypass marker; downstream handlers see the new context. | match
// 为 nil 时中间件不生效。它会用携带旁路标记的请求替换原请求，下游处理器看到新的上下文。
func CacheBypass(match func(*http.Request) bool) router.Middleware {
	return func(c *router.Ctx) {
		if match != nil && c != nil && c.Request != nil && match(c.Request) {
			c.Request = c.Request.WithContext(cache.WithBypass(c.Request.Context()))
		}
		c.Next()
	}
}
