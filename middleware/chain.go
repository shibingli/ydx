package middleware

import (
	"net/http"

	"github.com/shibingli/ydx/router"
)

// Chain combines middlewares into a single middleware executed in the given order. | Chain
// 把多个中间件按传入顺序组合为一个中间件。
//
// The combined middleware runs each child in turn and finally calls c.Next() exactly once.
// Children must therefore only perform their own work: a child that calls c.Next() itself
// would jump into the router chain early, so such wrapping middlewares belong in router.Use
// directly. nil entries are skipped, and an aborted context stops the sequence. | 组合中间件
// 依次执行每个子中间件，最后统一调用一次 c.Next()。因此子中间件只应完成自身逻辑：子中间件内部
// 调用 c.Next() 会提前进入路由器链，这类「环绕式」中间件请直接用 router.Use 注册。nil 项会被
// 跳过；上下文被 Abort 后立即停止后续执行。
func Chain(mw ...router.Middleware) router.Middleware {
	list := make([]router.Middleware, 0, len(mw))
	for _, m := range mw {
		if m != nil {
			list = append(list, m)
		}
	}
	return func(c *router.Ctx) {
		for _, m := range list {
			if c.Aborted() {
				return
			}
			m(c)
		}
		if c.Aborted() {
			return
		}
		c.Next()
	}
}

// Adapt wraps a plain http.Handler with the YD middleware chain. | Adapt 用 YD 中间件包裹
// 原生 http.Handler。
//
// It is a thin forwarding helper over router.Adapt, kept here so callers that already import
// the aggregate do not need a second import. | 它是对 router.Adapt 的薄转发，放在这里让已经
// 导入聚合门面的调用方无需再导入第二个包。
func Adapt(next http.Handler, mw ...router.Middleware) http.Handler {
	return router.Adapt(next, mw...)
}
