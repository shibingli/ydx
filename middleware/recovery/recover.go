package recovery

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/middleware/requestid"
	"github.com/shibingli/ydx/router"
)

// Recover returns a middleware that catches panics raised by downstream handlers. | Recover 返回捕获下游处理器 panic 的中间件。
// The panic value and the goroutine stack are logged through l, which may be nil. | panic 值与 goroutine 调用栈经 l 记录，l 可为 nil。
// The remaining chain is aborted and a bare 500 response is written. | 随后终止链上剩余处理器，并写出一个不含内部细节的 500 响应。
// When the response header has already been written the 500 is skipped, so a response that
// already started stays consistent. | 若响应头已写出则跳过 500，保证已经开始输出的响应不被破坏。
func Recover(l *log.Logger) router.Middleware {
	return func(c *router.Ctx) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if l != nil {
				l.Error("panic recovered | 捕获到 panic",
					log.Str("request_id", requestid.FromContext(c)),
					log.Str("method", c.Request.Method),
					log.Str("path", c.Request.URL.Path),
					log.Str("panic", fmt.Sprint(rec)),
					log.Str("stack", string(debug.Stack())),
				)
			}
			// Stop the remaining handlers so a recovered panic cannot resume the chain. | 终止剩余处理器，避免恢复之后又继续执行链上内容。
			c.Abort()
			if c.Written() {
				return
			}
			_ = c.String(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		}()
		c.Next()
	}
}

// Middleware returns the native net/http form of Recover. | Middleware 返回 Recover 的
// 原生 net/http 形态。
//
// It wraps next with router.Adapt, so the native path shares the exact panic-recovery
// implementation and only pays the adapter cost once per request. | 它用 router.Adapt 包裹
// next，因此原生路径共享同一份 panic 恢复实现，每请求只支付一次适配开销。
func Middleware(l *log.Logger) func(http.Handler) http.Handler {
	mw := Recover(l)
	return func(next http.Handler) http.Handler {
		return router.Adapt(next, mw)
	}
}
