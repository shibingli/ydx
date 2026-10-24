package recovery

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/middleware/requestid"
	"github.com/shibingli/ydx/router"
)

// logRecovered writes the panic record shared by both entry points. | logRecovered 写出两个入口共用的 panic 记录。
func logRecovered(l *log.Logger, requestID, method, path string, rec any) {
	if l == nil {
		return
	}
	l.Error("panic recovered | 捕获到 panic",
		log.Str("request_id", requestID),
		log.Str("method", method),
		log.Str("path", path),
		log.Str("panic", fmt.Sprint(rec)),
		log.Str("stack", string(debug.Stack())),
	)
}

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
			logRecovered(l, requestid.FromContext(c), c.Request.Method, c.Request.URL.Path, rec)
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

// nativeRecover is the direct net/http form of the recovery middleware. Keeping it as a value
// handler (instead of router.Adapt) removes the router context pool, reset and chain walk from
// the no-panic path, which is the common case for every request that does not crash. | nativeRecover
// 是恢复中间件的原生 net/http 形态。把它做成值处理器（而不是 router.Adapt）可从未发生 panic 的
// 常态路径上去掉路由上下文池、reset 与链遍历——对每个不崩溃的请求而言这才是常见路径。
//
// The net/http form cannot observe writes made directly to the underlying ResponseWriter, so a
// panic raised after a response has started appends a 500 (the same behaviour as chi's Recoverer).
// The YD router form keeps the stronger check through Ctx.Written. | 原生形态无法观察到直接写向底层
// ResponseWriter 的内容，因此响应已开始后再 panic 会追加一个 500（与 chi 的 Recoverer 行为一致）。
// YD 路由形态通过 Ctx.Written 保留更强的检查。
type nativeRecover struct {
	next   http.Handler
	logger *log.Logger
}

// ServeHTTP runs the next handler and converts a panic into a logged 500. | ServeHTTP 执行下一个
// 处理器，并把 panic 转换为记录日志的 500。
func (h *nativeRecover) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer h.handlePanic(w, r)
	h.next.ServeHTTP(w, r)
}

// handlePanic is the deferred tail of ServeHTTP. | handlePanic 是 ServeHTTP 的延迟收尾。
func (h *nativeRecover) handlePanic(w http.ResponseWriter, r *http.Request) {
	rec := recover()
	if rec == nil {
		return
	}
	logRecovered(h.logger, "", r.Method, r.URL.Path, rec)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

// Middleware returns the native net/http form of Recover. | Middleware 返回 Recover 的
// 原生 net/http 形态。
//
// Both entry points run the same recovery policy; the native one avoids the router adapter on
// every request. | 两个入口执行同一份恢复策略；原生入口省去了每请求的路由适配器。
func Middleware(l *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if next == nil {
			next = http.NotFoundHandler()
		}
		return &nativeRecover{next: next, logger: l}
	}
}
