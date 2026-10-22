package router

import (
	"net/http"
	"sync"
)

// adaptPool recycles the Ctx used by Adapt. The pool is separate from a
// Router's pool because an adapted chain has no route table or renderer. |
// adaptPool 复用 Adapt 使用的 Ctx。它与 Router 的对象池分开，因为适配链没有
// 路由表与渲染器。
var adaptPool = sync.Pool{New: func() any { return new(Ctx) }}

// Adapt runs the YD middleware chain around a plain net/http handler. | Adapt 让
// YD 中间件链包裹原生 net/http 处理器。
//
// The returned handler is the bridge for projects that use net/http directly:
// each request borrows a Ctx from a private pool, installs mw as the chain and
// calls the terminal handler through c.Writer/c.Request. The original response
// writer is passed through untouched, so http.Hijacker, http.Flusher and
// http.ResponseController keep working. | 返回的处理器是给直接使用 net/http 的项目
// 准备的桥梁：每个请求从私有池借一个 Ctx，把 mw 作为链安装进去，并通过
// c.Writer/c.Request 调用终止处理器。原始响应写入器原样透传，因此 http.Hijacker、
// http.Flusher 与 http.ResponseController 仍然可用。
//
// Adapt is not used by Router.ServeHTTP; YD's own routing path keeps its zero
// adapter overhead. Ctx.Router returns nil inside an adapted chain, so only
// middleware that does not depend on the router itself should be used here. |
// Router.ServeHTTP 不经过 Adapt，YD 自身路由路径保持零适配开销。适配链中的
// Ctx.Router 返回 nil，因此这里只应使用不依赖路由器本身的中间件。
//
// A nil next is treated as http.NotFound. A panic is forwarded after the Ctx is
// cleaned and returned to the pool, so the next request never observes state
// from the failed one. | next 为 nil 时按 http.NotFound 处理。panic 会在 Ctx 清理
// 并归还池之后原样转发，因此下一个请求绝不会观察到失败请求的状态。
func Adapt(next http.Handler, mw ...Middleware) http.Handler {
	if next == nil {
		next = http.HandlerFunc(http.NotFound)
	}
	chain := make([]HandlerFunc, 0, len(mw)+1)
	for _, m := range mw {
		if m != nil {
			chain = append(chain, m)
		}
	}
	chain = append(chain, func(c *Ctx) {
		next.ServeHTTP(c.Writer, c.Request)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := adaptPool.Get().(*Ctx)
		c.reset(w, r)
		// The chain is immutable and shared by every request; ctxBorrowed tells
		// reset not to append through (or reslice) it. | 链不可变且被所有请求共享；
		// ctxBorrowed 让 reset 不通过它 append，也不重新切片。
		c.handlers = chain
		c.flags |= ctxBorrowed
		c.index = -1
		defer func() {
			rec := recover()
			c.reset(nil, nil)
			adaptPool.Put(c)
			if rec != nil {
				panic(rec)
			}
		}()
		c.Next()
	})
}
