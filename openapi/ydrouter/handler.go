package ydrouter

import (
	"net/http"

	"github.com/shibingli/ydx/openapi"
	"github.com/shibingli/ydx/router"
)

// Handler returns the router handler serving the JSON document, the built-in viewer and the
// embedded viewer assets. | Handler 返回提供 JSON 文档、内置查看器与内嵌查看器资源的路由处理器。
//
// Mount the same handler on every configured endpoint: | 请把同一个处理器挂载到全部配置端点上：
//
//	h := ydrouter.Handler(doc, opts)
//	r.GET(opts.Path, h)
//	r.GET(opts.DocsPath, h)
//	r.GET(opts.AssetsPath+"*filepath", h)
//
// The adapter only translates the router context into a standard http.ResponseWriter; all
// serving semantics, including the strong ETag and Options.Blocked, come from
// openapi.HTTPHandler. | 适配器只把路由上下文转换为标准 http.ResponseWriter；包括强 ETag 与
// Options.Blocked 在内的全部服务语义都来自 openapi.HTTPHandler。
func Handler(d *openapi.Document, o openapi.Options) router.HandlerFunc {
	h := openapi.HTTPHandler(d, o)
	return func(c *router.Ctx) {
		h.ServeHTTP(ctxResponseWriter{c: c}, c.Request)
	}
}

// ctxResponseWriter adapts a router context to http.ResponseWriter while keeping the router's
// status bookkeeping intact. | ctxResponseWriter 把路由上下文适配为 http.ResponseWriter，同时保留
// 路由的状态记录。
//
// Header goes straight to the underlying writer; WriteHeader goes through Ctx.WriteHeader so
// access logs and the router's written flag observe the final status. | Header 直接写入底层
// 响应；WriteHeader 经过 Ctx.WriteHeader，使访问日志与路由的「已写出」标记看到最终状态。
type ctxResponseWriter struct {
	c *router.Ctx
}

// Header implements http.ResponseWriter. | Header 实现 http.ResponseWriter。
func (w ctxResponseWriter) Header() http.Header { return w.c.Writer.Header() }

// Write implements http.ResponseWriter. | Write 实现 http.ResponseWriter。
func (w ctxResponseWriter) Write(p []byte) (int, error) { return w.c.Writer.Write(p) }

// WriteHeader implements http.ResponseWriter. | WriteHeader 实现 http.ResponseWriter。
func (w ctxResponseWriter) WriteHeader(code int) { w.c.WriteHeader(code) }
