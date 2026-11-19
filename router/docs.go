// Package router provides a self-developed high-performance radix tree (Radix Tree) router.
// | Package router 提供自研的高性能基数树（Radix Tree）路由。
//
// Besides the usual static and parameter segments, this router natively supports mixed
// static/dynamic matching within a single segment, that is, it allows literals and dynamic
// captures to be mixed inside the same path segment separated by "/": | 除常规静态段与参数段外，
// 本路由原生支持单段内的混合静态/动态匹配，即允许在非 "/" 分隔的同一路径段内混合字面量与动态捕获：
//
//	/avatar/:id.jpg        capture id, requiring the .jpg suffix | 捕获 id，且必须以 .jpg 结尾
//	/report/:id-xx.png     capture id, stripping the -xx.png suffix | 捕获 id，剥离静态后缀 -xx.png
//	/archive/:y-:m-:d.html capture three parameters in one segment | 单段内捕获三个参数
//	/static/*filepath      wildcard tail, capturing everything including "/" | 末段通配，捕获含 "/" 的剩余全部内容
//
// Special characters in literals can be escaped with a backslash (`\:`, `\*`, `\\`). | 字面量中的
// 特殊字符可用反斜杠转义（`\:`、`\*`、`\\`）。
//
// Router implements http.Handler. Adapt additionally lets the same middleware run around a
// plain net/http handler without going through the router's route table: | Router 实现
// http.Handler。Adapt 还可让同一套中间件包裹原生 net/http 处理器，而不经过路由表：
//
//	r := router.New()
//	r.Use(cors.CORS(o))
//
//	native := router.Adapt(mux, cors.CORS(o))
//
// Static assets and single-page applications use the same dual entry. SPA history mode is
// registered as a router-wide fallback: registered routes always win, unmatched page-like
// GET/HEAD requests receive the index document, and /api-style prefixes stay with the backend: |
// 静态资源与单页应用同样具备双入口。SPA 的 history 模式注册为路由器级兜底：已注册路由始终优先，
// 未命中且形如页面的 GET/HEAD 请求得到入口文档，/api 这类前缀保留给后端：
//
//	r.SPA("/", "dist", router.WithSPAExclude("/api"))
//
//	native := router.NewSPAHandler(afs.NewOS("dist"), router.WithSPAExclude("/api"))
package router
