// Package middleware is the aggregate facade of the ydx middleware plugins. | Package
// middleware 是 ydx 中间件插件的聚合门面。
//
// Each plugin lives in its own module — accesslog, asyncafter, compress, cors, ratelimit,
// recovery and requestid — while this package re-exports their public API under the original
// middleware.* names. Existing YD call sites can therefore keep middleware.Recover,
// middleware.CORS and friends while depending only on this module. | 每个插件都在独立模块中
// ——accesslog、asyncafter、compress、cors、ratelimit、recovery 与 requestid——本包以原有的
// middleware.* 名称重新导出它们的公开 API。因此既有 YD 调用点可以继续使用
// middleware.Recover、middleware.CORS 等，而只需依赖本模块。
//
// Chain and Adapt compose middleware for the YD router and plain net/http respectively. |
// Chain 与 Adapt 分别面向 YD 路由与原生 net/http 组合中间件。
//
// Typical usage | 典型用法：
//
//	r.Use(middleware.RequestID(""), middleware.CORS(middleware.CORSOptions{}))
//
//	// plain net/http | 原生 net/http
//	handler := middleware.Adapt(mux,
//		middleware.CORS(middleware.CORSOptions{}),
//		middleware.Compress(middleware.CompressOptions{}),
//	)
package middleware
