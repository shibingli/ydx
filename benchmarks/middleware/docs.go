// Package middleware contains the middleware benchmarks that live outside the component
// modules, so the plugin and aggregate modules never depend on benchmark-only code. |
// Package middleware 保存位于组件模块之外的中间件基准，使插件与聚合模块不依赖基准专用代码。
//
// The benchmarks exercise the aggregate YD middleware API on a real router path and include
// the synchronous/async access-log and compression cases. | 基准在真实路由路径上使用聚合
// YD 中间件 API，并包含同步/异步访问日志与压缩用例。
//
// Compared with rs/cors, chi middleware, klauspost/compress/gzhttp and
// golang.org/x/time/rate; see README.md for the measured tables. | 对比 rs/cors、chi 中间件、
// klauspost/compress/gzhttp 与 golang.org/x/time/rate；实测表见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/middleware
//	GOWORK=off go test -run '^$' -bench . -benchmem
package middleware
