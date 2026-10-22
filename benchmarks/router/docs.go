// Package router contains the router benchmarks that live outside the component module,
// so github.com/shibingli/ydx/router never depends on benchmark-only code. | Package router
// 保存位于组件模块之外的路由基准，使 github.com/shibingli/ydx/router 不依赖基准专用代码。
//
// The isolated matcher microbenchmarks that used unexported routePattern internals are not
// part of this module; the public router and Adapt benchmarks cover the same hot path. |
// 依赖未导出 routePattern 内部实现的独立匹配器微基准不在此模块中；公开的路由与 Adapt 基准
// 覆盖同一条热路径。
//
// Compared with net/http.ServeMux, httprouter, chi and gin; see README.md for the measured
// tables. | 对比 net/http.ServeMux、httprouter、chi 与 gin；实测表见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/router
//	GOWORK=off go test -run '^$' -bench . -benchmem
package router
