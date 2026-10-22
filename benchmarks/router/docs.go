// Package routerbench contains the router benchmarks that live outside the component module,
// so github.com/shibingli/ydx/router never depends on benchmark-only code. | Package routerbench
// 保存位于组件模块之外的路由基准，使 github.com/shibingli/ydx/router 不依赖基准专用代码。
//
// The isolated matcher microbenchmarks that used unexported routePattern internals are not
// part of this module; the public router and Adapt benchmarks cover the same hot path. |
// 依赖未导出 routePattern 内部实现的独立匹配器微基准不在此模块中；公开的路由与 Adapt 基准
// 覆盖同一条热路径。
//
// Run with | 运行方式：
//
//	cd benchmarks/router
//	go test -run '^$' -bench . -benchmem
package routerbench
