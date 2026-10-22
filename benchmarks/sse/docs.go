// Package ssebench contains the SSE benchmarks that live outside the component module, so
// github.com/shibingli/ydx/sse never depends on benchmark-only code. | Package ssebench
// 保存位于组件模块之外的 SSE 基准，使 github.com/shibingli/ydx/sse 不依赖基准专用代码。
//
// Run with | 运行方式：
//
//	cd benchmarks/sse
//	go test -run '^$' -bench . -benchmem
package ssebench
