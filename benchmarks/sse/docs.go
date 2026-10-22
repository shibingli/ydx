// Package sse contains the SSE benchmarks that live outside the component module, so
// github.com/shibingli/ydx/sse never depends on benchmark-only code. | Package sse
// 保存位于组件模块之外的 SSE 基准，使 github.com/shibingli/ydx/sse 不依赖基准专用代码。
//
// Compared with gin-contrib/sse and a hand-written fmt.Fprintf baseline; see README.md for
// the measured tables. | 对比 gin-contrib/sse 与手写 fmt.Fprintf 基线；实测表见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/sse
//	GOWORK=off go test -run '^$' -bench . -benchmem
package sse
