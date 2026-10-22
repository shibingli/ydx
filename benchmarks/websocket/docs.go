// Package websocketbench contains the WebSocket benchmarks that live outside the component
// module, so github.com/shibingli/ydx/websocket never depends on benchmark-only code. The
// benchmarks use only the public Upgrade/Dial/WriteBatch API over real connections. |
// Package websocketbench 保存位于组件模块之外的 WebSocket 基准，使
// github.com/shibingli/ydx/websocket 不依赖基准专用代码。基准只使用公开的
// Upgrade/Dial/WriteBatch API，并运行在真实连接上。
//
// The frame-level microbenchmarks that used unexported codec internals are intentionally not
// part of this module. | 依赖未导出编解码内部实现的帧级微基准刻意不在此模块中。
//
// Run with | 运行方式：
//
//	cd benchmarks/websocket
//	go test -run '^$' -bench . -benchmem
package websocketbench
