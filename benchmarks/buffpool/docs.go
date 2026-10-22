// Package buffpool contains the buffer-pool benchmarks that live outside the component
// module, so github.com/shibingli/ydx/buffpool never depends on benchmark-only code. |
// Package buffpool 保存位于组件模块之外的缓冲池基准，使
// github.com/shibingli/ydx/buffpool 不依赖基准专用代码。
//
// Run with | 运行方式：
//
//	cd benchmarks/buffpool
//	go test -run '^$' -bench . -benchmem
package buffpool
