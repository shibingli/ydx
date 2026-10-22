// Package buffpool contains the buffer-pool benchmarks that live outside the component
// module, so github.com/shibingli/ydx/buffpool never depends on benchmark-only code. |
// Package buffpool 保存位于组件模块之外的缓冲池基准，使
// github.com/shibingli/ydx/buffpool 不依赖基准专用代码。
//
// Compared with sync.Pool and github.com/valyala/bytebufferpool; see README.md for the
// measured tables. | 对比 sync.Pool 与 github.com/valyala/bytebufferpool；实测表见
// README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/buffpool
//	GOWORK=off go test -run '^$' -bench . -benchmem
package buffpool
