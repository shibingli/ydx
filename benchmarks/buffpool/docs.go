// Package buffpool contains the buffer-pool benchmarks that live outside the component
// module, so github.com/shibingli/ydx/buffpool never depends on benchmark-only code. |
// Package buffpool 保存位于组件模块之外的缓冲池基准，使
// github.com/shibingli/ydx/buffpool 不依赖基准专用代码。
//
// Compared with a fair sync.Pool baseline (which also stores *byte) and
// github.com/valyala/bytebufferpool; see README.md for the measured tables and
// the mixed-class parallel scenario. | 对比公平的 sync.Pool 基线（同样存放 *byte）与
// github.com/valyala/bytebufferpool；实测表与混合分级并行场景见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/buffpool
//	GOWORK=off go test -run '^$' -bench . -benchmem
package buffpool
