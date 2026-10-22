// Package cache contains the two-level cache benchmarks that live outside the component
// module, so github.com/shibingli/ydx/cache never depends on benchmark-only code. |
// Package cache 保存位于组件模块之外的二级缓存基准，使 github.com/shibingli/ydx/cache
// 不依赖基准专用代码。
//
// The local subpackage benchmarks the L1 ring cache. | local 子包测量 L1 环形缓存。
//
// Run with | 运行方式：
//
//	cd benchmarks/cache
//	go test -run '^$' -bench . -benchmem ./...
package cache
