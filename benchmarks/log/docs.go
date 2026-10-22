// Package log contains the logging benchmarks that live outside the component module,
// so github.com/shibingli/ydx/log never depends on benchmark-only code or comparison
// libraries. | Package log 保存位于组件模块之外的日志基准，使
// github.com/shibingli/ydx/log 不依赖基准专用代码或对比库。
//
// Run with | 运行方式：
//
//	cd benchmarks/log
//	go test -run '^$' -bench . -benchmem
package log
