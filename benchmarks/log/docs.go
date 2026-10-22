// Package log contains the logging benchmarks that live outside the component module,
// so github.com/shibingli/ydx/log never depends on benchmark-only code or comparison
// libraries. | Package log 保存位于组件模块之外的日志基准，使
// github.com/shibingli/ydx/log 不依赖基准专用代码或对比库。
//
// Compared with zap, zerolog, slog and logrus; see README.md for the measured tables and
// async/slow-writer results. | 对比 zap、zerolog、slog 与 logrus；实测表与异步/慢写入器结果
// 见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/log
//	GOWORK=off go test -run '^$' -bench . -benchmem
package log
