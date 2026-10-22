// Package json contains the JSON benchmarks that live outside the component module,
// so github.com/shibingli/ydx/json never depends on benchmark-only code or comparison
// libraries. | Package json 保存位于组件模块之外的 JSON 基准，使
// github.com/shibingli/ydx/json 不依赖基准专用代码或对比库。
//
// Run with | 运行方式：
//
//	cd benchmarks/json
//	go test -run '^$' -bench . -benchmem
package json
