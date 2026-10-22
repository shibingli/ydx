// Package render contains the template rendering benchmarks that live outside the
// component module, so github.com/shibingli/ydx/render never depends on benchmark-only code
// beyond its production afero dependency. | Package render 保存位于组件模块之外的模板
// 渲染基准，使 github.com/shibingli/ydx/render 除生产依赖 afero 外不依赖基准专用代码。
//
// Run with | 运行方式：
//
//	cd benchmarks/render
//	go test -run '^$' -bench . -benchmem
package render
