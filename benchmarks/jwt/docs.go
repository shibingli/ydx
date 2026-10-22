// Package jwtbench contains the JWT benchmarks that live outside the component module, so
// github.com/shibingli/ydx/jwt never depends on benchmark-only code or comparison
// libraries. | Package jwtbench 保存位于组件模块之外的 JWT 基准，使
// github.com/shibingli/ydx/jwt 不依赖基准专用代码或对比库。
//
// Run with | 运行方式：
//
//	cd benchmarks/jwt
//	go test -run '^$' -bench . -benchmem
package jwtbench
