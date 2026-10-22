// Package base64 contains the Base64 benchmarks that live outside the component
// module, so github.com/shibingli/ydx/base64 never depends on benchmark-only code or
// third-party comparison libraries. | Package base64 保存位于组件模块之外的 Base64
// 基准，使 github.com/shibingli/ydx/base64 不依赖基准专用代码或第三方对比库。
//
// Compared with encoding/base64 and github.com/cristalhq/base64; see README.md for the
// default-build and GOEXPERIMENT=simd result tables. | 对比 encoding/base64 与
// github.com/cristalhq/base64；默认构建与 GOEXPERIMENT=simd 的实测表见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/base64
//	GOWORK=off go test -run '^$' -bench . -benchmem
package base64
