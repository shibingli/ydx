// Package base64 contains the Base64 benchmarks that live outside the component
// module, so github.com/shibingli/ydx/base64 never depends on benchmark-only code or
// third-party comparison libraries. | Package base64 保存位于组件模块之外的 Base64
// 基准，使 github.com/shibingli/ydx/base64 不依赖基准专用代码或第三方对比库。
//
// Compared with encoding/base64, github.com/cristalhq/base64 and
// github.com/cloudwego/base64x; see README.md for the reference-host tables and the
// same-machine cloudwego comparison. | 对比 encoding/base64、github.com/cristalhq/base64
// 与 github.com/cloudwego/base64x；参考主机实测表与 cloudwego 同机对照见 README.md。
//
// cloudwego/base64x requests sonic/loader v0.5.1, which aborts on Go 1.27.3; go.mod pins
// v0.5.2 so the JIT path loads. | cloudwego/base64x 请求的 sonic/loader v0.5.1 在
// Go 1.27.3 上会中止进程；go.mod 固定 v0.5.2，使 JIT 路径正常加载。
//
// Run with | 运行方式：
//
//	cd benchmarks/base64
//	GOWORK=off go test -run '^$' -bench . -benchmem
package base64
