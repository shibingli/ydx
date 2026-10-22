// Package json contains the JSON benchmarks that live outside the component module,
// so github.com/shibingli/ydx/json never depends on benchmark-only code or comparison
// libraries. | Package json 保存位于组件模块之外的 JSON 基准，使
// github.com/shibingli/ydx/json 不依赖基准专用代码或对比库。
//
// Compared with encoding/json, goccy/go-json, json-iterator/go, bytedance/sonic and
// segmentio/encoding; see README.md for the measured tables. | 对比 encoding/json、
// goccy/go-json、json-iterator/go、bytedance/sonic 与 segmentio/encoding；实测表见
// README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/json
//	GOWORK=off go test -run '^$' -bench . -benchmem
package json
