// Package json contains the JSON benchmarks that live outside the component module,
// so github.com/shibingli/ydx/json never depends on benchmark-only code or comparison
// libraries. | Package json 保存位于组件模块之外的 JSON 基准，使
// github.com/shibingli/ydx/json 不依赖基准专用代码或对比库。
//
// Compared with encoding/json, encoding/json/v2 (stdlib-v2), the ydx/json v2 entry
// (jsonx-v2), goccy/go-json, json-iterator/go, bytedance/sonic, segmentio/encoding and
// go-json-experiment; see README.md for the measured tables. | 对比 encoding/json、
// encoding/json/v2（stdlib-v2）、ydx/json v2 入口（jsonx-v2）、goccy/go-json、
// json-iterator/go、bytedance/sonic、segmentio/encoding 与 go-json-experiment；实测表见
// README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/json
//	GOWORK=off go test -run '^$' -bench . -benchmem
package json
