//go:build jsonx_v2_bench

package json

import (
	stdjsonv2 "encoding/json/v2"

	jsonx "github.com/shibingli/ydx/json"
)

// The jsonx_v2_bench build tag enables the v2 comparison entries. They require a ydx/json newer
// than the version pinned in go.mod, so they are opt-in: run with a workspace or a local
// replace that points at the working tree. | jsonx_v2_bench 构建标签启用 v2 对比条目。它们需要
// 比 go.mod 固定版本更新的 ydx/json，因此是可选启用：用工作区或指向工作树的本地 replace 运行。
func init() {
	extraMarshalers = append(extraMarshalers,
		benchMarshaler{name: "jsonx-v2", fn: func(v any) ([]byte, error) { return jsonx.Marshal(v, jsonx.DefaultOptionsV2()) }},
		benchMarshaler{name: "stdlib-v2", fn: func(v any) ([]byte, error) { return stdjsonv2.Marshal(v) }},
	)
	extraUnmarshalers = append(extraUnmarshalers,
		benchUnmarshaler{name: "jsonx-v2", fn: func(data []byte, v any) error {
			return jsonx.Unmarshal(data, v, jsonx.DefaultOptionsV2())
		}},
		benchUnmarshaler{name: "stdlib-v2", fn: func(data []byte, v any) error { return stdjsonv2.Unmarshal(data, v) }},
	)
	extraCodecs = append(extraCodecs, frameworkCodec{
		name:      "yd-jsonx-v2",
		marshal:   func(v any) ([]byte, error) { return jsonx.Marshal(v, jsonx.DefaultOptionsV2()) },
		unmarshal: func(data []byte, v any) error { return jsonx.Unmarshal(data, v, jsonx.DefaultOptionsV2()) },
	})
}
