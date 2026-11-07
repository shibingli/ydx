package json

import (
	stdjsonv2 "encoding/json/v2"

	jsonx "github.com/shibingli/ydx/json"
)

// The v2 comparison entries are part of the default set now that go.mod requires ydx/json
// v0.1.16. | 由于 go.mod 已要求 ydx/json v0.1.16，v2 对比条目属于默认集合。
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
