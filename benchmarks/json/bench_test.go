package json

import (
	stdjson "encoding/json"
	"testing"

	sonic "github.com/bytedance/sonic"
	expjson "github.com/go-json-experiment/json"
	goccyjson "github.com/goccy/go-json"
	jsoniter "github.com/json-iterator/go"
	segjson "github.com/segmentio/encoding/json"

	jsonx "github.com/shibingli/ydx/json"
)

// benchSinkBytes keeps serialized results observable. | benchSinkBytes 让序列化结果保持可观测。
var benchSinkBytes []byte

// benchUser is the fixed payload shape used by every case. | benchUser 是每个用例共用的固定载荷形态。
type benchUser struct {
	Name   string   `json:"name"`
	Tags   []string `json:"tags"`
	ID     int64    `json:"id"`
	Score  float64  `json:"score"`
	Active bool     `json:"active"`
}

// benchUsers returns n users with repetitive but realistic content. | benchUsers 返回 n 个内容重复但贴近真实的用户。
func benchUsers(n int) []benchUser {
	out := make([]benchUser, n)
	for i := range out {
		out[i] = benchUser{
			ID:     int64(i + 1),
			Name:   "bench-user",
			Active: true,
			Score:  98.5,
			Tags:   []string{"alpha", "beta", "gamma"},
		}
	}
	return out
}

// benchMarshaler names one JSON encoder under comparison. | benchMarshaler 命名一个参与对比的 JSON 编码器。
type benchMarshaler struct {
	name string
	fn   func(any) ([]byte, error)
}

// benchUnmarshaler names one JSON decoder under comparison. | benchUnmarshaler 命名一个参与对比的 JSON 解码器。
type benchUnmarshaler struct {
	name string
	fn   func([]byte, any) error
}

// benchMarshalers returns the encoder set, starting with the adaptive layer and the standard
// library as references. jsoniter uses its standard-library-compatible configuration so every
// entry honours the same struct tags and number semantics. |
// benchMarshalers 返回编码器集合，自适应层与标准库排在最前作为参照。jsoniter 使用与标准库兼容
// 的配置，使每个实现遵循相同的结构体标签与数值语义。
func benchMarshalers() []benchMarshaler {
	return []benchMarshaler{
		{name: "jsonx", fn: jsonx.Marshal},
		{name: "stdlib", fn: stdjson.Marshal},
		{name: "goccy", fn: goccyjson.Marshal},
		{name: "jsoniter", fn: jsoniter.ConfigCompatibleWithStandardLibrary.Marshal},
		{name: "sonic", fn: sonic.Marshal},
		{name: "segmentio", fn: segjson.Marshal},
		{name: "go-json-v2", fn: func(v any) ([]byte, error) { return expjson.Marshal(v) }},
	}
}

// benchUnmarshalers returns the decoder set in the same order. | benchUnmarshalers 按相同顺序返回解码器集合。
func benchUnmarshalers() []benchUnmarshaler {
	return []benchUnmarshaler{
		{name: "jsonx", fn: jsonx.Unmarshal},
		{name: "stdlib", fn: stdjson.Unmarshal},
		{name: "goccy", fn: goccyjson.Unmarshal},
		{name: "jsoniter", fn: jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal},
		{name: "sonic", fn: sonic.Unmarshal},
		{name: "segmentio", fn: segjson.Unmarshal},
		{name: "go-json-v2", fn: func(data []byte, v any) error { return expjson.Unmarshal(data, v) }},
	}
}

// BenchmarkMarshal compares every encoder on the same single-object and 64-object payloads.
// Each sub-benchmark performs one warm-up call outside the timed region so first-call caches and
// sonic's runtime code generation do not distort the steady-state number. |
// BenchmarkMarshal 在相同的单对象与 64 对象载荷上对比所有编码器。每个子基准在计时区外先做一次
// 预热调用，避免首次调用的缓存与 sonic 的运行时代码生成污染稳态数字。
func BenchmarkMarshal(b *testing.B) {
	cases := []struct {
		name string
		v    any
	}{
		{name: "one", v: benchUsers(1)[0]},
		{name: "many", v: benchUsers(64)},
		{name: "large", v: benchUsers(1024)},
	}
	for _, c := range cases {
		for _, enc := range benchMarshalers() {
			b.Run(c.name+"/"+enc.name, func(b *testing.B) {
				if _, err := enc.fn(c.v); err != nil {
					b.Fatalf("warm-up failed | 预热失败: %v", err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					out, err := enc.fn(c.v)
					if err != nil {
						b.Fatalf("Marshal failed | Marshal 失败: %v", err)
					}
					benchSinkBytes = out
				}
			})
		}
	}
}

// BenchmarkUnmarshal compares every decoder into a fresh value. The input is produced by the
// adaptive layer once, so all decoders parse identical bytes. |
// BenchmarkUnmarshal 对比所有解码器解码到新值。输入由自适应层一次性生成，使所有解码器解析完全相同的字节。
func BenchmarkUnmarshal(b *testing.B) {
	small := benchUsers(1)[0]
	many := benchUsers(64)
	large := benchUsers(1024)
	smallJSON, err := jsonx.Marshal(small)
	if err != nil {
		b.Fatalf("setup failed | 准备失败: %v", err)
	}
	manyJSON, err := jsonx.Marshal(many)
	if err != nil {
		b.Fatalf("setup failed | 准备失败: %v", err)
	}
	largeJSON, err := jsonx.Marshal(large)
	if err != nil {
		b.Fatalf("setup failed | 准备失败: %v", err)
	}

	cases := []struct {
		name string
		in   []byte
		new  func() any
	}{
		{name: "one", in: smallJSON, new: func() any { return new(benchUser) }},
		{name: "many", in: manyJSON, new: func() any { return new([]benchUser) }},
		{name: "large", in: largeJSON, new: func() any { return new([]benchUser) }},
	}
	for _, c := range cases {
		for _, dec := range benchUnmarshalers() {
			b.Run(c.name+"/"+dec.name, func(b *testing.B) {
				if err := dec.fn(c.in, c.new()); err != nil {
					b.Fatalf("warm-up failed | 预热失败: %v", err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := dec.fn(c.in, c.new()); err != nil {
						b.Fatalf("Unmarshal failed | Unmarshal 失败: %v", err)
					}
				}
			})
		}
	}
}
