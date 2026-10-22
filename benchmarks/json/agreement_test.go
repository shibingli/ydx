package json

import (
	stdjson "encoding/json"
	"reflect"
	"testing"
)

// TestEncodersAgree proves that every compared encoder emits valid JSON that the standard
// library decodes back to the same value, so the benchmark compares equivalent implementations. |
// TestEncodersAgree 证明每个参与对比的编码器都输出合法 JSON，且标准库能解码回相同值，
// 从而保证基准比较的是等价实现。
func TestEncodersAgree(t *testing.T) {
	values := []struct {
		name string
		in   any
	}{
		{name: "one", in: benchUsers(1)[0]},
		{name: "many", in: benchUsers(64)},
	}
	for _, v := range values {
		for _, enc := range benchMarshalers() {
			t.Run(v.name+"/"+enc.name, func(t *testing.T) {
				out, err := enc.fn(v.in)
				if err != nil {
					t.Fatalf("Marshal: %v", err)
				}
				if !stdjson.Valid(out) {
					t.Fatalf("output is not valid JSON | 输出不是合法 JSON")
				}
				var got any
				if err := stdjson.Unmarshal(out, &got); err != nil {
					t.Fatalf("stdlib Unmarshal: %v", err)
				}
				var want any
				wantBytes, err := stdjson.Marshal(v.in)
				if err != nil {
					t.Fatalf("stdlib Marshal: %v", err)
				}
				if err := stdjson.Unmarshal(wantBytes, &want); err != nil {
					t.Fatalf("stdlib Unmarshal reference: %v", err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("decoded value differs from the reference | 解码值与参照不一致")
				}
			})
		}
	}
}

// TestDecodersAgree proves that every compared decoder recovers the same value from the
// adaptive layer's bytes. | TestDecodersAgree 证明每个参与对比的解码器都能从自适应层的字节中
// 还原出相同的值。
func TestDecodersAgree(t *testing.T) {
	one := benchUsers(1)[0]
	many := benchUsers(64)
	cases := []struct {
		name string
		in   any
		new  func() any
	}{
		{name: "one", in: one, new: func() any { return new(benchUser) }},
		{name: "many", in: many, new: func() any { return new([]benchUser) }},
	}
	for _, c := range cases {
		data, err := stdjson.Marshal(c.in)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		for _, dec := range benchUnmarshalers() {
			t.Run(c.name+"/"+dec.name, func(t *testing.T) {
				got := c.new()
				if err := dec.fn(data, got); err != nil {
					t.Fatalf("Unmarshal: %v", err)
				}
				gotValue := reflect.ValueOf(got).Elem().Interface()
				if !reflect.DeepEqual(gotValue, c.in) {
					t.Fatalf("decoded value differs | 解码值不一致")
				}
			})
		}
	}
}
