//go:build !jsonx_std

package json

import (
	stdjson "encoding/json"
	"math"
	"math/rand"
	"reflect"
	"strconv"
	"testing"
)

// TestParseShortDecimalFloat verifies the fast decimal parser is bit-identical to
// strconv.ParseFloat for every short form it accepts, including rounding boundaries. |
// TestParseShortDecimalFloat 验证快速十进制解析器对所有接受的短形式与 strconv.ParseFloat 位级一致，
// 包括舍入边界。
func TestParseShortDecimalFloat(t *testing.T) {
	cases := []string{
		"0", "-0", "0.0", "-0.0", "1", "-1", "1.5", "-1.5", "0.1", "-0.1",
		"98.5", "2.675", "1.005", "123456789012345", "123456789012345.6",
		"0.000001", "0.0000000000000001", "9007199254740991",
		"3.14159265358979", "2.71828182845904", "1.79769313486231",
	}
	for _, s := range cases {
		got, ok := parseShortDecimalFloat([]byte(s))
		if !ok {
			t.Fatalf("parseShortDecimalFloat(%q) rejected a short literal | 拒绝了短字面量", s)
		}
		want, err := strconv.ParseFloat(s, 64)
		if err != nil {
			t.Fatalf("strconv.ParseFloat(%q) failed | 失败: %v", s, err)
		}
		if math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("parseShortDecimalFloat(%q) = %v (%016x), want %v (%016x)",
				s, got, math.Float64bits(got), want, math.Float64bits(want))
		}
	}

	// Long and exponent forms must be rejected so the caller falls back to strconv. | 过长与带指数的
	// 形式必须被拒绝，使调用方回退到 strconv。
	for _, s := range []string{"", "-", ".", "1.", ".5", "1e5", "12345678901234567", "0.30000000000000004", "4503599627370497.5", "12.34.56"} {
		if _, ok := parseShortDecimalFloat([]byte(s)); ok {
			t.Fatalf("parseShortDecimalFloat(%q) should be rejected | 应被拒绝", s)
		}
	}

	// Deterministic random decimals with a 15-digit mantissa. | 使用 15 位尾数的确定性随机小数。
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		mant := rng.Int63n(9e14) + 1e14
		digits := strconv.FormatInt(mant, 10)
		point := rng.Intn(len(digits)-1) + 1
		s := digits[:point] + "." + digits[point:]
		if rng.Intn(2) == 0 {
			s = "-" + s
		}
		got, ok := parseShortDecimalFloat([]byte(s))
		if !ok {
			t.Fatalf("parseShortDecimalFloat(%q) rejected | 拒绝", s)
		}
		want, err := strconv.ParseFloat(s, 64)
		if err != nil {
			t.Fatalf("strconv.ParseFloat(%q) failed | 失败: %v", s, err)
		}
		if math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("parseShortDecimalFloat(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestUnmarshalStructSliceFastPath verifies the direct-memory []struct decoder across array
// lengths, preallocated destinations and error-free edge cases. | TestUnmarshalStructSliceFastPath
// 验证直接按内存解码的 []struct 解码器在多种数组长度、预分配目标与无错误边界情况下的行为。
func TestUnmarshalStructSliceFastPath(t *testing.T) {
	type item struct {
		Name   string   `json:"name"`
		Tags   []string `json:"tags"`
		ID     int64    `json:"id"`
		Score  float64  `json:"score"`
		Active bool     `json:"active"`
	}
	if info := fastStructDecFor(reflect.TypeOf(item{})); info == nil {
		t.Fatal("fast struct decoder is unavailable for the fixture | 测试载荷没有可用的快速结构体解码器")
	}
	makeJSON := func(n int) []byte {
		var b []byte
		b = append(b, '[')
		for i := 0; i < n; i++ {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, `{"name":"n","tags":["a","b"],"id":1,"score":98.5,"active":true}`...)
		}
		b = append(b, ']')
		return b
	}
	for _, n := range []int{0, 1, 2, 3, 4, 5, 8, 9, 17, 100} {
		in := makeJSON(n)
		var got []item
		if err := Unmarshal(in, &got); err != nil {
			t.Fatalf("Unmarshal(%d) failed | 失败: %v", n, err)
		}
		var want []item
		if err := stdjson.Unmarshal(in, &want); err != nil {
			t.Fatalf("encoding/json Unmarshal(%d) failed | 失败: %v", n, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("length %d mismatch\n got: %#v\nwant: %#v", n, got, want)
		}

		// Reuse a destination with spare capacity and stale contents. | 复用带多余容量和旧内容的
		// 目标切片。
		reuse := make([]item, 3, 32)
		reuse[0].Name = "stale"
		if err := Unmarshal(in, &reuse); err != nil {
			t.Fatalf("Unmarshal reuse(%d) failed | 失败: %v", n, err)
		}
		if !reflect.DeepEqual(reuse, want) {
			t.Fatalf("length %d reuse mismatch\n got: %#v\nwant: %#v", n, reuse, want)
		}
	}

	// null and empty arrays keep their encoding/json semantics. | null 与空数组保持
	// encoding/json 的语义。
	for _, tc := range []struct {
		in   string
		nil  bool
		zero bool
	}{
		{in: "null", nil: true},
		{in: "[]", zero: true},
	} {
		var got []item
		if err := Unmarshal([]byte(tc.in), &got); err != nil {
			t.Fatalf("Unmarshal(%q) failed | 失败: %v", tc.in, err)
		}
		var want []item
		if err := stdjson.Unmarshal([]byte(tc.in), &want); err != nil {
			t.Fatalf("encoding/json Unmarshal(%q) failed | 失败: %v", tc.in, err)
		}
		if (got == nil) != tc.nil || tc.zero && (got == nil || len(got) != 0) {
			t.Fatalf("Unmarshal(%q) = %#v (nil=%v), want nil=%v", tc.in, got, got == nil, tc.nil)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Unmarshal(%q) mismatch: got %#v, want %#v", tc.in, got, want)
		}
	}
}

// TestFastStructDecRejectsCustomUnmarshaler keeps the direct-memory slice decoder from bypassing
// pointer-receiver UnmarshalJSON methods. | TestFastStructDecRejectsCustomUnmarshaler 防止直接按内存
// 解码的切片解码器绕过指针接收者的 UnmarshalJSON 方法。
func TestFastStructDecRejectsCustomUnmarshaler(t *testing.T) {
	if fastStructDecFor(reflect.TypeOf(customDecodeItem{})) != nil {
		t.Fatal("custom Unmarshaler must not use the fast struct decoder | 自定义 Unmarshaler 不得使用快速结构体解码器")
	}
	var got []customDecodeItem
	if err := Unmarshal([]byte(`[{"value":"x"}]`), &got); err != nil {
		t.Fatalf("Unmarshal failed | 失败: %v", err)
	}
	if len(got) != 1 || got[0].Value != "decoded:x" {
		t.Fatalf("custom Unmarshaler was not called: %#v", got)
	}
	var one customDecodeItem
	if err := Unmarshal([]byte(`{"value":"x"}`), &one); err != nil {
		t.Fatalf("Unmarshal single failed | 单值 Unmarshal 失败: %v", err)
	}
	if one.Value != "decoded:x" {
		t.Fatalf("top-level custom Unmarshaler was not called: %#v", one)
	}
}

// customDecodeItem implements UnmarshalJSON on the pointer receiver. | customDecodeItem 在指针接收者上
// 实现 UnmarshalJSON。
type customDecodeItem struct {
	Value string `json:"value"`
}

func (c *customDecodeItem) UnmarshalJSON(b []byte) error {
	var v struct {
		Value string `json:"value"`
	}
	if err := stdjson.Unmarshal(b, &v); err != nil {
		return err
	}
	c.Value = "decoded:" + v.Value
	return nil
}

// TestUnmarshalFloat64FieldFastPath compares the fused field scanner with encoding/json across
// valid, exponent, oversized and malformed literals, containers and delimiters. |
// TestUnmarshalFloat64FieldFastPath 在合法、指数、超大与畸形字面量、容器与分隔符上对比融合字段扫描器
// 与 encoding/json。
func TestUnmarshalFloat64FieldFastPath(t *testing.T) {
	type box struct {
		F float64 `json:"f"`
	}
	literals := []string{
		"0", "-0", "0.0", "-0.0", "98.5", "-1.5", "0.1", "123456789012345.6",
		"0.0000000000000001", "1e5", "-2.5e-3", "9007199254740993", "01", "1.", ".5", "1x",
	}
	for _, lit := range literals {
		in := []byte(`{"f":` + lit + `}`)
		var got box
		gotErr := Unmarshal(in, &got)
		var want box
		wantErr := stdjson.Unmarshal(in, &want)
		if (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("literal %q: error mismatch: jsonx=%v encoding/json=%v", lit, gotErr, wantErr)
		}
		if gotErr == nil && math.Float64bits(got.F) != math.Float64bits(want.F) {
			t.Fatalf("literal %q: got %v, want %v", lit, got.F, want.F)
		}
	}
	inputs := []string{`[98.5, 1, -2.5]`, `98.5`, `{"f": 98.5 }`}
	for _, in := range inputs {
		var gotF float64
		var wantF float64
		if in[0] == '[' {
			var got, want []float64
			if err := Unmarshal([]byte(in), &got); err != nil {
				t.Fatalf("Unmarshal(%q) failed | 失败: %v", in, err)
			}
			if err := stdjson.Unmarshal([]byte(in), &want); err != nil {
				t.Fatalf("encoding/json Unmarshal(%q) failed | 失败: %v", in, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Unmarshal(%q) = %v, want %v", in, got, want)
			}
			continue
		}
		got := &gotF
		want := &wantF
		if in[0] == '{' {
			var gb, wb box
			if err := Unmarshal([]byte(in), &gb); err != nil {
				t.Fatalf("Unmarshal(%q) failed | 失败: %v", in, err)
			}
			if err := stdjson.Unmarshal([]byte(in), &wb); err != nil {
				t.Fatalf("encoding/json Unmarshal(%q) failed | 失败: %v", in, err)
			}
			if math.Float64bits(gb.F) != math.Float64bits(wb.F) {
				t.Fatalf("Unmarshal(%q) = %v, want %v", in, gb.F, wb.F)
			}
			continue
		}
		if err := Unmarshal([]byte(in), got); err != nil {
			t.Fatalf("Unmarshal(%q) failed | 失败: %v", in, err)
		}
		if err := stdjson.Unmarshal([]byte(in), want); err != nil {
			t.Fatalf("encoding/json Unmarshal(%q) failed | 失败: %v", in, err)
		}
		if math.Float64bits(*got) != math.Float64bits(*want) {
			t.Fatalf("Unmarshal(%q) = %v, want %v", in, *got, *want)
		}
	}
}

// TestUnmarshalFloatUsesShortDecimalPath verifies the decoder wiring for float64 fields and
// interface values. | TestUnmarshalFloatUsesShortDecimalPath 验证 float64 字段与接口值的解码接线。
func TestUnmarshalFloatUsesShortDecimalPath(t *testing.T) {
	var obj struct {
		F float64 `json:"f"`
		G any     `json:"g"`
	}
	if err := Unmarshal([]byte(`{"f":98.5,"g":-2.675}`), &obj); err != nil {
		t.Fatalf("Unmarshal failed | Unmarshal 失败: %v", err)
	}
	if obj.F != 98.5 {
		t.Fatalf("F = %v, want 98.5", obj.F)
	}
	if g, ok := obj.G.(float64); !ok || math.Float64bits(g) != math.Float64bits(-2.675) {
		t.Fatalf("G = %#v, want -2.675", obj.G)
	}
}
