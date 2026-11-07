package json_test

import (
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"
	"errors"
	"reflect"
	"testing"
	"time"

	jsonx "github.com/shibingli/ydx/json"
)

// v2MarshalPair marshals v with this package and the standard library using identical options
// and returns both results. | v2MarshalPair 用相同选项分别经本包与标准库编码 v，返回两个结果。
func v2MarshalPair(t *testing.T, v any, opts ...jsonx.Options) ([]byte, []byte) {
	t.Helper()
	got, gotErr := jsonx.Marshal(v, opts...)
	want, wantErr := stdjsonv2.Marshal(v, opts...)
	if (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("Marshal(%T) error mismatch: ydx=%v stdlib=%v | 错误不一致", v, gotErr, wantErr)
	}
	if gotErr != nil {
		// The standard library may return partial output on failure; only error presence is
		// comparable there. | 标准库失败时可能返回部分输出；错误路径只比较错误是否存在。
		return nil, nil
	}
	return got, want
}

// v2Defaults are the options every default-semantics case passes explicitly. The bare ydx call
// keeps v1 semantics for compatibility, so v2 behavior is requested with DefaultOptionsV2. |
// v2Defaults 是每个默认语义用例显式传入的选项。裸调用保持 v1 兼容语义，因此 v2 行为通过
// DefaultOptionsV2 请求。
func v2Defaults() []jsonx.Options { return []jsonx.Options{jsonx.DefaultOptionsV2()} }

// TestV2MarshalScalarsAndContainers compares v2 encoding of scalars and nil-able containers. |
// TestV2MarshalScalarsAndContainers 对比标量与可空容器的 v2 编码。
func TestV2MarshalScalarsAndContainers(t *testing.T) {
	cases := []any{
		nil,
		true,
		false,
		int64(0),
		int64(-42),
		uint64(42),
		float64(1.5),
		"plain",
		"<a&b>",
		"  ",
		"é😀",
		[]int(nil),
		[]int{},
		[]int{1, 2},
		map[string]int(nil),
		map[string]int{},
		[3]byte{1, 2, 3},
		[]byte{1, 2, 3},
		[]byte(nil),
		(*int)(nil),
	}
	for _, v := range cases {
		got, want := v2MarshalPair(t, v, v2Defaults()...)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Marshal(%T %v) = %s want %s | 编码不一致", v, v, got, want)
		}
	}
}

// v2Tagged covers ordinary tags, omitempty and omitzero. | v2Tagged 覆盖普通标签、omitempty 与
// omitzero。
type v2Tagged struct {
	Name   string         `json:"name"`
	Empty  string         `json:"empty,omitempty"`
	Zero   int            `json:"zero,omitempty"`
	Flag   bool           `json:"flag,omitempty"`
	Slice  []int          `json:"slice,omitempty"`
	Map    map[string]int `json:"map,omitempty"`
	Ptr    *int           `json:"ptr,omitempty"`
	Struct struct{}       `json:"st,omitempty"`
	Omit   int            `json:"omit,omitzero"`
}

// TestV2MarshalStructSemantics compares struct tag semantics under v2 defaults. |
// TestV2MarshalStructSemantics 对比 v2 默认下的结构体标签语义。
func TestV2MarshalStructSemantics(t *testing.T) {
	values := []any{
		v2Tagged{},
		v2Tagged{Name: "x", Zero: 3, Flag: true, Slice: []int{}, Map: map[string]int{}},
	}
	for _, useOpts := range [][]jsonx.Options{
		v2Defaults(),
		{jsonx.DefaultOptionsV2(), jsonx.OmitZeroStructFields(true)},
		{jsonx.DefaultOptionsV2(), jsonx.JoinOptions(jsonx.DefaultOptionsV1(), jsonx.DefaultOptionsV2())},
	} {
		for _, v := range values {
			got, want := v2MarshalPair(t, v, useOpts...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("opts=%v Marshal(%+v) = %s want %s | 编码不一致", useOpts, v, got, want)
			}
		}
	}
}

// TestV2MarshalOptionToggles compares the option-driven formatting switches. |
// TestV2MarshalOptionToggles 对比选项驱动的格式开关。
func TestV2MarshalOptionToggles(t *testing.T) {
	nilSlice := []int(nil)
	nilMap := map[string]int(nil)
	type dur struct {
		D time.Duration `json:"d"`
	}
	cases := []struct {
		name string
		v    any
		opts []jsonx.Options
	}{
		{"nil-slice-null", nilSlice, []jsonx.Options{jsonx.FormatNilSliceAsNull(true)}},
		{"nil-map-null", nilMap, []jsonx.Options{jsonx.FormatNilMapAsNull(true)}},
		{"html-escape", "<a&b>", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.EscapeForHTML(true))}},
		{"js-escape", "  ", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.EscapeForJS(true))}},
		{"byte-array-array", [3]byte{1, 2, 3}, []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.FormatByteArrayAsArray(true))}},
		{"duration-nano", dur{D: 1500 * time.Millisecond}, []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.FormatDurationAsNano(true))}},
		{"duration-default", dur{D: 1500 * time.Millisecond}, v2Defaults()},
		{"stringify", struct{ N int }{N: 42}, []jsonx.Options{jsonx.StringifyNumbers(true)}},
		{"indent", map[string]int{"a": 1}, []jsonx.Options{jsontext.WithIndent("  ")}},
		{"multiline", []int{1, 2}, []jsonx.Options{jsontext.Multiline(true)}},
		{"space-both", map[string]int{"a": 1}, []jsonx.Options{jsontext.SpaceAfterColon(true), jsontext.SpaceAfterComma(true)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, want := v2MarshalPair(t, c.v, c.opts...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Marshal(%T) = %q want %q | 编码不一致", c.v, got, want)
			}
			if _, wantErr := stdjsonv2.Marshal(c.v, c.opts...); wantErr != nil {
				_, gotErr := jsonx.Marshal(c.v, c.opts...)
				if gotErr == nil {
					t.Errorf("expected error %v | 期望错误", wantErr)
				}
			}
		})
	}
}

// v2Marshaler implements the legacy MarshalJSON method. | v2Marshaler 实现旧版 MarshalJSON 方法。
type v2Marshaler struct{ V string }

func (m v2Marshaler) MarshalJSON() ([]byte, error) { return []byte(`{"custom":"` + m.V + `"}`), nil }

// v2MarshalerTo implements MarshalJSONTo. | v2MarshalerTo 实现 MarshalJSONTo。
type v2MarshalerTo struct{ V string }

func (m v2MarshalerTo) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(m.V))
}

// TestV2MarshalMethods compares custom marshal method dispatch. | TestV2MarshalMethods 对比自定义
// 编码方法的分派。
func TestV2MarshalMethods(t *testing.T) {
	cases := []any{
		v2Marshaler{V: "x<&>"},
		&v2Marshaler{V: "y"},
		v2MarshalerTo{V: "z<&>"},
		&v2MarshalerTo{V: "w"},
		jsontext.Value(` { "b" : 2, "a" : 1 } `),
	}
	for _, v := range cases {
		got, want := v2MarshalPair(t, v, v2Defaults()...)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Marshal(%T) = %q want %q | 编码不一致", v, got, want)
		}
	}
}

// v2ErrorTarget has no exported fields, which v2 rejects. | v2ErrorTarget 没有导出字段，v2 会拒绝。
type v2ErrorTarget struct{ hidden int }

// TestV2MarshalErrors compares the error type family on failing values. |
// TestV2MarshalErrors 对比失败值的错误类型族。
func TestV2MarshalErrors(t *testing.T) {
	cases := []any{
		make(chan int),
		v2ErrorTarget{},
		time.Duration(time.Second),
	}
	for _, v := range cases {
		_, gotErr := jsonx.Marshal(v, v2Defaults()...)
		_, wantErr := stdjsonv2.Marshal(v, v2Defaults()...)
		if (gotErr == nil) != (wantErr == nil) {
			t.Errorf("Marshal(%T) error = %v want %v | 错误不一致", v, gotErr, wantErr)
			continue
		}
		if wantErr == nil {
			continue
		}
		var gotSem, wantSem *stdjsonv2.SemanticError
		if errors.As(gotErr, &gotSem) != errors.As(wantErr, &wantSem) {
			t.Errorf("Marshal(%T) semantic error type = %v want %v | 错误类型不一致", v, gotErr, wantErr)
		}
	}
}
