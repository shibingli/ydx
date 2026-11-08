package json_test

import (
	"bytes"
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	jsonx "github.com/shibingli/ydx/json"
)

// v2DifferentialAll is the payload set used by the differential comparison. |
// v2DifferentialAll 是差分对比使用的载荷集合。
type v2DifferentialAll struct {
	Ptr     *int               `json:"ptr"`
	Map     map[string]int     `json:"map"`
	Slice   []string           `json:"slice"`
	Bytes   []byte             `json:"bytes"`
	Array   [3]byte            `json:"array"`
	Time    time.Time          `json:"time"`
	Number  jsonx.Number       `json:"number"`
	Raw     jsontext.Value     `json:"raw"`
	Nested  *v2DifferentialAll `json:"nested,omitempty"`
	Float   float64            `json:"float"`
	Float32 float32            `json:"float32"`
	I       int                `json:"i"`
	U       uint64             `json:"u"`
	B       bool               `json:"b"`
	S       string             `json:"s"`
}

// v2OptionSets returns the option combinations exercised by the differential test. |
// v2OptionSets 返回差分测试覆盖的选项组合。
func v2OptionSets() []struct {
	name string
	opts []jsonx.Options
} {
	return []struct {
		name string
		opts []jsonx.Options
	}{
		{"default", []jsonx.Options{jsonx.DefaultOptionsV2()}},
		{"html", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.EscapeForHTML(true))}},
		{"js", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.EscapeForJS(true))}},
		{"nil-null", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.FormatNilMapAsNull(true), jsonx.FormatNilSliceAsNull(true))}},
		{"deterministic", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.Deterministic(true))}},
		{"stringify", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.StringifyNumbers(true))}},
		{"omitzero", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.OmitZeroStructFields(true))}},
		{"byte-array", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.FormatByteArrayAsArray(true))}},
		{"duration-nano", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.FormatDurationAsNano(true))}},
		{"indent", []jsonx.Options{jsontext.WithIndent("  ")}},
		{"multiline", []jsonx.Options{jsontext.Multiline(true)}},
		{"space", []jsonx.Options{jsontext.SpaceAfterColon(true), jsontext.SpaceAfterComma(true)}},
		{"allow-dup", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.AllowDuplicateNames(true))}},
		{"allow-utf8", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.AllowInvalidUTF8(true))}},
		{"canon-raw", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.CanonicalizeRawInts(true), jsontext.CanonicalizeRawFloats(true))}},
		{"reorder-raw", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.ReorderRawObjects(true))}},
		{"preserve-raw", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.PreserveRawStrings(true))}},
	}
}

// canonicalJSON decodes raw JSON into a comparable form. | canonicalJSON 把原始 JSON 解码为可比较
// 的形式。
func canonicalJSON(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := stdjsonv2.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return v
}

// TestV2DifferentialMarshal compares exact output for structs (whose field order is stable) and
// canonical output for map-bearing values across every option set. |
// TestV2DifferentialMarshal 在每个选项集合上对比结构体的精确输出与含 map 值的规范输出。
func TestV2DifferentialMarshal(t *testing.T) {
	i := 7
	values := []any{
		v2DifferentialAll{},
		v2DifferentialAll{
			Ptr: &i, Map: map[string]int{"b": 2, "a": 1}, Slice: []string{"x<&>", "y"},
			Bytes: []byte{1, 2, 3}, Array: [3]byte{4, 5, 6},
			Time: time.Date(2020, 1, 2, 3, 4, 5, 123456789, time.UTC), Number: "42",
			Raw: jsontext.Value(`{ "a" : 1 }`), Float: 1.5, Float32: 2.25, I: -3,
			U: 4, B: true, S: "héllo <&>",
		},
		map[string]any{"b": 2, "a": []any{1.0, "x", nil}},
		[]any{int64(1), "two", true, nil},
		"plain", "<&>", "  ", "é😀",
		[]int(nil), map[string]int(nil), []byte(nil), [3]byte{}, time.Duration(1500 * time.Millisecond),
		[]float64{1.09, -1.09, math.Float64frombits(0x42ec8bc8eaa90629), 123456789.5, math.Copysign(0, -1), math.MaxFloat64},
		math.Inf(1), math.NaN(),
		string([]byte{'a', 0xff, 'b'}),
		jsontext.Value(`{ "a" : "A", "n" : 1.00, "i" : 1e2 }`),
		jsontext.Value(`{"b":1,"a":2}`),
		jsontext.Value(`[1, 2]`),
	}
	for _, set := range v2OptionSets() {
		for _, v := range values {
			got, gotErr := jsonx.Marshal(v, set.opts...)
			want, wantErr := stdjsonv2.Marshal(v, set.opts...)
			if (gotErr == nil) != (wantErr == nil) {
				t.Errorf("%s Marshal(%T) error = %v want %v | 错误不一致", set.name, v, gotErr, wantErr)
				continue
			}
			if gotErr != nil {
				continue
			}
			if bytes.Equal(got, want) {
				continue
			}
			// Map key order may differ; compare canonical forms when the exact bytes differ. |
			// map 键顺序可能不同；字节不同时比较规范形式。
			if !reflect.DeepEqual(canonicalJSON(t, got), canonicalJSON(t, want)) {
				t.Errorf("%s Marshal(%T) = %s want %s | 编码不一致", set.name, v, got, want)
			}
		}
	}
}

// TestV2DifferentialUnmarshal compares decoding results and error kinds for the same inputs. |
// TestV2DifferentialUnmarshal 对比相同输入的解码结果与错误种类。
func TestV2DifferentialUnmarshal(t *testing.T) {
	inputs := []string{
		`{}`, `null`,
		`{"ptr":1,"map":{"a":1},"slice":["x"],"bytes":"AQID","array":"BAUG","time":"2020-01-02T03:04:05Z","number":42,"raw":{"a":1},"float":1.5,"float32":2.5,"i":-1,"u":2,"b":true,"s":"x"}`,
		`{"i":"5"}`, `{"raw":{"a":1,"a":2}}`, `{"raw":[1,2]}`, `{"array":[4,5,6]}`,
		`{"a":1,"a":2}`, "\"a\xffb\"", `{"nested":{"i":1}}`,
	}
	for _, set := range v2OptionSets() {
		for _, in := range inputs {
			got := new(v2DifferentialAll)
			want := new(v2DifferentialAll)
			gotErr := jsonx.Unmarshal([]byte(in), got, set.opts...)
			wantErr := stdjsonv2.Unmarshal([]byte(in), want, set.opts...)
			if (gotErr == nil) != (wantErr == nil) {
				t.Errorf("%s Unmarshal(%s) error = %v want %v | 错误不一致", set.name, in, gotErr, wantErr)
				continue
			}
			if gotErr != nil {
				var gotSyn, wantSyn *jsontext.SyntacticError
				var gotSem, wantSem *stdjsonv2.SemanticError
				_ = errors.As(gotErr, &gotSyn)
				_ = errors.As(wantErr, &wantSyn)
				_ = errors.As(gotErr, &gotSem)
				_ = errors.As(wantErr, &wantSem)
				if (gotSyn != nil) != (wantSyn != nil) || (gotSem != nil) != (wantSem != nil) {
					t.Errorf("%s Unmarshal(%s) error kinds = %v want %v | 错误种类不一致", set.name, in, gotErr, wantErr)
				}
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s Unmarshal(%s) = %+v want %+v | 解码不一致", set.name, in, got, want)
			}
		}
	}
}
