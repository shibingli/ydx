package json_test

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/shibingli/ydx/json"
)

// Compile-time proof that every compatibility alias is identical to its encoding/json
// counterpart, so a caller can swap the import without changing declarations. | 编译期证明每个
// 兼容别名都与 encoding/json 的对应类型完全相同，调用方替换导入时无需改动声明。
var (
	_ json.Number        = stdjson.Number("1")
	_ stdjson.Number     = json.Number("1")
	_ json.RawMessage    = stdjson.RawMessage(nil)
	_ stdjson.RawMessage = json.RawMessage(nil)
	_ json.Delim         = stdjson.Delim('{')
	_ stdjson.Delim      = json.Delim('{')
	_ json.Token         = stdjson.Token(nil)
	_ stdjson.Token      = json.Token(nil)
	_ json.Marshaler     = stdjson.Marshaler(nil)
	_ json.Unmarshaler   = stdjson.Unmarshaler(nil)
	_ json.SyntaxError   = stdjson.SyntaxError{}
)

// The aliased types inherit every encoding/json method, and the v1/v2 option helpers keep
// compiling after switching imports. | 被别名的类型继承 encoding/json 的全部方法，v1/v2 选项
// 辅助函数在替换导入后仍可编译。
var (
	_ func() string             = json.Delim('{').String
	_ func() (float64, error)   = json.Number("1").Float64
	_ func() (int64, error)     = json.Number("1").Int64
	_ func() string             = json.Number("1").String
	_ func() json.Options       = json.DefaultOptionsV1
	_ func(bool) json.Options   = json.CallMethodsWithLegacySemantics
	_ func(bool) json.Options   = json.FormatByteArrayAsArray
	_ func(bool) json.Options   = json.FormatDurationAsNano
	_ func(bool) json.Options   = json.MatchCaseSensitiveDelimiter
	_ func(bool) json.Options   = json.MergeWithLegacySemantics
	_ func(bool) json.Options   = json.OmitEmptyWithLegacySemantics
	_ func(bool) json.Options   = json.ParseBytesWithLooseRFC4648
	_ func(bool) json.Options   = json.ParseTimeWithLooseRFC3339
	_ func(bool) json.Options   = json.ReportErrorsWithLegacySemantics
	_ func(bool) json.Options   = json.StringifyWithLegacySemantics
	_ func(bool) json.Options   = json.UnmarshalArrayFromAnyLength
	_ *json.InvalidUTF8Error    = nil
	_ *json.UnmarshalFieldError = nil
)

// TestCompactMatchesStdlib cross-checks Compact on valid and invalid inputs, including the error
// type and offset. | TestCompactMatchesStdlib 对合法与非法输入对拍 Compact，含错误类型与偏移。
func TestCompactMatchesStdlib(t *testing.T) {
	inputs := []string{
		"", "1", "  1  ", ` { "a" : 1 } `, `[1, 2, {"b": [3]}]`,
		`"a b\tc"`, `"\u00e9 <>&"`, "1 2", "[1,]", `{"a":1 "b":2}`, "{}", "[]",
	}
	for _, in := range inputs {
		var ours, theirs bytes.Buffer
		ours.WriteString("keep")
		theirs.WriteString("keep")
		ourErr := json.Compact(&ours, []byte(in))
		stdErr := stdjson.Compact(&theirs, []byte(in))
		if ours.String() != theirs.String() {
			t.Fatalf("%q: Compact = %q want %q", in, ours.String(), theirs.String())
		}
		if (ourErr == nil) != (stdErr == nil) {
			t.Fatalf("%q: Compact err = %v want %v", in, ourErr, stdErr)
		}
		if ourErr != nil {
			assertSyntaxErrorAt(t, in, ourErr, stdErr)
		}
	}
}

// TestIndentMatchesStdlib cross-checks Indent for several prefix/indent pairs, including trailing
// whitespace preservation. | TestIndentMatchesStdlib 用多组 prefix/indent 对拍 Indent，含尾部空白
// 保留语义。
func TestIndentMatchesStdlib(t *testing.T) {
	inputs := []string{
		"", "1", "  1  ", ` { "a" : 1 } `, `[1, 2, {"b": [3, []]}]`,
		`{"nested":{"empty":{},"arr":[]},"s":"a,b:c{[]}\"q\"","u":"\u2028"}`,
		`{"a":1} ` + "\n", "1 2", "[1,]", "{}", "[]",
	}
	pairs := [][2]string{{"", "  "}, {"", "\t"}, {"P", "  "}, {"> ", "--"}}
	for _, in := range inputs {
		for _, p := range pairs {
			var ours, theirs bytes.Buffer
			ours.WriteString("keep")
			theirs.WriteString("keep")
			ourErr := json.Indent(&ours, []byte(in), p[0], p[1])
			stdErr := stdjson.Indent(&theirs, []byte(in), p[0], p[1])
			if ours.String() != theirs.String() {
				t.Fatalf("%q prefix=%q indent=%q: Indent = %q want %q", in, p[0], p[1], ours.String(), theirs.String())
			}
			if (ourErr == nil) != (stdErr == nil) {
				t.Fatalf("%q prefix=%q indent=%q: Indent err = %v want %v", in, p[0], p[1], ourErr, stdErr)
			}
			if ourErr != nil {
				assertSyntaxErrorAt(t, in, ourErr, stdErr)
			}
		}
	}
}

// TestHTMLEscapeMatchesStdlib cross-checks HTMLEscape. | TestHTMLEscapeMatchesStdlib 对拍
// HTMLEscape。
func TestHTMLEscapeMatchesStdlib(t *testing.T) {
	inputs := []string{
		"", `"<a href=\"x\">&</a>"`, `"\u2028\u2029"`, `{"a":"<b>","c":"d"}`,
		"<>&\u2028\u2029", `"\u00e9"`,
	}
	for _, in := range inputs {
		var ours, theirs bytes.Buffer
		json.HTMLEscape(&ours, []byte(in))
		stdjson.HTMLEscape(&theirs, []byte(in))
		if ours.String() != theirs.String() {
			t.Fatalf("%q: HTMLEscape = %q want %q", in, ours.String(), theirs.String())
		}
	}
}

// assertSyntaxErrorAt verifies both errors carry a standard *SyntaxError with identical message
// and offset. | assertSyntaxErrorAt 验证两个错误都携带标准 *SyntaxError，且文案与偏移相同。
func assertSyntaxErrorAt(t *testing.T, in string, ours, theirs error) {
	t.Helper()
	var ourSE, stdSE *stdjson.SyntaxError
	if !errors.As(ours, &ourSE) {
		t.Fatalf("%q: %v is not *json.SyntaxError", in, ours)
	}
	if !errors.As(theirs, &stdSE) {
		t.Fatalf("%q: std error %v is not *json.SyntaxError", in, theirs)
	}
	if ourSE.Error() != stdSE.Error() || ourSE.Offset != stdSE.Offset {
		t.Fatalf("%q: SyntaxError = (%q, %d) want (%q, %d)", in, ourSE.Error(), ourSE.Offset, stdSE.Error(), stdSE.Offset)
	}
}

// TestEncoderSetIndentMatchesStdlib cross-checks Encoder.SetIndent output. |
// TestEncoderSetIndentMatchesStdlib 对拍 Encoder.SetIndent 的输出。
func TestEncoderSetIndentMatchesStdlib(t *testing.T) {
	value := map[string]any{
		"name": "ydx",
		"tags": []any{"a", "b"},
		"nested": map[string]any{
			"empty": map[string]any{},
			"html":  "<&>",
			"n":     float64(1.5),
		},
	}
	pairs := [][2]string{{"", "  "}, {"", "\t"}, {"P", "    "}}
	for _, p := range pairs {
		for _, escape := range []bool{true, false} {
			var ours, theirs bytes.Buffer
			ourEnc := json.NewEncoder(&ours)
			stdEnc := stdjson.NewEncoder(&theirs)
			ourEnc.SetIndent(p[0], p[1])
			stdEnc.SetIndent(p[0], p[1])
			ourEnc.SetEscapeHTML(escape)
			stdEnc.SetEscapeHTML(escape)
			if err := ourEnc.Encode(value); err != nil {
				t.Fatalf("our Encode: %v", err)
			}
			if err := stdEnc.Encode(value); err != nil {
				t.Fatalf("std Encode: %v", err)
			}
			if ours.String() != theirs.String() {
				t.Fatalf("prefix=%q indent=%q escape=%v:\n ours=%q\n std =%q", p[0], p[1], escape, ours.String(), theirs.String())
			}
		}
	}
}

// TestMarshaledIndentUnchangedWithoutSetIndent verifies that SetIndent(false) keeps compact
// output. | TestMarshaledIndentUnchangedWithoutSetIndent 验证未调用 SetIndent 时仍输出紧凑 JSON。
func TestMarshaledIndentUnchangedWithoutSetIndent(t *testing.T) {
	var ours, theirs bytes.Buffer
	_ = json.NewEncoder(&ours).Encode([]int{1, 2})
	_ = stdjson.NewEncoder(&theirs).Encode([]int{1, 2})
	if ours.String() != theirs.String() {
		t.Fatalf("Encode = %q want %q", ours.String(), theirs.String())
	}
}

// TestDecoderTokenMatchesStdlib cross-checks the Token sequence, offsets, More and Buffered
// against encoding/json. | TestDecoderTokenMatchesStdlib 与 encoding/json 对拍 Token 序列、偏移、
// More 与 Buffered。
func TestDecoderTokenMatchesStdlib(t *testing.T) {
	streams := []string{
		"", "1", "1 2", "[]", "[1,2]", `{"a":1}`, `{"a":1,"b":[true,null]}`,
		`[ "x" , { "y" : [ ] } , false , -1.5e3 ]`,
		`{"a":1,"b":2} {"c":3}`,
		"[1,]", `{"a"}`, `{"a":}`, "[1 2]", `{"a":1 "b":2}`, "1,2", `{"a":1]`,
	}
	for _, useNumber := range []bool{false, true} {
		for _, s := range streams {
			ourTokens, ourOffsets, ourErr := collectTokens(json.NewDecoder(strings.NewReader(s)), useNumber)
			stdTokens, stdOffsets, stdErr := collectTokens(stdjson.NewDecoder(strings.NewReader(s)), useNumber)
			if strings.Join(ourTokens, " ") != strings.Join(stdTokens, " ") {
				t.Fatalf("%q useNumber=%v: tokens = %v want %v (err %v / %v)", s, useNumber, ourTokens, stdTokens, ourErr, stdErr)
			}
			if (ourErr == nil) != (stdErr == nil) {
				t.Fatalf("%q useNumber=%v: err = %v want %v", s, useNumber, ourErr, stdErr)
			}
			for i := range ourOffsets {
				if ourOffsets[i] != stdOffsets[i] {
					t.Fatalf("%q useNumber=%v: offset[%d] = %d want %d (tokens %v)", s, useNumber, i, ourOffsets[i], stdOffsets[i], ourTokens)
				}
			}
		}
	}
}

// collectTokens drains a Decoder through Token and records each token and the InputOffset after
// it. | collectTokens 通过 Token 抽干 Decoder，记录每个记号及其之后的 InputOffset。
func collectTokens(d any, useNumber bool) ([]string, []int64, error) {
	var tokens []string
	var offsets []int64
	if useNumber {
		switch dec := d.(type) {
		case *json.Decoder:
			dec.UseNumber()
		case *stdjson.Decoder:
			dec.UseNumber()
		}
	}
	for i := 0; i < 1000; i++ {
		tok, err := tokenOf(d)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return tokens, offsets, nil
			}
			return tokens, offsets, err
		}
		tokens = append(tokens, tokenString(tok))
		offsets = append(offsets, offsetOf(d))
	}
	return tokens, offsets, errors.New("token loop did not terminate")
}

func tokenOf(d any) (any, error) {
	switch dec := d.(type) {
	case *json.Decoder:
		return dec.Token()
	case *stdjson.Decoder:
		return dec.Token()
	}
	return nil, errors.New("unsupported decoder")
}

func offsetOf(d any) int64 {
	switch dec := d.(type) {
	case *json.Decoder:
		return dec.InputOffset()
	case *stdjson.Decoder:
		return dec.InputOffset()
	}
	return -1
}

// tokenString renders a token from either decoder in a comparable form. | tokenString 把任一解码器
// 的记号渲染为可比较的文本。
func tokenString(tok any) string {
	switch v := tok.(type) {
	case json.Delim:
		return "D" + string(v)
	case string:
		return "s:" + v
	case float64:
		return "f:" + strconv.FormatFloat(v, 'g', -1, 64)
	case json.Number:
		return "n:" + v.String()
	case bool:
		return "b:" + strconv.FormatBool(v)
	case nil:
		return "null"
	default:
		return "?" + strconv.Quote(strconv.FormatInt(0, 10))
	}
}

// TestDecoderMoreAndBuffered verifies More inside containers and Buffered after Decode. |
// TestDecoderMoreAndBuffered 验证容器内的 More 与 Decode 之后的 Buffered。
func TestDecoderMoreAndBuffered(t *testing.T) {
	for _, s := range []string{"[]", "[1]", `{"a":1}`, `{}`, `[1,2,3]`, `{"a":[1],"b":{}}`} {
		our := json.NewDecoder(strings.NewReader(s))
		std := stdjson.NewDecoder(strings.NewReader(s))
		if _, err := our.Token(); err != nil {
			t.Fatalf("%q: Token: %v", s, err)
		}
		if _, err := std.Token(); err != nil {
			t.Fatalf("%q: std Token: %v", s, err)
		}
		for {
			ourMore, stdMore := our.More(), std.More()
			if ourMore != stdMore {
				t.Fatalf("%q: More = %v want %v", s, ourMore, stdMore)
			}
			if !stdMore {
				break
			}
			if _, err := our.Token(); err != nil {
				t.Fatalf("%q: Token: %v", s, err)
			}
			if _, err := std.Token(); err != nil {
				t.Fatalf("%q: std Token: %v", s, err)
			}
		}
	}
	for _, s := range []string{`{"a":1} tail`, "1 2", `[1] x`} {
		our := json.NewDecoder(strings.NewReader(s))
		std := stdjson.NewDecoder(strings.NewReader(s))
		var ourV, stdV any
		ourErr := our.Decode(&ourV)
		stdErr := std.Decode(&stdV)
		if (ourErr == nil) != (stdErr == nil) {
			t.Fatalf("%q: Decode err = %v want %v", s, ourErr, stdErr)
		}
		ourBuf, _ := io.ReadAll(our.Buffered())
		stdBuf, _ := io.ReadAll(std.Buffered())
		if string(ourBuf) != string(stdBuf) {
			t.Fatalf("%q: Buffered = %q want %q", s, ourBuf, stdBuf)
		}
		if our.InputOffset() != std.InputOffset() {
			t.Fatalf("%q: InputOffset = %d want %d", s, our.InputOffset(), std.InputOffset())
		}
	}
}

// TestDecoderDisallowUnknownFields matches the standard library's unknown-field behavior. |
// TestDecoderDisallowUnknownFields 与标准库的未知字段行为一致。
func TestDecoderDisallowUnknownFields(t *testing.T) {
	type inner struct {
		B int `json:"b"`
	}
	type target struct {
		A int   `json:"a"`
		N inner `json:"nested"`
	}
	cases := []struct {
		in      string
		wantErr bool
	}{
		{`{"a":1}`, false},
		{`{"a":1,"nested":{"b":2}}`, false},
		{`{"A":1}`, false},
		{`{"a":1,"x":2}`, true},
		{`{"nested":{"b":1,"c":2}}`, true},
		{`{"nested":{"c":2}}`, true},
	}
	for _, c := range cases {
		var ours, theirs target
		ourDec := json.NewDecoder(strings.NewReader(c.in))
		stdDec := stdjson.NewDecoder(strings.NewReader(c.in))
		ourDec.DisallowUnknownFields()
		stdDec.DisallowUnknownFields()
		ourErr := ourDec.Decode(&ours)
		stdErr := stdDec.Decode(&theirs)
		if (ourErr != nil) != c.wantErr || (stdErr != nil) != c.wantErr {
			t.Fatalf("%q: err = %v want %v (std %v)", c.in, ourErr, c.wantErr, stdErr)
		}
		if ourErr == nil && (ours.A != theirs.A || ours.N.B != theirs.N.B) {
			t.Fatalf("%q: value = %+v want %+v", c.in, ours, theirs)
		}
	}
	// Extra map keys are legal under DisallowUnknownFields, as in encoding/json. |
	// DisallowUnknownFields 下多余的映射键仍然合法，与 encoding/json 一致。
	var ourMap, stdMap map[string]int
	ourDec := json.NewDecoder(strings.NewReader(`{"x":1}`))
	stdDec := stdjson.NewDecoder(strings.NewReader(`{"x":1}`))
	ourDec.DisallowUnknownFields()
	stdDec.DisallowUnknownFields()
	if err := ourDec.Decode(&ourMap); err != nil {
		t.Fatalf("map Decode: %v", err)
	}
	if err := stdDec.Decode(&stdMap); err != nil {
		t.Fatalf("std map Decode: %v", err)
	}
}

// TestUnmarshalSyntaxErrorMatchesStdlib verifies syntax errors keep the standard type and offset.
// | TestUnmarshalSyntaxErrorMatchesStdlib 验证语法错误保持标准类型与偏移。
func TestUnmarshalSyntaxErrorMatchesStdlib(t *testing.T) {
	for _, in := range []string{"", "{", `{"a":}`, "[1,]", "01", `"a`} {
		var ours, theirs map[string]any
		ourErr := json.Unmarshal([]byte(in), &ours)
		stdErr := stdjson.Unmarshal([]byte(in), &theirs)
		if (ourErr == nil) != (stdErr == nil) {
			t.Fatalf("%q: err = %v want %v", in, ourErr, stdErr)
		}
		if ourErr == nil {
			continue
		}
		assertSyntaxErrorAt(t, in, ourErr, stdErr)
		if !errors.Is(ourErr, json.ErrSyntax) {
			t.Fatalf("%q: errors.Is(ErrSyntax) = false for %v", in, ourErr)
		}
	}
}

// TestUnmarshalTypeErrorMatchesStdlib verifies type errors keep the standard fields. |
// TestUnmarshalTypeErrorMatchesStdlib 验证类型错误保持标准字段。
func TestUnmarshalTypeErrorMatchesStdlib(t *testing.T) {
	type target struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	in := []byte(`{"id":"not-a-number","name":"x"}`)
	var ours, theirs target
	ourErr := json.Unmarshal(in, &ours)
	stdErr := stdjson.Unmarshal(in, &theirs)
	if ourErr == nil || stdErr == nil {
		t.Fatalf("err = %v, std err = %v", ourErr, stdErr)
	}
	var ourTE, stdTE *stdjson.UnmarshalTypeError
	if !errors.As(ourErr, &ourTE) {
		t.Fatalf("%v is not *json.UnmarshalTypeError", ourErr)
	}
	if !errors.As(stdErr, &stdTE) {
		t.Fatalf("%v is not *json.UnmarshalTypeError", stdErr)
	}
	if ourTE.Value != stdTE.Value || ourTE.Offset != stdTE.Offset ||
		ourTE.Struct != stdTE.Struct || ourTE.Field != stdTE.Field ||
		ourTE.Type != stdTE.Type {
		t.Fatalf("UnmarshalTypeError = %+v want %+v", ourTE, stdTE)
	}
	if !errors.Is(ourErr, json.ErrTypeMismatch) {
		t.Fatalf("errors.Is(ErrTypeMismatch) = false for %v", ourErr)
	}
}

// TestInvalidUnmarshalErrorMatchesStdlib verifies invalid targets use the standard error type. |
// TestInvalidUnmarshalErrorMatchesStdlib 验证非法目标使用标准错误类型。
func TestInvalidUnmarshalErrorMatchesStdlib(t *testing.T) {
	for _, v := range []any{nil, 42, (*int)(nil)} {
		ourErr := json.Unmarshal([]byte("1"), v)
		stdErr := stdjson.Unmarshal([]byte("1"), v)
		var ourIE, stdIE *stdjson.InvalidUnmarshalError
		if !errors.As(ourErr, &ourIE) {
			t.Fatalf("Unmarshal(%v) = %v, not *json.InvalidUnmarshalError", v, ourErr)
		}
		if !errors.As(stdErr, &stdIE) {
			t.Fatalf("std Unmarshal(%v) = %v, not *json.InvalidUnmarshalError", v, stdErr)
		}
		if ourIE.Type != stdIE.Type {
			t.Fatalf("InvalidUnmarshalError.Type = %v want %v", ourIE.Type, stdIE.Type)
		}
		if !errors.Is(ourErr, json.ErrTypeMismatch) {
			t.Fatalf("errors.Is(ErrTypeMismatch) = false for %v", ourErr)
		}
	}
}

// breakingMarshaler always fails to marshal. | breakingMarshaler 总是编码失败。
type breakingMarshaler struct{}

func (breakingMarshaler) MarshalJSON() ([]byte, error) { return nil, errors.New("boom") }

// TestMarshalErrorTypesMatchStdlib verifies typed marshal errors match encoding/json. |
// TestMarshalErrorTypesMatchStdlib 验证带类型的编码错误与 encoding/json 一致。
func TestMarshalErrorTypesMatchStdlib(t *testing.T) {
	cases := []struct {
		name string
		v    any
	}{
		{"chan", make(chan int)},
		{"func", func() {}},
		{"nan", math.NaN()},
		{"inf", math.Inf(1)},
		{"marshaler", breakingMarshaler{}},
	}
	for _, c := range cases {
		_, ourErr := json.Marshal(c.v)
		_, stdErr := stdjson.Marshal(c.v)
		if ourErr == nil || stdErr == nil {
			t.Fatalf("%s: err = %v want %v", c.name, ourErr, stdErr)
		}
		switch stdErr.(type) {
		case *stdjson.UnsupportedTypeError:
			var ourTE, stdTE *stdjson.UnsupportedTypeError
			if !errors.As(ourErr, &ourTE) || !errors.As(stdErr, &stdTE) || ourTE.Type != stdTE.Type {
				t.Fatalf("%s: UnsupportedTypeError missing or differs: %v", c.name, ourErr)
			}
		case *stdjson.UnsupportedValueError:
			var ourVE, stdVE *stdjson.UnsupportedValueError
			if !errors.As(ourErr, &ourVE) || !errors.As(stdErr, &stdVE) || ourVE.Str != stdVE.Str {
				t.Fatalf("%s: UnsupportedValueError missing or differs: %v", c.name, ourErr)
			}
		case *stdjson.MarshalerError:
			var ourME, stdME *stdjson.MarshalerError
			if !errors.As(ourErr, &ourME) || !errors.As(stdErr, &stdME) || ourME.Err.Error() != stdME.Err.Error() {
				t.Fatalf("%s: MarshalerError missing or differs: %v", c.name, ourErr)
			}
		default:
			t.Fatalf("%s: unexpected std error type %T", c.name, stdErr)
		}
	}
}

// TestRawMessageAndNumberRoundTrip verifies the aliases work through both directions. |
// TestRawMessageAndNumberRoundTrip 验证别名在两个方向上都能正常工作。
func TestRawMessageAndNumberRoundTrip(t *testing.T) {
	raw := json.RawMessage(`{"a":1}`)
	out, err := json.Marshal(raw)
	if err != nil || string(out) != `{"a":1}` {
		t.Fatalf("Marshal(RawMessage) = (%q, %v)", out, err)
	}
	var num struct {
		N json.Number `json:"n"`
	}
	if err := json.Unmarshal([]byte(`{"n":12345678901234567890}`), &num); err != nil {
		t.Fatalf("Unmarshal Number: %v", err)
	}
	if num.N.String() != "12345678901234567890" {
		t.Fatalf("Number = %q", num.N)
	}
}
