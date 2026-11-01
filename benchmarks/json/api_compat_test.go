package json

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	ydxjson "github.com/shibingli/ydx/json"
)

// TestFormattingAPIMatchesStdlib cross-checks Compact / Indent / HTMLEscape. |
// TestFormattingAPIMatchesStdlib 对拍 Compact / Indent / HTMLEscape。
func TestFormattingAPIMatchesStdlib(t *testing.T) {
	inputs := []string{
		"", "1", "  1  ", ` { "a" : 1 } `, `[1, 2, {"b": [3, []]}]`,
		`{"s":"a,b:c{[]}\"q\"","u":"  ","h":"<&>"}`,
		`{"a":1} ` + "\n", "1 2", "[1,]", `{"a":1 "b":2}`, "{}", "[]",
	}
	for _, in := range inputs {
		var ydxCompact, stdCompact bytes.Buffer
		ydxErr := ydxjson.Compact(&ydxCompact, []byte(in))
		stdErr := stdjson.Compact(&stdCompact, []byte(in))
		if ydxCompact.String() != stdCompact.String() || (ydxErr == nil) != (stdErr == nil) {
			t.Fatalf("%q: Compact = (%q, %v) want (%q, %v)", in, ydxCompact.String(), ydxErr, stdCompact.String(), stdErr)
		}
		for _, p := range [][2]string{{"", "  "}, {"P", "\t"}} {
			var ydxIndent, stdIndent bytes.Buffer
			ydxErr := ydxjson.Indent(&ydxIndent, []byte(in), p[0], p[1])
			stdErr := stdjson.Indent(&stdIndent, []byte(in), p[0], p[1])
			if ydxIndent.String() != stdIndent.String() || (ydxErr == nil) != (stdErr == nil) {
				t.Fatalf("%q prefix=%q: Indent = (%q, %v) want (%q, %v)", in, p[0], ydxIndent.String(), ydxErr, stdIndent.String(), stdErr)
			}
		}
		var ydxHTML, stdHTML bytes.Buffer
		ydxjson.HTMLEscape(&ydxHTML, []byte(in))
		stdjson.HTMLEscape(&stdHTML, []byte(in))
		if ydxHTML.String() != stdHTML.String() {
			t.Fatalf("%q: HTMLEscape = %q want %q", in, ydxHTML.String(), stdHTML.String())
		}
	}
	// Syntax errors keep the standard type and offset. | 语法错误保持标准类型与偏移。
	var ydxBuf, stdBuf bytes.Buffer
	ydxErr := ydxjson.Compact(&ydxBuf, []byte("[1,]"))
	stdErr := stdjson.Compact(&stdBuf, []byte("[1,]"))
	var ydxSE, stdSE *stdjson.SyntaxError
	if !errors.As(ydxErr, &ydxSE) || !errors.As(stdErr, &stdSE) || ydxSE.Error() != stdSE.Error() || ydxSE.Offset != stdSE.Offset {
		t.Fatalf("Compact syntax error = %v want %v", ydxErr, stdErr)
	}
}

// TestTokenAPIMatchesStdlib cross-checks Decoder.Token / More / Buffered / InputOffset. |
// TestTokenAPIMatchesStdlib 对拍 Decoder.Token / More / Buffered / InputOffset。
func TestTokenAPIMatchesStdlib(t *testing.T) {
	streams := []string{
		"", "1", "1 2", "[]", "[1,2]", `{"a":1}`, `{"a":1,"b":[true,null]}`,
		`[ "x" , { "y" : [ ] } , false , -1.5e3 ]`, `{"a":1,"b":2} {"c":3}`,
		"[1,]", `{"a"}`, `{"a":}`, "[1 2]", `{"a":1 "b":2}`, "1,2", `{"a":1]`,
	}
	for _, useNumber := range []bool{false, true} {
		for _, s := range streams {
			ydxTokens, ydxOffsets, ydxErr := drainTokens(ydxjson.NewDecoder(strings.NewReader(s)), useNumber)
			stdTokens, stdOffsets, stdErr := drainTokens(stdjson.NewDecoder(strings.NewReader(s)), useNumber)
			if strings.Join(ydxTokens, " ") != strings.Join(stdTokens, " ") {
				t.Fatalf("%q useNumber=%v: tokens = %v want %v", s, useNumber, ydxTokens, stdTokens)
			}
			if (ydxErr == nil) != (stdErr == nil) {
				t.Fatalf("%q useNumber=%v: err = %v want %v", s, useNumber, ydxErr, stdErr)
			}
			for i := range ydxOffsets {
				if ydxOffsets[i] != stdOffsets[i] {
					t.Fatalf("%q useNumber=%v: offset[%d] = %d want %d", s, useNumber, i, ydxOffsets[i], stdOffsets[i])
				}
			}
		}
	}
	// More inside a container. | 容器内的 More。
	for _, s := range []string{"[]", "[1]", `{"a":1}`, `{"a":[1],"b":{}}`} {
		ydxDec := ydxjson.NewDecoder(strings.NewReader(s))
		stdDec := stdjson.NewDecoder(strings.NewReader(s))
		if _, err := ydxDec.Token(); err != nil {
			t.Fatalf("%q: ydx Token: %v", s, err)
		}
		if _, err := stdDec.Token(); err != nil {
			t.Fatalf("%q: std Token: %v", s, err)
		}
		for {
			if ydxDec.More() != stdDec.More() {
				t.Fatalf("%q: More differs", s)
			}
			if !stdDec.More() {
				break
			}
			if _, err := ydxDec.Token(); err != nil {
				t.Fatalf("%q: ydx Token: %v", s, err)
			}
			if _, err := stdDec.Token(); err != nil {
				t.Fatalf("%q: std Token: %v", s, err)
			}
		}
	}
	// Buffered and InputOffset after Decode. | Decode 之后的 Buffered 与 InputOffset。
	for _, s := range []string{`{"a":1} tail`, "1 2", `[1] x`} {
		ydxDec := ydxjson.NewDecoder(strings.NewReader(s))
		stdDec := stdjson.NewDecoder(strings.NewReader(s))
		var ydxV, stdV any
		ydxErr := ydxDec.Decode(&ydxV)
		stdErr := stdDec.Decode(&stdV)
		if (ydxErr == nil) != (stdErr == nil) || ydxDec.InputOffset() != stdDec.InputOffset() {
			t.Fatalf("%q: Decode/offset = (%v, %d) want (%v, %d)", s, ydxErr, ydxDec.InputOffset(), stdErr, stdDec.InputOffset())
		}
		ydxBuf, _ := io.ReadAll(ydxDec.Buffered())
		stdBuf, _ := io.ReadAll(stdDec.Buffered())
		if !bytes.Equal(ydxBuf, stdBuf) {
			t.Fatalf("%q: Buffered = %q want %q", s, ydxBuf, stdBuf)
		}
	}
}

// drainTokens collects tokens and offsets from either decoder implementation. | drainTokens 收集任一
// 解码器实现的记号与偏移。
func drainTokens(d any, useNumber bool) ([]string, []int64, error) {
	var tokens []string
	var offsets []int64
	if useNumber {
		switch dec := d.(type) {
		case *ydxjson.Decoder:
			dec.UseNumber()
		case *stdjson.Decoder:
			dec.UseNumber()
		}
	}
	for i := 0; i < 1000; i++ {
		var tok any
		var err error
		switch dec := d.(type) {
		case *ydxjson.Decoder:
			tok, err = dec.Token()
			if err == nil {
				offsets = append(offsets, dec.InputOffset())
			}
		case *stdjson.Decoder:
			tok, err = dec.Token()
			if err == nil {
				offsets = append(offsets, dec.InputOffset())
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return tokens, offsets, nil
			}
			return tokens, offsets, err
		}
		tokens = append(tokens, compatTokenString(tok))
	}
	return tokens, offsets, errors.New("token loop did not terminate")
}

// compatTokenString renders a token from either decoder in a comparable form. |
// compatTokenString 把任一解码器的记号渲染为可比较的文本。
func compatTokenString(tok any) string {
	switch v := tok.(type) {
	case ydxjson.Delim:
		return "D" + string(v)
	case string:
		return "s:" + v
	case float64:
		return "f:" + strconv.FormatFloat(v, 'g', -1, 64)
	case ydxjson.Number:
		return "n:" + v.String()
	case bool:
		return "b:" + strconv.FormatBool(v)
	case nil:
		return "null"
	default:
		return "?unknown"
	}
}

// TestEncoderOptionsMatchStdlib cross-checks Encoder.SetIndent and Decoder.DisallowUnknownFields.
// | TestEncoderOptionsMatchStdlib 对拍 Encoder.SetIndent 与 Decoder.DisallowUnknownFields。
func TestEncoderOptionsMatchStdlib(t *testing.T) {
	value := map[string]any{
		"name":   "ydx",
		"tags":   []any{"a", "b"},
		"nested": map[string]any{"empty": map[string]any{}, "n": 1.5, "html": "<&>"},
	}
	for _, p := range [][2]string{{"", "  "}, {"P", "\t"}} {
		for _, escape := range []bool{true, false} {
			var ydxOut, stdOut bytes.Buffer
			ydxEnc := ydxjson.NewEncoder(&ydxOut)
			stdEnc := stdjson.NewEncoder(&stdOut)
			ydxEnc.SetIndent(p[0], p[1])
			stdEnc.SetIndent(p[0], p[1])
			ydxEnc.SetEscapeHTML(escape)
			stdEnc.SetEscapeHTML(escape)
			if err := ydxEnc.Encode(value); err != nil {
				t.Fatalf("ydx Encode: %v", err)
			}
			if err := stdEnc.Encode(value); err != nil {
				t.Fatalf("std Encode: %v", err)
			}
			if ydxOut.String() != stdOut.String() {
				t.Fatalf("prefix=%q escape=%v: output differs", p[0], escape)
			}
		}
	}
	type target struct {
		A int `json:"a"`
	}
	for _, in := range []string{`{"a":1}`, `{"a":1,"x":2}`} {
		var ydxV, stdV target
		ydxDec := ydxjson.NewDecoder(strings.NewReader(in))
		stdDec := stdjson.NewDecoder(strings.NewReader(in))
		ydxDec.DisallowUnknownFields()
		stdDec.DisallowUnknownFields()
		ydxErr := ydxDec.Decode(&ydxV)
		stdErr := stdDec.Decode(&stdV)
		if (ydxErr == nil) != (stdErr == nil) || ydxV != stdV {
			t.Fatalf("%q: DisallowUnknownFields = (%v, %+v) want (%v, %+v)", in, ydxErr, ydxV, stdErr, stdV)
		}
	}
}

// TestErrorTypesMatchStdlib verifies errors.As works with the encoding/json error types. |
// TestErrorTypesMatchStdlib 验证 errors.As 可取到 encoding/json 的错误类型。
func TestErrorTypesMatchStdlib(t *testing.T) {
	var ydxV, stdV map[string]any
	ydxErr := ydxjson.Unmarshal([]byte(`{"a":}`), &ydxV)
	stdErr := stdjson.Unmarshal([]byte(`{"a":}`), &stdV)
	var ydxSE, stdSE *stdjson.SyntaxError
	if !errors.As(ydxErr, &ydxSE) || !errors.As(stdErr, &stdSE) || ydxSE.Error() != stdSE.Error() || ydxSE.Offset != stdSE.Offset {
		t.Fatalf("SyntaxError = %v want %v", ydxErr, stdErr)
	}
	type target struct {
		ID int `json:"id"`
	}
	var ydxT, stdT target
	ydxErr = ydxjson.Unmarshal([]byte(`{"id":"x"}`), &ydxT)
	stdErr = stdjson.Unmarshal([]byte(`{"id":"x"}`), &stdT)
	var ydxTE, stdTE *stdjson.UnmarshalTypeError
	if !errors.As(ydxErr, &ydxTE) || !errors.As(stdErr, &stdTE) ||
		ydxTE.Value != stdTE.Value || ydxTE.Offset != stdTE.Offset || ydxTE.Field != stdTE.Field || ydxTE.Type != stdTE.Type {
		t.Fatalf("UnmarshalTypeError = %+v want %+v", ydxTE, stdTE)
	}
	ydxErr = ydxjson.Unmarshal([]byte("1"), nil)
	stdErr = stdjson.Unmarshal([]byte("1"), nil)
	var ydxIE, stdIE *stdjson.InvalidUnmarshalError
	if !errors.As(ydxErr, &ydxIE) || !errors.As(stdErr, &stdIE) || ydxIE.Type != stdIE.Type {
		t.Fatalf("InvalidUnmarshalError = %v want %v", ydxErr, stdErr)
	}
	_, ydxErr = ydxjson.Marshal(make(chan int))
	_, stdErr = stdjson.Marshal(make(chan int))
	var ydxUTE, stdUTE *stdjson.UnsupportedTypeError
	if !errors.As(ydxErr, &ydxUTE) || !errors.As(stdErr, &stdUTE) || ydxUTE.Type != stdUTE.Type {
		t.Fatalf("UnsupportedTypeError = %v want %v", ydxErr, stdErr)
	}
}

// compatUnicode covers CJK, emoji (including ZWJ sequences), combining marks, metacharacters,
// line separators and control characters. | compatUnicode 覆盖 CJK、表情符号（含 ZWJ 组合）、
// 组合附加符、元字符、行分隔符与控制字符。
var compatUnicode = []string{
	"中文测试", "日本語と韓国語", "😀🚀🎉", "👨‍👩‍👧‍👦", "e\u0301",
	`<>"'&\/`, "\u2028\u2029", "\x00\x01\x1f", "mixed 中文😀 <&> end",
}

// unicodeTagTarget covers tag aliases with CJK, emoji, spaces and reserved characters. |
// unicodeTagTarget 覆盖含 CJK、表情符号、空格与保留字符的标签别名。
type unicodeTagTarget struct {
	CJK   string `json:"别名"`
	Emoji string `json:"🚀,omitempty"`
	Space string `json:"a b"`
	Punct string `json:"<&>"`
	Trunc string `json:"pre\"post"`
}

// TestUnicodeAPIMatchesStdlib cross-checks strings, keys and tag aliases containing non-ASCII
// and special characters against encoding/json, including Encoder HTML-escaping of names. |
// TestUnicodeAPIMatchesStdlib 用含非 ASCII 与特殊字符的字符串、键与标签别名对拍
// encoding/json，含 Encoder 对字段名的 HTML 转义。
func TestUnicodeAPIMatchesStdlib(t *testing.T) {
	for _, in := range compatUnicode {
		ourOut, ourErr := ydxjson.Marshal(in)
		stdOut, stdErr := stdjson.Marshal(in)
		if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
			t.Fatalf("%q: Marshal = (%q, %v) want (%q, %v)", in, ourOut, ourErr, stdOut, stdErr)
		}
		var ourBack, stdBack string
		if err := ydxjson.Unmarshal(stdOut, &ourBack); err != nil {
			t.Fatalf("%q: ydx Unmarshal: %v", in, err)
		}
		if err := stdjson.Unmarshal(stdOut, &stdBack); err != nil {
			t.Fatalf("%q: std Unmarshal: %v", in, err)
		}
		if ourBack != stdBack {
			t.Fatalf("%q: Unmarshal = %q want %q", in, ourBack, stdBack)
		}
		for _, escape := range []bool{true, false} {
			var ourBuf, stdBuf bytes.Buffer
			ourEnc := ydxjson.NewEncoder(&ourBuf)
			stdEnc := stdjson.NewEncoder(&stdBuf)
			ourEnc.SetEscapeHTML(escape)
			stdEnc.SetEscapeHTML(escape)
			if err := ourEnc.Encode(in); err != nil {
				t.Fatalf("%q: ydx Encode: %v", in, err)
			}
			if err := stdEnc.Encode(in); err != nil {
				t.Fatalf("%q: std Encode: %v", in, err)
			}
			if ourBuf.String() != stdBuf.String() {
				t.Fatalf("%q escape=%v: Encode differs", in, escape)
			}
		}
	}
	// Non-ASCII and emoji object keys. | 非 ASCII 与表情符号对象键。
	m := map[string]string{"中文": "值", "😀": "emoji", "é": "accent"}
	ourMap, ourErr := ydxjson.Marshal(m)
	stdMap, stdErr := stdjson.Marshal(m)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourMap, stdMap) {
		t.Fatalf("map Marshal = (%q, %v) want (%q, %v)", ourMap, ourErr, stdMap, stdErr)
	}
	// Field-name aliases, including HTML escaping of names. | 字段名别名，含字段名的 HTML 转义。
	val := unicodeTagTarget{CJK: "中文", Emoji: "😀", Space: "s", Punct: "p", Trunc: "t"}
	ourOut, ourErr := ydxjson.Marshal(val)
	stdOut, stdErr := stdjson.Marshal(val)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("tag Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
	for _, escape := range []bool{true, false} {
		var ourBuf, stdBuf bytes.Buffer
		ourEnc := ydxjson.NewEncoder(&ourBuf)
		stdEnc := stdjson.NewEncoder(&stdBuf)
		ourEnc.SetEscapeHTML(escape)
		stdEnc.SetEscapeHTML(escape)
		if err := ourEnc.Encode(val); err != nil {
			t.Fatalf("ydx Encode val: %v", err)
		}
		if err := stdEnc.Encode(val); err != nil {
			t.Fatalf("std Encode val: %v", err)
		}
		if ourBuf.String() != stdBuf.String() {
			t.Fatalf("tag Encode escape=%v differs", escape)
		}
	}
}
