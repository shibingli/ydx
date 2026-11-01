package json_test

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/shibingli/ydx/json"
)

// unicodeCorpus covers CJK, emoji (including ZWJ sequences and flags), combining marks, RTL
// text, JSON metacharacters, control characters and the line separators that encoding/json
// escapes. | unicodeCorpus 覆盖 CJK、表情符号（含 ZWJ 组合与旗帜）、组合附加符、RTL 文本、
// JSON 元字符、控制字符以及 encoding/json 会转义的行分隔符。
var unicodeCorpus = []string{
	"中文测试", "日本語と韓国語", "한국어 테스트",
	"😀🚀🎉", "👨‍👩‍👧‍👦", "🇨🇳", "🏳️‍🌈",
	"é", "مرحبا بالعالم", `<>"'&\\/`,
	"line\nbreak\ttab\rcr", "  ", "\x00\x01\x1f",
	"mixed 中文😀 <&> \\/ end",
}

// TestUnicodeStringMatchesStdlib cross-checks every JSON entry point with non-ASCII and special
// text: Marshal, Unmarshal, Encoder HTML escaping, Compact, Indent and HTMLEscape. |
// TestUnicodeStringMatchesStdlib 用非 ASCII 与特殊文本对拍所有 JSON 入口：Marshal、Unmarshal、
// Encoder 的 HTML 转义、Compact、Indent 与 HTMLEscape。
func TestUnicodeStringMatchesStdlib(t *testing.T) {
	for _, in := range unicodeCorpus {
		ourOut, ourErr := json.Marshal(in)
		stdOut, stdErr := stdjson.Marshal(in)
		if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
			t.Fatalf("%q: Marshal = (%q, %v) want (%q, %v)", in, ourOut, ourErr, stdOut, stdErr)
		}
		var ourBack, stdBack string
		if err := json.Unmarshal(stdOut, &ourBack); err != nil {
			t.Fatalf("%q: ydx Unmarshal: %v", in, err)
		}
		if err := stdjson.Unmarshal(stdOut, &stdBack); err != nil {
			t.Fatalf("%q: std Unmarshal: %v", in, err)
		}
		if ourBack != stdBack || ourBack != in {
			t.Fatalf("%q: Unmarshal = %q want %q", in, ourBack, stdBack)
		}
		for _, escape := range []bool{true, false} {
			var ourBuf, stdBuf bytes.Buffer
			ourEnc := json.NewEncoder(&ourBuf)
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
				t.Fatalf("%q escape=%v: Encode = %q want %q", in, escape, ourBuf.String(), stdBuf.String())
			}
		}
		var ourCompact, stdCompact bytes.Buffer
		if err := json.Compact(&ourCompact, ourOut); err != nil {
			t.Fatalf("%q: ydx Compact: %v", in, err)
		}
		if err := stdjson.Compact(&stdCompact, ourOut); err != nil {
			t.Fatalf("%q: std Compact: %v", in, err)
		}
		if ourCompact.String() != stdCompact.String() {
			t.Fatalf("%q: Compact = %q want %q", in, ourCompact.String(), stdCompact.String())
		}
		var ourIndent, stdIndent bytes.Buffer
		if err := json.Indent(&ourIndent, ourOut, "", "  "); err != nil {
			t.Fatalf("%q: ydx Indent: %v", in, err)
		}
		if err := stdjson.Indent(&stdIndent, ourOut, "", "  "); err != nil {
			t.Fatalf("%q: std Indent: %v", in, err)
		}
		if ourIndent.String() != stdIndent.String() {
			t.Fatalf("%q: Indent = %q want %q", in, ourIndent.String(), stdIndent.String())
		}
		var ourHTML, stdHTML bytes.Buffer
		json.HTMLEscape(&ourHTML, ourOut)
		stdjson.HTMLEscape(&stdHTML, ourOut)
		if ourHTML.String() != stdHTML.String() {
			t.Fatalf("%q: HTMLEscape = %q want %q", in, ourHTML.String(), stdHTML.String())
		}
	}
	// Non-ASCII and emoji object keys must sort and round-trip identically. |
	// 非 ASCII 与表情符号对象键必须与标准库一样排序并可往返。
	m := map[string]string{"中文": "值", "😀": "emoji", "a": "ascii", "é": "accent"}
	ourMap, ourErr := json.Marshal(m)
	stdMap, stdErr := stdjson.Marshal(m)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourMap, stdMap) {
		t.Fatalf("map Marshal = (%q, %v) want (%q, %v)", ourMap, ourErr, stdMap, stdErr)
	}
	var ourDecoded, stdDecoded map[string]string
	if err := json.Unmarshal(stdMap, &ourDecoded); err != nil {
		t.Fatalf("map ydx Unmarshal: %v", err)
	}
	if err := stdjson.Unmarshal(stdMap, &stdDecoded); err != nil {
		t.Fatalf("map std Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(ourDecoded, stdDecoded) {
		t.Fatalf("map value = %#v want %#v", ourDecoded, stdDecoded)
	}
}

// EmbeddedAlias is flattened into aliasTarget. | EmbeddedAlias 被展平进 aliasTarget。
type EmbeddedAlias struct {
	X int `json:"x"`
}

// aliasTarget covers JSON tag aliases: renamed fields, CJK and emoji tag names, skip, omitempty,
// omitzero, the string option, case-insensitive matching and embedded struct flattening. |
// aliasTarget 覆盖 JSON 标签别名：改名、CJK 与表情符号标签名、跳过、omitempty、omitzero、
// string 选项、大小写不敏感匹配与嵌入结构体展平。
type aliasTarget struct {
	ID      int    `json:"id"`
	CJK     string `json:"别名"`
	Emoji   string `json:"🚀,omitempty"`
	Skip    string `json:"-"`
	Renamed string `json:"Renamed"`
	Quoted  int    `json:"quoted,string"`
	Zero    int    `json:"zero,omitzero"`
	Empty   string `json:"empty,omitempty"`
	EmbeddedAlias
}

// TestJSONTagAliases verifies struct tag aliases behave exactly like encoding/json. |
// TestJSONTagAliases 验证结构体标签别名与 encoding/json 完全一致。
func TestJSONTagAliases(t *testing.T) {
	val := aliasTarget{
		ID: 7, CJK: "中文值", Emoji: "😀🚀", Skip: "hidden", Renamed: "r",
		Quoted: 42, Zero: 0, Empty: "", EmbeddedAlias: EmbeddedAlias{X: 9},
	}
	ourOut, ourErr := json.Marshal(val)
	stdOut, stdErr := stdjson.Marshal(val)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
	var ourBack, stdBack aliasTarget
	if err := json.Unmarshal(stdOut, &ourBack); err != nil {
		t.Fatalf("ydx Unmarshal: %v", err)
	}
	if err := stdjson.Unmarshal(stdOut, &stdBack); err != nil {
		t.Fatalf("std Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(ourBack, stdBack) {
		t.Fatalf("round trip = %+v want %+v", ourBack, stdBack)
	}
	if ourBack.Skip != "" {
		t.Fatalf(`json:"-" field must be skipped, got %q`, ourBack.Skip)
	}
	// Case-insensitive alias matching, as in encoding/json. | 与 encoding/json 一样进行大小写
	// 不敏感的别名匹配。
	cased := []byte(`{"ID":1,"别名":"甲","renamed":"乙","quoted":"43","x":5}`)
	var ourCased, stdCased aliasTarget
	if err := json.Unmarshal(cased, &ourCased); err != nil {
		t.Fatalf("ydx Unmarshal cased: %v", err)
	}
	if err := stdjson.Unmarshal(cased, &stdCased); err != nil {
		t.Fatalf("std Unmarshal cased: %v", err)
	}
	if !reflect.DeepEqual(ourCased, stdCased) {
		t.Fatalf("cased value = %+v want %+v", ourCased, stdCased)
	}
}

// TestDuplicateJSONTagMatchesStdlib verifies duplicate tag names are ignored like encoding/json.
// The type is built with reflect so go vet does not flag the intentional duplicate tag. |
// TestDuplicateJSONTagMatchesStdlib 验证重复标签名与 encoding/json 一样被忽略。测试用反射构造类型，
// 避免 go vet 报告有意重复的标签。
func TestDuplicateJSONTagMatchesStdlib(t *testing.T) {
	typ := reflect.StructOf([]reflect.StructField{
		{Name: "A", Type: reflect.TypeOf(""), Tag: `json:"dup"`},
		{Name: "B", Type: reflect.TypeOf(""), Tag: `json:"dup"`},
		{Name: "C", Type: reflect.TypeOf(""), Tag: `json:"c"`},
	})
	val := reflect.New(typ).Elem()
	val.Field(0).SetString("a")
	val.Field(1).SetString("b")
	val.Field(2).SetString("c")
	ourOut, ourErr := json.Marshal(val.Interface())
	stdOut, stdErr := stdjson.Marshal(val.Interface())
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
}

// TestInvalidUTF8MatchesStdlib verifies invalid UTF-8 bytes are replaced by U+FFFD exactly like
// encoding/json, in strings, keys and RawMessage. | TestInvalidUTF8MatchesStdlib 验证字符串、键
// 与 RawMessage 中的非法 UTF-8 字节与 encoding/json 一样被替换为 U+FFFD。
func TestInvalidUTF8MatchesStdlib(t *testing.T) {
	bad := "a\xffb\xfe"
	ourOut, ourErr := json.Marshal(bad)
	stdOut, stdErr := stdjson.Marshal(bad)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
	raw := []byte("{\"k\xff\":\"v\xfe\"}")
	var ourMap, stdMap map[string]string
	if err := json.Unmarshal(raw, &ourMap); err != nil {
		t.Fatalf("ydx Unmarshal invalid UTF-8: %v", err)
	}
	if err := stdjson.Unmarshal(raw, &stdMap); err != nil {
		t.Fatalf("std Unmarshal invalid UTF-8: %v", err)
	}
	if !reflect.DeepEqual(ourMap, stdMap) {
		t.Fatalf("map = %#v want %#v", ourMap, stdMap)
	}
	// Invalid RawMessage input must fail with the standard *MarshalerError type on both sides. |
	// 非法 RawMessage 输入必须在两侧都以标准 *MarshalerError 类型失败。
	_, ourErr = json.Marshal(json.RawMessage("\xff"))
	_, stdErr = stdjson.Marshal(stdjson.RawMessage("\xff"))
	var ourME, stdME *stdjson.MarshalerError
	if !errors.As(ourErr, &ourME) || !errors.As(stdErr, &stdME) {
		t.Fatalf("RawMessage Marshal errors = (%v, %v), want *MarshalerError", ourErr, stdErr)
	}
}

// specialTag covers tag names with spaces, HTML metacharacters and reserved characters. The
// standard library ends the name at ',', '\”, '"', '\\' or '`', so the last two fields are
// named "pre" and "a". | specialTag 覆盖含空格、HTML 元字符与保留字符的标签名。标准库在
// ','、'\”、'"'、'\\' 或 '`' 处结束名称，因此最后两个字段名为 "pre" 与 "a"。
type specialTag struct {
	Space string `json:"a b"`
	Punct string `json:"<&>"`
	Trunc string `json:"pre\"post"`
	Quote string `json:"a'b"`
}

// TestJSONSpecialTagNamesMatchStdlib verifies special characters in tag names follow the same
// truncation and escaping rules as encoding/json. | TestJSONSpecialTagNamesMatchStdlib 验证标签名
// 中的特殊字符与 encoding/json 遵循相同的截断与转义规则。
func TestJSONSpecialTagNamesMatchStdlib(t *testing.T) {
	val := specialTag{Space: "s", Punct: "p", Trunc: "t", Quote: "q"}
	ourOut, ourErr := json.Marshal(val)
	stdOut, stdErr := stdjson.Marshal(val)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
	var ourBack, stdBack specialTag
	if err := json.Unmarshal(stdOut, &ourBack); err != nil {
		t.Fatalf("ydx Unmarshal: %v", err)
	}
	if err := stdjson.Unmarshal(stdOut, &stdBack); err != nil {
		t.Fatalf("std Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(ourBack, stdBack) {
		t.Fatalf("value = %+v want %+v", ourBack, stdBack)
	}
	// Encoder escaping options apply to field names as well as string values. |
	// Encoder 的转义选项同样作用于字段名，而不只是字符串值。
	for _, escape := range []bool{true, false} {
		var ourBuf, stdBuf bytes.Buffer
		ourEnc := json.NewEncoder(&ourBuf)
		stdEnc := stdjson.NewEncoder(&stdBuf)
		ourEnc.SetEscapeHTML(escape)
		stdEnc.SetEscapeHTML(escape)
		if err := ourEnc.Encode(val); err != nil {
			t.Fatalf("ydx Encode: %v", err)
		}
		if err := stdEnc.Encode(val); err != nil {
			t.Fatalf("std Encode: %v", err)
		}
		if ourBuf.String() != stdBuf.String() {
			t.Fatalf("escape=%v: Encode = %q want %q", escape, ourBuf.String(), stdBuf.String())
		}
	}
}
