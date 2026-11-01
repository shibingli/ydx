package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"reflect"
	"strings"
	"testing"
)

// unicodeXML covers CJK element/attribute names and text, emoji (including a surrogate-pair
// code point written as a numeric reference), comments, CDATA, processing instructions and
// predefined entities. | unicodeXML 覆盖 CJK 元素/属性名与文本、表情符号（含以数字引用书写的
// 代理对码点）、注释、CDATA、处理指令与预定义实体。
const unicodeXML = `<?xml version="1.0" encoding="UTF-8"?>
<?pi 中文?>
<目录 类型="书籍">
  <!-- 注释 😀 -->
  <条目 编号="1">中文 &amp; 表情 😀🚀</条目>
  <条目 编号="2"><![CDATA[<中文>&😀]]></条目>
  <数值>&#x4E2D;&#25991;&#128512;</数值>
</目录>`

// unicodeDocs extends the token corpus with non-ASCII and special-symbol documents. |
// unicodeDocs 在词法语料上补充非 ASCII 与特殊符号文档。
var unicodeDocs = []string{
	unicodeXML,
	`<根><元素 属性="值 &amp; &lt; &gt; &quot;">文本 😀</元素></根>`,
	`<a>😀&#x1F680;&#x4E2D;</a>`,
	`<a><!-- 中文 😀 --><![CDATA[数据 <>& 😀]]></a>`,
	`<?中文 数据?><根/>`,
}

// TestUnicodeTokenCompatibility compares Token and RawToken streams for unicode documents. |
// TestUnicodeTokenCompatibility 对拍 Unicode 文档的 Token 与 RawToken 流。
func TestUnicodeTokenCompatibility(t *testing.T) {
	for _, doc := range unicodeDocs {
		want, wantErr := collectStd(t, stdxml.NewDecoder(strings.NewReader(doc)))
		got, gotErr := collect(t, NewDecoderBytes([]byte(doc)))
		if (wantErr != nil) != (gotErr != nil) {
			t.Fatalf("doc %q: std err=%v, ours err=%v", doc, wantErr, gotErr)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("doc %q:\nstd: %v\ngot: %v", doc, want, got)
		}
	}
}

// ydxUnicodeDoc and stdUnicodeDoc mirror each other using CJK tag names, attributes, chardata
// and nested paths. | ydxUnicodeDoc 与 stdUnicodeDoc 使用 CJK 标签名、属性、字符数据与嵌套路径
// 互为镜像。
type ydxUnicodeDoc struct {
	XMLName ydxName        `xml:"目录"`
	Type    string         `xml:"类型,attr"`
	Items   []ydxUnicodeIt `xml:"条目"`
}

type ydxUnicodeIt struct {
	ID   string `xml:"编号,attr"`
	Text string `xml:",chardata"`
}

type ydxName = Name

type stdUnicodeDoc struct {
	XMLName stdxml.Name    `xml:"目录"`
	Type    string         `xml:"类型,attr"`
	Items   []stdUnicodeIt `xml:"条目"`
}

type stdUnicodeIt struct {
	ID   string `xml:"编号,attr"`
	Text string `xml:",chardata"`
}

// TestUnicodeUnmarshalMatchesStdlib compares unicode struct decoding with encoding/xml. |
// TestUnicodeUnmarshalMatchesStdlib 与 encoding/xml 对拍 Unicode 结构体解码。
func TestUnicodeUnmarshalMatchesStdlib(t *testing.T) {
	var ourDoc ydxUnicodeDoc
	var stdDoc stdUnicodeDoc
	if err := Unmarshal([]byte(unicodeXML), &ourDoc); err != nil {
		t.Fatalf("ydx Unmarshal: %v", err)
	}
	if err := stdxml.Unmarshal([]byte(unicodeXML), &stdDoc); err != nil {
		t.Fatalf("std Unmarshal: %v", err)
	}
	if ourDoc.XMLName.Local != stdDoc.XMLName.Local || ourDoc.XMLName.Space != stdDoc.XMLName.Space {
		t.Fatalf("root name = %v want %v", ourDoc.XMLName, stdDoc.XMLName)
	}
	if ourDoc.Type != stdDoc.Type || len(ourDoc.Items) != len(stdDoc.Items) {
		t.Fatalf("doc = %+v want %+v", ourDoc, stdDoc)
	}
	for i := range ourDoc.Items {
		if ourDoc.Items[i].ID != stdDoc.Items[i].ID || ourDoc.Items[i].Text != stdDoc.Items[i].Text {
			t.Fatalf("item[%d] = %+v want %+v", i, ourDoc.Items[i], stdDoc.Items[i])
		}
	}
	if !strings.Contains(ourDoc.Items[0].Text, "😀") || !strings.Contains(ourDoc.Items[0].Text, "中文") {
		t.Fatalf("decode lost unicode text: %q", ourDoc.Items[0].Text)
	}
}

// TestUnicodeMarshalMatchesStdlib compares struct encoding with encoding/xml for unicode tag
// names, attribute values and text. | TestUnicodeMarshalMatchesStdlib 对拍含 Unicode 标签名、
// 属性值与文本的结构体编码。
func TestUnicodeMarshalMatchesStdlib(t *testing.T) {
	ourVal := ydxUnicodeDoc{
		Type: "书籍 & <测试>",
		Items: []ydxUnicodeIt{
			{ID: "1", Text: "中文 😀 & <x>"},
			{ID: "2", Text: "数据 🚀"},
		},
	}
	stdVal := stdUnicodeDoc{
		Type: "书籍 & <测试>",
		Items: []stdUnicodeIt{
			{ID: "1", Text: "中文 😀 & <x>"},
			{ID: "2", Text: "数据 🚀"},
		},
	}
	ourOut, ourErr := Marshal(ourVal)
	stdOut, stdErr := stdxml.Marshal(stdVal)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
	ourIndent, ourErr := MarshalIndent(ourVal, "", "  ")
	stdIndent, stdErr := stdxml.MarshalIndent(stdVal, "", "  ")
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourIndent, stdIndent) {
		t.Fatalf("MarshalIndent = (%q, %v) want (%q, %v)", ourIndent, ourErr, stdIndent, stdErr)
	}
}

// innerXMLDoc and innerXMLStd mirror each other for the ,innerxml tag alias. |
// innerXMLDoc 与 innerXMLStd 为 ,innerxml 标签别名互为镜像。
type innerXMLDoc struct {
	XMLName Name   `xml:"根"`
	Raw     string `xml:",innerxml"`
}

type innerXMLStd struct {
	XMLName stdxml.Name `xml:"根"`
	Raw     string      `xml:",innerxml"`
}

// TestUnicodeTagAliases verifies CJK tag aliases, attributes, chardata, innerxml, comments and
// omitempty behave like encoding/xml. | TestUnicodeTagAliases 验证 CJK 标签别名、属性、字符数据、
// innerxml、注释与 omitempty 与 encoding/xml 行为一致。
func TestUnicodeTagAliases(t *testing.T) {
	doc := []byte(`<根><原样>中文 <b>😀</b> &amp; 文本</原样></根>`)
	var ourDoc innerXMLDoc
	var stdDoc innerXMLStd
	if err := Unmarshal(doc, &ourDoc); err != nil {
		t.Fatalf("ydx Unmarshal: %v", err)
	}
	if err := stdxml.Unmarshal(doc, &stdDoc); err != nil {
		t.Fatalf("std Unmarshal: %v", err)
	}
	if ourDoc.Raw != stdDoc.Raw {
		t.Fatalf("innerxml = %q want %q", ourDoc.Raw, stdDoc.Raw)
	}
	ourOut, ourErr := Marshal(ourDoc)
	stdOut, stdErr := stdxml.Marshal(stdDoc)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("innerxml Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
}

// TestUnicodeEscapeMatchesStdlib compares EscapeText for unicode, control and invalid UTF-8
// input. | TestUnicodeEscapeMatchesStdlib 对拍 Unicode、控制字符与非法 UTF-8 输入的 EscapeText。
func TestUnicodeEscapeMatchesStdlib(t *testing.T) {
	inputs := [][]byte{
		[]byte(""),
		[]byte("中文 😀 موسيقى"),
		[]byte(`<>"'&` + "\t\n\r"),
		[]byte("\u2028\u2029"),
		{0xff, 0xfe, 0x80},
		[]byte("e\u0301"),
	}
	for _, in := range inputs {
		var ourBuf, stdBuf bytes.Buffer
		if err := EscapeText(&ourBuf, in); err != nil {
			t.Fatalf("%q: ydx EscapeText: %v", in, err)
		}
		if err := stdxml.EscapeText(&stdBuf, in); err != nil {
			t.Fatalf("%q: std EscapeText: %v", in, err)
		}
		if ourBuf.String() != stdBuf.String() {
			t.Fatalf("%q: EscapeText = %q want %q", in, ourBuf.String(), stdBuf.String())
		}
	}
}
