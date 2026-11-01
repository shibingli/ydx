package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"fmt"
	"reflect"
	"strings"
	"testing"

	ydxml "github.com/shibingli/ydx/xml"
)

// apiDoc covers processing instructions, directives, comments, CDATA, entities, namespaces and
// nested elements. | apiDoc 覆盖处理指令、指令、注释、CDATA、实体、命名空间与嵌套元素。
const apiDoc = `<?xml version="1.0" encoding="UTF-8"?>
<?target inst?>
<!DOCTYPE root>
<root xmlns:x="urn:x" a="1">
  <!-- comment -->
  <item id="1">A &amp; B</item>
  <x:item id="2"><![CDATA[c<d]]></x:item>
</root>`

// TestStdlibTokenCompatibility compares Token and RawToken streams against encoding/xml. |
// TestStdlibTokenCompatibility 与 encoding/xml 对拍 Token 与 RawToken 流。
func TestStdlibTokenCompatibility(t *testing.T) {
	for _, doc := range []string{apiDoc, corpusXML} {
		ydxDec := ydxml.NewDecoderBytes([]byte(doc))
		stdDec := stdxml.NewDecoder(strings.NewReader(doc))
		for i := 0; ; i++ {
			yt, yerr := ydxDec.Token()
			st, serr := stdDec.Token()
			if (yerr == nil) != (serr == nil) {
				t.Fatalf("Token[%d]: err = %v want %v", i, yerr, serr)
			}
			if yerr != nil {
				break
			}
			if yk, sk := tokenKey(yt), tokenKey(st); yk != sk {
				t.Fatalf("Token[%d] = %s want %s", i, yk, sk)
			}
		}
	}
	// RawToken keeps entity references and raw text identical to the standard library. |
	// RawToken 保留实体引用与原始文本，与标准库一致。
	for _, doc := range []string{apiDoc, corpusXML} {
		ydxDec := ydxml.NewDecoderBytes([]byte(doc))
		stdDec := stdxml.NewDecoder(strings.NewReader(doc))
		for i := 0; ; i++ {
			yt, yerr := ydxDec.RawToken()
			st, serr := stdDec.RawToken()
			if (yerr == nil) != (serr == nil) {
				t.Fatalf("RawToken[%d]: err = %v want %v", i, yerr, serr)
			}
			if yerr != nil {
				break
			}
			if yk, sk := tokenKey(yt), tokenKey(st); yk != sk {
				t.Fatalf("RawToken[%d] = %s want %s", i, yk, sk)
			}
		}
	}
}

// tokenKey renders a token from either XML package in a comparable form. | tokenKey 把任一 XML 包的
// 记号渲染为可比较的文本。
func tokenKey(tok any) string {
	switch v := tok.(type) {
	case ydxml.StartElement:
		return "S" + nameKey(v.Name) + attrsKey(v.Attr, true)
	case stdxml.StartElement:
		return "S" + stdNameKey(v.Name) + attrsKey(v.Attr, false)
	case ydxml.EndElement:
		return "E" + nameKey(v.Name)
	case stdxml.EndElement:
		return "E" + stdNameKey(v.Name)
	case ydxml.CharData:
		return "C" + string(v)
	case stdxml.CharData:
		return "C" + string(v)
	case ydxml.Comment:
		return "M" + string(v)
	case stdxml.Comment:
		return "M" + string(v)
	case ydxml.ProcInst:
		return "P" + v.Target + " " + string(v.Inst)
	case stdxml.ProcInst:
		return "P" + v.Target + " " + string(v.Inst)
	case ydxml.Directive:
		return "D" + string(v)
	case stdxml.Directive:
		return "D" + string(v)
	default:
		return fmt.Sprintf("?%T", tok)
	}
}

func nameKey(n ydxml.Name) string { return "{" + n.Space + "}" + n.Local }

func stdNameKey(n stdxml.Name) string { return "{" + n.Space + "}" + n.Local }

func attrsKey(attrs any, ydx bool) string {
	var b strings.Builder
	if ydx {
		for _, a := range attrs.([]ydxml.Attr) {
			b.WriteString(" " + nameKey(a.Name) + "=" + a.Value)
		}
		return b.String()
	}
	for _, a := range attrs.([]stdxml.Attr) {
		b.WriteString(" " + stdNameKey(a.Name) + "=" + a.Value)
	}
	return b.String()
}

// ydxCatalog mirrors the corpus structure using ydx/xml types. | ydxCatalog 使用 ydx/xml 类型镜像
// 语料结构。
type ydxCatalog struct {
	Books []ydxBook `xml:"book"`
}

type ydxBook struct {
	ID    string  `xml:"id,attr"`
	Title string  `xml:"title"`
	Price float64 `xml:"price"`
}

// stdCatalog mirrors ydxCatalog using encoding/xml types. | stdCatalog 使用 encoding/xml 类型镜像
// ydxCatalog。
type stdCatalog struct {
	Books []stdBook `xml:"book"`
}

type stdBook struct {
	ID    string  `xml:"id,attr"`
	Title string  `xml:"title"`
	Price float64 `xml:"price"`
}

// TestStdlibUnmarshalCompatibility compares struct decoding with encoding/xml. |
// TestStdlibUnmarshalCompatibility 与 encoding/xml 对拍结构体解码。
func TestStdlibUnmarshalCompatibility(t *testing.T) {
	var ydxDoc ydxCatalog
	var stdDoc stdCatalog
	if err := ydxml.Unmarshal([]byte(corpusXML), &ydxDoc); err != nil {
		t.Fatalf("ydx Unmarshal: %v", err)
	}
	if err := stdxml.Unmarshal([]byte(corpusXML), &stdDoc); err != nil {
		t.Fatalf("std Unmarshal: %v", err)
	}
	if len(ydxDoc.Books) != len(stdDoc.Books) {
		t.Fatalf("book count = %d want %d", len(ydxDoc.Books), len(stdDoc.Books))
	}
	for i := range ydxDoc.Books {
		y, s := ydxDoc.Books[i], stdDoc.Books[i]
		if y.ID != s.ID || y.Title != s.Title || y.Price != s.Price {
			t.Fatalf("book[%d] = %+v want %+v", i, y, s)
		}
	}
}

// ydxOut and stdOut mirror each other for encoding tests. | ydxOut 与 stdOut 在编码测试中互为镜像。
type ydxOut struct {
	XMLName ydxml.Name `xml:"root"`
	ID      int        `xml:"id,attr"`
	Title   string     `xml:"title"`
	Tags    []string   `xml:"tags>tag"`
}

type stdOut struct {
	XMLName stdxml.Name `xml:"root"`
	ID      int         `xml:"id,attr"`
	Title   string      `xml:"title"`
	Tags    []string    `xml:"tags>tag"`
}

// TestStdlibMarshalCompatibility compares Marshal and Encoder output with encoding/xml. |
// TestStdlibMarshalCompatibility 与 encoding/xml 对拍 Marshal 与 Encoder 输出。
func TestStdlibMarshalCompatibility(t *testing.T) {
	ydxVal := ydxOut{ID: 7, Title: "A & B <c>", Tags: []string{"x", "y"}}
	stdVal := stdOut{ID: 7, Title: "A & B <c>", Tags: []string{"x", "y"}}
	ydxBytes, err := ydxml.Marshal(ydxVal)
	if err != nil {
		t.Fatalf("ydx Marshal: %v", err)
	}
	stdBytes, err := stdxml.Marshal(stdVal)
	if err != nil {
		t.Fatalf("std Marshal: %v", err)
	}
	if !bytes.Equal(ydxBytes, stdBytes) {
		t.Fatalf("Marshal = %q want %q", ydxBytes, stdBytes)
	}

	var ydxBuf, stdBuf bytes.Buffer
	ydxEnc := ydxml.NewEncoder(&ydxBuf)
	stdEnc := stdxml.NewEncoder(&stdBuf)
	ydxEnc.Indent("", "  ")
	stdEnc.Indent("", "  ")
	if err := ydxEnc.Encode(ydxVal); err != nil {
		t.Fatalf("ydx Encode: %v", err)
	}
	if err := stdEnc.Encode(stdVal); err != nil {
		t.Fatalf("std Encode: %v", err)
	}
	if ydxBuf.String() != stdBuf.String() {
		t.Fatalf("Encode = %q want %q", ydxBuf.String(), stdBuf.String())
	}

	ydxIndented, err := ydxml.MarshalIndent(ydxVal, "", "\t")
	if err != nil {
		t.Fatalf("ydx MarshalIndent: %v", err)
	}
	stdIndented, err := stdxml.MarshalIndent(stdVal, "", "\t")
	if err != nil {
		t.Fatalf("std MarshalIndent: %v", err)
	}
	if !bytes.Equal(ydxIndented, stdIndented) {
		t.Fatalf("MarshalIndent = %q want %q", ydxIndented, stdIndented)
	}
}

// TestStdlibEscapeCompatibility compares EscapeText output with encoding/xml. |
// TestStdlibEscapeCompatibility 与 encoding/xml 对拍 EscapeText 输出。
func TestStdlibEscapeCompatibility(t *testing.T) {
	inputs := []string{"", "plain", "A & B <c> \"q\" 'x'", "line\r\nbreak\tend", "é中"}
	for _, in := range inputs {
		var ydxBuf, stdBuf bytes.Buffer
		if err := ydxml.EscapeText(&ydxBuf, []byte(in)); err != nil {
			t.Fatalf("%q: ydx EscapeText: %v", in, err)
		}
		if err := stdxml.EscapeText(&stdBuf, []byte(in)); err != nil {
			t.Fatalf("%q: std EscapeText: %v", in, err)
		}
		if ydxBuf.String() != stdBuf.String() {
			t.Fatalf("%q: EscapeText = %q want %q", in, ydxBuf.String(), stdBuf.String())
		}
	}
	if ydxml.Header != stdxml.Header {
		t.Fatalf("Header = %q want %q", ydxml.Header, stdxml.Header)
	}
}

// TestDOMAgainstStdlibTokens verifies that the DOM text matches values decoded by the standard
// library token stream. | TestDOMAgainstStdlibTokens 验证 DOM 文本与标准库记号流解码出的值一致。
func TestDOMAgainstStdlibTokens(t *testing.T) {
	doc, err := ydxml.Parse([]byte(corpusXML))
	if err != nil {
		t.Fatalf("ydx Parse: %v", err)
	}
	path, err := ydxml.Compile("//book/title")
	if err != nil {
		t.Fatalf("ydx Compile: %v", err)
	}
	ydxTitles := doc.Values(path)

	var stdTitles []string
	dec := stdxml.NewDecoder(strings.NewReader(corpusXML))
	inTitle := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch v := tok.(type) {
		case stdxml.StartElement:
			if v.Name.Local == "title" {
				inTitle++
			}
		case stdxml.EndElement:
			if v.Name.Local == "title" {
				inTitle--
			}
		case stdxml.CharData:
			if inTitle > 0 {
				stdTitles = append(stdTitles, string(v))
			}
		}
	}
	if !reflect.DeepEqual(ydxTitles, stdTitles) {
		t.Fatalf("DOM titles = %#v want %#v", ydxTitles, stdTitles)
	}
}

// unicodeXML covers CJK element/attribute names and text, emoji, numeric character references,
// comments, CDATA and processing instructions. | unicodeXML 覆盖 CJK 元素/属性名与文本、表情符号、
// 数字字符引用、注释、CDATA 与处理指令。
const unicodeXML = `<?xml version="1.0" encoding="UTF-8"?>
<?pi 中文?>
<目录 类型="书籍">
  <!-- 注释 😀 -->
  <条目 编号="1">中文 &amp; 表情 😀🚀</条目>
  <条目 编号="2"><![CDATA[<中文>&😀]]></条目>
  <数值>&#x4E2D;&#25991;&#128512;</数值>
</目录>`

// TestUnicodeTokenCompatibility compares Token and RawToken streams for non-ASCII documents. |
// TestUnicodeTokenCompatibility 对拍非 ASCII 文档的 Token 与 RawToken 流。
func TestUnicodeTokenCompatibility(t *testing.T) {
	for _, raw := range []bool{false, true} {
		ydxDec := ydxml.NewDecoderBytes([]byte(unicodeXML))
		stdDec := stdxml.NewDecoder(strings.NewReader(unicodeXML))
		for i := 0; ; i++ {
			var yt, st any
			var yerr, serr error
			if raw {
				yt, yerr = ydxDec.RawToken()
				st, serr = stdDec.RawToken()
			} else {
				yt, yerr = ydxDec.Token()
				st, serr = stdDec.Token()
			}
			if (yerr == nil) != (serr == nil) {
				t.Fatalf("raw=%v token[%d]: err = %v want %v", raw, i, yerr, serr)
			}
			if yerr != nil {
				break
			}
			if yk, sk := tokenKey(yt), tokenKey(st); yk != sk {
				t.Fatalf("raw=%v token[%d] = %s want %s", raw, i, yk, sk)
			}
		}
	}
}

// compatItem and compatDoc use CJK tag aliases; the same struct can be encoded by both
// packages because the tags are plain strings. | compatItem 与 compatDoc 使用 CJK 标签别名；
// 标签是纯字符串，因此同一结构体可被两个包编码。
type compatItem struct {
	ID   string `xml:"编号,attr"`
	Text string `xml:",chardata"`
}

type compatDoc struct {
	Type  string       `xml:"类型,attr"`
	Items []compatItem `xml:"条目"`
}

// TestUnicodeMarshalCompatibility compares Marshal, MarshalIndent and Unmarshal for CJK tag
// aliases and unicode content. | TestUnicodeMarshalCompatibility 对拍 CJK 标签别名与 Unicode
// 内容的 Marshal、MarshalIndent 与 Unmarshal。
func TestUnicodeMarshalCompatibility(t *testing.T) {
	val := compatDoc{
		Type: "书籍 & <测试>",
		Items: []compatItem{
			{ID: "1", Text: "中文 😀 & <x>"},
			{ID: "2", Text: "数据 🚀"},
		},
	}
	ourOut, ourErr := ydxml.Marshal(val)
	stdOut, stdErr := stdxml.Marshal(val)
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourOut, stdOut) {
		t.Fatalf("Marshal = (%q, %v) want (%q, %v)", ourOut, ourErr, stdOut, stdErr)
	}
	ourIndent, ourErr := ydxml.MarshalIndent(val, "", "  ")
	stdIndent, stdErr := stdxml.MarshalIndent(val, "", "  ")
	if ourErr != nil || stdErr != nil || !bytes.Equal(ourIndent, stdIndent) {
		t.Fatalf("MarshalIndent = (%q, %v) want (%q, %v)", ourIndent, ourErr, stdIndent, stdErr)
	}
	var ourBack, stdBack compatDoc
	if err := ydxml.Unmarshal(ourOut, &ourBack); err != nil {
		t.Fatalf("ydx Unmarshal: %v", err)
	}
	if err := stdxml.Unmarshal(ourOut, &stdBack); err != nil {
		t.Fatalf("std Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(ourBack, stdBack) {
		t.Fatalf("value = %+v want %+v", ourBack, stdBack)
	}
}

// TestUnicodeEscapeCompatibility compares EscapeText for unicode, control and invalid UTF-8
// input. | TestUnicodeEscapeCompatibility 对拍 Unicode、控制字符与非法 UTF-8 输入的 EscapeText。
func TestUnicodeEscapeCompatibility(t *testing.T) {
	inputs := [][]byte{
		[]byte(""),
		[]byte("中文 😀 موسيقى"),
		[]byte(`<>"'&` + "\t\n\r"),
		[]byte("\u2028\u2029"),
		{0xff, 0xfe, 0x80},
	}
	for _, in := range inputs {
		var ourBuf, stdBuf bytes.Buffer
		if err := ydxml.EscapeText(&ourBuf, in); err != nil {
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
