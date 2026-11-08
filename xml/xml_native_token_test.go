package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func normalizeToken(t Token) string {
	switch t := t.(type) {
	case StartElement:
		var b strings.Builder
		fmt.Fprintf(&b, "S{%q,%q}[", t.Name.Space, t.Name.Local)
		for _, a := range t.Attr {
			fmt.Fprintf(&b, "{%q,%q}=%q;", a.Name.Space, a.Name.Local, a.Value)
		}
		b.WriteString("]")
		return b.String()
	case EndElement:
		return fmt.Sprintf("E{%q,%q}", t.Name.Space, t.Name.Local)
	case CharData:
		return fmt.Sprintf("C%q", string(t))
	case Comment:
		return fmt.Sprintf("M%q", string(t))
	case ProcInst:
		return fmt.Sprintf("P%q,%q", t.Target, string(t.Inst))
	case Directive:
		return fmt.Sprintf("D%q", string(t))
	default:
		return fmt.Sprintf("?%T", t)
	}
}

func stdToken(t stdxml.Token) Token {
	switch t := t.(type) {
	case stdxml.StartElement:
		attrs := make([]Attr, len(t.Attr))
		for i, a := range t.Attr {
			attrs[i] = Attr{Name: Name{Space: a.Name.Space, Local: a.Name.Local}, Value: a.Value}
		}
		return StartElement{Name: Name{Space: t.Name.Space, Local: t.Name.Local}, Attr: attrs}
	case stdxml.EndElement:
		return EndElement{Name: Name{Space: t.Name.Space, Local: t.Name.Local}}
	case stdxml.CharData:
		return CharData(append([]byte(nil), t...))
	case stdxml.Comment:
		return Comment(append([]byte(nil), t...))
	case stdxml.ProcInst:
		return ProcInst{Target: t.Target, Inst: append([]byte(nil), t.Inst...)}
	case stdxml.Directive:
		return Directive(append([]byte(nil), t...))
	}
	return nil
}

func collect(t *testing.T, d *Decoder) ([]string, error) {
	t.Helper()
	var out []string
	for i := 0; i < 100000; i++ {
		tok, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, normalizeToken(tok))
	}
	t.Fatal("token stream did not terminate")
	return nil, nil
}

func collectStd(t *testing.T, d *stdxml.Decoder) ([]string, error) {
	t.Helper()
	var out []string
	for i := 0; i < 100000; i++ {
		tok, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, normalizeToken(stdToken(tok)))
	}
	t.Fatal("token stream did not terminate")
	return nil, nil
}

var tokenCorpus = []string{
	`<a>x</a>`,
	`<a><b c="d" e='f'/>text</a>`,
	`<?xml version="1.0" encoding="UTF-8"?><root xmlns="urn:d" xmlns:p="urn:p"><p:a p:x="1" y="2">t&amp;u</p:a></root>`,
	`<a><!-- c --><![CDATA[ x<y ]]>&#65;&#x42;</a>`,
	"<a>line1\r\nline2\rend</a>",
	`<a b="1" c = "2" ></a>`,
	`<a><b></b><c/></a>`,
	`<?pi data?><a/>`,
	`<a xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:lang="en"/>`,
	`<a>  leading and trailing  </a>`,
	`<a x="&#x9;&#xA;&#xD;">&#9;&#10;&#13;</a>`,
	`<root><a>1</a><a>2</a><b><a>3</a></b></root>`,
	"\xEF\xBB\xBF<a>bom</a>",
	`<a xmlns=""><b xmlns="urn:x"><c/></b><d/></a>`,
	`<a b="a&amp;b&lt;c&gt;d&quot;e&apos;f"/>`,
	`<a><![CDATA[]]></a>`,
	`<!---->`,
	`<?pi?>`,
	`<!x>`,
	`<! >`,
	`<!-- before --><a/><!-- after -->`,
	`<?xml version='1.0'?><a/>`,
}

func TestTokenMatchesStdlib(t *testing.T) {
	for _, doc := range tokenCorpus {
		want, wantErr := collectStd(t, stdxml.NewDecoder(strings.NewReader(doc)))
		got, gotErr := collect(t, NewDecoderBytes([]byte(doc)))
		if (wantErr != nil) != (gotErr != nil) {
			t.Errorf("doc %q: std err=%v, ours err=%v", doc, wantErr, gotErr)
			continue
		}
		if len(want) != len(got) {
			t.Errorf("doc %q: token count %d != %d\nstd: %v\ngot: %v", doc, len(want), len(got), want, got)
			continue
		}
		for i := range want {
			if want[i] != got[i] {
				t.Errorf("doc %q token %d: std %s, ours %s", doc, i, want[i], got[i])
			}
		}
	}
}

func TestTokenMatchesStdlibReaderChunks(t *testing.T) {
	for _, doc := range tokenCorpus {
		want, _ := collectStd(t, stdxml.NewDecoder(strings.NewReader(doc)))
		for _, chunk := range []int{1, 2, 3, 7, 16} {
			got, err := collect(t, NewDecoder(&chunkReader{data: []byte(doc), n: chunk}))
			if err != nil {
				t.Errorf("doc %q chunk %d: unexpected error %v", doc, chunk, err)
				continue
			}
			if len(want) != len(got) {
				t.Errorf("doc %q chunk %d: token count %d != %d\nwant %v\ngot %v", doc, chunk, len(want), len(got), want, got)
				continue
			}
			for i := range want {
				if want[i] != got[i] {
					t.Errorf("doc %q chunk %d token %d: std %s, ours %s", doc, chunk, i, want[i], got[i])
				}
			}
		}
	}
}

func TestRawTokenMatchesStdlib(t *testing.T) {
	for _, doc := range tokenCorpus {
		var want []string
		sd := stdxml.NewDecoder(strings.NewReader(doc))
		for {
			tok, err := sd.RawToken()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			want = append(want, normalizeToken(stdToken(tok)))
		}
		got, _ := collectRaw(t, NewDecoderBytes([]byte(doc)))
		if len(want) != len(got) {
			t.Errorf("doc %q: raw token count %d != %d\nstd %v\nours %v", doc, len(want), len(got), want, got)
			continue
		}
		for i := range want {
			if want[i] != got[i] {
				t.Errorf("doc %q raw token %d: std %s, ours %s", doc, i, want[i], got[i])
			}
		}
	}
}

func collectRaw(t *testing.T, d *Decoder) ([]string, error) {
	t.Helper()
	var out []string
	for {
		tok, err := d.RawToken()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, normalizeToken(tok))
	}
}

func TestTokenErrorOnMalformed(t *testing.T) {
	cases := []string{
		`<a>`,
		`<a></b>`,
		`<a b=c/>`,
		`<a>&unknown;</a>`,
		`<a>]]></a>`,
		`<a><!-- x -- y --></a>`,
		`<a><b></a></b>`,
		`</a>`,
	}
	for _, doc := range cases {
		_, err := collect(t, NewDecoderBytes([]byte(doc)))
		if err == nil {
			t.Errorf("doc %q: expected error", doc)
		}
	}
}

func TestDecoderReaderMatchesBytes(t *testing.T) {
	doc := `<root xmlns:p="urn:p"><p:a x="1">t&amp;u</p:a><b>  spaced  </b></root>`
	b, _ := collect(t, NewDecoderBytes([]byte(doc)))
	r, err := collect(t, NewDecoder(bytes.NewReader([]byte(doc))))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(b, "|") != strings.Join(r, "|") {
		t.Fatalf("reader tokens differ\nbytes: %v\nreader: %v", b, r)
	}
}

// malformedCorpus exercises lexical and structural edge cases where encoding/xml still returns a
// token stream rather than an error, so malformed-input closeness is observable. | malformedCorpus
// 覆盖 encoding/xml 仍返回 token 流而非报错的词法与结构边界，使畸形输入的接近程度可观测。
var malformedCorpus = []string{
	`<a b=c/>`, `<a b=c d=e></a>`, `<a b c="1"/>`, `<a b=>`, `<a "x"/>`,
	`<a b="<"/>`, `<a b='&#x;'/>`, `<a b="]]>"/>`,
	`<a><![CDATA[x]]></a>`, `<a><![CDATA[x</a>`,
	`<a><!-- -- --></a>`, `<!---->`, `<!-->`, `<!--->`,
	`<?xml version="1.0"?>`, `<?pi?>`, `<?pi`, `<?xml?><a/>`,
	`<!DOCTYPE a><!DOCTYPE b><a/>`,
	`<!>`, `<!><a/>`, `<! >`, `<!x>`, `<!<!--c-->y>`, `<!'x>y'>`, `<! "x>y" >`, `<!<x>y>`,
	`<a xmlns:p="u"><p:b></p:b></a>`,
	`<a xmlns:p="u" xmlns:q="u"><p:b q:c="1"/></a>`,
	`<>`, `</>`, `<a/>junk`, `junk<a/>`,
	"<a>\r</a>", "<a>\r\n</a>", "<a b=\"x\r\ny\"/>",
	`<a>&#x41</a>`, `<a>&#65</a>`, `<a>]></a>`, `<a>&lt;</a>`,
	"\xEF\xBB\xBF<a/>", "<a>\x00</a>", "<a b=\"x\x00y\"/>",
	`<a></a >`, `</ a>`, `< a/>`, `<a b = "1"/>`,
	`<?xml version="1.1"?><a/>`, `<?xml version="1.0" encoding="utf-8"?><a/>`,
	`<?xml version="1.0" encoding="UTF-8 "?><a/>`,
	`<a xml:lang="en" xml:space="preserve"/>`,
	`<a xmlns:xml="urn:wrong"/>`,
	`<a xmlns:p=""/>`,
	`<a xmlns:xmlns="urn:x"/>`,
	`<a b="&#xD800;"/>`,
	`<a><?xml version="1.0"?></a>`,
}

// TestMalformedCorpusMatchesStdlib verifies token-level closeness with encoding/xml on malformed
// input in both strict and lenient modes. | TestMalformedCorpusMatchesStdlib 验证严格与宽松模式下
// 畸形输入与 encoding/xml 的 token 级接近程度。
func TestMalformedCorpusMatchesStdlib(t *testing.T) {
	for _, doc := range malformedCorpus {
		for _, strict := range []bool{true, false} {
			sd := stdxml.NewDecoder(strings.NewReader(doc))
			sd.Strict = strict
			want, wantErr := collectStd(t, sd)
			od := NewDecoderBytes([]byte(doc))
			od.Strict = strict
			got, gotErr := collect(t, od)
			if (wantErr != nil) != (gotErr != nil) {
				t.Errorf("doc %q strict=%v: std err=%v, ours err=%v", doc, strict, wantErr, gotErr)
				continue
			}
			if len(want) != len(got) {
				t.Errorf("doc %q strict=%v: token count %d != %d\nstd: %v\ngot: %v",
					doc, strict, len(want), len(got), want, got)
				continue
			}
			for i := range want {
				if want[i] != got[i] {
					t.Errorf("doc %q strict=%v token %d: std %s, ours %s", doc, strict, i, want[i], got[i])
				}
			}
		}
	}
}

func stdTokenNil(t stdxml.Token) (nilSlice, empty bool, ok bool) {
	switch t := t.(type) {
	case stdxml.CharData:
		return t == nil, len(t) == 0, true
	case stdxml.Comment:
		return t == nil, len(t) == 0, true
	case stdxml.ProcInst:
		return t.Inst == nil, len(t.Inst) == 0, true
	case stdxml.Directive:
		return t == nil, len(t) == 0, true
	}
	return false, false, false
}

func ourTokenNil(t Token) (nilSlice, empty bool, ok bool) {
	switch t := t.(type) {
	case CharData:
		return t == nil, len(t) == 0, true
	case Comment:
		return t == nil, len(t) == 0, true
	case ProcInst:
		return t.Inst == nil, len(t.Inst) == 0, true
	case Directive:
		return t == nil, len(t) == 0, true
	}
	return false, false, false
}

// TestEmptyTokenSlicesMatchStdlib checks that empty comments, processing instructions, CDATA and
// directives preserve encoding/xml's nil-versus-empty slice distinction. | TestEmptyTokenSlicesMatchStdlib
// 检查空注释、处理指令、CDATA 与指令保留 encoding/xml 的 nil 与非 nil 空切片区别。
func TestEmptyTokenSlicesMatchStdlib(t *testing.T) {
	docs := []string{
		`<!---->`,
		`<?pi?>`,
		`<a><![CDATA[]]></a>`,
		`<a></a>`,
		"<a>\r</a>",
	}
	for _, doc := range docs {
		sd := stdxml.NewDecoder(strings.NewReader(doc))
		od := NewDecoderBytes([]byte(doc))
		for i := 0; ; i++ {
			st, serr := sd.Token()
			ot, oerr := od.Token()
			if (serr == nil) != (oerr == nil) {
				t.Fatalf("doc %q token %d: std err=%v ours err=%v", doc, i, serr, oerr)
			}
			if serr != nil {
				break
			}
			wNil, wEmpty, wOK := stdTokenNil(st)
			gNil, gEmpty, gOK := ourTokenNil(ot)
			if wOK != gOK {
				t.Fatalf("doc %q token %d: nil-shape kinds differ: std %T ours %T", doc, i, st, ot)
			}
			if wOK && (wNil != gNil || wEmpty != gEmpty) {
				t.Errorf("doc %q token %d: std nil=%v empty=%v, ours nil=%v empty=%v",
					doc, i, wNil, wEmpty, gNil, gEmpty)
			}
		}
	}
}

// TestCopyPreservesEmptySlices verifies Copy keeps nil versus empty slices. | TestCopyPreservesEmptySlices
// 验证 Copy 保持 nil 与非 nil 空切片。
func TestCopyPreservesEmptySlices(t *testing.T) {
	emptyCharData := CharData{}
	if got := emptyCharData.Copy().(CharData); got == nil || len(got) != 0 {
		t.Errorf("empty CharData copy = %#v, want non-nil empty", got)
	}
	if got := CharData(nil).Copy().(CharData); got != nil {
		t.Errorf("nil CharData copy = %#v, want nil", got)
	}
	emptyComment := Comment{}
	if got := emptyComment.Copy().(Comment); got == nil || len(got) != 0 {
		t.Errorf("empty Comment copy = %#v, want non-nil empty", got)
	}
	if got := Comment(nil).Copy().(Comment); got != nil {
		t.Errorf("nil Comment copy = %#v, want nil", got)
	}
	emptyDirective := Directive{}
	if got := emptyDirective.Copy().(Directive); got == nil || len(got) != 0 {
		t.Errorf("empty Directive copy = %#v, want non-nil empty", got)
	}
	nilPI := ProcInst{Target: "p"}
	if got := nilPI.Copy().(ProcInst); got.Inst != nil {
		t.Errorf("nil ProcInst.Inst copy = %#v, want nil", got.Inst)
	}
	emptyPI := ProcInst{Target: "p", Inst: []byte{}}
	if got := emptyPI.Copy().(ProcInst); got.Inst == nil || len(got.Inst) != 0 {
		t.Errorf("empty ProcInst.Inst copy = %#v, want non-nil empty", got.Inst)
	}
}

// TestExternalEntitiesNeverLoaded verifies external entity and external DTD references are never
// fetched; using an external general entity is an unknown-entity error. |
// TestExternalEntitiesNeverLoaded 验证外部实体与外部 DTD 引用绝不会被加载；使用外部通用实体属于
// 未知实体错误。
func TestExternalEntitiesNeverLoaded(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("DTD entities are a native-backend extension | DTD 实体是原生后端扩展")
	}
	withUse := []string{
		`<!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>`,
		`<!DOCTYPE a [<!ENTITY e PUBLIC "-//x//EN" "http://127.0.0.1:1/x.dtd">]><a>&e;</a>`,
	}
	for _, doc := range withUse {
		_, err := collect(t, NewDecoderBytes([]byte(doc)))
		if !errors.Is(err, ErrSyntax) {
			t.Errorf("doc %q: err = %v, want ErrSyntax for unknown external entity", doc, err)
		}
	}
	withoutUse := []string{
		`<!DOCTYPE a SYSTEM "http://127.0.0.1:1/x.dtd"><a/>`,
		`<!DOCTYPE a [<!ENTITY % p SYSTEM "http://127.0.0.1:1/p.dtd"> %p;]><a/>`,
	}
	for _, doc := range withoutUse {
		got, err := collect(t, NewDecoderBytes([]byte(doc)))
		if err != nil {
			t.Errorf("doc %q: %v", doc, err)
			continue
		}
		if len(got) != 3 || !strings.HasPrefix(got[0], "D") || got[1] != `S{"","a"}[]` || got[2] != `E{"","a"}` {
			t.Errorf("doc %q: tokens %v", doc, got)
		}
	}
}

// TestEntityExpansionLimits verifies MaxEntityDepth and MaxEntityExpansion stop recursive DTD
// entity expansion. | TestEntityExpansionLimits 验证 MaxEntityDepth 与 MaxEntityExpansion 能阻止
// 递归 DTD 实体展开。
func TestEntityExpansionLimits(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("entity expansion budgets are a native-backend extension | 实体展开预算是原生后端扩展")
	}
	var b strings.Builder
	b.WriteString(`<!DOCTYPE a [<!ENTITY e0 "x">`)
	for i := 1; i <= 17; i++ {
		fmt.Fprintf(&b, `<!ENTITY e%d "&e%d;">`, i, i-1)
	}
	b.WriteString(`]><a>&e17;</a>`)
	d := NewDecoderBytes([]byte(b.String()))
	var err error
	for err == nil {
		_, err = d.Token()
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("depth: err = %v, want ErrLimit", err)
	}

	doc := `<!DOCTYPE a [<!ENTITY e "` + strings.Repeat("x", 100) + `">]><a>&e;&e;&e;</a>`
	d = NewDecoderBytes([]byte(doc))
	d.Limits = Limits{MaxEntityExpansion: 50}
	err = nil
	for err == nil {
		_, err = d.Token()
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("budget: err = %v, want ErrLimit", err)
	}
}

// TestTokenSizeLimit verifies MaxTokenSize is enforced for every token kind on both byte and reader
// sources and on both backends. | TestTokenSizeLimit 验证两种后端、字节与读取器源上所有 token 类型
// 都执行 MaxTokenSize 上限。
func TestTokenSizeLimit(t *testing.T) {
	long := strings.Repeat("x", 100)
	cases := []string{
		"<a>" + long + "</a>",
		long,
		"<![CDATA[" + long + "]]>",
		"<!--" + long + "-->",
		"<?pi " + long + "?>",
		"<!" + long + ">",
		`<a b="` + long + `"/>`,
		"<" + long + "/>",
	}
	for _, doc := range cases {
		for _, reader := range []bool{false, true} {
			var d *Decoder
			if reader {
				d = NewDecoder(&chunkReader{data: []byte(doc), n: 3})
			} else {
				d = NewDecoderBytes([]byte(doc))
			}
			d.Limits = Limits{MaxTokenSize: 32}
			var err error
			for err == nil {
				_, err = d.Token()
			}
			if !errors.Is(err, ErrLimit) {
				t.Errorf("doc %q reader=%v: err=%v, want ErrLimit", doc, reader, err)
			}
		}
	}
	// Entity names are scanned by the native lexer before expansion, so they must be bounded
	// there as well; the standard-library backend rejects an unknown entity as a syntax error
	// before a token exists. | 原生词法分析在展开前扫描实体名，因此也必须限制其长度；标准库后端
	// 在产生 token 前就把未知实体判为语法错误。
	if Backend() == "yd-native" {
		doc := "<a>&" + long + ";</a>"
		d := NewDecoderBytes([]byte(doc))
		d.Limits = Limits{MaxTokenSize: 32}
		var err error
		for err == nil {
			_, err = d.Token()
		}
		if !errors.Is(err, ErrLimit) {
			t.Errorf("entity name: err=%v, want ErrLimit", err)
		}
	}
}

// TestEntityErrorTextMatchesStdlib verifies entity diagnostics, including illegal code points and
// missing semicolons, match encoding/xml text. | TestEntityErrorTextMatchesStdlib 验证实体诊断
// （含非法码点与缺失分号）与 encoding/xml 文本一致。
func TestEntityErrorTextMatchesStdlib(t *testing.T) {
	docs := []string{
		`<a>&#0;</a>`,
		`<a>&#xFFFE;</a>`,
		`<a>&#x110000;</a>`,
		`<a>&#xD800;</a>`,
		`<a>&amp</a>`,
		`<a>&#65</a>`,
		`<a>&#x41</a>`,
		`<a>&#;</a>`,
		`<a>&#x;</a>`,
		`<a>&;</a>`,
		`<a>&nosuch;</a>`,
		`<a b="&#0;"/>`,
		`<a b="&amp"/>`,
	}
	for _, doc := range docs {
		for _, strict := range []bool{true, false} {
			sd := stdxml.NewDecoder(strings.NewReader(doc))
			sd.Strict = strict
			_, wantErr := collectStd(t, sd)
			od := NewDecoderBytes([]byte(doc))
			od.Strict = strict
			_, gotErr := collect(t, od)
			if (wantErr != nil) != (gotErr != nil) {
				t.Errorf("doc %q strict=%v: std err=%v, ours err=%v", doc, strict, wantErr, gotErr)
				continue
			}
			if wantErr != nil {
				var se *SyntaxError
				if !errors.As(gotErr, &se) {
					t.Errorf("doc %q strict=%v: ours error %v is not a *SyntaxError", doc, strict, gotErr)
					continue
				}
				if wantErr.Error() != se.Error() {
					t.Errorf("doc %q strict=%v: std error %q, ours %q", doc, strict, wantErr, se.Error())
				}
			}
		}
	}
}
