package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func collectLenient(t *testing.T, d *Decoder) ([]string, error) {
	t.Helper()
	var out []string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, normalizeToken(tok))
	}
}

func collectStdLenient(t *testing.T, d *stdxml.Decoder) ([]string, error) {
	t.Helper()
	var out []string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, normalizeToken(stdToken(tok)))
	}
}

func TestLenientMatchesStdlib(t *testing.T) {
	docs := []string{
		`<p>hello<br>world</p>`,
		`<a>&nbsp;&unknown;</a>`,
		`<a b=c d></a>`,
		`<a b="x&nbsp;y"/>`,
		`<br><br/>`,
		`<a>text &amp; more</a>`,
		`<a><b></a>`,
		`<a><b></a></b>`,
		`<a xmlns:p="urn:p"><b></p:b></a>`,
		`<a></b><c/>`,
	}
	for _, doc := range docs {
		sd := stdxml.NewDecoder(strings.NewReader(doc))
		sd.Strict = false
		sd.AutoClose = stdxml.HTMLAutoClose
		sd.Entity = stdxml.HTMLEntity
		want, wantErr := collectStdLenient(t, sd)
		od := NewDecoderBytes([]byte(doc))
		od.Strict = false
		od.AutoClose = HTMLAutoClose
		od.Entity = HTMLEntity
		got, gotErr := collectLenient(t, od)
		if (wantErr != nil) != (gotErr != nil) {
			t.Errorf("doc %q: std err=%v ours err=%v", doc, wantErr, gotErr)
			continue
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("doc %q:\nstd  %v\nours %v", doc, want, got)
		}
	}
}

func TestNamespaceEdgeCasesMatchStdlib(t *testing.T) {
	docs := []string{
		`<p:a p:b="1"/>`,
		`<a xmlns="urn:d"><b xmlns=""><c/></b></a>`,
		`<a xmlns:p="urn:p"><p:b p:c="1"/></a>`,
		`<a xml:lang="en"/>`,
		`<a xmlns="" b="1"/>`,
		`<a xmlns:p="urn:p" p:x="1" x="2"/>`,
		`<p:a xmlns:p="urn:p"/>`,
		`<a xmlns:xml="http://www.w3.org/XML/1998/namespace" xml:lang="en"/>`,
	}
	for _, doc := range docs {
		want, wantErr := collectStd(t, stdxml.NewDecoder(strings.NewReader(doc)))
		got, gotErr := collect(t, NewDecoderBytes([]byte(doc)))
		if (wantErr != nil) != (gotErr != nil) {
			t.Errorf("doc %q: std err=%v ours err=%v", doc, wantErr, gotErr)
			continue
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("doc %q:\nstd  %v\nours %v", doc, want, got)
		}
	}

	doc := `<a><b/></a>`
	sd := stdxml.NewDecoder(strings.NewReader(doc))
	sd.DefaultSpace = "urn:d"
	od := NewDecoderBytes([]byte(doc))
	od.DefaultSpace = "urn:d"
	want, _ := collectStd(t, sd)
	got, _ := collect(t, od)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("DefaultSpace:\nstd  %v\nours %v", want, got)
	}
}

func TestNamespacePrefixMismatchErrors(t *testing.T) {
	doc := `<p:a xmlns:p="urn:p"></q:a>`
	if _, err := collect(t, NewDecoderBytes([]byte(doc))); err == nil {
		t.Fatal("expected namespace mismatch error")
	}
}

func TestCharsetReaderMatchesStdlib(t *testing.T) {
	doc := append([]byte(`<?xml version="1.0" encoding="x-latin1"?><a>`), 0xE9)
	doc = append(doc, []byte(`</a>`)...)
	cr := func(charset string, input io.Reader) (io.Reader, error) {
		b, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		b = bytes.ReplaceAll(b, []byte{0xE9}, []byte{0xC3, 0xA9})
		return bytes.NewReader(b), nil
	}
	sd := stdxml.NewDecoder(bytes.NewReader(doc))
	sd.CharsetReader = cr
	want, wantErr := collectStd(t, sd)
	od := NewDecoderBytes(doc)
	od.CharsetReader = cr
	got, gotErr := collect(t, od)
	if (wantErr != nil) != (gotErr != nil) {
		t.Fatalf("std err=%v ours err=%v", wantErr, gotErr)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("std %v ours %v", want, got)
	}
}

func TestEncodingErrors(t *testing.T) {
	cases := []string{
		`<?xml version="1.1"?><a/>`,
		`<?xml version="1.0" encoding="x-unknown"?><a/>`,
		`<?xml version="1.0" encoding="ISO-8859-1"?><a/>`,
	}
	for _, doc := range cases {
		_, err := collect(t, NewDecoderBytes([]byte(doc)))
		if err == nil {
			t.Errorf("doc %q: expected error", doc)
			continue
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("doc %q: err = %v, want ErrUnsupported", doc, err)
		}
	}
	if _, err := collect(t, NewDecoderBytes([]byte{0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00})); err == nil {
		t.Fatal("expected truncated UTF-16 error")
	}
	if Backend() == "yd-native" {
		utf32 := [][]byte{
			{0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00, 0x00, 0x3C},
			{0xFF, 0xFE, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00},
		}
		for _, doc := range utf32 {
			if _, err := collect(t, NewDecoderBytes(doc)); !errors.Is(err, ErrUnsupported) {
				t.Errorf("UTF-32 doc % X: err = %v, want ErrUnsupported", doc, err)
			}
		}
	}
}

// TestBOMTokenMatchesStdlib verifies the UTF-8 BOM is preserved as character data exactly like
// encoding/xml, including when it precedes whitespace and the root element. | TestBOMTokenMatchesStdlib
// 验证 UTF-8 BOM 与 encoding/xml 一致地作为字符数据保留，包括位于空白与根元素之前的情况。
func TestBOMTokenMatchesStdlib(t *testing.T) {
	docs := [][]byte{
		append([]byte{0xEF, 0xBB, 0xBF}, []byte("<a/>")...),
		append([]byte{0xEF, 0xBB, 0xBF}, []byte("  <a/>")...),
		append([]byte{0xEF, 0xBB, 0xBF}, []byte("\n\t<a>t</a>")...),
		{0xEF, 0xBB, 0xBF},
	}
	for _, doc := range docs {
		want, wantErr := collectStd(t, stdxml.NewDecoder(bytes.NewReader(doc)))
		got, gotErr := collect(t, NewDecoderBytes(doc))
		if (wantErr != nil) != (gotErr != nil) {
			t.Errorf("doc %q: std err=%v, ours err=%v", doc, wantErr, gotErr)
			continue
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("doc %q:\nstd  %v\nours %v", doc, want, got)
		}
	}
}

// TestBOMValidity verifies a leading UTF-8 BOM is accepted before a root element and rejected on
// its own. | TestBOMValidity 验证根元素前的 UTF-8 BOM 被接受，而仅有 BOM 时被拒绝。
func TestBOMValidity(t *testing.T) {
	for _, doc := range [][]byte{
		append([]byte{0xEF, 0xBB, 0xBF}, []byte("<a/>")...),
		append([]byte{0xEF, 0xBB, 0xBF}, []byte("  <a/>")...),
	} {
		if !Valid(doc) {
			t.Errorf("Valid(%q) = false", doc)
		}
	}
	if Valid([]byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("Valid accepted a document with no root element")
	}
	if _, err := Parse([]byte{0xEF, 0xBB, 0xBF}); !errors.Is(err, ErrSyntax) {
		t.Fatalf("Parse err = %v, want ErrSyntax", err)
	}
}

// TestLenientNamespaceUnwindAfterMismatch locks in a deliberate divergence from encoding/xml: when
// a lenient mismatched end tag closes an element that declared a namespace, encoding/xml leaves the
// binding on its stack and then rejects the outer close tag, while we unwind the binding and accept
// the document. | TestLenientNamespaceUnwindAfterMismatch 固化一处与 encoding/xml 的有意差异：
// 宽松模式下不匹配的结束标签关闭了声明命名空间的元素时，encoding/xml 会把绑定留在栈上并拒绝外层
// 结束标签，而我们会回退绑定并接受文档。
func TestLenientNamespaceUnwindAfterMismatch(t *testing.T) {
	docs := []struct {
		doc  string
		want []string
	}{
		{
			doc:  `<a><b xmlns:p="u"></a>`,
			want: []string{`S{"","a"}[]`, `S{"","b"}[{"xmlns","p"}="u";]`, `E{"","b"}`, `E{"","a"}`},
		},
		{
			doc:  `<a><b xmlns="u"></a>`,
			want: []string{`S{"","a"}[]`, `S{"u","b"}[{"","xmlns"}="u";]`, `E{"","b"}`, `E{"","a"}`},
		},
	}
	for _, c := range docs {
		od := NewDecoderBytes([]byte(c.doc))
		od.Strict = false
		got, err := collect(t, od)
		if err != nil {
			t.Errorf("doc %q: %v", c.doc, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("doc %q:\ngot  %v\nwant %v", c.doc, got, c.want)
		}
	}
}

func TestInputOffsetsMatchStdlib(t *testing.T) {
	doc := "<?xml version=\"1.0\"?>\n<a x=\"1\">\n  text\n  <b/>\n</a>\n"
	sd := stdxml.NewDecoder(strings.NewReader(doc))
	od := NewDecoderBytes([]byte(doc))
	for i := 0; i < 100; i++ {
		st, serr := sd.Token()
		ot, oerr := od.Token()
		if (serr != nil) != (oerr != nil) {
			t.Fatalf("token %d: std err=%v ours err=%v", i, serr, oerr)
		}
		if serr != nil {
			break
		}
		if sd.InputOffset() != od.InputOffset() {
			t.Fatalf("token %d offset std=%d ours=%d (%v/%v)", i, sd.InputOffset(), od.InputOffset(), st, ot)
		}
		sl, sc := sd.InputPos()
		ol, oc := od.InputPos()
		if sl != ol || sc != oc {
			t.Fatalf("token %d pos std=%d:%d ours=%d:%d", i, sl, sc, ol, oc)
		}
	}
}

type rawTokenReader struct{ tokens []Token }

func (r *rawTokenReader) Token() (Token, error) {
	if len(r.tokens) == 0 {
		return nil, io.EOF
	}
	t := r.tokens[0]
	r.tokens = r.tokens[1:]
	return t, nil
}

func TestNewTokenDecoder(t *testing.T) {
	tokens := []Token{
		StartElement{Name: Name{Space: "p", Local: "a"}, Attr: []Attr{{Name: Name{Space: "xmlns", Local: "p"}, Value: "urn:p"}}},
		CharData("x"),
		EndElement{Name: Name{Space: "p", Local: "a"}},
	}
	d := NewTokenDecoder(&rawTokenReader{tokens: tokens})
	got, err := collect(t, d)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`S{"urn:p","a"}[{"xmlns","p"}="urn:p";]`, `C"x"`, `E{"urn:p","a"}`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if NewTokenDecoder(d) != d {
		t.Fatal("NewTokenDecoder(*Decoder) should return the decoder")
	}
}

func TestSyntaxErrorAs(t *testing.T) {
	_, err := collect(t, NewDecoderBytes([]byte("<a>\n</b>")))
	var se *SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("expected SyntaxError, got %T %v", err, err)
	}
	if se.Line == 0 {
		t.Fatalf("line should be set: %v", se)
	}
	if !errors.Is(err, ErrSyntax) {
		t.Fatalf("expected ErrSyntax, got %v", err)
	}
}

func TestTokenAttrSliceStable(t *testing.T) {
	d := NewDecoderBytes([]byte(`<a x="1"/><b y="2"/>`))
	tok, err := d.Token()
	if err != nil {
		t.Fatal(err)
	}
	first := tok.(StartElement)
	// Consume the synthetic end of <a/> and the start of <b>; the first token's Attr slice must
	// not be overwritten. | 消费 <a/> 的合成结束与 <b> 的起始；首个 token 的 Attr 切片不得被覆盖。
	for i := 0; i < 2; i++ {
		if _, err := d.Token(); err != nil {
			t.Fatal(err)
		}
	}
	if len(first.Attr) != 1 || first.Attr[0].Name.Local != "x" || first.Attr[0].Value != "1" {
		t.Fatalf("first token attributes changed: %#v", first.Attr)
	}
}
