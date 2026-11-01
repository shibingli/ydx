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
	}
	for _, doc := range cases {
		if _, err := collect(t, NewDecoderBytes([]byte(doc))); err == nil {
			t.Errorf("doc %q: expected error", doc)
		}
	}
	if _, err := collect(t, NewDecoderBytes([]byte{0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00})); err == nil {
		t.Fatal("expected truncated UTF-16 error")
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
