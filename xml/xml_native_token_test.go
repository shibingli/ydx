package xml

import (
	"bytes"
	stdxml "encoding/xml"
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
