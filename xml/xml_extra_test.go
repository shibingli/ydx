package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestValid(t *testing.T) {
	valid := []string{
		`<a/>`,
		`<?xml version="1.0"?><a><b x="1">text</b><!--c--></a>`,
		"\xEF\xBB\xBF<a/>",
		`<a xmlns:p="urn:p"><p:b/></a>`,
		`<a><![CDATA[ x<y ]]></a>`,
	}
	if Backend() == "yd-native" {
		valid = append(valid, `<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>`)
	}
	for _, doc := range valid {
		if !Valid([]byte(doc)) {
			t.Errorf("Valid(%q) = false", doc)
		}
	}
	invalid := []string{
		``,
		`<a></a><b></b>`,
		`<a/>tail`,
		`text<a/>`,
		`<a>`,
		`<a></b>`,
		`<a x="1" x="2"/>`,
		`<a>&unknown;</a>`,
		`<a>]]></a>`,
		`<a><!-- -- --></a>`,
	}
	for _, doc := range invalid {
		if Valid([]byte(doc)) {
			t.Errorf("Valid(%q) = true", doc)
		}
	}
}

func TestSkipAndDecodeElement(t *testing.T) {
	doc := `<root><skip><deep>x</deep></skip><keep id="1">value</keep></root>`
	d := NewDecoderBytes([]byte(doc))
	tok, err := d.Token()
	if err != nil {
		t.Fatal(err)
	}
	root, ok := tok.(StartElement)
	if !ok || root.Name.Local != "root" {
		t.Fatalf("root token = %#v", tok)
	}
	tok, err = d.Token()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tok.(StartElement); !ok {
		t.Fatalf("expected skip start, got %#v", tok)
	}
	if err := d.Skip(); err != nil {
		t.Fatal(err)
	}
	tok, err = d.Token()
	if err != nil {
		t.Fatal(err)
	}
	keep, ok := tok.(StartElement)
	if !ok || keep.Name.Local != "keep" {
		t.Fatalf("expected keep start, got %#v", tok)
	}
	var v struct {
		ID   int    `xml:"id,attr"`
		Text string `xml:",chardata"`
	}
	if err := d.DecodeElement(&v, &keep); err != nil {
		t.Fatal(err)
	}
	if v.ID != 1 || v.Text != "value" {
		t.Fatalf("decoded %#v", v)
	}
}

func TestDecodeFindsStartAndPrewarm(t *testing.T) {
	Prewarm(uBasic{}, (*uItem)(nil), (*[]uItem)(nil), (*uNested)(nil))
	doc := `<?xml version="1.0"?><!--c--><person id="1"><name>N</name></person>`
	var v uBasic
	if err := NewDecoder(strings.NewReader(doc)).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.ID != 1 || v.Name != "N" {
		t.Fatalf("decoded %#v", v)
	}
}

type rawInUnmarshal struct{}

func (r *rawInUnmarshal) UnmarshalXML(d *Decoder, start StartElement) error {
	if _, err := d.RawToken(); err == nil {
		return errors.New("RawToken succeeded inside UnmarshalXML")
	}
	return d.Skip()
}

func TestRawTokenForbiddenInUnmarshalXML(t *testing.T) {
	var v struct {
		X rawInUnmarshal `xml:"x"`
	}
	if err := Unmarshal([]byte(`<root><x/></root>`), &v); err != nil {
		t.Fatal(err)
	}
}

func TestValidReaderAndParseUTF16(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("UTF-16 auto-detection is a native-backend extension")
	}
	utf8Doc := `<root><b>hi</b></root>`
	var buf []byte
	buf = append(buf, 0xFE, 0xFF)
	for _, r := range utf8Doc {
		buf = append(buf, byte(r>>8), byte(r))
	}
	d, err := Parse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if d.Root == nil || d.Root.FirstChild("b").Text() != "hi" {
		t.Fatalf("bad DOM")
	}
	if !Valid(buf) {
		t.Fatal("Valid rejected UTF-16 document")
	}
}

// TestDOMCharsetReaderDisablesRawViews verifies raw byte views are withheld after a CharsetReader
// conversion, because doc.src is no longer UTF-8. | TestDOMCharsetReaderDisablesRawViews 验证
// CharsetReader 转换后不再提供原始字节视图，因为 doc.src 已不是 UTF-8。
func TestDOMCharsetReaderDisablesRawViews(t *testing.T) {
	doc := append([]byte(`<?xml version="1.0" encoding="x-latin1"?><a>x`), 0xE9)
	doc = append(doc, []byte(`<b>y</b></a>`)...)
	cr := func(charset string, input io.Reader) (io.Reader, error) {
		b, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		b = bytes.ReplaceAll(b, []byte{0xE9}, []byte{0xC3, 0xA9})
		return bytes.NewReader(b), nil
	}
	d, err := ParseWithOptions(doc, ParseOptions{CharsetReader: cr})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := d.Root.Text(); got != "xé" {
		t.Fatalf("root text = %q, want %q", got, "xé")
	}
	if got := d.Root.InnerXML(); got != nil {
		t.Fatalf("inner raw view = %q, want nil after charset conversion", got)
	}
	if got := d.Root.OuterXML(); got != nil {
		t.Fatalf("outer raw view = %q, want nil after charset conversion", got)
	}
	if b := d.Root.FirstChild("b"); b == nil || b.Text() != "y" {
		t.Fatalf("child b = %#v", b)
	}
}

// TestDOMUTF16RawViews verifies UTF-16 input exposes transcoded UTF-8 raw views. |
// TestDOMUTF16RawViews 验证 UTF-16 输入提供转码后的 UTF-8 原始视图。
func TestDOMUTF16RawViews(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("UTF-16 auto-detection is a native-backend extension | UTF-16 自动检测是原生后端扩展")
	}
	utf8Doc := `<a>x<b>y</b></a>`
	buf := []byte{0xFF, 0xFE}
	for _, r := range utf8Doc {
		buf = append(buf, byte(r), byte(r>>8))
	}
	d, err := Parse(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := string(d.Root.InnerXML()); got != "x<b>y</b>" {
		t.Fatalf("inner = %q", got)
	}
	if got := string(d.Root.OuterXML()); got != utf8Doc {
		t.Fatalf("outer = %q", got)
	}
	if got := d.Root.Text(); got != "x" {
		t.Fatalf("text = %q", got)
	}
}

type randomDoc struct {
	rng *rand.Rand
}

func (g *randomDoc) name() string {
	names := []string{"a", "b", "c", "item", "name", "x-y", "value_1", "数据"}
	return names[g.rng.Intn(len(names))]
}

func (g *randomDoc) text() string {
	parts := []string{"text", "a&amp;b", "x&lt;y", "&#65;", " ", "中文", "a\r\nb", "]]", "&quot;"}
	return parts[g.rng.Intn(len(parts))]
}

func (g *randomDoc) element(depth int) string {
	var b strings.Builder
	name := g.name()
	b.WriteByte('<')
	b.WriteString(name)
	if g.rng.Intn(2) == 0 {
		b.WriteString(` id="`)
		b.WriteString(g.text())
		b.WriteString(`"`)
	}
	if depth <= 0 || g.rng.Intn(3) == 0 {
		if g.rng.Intn(2) == 0 {
			b.WriteString("/>")
			return b.String()
		}
		b.WriteString(">")
		b.WriteString(g.text())
		b.WriteString("</")
		b.WriteString(name)
		b.WriteString(">")
		return b.String()
	}
	b.WriteString(">")
	for i := 0; i < 1+g.rng.Intn(3); i++ {
		switch g.rng.Intn(5) {
		case 0:
			b.WriteString("<!--c-->")
		case 1:
			b.WriteString("<![CDATA[raw<data]]>")
		case 2:
			b.WriteString(g.text())
		default:
			b.WriteString(g.element(depth - 1))
		}
	}
	b.WriteString("</")
	b.WriteString(name)
	b.WriteString(">")
	return b.String()
}

func TestRandomTokenDifferential(t *testing.T) {
	g := &randomDoc{rng: rand.New(rand.NewSource(42))}
	for i := 0; i < 300; i++ {
		doc := g.element(3)
		want, wantErr := collectStd(t, stdxmlDecoder(doc))
		got, gotErr := collect(t, NewDecoderBytes([]byte(doc)))
		if (wantErr != nil) != (gotErr != nil) {
			t.Fatalf("doc %q: std err=%v ours err=%v", doc, wantErr, gotErr)
		}
		if len(want) != len(got) {
			t.Fatalf("doc %q: token count %d != %d\nstd %v\nours %v", doc, len(want), len(got), want, got)
		}
		for j := range want {
			if want[j] != got[j] {
				t.Fatalf("doc %q token %d: std %s ours %s", doc, j, want[j], got[j])
			}
		}
	}
}

func stdxmlDecoder(doc string) *stdxml.Decoder { return stdxml.NewDecoder(strings.NewReader(doc)) }

func TestNoPanicOnRandomBytes(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alphabet := []byte("<>/&;=\"'[]!?-_ abcdefgxyz0123\r\n\t\x00\x01\x80\xC3\xA9\xEF\xBB\xBF")
	for i := 0; i < 2000; i++ {
		n := rng.Intn(80)
		b := make([]byte, n)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", b, r)
				}
			}()
			d := NewDecoderBytes(b)
			for k := 0; k < 100; k++ {
				if _, err := d.Token(); err != nil {
					break
				}
			}
			d = NewDecoderBytes(b)
			d.Strict = false
			for k := 0; k < 100; k++ {
				if _, err := d.Token(); err != nil {
					break
				}
			}
			_, _ = Parse(b)
			_ = Valid(b)
		}()
	}
}

type randomValue struct {
	ID    int      `xml:"id,attr"`
	Name  string   `xml:"name"`
	Tags  []string `xml:"tag"`
	Count int      `xml:"count"`
	Flag  bool     `xml:"flag"`
	Score float64  `xml:"score"`
	Note  string   `xml:",chardata"`
}

func TestRandomMarshalDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 300; i++ {
		v := randomValue{
			ID:    rng.Intn(1000),
			Name:  fmt.Sprintf("n%d<&>", rng.Intn(100)),
			Count: rng.Intn(100),
			Flag:  rng.Intn(2) == 0,
			Score: float64(rng.Intn(10000)) / 10,
			Note:  "note & <text>",
		}
		for j := 0; j < rng.Intn(5); j++ {
			v.Tags = append(v.Tags, fmt.Sprintf("t%d", j))
		}
		want, werr := stdxml.Marshal(v)
		got, gerr := Marshal(v)
		if (werr != nil) != (gerr != nil) {
			t.Fatalf("std err=%v ours err=%v", werr, gerr)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("marshal differs:\nstd  %q\nours %q", want, got)
		}
		var a, b randomValue
		if err := stdxml.Unmarshal(got, &a); err != nil {
			t.Fatal(err)
		}
		if err := Unmarshal(got, &b); err != nil {
			t.Fatal(err)
		}
		if a.ID != b.ID || a.Name != b.Name || a.Count != b.Count || a.Flag != b.Flag || a.Score != b.Score || a.Note != b.Note || len(a.Tags) != len(b.Tags) {
			t.Fatalf("unmarshal differs std=%#v ours=%#v", a, b)
		}
	}
}

func TestConcurrentAPI(t *testing.T) {
	doc := []byte(bookstoreXML)
	p := mustPath(t, "//title")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				d, err := Parse(doc)
				if err != nil {
					t.Error(err)
					return
				}
				if len(d.Values(p)) != 3 {
					t.Error("bad values")
					return
				}
				var v uNested
				if err := Unmarshal(doc, &v); err != nil {
					t.Error(err)
					return
				}
				if _, err := Marshal(v); err != nil {
					t.Error(err)
					return
				}
				s := NewSelectorBytes(doc, p)
				n := 0
				for s.Next() {
					n++
				}
				if s.Err() != nil || n != 3 {
					t.Errorf("selector n=%d err=%v", n, s.Err())
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestHeaderAndEscapeAlias(t *testing.T) {
	if Header != `<?xml version="1.0" encoding="UTF-8"?>`+"\n" {
		t.Fatalf("Header = %q", Header)
	}
	var b bytes.Buffer
	Escape(&b, []byte("<&>"))
	if b.String() != "&lt;&amp;&gt;" {
		t.Fatalf("Escape = %q", b.String())
	}
}

// TestInnerXMLCaptureLimit verifies MaxTokenSize also bounds ,innerxml capture on both byte and
// reader sources and both backends, even when every individual token stays below the limit. |
// TestInnerXMLCaptureLimit 验证 MaxTokenSize 同时限制 ,innerxml 捕获，覆盖字节与读取器源以及两种
// 后端，即使每个单独 token 都低于上限。
func TestInnerXMLCaptureLimit(t *testing.T) {
	const doc = `<a><b/><b/><b/></a>`
	type root struct {
		Inner string `xml:",innerxml"`
	}
	decode := func(t *testing.T, d *Decoder, limit int) (root, error) {
		t.Helper()
		d.Limits = Limits{MaxTokenSize: limit}
		var v root
		err := d.Decode(&v)
		return v, err
	}
	t.Run("bytes-limit", func(t *testing.T) {
		if _, err := decode(t, NewDecoderBytes([]byte(doc)), 8); !errors.Is(err, ErrLimit) {
			t.Fatalf("Decode err = %v, want ErrLimit", err)
		}
	})
	t.Run("reader-limit", func(t *testing.T) {
		d := NewDecoder(&chunkReader{data: []byte(doc), n: 3})
		if _, err := decode(t, d, 8); !errors.Is(err, ErrLimit) {
			t.Fatalf("Decode err = %v, want ErrLimit", err)
		}
	})
	t.Run("bytes-ok", func(t *testing.T) {
		v, err := decode(t, NewDecoderBytes([]byte(doc)), 16)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if v.Inner != `<b/><b/><b/>` {
			t.Fatalf("Inner = %q", v.Inner)
		}
	})
	t.Run("reader-ok", func(t *testing.T) {
		v, err := decode(t, NewDecoder(&chunkReader{data: []byte(doc), n: 2}), 16)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if v.Inner != `<b/><b/><b/>` {
			t.Fatalf("Inner = %q", v.Inner)
		}
	})
}

// TestFileEntryPoints covers ParseFile, EachFile and Document.AppendValue, which the in-memory
// tests do not exercise directly. | TestFileEntryPoints 覆盖 ParseFile、EachFile 与
// Document.AppendValue，这些入口在内存测试中没有直接覆盖。
func TestFileEntryPoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.xml")
	const doc = `<r><x>1</x><x>2</x></r>`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if got := d.Values(mustPath(t, "//x")); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Fatalf("ParseFile values = %#v", got)
	}
	var streamed []string
	if err := EachFile(path, mustPath(t, "//x"), func(m *Match) error {
		streamed = append(streamed, string(m.Text))
		return nil
	}); err != nil {
		t.Fatalf("EachFile: %v", err)
	}
	if !reflect.DeepEqual(streamed, []string{"1", "2"}) {
		t.Fatalf("EachFile values = %#v", streamed)
	}
	if out, ok := d.AppendValue([]byte("v="), mustPath(t, "//x[2]")); !ok || string(out) != "v=2" {
		t.Fatalf("AppendValue = %q, %v", out, ok)
	}
	if _, ok := d.AppendValue(nil, mustPath(t, "//missing")); ok {
		t.Fatal("AppendValue matched a missing path")
	}
	missing := filepath.Join(t.TempDir(), "missing.xml")
	if _, err := ParseFile(missing); !errors.Is(err, ErrSyntax) {
		t.Fatalf("ParseFile missing file err = %v, want ErrSyntax", err)
	}
	if err := EachFile(missing, mustPath(t, "//x"), func(*Match) error { return nil }); !errors.Is(err, ErrSyntax) {
		t.Fatalf("EachFile missing file err = %v, want ErrSyntax", err)
	}
}

var _ io.Reader = (*chunkReader)(nil)
