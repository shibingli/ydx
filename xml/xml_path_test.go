package xml

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const bookstoreXML = `<?xml version="1.0"?>
<!-- catalog -->
<bookstore xmlns:x="urn:x">
  <book id="b1" lang="en">
    <title>XML Guide</title>
    <price>29.99</price>
    <x:tag>t1</x:tag>
  </book>
  <book id="b2">
    <title>Fast Parsing</title>
    <price>19.99</price>
  </book>
  <book id="b3" lang="zh">
    <title>高性能解析</title>
    <price>39.99</price>
  </book>
</bookstore>`

func mustParse(t *testing.T, doc string) *Document {
	t.Helper()
	d, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustPath(t *testing.T, expr string) *Path {
	t.Helper()
	p, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile(%q): %v", expr, err)
	}
	return p
}

func TestParseDOMStructure(t *testing.T) {
	d := mustParse(t, bookstoreXML)
	if d.Root == nil || d.Root.Name.Local != "bookstore" {
		t.Fatalf("root = %#v", d.Root)
	}
	if len(d.Children) != 3 { // PI + comment + root
		t.Fatalf("document children = %d", len(d.Children))
	}
	if d.Children[0].Kind != ProcInstNode || d.Children[1].Kind != CommentNode {
		t.Fatalf("prolog kinds = %v %v", d.Children[0].Kind, d.Children[1].Kind)
	}
	books := d.Root.Children
	var elems []*Node
	for _, c := range books {
		if c.Kind == ElementNode {
			elems = append(elems, c)
		}
	}
	if len(elems) != 3 {
		t.Fatalf("books = %d", len(elems))
	}
	b := elems[0]
	if v, ok := b.Attr("id"); !ok || v != "b1" {
		t.Fatalf("attr id = %q %v", v, ok)
	}
	if v, ok := b.AttrNS("", "lang"); !ok || v != "en" {
		t.Fatalf("attr lang = %q %v", v, ok)
	}
	title := b.FirstChild("title")
	if title == nil || title.Text() != "XML Guide" {
		t.Fatalf("title = %#v", title)
	}
	if got, want := string(b.InnerXML()), "\n    <title>XML Guide</title>\n    <price>29.99</price>\n    <x:tag>t1</x:tag>\n  "; got != want {
		t.Fatalf("InnerXML = %q want %q", got, want)
	}
	if !strings.HasPrefix(string(b.OuterXML()), `<book id="b1" lang="en">`) {
		t.Fatalf("OuterXML = %q", b.OuterXML())
	}
	if title.NextSibling() == nil || title.NextSibling().Kind != TextNode {
		t.Fatalf("NextSibling = %#v", title.NextSibling())
	}
	if price := b.FirstChild("price"); price == nil || price.Text() != "29.99" {
		t.Fatalf("price = %#v", price)
	}
	tag := b.FirstChild("tag")
	if tag == nil || tag.Name.Space != "urn:x" {
		t.Fatalf("namespaced tag = %#v", tag)
	}
}

func TestPathDotStyle(t *testing.T) {
	d := mustParse(t, bookstoreXML)
	cases := []struct {
		expr string
		want []string
	}{
		{"bookstore.book[0].title", []string{"XML Guide"}},
		{"bookstore.book[*].title", []string{"XML Guide", "Fast Parsing", "高性能解析"}},
		{"bookstore.book[@id='b2'].price", []string{"19.99"}},
		{"bookstore.book[1].@id", []string{"b2"}},
		{"bookstore.book[2].title.text()", []string{"高性能解析"}},
		{"bookstore.book[0].title.#text", []string{"XML Guide"}},
		{"bookstore.book[@lang='zh'].title", []string{"高性能解析"}},
		{"bookstore.book[0].tag", []string{"t1"}},
	}
	for _, c := range cases {
		p := mustPath(t, c.expr)
		got := d.Values(p)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q = %#v want %#v", c.expr, got, c.want)
		}
	}
}

func TestPathXPathStyle(t *testing.T) {
	d := mustParse(t, bookstoreXML)
	cases := []struct {
		expr string
		want []string
	}{
		{"/bookstore/book[1]/title", []string{"XML Guide"}},
		{"//title", []string{"XML Guide", "Fast Parsing", "高性能解析"}},
		{"/bookstore//price", []string{"29.99", "19.99", "39.99"}},
		{`/bookstore/book[@id="b2"]/price`, []string{"19.99"}},
		{"/bookstore/book[2]/@id", []string{"b2"}},
		{"/bookstore/book[1]/text()", []string{"\n    \n    \n    \n  "}},
		{"//book[2]/title", []string{"Fast Parsing"}},
		{"//book[1]/title", []string{"XML Guide"}},
	}
	for _, c := range cases {
		p := mustPath(t, c.expr)
		got := d.Values(p)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q = %#v want %#v", c.expr, got, c.want)
		}
	}
}

func TestPathSelectAndRelative(t *testing.T) {
	d := mustParse(t, bookstoreXML)
	books := d.Select(mustPath(t, "bookstore.book"))
	if len(books) != 3 {
		t.Fatalf("books = %d", len(books))
	}
	if one := d.SelectOne(mustPath(t, "//book[3]")); one == nil || one.Name.Local != "book" {
		t.Fatalf("SelectOne = %#v", one)
	}
	root := d.Root
	title := root.SelectOne(mustPath(t, "book[0].title"))
	if title == nil || title.Text() != "XML Guide" {
		t.Fatalf("relative title = %#v", title)
	}
	if v, ok := root.Value(mustPath(t, "book[1].@id")); !ok || v != "b2" {
		t.Fatalf("relative value = %q %v", v, ok)
	}
	if p := mustPath(t, "book[0].title"); len(d.Select(p)) != 0 {
		t.Fatal("Select with non-element terminal should be empty")
	}
}

func TestPathNamespaceClark(t *testing.T) {
	doc := `<root xmlns:x="urn:x"><x:name>one</x:name><name>two</name></root>`
	d := mustParse(t, doc)
	if got := d.Values(mustPath(t, "//{urn:x}name")); !reflect.DeepEqual(got, []string{"one"}) {
		t.Fatalf("clark = %#v", got)
	}
	if got := d.Values(mustPath(t, "//{urn:x}name/text()")); !reflect.DeepEqual(got, []string{"one"}) {
		t.Fatalf("clark text = %#v", got)
	}
}

func TestPathMaximumSteps(t *testing.T) {
	expr := strings.Repeat("a/", 63) + "a"
	p, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile(64 steps): %v", err)
	}
	doc := strings.Repeat("<a>", 64) + strings.Repeat("</a>", 64)
	s := NewSelectorBytes([]byte(doc), p)
	n := 0
	for s.Next() {
		n++
	}
	if err := s.Err(); err != nil {
		t.Fatalf("selector: %v", err)
	}
	if n != 1 {
		t.Fatalf("64-step path matched %d times, want 1", n)
	}
	if _, err := Compile(expr + "/a"); !errors.Is(err, ErrPathSyntax) {
		t.Fatalf("65-step Compile err = %v, want ErrPathSyntax", err)
	}
}

func TestPathCompileErrors(t *testing.T) {
	bad := []string{"", "   ", "/", "//", "a.", "a..b", "a[", "a[]", "a[x]", "a[@]", "a[@x=", "//text()", "@id", "a[1", "a[0][1]", "a b", "a/text()x"}
	for _, expr := range bad {
		if _, err := Compile(expr); err == nil {
			t.Errorf("Compile(%q) unexpectedly succeeded", expr)
		}
	}
}

func TestPathConcurrent(t *testing.T) {
	d := mustParse(t, bookstoreXML)
	p := mustPath(t, "//book/title")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if got := d.Values(p); len(got) != 3 {
					t.Errorf("values = %d", len(got))
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		``,
		`<a></a><b></b>`,
		`text<a/>`,
		`<a/>tail`,
		`<a>`,
		`<a></b>`,
	}
	for _, doc := range bad {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", doc)
		}
	}
}

func TestParseOptions(t *testing.T) {
	doc := `<?xml version="1.0"?><!--c--><?pi x?><a>t</a>`
	d, err := ParseWithOptions([]byte(doc), ParseOptions{DiscardComments: true, DiscardProcInst: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range d.Children {
		if c.Kind == CommentNode || c.Kind == ProcInstNode {
			t.Fatalf("unexpected %v node", c.Kind)
		}
	}
	d, err = ParseWithOptions([]byte(doc), ParseOptions{DiscardDirectives: true})
	if err != nil {
		t.Fatal(err)
	}
	if d.Root == nil {
		t.Fatal("missing root")
	}
}

func TestParseLimits(t *testing.T) {
	doc := `<a><b><c/></b></a>`
	if _, err := ParseWithOptions([]byte(doc), ParseOptions{Limits: Limits{MaxDepth: 2}}); !errors.Is(err, ErrLimit) {
		t.Fatalf("depth limit err = %v, want ErrLimit", err)
	}
	if _, err := ParseWithOptions([]byte(doc), ParseOptions{Limits: Limits{MaxNodes: 2}}); !errors.Is(err, ErrLimit) {
		t.Fatalf("node limit err = %v, want ErrLimit", err)
	}
	d := NewDecoderBytes([]byte(doc))
	d.Limits = Limits{MaxDepth: 1}
	var err error
	for err == nil {
		_, err = d.Token()
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("stream depth err = %v, want ErrLimit", err)
	}
}

func TestParseReaderEqualsParse(t *testing.T) {
	a := mustParse(t, bookstoreXML)
	b, err := ParseReader(strings.NewReader(bookstoreXML))
	if err != nil {
		t.Fatal(err)
	}
	if a.Root.Name != b.Root.Name || len(a.Root.Children) != len(b.Root.Children) {
		t.Fatalf("reader DOM differs")
	}
	if p := mustPath(t, "//title"); !reflect.DeepEqual(a.Values(p), b.Values(p)) {
		t.Fatalf("values differ")
	}
}
