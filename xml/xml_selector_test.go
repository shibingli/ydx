package xml

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func selectorValues(t *testing.T, s *Selector) []string {
	t.Helper()
	var out []string
	for s.Next() {
		out = append(out, string(s.Match().Value()))
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSelectorMatchesDOM(t *testing.T) {
	d := mustParse(t, bookstoreXML)
	paths := []string{
		"bookstore.book",
		"bookstore.book[*].title",
		"bookstore.book[0].title",
		"bookstore.book[@id='b2'].price",
		"bookstore.book[1].@id",
		"bookstore.book[2].title.text()",
		"bookstore.book[0].title.#text",
		"/bookstore/book[1]/title",
		"//title",
		"/bookstore//price",
		`/bookstore/book[@id="b2"]/price`,
		"/bookstore/book[2]/@id",
		"/bookstore/book[1]/text()",
		"//book[2]/title",
	}
	for _, expr := range paths {
		p := mustPath(t, expr)
		want := d.Values(p)
		got := selectorValues(t, NewSelectorBytes([]byte(bookstoreXML), p))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q selector=%#v dom=%#v", expr, got, want)
		}
	}
}

func TestSelectorReaderChunks(t *testing.T) {
	p := mustPath(t, "//title")
	want := []string{"XML Guide", "Fast Parsing", "高性能解析"}
	for _, chunk := range []int{1, 2, 5, 64} {
		got := selectorValues(t, NewSelector(&chunkReader{data: []byte(bookstoreXML), n: chunk}, p))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("chunk %d: %#v", chunk, got)
		}
	}
}

func TestSelectorEachAndRaw(t *testing.T) {
	var titles []string
	err := EachBytes([]byte(bookstoreXML), mustPath(t, "//title"), func(m *Match) error {
		titles = append(titles, string(m.Text))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(titles) != 3 {
		t.Fatalf("titles = %#v", titles)
	}

	s := NewSelectorBytesWithOptions([]byte(bookstoreXML), mustPath(t, "//book"), SelectorOptions{CaptureRaw: true})
	seen := 0
	for s.Next() {
		m := s.Match()
		if !bytes.HasPrefix(m.Raw, []byte(`<book `)) || !bytes.HasSuffix(bytes.TrimSpace(m.Raw), []byte(`</book>`)) {
			t.Fatalf("raw = %q", m.Raw)
		}
		seen++
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 3 {
		t.Fatalf("seen = %d", seen)
	}
}

func TestSelectorRawUnavailableOnReader(t *testing.T) {
	s := NewSelectorWithOptions(strings.NewReader(bookstoreXML), mustPath(t, "//book"), SelectorOptions{CaptureRaw: true})
	for s.Next() {
		if s.Match().Raw != nil {
			t.Fatalf("reader raw = %q", s.Match().Raw)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSelectorLimits(t *testing.T) {
	p := mustPath(t, "//title")
	s := NewSelectorBytesWithOptions([]byte(bookstoreXML), p, SelectorOptions{Limits: Limits{MaxMatches: 2}})
	n := 0
	for s.Next() {
		n++
	}
	if s.Err() == nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, s.Err())
	}
	s = NewSelectorBytesWithOptions([]byte(bookstoreXML), p, SelectorOptions{Limits: Limits{MaxTextSize: 3}})
	for s.Next() {
	}
	if s.Err() == nil {
		t.Fatal("expected text size limit error")
	}
}

func TestSelectorNoText(t *testing.T) {
	s := NewSelectorBytesWithOptions([]byte(bookstoreXML), mustPath(t, "//title"), SelectorOptions{NoText: true})
	for s.Next() {
		if s.Match().Text != nil {
			t.Fatalf("NoText text = %q", s.Match().Text)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSelectorDTDEntity(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("DTD entities are a native-backend extension | DTD 实体是原生后端扩展")
	}
	doc := `<!DOCTYPE a [<!ENTITY e "hello">]><a><b>&e;</b></a>`
	got := selectorValues(t, NewSelectorBytes([]byte(doc), mustPath(t, "/a/b")))
	if !reflect.DeepEqual(got, []string{"hello"}) {
		t.Fatalf("got %#v", got)
	}
}

func TestSelectorUTF16(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("automatic UTF-16 BOM detection is a native-backend extension | UTF-16 BOM 自动检测是原生后端扩展")
	}
	utf8Doc := `<a><b>hi</b></a>`
	runes := []rune(utf8Doc)
	buf := []byte{0xFF, 0xFE}
	for _, r := range runes {
		buf = append(buf, byte(r), byte(r>>8))
	}
	got := selectorValues(t, NewSelectorBytes(buf, mustPath(t, "//b")))
	if !reflect.DeepEqual(got, []string{"hi"}) {
		t.Fatalf("got %#v", got)
	}
}

func TestSelectorLarge(t *testing.T) {
	var b strings.Builder
	b.WriteString("<root>")
	const n = 20000
	for i := 0; i < n; i++ {
		b.WriteString("<item id=\"")
		b.WriteString("x")
		b.WriteString("\"><name>n</name></item>")
	}
	b.WriteString("</root>")
	count := 0
	err := EachBytes([]byte(b.String()), mustPath(t, "//item[@id='x']/name"), func(m *Match) error {
		if string(m.Text) != "n" {
			t.Fatalf("text = %q", m.Text)
		}
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != n {
		t.Fatalf("count = %d", count)
	}
}
