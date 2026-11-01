package xml

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"github.com/beevik/etree"
	"github.com/clbanning/mxj/v2"
	ydxml "github.com/shibingli/ydx/xml"
)

func ydValues(t *testing.T, doc []byte, expr string) []string {
	t.Helper()
	d, err := ydxml.Parse(doc)
	if err != nil {
		t.Fatalf("ydx Parse: %v", err)
	}
	p, err := ydxml.Compile(expr)
	if err != nil {
		t.Fatalf("ydx Compile(%q): %v", expr, err)
	}
	return d.Values(p)
}

func etreeValues(t *testing.T, doc []byte, expr string) []string {
	t.Helper()
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		t.Fatalf("etree: %v", err)
	}
	elems := d.FindElements(expr)
	out := make([]string, 0, len(elems))
	for _, e := range elems {
		out = append(out, e.Text())
	}
	return out
}

func xmlqueryValues(t *testing.T, doc []byte, expr string) []string {
	t.Helper()
	d, err := xmlquery.Parse(bytes.NewReader(doc))
	if err != nil {
		t.Fatalf("xmlquery: %v", err)
	}
	x, err := xpath.Compile(expr)
	if err != nil {
		t.Fatalf("xpath.Compile(%q): %v", expr, err)
	}
	nodes := xmlquery.QuerySelectorAll(d, x)
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.InnerText())
	}
	return out
}

func TestCorpusCompatibility(t *testing.T) {
	titles := []string{"A & B", "Second"}
	if got := ydValues(t, []byte(corpusXML), "//book/title"); !reflect.DeepEqual(got, titles) {
		t.Errorf("ydx titles = %#v", got)
	}
	if got := etreeValues(t, []byte(corpusXML), "//book/title"); !reflect.DeepEqual(got, titles) {
		t.Errorf("etree titles = %#v", got)
	}
	if got := xmlqueryValues(t, []byte(corpusXML), "//book/title"); !reflect.DeepEqual(got, titles) {
		t.Errorf("xmlquery titles = %#v", got)
	}

	m, err := mxj.NewMapXml([]byte(corpusXML))
	if err != nil {
		t.Fatalf("mxj: %v", err)
	}
	if got, err := m.ValuesForPath("catalog.book.title"); err != nil || !reflect.DeepEqual(toStrings(got), titles) {
		t.Errorf("mxj titles = %#v err=%v", got, err)
	}

	// Attribute values. | 属性值。
	if got := ydValues(t, []byte(corpusXML), "/catalog/book[1]/@id"); !reflect.DeepEqual(got, []string{"b1"}) {
		t.Errorf("ydx attr = %#v", got)
	}
	e := etree.NewDocument()
	_ = e.ReadFromBytes([]byte(corpusXML))
	if got := e.FindElement("//book").SelectAttrValue("id", ""); got != "b1" {
		t.Errorf("etree attr = %q", got)
	}
	x, _ := xmlquery.Parse(bytes.NewReader([]byte(corpusXML)))
	if got := xmlquery.FindOne(x, "//book").SelectAttr("id"); got != "b1" {
		t.Errorf("xmlquery attr = %q", got)
	}
	if got, _ := m.ValuesForPath("catalog.book[0].-id"); !reflect.DeepEqual(toStrings(got), []string{"b1"}) {
		t.Errorf("mxj attr = %#v", got)
	}

	// Predicates. | 谓词。
	if got := ydValues(t, []byte(corpusXML), `/catalog/book[@id='b2']/price`); !reflect.DeepEqual(got, []string{"20"}) {
		t.Errorf("ydx predicate = %#v", got)
	}
	if got := e.FindElement(`//book[@id='b2']/price`); got == nil || got.Text() != "20" {
		t.Errorf("etree predicate = %v", got)
	}
	if got := xmlquery.FindOne(x, `//book[@id='b2']/price`); got == nil || got.InnerText() != "20" {
		t.Errorf("xmlquery predicate = %v", got)
	}
	if got, _ := m.ValuesForPath("catalog.book[1].price"); !reflect.DeepEqual(toStrings(got), []string{"20"}) {
		t.Errorf("mxj predicate = %#v", got)
	}

	// Namespaces. etree keeps the prefix, xmlquery needs local-name(), mxj drops the prefix. |
	// 命名空间：etree 保留前缀，xmlquery 需 local-name()，mxj 丢弃前缀。
	if got := ydValues(t, []byte(corpusXML), "//{urn:x}tag"); !reflect.DeepEqual(got, []string{"T"}) {
		t.Errorf("ydx namespace = %#v", got)
	}
	if got := e.FindElement("//x:tag"); got == nil || got.Text() != "T" {
		t.Errorf("etree namespace = %v", got)
	}
	if got := xmlquery.FindOne(x, "//*[local-name()='tag']"); got == nil || got.InnerText() != "T" {
		t.Errorf("xmlquery namespace = %v", got)
	}
	if got, _ := m.ValuesForPath("catalog.book[0].tag"); !reflect.DeepEqual(toStrings(got), []string{"T"}) {
		t.Errorf("mxj namespace = %#v", got)
	}

	// CDATA and entity decoding. | CDATA 与实体解码。
	if got := ydValues(t, []byte(corpusXML), "//desc"); !reflect.DeepEqual(got, []string{"c<d"}) {
		t.Errorf("ydx cdata = %#v", got)
	}
	if got := e.FindElement("//desc"); got == nil || got.Text() != "c<d" {
		t.Errorf("etree cdata = %v", got)
	}
	if got := xmlquery.FindOne(x, "//desc"); got == nil || got.InnerText() != "c<d" {
		t.Errorf("xmlquery cdata = %v", got)
	}
	if got, _ := m.ValuesForPath("catalog.book[0].desc"); !reflect.DeepEqual(toStrings(got), []string{"c<d"}) {
		t.Errorf("mxj cdata = %#v", got)
	}
}

func TestCommentCompatibility(t *testing.T) {
	d, err := ydxml.Parse([]byte(corpusXML))
	if err != nil {
		t.Fatal(err)
	}
	var ydComments []string
	var walk func(*ydxml.Node)
	walk = func(n *ydxml.Node) {
		if n.Kind == ydxml.CommentNode {
			ydComments = append(ydComments, string(n.Data))
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(d.Root)
	if len(ydComments) != 1 {
		t.Fatalf("ydx comments = %#v", ydComments)
	}

	e := etree.NewDocument()
	_ = e.ReadFromBytes([]byte(corpusXML))
	var etComments []string
	var walkE func(*etree.Element)
	walkE = func(el *etree.Element) {
		for _, tok := range el.Child {
			switch c := tok.(type) {
			case *etree.Comment:
				etComments = append(etComments, c.Data)
			case *etree.Element:
				walkE(c)
			}
		}
	}
	walkE(e.Root())
	if len(etComments) != 1 {
		t.Fatalf("etree comments = %#v", etComments)
	}

	x, _ := xmlquery.Parse(bytes.NewReader([]byte(corpusXML)))
	xqComments := xmlquery.Find(x, "//comment()")
	if len(xqComments) != 1 {
		t.Fatalf("xmlquery comments = %d", len(xqComments))
	}

	m, _ := mxj.NewMapXml([]byte(corpusXML))
	if _, ok := m["catalog"].(map[string]any)["#comment"]; ok {
		t.Log("mxj retained comments")
	} else {
		t.Log("mxj drops comments (documented limitation)")
	}
}

func TestLargeDocumentCompatibility(t *testing.T) {
	data := benchData()
	want := benchTitles()

	got := ydValues(t, data, "//book/title")
	if len(got) != len(want) || got[0] != want[0] || got[len(got)-1] != want[len(want)-1] {
		t.Fatalf("ydx large: n=%d first=%q last=%q", len(got), got[0], got[len(got)-1])
	}
	et := etreeValues(t, data, "//book/title")
	if len(et) != len(want) || et[0] != want[0] || et[len(et)-1] != want[len(want)-1] {
		t.Fatalf("etree large: n=%d", len(et))
	}
	xq := xmlqueryValues(t, data, "//book/title")
	if len(xq) != len(want) || xq[0] != want[0] || xq[len(xq)-1] != want[len(want)-1] {
		t.Fatalf("xmlquery large: n=%d", len(xq))
	}
	m, err := mxj.NewMapXml(data)
	if err != nil {
		t.Fatal(err)
	}
	mv, err := m.ValuesForPath("catalog.book.title")
	if err != nil || len(mv) != len(want) {
		t.Fatalf("mxj large: n=%d err=%v", len(mv), err)
	}
}

func TestStreamingLargeDocument(t *testing.T) {
	data := benchData()
	p, err := ydxml.Compile("//book/title")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	err = ydxml.EachBytes(data, p, func(m *ydxml.Match) error {
		if n == 0 && string(m.Text) != benchTitles()[0] {
			t.Fatalf("first = %q", m.Text)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 8000 {
		t.Fatalf("streaming count = %d", n)
	}
}

type gen struct{ rng *rand.Rand }

func (g *gen) name() string {
	names := []string{"a", "b", "c", "item", "name", "x-y", "value_1", "数据"}
	return names[g.rng.Intn(len(names))]
}

func (g *gen) text() string {
	parts := []string{"text", "a&amp;b", "x&lt;y", "&#65;", " ", "中文", "a\r\nb", "&quot;"}
	return parts[g.rng.Intn(len(parts))]
}

func (g *gen) element(depth int) string {
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
		b.WriteString(">")
		b.WriteString(g.text())
		b.WriteString("</")
		b.WriteString(name)
		b.WriteString(">")
		return b.String()
	}
	b.WriteString(">")
	for i := 0; i < 1+g.rng.Intn(3); i++ {
		switch g.rng.Intn(4) {
		case 0:
			b.WriteString("<!--c-->")
		case 1:
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

func TestRandomCorpusCompatibility(t *testing.T) {
	g := &gen{rng: rand.New(rand.NewSource(99))}
	for i := 0; i < 50; i++ {
		doc := []byte(g.element(3))
		yd := ydValues(t, doc, "//item/name/a")
		et := etreeValues(t, doc, "//item/name/a")
		xq := xmlqueryValues(t, doc, "//item/name/a")
		if len(yd) != len(et) || len(yd) != len(xq) {
			t.Fatalf("doc %q: lengths ydx=%d etree=%d xmlquery=%d", doc, len(yd), len(et), len(xq))
		}
		for j := range yd {
			if yd[j] != et[j] || yd[j] != xq[j] {
				t.Fatalf("doc %q index %d: ydx %q etree %q xmlquery %q", doc, j, yd[j], et[j], xq[j])
			}
		}
	}
}

func toStrings(v []any) []string {
	out := make([]string, len(v))
	for i := range v {
		out[i] = fmt.Sprint(v[i])
	}
	return out
}
