package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"github.com/beevik/etree"
	"github.com/clbanning/mxj/v2"
	ydxml "github.com/shibingli/ydx/xml"
)

var (
	benchDocData = benchData()
	sinkInt      int
	sinkBytes    []byte
)

type benchBook struct {
	ID     string `xml:"id,attr"`
	Title  string `xml:"title"`
	Author string `xml:"author"`
	Price  string `xml:"price"`
	Year   string `xml:"year"`
	Note   string `xml:"note"`
}

type benchCatalog struct {
	Books []benchBook `xml:"book"`
}

func charLen(s string) int { return len(s) }

func BenchmarkParseYdxDOM(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d, err := ydxml.Parse(benchDocData)
		if err != nil {
			b.Fatal(err)
		}
		sinkInt = len(d.Root.Children)
	}
}

func BenchmarkParseEtree(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d := etree.NewDocument()
		if err := d.ReadFromBytes(benchDocData); err != nil {
			b.Fatal(err)
		}
		sinkInt = len(d.Root().Child)
	}
}

func BenchmarkParseXMLQuery(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, err := xmlquery.Parse(bytes.NewReader(benchDocData))
		if err != nil {
			b.Fatal(err)
		}
		if n.FirstChild != nil {
			sinkInt = 1
		} else {
			sinkInt = 0
		}
	}
}

func BenchmarkParseMXJ(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m, err := mxj.NewMapXml(benchDocData)
		if err != nil {
			b.Fatal(err)
		}
		sinkInt = len(m)
	}
}

func BenchmarkQueryYdxDOM(b *testing.B) {
	d, err := ydxml.Parse(benchDocData)
	if err != nil {
		b.Fatal(err)
	}
	p, err := ydxml.Compile("//book/title")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		vals := d.Values(p)
		sinkInt = len(vals)
	}
}

func BenchmarkQueryYdxSelector(b *testing.B) {
	p, err := ydxml.Compile("//book/title")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := ydxml.NewSelectorBytes(benchDocData, p)
		n := 0
		for s.Next() {
			n++
		}
		if err := s.Err(); err != nil {
			b.Fatal(err)
		}
		sinkInt = n
	}
}

func BenchmarkQueryEtree(b *testing.B) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(benchDocData); err != nil {
		b.Fatal(err)
	}
	p, err := etree.CompilePath("//book/title")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		elems := d.FindElementsPath(p)
		n := 0
		for _, e := range elems {
			n += charLen(e.Text())
		}
		sinkInt = n
	}
}

func BenchmarkQueryXMLQuery(b *testing.B) {
	d, err := xmlquery.Parse(bytes.NewReader(benchDocData))
	if err != nil {
		b.Fatal(err)
	}
	x, err := xpath.Compile("//book/title")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		nodes := xmlquery.QuerySelectorAll(d, x)
		n := 0
		for _, node := range nodes {
			n += len(node.InnerText())
		}
		sinkInt = n
	}
}

func BenchmarkQueryMXJ(b *testing.B) {
	m, err := mxj.NewMapXml(benchDocData)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		vals, err := m.ValuesForPath("catalog.book.title")
		if err != nil {
			b.Fatal(err)
		}
		n := 0
		for _, v := range vals {
			n += len(v.(string))
		}
		sinkInt = n
	}
}

func BenchmarkTokenYdx(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d := ydxml.NewDecoderBytes(benchDocData)
		n := 0
		for {
			if _, err := d.Token(); err != nil {
				break
			}
			n++
		}
		sinkInt = n
	}
}

func BenchmarkTokenStd(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		d := stdxml.NewDecoder(bytes.NewReader(benchDocData))
		n := 0
		for {
			if _, err := d.Token(); err != nil {
				break
			}
			n++
		}
		sinkInt = n
	}
}

func BenchmarkUnmarshalYdx(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var v benchCatalog
		if err := ydxml.Unmarshal(benchDocData, &v); err != nil {
			b.Fatal(err)
		}
		sinkInt = len(v.Books)
	}
}

func BenchmarkUnmarshalStd(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var v benchCatalog
		if err := stdxml.Unmarshal(benchDocData, &v); err != nil {
			b.Fatal(err)
		}
		sinkInt = len(v.Books)
	}
}

func BenchmarkMarshalYdx(b *testing.B) {
	var v benchCatalog
	if err := ydxml.Unmarshal(benchDocData, &v); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := ydxml.Marshal(v)
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = out
	}
}

func BenchmarkMarshalStd(b *testing.B) {
	var v benchCatalog
	if err := stdxml.Unmarshal(benchDocData, &v); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := stdxml.Marshal(v)
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = out
	}
}

func BenchmarkMarshalEtree(b *testing.B) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(benchDocData); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := d.WriteToBytes()
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = out
	}
}

func BenchmarkMarshalMXJ(b *testing.B) {
	m, err := mxj.NewMapXml(benchDocData)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		out, err := m.Xml()
		if err != nil {
			b.Fatal(err)
		}
		sinkBytes = out
	}
}

func BenchmarkValidYdx(b *testing.B) {
	b.SetBytes(int64(len(benchDocData)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !ydxml.Valid(benchDocData) {
			b.Fatal("invalid")
		}
	}
}
