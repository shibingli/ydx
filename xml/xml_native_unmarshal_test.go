package xml

import (
	"bytes"
	stdxml "encoding/xml"
	"reflect"
	"strings"
	"testing"
)

type uBasic struct {
	ID    int      `xml:"id,attr"`
	Name  string   `xml:"name"`
	Age   int      `xml:"age"`
	Admin bool     `xml:"admin"`
	Score float64  `xml:"score"`
	Tags  []string `xml:"tags>tag"`
}

type uItem struct {
	ID   int    `xml:"id,attr"`
	Name string `xml:"name"`
	Data []byte `xml:"data"`
}

type uNested struct {
	Items []uItem `xml:"item"`
	Count int     `xml:"count"`
}

type uInner struct {
	Inner string `xml:",innerxml"`
	Text  string `xml:",chardata"`
}

type uComment struct {
	Comment string `xml:",comment"`
	Text    string `xml:",chardata"`
}

type uAny struct {
	Items []struct {
		Value string `xml:",chardata"`
	} `xml:",any"`
}

type uAnyAttr struct {
	Attrs []string `xml:",any,attr"`
	Name  string   `xml:"name"`
}

type uEmbedded struct {
	A string `xml:"a"`
}

type uEmbed struct {
	uEmbedded
	B string `xml:"b"`
}

type uPtr struct {
	P    *uItem   `xml:"p"`
	List []*uItem `xml:"list"`
}

type uNS struct {
	Name string `xml:"urn:x name"`
	Any  string `xml:"name"`
}

type uCDATA struct {
	Value string `xml:",cdata"`
}

type uStringRoot struct {
	Value string `xml:",chardata"`
}

type upString string

func (s *upString) UnmarshalText(b []byte) error {
	*s = upString(strings.ToUpper(string(b)))
	return nil
}

type uText struct {
	V upString `xml:"v"`
	A upString `xml:"a,attr"`
}

type uSliceRoot []uItem

func checkSame[T any](t *testing.T, doc string) {
	t.Helper()
	var want, got T
	stdErr := stdxml.Unmarshal([]byte(doc), &want)
	ourErr := Unmarshal([]byte(doc), &got)
	if (stdErr != nil) != (ourErr != nil) {
		t.Fatalf("doc %q: std err=%v ours err=%v", doc, stdErr, ourErr)
	}
	if stdErr == nil && !reflect.DeepEqual(want, got) {
		t.Fatalf("doc %q:\nstd  %#v\nours %#v", doc, want, got)
	}
}

func TestUnmarshalMatchesStdlib(t *testing.T) {
	basic := `<person id="7"><name>Ada</name><age>36</age><admin>true</admin><score>9.5</score><tags><tag>a</tag><tag>b</tag></tags></person>`
	checkSame[uBasic](t, basic)
	checkSame[uBasic](t, `<person/>`)
	checkSame[uBasic](t, `<person id="0"><name></name><age> 42 </age></person>`)
	checkSame[uNested](t, `<root><count>2</count><item id="1"><name>a</name><data>xy</data></item><item id="2"><name>b</name></item></root>`)
	checkSame[uNested](t, `<root><item/><item/></root>`)
	checkSame[uInner](t, `<a>pre<b x="1">in&amp;ner</b>post<!--c--></a>`)
	checkSame[uInner](t, `<a/>`)
	checkSame[uComment](t, `<a>text<!--one--><!--two--></a>`)
	checkSame[uAny](t, `<root><x>1</x><y>2</y><z><w>3</w></z></root>`)
	checkSame[uAnyAttr](t, `<root id="1" class="c" name="n"/>`)
	checkSame[uEmbed](t, `<root><a>A</a><b>B</b></root>`)
	checkSame[uPtr](t, `<root><p id="1"><name>p</name></p><list/><list><name>q</name></list></root>`)
	checkSame[uNS](t, `<root xmlns:p="urn:x"><p:name>N</p:name><name>A</name></root>`)
	checkSame[uCDATA](t, `<a><![CDATA[value]]></a>`)
	checkSame[uText](t, `<a v="hi" a="there"/>`)
	checkSame[uStringRoot](t, `<a>hello</a>`)
	checkSame[uSliceRoot](t, `<root><item><name>a</name></item><item><name>b</name></item></root>`)
	checkSame[uBasic](t, `<person><unknown><deep>x</deep></unknown><name>N</name></person>`)
}

func TestUnmarshalReaderMatchesStdlib(t *testing.T) {
	doc := `<person id="7"><name>Ada</name><age>36</age><tags><tag>a</tag><tag>b</tag></tags></person>`
	var want uBasic
	if err := stdxml.NewDecoder(strings.NewReader(doc)).Decode(&want); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []int{1, 3, 17} {
		var got uBasic
		if err := NewDecoder(&chunkReader{data: []byte(doc), n: chunk}).Decode(&got); err != nil {
			t.Fatalf("chunk %d: %v", chunk, err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("chunk %d: want %#v got %#v", chunk, want, got)
		}
	}
}

func TestUnmarshalErrors(t *testing.T) {
	if err := Unmarshal([]byte(`<a/>`), nil); err == nil {
		t.Fatal("expected non-pointer error")
	}
	var p *uBasic
	if err := Unmarshal([]byte(`<a/>`), p); err == nil {
		t.Fatal("expected nil pointer error")
	}
	var b uBasic
	if err := Unmarshal([]byte(`<person><age>x</age></person>`), &b); err == nil {
		t.Fatal("expected int conversion error")
	}
	if err := Unmarshal([]byte(`<person><name>x</name>`), &b); err == nil {
		t.Fatal("expected unexpected EOF")
	}
}

type uNameStruct struct {
	XMLName Name   `xml:"person"`
	ID      int    `xml:"id,attr"`
	Name    string `xml:"name"`
}

type uAttrStruct struct {
	A Attr `xml:"id,attr"`
}

func TestUnmarshalNameAndAttr(t *testing.T) {
	var v uNameStruct
	if err := Unmarshal([]byte(`<person id="3"><name>Ada</name></person>`), &v); err != nil {
		t.Fatal(err)
	}
	if v.XMLName.Local != "person" || v.ID != 3 || v.Name != "Ada" {
		t.Fatalf("bad result %#v", v)
	}
	if err := Unmarshal([]byte(`<other/>`), &v); err == nil {
		t.Fatal("expected XMLName mismatch error")
	}
	var a uAttrStruct
	if err := Unmarshal([]byte(`<x id="9"/>`), &a); err != nil {
		t.Fatal(err)
	}
	if a.A.Name.Local != "id" || a.A.Value != "9" {
		t.Fatalf("bad attr %#v", a.A)
	}
}

type uCustom struct {
	Value string `xml:"value"`
	Seen  bool
}

func (c *uCustom) UnmarshalXML(d *Decoder, start StartElement) error {
	c.Seen = true
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case CharData:
			c.Value += string(t)
		case EndElement:
			return nil
		}
	}
}

type uCustomBad struct{}

func (c *uCustomBad) UnmarshalXML(d *Decoder, start StartElement) error { return nil }

func TestCustomUnmarshaler(t *testing.T) {
	var v struct {
		C uCustom `xml:"c"`
	}
	if err := Unmarshal([]byte(`<root><c>abc</c></root>`), &v); err != nil {
		t.Fatal(err)
	}
	if !v.C.Seen || v.C.Value != "abc" {
		t.Fatalf("bad custom result %#v", v.C)
	}
	var bad struct {
		C uCustomBad `xml:"c"`
	}
	if err := Unmarshal([]byte(`<root><c>x</c></root>`), &bad); err == nil {
		t.Fatal("expected unconsumed element error")
	}
}

func TestUnmarshalDTDEntity(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("DTD entities are a native-backend extension | DTD 实体是原生后端扩展")
	}
	doc := `<!DOCTYPE a [<!ENTITY e "hello">]><a>&e; world</a>`
	var v uStringRoot
	if err := Unmarshal([]byte(doc), &v); err != nil {
		t.Fatal(err)
	}
	if v.Value != "hello world" {
		t.Fatalf("got %q", v.Value)
	}
	if !Valid([]byte(doc)) {
		t.Fatal("Valid rejected a DTD entity document")
	}
}

func TestUnmarshalBillionLaughsLimited(t *testing.T) {
	if Backend() != "yd-native" {
		t.Skip("entity expansion budgets are a native-backend extension | 实体展开预算是原生后端扩展")
	}
	var b strings.Builder
	b.WriteString(`<!DOCTYPE lolz [<!ENTITY lol "lol">`)
	for i := 1; i <= 9; i++ {
		b.WriteString(`<!ENTITY lol`)
		b.WriteString(string(rune('0' + i)))
		b.WriteString(` "`)
		for j := 0; j < 10; j++ {
			b.WriteString("&lol")
			if i > 1 {
				b.WriteString(string(rune('0' + i - 1)))
			}
			b.WriteString(";")
		}
		b.WriteString(`">`)
	}
	b.WriteString(`]><lolz>&lol9;</lolz>`)
	var v uStringRoot
	if err := Unmarshal([]byte(b.String()), &v); err == nil {
		t.Fatal("expected entity expansion limit error")
	}
}

func TestUnmarshalInnerXMLReader(t *testing.T) {
	doc := `<a>pre<b x="1">in&amp;ner</b>post</a>`
	var v uInner
	if err := NewDecoder(&chunkReader{data: []byte(doc), n: 2}).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Inner != `pre<b x="1">in&amp;ner</b>post` {
		t.Fatalf("inner=%q", v.Inner)
	}
	if v.Text != "prepost" {
		t.Fatalf("text=%q", v.Text)
	}
}

func TestUnmarshalBytesEqualsReader(t *testing.T) {
	doc := `<person><name>N</name><tags><tag>a</tag></tags></person>`
	var a, b uBasic
	if err := Unmarshal([]byte(doc), &a); err != nil {
		t.Fatal(err)
	}
	if err := NewDecoder(bytes.NewReader([]byte(doc))).Decode(&b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("bytes %#v reader %#v", a, b)
	}
}
