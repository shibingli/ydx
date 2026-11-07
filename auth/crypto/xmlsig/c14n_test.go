package xmlsig

import (
	"errors"
	"testing"

	"github.com/shibingli/ydx/xml"
)

// TestCanonicalizeW3CPIsAndComments covers the W3C Canonical XML 1.0 example 3.1. |
// TestCanonicalizeW3CPIsAndComments 覆盖 W3C Canonical XML 1.0 示例 3.1。
func TestCanonicalizeW3CPIsAndComments(t *testing.T) {
	input := []byte("\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->\n")
	want := "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Fatalf("canonical form mismatch\n got: %q\nwant: %q", got, want)
	}

	wantComments := "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
	got, err = CanonicalizeWithOptions(input, CanonicalizeOptions{WithComments: true})
	if err != nil {
		t.Fatalf("CanonicalizeWithOptions: %v", err)
	}
	if string(got) != wantComments {
		t.Fatalf("canonical form with comments mismatch\n got: %q\nwant: %q", got, wantComments)
	}
}

// TestCanonicalizeW3CWhitespace covers the W3C Canonical XML 1.0 example 3.2. |
// TestCanonicalizeW3CWhitespace 覆盖 W3C Canonical XML 1.0 示例 3.2。
func TestCanonicalizeW3CWhitespace(t *testing.T) {
	input := []byte(`<doc>
   <clean>   </clean>
   <dirty>   A   B   </dirty>
   <mixed>
      A
      <clean>   </clean>
      B
      <dirty>   A   B   </dirty>
      C
   </mixed>
</doc>`)
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != string(input) {
		t.Fatalf("whitespace changed\n got: %q\nwant: %q", got, input)
	}
}

// TestCanonicalizeW3CStartEndTags covers the W3C Canonical XML 1.0 example 3.3. |
// TestCanonicalizeW3CStartEndTags 覆盖 W3C Canonical XML 1.0 示例 3.3。
func TestCanonicalizeW3CStartEndTags(t *testing.T) {
	input := []byte(`<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>`)
	want := `<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org"></e9>
         </e8>
      </e7>
   </e6>
</doc>`
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Fatalf("canonical start/end tag form mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalizeExclusive checks the exclusive namespace rendering example. |
// TestCanonicalizeExclusive 校验排他命名空间渲染示例。
func TestCanonicalizeExclusive(t *testing.T) {
	input := []byte(`<doc xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org">
   <e1>
      <e2 xmlns="">
         <e3 id="E3"/>
      </e2>
   </e1>
</doc>`)
	want := `<doc xmlns="http://www.ietf.org">
   <e1>
      <e2 xmlns="">
         <e3 id="E3"></e3>
      </e2>
   </e1>
</doc>`
	got, err := CanonicalizeWithOptions(input, CanonicalizeOptions{Exclusive: true})
	if err != nil {
		t.Fatalf("CanonicalizeWithOptions: %v", err)
	}
	if string(got) != want {
		t.Fatalf("exclusive canonical form mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalizeElementInheritedXMLAttrs checks document-subset inheritance. xml:lang and
// xml:space are inherited in inclusive modes; xml:base fixup is only defined by Canonical XML 1.1
// and never applies to exclusive canonicalization. | TestCanonicalizeElementInheritedXMLAttrs 校验
// 文档子集继承。包容模式会继承 xml:lang 与 xml:space；xml:base 修正仅由 Canonical XML 1.1
// 定义，且从不适用于排他规范化。
func TestCanonicalizeElementInheritedXMLAttrs(t *testing.T) {
	input := []byte(`<doc xml:lang="en" xml:base="http://example.com/a/"><p ID="p1">hi</p></doc>`)
	got, err := CanonicalizeElement(input, "p1", CanonicalizeOptions{Version: "1.0"})
	if err != nil {
		t.Fatalf("CanonicalizeElement: %v", err)
	}
	want := `<p ID="p1" xml:lang="en">hi</p>`
	if string(got) != want {
		t.Fatalf("canonical XML 1.0 subset mismatch\n got: %s\nwant: %s", got, want)
	}
	got, err = CanonicalizeElement(input, "p1", CanonicalizeOptions{})
	if err != nil {
		t.Fatalf("CanonicalizeElement default: %v", err)
	}
	if string(got) != want {
		t.Fatalf("default (1.0) subset mismatch\n got: %s\nwant: %s", got, want)
	}
	got, err = CanonicalizeElement(input, "p1", CanonicalizeOptions{Version: "1.1"})
	if err != nil {
		t.Fatalf("CanonicalizeElement 1.1: %v", err)
	}
	want = `<p ID="p1" xml:base="http://example.com/a/" xml:lang="en">hi</p>`
	if string(got) != want {
		t.Fatalf("canonical XML 1.1 subset mismatch\n got: %s\nwant: %s", got, want)
	}
	got, err = CanonicalizeElement(input, "p1", CanonicalizeOptions{Exclusive: true})
	if err != nil {
		t.Fatalf("CanonicalizeElement exclusive: %v", err)
	}
	if string(got) != `<p ID="p1">hi</p>` {
		t.Fatalf("exclusive subset mismatch: %s", got)
	}
}

// TestCanonicalizeCommentsAndEscaping checks comment exclusion and escaping. |
// TestCanonicalizeCommentsAndEscaping 校验注释排除与转义。
func TestCanonicalizeCommentsAndEscaping(t *testing.T) {
	input := []byte("<r a=\"x\t y\"><!--drop--><t>a &amp; b &lt; c &gt; d</t></r>")
	got, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `<r a="x&#x9; y"><t>a &amp; b &lt; c &gt; d</t></r>`
	if string(got) != want {
		t.Fatalf("escaping mismatch\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalizeNode checks canonicalization of a programmatically built node. |
// TestCanonicalizeNode 校验程序构造节点的规范化。
func TestCanonicalizeNode(t *testing.T) {
	node := &xml.Node{
		Kind: xml.ElementNode,
		Name: xml.Name{Local: "root"},
		Attrs: []xml.Attr{
			{Name: xml.Name{Local: "a"}, Value: "v"},
		},
		Children: []*xml.Node{
			{Kind: xml.TextNode, Data: []byte("hi")},
		},
	}
	got, err := CanonicalizeNode(node, CanonicalizeOptions{})
	if err != nil {
		t.Fatalf("CanonicalizeNode: %v", err)
	}
	if string(got) != `<root a="v">hi</root>` {
		t.Fatalf("node canonical form mismatch: %s", got)
	}
}

// TestInvalidXMLRejected checks namespace and well-formedness guards. |
// TestInvalidXMLRejected 校验命名空间与良构性守卫。
func TestInvalidXMLRejected(t *testing.T) {
	cases := []string{
		`<a><b></a>`,
		`<a/><b/>`,
		`<a x:y="1"/>`,
		`<a xmlns:a="urn:x" xmlns:b="urn:x" a:q="1" b:q="2"/>`,
		`<a xmlns:p=""/>`,
		`<a xmlns:p="relative"/>`,
		`<a xmlns:xmlns="urn:x"/>`,
	}
	for _, input := range cases {
		if _, err := Canonicalize([]byte(input)); !errors.Is(err, ErrInvalidXML) {
			t.Errorf("Canonicalize(%q) error = %v, want ErrInvalidXML", input, err)
		}
	}
}
