package xmlsig

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/shibingli/ydx/xml"
)

// c14nNamespacedDocument exercises default, prefixed and attribute namespaces. |
// c14nNamespacedDocument 覆盖默认、前缀与属性命名空间。
const c14nNamespacedDocument = `<doc xmlns="urn:default" xmlns:p="urn:p" xmlns:q="urn:q"><p:child ID="c" q:a="1" a="2"><leaf/></p:child></doc>`

// TestExclusiveCanonicalizationPrefixList covers ec:InclusiveNamespaces visibility rules. |
// TestExclusiveCanonicalizationPrefixList 覆盖 ec:InclusiveNamespaces 的可见性规则。
func TestExclusiveCanonicalizationPrefixList(t *testing.T) {
	without, err := CanonicalizeElement([]byte(c14nNamespacedDocument), "c", CanonicalizeOptions{Exclusive: true})
	if err != nil {
		t.Fatalf("CanonicalizeElement: %v", err)
	}
	const wantWithout = `<p:child xmlns:p="urn:p" xmlns:q="urn:q" ID="c" a="2" q:a="1"><leaf xmlns="urn:default"></leaf></p:child>`
	if string(without) != wantWithout {
		t.Fatalf("exclusive output =\n%s\nwant\n%s", without, wantWithout)
	}
	with, err := CanonicalizeElement([]byte(c14nNamespacedDocument), "c", CanonicalizeOptions{
		Exclusive:           true,
		InclusiveNamespaces: []string{"#default", "q"},
	})
	if err != nil {
		t.Fatalf("CanonicalizeElement with PrefixList: %v", err)
	}
	const wantWith = `<p:child xmlns="urn:default" xmlns:p="urn:p" xmlns:q="urn:q" ID="c" a="2" q:a="1"><leaf></leaf></p:child>`
	if string(with) != wantWith {
		t.Fatalf("exclusive PrefixList output =\n%s\nwant\n%s", with, wantWith)
	}
	if _, err := CanonicalizeElement([]byte(c14nNamespacedDocument), "", CanonicalizeOptions{}); !errors.Is(err, ErrReference) {
		t.Fatalf("empty ID error = %v, want ErrReference", err)
	}
	if _, err := CanonicalizeElement([]byte(c14nNamespacedDocument), "missing", CanonicalizeOptions{}); !errors.Is(err, ErrReference) {
		t.Fatalf("missing ID error = %v, want ErrReference", err)
	}
	if _, err := CanonicalizeElement([]byte(c14nNamespacedDocument), "c", CanonicalizeOptions{Version: "2.0"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad version error = %v, want ErrInvalidOption", err)
	}
	if _, err := CanonicalizeWithOptions([]byte("<root>"), CanonicalizeOptions{}); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("invalid XML error = %v, want ErrInvalidXML", err)
	}
}

// TestCanonicalizationAlgorithmTable covers every algorithm URI mapping. |
// TestCanonicalizationAlgorithmTable 覆盖所有规范化算法 URI 映射。
func TestCanonicalizationAlgorithmTable(t *testing.T) {
	cases := []struct {
		uri     string
		opts    CanonicalizeOptions
		reverse string
	}{
		{uri: c14n10URI, opts: CanonicalizeOptions{Version: "1.0"}, reverse: c14n10URI},
		{uri: c14n10WithCommentsURI, opts: CanonicalizeOptions{Version: "1.0", WithComments: true}, reverse: c14n10WithCommentsURI},
		{uri: c14n11URI, opts: CanonicalizeOptions{Version: "1.1"}, reverse: c14n11URI},
		{uri: c14n11WithCommentsURI, opts: CanonicalizeOptions{Version: "1.1", WithComments: true}, reverse: c14n11WithCommentsURI},
		{uri: excC14NURI, opts: CanonicalizeOptions{Exclusive: true}, reverse: excC14NURI},
		{uri: excC14NWithCommentsURI, opts: CanonicalizeOptions{Exclusive: true, WithComments: true}, reverse: excC14NWithCommentsURI},
	}
	for _, tc := range cases {
		got, err := c14nSpecForURI(tc.uri)
		if err != nil {
			t.Fatalf("c14nSpecForURI(%q): %v", tc.uri, err)
		}
		if got.Version != tc.opts.Version || got.Exclusive != tc.opts.Exclusive ||
			got.WithComments != tc.opts.WithComments || len(got.InclusiveNamespaces) != 0 {
			t.Fatalf("c14nSpecForURI(%q) = %+v, want %+v", tc.uri, got, tc.opts)
		}
		if reverse := c14nOptionsURI(tc.opts); reverse != tc.reverse {
			t.Fatalf("c14nOptionsURI(%+v) = %q, want %q", tc.opts, reverse, tc.reverse)
		}
		if !isCanonicalizationURI(tc.uri) {
			t.Fatalf("isCanonicalizationURI(%q) = false", tc.uri)
		}
	}
	if _, err := c14nSpecForURI("urn:c14n:unknown"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown c14n error = %v, want ErrUnsupported", err)
	}
	if isCanonicalizationURI("urn:c14n:unknown") {
		t.Fatal("unknown c14n URI accepted")
	}
	c14nURIsValue := c14nURIs()
	if len(c14nURIsValue) != len(cases) {
		t.Fatalf("c14nURIs length = %d, want %d", len(c14nURIsValue), len(cases))
	}
}

// TestSignCanonicalizationMethods signs and verifies with every supported method. |
// TestSignCanonicalizationMethods 使用全部受支持方法签名并验证。
func TestSignCanonicalizationMethods(t *testing.T) {
	key := testRSAPrivateKey(t)
	document := []byte(`<root xmlns="urn:default" xmlns:p="urn:p"><p:child>text</p:child><order ID="order-1">42</order></root>`)
	for _, uri := range append(c14nURIs(), "") {
		name := uri
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			signed, err := Sign(document, SignOptions{PrivateKey: key, ID: "order-1", CanonicalizationMethod: uri})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if uri != "" && !bytes.Contains(signed, []byte(`Algorithm="`+uri+`"`)) {
				t.Fatalf("signature lacks canonicalization URI %q: %s", uri, signed)
			}
			if _, err := VerifyElement(signed, "order-1", VerifyOptions{Certificates: signerCertificates(t, key)}); err != nil {
				t.Fatalf("VerifyElement: %v", err)
			}
		})
	}

	exclusive, err := Sign(document, SignOptions{PrivateKey: key, ID: "order-1", Exclusive: true, WithComments: true})
	if err != nil {
		t.Fatalf("Sign exclusive with comments: %v", err)
	}
	if !bytes.Contains(exclusive, []byte(`Algorithm="`+excC14NWithCommentsURI+`"`)) {
		t.Fatalf("exclusive comment canonicalization missing: %s", exclusive)
	}
	if _, err := VerifyElement(exclusive, "order-1", VerifyOptions{Certificates: signerCertificates(t, key)}); err != nil {
		t.Fatalf("VerifyElement exclusive: %v", err)
	}

	// Selecting exclusive canonicalization through CanonicalizationMethod alone must emit the
	// PrefixList on both the method and the reference transform. | 仅通过 CanonicalizationMethod
	// 选择排他规范化时，方法和引用变换都必须写入 PrefixList。
	prefixList, err := Sign(document, SignOptions{
		PrivateKey:             key,
		ID:                     "order-1",
		CanonicalizationMethod: excC14NURI,
		InclusiveNamespaces:    []string{"#default"},
	})
	if err != nil {
		t.Fatalf("Sign exclusive PrefixList: %v", err)
	}
	if got := bytes.Count(prefixList, []byte("<ec:InclusiveNamespaces")); got != 2 {
		t.Fatalf("InclusiveNamespaces count = %d, want 2: %s", got, prefixList)
	}
	if !bytes.Contains(prefixList, []byte(`PrefixList="#default"`)) {
		t.Fatalf("PrefixList missing: %s", prefixList)
	}
	if _, err := VerifyElement(prefixList, "order-1", VerifyOptions{Certificates: signerCertificates(t, key)}); err != nil {
		t.Fatalf("VerifyElement exclusive PrefixList: %v", err)
	}
}

// signerCertificates returns one trusted certificate for key. | signerCertificates 返回 key 的
// 一张受信证书。
func signerCertificates(t *testing.T, key *rsa.PrivateKey) []*x509.Certificate {
	t.Helper()
	return []*x509.Certificate{testCertificate(t, key)}
}

// TestCanonicalizeNodeSynthesizedNamespaces covers the public DOM adapter. |
// TestCanonicalizeNodeSynthesizedNamespaces 覆盖公开 DOM 适配。
func TestCanonicalizeNodeSynthesizedNamespaces(t *testing.T) {
	root := &xml.Node{
		Kind: xml.ElementNode,
		Name: xml.Name{Space: "urn:root", Local: "root"},
		Attrs: []xml.Attr{
			{Name: xml.Name{Local: "b"}, Value: "2"},
			{Name: xml.Name{Space: "urn:attr", Local: "a"}, Value: "1"},
			{Name: xml.Name{Space: "xmlns", Local: "x"}, Value: "urn:x"},
			{Name: xml.Name{Space: xmlNamespaceURI, Local: "lang"}, Value: "en"},
		},
		Children: []*xml.Node{
			{Kind: xml.ElementNode, Name: xml.Name{Space: "urn:child", Local: "child"}},
			{Kind: xml.TextNode, Data: []byte("a&b<c>d")},
		},
	}
	out, err := CanonicalizeNode(root, CanonicalizeOptions{})
	if err != nil {
		t.Fatalf("CanonicalizeNode: %v", err)
	}
	const want = `<ns0:root xmlns:ns0="urn:root" xmlns:ns1="urn:attr" xmlns:x="urn:x" b="2" xml:lang="en" ns1:a="1"><ns2:child xmlns:ns2="urn:child"></ns2:child>a&amp;b&lt;c&gt;d</ns0:root>`
	if string(out) != want {
		t.Fatalf("CanonicalizeNode =\n%s\nwant\n%s", out, want)
	}

	text, err := CanonicalizeNode(&xml.Node{Kind: xml.TextNode, Data: []byte("x\ry&z")}, CanonicalizeOptions{})
	if err != nil || string(text) != "x&#xD;y&amp;z" {
		t.Fatalf("text node = %q, %v", text, err)
	}
	comment := &xml.Node{Kind: xml.CommentNode, Data: []byte("note")}
	if out, err := CanonicalizeNode(comment, CanonicalizeOptions{}); err != nil || len(out) != 0 {
		t.Fatalf("comment without comments = %q, %v", out, err)
	}
	if out, err := CanonicalizeNode(comment, CanonicalizeOptions{WithComments: true}); err != nil || string(out) != "<!--note-->" {
		t.Fatalf("comment = %q, %v", out, err)
	}
	procInst := &xml.Node{Kind: xml.ProcInstNode, Name: xml.Name{Local: "xml-stylesheet"}, Data: []byte(`href="a"`)}
	if out, err := CanonicalizeNode(procInst, CanonicalizeOptions{}); err != nil || string(out) != `<?xml-stylesheet href="a"?>` {
		t.Fatalf("processing instruction = %q, %v", out, err)
	}
	if _, err := CanonicalizeNode(nil, CanonicalizeOptions{}); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("nil node error = %v, want ErrInvalidXML", err)
	}
	if _, err := CanonicalizeNode(&xml.Node{Kind: xml.DirectiveNode, Data: []byte("DOCTYPE x")}, CanonicalizeOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("directive node error = %v, want ErrUnsupported", err)
	}
	if _, err := CanonicalizeNode(root, CanonicalizeOptions{Version: "3.0"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad version error = %v, want ErrInvalidOption", err)
	}
}

// TestXMLBaseFixup covers inclusive 1.1 xml:base combination and removals. |
// TestXMLBaseFixup 覆盖包容 1.1 的 xml:base 合并与删除。
func TestXMLBaseFixup(t *testing.T) {
	document := []byte(`<a xml:base="http://example.com/dir/" xml:lang="en" xml:space="preserve"><b xml:base="sub/"><leaf ID="leaf" xml:base="leaf.xml"><inner/></leaf></b></a>`)
	v11, err := CanonicalizeElement(document, "leaf", CanonicalizeOptions{Version: "1.1"})
	if err != nil {
		t.Fatalf("CanonicalizeElement 1.1: %v", err)
	}
	const want11 = `<leaf ID="leaf" xml:base="http://example.com/dir/sub/leaf.xml" xml:lang="en" xml:space="preserve"><inner></inner></leaf>`
	if string(v11) != want11 {
		t.Fatalf("C14N 1.1 output =\n%s\nwant\n%s", v11, want11)
	}
	v10, err := CanonicalizeElement(document, "leaf", CanonicalizeOptions{Version: "1.0"})
	if err != nil {
		t.Fatalf("CanonicalizeElement 1.0: %v", err)
	}
	const want10 = `<leaf ID="leaf" xml:base="leaf.xml" xml:lang="en" xml:space="preserve"><inner></inner></leaf>`
	if string(v10) != want10 {
		t.Fatalf("C14N 1.0 output =\n%s\nwant\n%s", v10, want10)
	}
	exclusive, err := CanonicalizeElement(document, "leaf", CanonicalizeOptions{Exclusive: true})
	if err != nil {
		t.Fatalf("CanonicalizeElement exclusive: %v", err)
	}
	if string(exclusive) != `<leaf ID="leaf" xml:base="leaf.xml"><inner></inner></leaf>` {
		t.Fatalf("exclusive output = %s", exclusive)
	}

	ancestorOnly := []byte(`<a xml:base="http://example.com/dir/"><b xml:base="sub/"><leaf ID="leaf"/></b></a>`)
	inherited, err := CanonicalizeElement(ancestorOnly, "leaf", CanonicalizeOptions{Version: "1.1"})
	if err != nil {
		t.Fatalf("CanonicalizeElement inherited base: %v", err)
	}
	if string(inherited) != `<leaf ID="leaf" xml:base="http://example.com/dir/sub/"></leaf>` {
		t.Fatalf("inherited base output = %s", inherited)
	}
	emptyBase := []byte(`<a xml:base=""><leaf ID="leaf" xml:base=""/></a>`)
	removed, err := CanonicalizeElement(emptyBase, "leaf", CanonicalizeOptions{Version: "1.1"})
	if err != nil {
		t.Fatalf("CanonicalizeElement empty base: %v", err)
	}
	if string(removed) != `<leaf ID="leaf"></leaf>` {
		t.Fatalf("empty base output = %s", removed)
	}
	if _, err := CanonicalizeElement(ancestorOnly, "leaf", CanonicalizeOptions{Version: "not-a-version"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("bad version error = %v, want ErrInvalidOption", err)
	}

	if got := joinBaseURI("http://example.com/dir/", "sub/x"); got != "http://example.com/dir/sub/x" {
		t.Fatalf("joinBaseURI relative = %q", got)
	}
	if got := joinBaseURI("http://example.com/dir/file", "x"); got != "http://example.com/dir/x" {
		t.Fatalf("joinBaseURI sibling = %q", got)
	}
	if got := joinBaseURI("sub/", "leaf.xml"); got != "sub/leaf.xml" {
		t.Fatalf("joinBaseURI relative base = %q", got)
	}
	if got := joinBaseURI("a/b/", "../x"); got != "a/x" {
		t.Fatalf("joinBaseURI relative parent = %q", got)
	}
	if got := joinBaseURI("dir/", "/abs/x"); got != "/abs/x" {
		t.Fatalf("joinBaseURI absolute path ref = %q", got)
	}
	if got := joinBaseURI("", "x"); got != "x" {
		t.Fatalf("joinBaseURI empty base = %q", got)
	}
	if got := joinBaseURI("base", ""); got != "base" {
		t.Fatalf("joinBaseURI empty ref = %q", got)
	}
	if got := joinBaseURI("://bad", "ref"); got != "ref" {
		t.Fatalf("joinBaseURI invalid base = %q", got)
	}
	if got := joinBaseURI("http://example.com/", "://bad"); got != "://bad" {
		t.Fatalf("joinBaseURI invalid ref = %q", got)
	}
}

// TestCanonicalizationDocumentNodes covers prolog, epilog, comments and escaping. |
// TestCanonicalizationDocumentNodes 覆盖序言、尾声、注释与转义。
func TestCanonicalizationDocumentNodes(t *testing.T) {
	document := []byte(`<?xml-stylesheet href="a"?><!--lead--><root a="&quot;&lt;&amp;&#x9;&#xA;&#xD;">x&#xD;y&gt;</root><!--tail-->`)
	plain, err := Canonicalize(document)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	const wantPlain = `<?xml-stylesheet href="a"?>
<root a="&quot;&lt;&amp;&#x9;&#xA;&#xD;">x&#xD;y&gt;</root>`
	if string(plain) != wantPlain {
		t.Fatalf("plain output =\n%s\nwant\n%s", plain, wantPlain)
	}
	withComments, err := CanonicalizeWithOptions(document, CanonicalizeOptions{WithComments: true})
	if err != nil {
		t.Fatalf("CanonicalizeWithOptions: %v", err)
	}
	const wantComments = `<?xml-stylesheet href="a"?>
<!--lead-->
<root a="&quot;&lt;&amp;&#x9;&#xA;&#xD;">x&#xD;y&gt;</root>
<!--tail-->`
	if string(withComments) != wantComments {
		t.Fatalf("comments output =\n%s\nwant\n%s", withComments, wantComments)
	}
	leadingOnly, err := CanonicalizeWithOptions([]byte(`<!--lead--><root/>`), CanonicalizeOptions{WithComments: true})
	if err != nil || string(leadingOnly) != "<!--lead-->\n<root></root>" {
		t.Fatalf("leading comment = %q, %v", leadingOnly, err)
	}
	trailingOnly, err := CanonicalizeWithOptions([]byte(`<root/><!--tail-->`), CanonicalizeOptions{WithComments: true})
	if err != nil || string(trailingOnly) != "<root></root>\n<!--tail-->" {
		t.Fatalf("trailing comment = %q, %v", trailingOnly, err)
	}
}

// TestParseXMLBoundsAndWellFormedness covers BOM, directives, limits and namespace validation. |
// TestParseXMLBoundsAndWellFormedness 覆盖 BOM、指令、上限与命名空间校验。
func TestParseXMLBoundsAndWellFormedness(t *testing.T) {
	if _, err := parseXML([]byte("\xEF\xBB\xBF<root>text</root>")); err != nil {
		t.Fatalf("UTF-8 BOM rejected: %v", err)
	}
	if got, err := Canonicalize([]byte("\xEF\xBB\xBF<root>text</root>")); err != nil || string(got) != "<root>text</root>" {
		t.Fatalf("BOM canonicalization = %q, %v", got, err)
	}
	if _, err := parseXML([]byte(`<!DOCTYPE root [<!ENTITY x "y">]><root>&x;</root>`)); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("DOCTYPE error = %v, want ErrInvalidXML", err)
	}
	if _, err := parseXML([]byte(`<root>text`)); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("unterminated root error = %v, want ErrInvalidXML", err)
	}
	if _, err := parseXML([]byte(`<a/><b/>`)); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("multiple roots error = %v, want ErrInvalidXML", err)
	}
	if _, err := parseXML([]byte(`text<root/>`)); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("text outside root error = %v, want ErrInvalidXML", err)
	}
	if _, err := parseXML([]byte(`<a></b>`)); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("mismatched end tag error = %v, want ErrInvalidXML", err)
	}
	if _, err := parseXML([]byte(``)); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("empty document error = %v, want ErrInvalidXML", err)
	}

	var deep strings.Builder
	for i := 0; i < maxXMLDepth+1; i++ {
		deep.WriteString("<a>")
	}
	for i := 0; i < maxXMLDepth+1; i++ {
		deep.WriteString("</a>")
	}
	if _, err := parseXML([]byte(deep.String())); !errors.Is(err, ErrLimit) {
		t.Fatalf("deep document error = %v, want ErrLimit", err)
	}

	malformed := []struct {
		name string
		xml  string
	}{
		{name: "duplicate attribute", xml: `<root a="1" a="2"/>`},
		{name: "duplicate expanded attribute", xml: `<root xmlns:p="urn:p" xmlns:q="urn:p" p:a="1" q:a="2"/>`},
		{name: "duplicate namespace", xml: `<root xmlns:p="urn:p" xmlns:p="urn:p"/>`},
		{name: "duplicate default namespace", xml: `<root xmlns="urn:a" xmlns="urn:b"/>`},
		{name: "xmlns prefix", xml: `<root xmlns:xmlns="urn:x"/>`},
		{name: "wrong xml prefix binding", xml: `<root xmlns:xml="urn:x"/>`},
		{name: "xml namespace on other prefix", xml: `<root xmlns:p="http://www.w3.org/XML/1998/namespace"/>`},
		{name: "xmlns namespace", xml: `<root xmlns:p="http://www.w3.org/2000/xmlns/"/>`},
		{name: "undeclared element prefix", xml: `<p:root/>`},
		{name: "undeclared attribute prefix", xml: `<root p:a="1"/>`},
		{name: "relative namespace", xml: `<root xmlns:p="relative"/>`},
		{name: "empty prefixed namespace", xml: `<root xmlns:p=""/>`},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseXML([]byte(tc.xml)); !errors.Is(err, ErrInvalidXML) {
				t.Fatalf("parseXML error = %v, want ErrInvalidXML", err)
			}
		})
	}

	if _, err := parseXML(bytes.Repeat([]byte(" "), maxXMLBytes+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized document error = %v, want ErrLimit", err)
	}
}

// TestInclusiveNamespacesHelpers covers PrefixList formatting and parsing. |
// TestInclusiveNamespacesHelpers 覆盖 PrefixList 的格式化与解析。
func TestInclusiveNamespacesHelpers(t *testing.T) {
	if got := joinPrefixList([]string{"", "p", "q"}); got != "#default p q" {
		t.Fatalf("joinPrefixList = %q", got)
	}
	if got := joinPrefixList(nil); got != "" {
		t.Fatalf("empty joinPrefixList = %q", got)
	}
	node := buildInclusiveNamespaces("ds", []string{"", "p"})
	if node.prefix != "ec" || node.local != "InclusiveNamespaces" {
		t.Fatalf("InclusiveNamespaces node = %s:%s", node.prefix, node.local)
	}
	value, ok := node.attrValue("", "PrefixList")
	if !ok || value != "#default p" {
		t.Fatalf("PrefixList attribute = %q, %v", value, ok)
	}
	ns, ok := resolvePrefix(node, "ec")
	if !ok || ns != NamespaceExcC14N {
		t.Fatalf("ec prefix = %q, %v", ns, ok)
	}
	parsed := parseInclusiveNamespaces(mustParseNode(t, `<Method xmlns:ec="`+NamespaceExcC14N+`"><ec:InclusiveNamespaces PrefixList="  #default	p  q "/></Method>`))
	if len(parsed) != 3 || parsed[0] != "#default" || parsed[2] != "q" {
		t.Fatalf("parseInclusiveNamespaces = %q", parsed)
	}
	if got := parseInclusiveNamespaces(mustParseNode(t, `<Method/>`)); got != nil {
		t.Fatalf("missing InclusiveNamespaces = %q", got)
	}
}

// TestECDSACanonicalizationRoundTrip keeps an ECDSA round trip under exclusive C14N. |
// TestECDSACanonicalizationRoundTrip 在排他规范化下保持 ECDSA 往返。
func TestECDSACanonicalizationRoundTrip(t *testing.T) {
	key := testECDSAPrivateKey(t, elliptic.P384())
	signed, err := Sign([]byte(c14nNamespacedDocument), SignOptions{
		PrivateKey:             key,
		ID:                     "c",
		Exclusive:              true,
		InclusiveNamespaces:    []string{"q"},
		CanonicalizationMethod: excC14NURI,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := VerifyElement(signed, "c", VerifyOptions{Certificates: signerCertificates(t, testRSAPrivateKey(t))}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong RSA certificate error = %v, want ErrSignatureInvalid", err)
	}
	ecCert := testCertificate(t, key)
	if _, err := VerifyElement(signed, "c", VerifyOptions{Certificates: []*x509.Certificate{ecCert}}); err != nil {
		t.Fatalf("VerifyElement: %v", err)
	}
}

// TestGoxmldsigShapedSignature locks the ds-prefix, C14N 1.1, RSA-SHA256 and trailing-signature
// layout emitted by goxmldsig-style signers, without depending on goxmldsig. |
// TestGoxmldsigShapedSignature 锁定 goxmldsig 风格签名器输出的 ds 前缀、C14N 1.1、RSA-SHA256
// 与尾部签名布局，且不依赖 goxmldsig。
func TestGoxmldsigShapedSignature(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	signed, err := Sign([]byte(`<root ID="r"><child>value</child></root>`), SignOptions{
		PrivateKey:             key,
		Certificate:            cert,
		IncludeKeyInfo:         true,
		ID:                     "r",
		Prefix:                 "ds",
		CanonicalizationMethod: c14n11URI,
		SignatureMethod:        sigRSASHA256URI,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(signed), []byte(`<root`)) {
		t.Fatalf("unexpected document: %s", signed)
	}
	for _, marker := range []string{`<ds:Signature`, `Algorithm="` + c14n11URI + `"`, `Algorithm="` + sigRSASHA256URI + `"`} {
		if !bytes.Contains(signed, []byte(marker)) {
			t.Fatalf("signature lacks %q: %s", marker, signed)
		}
	}
	if !bytes.HasSuffix(bytes.TrimSpace(signed), []byte(`</ds:Signature></root>`)) {
		t.Fatalf("signature is not the last root child: %s", signed)
	}
	result, err := VerifyElement(signed, "r", VerifyOptions{Certificates: []*x509.Certificate{cert}})
	if err != nil {
		t.Fatalf("VerifyElement: %v", err)
	}
	if result.SignatureMethod != sigRSASHA256URI {
		t.Fatalf("SignatureMethod = %q", result.SignatureMethod)
	}
}
