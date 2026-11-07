package xmlsig

import (
	"bytes"
	"net/url"
	"sort"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// Canonicalize returns the Canonical XML 1.0 form of data without comments. | Canonicalize 返回
// data 的无注释 Canonical XML 1.0 形式。
func Canonicalize(data []byte) ([]byte, error) {
	return CanonicalizeWithOptions(data, CanonicalizeOptions{})
}

// CanonicalizeWithOptions returns the canonical form of the whole document. | CanonicalizeWithOptions
// 返回整个文档的规范形式。
func CanonicalizeWithOptions(data []byte, opts CanonicalizeOptions) ([]byte, error) {
	if err := validateCanonicalizeOptions(opts); err != nil {
		return nil, err
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	return canonicalizeDocument(doc, opts), nil
}

// CanonicalizeElement returns the canonical form of the element carrying id. The element acts as
// the apex of a document subset: in inclusive mode inherited xml:lang, xml:space and xml:base
// values from omitted ancestors are applied, in exclusive mode they are not. | CanonicalizeElement
// 返回带有 id 的元素的规范形式。该元素作为文档子集的顶点：包容模式会应用被省略祖先继承的
// xml:lang、xml:space 与 xml:base，排他模式不会。
func CanonicalizeElement(data []byte, id string, opts CanonicalizeOptions) ([]byte, error) {
	if err := validateCanonicalizeOptions(opts); err != nil {
		return nil, err
	}
	if id == "" {
		return nil, errs.Detail(ErrReference, "empty element ID | 元素 ID 为空")
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	target, err := findElementByID(doc.root, id)
	if err != nil {
		return nil, err
	}
	return canonicalizeSubtree(target, opts), nil
}

// CanonicalizeNode returns the canonical form of one public DOM node. Namespace declarations were
// discarded by xml.Parse, so namespace URIs are re-declared with synthesized prefixes (ns0, ns1,
// ...). This function is intended for nodes built programmatically; use the byte-oriented
// functions when prefix fidelity matters. | CanonicalizeNode 返回单个公开 DOM 节点的规范形式。
// xml.Parse 会丢弃命名空间声明，因此命名空间 URI 会以合成前缀（ns0、ns1……）重新声明。本函数
// 面向程序构造的节点；需要保留前缀时请使用字节接口。
func CanonicalizeNode(node *xml.Node, opts CanonicalizeOptions) ([]byte, error) {
	if err := validateCanonicalizeOptions(opts); err != nil {
		return nil, err
	}
	n, err := convertDOMNode(node)
	if err != nil {
		return nil, err
	}
	switch n.kind {
	case elementNode:
		return canonicalizeSubtree(n, opts), nil
	case textNode:
		var b bytes.Buffer
		appendEscapedText(&b, n.data)
		return b.Bytes(), nil
	case commentNode:
		if !opts.WithComments {
			return nil, nil
		}
		var b bytes.Buffer
		b.WriteString("<!--")
		b.Write(n.data)
		b.WriteString("-->")
		return b.Bytes(), nil
	case procInstNode:
		var b bytes.Buffer
		writeProcInst(&b, n.local, n.data)
		return b.Bytes(), nil
	default:
		return nil, errs.Detail(ErrUnsupported, "node kind %d cannot be canonicalized | 节点类型 %d 无法规范化", n.kind, n.kind)
	}
}

// validateCanonicalizeOptions checks the canonicalization version label. | validateCanonicalizeOptions
// 检查规范化版本标签。
func validateCanonicalizeOptions(opts CanonicalizeOptions) error {
	switch opts.Version {
	case "", "1.0", "1.1":
		return nil
	default:
		return errs.Detail(ErrInvalidOption, "unsupported canonical XML version %q | 不支持的规范 XML 版本 %q", opts.Version, opts.Version)
	}
}

// canonicalizer holds the shared state of one canonicalization run. | canonicalizer 保存一次
// 规范化运行的共享状态。
type canonicalizer struct {
	buf        bytes.Buffer
	opts       CanonicalizeOptions
	prefixList map[string]struct{}
	exclude    *xmlNode
	scope      map[string]string
	rendered   map[string]string
}

// newCanonicalizer builds a canonicalizer. | newCanonicalizer 构造规范化器。
func newCanonicalizer(opts CanonicalizeOptions) *canonicalizer {
	list := make(map[string]struct{}, len(opts.InclusiveNamespaces))
	for _, p := range opts.InclusiveNamespaces {
		if p == "#default" {
			p = ""
		}
		list[p] = struct{}{}
	}
	return &canonicalizer{
		opts:       opts,
		prefixList: list,
		scope:      make(map[string]string),
		rendered:   make(map[string]string),
	}
}

// canonicalizeDocument canonicalizes all document-level nodes. | canonicalizeDocument 规范化所有
// 文档级节点。
func canonicalizeDocument(doc *xmlDocument, opts CanonicalizeOptions) []byte {
	return newCanonicalizer(opts).canonicalizeDocument(doc)
}

// canonicalizeDocument renders all document-level nodes with the receiver's state. |
// canonicalizeDocument 使用接收者的状态渲染所有文档级节点。
func (c *canonicalizer) canonicalizeDocument(doc *xmlDocument) []byte {
	seenRoot := false
	for _, n := range doc.children {
		switch n.kind {
		case elementNode:
			if n == c.exclude {
				continue
			}
			c.element(n, nil, nil)
			seenRoot = true
		case procInstNode:
			if seenRoot {
				c.buf.WriteByte('\n')
			}
			writeProcInst(&c.buf, n.local, n.data)
			if !seenRoot {
				c.buf.WriteByte('\n')
			}
		case commentNode:
			if !c.opts.WithComments {
				continue
			}
			if seenRoot {
				c.buf.WriteByte('\n')
			}
			c.buf.WriteString("<!--")
			c.buf.Write(n.data)
			c.buf.WriteString("-->")
			if !seenRoot {
				c.buf.WriteByte('\n')
			}
		}
	}
	return c.buf.Bytes()
}

// canonicalizeSubtree canonicalizes an element as the apex of a document subset. | canonicalizeSubtree
// 把元素作为文档子集顶点进行规范化。
func canonicalizeSubtree(apex *xmlNode, opts CanonicalizeOptions) []byte {
	return newCanonicalizer(opts).canonicalizeSubtree(apex)
}

// canonicalizeSubtree renders an element as the apex of a document subset with the receiver's
// state. | canonicalizeSubtree 使用接收者的状态把元素作为文档子集顶点渲染。
func (c *canonicalizer) canonicalizeSubtree(apex *xmlNode) []byte {
	// Apply omitted ancestor declarations from the outermost ancestor inwards so that the
	// nearest declaration wins, as required by namespace scoping. | 从最外层祖先向内应用被省略的
	// 声明，使最近的声明获胜，符合命名空间作用域规则。
	var ancestors []*xmlNode
	for p := apex.parent; p != nil; p = p.parent {
		ancestors = append(ancestors, p)
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		applyNamespaceDecls(ancestors[i], c.scope)
	}
	var extra []xmlAttr
	var baseOverride *string
	if !c.opts.Exclusive {
		if v, ok := inheritedXMLAttr(apex, "lang"); ok {
			if _, own := apex.attrValue("xml", "lang"); !own {
				extra = append(extra, xmlAttr{prefix: "xml", local: "lang", value: v})
			}
		}
		if v, ok := inheritedXMLAttr(apex, "space"); ok {
			if _, own := apex.attrValue("xml", "space"); !own {
				extra = append(extra, xmlAttr{prefix: "xml", local: "space", value: v})
			}
		}
		// Canonical XML 1.0 (and exclusive canonicalization) leaves xml:base fixup
		// undefined; only inclusive 1.1 applies it. | Canonical XML 1.0（以及排他规范化）
		// 未定义 xml:base 修正；只有包容 1.1 会应用它。
		if c.opts.Version == "1.1" {
			if v, ok := fixupXMLBase(apex); ok {
				baseOverride = &v
			}
		}
	}
	c.element(apex, extra, baseOverride)
	return c.buf.Bytes()
}

// inheritedXMLAttr returns the nearest xml:lang or xml:space value on an omitted ancestor. |
// inheritedXMLAttr 返回被省略祖先上最近的 xml:lang 或 xml:space 值。
func inheritedXMLAttr(n *xmlNode, local string) (string, bool) {
	for p := n.parent; p != nil; p = p.parent {
		if v, ok := p.attrValue("xml", local); ok {
			return v, true
		}
	}
	return "", false
}

// fixupXMLBase combines xml:base values from omitted ancestors with the value on n. The second
// result reports whether the element's rendered xml:base must be replaced or removed. Ancestor
// values are resolved from the outermost ancestor inwards, as XML Base requires; nearest-first
// combination produces wrong URIs for relative bases. | fixupXMLBase 把被省略祖先的 xml:base 与 n
// 自身的值组合。第二个返回值表示是否必须替换或删除元素渲染出的 xml:base。按 XML Base 要求，
// 祖先值从最外层向内解析；由近及远合并会为相对基址产生错误 URI。
func fixupXMLBase(n *xmlNode) (string, bool) {
	var ancestors []*xmlNode
	for p := n.parent; p != nil; p = p.parent {
		ancestors = append(ancestors, p)
	}
	base := ""
	found := false
	for i := len(ancestors) - 1; i >= 0; i-- {
		v, ok := ancestors[i].attrValue("xml", "base")
		if !ok {
			continue
		}
		base = joinBaseURI(base, v)
		found = true
	}
	if !found {
		return "", false
	}
	value, _ := n.attrValue("xml", "base")
	return joinBaseURI(base, value), true
}

// joinBaseURI resolves ref against base using RFC 3986 reference resolution. | joinBaseURI 按
// RFC 3986 引用解析规则把 ref 解析到 base 上。
func joinBaseURI(base, ref string) string {
	if ref == "" {
		return base
	}
	if base == "" {
		return ref
	}
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if b.IsAbs() || b.Host != "" {
		return b.ResolveReference(r).String()
	}
	// net/url turns a relative base into an absolute path, so merge the paths under a synthetic
	// authority and restore the relative form afterwards. | net/url 会把相对基址变为绝对路径，
	// 因此在合成 authority 下合并路径，再还原相对形式。
	if r.IsAbs() || r.Host != "" || strings.HasPrefix(r.Path, "/") {
		return ref
	}
	absolutePath := strings.HasPrefix(b.Path, "/")
	path := b.Path
	if !absolutePath {
		path = "/" + b.Path
	}
	synthetic := &url.URL{Scheme: "http", Host: "xmlsig.invalid", Path: path}
	resolved := synthetic.ResolveReference(r).String()
	if absolutePath {
		return strings.TrimPrefix(resolved, "http://xmlsig.invalid")
	}
	return strings.TrimPrefix(resolved, "http://xmlsig.invalid/")
}

// nsRenderedChange records one reversible namespace-rendering change. | nsRenderedChange 记录一次
// 可撤销的命名空间渲染变更。
type nsRenderedChange struct {
	prefix string
	old    string
	had    bool
}

// element renders one element and its subtree. | element 渲染一个元素及其子树。
func (c *canonicalizer) element(n *xmlNode, extra []xmlAttr, baseOverride *string) {
	if n == c.exclude {
		return
	}
	c.buf.WriteByte('<')
	c.buf.WriteString(qualifiedName(n.prefix, n.local))
	scopeChanges := applyNamespaceDecls(n, c.scope)
	renderedChanges := c.writeNamespaces(n)
	c.writeAttributes(n, extra, baseOverride)
	c.buf.WriteByte('>')
	for _, child := range n.children {
		c.renderNode(child)
	}
	c.buf.WriteString("</")
	c.buf.WriteString(qualifiedName(n.prefix, n.local))
	c.buf.WriteByte('>')
	undoRendered(c.rendered, renderedChanges)
	undoNamespaceDecls(c.scope, scopeChanges)
}

// renderNode renders one child node. | renderNode 渲染一个子节点。
func (c *canonicalizer) renderNode(n *xmlNode) {
	switch n.kind {
	case elementNode:
		c.element(n, nil, nil)
	case textNode:
		appendEscapedText(&c.buf, n.data)
	case commentNode:
		if c.opts.WithComments {
			c.buf.WriteString("<!--")
			c.buf.Write(n.data)
			c.buf.WriteString("-->")
		}
	case procInstNode:
		writeProcInst(&c.buf, n.local, n.data)
	}
}

// writeNamespaces emits the namespace declarations required at n and reports reversible changes.
// | writeNamespaces 在 n 处输出所需的命名空间声明，并返回可撤销的变更。
func (c *canonicalizer) writeNamespaces(n *xmlNode) []nsRenderedChange {
	visible := make(map[string]struct{})
	if c.opts.Exclusive {
		if n.prefix == "" {
			visible[""] = struct{}{}
		} else if n.prefix != "xml" {
			visible[n.prefix] = struct{}{}
		}
		for _, a := range n.attrs {
			if a.prefix != "" && a.prefix != "xml" {
				visible[a.prefix] = struct{}{}
			}
		}
		for p := range c.prefixList {
			if p != "xml" {
				visible[p] = struct{}{}
			}
		}
	} else {
		for p := range c.scope {
			if p != "xml" {
				visible[p] = struct{}{}
			}
		}
		visible[""] = struct{}{}
	}

	prefixes := make([]string, 0, len(visible))
	for p := range visible {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	var changes []nsRenderedChange
	for _, p := range prefixes {
		uri := c.scope[p]
		old, had := c.rendered[p]
		if uri == "" {
			if old == "" {
				continue
			}
		} else if had && old == uri {
			continue
		}
		writeNamespaceDecl(&c.buf, p, uri)
		c.rendered[p] = uri
		changes = append(changes, nsRenderedChange{prefix: p, old: old, had: had})
	}
	return changes
}

// undoRendered reverts namespace-rendering changes. | undoRendered 撤销命名空间渲染变更。
func undoRendered(rendered map[string]string, changes []nsRenderedChange) {
	for i := len(changes) - 1; i >= 0; i-- {
		ch := changes[i]
		if ch.had {
			rendered[ch.prefix] = ch.old
		} else {
			delete(rendered, ch.prefix)
		}
	}
}

// sortableAttr is an attribute prepared for canonical sorting. | sortableAttr 是准备规范排序的
// 属性。
type sortableAttr struct {
	prefix string
	local  string
	uri    string
	value  string
}

// writeAttributes emits attributes sorted by namespace URI and local name. | writeAttributes 按
// 命名空间 URI 与本地名排序输出属性。
func (c *canonicalizer) writeAttributes(n *xmlNode, extra []xmlAttr, baseOverride *string) {
	attrs := make([]sortableAttr, 0, len(n.attrs)+len(extra)+1)
	hasBase := false
	for _, a := range n.attrs {
		if a.prefix == "xml" && a.local == "base" {
			hasBase = true
			if baseOverride != nil {
				if *baseOverride == "" {
					continue
				}
				a.value = *baseOverride
			}
		}
		attrs = append(attrs, sortableAttr{prefix: a.prefix, local: a.local, uri: attrNamespaceURI(n, a.prefix), value: a.value})
	}
	if baseOverride != nil && !hasBase && *baseOverride != "" {
		attrs = append(attrs, sortableAttr{prefix: "xml", local: "base", uri: xmlNamespaceURI, value: *baseOverride})
	}
	for _, a := range extra {
		attrs = append(attrs, sortableAttr{prefix: a.prefix, local: a.local, uri: attrNamespaceURI(n, a.prefix), value: a.value})
	}
	sort.SliceStable(attrs, func(i, j int) bool {
		if attrs[i].uri != attrs[j].uri {
			return attrs[i].uri < attrs[j].uri
		}
		return attrs[i].local < attrs[j].local
	})
	for _, a := range attrs {
		c.buf.WriteByte(' ')
		c.buf.WriteString(qualifiedName(a.prefix, a.local))
		c.buf.WriteString(`="`)
		appendEscapedAttr(&c.buf, a.value)
		c.buf.WriteByte('"')
	}
}

// attrNamespaceURI resolves the namespace URI of an attribute prefix. | attrNamespaceURI 解析属性
// 前缀的命名空间 URI。
func attrNamespaceURI(n *xmlNode, prefix string) string {
	if prefix == "" {
		return ""
	}
	uri, _ := resolvePrefix(n, prefix)
	return uri
}

// c14nSpecForURI maps a canonicalization algorithm URI to options. | c14nSpecForURI 把规范化算法
// URI 映射为选项。
func c14nSpecForURI(uri string) (CanonicalizeOptions, error) {
	switch uri {
	case c14n10URI:
		return CanonicalizeOptions{Version: "1.0"}, nil
	case c14n10WithCommentsURI:
		return CanonicalizeOptions{Version: "1.0", WithComments: true}, nil
	case c14n11URI:
		return CanonicalizeOptions{Version: "1.1"}, nil
	case c14n11WithCommentsURI:
		return CanonicalizeOptions{Version: "1.1", WithComments: true}, nil
	case excC14NURI:
		return CanonicalizeOptions{Exclusive: true}, nil
	case excC14NWithCommentsURI:
		return CanonicalizeOptions{Exclusive: true, WithComments: true}, nil
	default:
		return CanonicalizeOptions{}, errs.Detail(ErrUnsupported, "canonicalization algorithm %q is not supported | 不支持规范化算法 %q", uri, uri)
	}
}

// c14nURIs lists every accepted canonicalization algorithm URI. | c14nURIs 列出所有接受的规范化
// 算法 URI。
func c14nURIs() []string {
	return []string{
		c14n10URI, c14n10WithCommentsURI,
		c14n11URI, c14n11WithCommentsURI,
		excC14NURI, excC14NWithCommentsURI,
	}
}

// isCanonicalizationURI reports whether uri names a supported canonicalization algorithm. |
// isCanonicalizationURI 判断 uri 是否为受支持的规范化算法。
func isCanonicalizationURI(uri string) bool {
	for _, u := range c14nURIs() {
		if u == uri {
			return true
		}
	}
	return false
}

// trimSpaceText removes XML whitespace around base64 payload text. | trimSpaceText 删除 base64
// 载荷文本两端的 XML 空白。
func trimSpaceText(s string) string {
	return strings.Trim(s, " \t\r\n")
}
