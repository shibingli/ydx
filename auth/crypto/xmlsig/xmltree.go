package xmlsig

import (
	"bytes"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/xml"
)

// nodeKind identifies the kind of an internal tree node. | nodeKind 标识内部树节点类型。
type nodeKind uint8

const (
	elementNode nodeKind = iota + 1
	textNode
	commentNode
	procInstNode
	directiveNode
)

// nsDecl is one namespace declaration written on an element. | nsDecl 是元素上的一条命名空间声明。
type nsDecl struct {
	prefix string
	uri    string
}

// xmlAttr is one non-namespace attribute. | xmlAttr 是一条非命名空间属性。
type xmlAttr struct {
	prefix string
	local  string
	value  string
}

// xmlNode is one parsed XML node. The tree keeps prefixes and namespace declarations verbatim,
// which the canonicalizer needs. | xmlNode 是一个解析后的 XML 节点。树逐字保留前缀与命名空间
// 声明，这是规范化器所必需的。
type xmlNode struct {
	parent   *xmlNode
	kind     nodeKind
	prefix   string
	local    string
	attrs    []xmlAttr
	nsDecls  []nsDecl
	children []*xmlNode
	data     []byte
}

// xmlDocument is a parsed document with prolog, root element and epilog. | xmlDocument 是包含
// 序言、根元素与尾声的解析后文档。
type xmlDocument struct {
	children []*xmlNode
	root     *xmlNode
}

// Parsing bounds protect canonicalization, signature and encryption paths from resource
// exhaustion. | 解析上限保护规范化、签名与加密路径免受资源耗尽影响。
const (
	maxXMLBytes   = 64 << 20
	maxXMLDepth   = 256
	maxXMLNodes   = 1 << 20
	maxXMLAttrs   = 4096
	maxXMLNSDecls = 1024
)

// parseXML parses data into an internal tree with namespace prefixes and declarations intact. | parseXML
// 把 data 解析为保留命名空间前缀与声明的内部树。
func parseXML(data []byte) (*xmlDocument, error) {
	if int64(len(data)) > maxXMLBytes {
		return nil, errs.Detail(ErrLimit, "XML document exceeds %d bytes | XML 文档超过 %d 字节", maxXMLBytes, maxXMLBytes)
	}
	// A UTF-8 byte order mark is not part of the XML infoset; ydx/xml (following encoding/xml)
	// reports it as character data, which would otherwise look like text outside the root. |
	// UTF-8 字节序标记不属于 XML 信息集；ydx/xml（与 encoding/xml 一致）把它作为字符数据返回，
	// 否则会被视为根元素之外的文本。
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	dec := xml.NewDecoderBytes(data)
	doc := &xmlDocument{}
	var stack []*xmlNode
	rootSeen := false
	rootClosed := false
	nodes := 0
	countNode := func() error {
		nodes++
		if nodes > maxXMLNodes {
			return errs.Detail(ErrLimit, "XML document exceeds %d nodes | XML 文档超过 %d 个节点", maxXMLNodes, maxXMLNodes)
		}
		return nil
	}

	attach := func(n *xmlNode) {
		if len(stack) == 0 {
			doc.children = append(doc.children, n)
			return
		}
		p := stack[len(stack)-1]
		n.parent = p
		p.children = append(p.children, n)
	}

	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidXML)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if rootClosed {
				return nil, errs.Detail(ErrInvalidXML, "multiple root elements | 存在多个根元素")
			}
			if len(stack) >= maxXMLDepth {
				return nil, errs.Detail(ErrLimit, "XML depth exceeds %d | XML 深度超过 %d", maxXMLDepth, maxXMLDepth)
			}
			if err := countNode(); err != nil {
				return nil, err
			}
			if len(t.Attr) > maxXMLAttrs+maxXMLNSDecls {
				return nil, errs.Detail(ErrLimit, "element <%s> has %d attributes | 元素 <%s> 有 %d 个属性", t.Name.Local, len(t.Attr), t.Name.Local, len(t.Attr))
			}
			n := &xmlNode{kind: elementNode, prefix: t.Name.Space, local: t.Name.Local}
			seenAttr := make(map[string]struct{}, len(t.Attr))
			seenNS := make(map[string]struct{}, len(t.Attr))
			for _, a := range t.Attr {
				switch {
				case a.Name.Space == "xmlns":
					if _, dup := seenNS[a.Name.Local]; dup {
						return nil, errs.Detail(ErrInvalidXML, "duplicate namespace declaration for prefix %q | 前缀 %q 的命名空间声明重复", a.Name.Local, a.Name.Local)
					}
					seenNS[a.Name.Local] = struct{}{}
					n.nsDecls = append(n.nsDecls, nsDecl{prefix: a.Name.Local, uri: a.Value})
					continue
				case a.Name.Space == "" && a.Name.Local == "xmlns":
					if _, dup := seenNS[""]; dup {
						return nil, errs.Detail(ErrInvalidXML, "duplicate default namespace declaration | 默认命名空间声明重复")
					}
					seenNS[""] = struct{}{}
					n.nsDecls = append(n.nsDecls, nsDecl{prefix: "", uri: a.Value})
					continue
				}
				key := a.Name.Space + "\x00" + a.Name.Local
				if _, dup := seenAttr[key]; dup {
					return nil, errs.Detail(ErrInvalidXML, "duplicate attribute %q | 属性 %q 重复", a.Name.Local, a.Name.Local)
				}
				seenAttr[key] = struct{}{}
				n.attrs = append(n.attrs, xmlAttr{prefix: a.Name.Space, local: a.Name.Local, value: a.Value})
			}
			attach(n)
			if !rootSeen {
				rootSeen = true
				doc.root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errs.Detail(ErrInvalidXML, "unexpected end element | 意外的结束元素")
			}
			top := stack[len(stack)-1]
			if top.local != t.Name.Local || top.prefix != t.Name.Space {
				return nil, errs.Detail(ErrInvalidXML, "element <%s> closed by </%s> | 元素 <%s> 被 </%s> 关闭", qualifiedName(top.prefix, top.local), qualifiedName(t.Name.Space, t.Name.Local), qualifiedName(top.prefix, top.local), qualifiedName(t.Name.Space, t.Name.Local))
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				rootClosed = true
			}
		case xml.CharData:
			data := append([]byte(nil), t...)
			if len(stack) == 0 {
				if isXMLSpace(data) {
					continue
				}
				return nil, errs.Detail(ErrInvalidXML, "character data outside the root element | 根元素之外存在字符数据")
			}
			if err := countNode(); err != nil {
				return nil, err
			}
			attach(&xmlNode{kind: textNode, data: data})
		case xml.Comment:
			if err := countNode(); err != nil {
				return nil, err
			}
			attach(&xmlNode{kind: commentNode, data: append([]byte(nil), t...)})
		case xml.ProcInst:
			if err := countNode(); err != nil {
				return nil, err
			}
			attach(&xmlNode{kind: procInstNode, local: t.Target, data: append([]byte(nil), t.Inst...)})
		case xml.Directive:
			// DOCTYPE and other directives can declare entities; reject them outright. | DOCTYPE 与
			// 其它指令可以声明实体，直接拒绝。
			return nil, errs.Detail(ErrInvalidXML, "XML directives are not allowed | 不允许 XML 指令")
		}
	}
	if len(stack) != 0 {
		return nil, errs.Detail(ErrInvalidXML, "unexpected end of input | 输入意外结束")
	}
	if doc.root == nil {
		return nil, errs.Detail(ErrInvalidXML, "no root element | 缺少根元素")
	}
	if err := validateNamespaces(doc.root, make(map[string]string)); err != nil {
		return nil, err
	}
	return doc, nil
}

// isXMLSpace reports whether b consists only of XML whitespace. | isXMLSpace 判断 b 是否只包含
// XML 空白字符。
func isXMLSpace(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}
	return true
}

// qualifiedName renders prefix:local or local. | qualifiedName 渲染 prefix:local 或 local。
func qualifiedName(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

// applyNamespaceDecls updates scope with the declarations of n and returns undo information. |
// applyNamespaceDecls 用 n 的声明更新 scope，并返回撤销信息。
func applyNamespaceDecls(n *xmlNode, scope map[string]string) (changes []nsChange) {
	for _, d := range n.nsDecls {
		old, had := scope[d.prefix]
		if d.uri == "" {
			delete(scope, d.prefix)
		} else {
			scope[d.prefix] = d.uri
		}
		changes = append(changes, nsChange{prefix: d.prefix, old: old, had: had})
	}
	return changes
}

// nsChange records one reversible namespace scope change. | nsChange 记录一次可撤销的命名空间
// 作用域变更。
type nsChange struct {
	prefix string
	old    string
	had    bool
}

// undoNamespaceDecls reverts changes in reverse order. | undoNamespaceDecls 逆序撤销变更。
func undoNamespaceDecls(scope map[string]string, changes []nsChange) {
	for i := len(changes) - 1; i >= 0; i-- {
		c := changes[i]
		if c.had {
			scope[c.prefix] = c.old
		} else {
			delete(scope, c.prefix)
		}
	}
}

// resolvePrefix resolves a prefix in the scope of n. The reserved xml prefix is always bound. |
// resolvePrefix 在 n 的作用域内解析前缀；保留前缀 xml 始终有绑定。
func resolvePrefix(n *xmlNode, prefix string) (string, bool) {
	if prefix == "xml" {
		return xmlNamespaceURI, true
	}
	for cur := n; cur != nil; cur = cur.parent {
		for i := len(cur.nsDecls) - 1; i >= 0; i-- {
			d := cur.nsDecls[i]
			if d.prefix != prefix {
				continue
			}
			if d.uri == "" {
				return "", false
			}
			return d.uri, true
		}
	}
	if prefix == "" {
		return "", true
	}
	return "", false
}

// validateNamespaces checks namespace well-formedness and the reserved binding rules. |
// validateNamespaces 检查命名空间良构性与保留绑定规则。
func validateNamespaces(n *xmlNode, scope map[string]string) error {
	for _, d := range n.nsDecls {
		switch {
		case d.prefix == "xmlns":
			return errs.Detail(ErrInvalidXML, "the xmlns prefix cannot be declared | 不得声明 xmlns 前缀")
		case d.prefix == "xml" && d.uri != xmlNamespaceURI:
			return errs.Detail(ErrInvalidXML, "the xml prefix must be bound to %s | xml 前缀必须绑定到 %s", xmlNamespaceURI, xmlNamespaceURI)
		case d.uri == xmlNamespaceURI && d.prefix != "xml":
			return errs.Detail(ErrInvalidXML, "only the xml prefix may use the XML namespace | 只有 xml 前缀可以使用 XML 命名空间")
		case d.uri == xmlnsNamespaceURI:
			return errs.Detail(ErrInvalidXML, "the xmlns namespace cannot be bound | 不得绑定 xmlns 命名空间")
		case d.prefix != "" && d.uri == "":
			return errs.Detail(ErrInvalidXML, "prefix %q cannot be undeclared in XML 1.0 | XML 1.0 中不得取消前缀 %q 的声明", d.prefix, d.prefix)
		case d.uri != "" && !isAbsoluteURI(d.uri):
			return errs.Detail(ErrInvalidXML, "namespace URI %q is relative | 命名空间 URI %q 是相对 URI", d.uri, d.uri)
		}
	}
	changes := applyNamespaceDecls(n, scope)
	defer undoNamespaceDecls(scope, changes)

	if n.prefix != "" {
		if _, ok := resolvePrefix(n, n.prefix); !ok {
			return errs.Detail(ErrInvalidXML, "undeclared namespace prefix %q | 未声明的命名空间前缀 %q", n.prefix, n.prefix)
		}
	}
	seenExpanded := make(map[string]struct{}, len(n.attrs))
	for _, a := range n.attrs {
		uri := ""
		if a.prefix != "" {
			resolved, ok := resolvePrefix(n, a.prefix)
			if !ok {
				return errs.Detail(ErrInvalidXML, "undeclared namespace prefix %q on attribute %q | 属性 %q 使用了未声明的前缀 %q", a.prefix, a.local, a.local, a.prefix)
			}
			uri = resolved
		}
		key := uri + "\x00" + a.local
		if _, dup := seenExpanded[key]; dup {
			return errs.Detail(ErrInvalidXML, "duplicate expanded attribute {%s}%s | 展开名 {%s}%s 的属性重复", uri, a.local, uri, a.local)
		}
		seenExpanded[key] = struct{}{}
	}
	for _, c := range n.children {
		if c.kind == elementNode {
			if err := validateNamespaces(c, scope); err != nil {
				return err
			}
		}
	}
	return nil
}

// isAbsoluteURI reports whether s has a URI scheme. | isAbsoluteURI 判断 s 是否带有 URI scheme。
func isAbsoluteURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != ""
}

// walkElements calls fn for every element in document order. | walkElements 按文档顺序对每个元素
// 调用 fn。
func walkElements(root *xmlNode, fn func(*xmlNode)) {
	if root == nil {
		return
	}
	fn(root)
	for _, c := range root.children {
		if c.kind == elementNode {
			walkElements(c, fn)
		}
	}
}

// isIDAttribute reports whether a is treated as an identifier attribute. Matching is
// case-insensitive on the local name so id, Id, ID, xml:id and wsu:Id are all covered. | isIDAttribute
// 判断 a 是否被视为标识属性。本地名不区分大小写，因此覆盖 id、Id、ID、xml:id 与 wsu:Id。
func isIDAttribute(a xmlAttr) bool {
	return strings.EqualFold(a.local, "id")
}

// collectIDs indexes identifier attributes and rejects duplicates and ambiguous elements. |
// collectIDs 建立标识属性索引，并拒绝重复值与存在歧义的元素。
func collectIDs(root *xmlNode) (map[string]*xmlNode, error) {
	ids := make(map[string]*xmlNode)
	var problem error
	walkElements(root, func(n *xmlNode) {
		if problem != nil {
			return
		}
		seen := false
		for _, a := range n.attrs {
			if !isIDAttribute(a) {
				continue
			}
			if seen {
				problem = errs.Detail(ErrDuplicateID, "element <%s> has more than one ID attribute | 元素 <%s> 含多个 ID 属性", qualifiedName(n.prefix, n.local), qualifiedName(n.prefix, n.local))
				return
			}
			seen = true
			if a.value == "" {
				continue
			}
			if _, dup := ids[a.value]; dup {
				problem = errs.Detail(ErrDuplicateID, "ID %q appears more than once | ID %q 出现了多次", a.value, a.value)
				return
			}
			ids[a.value] = n
		}
	})
	return ids, problem
}

// findElementByID resolves id to exactly one element. | findElementByID 把 id 解析为唯一元素。
func findElementByID(root *xmlNode, id string) (*xmlNode, error) {
	ids, err := collectIDs(root)
	if err != nil {
		return nil, err
	}
	n, ok := ids[id]
	if !ok {
		return nil, errs.Detail(ErrReference, "element with ID %q not found | 未找到 ID 为 %q 的元素", id, id)
	}
	return n, nil
}

// serializeDocument renders a document back to XML. | serializeDocument 把文档重新渲染为 XML。
func serializeDocument(doc *xmlDocument) []byte {
	var b bytes.Buffer
	for _, n := range doc.children {
		serializeNode(&b, n)
	}
	return b.Bytes()
}

// serializeNode renders one node. | serializeNode 渲染单个节点。
func serializeNode(b *bytes.Buffer, n *xmlNode) {
	switch n.kind {
	case elementNode:
		b.WriteByte('<')
		b.WriteString(qualifiedName(n.prefix, n.local))
		for _, d := range n.nsDecls {
			writeNamespaceDecl(b, d.prefix, d.uri)
		}
		for _, a := range n.attrs {
			b.WriteByte(' ')
			b.WriteString(qualifiedName(a.prefix, a.local))
			b.WriteString(`="`)
			appendEscapedAttr(b, a.value)
			b.WriteByte('"')
		}
		if len(n.children) == 0 {
			b.WriteString("/>")
			return
		}
		b.WriteByte('>')
		for _, c := range n.children {
			serializeNode(b, c)
		}
		b.WriteString("</")
		b.WriteString(qualifiedName(n.prefix, n.local))
		b.WriteByte('>')
	case textNode:
		appendEscapedText(b, n.data)
	case commentNode:
		b.WriteString("<!--")
		b.Write(n.data)
		b.WriteString("-->")
	case procInstNode:
		writeProcInst(b, n.local, n.data)
	case directiveNode:
		b.WriteString("<!")
		b.Write(n.data)
		b.WriteByte('>')
	}
}

// serializeNodeBytes renders one node to a byte slice. | serializeNodeBytes 把单个节点渲染为字节切片。
func serializeNodeBytes(n *xmlNode) []byte {
	var b bytes.Buffer
	serializeNode(&b, n)
	return b.Bytes()
}

// serializeElementStandalone renders an element with every in-scope namespace declaration copied
// onto its start tag, so the result can be parsed outside its original document. | serializeElementStandalone
// 把元素渲染为带全部作用域内命名空间声明的独立片段，使其脱离原文档后仍可解析。
func serializeElementStandalone(n *xmlNode) []byte {
	scope := make(map[string]string)
	var chain []*xmlNode
	for p := n; p != nil; p = p.parent {
		chain = append(chain, p)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		applyNamespaceDecls(chain[i], scope)
	}
	var b bytes.Buffer
	b.WriteByte('<')
	b.WriteString(qualifiedName(n.prefix, n.local))
	prefixes := make([]string, 0, len(scope))
	for p := range scope {
		if p != "" && p != "xml" && scope[p] != "" {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		writeNamespaceDecl(&b, p, scope[p])
	}
	if uri := scope[""]; uri != "" {
		writeNamespaceDecl(&b, "", uri)
	}
	for _, a := range n.attrs {
		b.WriteByte(' ')
		b.WriteString(qualifiedName(a.prefix, a.local))
		b.WriteString(`="`)
		appendEscapedAttr(&b, a.value)
		b.WriteByte('"')
	}
	if len(n.children) == 0 {
		b.WriteString("/>")
	} else {
		b.WriteByte('>')
		for _, c := range n.children {
			serializeNode(&b, c)
		}
		b.WriteString("</")
		b.WriteString(qualifiedName(n.prefix, n.local))
		b.WriteByte('>')
	}
	return b.Bytes()
}

// writeNamespaceDecl renders one namespace declaration. | writeNamespaceDecl 渲染一条命名空间声明。
func writeNamespaceDecl(b *bytes.Buffer, prefix, uri string) {
	b.WriteString(" xmlns")
	if prefix != "" {
		b.WriteByte(':')
		b.WriteString(prefix)
	}
	b.WriteString(`="`)
	appendEscapedAttr(b, uri)
	b.WriteByte('"')
}

// appendEscapedText appends text escaped for XML character content. | appendEscapedText 追加按
// XML 字符内容规则转义的文本。
func appendEscapedText(b *bytes.Buffer, s []byte) {
	for _, c := range s {
		switch c {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteByte(c)
		}
	}
}

// appendEscapedAttr appends an attribute value escaped for a double-quoted literal. | appendEscapedAttr
// 追加按双引号字面量规则转义的属性值。
func appendEscapedAttr(b *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '"':
			b.WriteString("&quot;")
		case '\t':
			b.WriteString("&#x9;")
		case '\n':
			b.WriteString("&#xA;")
		case '\r':
			b.WriteString("&#xD;")
		default:
			b.WriteByte(c)
		}
	}
}

// writeProcInst renders a processing instruction. | writeProcInst 渲染处理指令。
func writeProcInst(b *bytes.Buffer, target string, data []byte) {
	b.WriteString("<?")
	b.WriteString(target)
	if len(data) != 0 {
		b.WriteByte(' ')
		b.Write(data)
	}
	b.WriteString("?>")
}

// appendChild appends c to the children of n. | appendChild 把 c 追加为 n 的子节点。
func (n *xmlNode) appendChild(c *xmlNode) {
	c.parent = n
	n.children = append(n.children, c)
}

// appendText appends a text child. | appendText 追加文本子节点。
func (n *xmlNode) appendText(s string) {
	if s == "" {
		return
	}
	n.appendChild(&xmlNode{kind: textNode, data: []byte(s)})
}

// addNamespaceDecl records a namespace declaration on n. | addNamespaceDecl 在 n 上记录命名空间声明。
func (n *xmlNode) addNamespaceDecl(prefix, uri string) {
	n.nsDecls = append(n.nsDecls, nsDecl{prefix: prefix, uri: uri})
}

// setAttr sets a non-namespace attribute, replacing an existing one with the same name. |
// setAttr 设置非命名空间属性；同名属性会被替换。
func (n *xmlNode) setAttr(prefix, local, value string) {
	for i := range n.attrs {
		if n.attrs[i].prefix == prefix && n.attrs[i].local == local {
			n.attrs[i].value = value
			return
		}
	}
	n.attrs = append(n.attrs, xmlAttr{prefix: prefix, local: local, value: value})
}

// attrValue returns the value of an attribute. | attrValue 返回属性值。
func (n *xmlNode) attrValue(prefix, local string) (string, bool) {
	for _, a := range n.attrs {
		if a.prefix == prefix && a.local == local {
			return a.value, true
		}
	}
	return "", false
}

// childByLocal returns the first direct child element with the given local name. | childByLocal
// 返回首个具有给定本地名的直接子元素。
func (n *xmlNode) childByLocal(local string) *xmlNode {
	for _, c := range n.children {
		if c.kind == elementNode && c.local == local {
			return c
		}
	}
	return nil
}

// childrenByLocal returns all direct child elements with the given local name. | childrenByLocal
// 返回所有具有给定本地名的直接子元素。
func (n *xmlNode) childrenByLocal(local string) []*xmlNode {
	var out []*xmlNode
	for _, c := range n.children {
		if c.kind == elementNode && c.local == local {
			out = append(out, c)
		}
	}
	return out
}

// elementText returns the concatenation of all descendant text content. | elementText 返回所有
// 后代文本内容的拼接。
func elementText(n *xmlNode) string {
	var b strings.Builder
	var walk func(*xmlNode)
	walk = func(cur *xmlNode) {
		switch cur.kind {
		case textNode:
			b.Write(cur.data)
		case elementNode:
			for _, c := range cur.children {
				walk(c)
			}
		}
	}
	walk(n)
	return b.String()
}

// domConverter converts a ydx/xml DOM node into the internal tree. Namespace URIs are mapped to
// synthesized prefixes because the public DOM drops prefix information. | domConverter 把 ydx/xml
// DOM 节点转换为内部树。由于公开 DOM 丢弃前缀信息，命名空间 URI 会映射为合成前缀。
type domConverter struct {
	prefixes map[string]string
	next     int
}

// convertDOMNode converts a public DOM node. | convertDOMNode 转换公开 DOM 节点。
func convertDOMNode(node *xml.Node) (*xmlNode, error) {
	if node == nil {
		return nil, errs.Detail(ErrInvalidXML, "nil DOM node | DOM 节点为 nil")
	}
	c := &domConverter{prefixes: map[string]string{xmlNamespaceURI: "xml"}}
	return c.convert(node)
}

// prefixFor returns a stable prefix for a namespace URI. | prefixFor 返回命名空间 URI 的稳定前缀。
func (c *domConverter) prefixFor(uri string) string {
	if p, ok := c.prefixes[uri]; ok {
		return p
	}
	p := "ns" + strconv.Itoa(c.next)
	c.next++
	c.prefixes[uri] = p
	return p
}

// convert converts one node and its subtree. | convert 转换一个节点及其子树。
func (c *domConverter) convert(node *xml.Node) (*xmlNode, error) {
	out := &xmlNode{}
	switch node.Kind {
	case xml.ElementNode:
		out.kind = elementNode
		if node.Name.Space != "" {
			out.prefix = c.prefixFor(node.Name.Space)
			out.addNamespaceDecl(out.prefix, node.Name.Space)
		}
		out.local = node.Name.Local
		for _, a := range node.Attrs {
			switch {
			case a.Name.Space == "xmlns":
				out.addNamespaceDecl(a.Name.Local, a.Value)
				continue
			case a.Name.Space == "" && a.Name.Local == "xmlns":
				out.addNamespaceDecl("", a.Value)
				continue
			}
			attr := xmlAttr{local: a.Name.Local, value: a.Value}
			switch a.Name.Space {
			case "":
			case xmlNamespaceURI:
				attr.prefix = "xml"
			default:
				attr.prefix = c.prefixFor(a.Name.Space)
				out.addNamespaceDecl(attr.prefix, a.Name.Space)
			}
			out.attrs = append(out.attrs, attr)
		}
		for _, child := range node.Children {
			converted, err := c.convert(child)
			if err != nil {
				return nil, err
			}
			out.appendChild(converted)
		}
	case xml.TextNode:
		out.kind = textNode
		out.data = append([]byte(nil), node.Data...)
	case xml.CommentNode:
		out.kind = commentNode
		out.data = append([]byte(nil), node.Data...)
	case xml.ProcInstNode:
		out.kind = procInstNode
		out.local = node.Name.Local
		out.data = append([]byte(nil), node.Data...)
	case xml.DirectiveNode:
		out.kind = directiveNode
		out.data = append([]byte(nil), node.Data...)
	default:
		return nil, errs.Detail(ErrInvalidXML, "unsupported DOM node kind %s | 不支持的 DOM 节点类型 %s", node.Kind.String(), node.Kind.String())
	}
	return out, nil
}
