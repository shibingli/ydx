package xml

// Kind identifies the kind of a DOM node. | Kind 标识 DOM 节点类型。
type Kind uint8

const (
	// ElementNode is an element node. | ElementNode 表示元素节点。
	ElementNode Kind = iota + 1
	// TextNode is character data, including CDATA content. | TextNode 表示字符数据，包括 CDATA 内容。
	TextNode
	// CommentNode is a comment node. | CommentNode 表示注释节点。
	CommentNode
	// ProcInstNode is a processing instruction node; Name.Local is the target. | ProcInstNode 表示
	// 处理指令节点；Name.Local 是目标。
	ProcInstNode
	// DirectiveNode is a directive node such as DOCTYPE. | DirectiveNode 表示指令节点，例如 DOCTYPE。
	DirectiveNode
)

// String returns the node kind name. | String 返回节点类型名称。
func (k Kind) String() string {
	switch k {
	case ElementNode:
		return "Element"
	case TextNode:
		return "Text"
	case CommentNode:
		return "Comment"
	case ProcInstNode:
		return "ProcInst"
	case DirectiveNode:
		return "Directive"
	default:
		return "Unknown"
	}
}

// Document is a parsed XML document. It owns the source bytes and a node tree. | Document 是解析后的
// XML 文档，持有源字节与节点树。
type Document struct {
	// Root is the document element, or nil for an empty document. | Root 是文档元素；空文档时为 nil。
	Root *Node

	// Children holds top-level nodes in document order, including prolog and epilog comments,
	// processing instructions and directives together with the root element. | Children 按文档顺序
	// 保存顶层节点，包括序言/尾声的注释、处理指令、指令以及根元素。
	Children []*Node

	src   []byte
	rawOK bool
}

// Source returns the document source bytes. The slice must not be modified. | Source 返回文档源字节；
// 不得修改该切片。
func (d *Document) Source() []byte { return d.src }

// Node is one DOM node. Element nodes carry Name, Attrs and Children; leaf nodes carry Data. |
// Node 是一个 DOM 节点。元素节点携带 Name、Attrs 与 Children；叶子节点携带 Data。
type Node struct {
	Parent *Node

	doc      *Document
	Name     Name
	Attrs    []Attr
	Children []*Node
	Data     []byte
	Index    int

	start       int64
	startTagEnd int64
	innerEnd    int64
	end         int64
	Kind        Kind
}

// Text returns the decoded direct character data of the node. For an element it concatenates the
// data of direct TextNode children. | Text 返回节点已解码的直接字符数据；对元素而言，它拼接直接
// 子文本节点的数据。
func (n *Node) Text() string {
	if n.Kind == TextNode {
		return string(n.Data)
	}
	if n.Kind != ElementNode {
		return string(n.Data)
	}
	size := 0
	for _, c := range n.Children {
		if c.Kind == TextNode {
			size += len(c.Data)
		}
	}
	if size == 0 {
		return ""
	}
	buf := make([]byte, 0, size)
	for _, c := range n.Children {
		if c.Kind == TextNode {
			buf = append(buf, c.Data...)
		}
	}
	return string(buf)
}

// AppendText appends the decoded direct character data to dst and returns the extended slice. |
// AppendText 把已解码的直接字符数据追加到 dst 并返回扩展后的切片。
func (n *Node) AppendText(dst []byte) []byte {
	if n.Kind != ElementNode {
		return append(dst, n.Data...)
	}
	for _, c := range n.Children {
		if c.Kind == TextNode {
			dst = append(dst, c.Data...)
		}
	}
	return dst
}

// Attr returns the value of the first attribute with the given local name. | Attr 返回首个具有给定
// 本地名的属性值。
func (n *Node) Attr(local string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

// AttrNS returns the value of the attribute with the given namespace and local name. | AttrNS 返回
// 给定命名空间与本地名的属性值。
func (n *Node) AttrNS(space, local string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Name.Space == space && a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

// Child returns the i-th child node, or nil when i is out of range. | Child 返回第 i 个子节点；越界
// 时返回 nil。
func (n *Node) Child(i int) *Node {
	if i < 0 || i >= len(n.Children) {
		return nil
	}
	return n.Children[i]
}

// FirstChild returns the first element child with the given local name. | FirstChild 返回首个具有
// 给定本地名的元素子节点。
func (n *Node) FirstChild(local string) *Node {
	for _, c := range n.Children {
		if c.Kind == ElementNode && c.Name.Local == local {
			return c
		}
	}
	return nil
}

// NextSibling returns the next node in the parent's child list, or nil. | NextSibling 返回父节点
// 子列表中的下一个节点，没有则返回 nil。
func (n *Node) NextSibling() *Node {
	if n.Parent != nil {
		if n.Index+1 < len(n.Parent.Children) {
			return n.Parent.Children[n.Index+1]
		}
		return nil
	}
	if n.doc == nil {
		return nil
	}
	if n.Index+1 < len(n.doc.Children) {
		return n.doc.Children[n.Index+1]
	}
	return nil
}

// InnerXML returns the raw bytes between the element's start and end tags, or nil when raw views
// are unavailable. | InnerXML 返回元素起始与结束标签之间的原始字节；原始视图不可用时返回 nil。
func (n *Node) InnerXML() []byte {
	if n.Kind != ElementNode || n.doc == nil || !n.doc.rawOK {
		return nil
	}
	if n.startTagEnd < 0 || n.innerEnd < n.startTagEnd || n.innerEnd > int64(len(n.doc.src)) {
		return nil
	}
	return n.doc.src[n.startTagEnd:n.innerEnd]
}

// OuterXML returns the raw bytes of the node including markup, or nil when raw views are
// unavailable. | OuterXML 返回包含标记的节点原始字节；原始视图不可用时返回 nil。
func (n *Node) OuterXML() []byte {
	if n.doc == nil || !n.doc.rawOK {
		return nil
	}
	if n.start < 0 || n.end < n.start || n.end > int64(len(n.doc.src)) {
		return nil
	}
	return n.doc.src[n.start:n.end]
}

// String returns the node's outer XML when available, otherwise its text. | String 在可用时返回
// 节点外层 XML，否则返回其文本。
func (n *Node) String() string {
	if b := n.OuterXML(); b != nil {
		return string(b)
	}
	if n.Kind == ElementNode {
		return "<" + n.Name.String() + ">"
	}
	return string(n.Data)
}
