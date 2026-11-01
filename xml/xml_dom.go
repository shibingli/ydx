package xml

import (
	"io"
	"os"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// Parse parses data into a DOM document using strict well-formedness checking. The document keeps
// zero-copy raw views into data for InnerXML and OuterXML. | Parse 使用严格良构检查把 data 解析为
// DOM 文档；文档为零拷贝的 InnerXML 与 OuterXML 保留指向 data 的原始视图。
func Parse(data []byte) (*Document, error) {
	return ParseWithOptions(data, ParseOptions{})
}

// ParseWithOptions parses data into a DOM document with explicit options. | ParseWithOptions 使用
// 显式选项把 data 解析为 DOM 文档。
func ParseWithOptions(data []byte, opts ParseOptions) (*Document, error) {
	d := NewDecoderBytes(data)
	d.Strict = !opts.Lenient
	d.AutoClose = opts.AutoClose
	d.Entity = opts.Entity
	d.CharsetReader = opts.CharsetReader
	d.DefaultSpace = opts.DefaultSpace
	d.Limits = opts.Limits

	doc := &Document{}
	if src, ok := d.src.bytes(); ok {
		doc.src = src
		doc.rawOK = true
	}
	limits := d.limits()
	var stack []*Node
	seenRoot := false
	rootClosed := false
	nodes := 0

	add := func(n *Node) error {
		nodes++
		if limits.MaxNodes > 0 && nodes > limits.MaxNodes {
			return errs.Detail(ErrLimit, "DOM node count exceeds MaxNodes | DOM 节点数超过 MaxNodes")
		}
		if len(stack) == 0 {
			n.Index = len(doc.Children)
			doc.Children = append(doc.Children, n)
			return nil
		}
		p := stack[len(stack)-1]
		n.Parent = p
		n.Index = len(p.Children)
		p.Children = append(p.Children, n)
		return nil
	}

	var ev event
	for {
		err := d.nextEvent(&ev)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch ev.kind {
		case evStart:
			if rootClosed {
				return nil, errs.Detail(ErrSyntax, "multiple root elements | 多个根元素")
			}
			if len(stack) == 0 {
				if seenRoot {
					return nil, errs.Detail(ErrSyntax, "multiple root elements | 多个根元素")
				}
				seenRoot = true
			}
			n := &Node{
				Kind:        ElementNode,
				Name:        ev.name,
				Attrs:       ev.attrs,
				doc:         doc,
				start:       d.tokenStartOffset(),
				startTagEnd: d.InputOffset(),
			}
			if err := add(n); err != nil {
				return nil, err
			}
			stack = append(stack, n)
			if len(stack) == 1 {
				doc.Root = n
			}
		case evEnd:
			if len(stack) == 0 {
				return nil, errs.Detail(ErrSyntax, "unexpected end element | 意外的结束元素")
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			n.innerEnd = d.tokenStartOffset()
			n.end = d.InputOffset()
			if len(stack) == 0 {
				rootClosed = true
			}
		case evText:
			data := doc.own(ev.data)
			if len(stack) == 0 {
				if isAllXMLSpace(data) {
					continue
				}
				if !seenRoot && isUTF8BOM(data) {
					continue
				}
				return nil, errs.Detail(ErrSyntax, "character data outside root element | 根元素外存在字符数据")
			}
			n := &Node{Kind: TextNode, Data: data, doc: doc, start: d.tokenStartOffset(), end: d.InputOffset()}
			if err := add(n); err != nil {
				return nil, err
			}
		case evComment:
			if opts.DiscardComments {
				continue
			}
			n := &Node{Kind: CommentNode, Data: doc.own(ev.data), doc: doc, start: d.tokenStartOffset(), end: d.InputOffset()}
			if err := add(n); err != nil {
				return nil, err
			}
		case evProcInst:
			if opts.DiscardProcInst {
				continue
			}
			n := &Node{
				Kind:  ProcInstNode,
				Name:  Name{Local: ev.target},
				Data:  doc.own(ev.data),
				doc:   doc,
				start: d.tokenStartOffset(),
				end:   d.InputOffset(),
			}
			if err := add(n); err != nil {
				return nil, err
			}
		case evDirective:
			if opts.DiscardDirectives {
				continue
			}
			n := &Node{Kind: DirectiveNode, Data: doc.own(ev.data), doc: doc, start: d.tokenStartOffset(), end: d.InputOffset()}
			if err := add(n); err != nil {
				return nil, err
			}
		}
	}
	if len(stack) != 0 {
		return nil, errs.Detail(ErrSyntax, "unexpected EOF | 意外的 EOF")
	}
	if !seenRoot {
		return nil, errs.Detail(ErrSyntax, "no root element | 缺少根元素")
	}
	return doc, nil
}

// ParseReader reads all of r and parses the result as a DOM document. Use Selector or Decoder for
// documents that do not fit in memory. | ParseReader 读取 r 的全部内容并解析为 DOM 文档；不适合放入
// 内存的文档请使用 Selector 或 Decoder。
func ParseReader(r io.Reader) (*Document, error) {
	return ParseReaderWithOptions(r, ParseOptions{})
}

// ParseReaderWithOptions reads all of r and parses it with explicit options. | ParseReaderWithOptions
// 读取 r 的全部内容并使用显式选项解析。
func ParseReaderWithOptions(r io.Reader, opts ParseOptions) (*Document, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrSyntax, "reading XML input | 读取 XML 输入")
	}
	return ParseWithOptions(data, opts)
}

// ParseFile reads path and parses it as a DOM document. | ParseFile 读取 path 并解析为 DOM 文档。
func ParseFile(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrSyntax, "reading XML file | 读取 XML 文件")
	}
	return Parse(data)
}

// own returns b unchanged when it already points into the document source, otherwise it returns a
// stable copy. | own 在 b 已指向文档源时原样返回，否则返回稳定副本。
func (d *Document) own(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	if d.rawOK && sliceWithin(b, d.src) {
		return b
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func sliceWithin(b, src []byte) bool {
	if len(b) == 0 || len(src) == 0 {
		return false
	}
	bp := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	sp := uintptr(unsafe.Pointer(unsafe.SliceData(src)))
	return bp >= sp && bp+uintptr(len(b)) <= sp+uintptr(len(src))
}
