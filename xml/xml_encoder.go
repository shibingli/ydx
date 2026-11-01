package xml

import (
	"bufio"
	"bytes"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// An Encoder writes XML data to an output stream. | Encoder 把 XML 数据写入输出流。
type Encoder struct {
	p printer
}

// NewEncoder returns a new encoder that writes to w. | NewEncoder 返回写入 w 的新编码器。
func NewEncoder(w io.Writer) *Encoder {
	e := &Encoder{printer{w: bufio.NewWriter(w)}}
	e.p.encoder = e
	return e
}

// Indent sets the encoder to generate XML in which each element begins on a new indented line
// that starts with prefix and is followed by copies of indent. | Indent 设置编码器为每个元素开始新行，
// 行首为 prefix 后跟按层级重复的 indent。
func (enc *Encoder) Indent(prefix, indent string) {
	enc.p.prefix = prefix
	enc.p.indent = indent
}

// Encode writes the XML encoding of v to the stream and flushes it. | Encode 把 v 的 XML 编码写入流
// 并刷新。
func (enc *Encoder) Encode(v any) error {
	if err := enc.p.marshalValue(reflect.ValueOf(v), nil, nil); err != nil {
		return err
	}
	return enc.p.flush()
}

// EncodeElement writes the XML encoding of v using start as the outermost tag. | EncodeElement 使用
// start 作为最外层标签写入 v 的 XML 编码。
func (enc *Encoder) EncodeElement(v any, start StartElement) error {
	if err := enc.p.marshalValue(reflect.ValueOf(v), nil, &start); err != nil {
		return err
	}
	return enc.p.flush()
}

var (
	begComment  = []byte("<!--")
	endComment  = []byte("-->")
	endProcInst = []byte("?>")
	ddBytes     = []byte("--")
)

// EncodeToken writes the given XML token to the stream. It returns an error if start and end
// elements are not properly matched. | EncodeToken 把给定 XML token 写入流；起始与结束元素不匹配时
// 返回错误。
func (enc *Encoder) EncodeToken(t Token) error {
	p := &enc.p
	switch t := t.(type) {
	case StartElement:
		if err := p.writeStart(&t); err != nil {
			return err
		}
	case EndElement:
		if err := p.writeEnd(t.Name); err != nil {
			return err
		}
	case CharData:
		escapeText(p, t, false)
	case Comment:
		if bytes.Contains(t, endComment) {
			return errs.Detail(ErrTypeMismatch, "xml: EncodeToken of Comment containing --> marker")
		}
		p.WriteString("<!--")
		p.Write(t)
		p.WriteString("-->")
		return p.cachedWriteError()
	case ProcInst:
		if t.Target == "xml" && p.buffered() != 0 {
			return errs.Detail(ErrTypeMismatch, "xml: EncodeToken of ProcInst xml target only valid for xml declaration, first token encoded")
		}
		if !isNameString(t.Target) {
			return errs.Detail(ErrTypeMismatch, "xml: EncodeToken of ProcInst with invalid Target")
		}
		if bytes.Contains(t.Inst, endProcInst) {
			return errs.Detail(ErrTypeMismatch, "xml: EncodeToken of ProcInst containing ?> marker")
		}
		p.WriteString("<?")
		p.WriteString(t.Target)
		if len(t.Inst) > 0 {
			p.WriteByte(' ')
			p.Write(t.Inst)
		}
		p.WriteString("?>")
	case Directive:
		if !isValidDirective(t) {
			return errs.Detail(ErrTypeMismatch, "xml: EncodeToken of Directive containing wrong < or > markers")
		}
		p.WriteString("<!")
		p.Write(t)
		p.WriteString(">")
	default:
		return errs.Detail(ErrTypeMismatch, "xml: EncodeToken of invalid token type")
	}
	return p.cachedWriteError()
}

// isValidDirective reports whether dir is valid directive text with matched angle brackets,
// ignoring comments and quoted strings. | isValidDirective 判断 dir 是否为尖括号匹配的合法指令文本，
// 忽略注释与引号字符串。
func isValidDirective(dir Directive) bool {
	var (
		depth     int
		inquote   uint8
		incomment bool
	)
	for i, c := range dir {
		switch {
		case incomment:
			if c == '>' {
				if n := 1 + i - len(endComment); n >= 0 && bytes.Equal(dir[n:i+1], endComment) {
					incomment = false
				}
			}
		case inquote != 0:
			if c == inquote {
				inquote = 0
			}
		case c == '\'' || c == '"':
			inquote = c
		case c == '<':
			if i+len(begComment) < len(dir) && bytes.Equal(dir[i:i+len(begComment)], begComment) {
				incomment = true
			} else {
				depth++
			}
		case c == '>':
			if depth == 0 {
				return false
			}
			depth--
		}
	}
	return depth == 0 && inquote == 0 && !incomment
}

// Flush flushes buffered XML to the underlying writer. | Flush 把缓冲的 XML 刷新到底层写入器。
func (enc *Encoder) Flush() error { return enc.p.flush() }

// Close flushes buffered XML and reports unclosed elements. | Close 刷新缓冲的 XML 并报告未关闭元素。
func (enc *Encoder) Close() error { return enc.p.Close() }

type printer struct {
	err        error
	w          *bufio.Writer
	buf        []byte
	direct     bool
	encoder    *Encoder
	attrNS     map[string]string
	attrPrefix map[string]string
	indent     string
	prefix     string
	prefixes   []string
	tags       []Name
	seq        int
	depth      int
	indentedIn bool
	putNewline bool
	closed     bool
}

func (p *printer) createAttrPrefix(url string) string {
	if prefix := p.attrPrefix[url]; prefix != "" {
		return prefix
	}
	if url == xmlURL {
		return xmlPrefix
	}
	if p.attrPrefix == nil {
		p.attrPrefix = make(map[string]string)
		p.attrNS = make(map[string]string)
	}
	prefix := strings.TrimRight(url, "/")
	if i := strings.LastIndex(prefix, "/"); i >= 0 {
		prefix = prefix[i+1:]
	}
	if prefix == "" || !isNameBytes([]byte(prefix)) || strings.Contains(prefix, ":") {
		prefix = "_"
	}
	if len(prefix) >= 3 && strings.EqualFold(prefix[:3], "xml") {
		prefix = "_" + prefix
	}
	if p.attrNS[prefix] != "" {
		for p.seq++; ; p.seq++ {
			if id := prefix + "_" + strconv.Itoa(p.seq); p.attrNS[id] == "" {
				prefix = id
				break
			}
		}
	}
	p.attrPrefix[url] = prefix
	p.attrNS[prefix] = url
	p.WriteString(`xmlns:`)
	p.WriteString(prefix)
	p.WriteString(`="`)
	EscapeText(p, []byte(url))
	p.WriteString(`" `)
	p.prefixes = append(p.prefixes, prefix)
	return prefix
}

func (p *printer) deleteAttrPrefix(prefix string) {
	delete(p.attrPrefix, p.attrNS[prefix])
	delete(p.attrNS, prefix)
}

func (p *printer) markPrefix() { p.prefixes = append(p.prefixes, "") }

func (p *printer) popPrefix() {
	for len(p.prefixes) > 0 {
		prefix := p.prefixes[len(p.prefixes)-1]
		p.prefixes = p.prefixes[:len(p.prefixes)-1]
		if prefix == "" {
			break
		}
		p.deleteAttrPrefix(prefix)
	}
}

func (p *printer) writeStart(start *StartElement) error {
	if start.Name.Local == "" {
		return errs.Detail(ErrTypeMismatch, "xml: start tag with no name")
	}
	p.tags = append(p.tags, start.Name)
	p.markPrefix()
	p.writeIndent(1)
	p.WriteByte('<')
	p.WriteString(start.Name.Local)
	if start.Name.Space != "" {
		p.WriteString(` xmlns="`)
		p.EscapeString(start.Name.Space)
		p.WriteByte('"')
	}
	for _, attr := range start.Attr {
		name := attr.Name
		if name.Local == "" {
			continue
		}
		p.WriteByte(' ')
		if name.Space != "" {
			p.WriteString(p.createAttrPrefix(name.Space))
			p.WriteByte(':')
		}
		p.WriteString(name.Local)
		p.WriteString(`="`)
		p.EscapeString(attr.Value)
		p.WriteByte('"')
	}
	p.WriteByte('>')
	return nil
}

func (p *printer) writeEnd(name Name) error {
	if name.Local == "" {
		return errs.Detail(ErrTypeMismatch, "xml: end tag with no name")
	}
	if len(p.tags) == 0 || p.tags[len(p.tags)-1].Local == "" {
		return errs.Detail(ErrTypeMismatch, "xml: end tag </%s> without start tag", name.Local)
	}
	if top := p.tags[len(p.tags)-1]; top != name {
		if top.Local != name.Local {
			return errs.Detail(ErrTypeMismatch, "xml: end tag </%s> does not match start tag <%s>", name.Local, top.Local)
		}
		return errs.Detail(ErrTypeMismatch, "xml: end tag </%s> in namespace %s does not match start tag <%s> in namespace %s",
			name.Local, name.Space, top.Local, top.Space)
	}
	p.tags = p.tags[:len(p.tags)-1]
	p.writeIndent(-1)
	p.WriteByte('<')
	p.WriteByte('/')
	p.WriteString(name.Local)
	p.WriteByte('>')
	p.popPrefix()
	return nil
}

func (p *printer) Write(b []byte) (n int, err error) {
	if p.closed && p.err == nil {
		p.err = errs.New("xml: use of closed Encoder | xml：使用已关闭的 Encoder")
	}
	if p.err == nil {
		if p.direct {
			p.ensure(len(b))
			p.buf = append(p.buf, b...)
			return len(b), nil
		}
		n, p.err = p.w.Write(b)
	}
	return n, p.err
}

func (p *printer) WriteString(s string) (n int, err error) {
	if p.closed && p.err == nil {
		p.err = errs.New("xml: use of closed Encoder | xml：使用已关闭的 Encoder")
	}
	if p.err == nil {
		if p.direct {
			p.ensure(len(s))
			p.buf = append(p.buf, s...)
			return len(s), nil
		}
		n, p.err = p.w.WriteString(s)
	}
	return n, p.err
}

func (p *printer) WriteByte(c byte) error {
	if p.closed && p.err == nil {
		p.err = errs.New("xml: use of closed Encoder | xml：使用已关闭的 Encoder")
	}
	if p.err == nil {
		if p.direct {
			p.ensure(1)
			p.buf = append(p.buf, c)
			return nil
		}
		p.err = p.w.WriteByte(c)
	}
	return p.err
}

func (p *printer) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	if err := p.flush(); err != nil {
		return err
	}
	if len(p.tags) > 0 {
		return errs.Detail(ErrTypeMismatch, "xml: unclosed tag <%s>", p.tags[len(p.tags)-1].Local)
	}
	return nil
}

// ensure grows the direct output buffer geometrically. Doubling keeps the total bytes
// allocated across growth steps near twice the final size, whereas the runtime's 1.25x growth
// for large slices allocates roughly five times the final size. | ensure 按倍数增长直接输出缓冲。
// 翻倍使整个增长过程累计分配的字节接近最终大小的两倍；运行时对大切片采用 1.25 倍增长，累计
// 分配约为最终大小的五倍。
func (p *printer) ensure(n int) {
	if cap(p.buf)-len(p.buf) >= n {
		return
	}
	newCap := 2 * cap(p.buf)
	if newCap < len(p.buf)+n {
		newCap = len(p.buf) + n
	}
	if newCap < 512 {
		newCap = 512
	}
	next := make([]byte, len(p.buf), newCap)
	copy(next, p.buf)
	p.buf = next
}

// flush flushes buffered output; the direct byte-slice printer needs no flush. |
// flush 刷新缓冲输出；直接写入字节切片的打印器无需刷新。
func (p *printer) flush() error {
	if p.direct {
		return p.err
	}
	return p.w.Flush()
}

// buffered reports the number of bytes written so far. | buffered 返回目前已写入的字节数。
func (p *printer) buffered() int {
	if p.direct {
		return len(p.buf)
	}
	return p.w.Buffered()
}

func (p *printer) cachedWriteError() error {
	_, err := p.Write(nil)
	return err
}

func (p *printer) writeIndent(depthDelta int) {
	if len(p.prefix) == 0 && len(p.indent) == 0 {
		return
	}
	if depthDelta < 0 {
		p.depth--
		if p.indentedIn {
			p.indentedIn = false
			return
		}
		p.indentedIn = false
	}
	if p.putNewline {
		p.WriteByte('\n')
	} else {
		p.putNewline = true
	}
	if len(p.prefix) > 0 {
		p.WriteString(p.prefix)
	}
	if len(p.indent) > 0 {
		for i := 0; i < p.depth; i++ {
			p.WriteString(p.indent)
		}
	}
	if depthDelta > 0 {
		p.depth++
		p.indentedIn = true
	}
}
