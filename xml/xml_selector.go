package xml

import (
	"io"
	"math/bits"
	"os"

	"github.com/shibingli/ydx/errs"
)

// Match is one streaming Selector result. Its slices are valid until the next call to Next and
// must be copied to be retained. | Match 是 Selector 的一个流式结果；其切片在下一次 Next 前有效，
// 如需保留必须复制。
type Match struct {
	// Name is the matched element name. | Name 是匹配的元素名。
	Name Name

	// Text is the terminal value: the element's direct text, the attribute value, or the text
	// selected by text(). | Text 是终结值：元素的直接文本、属性值或 text() 选中的文本。
	Text []byte

	// Raw is the raw outer XML when CaptureRaw is enabled and the source supports raw views. |
	// Raw 在启用 CaptureRaw 且源支持原始视图时是外层 XML 原始字节。
	Raw []byte
}

// Value returns the terminal value. | Value 返回终结值。
func (m *Match) Value() []byte { return m.Text }

// SelectorOptions configures Selector. | SelectorOptions 配置 Selector。
type SelectorOptions struct {

	// Entity adds non-standard entity mappings. | Entity 增加非标准实体映射。
	Entity map[string]string

	// CharsetReader converts a declared non-UTF-8 encoding to UTF-8. | CharsetReader 把声明的
	// 非 UTF-8 编码转换为 UTF-8。
	CharsetReader func(charset string, input io.Reader) (io.Reader, error)

	// DefaultSpace is the default namespace for unadorned element names. | DefaultSpace 是
	// 无前缀元素名的默认命名空间。
	DefaultSpace string

	// AutoClose lists implicitly closed element names in lenient mode. | AutoClose 列出宽松模式下
	// 隐式关闭的元素名。
	AutoClose []string

	// Limits bounds resource usage. | Limits 限制资源占用。
	Limits Limits

	// Lenient disables strict well-formedness checks. | Lenient 关闭严格良构检查。
	Lenient bool

	// NoText disables direct-text capture for element matches; text terminals still capture. |
	// NoText 关闭元素匹配的直接文本捕获；文本终结符仍会捕获。
	NoText bool

	// CaptureRaw enables raw outer XML capture for element matches on byte sources. | CaptureRaw
	// 在字节源上为元素匹配启用外层 XML 原始捕获。
	CaptureRaw bool
}

// Selector performs a streaming path query without building a DOM. Memory usage is proportional
// to nesting depth and to the text captured for in-flight matches. | Selector 在不构建 DOM 的情况下
// 执行流式路径查询；内存占用与嵌套深度及在途匹配捕获的文本成正比。
type Selector struct {
	err    error
	d      *Decoder
	p      *Path
	m      Match
	stack  []selFrame
	pool   [][]int32
	global []int32
	caps   []selCap
	capBuf [][]byte

	textBuf []byte
	opts    SelectorOptions
	limit   Limits
	count   int
	done    bool
	pending bool
}

type selFrame struct {
	counters []int32
	childCtx uint64
}

type selCap struct {
	name     Name
	text     []byte
	depth    int
	rawStart int64
	term     terminalKind
}

// NewSelector creates a streaming selector reading from r. | NewSelector 创建从 r 读取的流式选择器。
func NewSelector(r io.Reader, p *Path) *Selector {
	return NewSelectorWithOptions(r, p, SelectorOptions{})
}

// NewSelectorBytes creates a streaming selector over data with zero-copy tokenization. | NewSelectorBytes
// 在 data 上创建零拷贝词法分析的流式选择器。
func NewSelectorBytes(data []byte, p *Path) *Selector {
	return NewSelectorBytesWithOptions(data, p, SelectorOptions{})
}

// NewSelectorWithOptions creates a streaming selector reading from r with explicit options. |
// NewSelectorWithOptions 使用显式选项创建从 r 读取的流式选择器。
func NewSelectorWithOptions(r io.Reader, p *Path, opts SelectorOptions) *Selector {
	d := NewDecoder(r)
	return newSelector(d, p, opts)
}

// NewSelectorBytesWithOptions creates a streaming selector over data with explicit options. |
// NewSelectorBytesWithOptions 在 data 上使用显式选项创建流式选择器。
func NewSelectorBytesWithOptions(data []byte, p *Path, opts SelectorOptions) *Selector {
	d := NewDecoderBytes(data)
	return newSelector(d, p, opts)
}

func newSelector(d *Decoder, p *Path, opts SelectorOptions) *Selector {
	d.Strict = !opts.Lenient
	d.AutoClose = opts.AutoClose
	d.Entity = opts.Entity
	d.CharsetReader = opts.CharsetReader
	d.DefaultSpace = opts.DefaultSpace
	d.Limits = opts.Limits
	s := &Selector{d: d, p: p, opts: opts, limit: d.limits()}
	if p == nil {
		s.err = errs.Detail(ErrPathSyntax, "nil path | 路径为 nil")
		s.done = true
		return s
	}
	s.global = make([]int32, len(p.steps))
	s.stack = append(s.stack, selFrame{childCtx: 1, counters: s.countersAt(0)})
	return s
}

func (s *Selector) countersAt(depth int) []int32 {
	for len(s.pool) <= depth {
		s.pool = append(s.pool, make([]int32, len(s.p.steps)))
	}
	f := s.pool[depth]
	for i := range f {
		f[i] = 0
	}
	return f
}

func (s *Selector) capText() []byte {
	if len(s.capBuf) == 0 {
		return make([]byte, 0, 64)
	}
	b := s.capBuf[len(s.capBuf)-1]
	s.capBuf = s.capBuf[:len(s.capBuf)-1]
	return b[:0]
}

func (s *Selector) releaseText(b []byte) {
	if cap(b) <= 1<<20 {
		s.capBuf = append(s.capBuf, b)
	}
}

func (s *Selector) fail(err error) {
	if s.err == nil {
		s.err = err
	}
	s.done = true
}

// Next advances to the next match. It returns false at EOF or on error. | Next 前进到下一个匹配；
// EOF 或出错时返回 false。
func (s *Selector) Next() bool {
	if s.pending {
		s.pending = false
		return true
	}
	var ev event
	for !s.done {
		err := s.d.nextEvent(&ev)
		if err == io.EOF {
			s.done = true
			return false
		}
		if err != nil {
			s.fail(err)
			return false
		}
		switch ev.kind {
		case evStart:
			s.startElement(&ev)
		case evEnd:
			s.endElement()
		case evText:
			s.charData(ev.data)
		}
		if s.pending {
			s.pending = false
			return true
		}
	}
	return false
}

// Match returns the current match; it is valid until the next call to Next. | Match 返回当前匹配；
// 在下一次 Next 前有效。
func (s *Selector) Match() *Match { return &s.m }

// Err returns the first error encountered. | Err 返回首次遇到的错误。
func (s *Selector) Err() error { return s.err }

func (s *Selector) startElement(ev *event) {
	if s.err != nil {
		return
	}
	depth := len(s.stack)
	parent := &s.stack[len(s.stack)-1]
	matched, childCtx := s.transition(parent.childCtx, parent.counters, ev.name, ev.attrs)
	s.stack = append(s.stack, selFrame{childCtx: childCtx, counters: s.countersAt(depth)})
	if matched&(uint64(1)<<uint(len(s.p.steps))) == 0 {
		return
	}
	if s.limit.MaxMatches > 0 && s.count >= s.limit.MaxMatches {
		s.fail(errs.Detail(ErrLimit, "match count exceeds MaxMatches | 匹配数超过 MaxMatches"))
		return
	}
	switch s.p.terminal {
	case termAttr:
		if v, ok := findAttr(ev.attrs, s.p.termName); ok {
			s.m = Match{Name: ev.name, Text: []byte(v)}
			s.count++
			s.pending = true
		}
	case termElement:
		s.caps = append(s.caps, selCap{
			depth:    depth,
			name:     ev.name,
			text:     s.capText(),
			rawStart: s.d.tokenStartOffset(),
			term:     termElement,
		})
	case termText:
		s.caps = append(s.caps, selCap{
			depth: depth,
			name:  ev.name,
			text:  s.capText(),
			term:  termText,
		})
	}
}

func (s *Selector) transition(ctx uint64, counters []int32, name Name, attrs []Attr) (matched, childCtx uint64) {
	for b := ctx; b != 0; b &= b - 1 {
		i := bits.TrailingZeros64(b)
		st := &s.p.steps[i]
		if st.axis == axisDescendant {
			childCtx |= uint64(1) << uint(i)
		}
		if !stepMatchesName(st, name, attrs) {
			continue
		}
		if st.index >= 0 {
			if st.axis == axisChild {
				counters[i]++
				if int(counters[i])-1 != st.index-s.p.base {
					continue
				}
			} else {
				s.global[i]++
				if int(s.global[i])-1 != st.index-s.p.base {
					continue
				}
			}
		}
		matched |= uint64(1) << uint(i+1)
	}
	childCtx |= matched & ((uint64(1) << uint(len(s.p.steps))) - 1)
	return matched, childCtx
}

func (s *Selector) endElement() {
	if len(s.stack) > 1 {
		s.stack = s.stack[:len(s.stack)-1]
	}
	depth := len(s.stack)
	if len(s.caps) == 0 {
		return
	}
	cap := s.caps[len(s.caps)-1]
	if cap.depth != depth {
		return
	}
	s.caps = s.caps[:len(s.caps)-1]
	if s.err != nil {
		s.releaseText(cap.text)
		return
	}
	end := s.d.InputOffset()
	s.textBuf = append(s.textBuf[:0], cap.text...)
	s.releaseText(cap.text)
	s.m = Match{Name: cap.name}
	if cap.term == termText || !s.opts.NoText {
		s.m.Text = s.textBuf
	}
	if cap.term == termElement && s.opts.CaptureRaw {
		if data, ok := s.d.src.bytes(); ok && cap.rawStart >= 0 && end >= cap.rawStart && end <= int64(len(data)) {
			s.m.Raw = data[cap.rawStart:end]
		}
	}
	s.count++
	s.pending = true
}

func (s *Selector) charData(t []byte) {
	if len(s.caps) == 0 || s.err != nil {
		return
	}
	depth := len(s.stack) - 1
	cap := &s.caps[len(s.caps)-1]
	if cap.depth != depth {
		return
	}
	if cap.term == termElement && s.opts.NoText {
		return
	}
	if len(cap.text)+len(t) > s.limit.MaxTextSize {
		s.fail(errs.Detail(ErrLimit, "matched text exceeds MaxTextSize | 匹配文本超过 MaxTextSize"))
		return
	}
	cap.text = append(cap.text, t...)
}

func findAttr(attrs []Attr, name Name) (string, bool) {
	for _, a := range attrs {
		if a.Name.Local != name.Local {
			continue
		}
		if name.Space != "" && a.Name.Space != name.Space {
			continue
		}
		return a.Value, true
	}
	return "", false
}

// Each calls fn for every match from r. | Each 对 r 的每个匹配调用 fn。
func Each(r io.Reader, p *Path, fn func(*Match) error) error {
	s := NewSelector(r, p)
	for s.Next() {
		if err := fn(s.Match()); err != nil {
			return err
		}
	}
	return s.Err()
}

// EachBytes calls fn for every match in data. | EachBytes 对 data 的每个匹配调用 fn。
func EachBytes(data []byte, p *Path, fn func(*Match) error) error {
	s := NewSelectorBytes(data, p)
	for s.Next() {
		if err := fn(s.Match()); err != nil {
			return err
		}
	}
	return s.Err()
}

// EachFile streams path and calls fn for every match. It keeps memory proportional to nesting
// depth and captured text, so it is suitable for very large files. | EachFile 流式读取 path 并对
// 每个匹配调用 fn；内存与嵌套深度及捕获文本成正比，适合超大文件。
func EachFile(path string, p *Path, fn func(*Match) error) error {
	f, err := os.Open(path)
	if err != nil {
		return errs.WrapDetail(err, ErrUnsupported, "opening XML file | 打开 XML 文件")
	}
	defer f.Close()
	return Each(f, p, fn)
}
