package xml

import (
	"math/bits"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

type pathAxis uint8

const (
	axisChild pathAxis = iota
	axisDescendant
)

type terminalKind uint8

const (
	termElement terminalKind = iota
	termAttr
	termText
)

type attrPred struct {
	space    string
	local    string
	value    string
	hasValue bool
}

type pathStep struct {
	space string
	local string
	preds []attrPred
	index int // -1 means no index filter
	axis  pathAxis
	any   bool
}

// Path is a compiled XML path expression. It is immutable and safe for concurrent use. | Path 是
// 编译后的 XML 路径表达式，不可变且可并发使用。
type Path struct {
	termName Name
	expr     string
	steps    []pathStep
	base     int
	terminal terminalKind
}

// String returns the original path expression. | String 返回原始路径表达式。
func (p *Path) String() string { return p.expr }

// Compile parses a path expression. Two styles are accepted:
//
//   - dot style (no '/'): separators are '.', indices are zero-based, for example
//     "bookstore.book[0].title", "bookstore.book[@id='b1'].price", "bookstore.book[0].#text"
//     or "bookstore.book[0].@id";
//   - XPath style (contains '/'): separators are '/' and '//', indices are one-based, for
//     example "/bookstore/book[1]/title", "//title", "/bookstore//price",
//     "/bookstore/book[@id=\"b1\"]/@id" or "/bookstore/book[1]/text()".
//
// A step is a local name, '*', or Clark notation "{uri}local". A namespace-less name matches the
// local name in any namespace. Predicates are "[n]", "[*]", "[@a]", "[@a='v']" and may be chained;
// attribute predicates are evaluated before the index, and descendant-axis indices count matches
// in document order globally while child-axis indices count per parent. | Compile 解析路径表达式。
// 支持两种风格：
//
//   - 点号风格（不含 '/'）：分隔符为 '.'，下标从 0 开始，例如 "bookstore.book[0].title"...
//   - XPath 风格（含 '/'）：分隔符为 '/' 与 '//'，下标从 1 开始，例如 "/bookstore/book[1]/title"...
//
// 步骤为本地名、'*' 或 Clark 记法 "{uri}local"；无命名空间名匹配任意命名空间下的本地名。谓词
// 支持 "[n]"、"[*]"、"[@a]"、"[@a='v']" 并可链式；属性谓词先于下标求值，后代轴下标按文档顺序
// 全局计数，子轴下标按父元素分组计数。
func Compile(expr string) (*Path, error) {
	original := expr
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, errs.Detail(ErrPathSyntax, "empty path | 空路径")
	}
	p := &Path{expr: original}
	xpath := strings.Contains(expr, "/")
	if xpath {
		p.base = 1
	}

	i := 0
	axis := axisChild
	if strings.HasPrefix(expr, "//") {
		axis = axisDescendant
		i = 2
	} else if expr[0] == '/' {
		i = 1
	}
	if i >= len(expr) {
		return nil, errs.Detail(ErrPathSyntax, "path ends after separator | 路径在分隔符后结束")
	}

	for {
		if expr[i] == '@' {
			if len(p.steps) == 0 {
				return nil, errs.Detail(ErrPathSyntax, "attribute terminal without element step | 属性终结符前缺少元素步骤")
			}
			name, next, err := parseNameToken(expr, i+1, nameStops(xpath, true))
			if err != nil {
				return nil, err
			}
			if next != len(expr) {
				return nil, errs.Detail(ErrPathSyntax, "unexpected text after attribute terminal | 属性终结符后存在多余文本")
			}
			p.terminal = termAttr
			p.termName = name
			break
		}
		if strings.HasPrefix(expr[i:], "#text") || strings.HasPrefix(expr[i:], "text()") {
			n := len("#text")
			if strings.HasPrefix(expr[i:], "text()") {
				n = len("text()")
			}
			if i+n != len(expr) {
				return nil, errs.Detail(ErrPathSyntax, "unexpected text after text terminal | 文本终结符后存在多余文本")
			}
			if len(p.steps) == 0 {
				return nil, errs.Detail(ErrPathSyntax, "text terminal without element step | 文本终结符前缺少元素步骤")
			}
			p.terminal = termText
			i = len(expr)
			break
		}

		step := pathStep{axis: axis, index: -1}
		if expr[i] == '*' {
			step.any = true
			i++
		} else {
			name, next, err := parseNameToken(expr, i, nameStops(xpath, false))
			if err != nil {
				return nil, err
			}
			step.space, step.local = name.Space, name.Local
			i = next
		}
		for i < len(expr) && expr[i] == '[' {
			next, err := parsePredicate(expr, i, &step, p.base)
			if err != nil {
				return nil, err
			}
			i = next
		}
		p.steps = append(p.steps, step)
		if len(p.steps) > 64 {
			return nil, errs.Detail(ErrPathSyntax, "path has more than 64 steps | 路径步骤超过 64 个")
		}
		if i == len(expr) {
			p.terminal = termElement
			break
		}
		if xpath {
			if strings.HasPrefix(expr[i:], "//") {
				axis = axisDescendant
				i += 2
			} else if expr[i] == '/' {
				axis = axisChild
				i++
			} else {
				return nil, errs.Detail(ErrPathSyntax, "expected '/' or '//' at %d | 第 %d 个字符处应为 '/' 或 '//'", i, i)
			}
		} else {
			if expr[i] == '.' {
				axis = axisChild
				i++
			} else {
				return nil, errs.Detail(ErrPathSyntax, "expected '.' at %d | 第 %d 个字符处应为 '.'", i, i)
			}
		}
		if i >= len(expr) {
			return nil, errs.Detail(ErrPathSyntax, "path ends after separator | 路径在分隔符后结束")
		}
	}
	return p, nil
}

func nameStops(xpath, attr bool) string {
	if xpath {
		if attr {
			return "=]"
		}
		return "/["
	}
	if attr {
		return "=]"
	}
	return ".["
}

func parseNameToken(s string, i int, stops string) (Name, int, error) {
	var name Name
	if i < len(s) && s[i] == '{' {
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return name, i, errs.Detail(ErrPathSyntax, "unterminated namespace | 命名空间未闭合")
		}
		name.Space = s[i+1 : i+j]
		i += j + 1
	}
	start := i
	for i < len(s) && !strings.ContainsRune(stops, rune(s[i])) {
		i++
	}
	if start == i {
		return name, i, errs.Detail(ErrPathSyntax, "empty name at %d | 第 %d 个字符处名称为空", i, i)
	}
	name.Local = s[start:i]
	if name.Local == "" {
		return name, i, errs.Detail(ErrPathSyntax, "empty local name | 本地名为空")
	}
	if !isNameString(name.Local) {
		return name, i, errs.Detail(ErrPathSyntax, "invalid XML name %q | 非法的 XML 名称 %q", name.Local, name.Local)
	}
	return name, i, nil
}

func parsePredicate(expr string, i int, step *pathStep, base int) (int, error) {
	i++ // [
	if i >= len(expr) {
		return i, errs.Detail(ErrPathSyntax, "unterminated predicate | 谓词未闭合")
	}
	switch {
	case expr[i] == '*':
		i++
	case expr[i] >= '0' && expr[i] <= '9':
		if step.index >= 0 {
			return i, errs.Detail(ErrPathSyntax, "multiple index predicates | 多个下标谓词")
		}
		start := i
		for i < len(expr) && expr[i] >= '0' && expr[i] <= '9' {
			i++
		}
		n, err := strconv.Atoi(expr[start:i])
		if err != nil {
			return i, errs.Detail(ErrPathSyntax, "invalid index | 非法下标")
		}
		if n < base {
			return i, errs.Detail(ErrPathSyntax, "index below base %d | 下标小于基数 %d", base, base)
		}
		step.index = n
	case expr[i] == '@':
		i++
		name, next, err := parseNameToken(expr, i, "=]")
		if err != nil {
			return i, err
		}
		i = next
		pred := attrPred{space: name.Space, local: name.Local}
		if i < len(expr) && expr[i] == '=' {
			i++
			if i >= len(expr) || expr[i] != '\'' && expr[i] != '"' {
				return i, errs.Detail(ErrPathSyntax, "predicate value must be quoted | 谓词值必须带引号")
			}
			q := expr[i]
			i++
			start := i
			for i < len(expr) && expr[i] != q {
				i++
			}
			if i >= len(expr) {
				return i, errs.Detail(ErrPathSyntax, "unterminated predicate value | 谓词值未闭合")
			}
			pred.value = expr[start:i]
			pred.hasValue = true
			i++
		}
		step.preds = append(step.preds, pred)
	default:
		return i, errs.Detail(ErrPathSyntax, "unsupported predicate at %d | 第 %d 个字符处的谓词不受支持", i, i)
	}
	if i >= len(expr) || expr[i] != ']' {
		return i, errs.Detail(ErrPathSyntax, "expected ']' at %d | 第 %d 个字符处应为 ']'", i, i)
	}
	return i + 1, nil
}

type pathRunner struct {
	p      *Path
	nodes  []*Node
	values []string
	out    []byte

	global []int32
	frames [][]int32
	first  bool
	stop   bool
	found  bool
}

func newPathRunner(p *Path) *pathRunner {
	return &pathRunner{p: p, global: make([]int32, len(p.steps))}
}

func (r *pathRunner) frame(depth int) []int32 {
	for len(r.frames) <= depth {
		r.frames = append(r.frames, make([]int32, len(r.p.steps)))
	}
	f := r.frames[depth]
	for i := range f {
		f[i] = 0
	}
	return f
}

func (r *pathRunner) walk(children []*Node, ctxBits uint64, counters []int32, depth int) bool {
	for _, e := range children {
		if e.Kind != ElementNode {
			continue
		}
		terminal := false
		childCtx := uint64(0)
		for b := ctxBits; b != 0; b &= b - 1 {
			i := bits.TrailingZeros64(b)
			st := &r.p.steps[i]
			if st.axis == axisDescendant {
				childCtx |= uint64(1) << uint(i)
			}
			if !stepMatches(st, e) {
				continue
			}
			if st.index >= 0 {
				if st.axis == axisChild {
					counters[i]++
					if int(counters[i])-1 != st.index-r.p.base {
						continue
					}
				} else {
					r.global[i]++
					if int(r.global[i])-1 != st.index-r.p.base {
						continue
					}
				}
			}
			// The terminal step has no successor bit; keeping it separate lets all 64
			// step bits be used by the uint64 candidate mask. | 终结步骤没有后继位；单独记录
			// 终结标记，使 uint64 候选位图可以完整使用 64 个步骤位。
			if i+1 < len(r.p.steps) {
				childCtx |= uint64(1) << uint(i+1)
			} else {
				terminal = true
			}
		}
		if terminal {
			r.emit(e)
			if r.stop {
				return true
			}
		}
		if len(e.Children) > 0 {
			if r.walk(e.Children, childCtx, r.frame(depth+1), depth+1) {
				return true
			}
		}
	}
	return false
}

func stepMatches(st *pathStep, e *Node) bool {
	return stepMatchesName(st, e.Name, e.Attrs)
}

func stepMatchesName(st *pathStep, name Name, attrs []Attr) bool {
	if !st.any {
		if st.space != "" {
			if name.Space != st.space || name.Local != st.local {
				return false
			}
		} else if name.Local != st.local {
			return false
		}
	}
	for _, pred := range st.preds {
		ok := false
		for _, a := range attrs {
			if a.Name.Local != pred.local {
				continue
			}
			if pred.space != "" && a.Name.Space != pred.space {
				continue
			}
			if !pred.hasValue || a.Value == pred.value {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (r *pathRunner) emit(e *Node) {
	switch r.p.terminal {
	case termElement:
		r.found = true
		r.nodes = append(r.nodes, e)
		text := e.Text()
		r.values = append(r.values, text)
		r.out = append(r.out, text...)
		if r.first {
			r.stop = true
		}
	case termAttr:
		for _, a := range e.Attrs {
			if a.Name.Local != r.p.termName.Local {
				continue
			}
			if r.p.termName.Space != "" && a.Name.Space != r.p.termName.Space {
				continue
			}
			r.found = true
			r.values = append(r.values, a.Value)
			r.out = append(r.out, a.Value...)
			if r.first {
				r.stop = true
			}
			return
		}
	case termText:
		r.found = true
		text := e.Text()
		r.values = append(r.values, text)
		r.out = append(r.out, text...)
		if r.first {
			r.stop = true
		}
	}
}

func (p *Path) run(children []*Node, first bool) *pathRunner {
	r := newPathRunner(p)
	r.first = first
	r.walk(children, 1, r.frame(0), 0)
	return r
}

// Select returns the element nodes matching p. It returns nil when p's terminal is an attribute
// or text. | Select 返回匹配 p 的元素节点；p 以属性或文本终结时返回 nil。
func (d *Document) Select(p *Path) []*Node {
	if p == nil || p.terminal != termElement {
		return nil
	}
	return p.run(d.Children, false).nodes
}

// SelectOne returns the first element node matching p, or nil. | SelectOne 返回首个匹配 p 的元素
// 节点，没有则返回 nil。
func (d *Document) SelectOne(p *Path) *Node {
	if p == nil || p.terminal != termElement {
		return nil
	}
	r := p.run(d.Children, true)
	if len(r.nodes) == 0 {
		return nil
	}
	return r.nodes[0]
}

// Value returns the first terminal value of p: the text of the matched element, the attribute
// value, or the direct text selected by text(). | Value 返回 p 的首个终结值：匹配元素的文本、属性值，
// 或 text() 选中的直接文本。
func (d *Document) Value(p *Path) (string, bool) {
	if p == nil {
		return "", false
	}
	r := p.run(d.Children, true)
	if !r.found || len(r.values) == 0 {
		return "", false
	}
	return r.values[0], true
}

// Values returns all terminal values of p. | Values 返回 p 的所有终结值。
func (d *Document) Values(p *Path) []string {
	if p == nil {
		return nil
	}
	return p.run(d.Children, false).values
}

// AppendValue appends the first terminal value of p to dst. | AppendValue 把 p 的首个终结值追加到 dst。
func (d *Document) AppendValue(dst []byte, p *Path) ([]byte, bool) {
	if p == nil {
		return dst, false
	}
	r := p.run(d.Children, true)
	if !r.found {
		return dst, false
	}
	return append(dst, r.out...), true
}

// Select returns the element nodes matching p relative to n. | Select 返回相对 n 匹配 p 的元素节点。
func (n *Node) Select(p *Path) []*Node {
	if p == nil || p.terminal != termElement {
		return nil
	}
	return p.run(n.Children, false).nodes
}

// SelectOne returns the first element node matching p relative to n, or nil. | SelectOne 返回相对 n
// 首个匹配 p 的元素节点，没有则返回 nil。
func (n *Node) SelectOne(p *Path) *Node {
	if p == nil || p.terminal != termElement {
		return nil
	}
	r := p.run(n.Children, true)
	if len(r.nodes) == 0 {
		return nil
	}
	return r.nodes[0]
}

// Value returns the first terminal value of p relative to n. | Value 返回相对 n 的 p 首个终结值。
func (n *Node) Value(p *Path) (string, bool) {
	if p == nil {
		return "", false
	}
	r := p.run(n.Children, true)
	if !r.found || len(r.values) == 0 {
		return "", false
	}
	return r.values[0], true
}

// Values returns all terminal values of p relative to n. | Values 返回相对 n 的 p 所有终结值。
func (n *Node) Values(p *Path) []string {
	if p == nil {
		return nil
	}
	return p.run(n.Children, false).values
}

// AppendValue appends the first terminal value of p relative to n to dst. | AppendValue 把相对 n 的
// p 首个终结值追加到 dst。
func (n *Node) AppendValue(dst []byte, p *Path) ([]byte, bool) {
	if p == nil {
		return dst, false
	}
	r := p.run(n.Children, true)
	if !r.found {
		return dst, false
	}
	return append(dst, r.out...), true
}
