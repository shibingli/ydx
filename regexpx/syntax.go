package regexpx

import (
	"fmt"
)

// flagSet holds the inline matching options that apply to a pattern region. | flagSet 保存作用于模式
// 区域的匹配选项。
type flagSet uint8

const (
	// flagFold enables Unicode simple case folding. | flagFold 启用 Unicode 简单大小写折叠。
	flagFold flagSet = 1 << iota
	// flagMultiline makes ^ and $ match at line boundaries. | flagMultiline 使 ^ 与 $ 匹配行边界。
	flagMultiline
	// flagDotAll makes . match newline. | flagDotAll 使 . 匹配换行。
	flagDotAll
	// flagUngreedy swaps the default greediness of quantifiers. | flagUngreedy 交换量词的默认贪婪性。
	flagUngreedy
	// flagIgnoreSpace enables the .NET free-spacing mode. | flagIgnoreSpace 启用 .NET 自由空白模式。
	flagIgnoreSpace
)

// assertKind enumerates the zero-width assertions the engine understands. | assertKind 枚举引擎支持的
// 零宽断言。
type assertKind uint8

const (
	// assertBeginText matches at the beginning of the input. | assertBeginText 匹配输入开头。
	assertBeginText assertKind = iota
	// assertEndText matches at the end of the input. | assertEndText 匹配输入末尾。
	assertEndText
	// assertBeginLine matches at the beginning of a line. | assertBeginLine 匹配行首。
	assertBeginLine
	// assertEndLine matches at the end of a line. | assertEndLine 匹配行尾。
	assertEndLine
	// assertWordBoundary matches an ASCII word boundary. | assertWordBoundary 匹配 ASCII 单词边界。
	assertWordBoundary
	// assertNotWordBoundary matches a position that is not an ASCII word boundary. |
	// assertNotWordBoundary 匹配非 ASCII 单词边界的位置。
	assertNotWordBoundary
	// assertEndTextFinalNewline matches at the end of the input or before one final newline. |
	// assertEndTextFinalNewline 匹配输入末尾或最后一个换行之前。
	assertEndTextFinalNewline
)

// node is one parsed regular-expression syntax node. | node 表示一个解析后的正则语法节点。
type node interface{ regexNode() }

// nEmpty matches the empty string. | nEmpty 匹配空串。
type nEmpty struct{}

// nLiteral matches one literal rune. | nLiteral 匹配一个字面量符文。
type nLiteral struct {
	r    rune
	fold bool
}

// nString matches a run of literal runes. | nString 匹配一段连续的字面量符文。
type nString struct {
	runes []rune
	fold  bool
}

// nClass matches one rune from a character class. | nClass 匹配字符类中的单个符文。
type nClass struct{ c *charClass }

// nAny matches any rune, optionally including newline. | nAny 匹配任意符文，可选包含换行。
type nAny struct{ dotAll bool }

// nConcat matches its children in sequence. | nConcat 依次匹配其子节点。
type nConcat struct{ sub []node }

// nAlt matches one of its alternatives in priority order. | nAlt 按优先级匹配其中一个分支。
type nAlt struct{ sub []node }

// nRepeat matches its child between min and max times. | nRepeat 将子节点匹配 min 到 max 次。
type nRepeat struct {
	sub    node
	min    int
	max    int // -1 means unbounded | -1 表示无上限
	greedy bool
}

// nCapture is a capturing group. | nCapture 是捕获分组。
type nCapture struct {
	index int
	name  string
	sub   node
}

// nAssert is a zero-width assertion. | nAssert 是零宽断言。
type nAssert struct{ kind assertKind }

// nLook is a lookahead or lookbehind group. | nLook 是先行或后行断言分组。
type nLook struct {
	sub    node
	behind bool
	neg    bool
}

// nBackref matches the text captured by an earlier group. | nBackref 匹配先前分组捕获的文本。
type nBackref struct {
	index int
	name  string
	fold  bool
}

// nAtomic is an atomic group: its preferred match cannot be revisited. | nAtomic 是原子分组：其首选
// 匹配不会被回溯改写。
type nAtomic struct{ sub node }

// nAmbig is an escape that is a backreference when the pattern has enough groups and an octal escape
// otherwise. It is resolved after the whole pattern has been parsed. | nAmbig 是歧义转义：模式中的分组
// 足够多时按反向引用处理，否则按八进制转义处理；它在整个模式解析完成后确定。
type nAmbig struct {
	value rune
	fold  bool
}

func (*nEmpty) regexNode()   {}
func (*nLiteral) regexNode() {}
func (*nString) regexNode()  {}
func (*nClass) regexNode()   {}
func (*nAny) regexNode()     {}
func (*nConcat) regexNode()  {}
func (*nAlt) regexNode()     {}
func (*nRepeat) regexNode()  {}
func (*nCapture) regexNode() {}
func (*nAssert) regexNode()  {}
func (*nLook) regexNode()    {}
func (*nBackref) regexNode() {}
func (*nAtomic) regexNode()  {}
func (*nAmbig) regexNode()   {}

// syntaxError reports where a pattern failed to parse. | syntaxError 报告模式解析失败的位置。
type syntaxError struct {
	pattern string
	pos     int // rune offset | 符文偏移
	msg     string
}

// Error renders the position and the offending pattern. | Error 渲染位置与出错的模式。
func (e *syntaxError) Error() string {
	return fmt.Sprintf("%s at position %d in %q | %s，位置 %d，模式 %q", e.msg, e.pos, e.pattern, e.msg, e.pos, e.pattern)
}

// parser is a recursive-descent parser for the RE2 syntax plus the .NET constructs the compatibility
// layer needs. | parser 是 RE2 语法加 .NET 兼容构造的递归下降解析器。
type parser struct {
	src    string
	runes  []rune
	pos    int
	numCap int
	names  map[string]int
	err    error
	// posix selects POSIX repetition grammar, where a quantifier following another quantifier
	// applies to the quantified expression instead of acting as a lazy/possessive modifier. |
	// posix 选择 POSIX 重复语法：量词后的另一个量词作用于已量化的表达式，而不是作为惰性/占有
	// 修饰符。
	posix bool
}

// parsePattern parses src into an AST plus the capture metadata. | parsePattern 把 src 解析为 AST 与
// 捕获元数据。
func parsePattern(src string) (node, int, map[string]int, error) {
	return parsePatternWithMode(src, false)
}

// parsePatternWithMode parses src with the standard or POSIX repetition grammar. | parsePatternWithMode
// 使用标准或 POSIX 重复语法解析 src。
func parsePatternWithMode(src string, posix bool) (node, int, map[string]int, error) {
	p := &parser{src: src, runes: []rune(src), names: make(map[string]int), posix: posix}
	flags := flagSet(0)
	n := p.parseAlternation(&flags)
	if p.err == nil && p.pos < len(p.runes) {
		p.fail("unexpected ) | 意外的 )")
	}
	if p.err != nil {
		return nil, 0, nil, p.err
	}
	n = resolveAmbiguous(n, p.numCap)
	return simplify(n), p.numCap, p.names, nil
}

// fail records the first syntax error. | fail 记录首个语法错误。
func (p *parser) fail(msg string) {
	if p.err == nil {
		p.err = &syntaxError{pattern: p.src, pos: p.pos, msg: msg}
	}
}

// failf records a formatted syntax error. | failf 记录格式化的语法错误。
func (p *parser) failf(format string, args ...any) {
	p.fail(fmt.Sprintf(format, args...))
}

// peek returns the current rune or -1 at end of input. | peek 返回当前符文，输入结束时返回 -1。
func (p *parser) peek() rune {
	if p.pos < len(p.runes) {
		return p.runes[p.pos]
	}
	return -1
}

// peekAt returns the rune n positions ahead or -1. | peekAt 返回前方第 n 个符文，越界时返回 -1。
func (p *parser) peekAt(n int) rune {
	if p.pos+n < len(p.runes) && p.pos+n >= 0 {
		return p.runes[p.pos+n]
	}
	return -1
}

// next consumes and returns the current rune. | next 消费并返回当前符文。
func (p *parser) next() rune {
	r := p.runes[p.pos]
	p.pos++
	return r
}

// expect consumes r or records an error. | expect 消费 r，否则记录错误。
func (p *parser) expect(r rune) bool {
	if p.peek() != r {
		p.failf("expected %q | 期望 %q", r, r)
		return false
	}
	p.pos++
	return true
}

// skipSpace implements the free-spacing mode: whitespace and # comments are ignored. | skipSpace 实现
// 自由空白模式：忽略空白与 # 注释。
func (p *parser) skipSpace() {
	for p.pos < len(p.runes) {
		switch p.runes[p.pos] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			p.pos++
		case '#':
			for p.pos < len(p.runes) && p.runes[p.pos] != '\n' {
				p.pos++
			}
		default:
			return
		}
	}
}

// parseAlternation parses alternatives separated by |. Flag changes made inside one alternative remain
// in effect for later alternatives of the same enclosing group. | parseAlternation 解析以 | 分隔的分支。
// 某个分支内的标志变更对同一外层分组的后续分支继续生效。
func (p *parser) parseAlternation(flags *flagSet) node {
	first := p.parseConcat(flags)
	if p.err != nil {
		return first
	}
	if p.peek() != '|' {
		return first
	}
	subs := []node{first}
	for p.peek() == '|' {
		p.pos++
		subs = append(subs, p.parseConcat(flags))
		if p.err != nil {
			return nil
		}
	}
	return &nAlt{sub: subs}
}

// parseConcat parses a sequence of quantified atoms. | parseConcat 解析一串带量词的原子。
func (p *parser) parseConcat(flags *flagSet) node {
	var subs []node
	for p.err == nil {
		if *flags&flagIgnoreSpace != 0 {
			p.skipSpace()
		}
		r := p.peek()
		if r == -1 || r == '|' || r == ')' {
			break
		}
		atom := p.parseAtom(flags)
		if p.err != nil {
			return nil
		}
		if atom == nil {
			continue
		}
		subs = append(subs, p.parseQuantifier(atom, *flags))
	}
	switch len(subs) {
	case 0:
		return &nEmpty{}
	case 1:
		return subs[0]
	default:
		return &nConcat{sub: subs}
	}
}

// parseAtom parses one atom that is not yet quantified. | parseAtom 解析一个尚未加量词的原子。
func (p *parser) parseAtom(flags *flagSet) node {
	r := p.peek()
	switch r {
	case '(':
		return p.parseGroup(flags)
	case '[':
		return p.parseClass(*flags)
	case '.':
		p.pos++
		return &nAny{dotAll: *flags&flagDotAll != 0}
	case '^':
		p.pos++
		if p.posix || *flags&flagMultiline != 0 {
			// POSIX mode has no OneLine flag: ^ and $ are line anchors. | POSIX 模式没有 OneLine
			// 标志：^ 与 $ 是行锚点。
			return &nAssert{kind: assertBeginLine}
		}
		return &nAssert{kind: assertBeginText}
	case '$':
		p.pos++
		if p.posix || *flags&flagMultiline != 0 {
			return &nAssert{kind: assertEndLine}
		}
		return &nAssert{kind: assertEndText}
	case '\\':
		return p.parseEscape(*flags)
	case '*', '+', '?':
		p.failf("missing argument to repetition operator %q | 重复运算符 %q 缺少参数", r, r)
		return nil
	case '{':
		// A brace that does not form a valid repetition is a literal brace. | 不构成合法重复的
		// 花括号按字面量处理。
		if _, _, ok := p.tryRepeatCount(); ok {
			p.fail("missing argument to repetition operator | 重复运算符缺少参数")
			return nil
		}
		p.pos++
		return p.literal('{', *flags)
	default:
		p.pos++
		return p.literal(r, *flags)
	}
}

// literal builds a literal node with the current case-folding option. | literal 按当前大小写折叠选项
// 构造字面量节点。
func (p *parser) literal(r rune, flags flagSet) node {
	return &nLiteral{r: r, fold: flags&flagFold != 0}
}

// parseQuantifier parses an optional quantifier and its greediness modifier. In POSIX mode a
// following quantifier is a nested repetition, matching regexp.CompilePOSIX. | parseQuantifier 解析
// 可选的量词及其贪婪性修饰。POSIX 模式下后续量词构成嵌套重复，与 regexp.CompilePOSIX 一致。
func (p *parser) parseQuantifier(atom node, flags flagSet) node {
	min, max, ok := p.parseRepeatOp()
	if !ok {
		return atom
	}
	if p.posix {
		var n node = &nRepeat{sub: atom, min: min, max: max, greedy: true}
		for {
			nextMin, nextMax, nextOK := p.parseRepeatOp()
			if !nextOK {
				return n
			}
			n = &nRepeat{sub: n, min: nextMin, max: nextMax, greedy: true}
		}
	}
	greedy := flags&flagUngreedy == 0
	possessive := false
	switch p.peek() {
	case '?':
		p.pos++
		greedy = !greedy
	case '+':
		p.pos++
		possessive = true
	}
	switch p.peek() {
	case '*', '+', '?':
		p.fail("invalid nested repetition operator | 非法的嵌套重复运算符")
		return atom
	case '{':
		if _, _, ok := p.tryRepeatCount(); ok {
			p.fail("invalid nested repetition operator | 非法的嵌套重复运算符")
			return atom
		}
	}
	n := &nRepeat{sub: atom, min: min, max: max, greedy: greedy}
	if possessive {
		return &nAtomic{sub: n}
	}
	return n
}

// parseRepeatOp consumes one repetition operator. It leaves the position unchanged when the next
// token is not a quantifier. | parseRepeatOp 消费一个重复运算符；下一个标记不是量词时不移动位置。
func (p *parser) parseRepeatOp() (min, max int, ok bool) {
	switch p.peek() {
	case '*':
		p.pos++
		return 0, -1, true
	case '+':
		p.pos++
		return 1, -1, true
	case '?':
		p.pos++
		return 0, 1, true
	case '{':
		return p.tryRepeatCount()
	}
	return 0, 0, false
}

// tryRepeatCount parses {n}, {n,} or {n,m} and reports whether the text was a valid count. It leaves
// the position unchanged on failure so the brace can become a literal. | tryRepeatCount 解析 {n}、
// {n,} 或 {n,m} 并报告是否为合法计数；失败时不移动位置，使花括号可作为字面量。
func (p *parser) tryRepeatCount() (min, max int, ok bool) {
	save := p.pos
	if p.peek() != '{' {
		return 0, 0, false
	}
	p.pos++
	min, ok = p.scanDecimal()
	if !ok {
		p.pos = save
		return 0, 0, false
	}
	max = min
	if p.peek() == ',' {
		p.pos++
		if p.peek() == '}' {
			max = -1
		} else {
			max, ok = p.scanDecimal()
			if !ok {
				p.pos = save
				return 0, 0, false
			}
		}
	}
	if p.peek() != '}' {
		p.pos = save
		return 0, 0, false
	}
	p.pos++
	const maxRepeat = 1000
	if min > maxRepeat || (max >= 0 && max > maxRepeat) {
		p.failf("invalid repeat count | 非法的重复次数")
		p.pos = save
		return 0, 0, false
	}
	if max >= 0 && min > max {
		p.failf("invalid repeat count {%d,%d} | 非法的重复次数 {%d,%d}", min, max, min, max)
		p.pos = save
		return 0, 0, false
	}
	return min, max, true
}

// scanDecimal scans a decimal count with overflow protection. | scanDecimal 扫描十进制计数并防止溢出。
func (p *parser) scanDecimal() (int, bool) {
	start := p.pos
	value := 0
	for p.pos < len(p.runes) && p.runes[p.pos] >= '0' && p.runes[p.pos] <= '9' {
		value = value*10 + int(p.runes[p.pos]-'0')
		if value > 1<<20 {
			for p.pos < len(p.runes) && p.runes[p.pos] >= '0' && p.runes[p.pos] <= '9' {
				p.pos++
			}
			p.fail("repeat count too large | 重复次数过大")
			return 0, false
		}
		p.pos++
	}
	return value, p.pos > start
}

// parseGroup parses every parenthesized construct. | parseGroup 解析所有括号构造。
func (p *parser) parseGroup(flags *flagSet) node {
	p.pos++ // consume '('
	if p.peek() != '?' {
		index, name := p.newCapture("")
		inner := *flags
		sub := p.parseAlternation(&inner)
		p.expect(')')
		return &nCapture{index: index, name: name, sub: sub}
	}
	p.pos++ // consume '?'
	switch r := p.peek(); r {
	case ':':
		p.pos++
		return p.parseScoped(flags)
	case '=':
		p.pos++
		return p.parseLook(flags, false, false)
	case '!':
		p.pos++
		return p.parseLook(flags, false, true)
	case '>':
		p.pos++
		inner := *flags
		sub := p.parseAlternation(&inner)
		p.expect(')')
		return &nAtomic{sub: sub}
	case '<':
		switch p.peekAt(1) {
		case '=':
			p.pos += 2
			return p.parseLook(flags, true, false)
		case '!':
			p.pos += 2
			return p.parseLook(flags, true, true)
		}
		p.pos++ // consume '<'
		name := p.parseName('>')
		index, _ := p.newCapture(name)
		inner := *flags
		sub := p.parseAlternation(&inner)
		p.expect(')')
		return &nCapture{index: index, name: name, sub: sub}
	case '\'':
		p.pos++
		name := p.parseName('\'')
		index, _ := p.newCapture(name)
		inner := *flags
		sub := p.parseAlternation(&inner)
		p.expect(')')
		return &nCapture{index: index, name: name, sub: sub}
	case 'P':
		if p.peekAt(1) != '<' {
			p.fail("invalid named capture | 非法的命名捕获")
			return nil
		}
		p.pos += 2
		name := p.parseName('>')
		index, _ := p.newCapture(name)
		inner := *flags
		sub := p.parseAlternation(&inner)
		p.expect(')')
		return &nCapture{index: index, name: name, sub: sub}
	case '#':
		for p.pos < len(p.runes) && p.runes[p.pos] != ')' {
			p.pos++
		}
		p.expect(')')
		return &nEmpty{}
	}
	on, off, scoped, ok := p.parseFlags()
	if !ok {
		return nil
	}
	if scoped {
		inner := (*flags &^ off) | on
		return p.parseScoped(&inner)
	}
	*flags = (*flags &^ off) | on
	return &nEmpty{}
}

// parseScoped parses the body and closing parenthesis of a non-capturing group. | parseScoped 解析
// 非捕获分组的主体与右括号。
func (p *parser) parseScoped(flags *flagSet) node {
	inner := *flags
	sub := p.parseAlternation(&inner)
	p.expect(')')
	return sub
}

// parseLook parses a lookahead or lookbehind body. | parseLook 解析先行或后行断言主体。
func (p *parser) parseLook(flags *flagSet, behind, neg bool) node {
	inner := *flags
	sub := p.parseAlternation(&inner)
	p.expect(')')
	return &nLook{sub: sub, behind: behind, neg: neg}
}

// parseName scans a group name up to close and validates it. | parseName 扫描到 close 为止的分组名并校验。
func (p *parser) parseName(close rune) string {
	start := p.pos
	for p.pos < len(p.runes) && p.runes[p.pos] != close {
		p.pos++
	}
	if p.pos >= len(p.runes) {
		p.failf("missing closing %q in group name | 分组名缺少 %q", close, close)
		return ""
	}
	name := string(p.runes[start:p.pos])
	p.pos++
	if name == "" {
		p.fail("empty group name | 空分组名")
		return ""
	}
	for _, r := range name {
		// The standard library accepts [A-Za-z0-9_]+ for capture names, including a leading
		// digit, and rejects non-ASCII letters. | 标准库接受 [A-Za-z0-9_]+ 作为捕获名（允许数字
		// 开头），并拒绝非 ASCII 字母。
		if r != '_' && !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') {
			p.failf("invalid group name %q | 非法的分组名 %q", name, name)
			return ""
		}
	}
	return name
}

// newCapture allocates the next capture index and records its name. | newCapture 分配下一个捕获下标并
// 记录名称。
func (p *parser) newCapture(name string) (int, string) {
	p.numCap++
	if name != "" {
		if _, dup := p.names[name]; dup {
			p.failf("duplicate group name %q | 重复的分组名 %q", name, name)
		}
		p.names[name] = p.numCap
	}
	return p.numCap, name
}

// parseFlags parses the inline flag syntax (?im-sx) or (?im-sx:. It reports scoped=true when the flags
// are followed by a colon. | parseFlags 解析内联标志语法 (?im-sx) 或 (?im-sx:；标志后跟冒号时
// scoped 为 true。
func (p *parser) parseFlags() (on, off flagSet, scoped, ok bool) {
	neg := false
	for {
		r := p.peek()
		if r == -1 {
			p.fail("missing closing ) in flags | 标志缺少右括号")
			return 0, 0, false, false
		}
		if r == ')' || r == ':' {
			p.pos++
			return on, off, r == ':', true
		}
		var f flagSet
		switch r {
		case 'i':
			f = flagFold
		case 'm':
			f = flagMultiline
		case 's':
			f = flagDotAll
		case 'U':
			f = flagUngreedy
		case 'x':
			f = flagIgnoreSpace
		case '-':
			if neg {
				p.fail("repeated - in flags | 标志中重复的 -")
				return 0, 0, false, false
			}
			neg = true
			p.pos++
			continue
		default:
			p.failf("unknown flag %q | 未知标志 %q", r, r)
			return 0, 0, false, false
		}
		p.pos++
		if neg {
			off |= f
		} else {
			on |= f
		}
	}
}
