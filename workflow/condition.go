package workflow

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// maxConditionDepth bounds parser recursion so a hostile expression cannot exhaust the stack. |
// maxConditionDepth 限制解析器递归深度，使恶意表达式无法耗尽栈空间。
const maxConditionDepth = 64

// maxConditionTokens bounds one expression. | maxConditionTokens 限制单条表达式的记号数量。
const maxConditionTokens = 512

// conditionTokenKind is the lexical class of one token. | conditionTokenKind 是一个记号的词法类别。
type conditionTokenKind int

// Token kinds of the condition language. | 条件语言的记号类型。
const (
	condEOF conditionTokenKind = iota
	condIdent
	condString
	condNumber
	condBool
	condNull
	condOp
	condAnd
	condOr
	condNotKind
	condLParen
	condRParen
	condLBracket
	condRBracket
	condComma
)

// conditionToken is one lexeme. | conditionToken 是一个词法记号。
type conditionToken struct {
	// text is the raw spelling or the identifier path. | text 是原始拼写或标识符路径。
	text string
	// num is the numeric value of a number literal. | num 是数字字面量的数值。
	num float64
	// boolean is the value of a boolean literal. | boolean 是布尔字面量的值。
	boolean bool
	// kind is the lexical class. | kind 是词法类别。
	kind conditionTokenKind
	// pos is the byte offset, used in error details. | pos 是字节偏移，用于错误细节。
	pos int
}

// conditionLexer turns an expression into tokens. | conditionLexer 把表达式转换为记号。
type conditionLexer struct {
	// src is the expression. | src 是表达式。
	src string
	// pos is the current byte offset. | pos 是当前字节偏移。
	pos int
	// count is the number of tokens produced. | count 是已产生的记号数。
	count int
}

// next returns the next token. | next 返回下一个记号。
func (l *conditionLexer) next() (conditionToken, error) {
	for l.pos < len(l.src) {
		switch l.src[l.pos] {
		case ' ', '\t', '\n', '\r':
			l.pos++
			continue
		}
		break
	}
	if l.pos >= len(l.src) {
		return conditionToken{kind: condEOF, pos: l.pos}, nil
	}
	if l.count >= maxConditionTokens {
		return conditionToken{}, errs.Detail(ErrInvalidCondition, "too many tokens | 记号过多")
	}
	l.count++

	start := l.pos
	ch := l.src[l.pos]
	switch ch {
	case '(':
		l.pos++
		return conditionToken{kind: condLParen, text: "(", pos: start}, nil
	case ')':
		l.pos++
		return conditionToken{kind: condRParen, text: ")", pos: start}, nil
	case '[':
		l.pos++
		return conditionToken{kind: condLBracket, text: "[", pos: start}, nil
	case ']':
		l.pos++
		return conditionToken{kind: condRBracket, text: "]", pos: start}, nil
	case ',':
		l.pos++
		return conditionToken{kind: condComma, text: ",", pos: start}, nil
	case '\'', '"':
		return l.lexString(ch)
	case '&':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '&' {
			l.pos += 2
			return conditionToken{kind: condAnd, text: "&&", pos: start}, nil
		}
		return conditionToken{}, errs.Detail(ErrInvalidCondition, "unexpected %[1]q at %[2]d | 位置 %[2]d 出现意外的 %[1]q", "&", start)
	case '|':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '|' {
			l.pos += 2
			return conditionToken{kind: condOr, text: "||", pos: start}, nil
		}
		return conditionToken{}, errs.Detail(ErrInvalidCondition, "unexpected %[1]q at %[2]d | 位置 %[2]d 出现意外的 %[1]q", "|", start)
	case '!':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
			l.pos += 2
			return conditionToken{kind: condOp, text: "!=", pos: start}, nil
		}
		l.pos++
		return conditionToken{kind: condNotKind, text: "!", pos: start}, nil
	case '=':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '=' {
			l.pos += 2
			return conditionToken{kind: condOp, text: "==", pos: start}, nil
		}
		l.pos++
		return conditionToken{kind: condOp, text: "=", pos: start}, nil
	case '>', '<':
		l.pos++
		if l.pos < len(l.src) && l.src[l.pos] == '=' {
			l.pos++
			return conditionToken{kind: condOp, text: string([]byte{ch, '='}), pos: start}, nil
		}
		return conditionToken{kind: condOp, text: string(ch), pos: start}, nil
	}

	if isDigit(ch) || (ch == '-' && l.pos+1 < len(l.src) && isDigit(l.src[l.pos+1])) {
		return l.lexNumber()
	}
	if isIdentStart(ch) {
		return l.lexIdent()
	}
	return conditionToken{}, errs.Detail(ErrInvalidCondition, "unexpected %[1]q at %[2]d | 位置 %[2]d 出现意外的 %[1]q", string(ch), start)
}

// isDigit reports whether ch is an ASCII digit. | isDigit 报告 ch 是否为 ASCII 数字。
func isDigit(ch byte) bool { return ch >= '0' && ch <= '9' }

// isIdentStart reports whether ch may start an identifier. | isIdentStart 报告 ch 是否可作为标识符首字符。
func isIdentStart(ch byte) bool {
	return ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// isIdentPart reports whether ch may continue an identifier path. | isIdentPart 报告 ch 是否可作为标识符路径的后续字符。
func isIdentPart(ch byte) bool {
	return isIdentStart(ch) || isDigit(ch) || ch == '.'
}

// lexString scans a quoted string with the usual backslash escapes. | lexString 扫描带常规反斜杠转义的引号字符串。
func (l *conditionLexer) lexString(quote byte) (conditionToken, error) {
	start := l.pos
	l.pos++
	var b strings.Builder
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		switch ch {
		case '\\':
			if l.pos+1 >= len(l.src) {
				return conditionToken{}, errs.Detail(ErrInvalidCondition, "unterminated escape at %[1]d | 位置 %[1]d 的转义未结束", l.pos)
			}
			next := l.src[l.pos+1]
			switch next {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '\'', '"':
				b.WriteByte(next)
			default:
				return conditionToken{}, errs.Detail(ErrInvalidCondition, "unknown escape \\%[1]c at %[2]d | 位置 %[2]d 出现未知转义 \\%[1]c", next, l.pos)
			}
			l.pos += 2
		case quote:
			l.pos++
			return conditionToken{kind: condString, text: b.String(), pos: start}, nil
		default:
			b.WriteByte(ch)
			l.pos++
		}
	}
	return conditionToken{}, errs.Detail(ErrInvalidCondition, "unterminated string at %[1]d | 位置 %[1]d 的字符串未结束", start)
}

// lexNumber scans a decimal number, including a fraction and an exponent. | lexNumber 扫描十进制数字，含小数与指数。
func (l *conditionLexer) lexNumber() (conditionToken, error) {
	start := l.pos
	if l.src[l.pos] == '-' {
		l.pos++
	}
	for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
		l.pos++
	}
	if l.pos < len(l.src) && l.src[l.pos] == '.' {
		l.pos++
		for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			l.pos++
		}
	}
	if l.pos < len(l.src) && (l.src[l.pos] == 'e' || l.src[l.pos] == 'E') {
		l.pos++
		if l.pos < len(l.src) && (l.src[l.pos] == '+' || l.src[l.pos] == '-') {
			l.pos++
		}
		for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			l.pos++
		}
	}
	raw := l.src[start:l.pos]
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return conditionToken{}, errs.Detail(ErrInvalidCondition, "number=%[1]q | 数字=%[1]q", raw)
	}
	return conditionToken{kind: condNumber, text: raw, num: value, pos: start}, nil
}

// lexIdent scans an identifier path and classifies the reserved words. | lexIdent 扫描标识符路径并归类保留字。
func (l *conditionLexer) lexIdent() (conditionToken, error) {
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
	}
	raw := l.src[start:l.pos]
	switch strings.ToLower(raw) {
	case "true":
		return conditionToken{kind: condBool, text: raw, boolean: true, pos: start}, nil
	case "false":
		return conditionToken{kind: condBool, text: raw, boolean: false, pos: start}, nil
	case "null", "nil":
		return conditionToken{kind: condNull, text: raw, pos: start}, nil
	case "and":
		return conditionToken{kind: condAnd, text: raw, pos: start}, nil
	case "or":
		return conditionToken{kind: condOr, text: raw, pos: start}, nil
	case "not":
		return conditionToken{kind: condNotKind, text: raw, pos: start}, nil
	case "in", "contains", "startswith", "endswith":
		return conditionToken{kind: condOp, text: strings.ToLower(raw), pos: start}, nil
	default:
		return conditionToken{kind: condIdent, text: raw, pos: start}, nil
	}
}

// condNode is one node of the parsed expression tree. | condNode 是解析后的表达式树节点。
type condNode interface {
	// eval computes the node against vars. | eval 针对 vars 计算节点。
	eval(vars map[string]any) (any, error)
}

// condLiteral is a constant value. | condLiteral 是常量值。
type condLiteral struct{ value any }

// eval returns the literal. | eval 返回字面量。
func (n condLiteral) eval(map[string]any) (any, error) { return n.value, nil }

// condPath reads a dotted path from the variable object. | condPath 从变量对象读取点分路径。
type condPath struct{ parts []string }

// eval walks the path; a missing segment evaluates to nil. | eval 沿路径取值；缺失段求值为 nil。
func (n condPath) eval(vars map[string]any) (any, error) {
	var current any = vars
	for _, part := range n.parts {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, nil
		}
		current = object[part]
	}
	return current, nil
}

// condList is a list literal. | condList 是列表字面量。
type condList struct{ items []condNode }

// eval evaluates every item. | eval 求值每个元素。
func (n condList) eval(vars map[string]any) (any, error) {
	out := make([]any, 0, len(n.items))
	for _, item := range n.items {
		value, err := item.eval(vars)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, nil
}

// condNot is logical negation. | condNot 是逻辑取反。
type condNot struct{ inner condNode }

// eval negates the truthiness of the inner node. | eval 对内层节点的真值取反。
func (n condNot) eval(vars map[string]any) (any, error) {
	value, err := n.inner.eval(vars)
	if err != nil {
		return nil, err
	}
	return !truthy(value), nil
}

// condLogical is short-circuit AND or OR. | condLogical 是短路与或。
type condLogical struct {
	left  condNode
	right condNode
	op    string
}

// eval applies the short-circuit rule. | eval 应用短路规则。
func (n condLogical) eval(vars map[string]any) (any, error) {
	left, err := n.left.eval(vars)
	if err != nil {
		return nil, err
	}
	leftTruth := truthy(left)
	if n.op == "and" {
		if !leftTruth {
			return false, nil
		}
		right, err := n.right.eval(vars)
		if err != nil {
			return nil, err
		}
		return truthy(right), nil
	}
	if leftTruth {
		return true, nil
	}
	right, err := n.right.eval(vars)
	if err != nil {
		return nil, err
	}
	return truthy(right), nil
}

// condCompare is one comparison. | condCompare 是一次比较。
type condCompare struct {
	left  condNode
	right condNode
	op    string
}

// eval performs the comparison. | eval 执行比较。
func (n condCompare) eval(vars map[string]any) (any, error) {
	left, err := n.left.eval(vars)
	if err != nil {
		return nil, err
	}
	right, err := n.right.eval(vars)
	if err != nil {
		return nil, err
	}
	return compareValues(n.op, left, right)
}

// compareValues implements every supported operator. | compareValues 实现全部支持的运算符。
func compareValues(op string, left, right any) (bool, error) {
	switch op {
	case "=", "==":
		return equalValues(left, right), nil
	case "!=":
		return !equalValues(left, right), nil
	case ">", ">=", "<", "<=":
		if lf, ok := numericValue(left); ok {
			if rf, ok := numericValue(right); ok {
				return ordered(op, lf, rf), nil
			}
		}
		if ls, ok := left.(string); ok {
			if rs, ok := right.(string); ok {
				return orderedString(op, ls, rs), nil
			}
		}
		return false, errs.Detail(ErrInvalidCondition, "operator %[1]q needs two numbers or two strings | 运算符 %[1]q 需要两个数字或两个字符串", op)
	case "contains":
		switch value := left.(type) {
		case string:
			return strings.Contains(value, stringValue(right)), nil
		case []any:
			for _, item := range value {
				if equalValues(item, right) {
					return true, nil
				}
			}
			return false, nil
		default:
			return false, errs.Detail(ErrInvalidCondition, "contains needs a string or list on the left | contains 左侧需要字符串或列表")
		}
	case "startswith":
		leftString, ok := left.(string)
		if !ok {
			return false, errs.Detail(ErrInvalidCondition, "startsWith needs a string on the left | startsWith 左侧需要字符串")
		}
		return strings.HasPrefix(leftString, stringValue(right)), nil
	case "endswith":
		leftString, ok := left.(string)
		if !ok {
			return false, errs.Detail(ErrInvalidCondition, "endsWith needs a string on the left | endsWith 左侧需要字符串")
		}
		return strings.HasSuffix(leftString, stringValue(right)), nil
	case "in":
		if list, ok := right.([]any); ok {
			for _, item := range list {
				if equalValues(left, item) {
					return true, nil
				}
			}
			return false, nil
		}
		return strings.Contains(stringValue(right), stringValue(left)), nil
	default:
		return false, errs.Detail(ErrInvalidCondition, "unknown operator %[1]q | 未知运算符 %[1]q", op)
	}
}

// ordered applies a numeric ordering operator. | ordered 应用数值排序运算符。
func ordered(op string, left, right float64) bool {
	switch op {
	case ">":
		return left > right
	case ">=":
		return left >= right
	case "<":
		return left < right
	default:
		return left <= right
	}
}

// orderedString applies a lexicographic ordering operator. | orderedString 应用字符串字典序运算符。
func orderedString(op string, left, right string) bool {
	switch op {
	case ">":
		return left > right
	case ">=":
		return left >= right
	case "<":
		return left < right
	default:
		return left <= right
	}
}

// equalValues compares two values with numeric tolerance for numbers. | equalValues 比较两个值，数字之间按数值比较。
func equalValues(left, right any) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	if lf, ok := numericValue(left); ok {
		if rf, ok := numericValue(right); ok {
			return lf == rf
		}
		return false
	}
	if lb, ok := left.(bool); ok {
		rb, ok := right.(bool)
		return ok && lb == rb
	}
	if ls, ok := left.(string); ok {
		rs, ok := right.(string)
		return ok && ls == rs
	}
	return false
}

// numericValue converts the numeric carriers ydx/json produces. | numericValue 转换 ydx/json 产生的数字载体。
func numericValue(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case jsonNumber:
		f, err := strconv.ParseFloat(string(v), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// jsonNumber is the textual number carrier some decoders use. | jsonNumber 是部分解码器使用的文本数字载体。
type jsonNumber string

// stringValue renders a value for string operators. | stringValue 为字符串运算符渲染值。
func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(v)
	default:
		if f, ok := numericValue(value); ok {
			return strconv.FormatFloat(f, 'f', -1, 64)
		}
		return ""
	}
}

// truthy reports the boolean reading of a value. | truthy 报告值的布尔解读。
func truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		if f, ok := numericValue(value); ok {
			return f != 0
		}
		return value != nil
	}
}

// conditionParser is a recursive-descent parser for the condition language. | conditionParser
// 是条件语言的递归下降解析器。
type conditionParser struct {
	// lexer produces tokens. | lexer 产生记号。
	lexer *conditionLexer
	// current is the look-ahead token. | current 是预读记号。
	current conditionToken
	// depth is the current recursion depth. | depth 是当前递归深度。
	depth int
}

// parseCondition parses src into an expression tree. | parseCondition 把 src 解析为表达式树。
func parseCondition(src string) (condNode, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return condLiteral{value: true}, nil
	}
	if len(src) > maxConditionLen {
		return nil, errs.Detail(ErrInvalidCondition, "condition is longer than %[1]d bytes | 条件超过 %[1]d 字节", maxConditionLen)
	}
	p := &conditionParser{lexer: &conditionLexer{src: src}}
	if err := p.advance(); err != nil {
		return nil, err
	}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.current.kind != condEOF {
		return nil, errs.Detail(ErrInvalidCondition, "unexpected %[1]q at %[2]d | 位置 %[2]d 出现意外的 %[1]q", p.current.text, p.current.pos)
	}
	return node, nil
}

// maxConditionLen is the standalone ceiling used by validators outside a Service. | maxConditionLen
// 是 Service 之外校验器使用的独立上限。
const maxConditionLen = 2048

// advance reads the next token. | advance 读取下一个记号。
func (p *conditionParser) advance() error {
	token, err := p.lexer.next()
	if err != nil {
		return err
	}
	p.current = token
	return nil
}

// enter increments the depth and rejects an over-deep expression. | enter 增加深度并拒绝过深表达式。
func (p *conditionParser) enter() error {
	p.depth++
	if p.depth > maxConditionDepth {
		return errs.Detail(ErrInvalidCondition, "condition is nested too deeply | 条件嵌套过深")
	}
	return nil
}

// leave decrements the depth. | leave 减少深度。
func (p *conditionParser) leave() { p.depth-- }

// parseOr parses a chain of OR operators. | parseOr 解析或运算链。
func (p *conditionParser) parseOr() (condNode, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.current.kind == condOr {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = condLogical{left: left, right: right, op: "or"}
	}
	return left, nil
}

// parseAnd parses a chain of AND operators. | parseAnd 解析与运算链。
func (p *conditionParser) parseAnd() (condNode, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.current.kind == condAnd {
		if err := p.advance(); err != nil {
			return nil, err
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = condLogical{left: left, right: right, op: "and"}
	}
	return left, nil
}

// parseUnary parses NOT and one comparison. | parseUnary 解析取反与一次比较。
func (p *conditionParser) parseUnary() (condNode, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	if p.current.kind == condNotKind {
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return condNot{inner: inner}, nil
	}
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	if p.current.kind != condOp {
		return left, nil
	}
	op := strings.ToLower(p.current.text)
	if err := p.advance(); err != nil {
		return nil, err
	}
	right, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	return condCompare{left: left, right: right, op: op}, nil
}

// parsePrimary parses a literal, path, list or parenthesised expression. | parsePrimary
// 解析字面量、路径、列表或括号表达式。
func (p *conditionParser) parsePrimary() (condNode, error) {
	switch p.current.kind {
	case condLParen:
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.current.kind != condRParen {
			return nil, errs.Detail(ErrInvalidCondition, "missing ) at %[1]d | 位置 %[1]d 缺少 )", p.current.pos)
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
		return inner, nil
	case condString:
		value := p.current.text
		if err := p.advance(); err != nil {
			return nil, err
		}
		return condLiteral{value: value}, nil
	case condNumber:
		value := p.current.num
		if err := p.advance(); err != nil {
			return nil, err
		}
		return condLiteral{value: value}, nil
	case condBool:
		value := p.current.boolean
		if err := p.advance(); err != nil {
			return nil, err
		}
		return condLiteral{value: value}, nil
	case condNull:
		if err := p.advance(); err != nil {
			return nil, err
		}
		return condLiteral{value: nil}, nil
	case condIdent:
		raw := p.current.text
		if err := p.advance(); err != nil {
			return nil, err
		}
		parts := strings.Split(raw, ".")
		for _, part := range parts {
			if part == "" {
				return nil, errs.Detail(ErrInvalidCondition, "malformed path %[1]q | 路径 %[1]q 格式非法", raw)
			}
		}
		return condPath{parts: parts}, nil
	case condLBracket:
		return p.parseList()
	default:
		return nil, errs.Detail(ErrInvalidCondition, "unexpected %[1]q at %[2]d | 位置 %[2]d 出现意外的 %[1]q", p.current.text, p.current.pos)
	}
}

// parseList parses a bracketed list literal. | parseList 解析方括号列表字面量。
func (p *conditionParser) parseList() (condNode, error) {
	if err := p.advance(); err != nil {
		return nil, err
	}
	items := make([]condNode, 0, 4)
	for p.current.kind != condRBracket {
		item, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		if p.current.kind == condComma {
			if err := p.advance(); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	if p.current.kind != condRBracket {
		return nil, errs.Detail(ErrInvalidCondition, "missing ] at %[1]d | 位置 %[1]d 缺少 ]", p.current.pos)
	}
	if err := p.advance(); err != nil {
		return nil, err
	}
	return condList{items: items}, nil
}

// ValidateCondition reports whether expr is syntactically valid; empty is valid and means true. |
// ValidateCondition 报告 expr 语法是否合法；空表达式合法且表示真。
func ValidateCondition(expr string) error {
	_, err := compileCondition(expr)
	return err
}

// EvaluateCondition evaluates expr against vars. A missing path yields nil; comparing nil with
// an ordering operator is an error so a broken condition fails closed instead of silently
// selecting a branch. Compiled expressions are cached, so repeated edge and rule evaluation does
// not reparse the source. | EvaluateCondition 针对 vars 求值 expr。缺失路径得到 nil；用排序运算符
// 比较 nil 会报错，使错误条件失败关闭，而不是静默选择某个分支。已编译表达式会被缓存，重复的连线与
// 规则求值不再重新解析源码。
func EvaluateCondition(expr string, vars map[string]any) (bool, error) {
	node, err := compileCondition(expr)
	if err != nil {
		return false, err
	}
	value, err := node.eval(vars)
	if err != nil {
		return false, err
	}
	return truthy(value), nil
}
