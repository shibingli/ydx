package scim

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Filter is a parsed RFC 7644 filter expression. | Filter 是已解析的 RFC 7644 过滤表达式。
type Filter interface {
	// Match reports whether resource satisfies the filter. Supported resource types are *User,
	// User, *Group, Group, *EnterpriseUser and map[string]any. | Match 报告 resource 是否满足过滤
	// 条件。支持的资源类型为 *User、User、*Group、Group、*EnterpriseUser 与 map[string]any。
	Match(resource any) bool
	// String returns the canonical text of the filter. | String 返回过滤器的规范化文本。
	String() string
}

// AttributePath is a parsed SCIM attribute path, optionally schema-qualified, with a value
// filter and a sub-attribute. | AttributePath 是已解析的 SCIM 属性路径，可带 Schema 限定、值
// 过滤器与子属性。
type AttributePath struct {
	// ValueFilter is the optional filter applied to entries of a multi-valued attribute. |
	// ValueFilter 是应用于多值属性条目的可选过滤器。
	ValueFilter Filter
	// Schema is the optional schema URN prefix. | Schema 是可选的 Schema URN 前缀。
	Schema string
	// Attribute is the attribute name. | Attribute 是属性名。
	Attribute string
	// SubAttribute is the optional sub-attribute name. | SubAttribute 是可选的子属性名。
	SubAttribute string
}

// String returns the canonical text of the path. | String 返回路径的规范化文本。
func (p *AttributePath) String() string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	if p.Schema != "" {
		b.WriteString(p.Schema)
		if p.Attribute != "" {
			b.WriteByte(':')
		}
	}
	b.WriteString(p.Attribute)
	if p.ValueFilter != nil {
		b.WriteByte('[')
		b.WriteString(p.ValueFilter.String())
		b.WriteByte(']')
	}
	if p.SubAttribute != "" {
		b.WriteByte('.')
		b.WriteString(p.SubAttribute)
	}
	return b.String()
}

// compareOp is one RFC 7644 comparison operator. | compareOp 是一个 RFC 7644 比较运算符。
type compareOp uint8

const (
	opEQ compareOp = iota
	opNE
	opCO
	opSW
	opEW
	opGT
	opGE
	opLT
	opLE
)

// operatorText returns the lowercase wire name of op. | operatorText 返回 op 的小写线名。
func operatorText(op compareOp) string {
	switch op {
	case opEQ:
		return "eq"
	case opNE:
		return "ne"
	case opCO:
		return "co"
	case opSW:
		return "sw"
	case opEW:
		return "ew"
	case opGT:
		return "gt"
	case opGE:
		return "ge"
	case opLT:
		return "lt"
	case opLE:
		return "le"
	}
	return ""
}

// parseOperator parses a comparison operator name case-insensitively. | parseOperator 以大小写
// 不敏感方式解析比较运算符名。
func parseOperator(value string) (compareOp, bool) {
	switch strings.ToLower(value) {
	case "eq":
		return opEQ, true
	case "ne":
		return opNE, true
	case "co":
		return opCO, true
	case "sw":
		return opSW, true
	case "ew":
		return opEW, true
	case "gt":
		return opGT, true
	case "ge":
		return opGE, true
	case "lt":
		return opLT, true
	case "le":
		return opLE, true
	}
	return 0, false
}

// literalKind classifies a comparison literal. | literalKind 对比较字面量分类。
type literalKind uint8

const (
	litNull literalKind = iota
	litBool
	litNumber
	litString
)

// literal is the right hand side of a comparison. | literal 是比较的右侧值。
type literal struct {
	// text is the original textual value. | text 是原始文本值。
	text string
	// number is the parsed numeric value for litNumber. | number 是 litNumber 的解析数值。
	number float64
	// boolean is the parsed value for litBool. | boolean 是 litBool 的解析布尔值。
	boolean bool
	// kind is the literal class. | kind 是字面量类别。
	kind literalKind
}

// String renders the literal in canonical filter syntax. | String 以规范过滤语法渲染字面量。
func (l literal) String() string {
	switch l.kind {
	case litNull:
		return "null"
	case litBool:
		if l.boolean {
			return "true"
		}
		return "false"
	case litNumber:
		return l.text
	default:
		return quoteFilterString(l.text)
	}
}

// attributeFilter is a path-operator-value expression. | attributeFilter 是路径-运算符-值表达式。
type attributeFilter struct {
	// path is the attribute path. | path 是属性路径。
	path *AttributePath
	// value is the comparison literal. | value 是比较字面量。
	value literal
	// op is the comparison operator. | op 是比较运算符。
	op compareOp
}

// String returns the canonical text of the expression. | String 返回表达式的规范化文本。
func (f *attributeFilter) String() string {
	return f.path.String() + " " + operatorText(f.op) + " " + f.value.String()
}

// presenceFilter is a path "pr" expression. | presenceFilter 是路径 "pr" 表达式。
type presenceFilter struct {
	// path is the attribute path. | path 是属性路径。
	path *AttributePath
}

// String returns the canonical text of the expression. | String 返回表达式的规范化文本。
func (f *presenceFilter) String() string { return f.path.String() + " pr" }

// logicalFilter combines two filters with and or or. | logicalFilter 用 and 或 or 组合两个过滤器。
type logicalFilter struct {
	// left and right are the operands. | left 与 right 是操作数。
	left  Filter
	right Filter
	// op is "and" or "or". | op 取值为 "and" 或 "or"。
	op string
}

// String returns the canonical text of the expression. Operands with a
// different operator are parenthesized so the text reparses to the same tree. |
// String 返回表达式的规范化文本。运算符不同的操作数会加括号，确保文本重新解析后得到相同
// 语法树。
func (f *logicalFilter) String() string {
	return logicalOperandText(f.left, f.op) + " " + f.op + " " + logicalOperandText(f.right, f.op)
}

// logicalOperandText renders filter and parenthesizes a nested logical filter
// whose operator differs from parentOp. | logicalOperandText 渲染 filter，并在嵌套逻辑
// 过滤器运算符与 parentOp 不同时加括号。
func logicalOperandText(filter Filter, parentOp string) string {
	if filter == nil {
		return ""
	}
	text := filter.String()
	if nested, ok := filter.(*logicalFilter); ok && nested.op != parentOp {
		return "(" + text + ")"
	}
	return text
}

// notFilter negates an inner filter. | notFilter 对内部过滤器取反。
type notFilter struct {
	// inner is the negated filter. | inner 是被取反的过滤器。
	inner Filter
}

// String returns the canonical text of the expression. | String 返回表达式的规范化文本。
func (f *notFilter) String() string { return "not (" + f.inner.String() + ")" }

// ParseFilter parses an RFC 7644 section 3.4.2.2 filter expression. | ParseFilter 解析
// RFC 7644 第 3.4.2.2 节的过滤表达式。
//
// Attribute names, operators and the and / or / not / pr keywords are case-insensitive. The
// returned error always satisfies errors.Is(err, ErrInvalidFilter). | 属性名、运算符以及
// and / or / not / pr 关键字均大小写不敏感。返回的错误始终满足
// errors.Is(err, ErrInvalidFilter)。
func ParseFilter(input string) (Filter, error) {
	if strings.TrimSpace(input) == "" {
		return nil, errs.Detail(ErrInvalidFilter, "empty filter | 空过滤器")
	}
	tokens, err := lexFilter(input)
	if err != nil {
		return nil, err
	}
	p := &filterParser{tokens: tokens}
	filter, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if tok := p.peek(); tok.typ != tokenEOF {
		return nil, errs.Detail(ErrInvalidFilter, "unexpected token %q at offset %d", tok.text, tok.pos)
	}
	return filter, nil
}

// ParseAttributePath parses a standalone SCIM attribute path such as
// emails[type eq "work"].value or urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department.
// | ParseAttributePath 解析独立的 SCIM 属性路径，例如 emails[type eq "work"].value 或
// urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department。
//
// The returned error always satisfies errors.Is(err, ErrInvalidPath). | 返回的错误始终满足
// errors.Is(err, ErrInvalidPath)。
func ParseAttributePath(input string) (*AttributePath, error) {
	if strings.TrimSpace(input) == "" {
		return nil, errs.Detail(ErrInvalidPath, "empty path | 空路径")
	}
	tokens, err := lexFilter(input)
	if err != nil {
		return nil, errs.Detail(ErrInvalidPath, "%s", err.Error())
	}
	p := &filterParser{tokens: tokens}
	path, err := p.parseAttributePath()
	if err != nil {
		return nil, errs.Detail(ErrInvalidPath, "%s", err.Error())
	}
	if tok := p.peek(); tok.typ != tokenEOF {
		return nil, errs.Detail(ErrInvalidPath, "unexpected token %q at offset %d", tok.text, tok.pos)
	}
	return path, nil
}

// tokenType classifies a lexer token. | tokenType 对词法记号分类。
type tokenType uint8

const (
	tokenEOF tokenType = iota
	tokenWord
	tokenString
	tokenLParen
	tokenRParen
	tokenLBracket
	tokenRBracket
	tokenDot
)

// token is one lexer output. | token 是一个词法输出。
type token struct {
	// text is the decoded token text. | text 是解码后的记号文本。
	text string
	// pos is the byte offset in the source. | pos 是源中的字节偏移。
	pos int
	// typ is the token class. | typ 是记号类别。
	typ tokenType
}

// lexFilter splits input into SCIM filter tokens. | lexFilter 把输入切分为 SCIM 过滤记号。
func lexFilter(input string) ([]token, error) {
	tokens := make([]token, 0, 16)
	for i := 0; i < len(input); {
		ch := input[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n':
			i++
		case ch == '(':
			tokens = append(tokens, token{typ: tokenLParen, text: "(", pos: i})
			i++
		case ch == ')':
			tokens = append(tokens, token{typ: tokenRParen, text: ")", pos: i})
			i++
		case ch == '[':
			tokens = append(tokens, token{typ: tokenLBracket, text: "[", pos: i})
			i++
		case ch == ']':
			tokens = append(tokens, token{typ: tokenRBracket, text: "]", pos: i})
			i++
		case ch == '.':
			tokens = append(tokens, token{typ: tokenDot, text: ".", pos: i})
			i++
		case ch == '"':
			text, next, err := readFilterString(input, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{typ: tokenString, text: text, pos: i})
			i = next
		case isFilterWordChar(ch):
			start := i
			hasColon := ch == ':'
			numeric := ch >= '0' && ch <= '9'
			for i < len(input) && isFilterWordChar(input[i]) {
				if input[i] == '.' && !hasColon && !numeric {
					break
				}
				if input[i] == ':' {
					hasColon = true
				}
				i++
			}
			tokens = append(tokens, token{typ: tokenWord, text: input[start:i], pos: start})
		default:
			return nil, errs.Detail(ErrInvalidFilter, "unexpected character %q at offset %d", string(ch), i)
		}
	}
	tokens = append(tokens, token{typ: tokenEOF, pos: len(input)})
	return tokens, nil
}

// isFilterWordChar reports whether ch may appear inside an unquoted token. | isFilterWordChar
// 报告 ch 是否可出现在非引号记号中。
func isFilterWordChar(ch byte) bool {
	switch {
	case ch >= 'a' && ch <= 'z':
		return true
	case ch >= 'A' && ch <= 'Z':
		return true
	case ch >= '0' && ch <= '9':
		return true
	}
	switch ch {
	case '_', '-', '$', ':', '.':
		return true
	}
	return false
}

// readFilterString decodes a double-quoted JSON string starting at start. | readFilterString 解码
// 从 start 开始的双引号 JSON 字符串。
func readFilterString(input string, start int) (string, int, error) {
	var b strings.Builder
	i := start + 1
	for i < len(input) {
		ch := input[i]
		switch ch {
		case '"':
			return b.String(), i + 1, nil
		case '\\':
			if i+1 >= len(input) {
				return "", 0, errs.Detail(ErrInvalidFilter, "unterminated escape at offset %d", i)
			}
			next, err := appendFilterEscape(&b, input, i)
			if err != nil {
				return "", 0, err
			}
			i = next
		default:
			b.WriteByte(ch)
			i++
		}
	}
	return "", 0, errs.Detail(ErrInvalidFilter, "unterminated string at offset %d", start)
}

// appendFilterEscape decodes one backslash escape and appends its value. | appendFilterEscape 解码
// 一个反斜杠转义并追加其值。
func appendFilterEscape(b *strings.Builder, input string, index int) (int, error) {
	ch := input[index+1]
	switch ch {
	case '"':
		b.WriteByte('"')
		return index + 2, nil
	case '\\':
		b.WriteByte('\\')
		return index + 2, nil
	case '/':
		b.WriteByte('/')
		return index + 2, nil
	case 'b':
		b.WriteByte('\b')
		return index + 2, nil
	case 'f':
		b.WriteByte('\f')
		return index + 2, nil
	case 'n':
		b.WriteByte('\n')
		return index + 2, nil
	case 'r':
		b.WriteByte('\r')
		return index + 2, nil
	case 't':
		b.WriteByte('\t')
		return index + 2, nil
	case 'u':
		if index+6 > len(input) {
			return 0, errs.Detail(ErrInvalidFilter, "truncated unicode escape at offset %d", index)
		}
		value, err := strconv.ParseUint(input[index+2:index+6], 16, 32)
		if err != nil {
			return 0, errs.Detail(ErrInvalidFilter, "invalid unicode escape at offset %d", index)
		}
		r := rune(value)
		next := index + 6
		if r >= 0xD800 && r <= 0xDBFF && next+6 <= len(input) && input[next] == '\\' && input[next+1] == 'u' {
			low, lowErr := strconv.ParseUint(input[next+2:next+6], 16, 32)
			if lowErr == nil && low >= 0xDC00 && low <= 0xDFFF {
				r = 0x10000 + (r-0xD800)<<10 + (rune(low) - 0xDC00)
				next += 6
			}
		}
		b.WriteRune(r)
		return next, nil
	}
	return 0, errs.Detail(ErrInvalidFilter, "invalid escape %q at offset %d", string(ch), index)
}

// quoteFilterString renders value as a quoted filter string literal. | quoteFilterString 把 value
// 渲染为带引号的过滤字符串字面量。
func quoteFilterString(value string) string {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// maxFilterDepth bounds recursive filter nesting so hostile filter text cannot
// exhaust the goroutine stack. | maxFilterDepth 限制过滤器递归嵌套深度，避免恶意过滤
// 文本耗尽 goroutine 栈。
const maxFilterDepth = 64

// filterParser is a recursive descent parser over the token stream. | filterParser 是记号流上的
// 递归下降解析器。
type filterParser struct {
	// tokens is the lexer output including the trailing EOF. | tokens 是包含末尾 EOF 的词法输出。
	tokens []token
	// pos is the next token index. | pos 是下一个记号索引。
	pos int
	// depth is the current logical nesting depth. | depth 是当前逻辑嵌套深度。
	depth int
}

// peek returns the current token without consuming it. | peek 返回当前记号但不消费。
func (p *filterParser) peek() token { return p.tokens[p.pos] }

// matchKeyword consumes a word token equal to keyword case-insensitively. | matchKeyword 消费一个
// 与 keyword 大小写不敏感相等的词记号。
func (p *filterParser) matchKeyword(keyword string) bool {
	tok := p.peek()
	if tok.typ == tokenWord && strings.EqualFold(tok.text, keyword) {
		p.pos++
		return true
	}
	return false
}

// expect consumes a token of the requested type. | expect 消费一个指定类型的记号。
func (p *filterParser) expect(typ tokenType, label string) (token, error) {
	tok := p.peek()
	if tok.typ != typ {
		return token{}, errs.Detail(ErrInvalidFilter, "expected %s at offset %d", label, tok.pos)
	}
	p.pos++
	return tok, nil
}

// parseOr parses a sequence of and expressions joined by or. | parseOr 解析用 or 连接的 and
// 表达式序列。
func (p *filterParser) parseOr() (Filter, error) {
	if p.depth >= maxFilterDepth {
		return nil, errs.Detail(ErrInvalidFilter, "filter nesting exceeds %d | 过滤器嵌套超过 %d", maxFilterDepth, maxFilterDepth)
	}
	p.depth++
	defer func() { p.depth-- }()
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.matchKeyword("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &logicalFilter{op: "or", left: left, right: right}
	}
	return left, nil
}

// parseAnd parses a sequence of primary expressions joined by and. | parseAnd 解析用 and 连接的
// 主表达式序列。
func (p *filterParser) parseAnd() (Filter, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.matchKeyword("and") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &logicalFilter{op: "and", left: left, right: right}
	}
	return left, nil
}

// parseNot parses not ( filter ) or delegates to the primary parser. | parseNot 解析
// not ( filter )，否则交给主表达式解析器。
func (p *filterParser) parseNot() (Filter, error) {
	if p.matchKeyword("not") {
		if _, err := p.expect(tokenLParen, "("); err != nil {
			return nil, err
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokenRParen, ")"); err != nil {
			return nil, err
		}
		return &notFilter{inner: inner}, nil
	}
	return p.parsePrimary()
}

// parsePrimary parses a parenthesized expression or an attribute expression. | parsePrimary 解析
// 括号表达式或属性表达式。
func (p *filterParser) parsePrimary() (Filter, error) {
	if p.peek().typ == tokenLParen {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokenRParen, ")"); err != nil {
			return nil, err
		}
		return inner, nil
	}
	return p.parseAttributeExpression()
}

// parseAttributeExpression parses attrPath pr or attrPath compareOp compValue. | parseAttributeExpression
// 解析 attrPath pr 或 attrPath compareOp compValue。
func (p *filterParser) parseAttributeExpression() (Filter, error) {
	path, err := p.parseAttributePath()
	if err != nil {
		return nil, err
	}
	if p.matchKeyword("pr") {
		return &presenceFilter{path: path}, nil
	}
	tok := p.peek()
	if tok.typ != tokenWord {
		return nil, errs.Detail(ErrInvalidFilter, "expected operator at offset %d", tok.pos)
	}
	op, ok := parseOperator(tok.text)
	if !ok {
		return nil, errs.Detail(ErrInvalidFilter, "unknown operator %q at offset %d", tok.text, tok.pos)
	}
	p.pos++
	value, err := p.parseLiteral()
	if err != nil {
		return nil, err
	}
	return &attributeFilter{path: path, op: op, value: value}, nil
}

// parseLiteral parses a comparison value. | parseLiteral 解析比较值。
func (p *filterParser) parseLiteral() (literal, error) {
	tok := p.peek()
	switch tok.typ {
	case tokenString:
		p.pos++
		return literal{kind: litString, text: tok.text}, nil
	case tokenWord:
		p.pos++
		switch {
		case strings.EqualFold(tok.text, "null"):
			return literal{kind: litNull}, nil
		case strings.EqualFold(tok.text, "true"):
			return literal{kind: litBool, boolean: true, text: tok.text}, nil
		case strings.EqualFold(tok.text, "false"):
			return literal{kind: litBool, boolean: false, text: tok.text}, nil
		}
		if number, err := strconv.ParseFloat(tok.text, 64); err == nil {
			return literal{kind: litNumber, number: number, text: tok.text}, nil
		}
		// Unquoted strings are accepted for interoperability even though the RFC requires quotes. |
		// 为互操作性接受非引号字符串，尽管 RFC 要求使用引号。
		return literal{kind: litString, text: tok.text}, nil
	}
	return literal{}, errs.Detail(ErrInvalidFilter, "expected comparison value at offset %d", tok.pos)
}

// parseAttributePath parses an attribute path with optional value filter and sub-attribute. |
// parseAttributePath 解析可带值过滤器与子属性的属性路径。
func (p *filterParser) parseAttributePath() (*AttributePath, error) {
	tok := p.peek()
	if tok.typ != tokenWord {
		return nil, errs.Detail(ErrInvalidFilter, "expected attribute name at offset %d", tok.pos)
	}
	if strings.EqualFold(tok.text, "and") || strings.EqualFold(tok.text, "or") || strings.EqualFold(tok.text, "not") {
		return nil, errs.Detail(ErrInvalidFilter, "unexpected keyword %q at offset %d", tok.text, tok.pos)
	}
	p.pos++
	path := &AttributePath{}
	path.Schema, path.Attribute, path.SubAttribute = splitPathWord(tok.text)
	if path.Attribute == "" && path.Schema == "" {
		return nil, errs.Detail(ErrInvalidFilter, "empty attribute path at offset %d", tok.pos)
	}
	if p.peek().typ == tokenLBracket {
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokenRBracket, "]"); err != nil {
			return nil, err
		}
		path.ValueFilter = inner
	}
	if p.peek().typ == tokenDot {
		p.pos++
		sub, err := p.expect(tokenWord, "sub-attribute name")
		if err != nil {
			return nil, err
		}
		if path.SubAttribute != "" {
			return nil, errs.Detail(ErrInvalidFilter, "duplicate sub-attribute at offset %d", sub.pos)
		}
		path.SubAttribute = sub.text
	}
	return path, nil
}

// splitPathWord splits a lexical path word into schema, attribute and sub-attribute parts. |
// splitPathWord 把词法路径单词拆分为 Schema、属性与子属性部分。
func splitPathWord(word string) (schema, attribute, subAttribute string) {
	for _, urn := range knownSchemaURNs {
		if strings.EqualFold(word, urn) {
			return urn, "", ""
		}
	}
	rest := word
	if index := strings.LastIndexByte(word, ':'); index >= 0 {
		schema = word[:index]
		rest = word[index+1:]
	}
	if index := strings.IndexByte(rest, '.'); index >= 0 {
		return schema, rest[:index], rest[index+1:]
	}
	return schema, rest, ""
}
