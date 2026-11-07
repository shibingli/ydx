package ldap

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Filter is an RFC 4515 search filter. Only the filter types declared in this
// package implement it. | Filter 是 RFC 4515 搜索过滤器，只有本包声明的过滤器类型实现它。
type Filter interface {
	// String renders the filter in RFC 4515 form. | String 以 RFC 4515 形式渲染过滤器。
	String() string
	appendFilter(*berEncoder)
}

// AndFilter is a logical AND. | AndFilter 是逻辑与。
type AndFilter struct {
	// Filters are all required to match. | Filters 必须全部匹配。
	Filters []Filter
}

// OrFilter is a logical OR. | OrFilter 是逻辑或。
type OrFilter struct {
	// Filters are alternatives. | Filters 是任意匹配项。
	Filters []Filter
}

// NotFilter is a logical negation. | NotFilter 是逻辑非。
type NotFilter struct {
	// Filter is the negated child. | Filter 是被否定的子过滤器。
	Filter Filter
}

// EqualityFilter is an equalityMatch assertion. | EqualityFilter 是
// equalityMatch 断言。
type EqualityFilter struct {
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
	// Value is the assertion value. | Value 是断言值。
	Value string
}

// SubstringFilter is a substring assertion. | SubstringFilter 是子串断言。
type SubstringFilter struct {
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
	// Initial is the required prefix, possibly empty. | Initial 是必需前缀，可为空。
	Initial string
	// Any are ordered required infixes. | Any 是顺序必需的中间片段。
	Any []string
	// Final is the required suffix, possibly empty. | Final 是必需后缀，可为空。
	Final string
}

// PresentFilter asserts attribute presence. | PresentFilter 断言属性存在。
type PresentFilter struct {
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
}

// GreaterOrEqualFilter is a greaterOrEqual assertion. | GreaterOrEqualFilter 是
// greaterOrEqual 断言。
type GreaterOrEqualFilter struct {
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
	// Value is the assertion value. | Value 是断言值。
	Value string
}

// LessOrEqualFilter is a lessOrEqual assertion. | LessOrEqualFilter 是
// lessOrEqual 断言。
type LessOrEqualFilter struct {
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
	// Value is the assertion value. | Value 是断言值。
	Value string
}

// ApproxFilter is an approximateMatch assertion. | ApproxFilter 是
// approximateMatch 断言。
type ApproxFilter struct {
	// Attribute is the attribute description. | Attribute 是属性描述。
	Attribute string
	// Value is the assertion value. | Value 是断言值。
	Value string
}

// ExtensibleMatchFilter is an extensibleMatch assertion (RFC 4511 section
// 4.5.1.7). | ExtensibleMatchFilter 是 extensibleMatch 断言（RFC 4511 4.5.1.7 节）。
type ExtensibleMatchFilter struct {
	// MatchingRule optionally names a matching rule. | MatchingRule 可选指定匹配规则。
	MatchingRule string
	// Attribute optionally restricts the assertion to one attribute. | Attribute 可选把断言限制到一个属性。
	Attribute string
	// Value is the assertion value. | Value 是断言值。
	Value string
	// DNAttributes requests matching against DN attributes. | DNAttributes 请求匹配 DN 属性。
	DNAttributes bool
}

// And returns a logical conjunction. At least one child is required by the
// protocol; an empty conjunction is rejected when the request is encoded. | And
// 返回逻辑与。协议要求至少一个子过滤器；空合取会在请求编码时被拒绝。
func And(filters ...Filter) Filter { return &AndFilter{Filters: filters} }

// Or returns a logical disjunction. At least one child is required by the
// protocol; an empty disjunction is rejected when the request is encoded. | Or
// 返回逻辑或。协议要求至少一个子过滤器；空析取会在请求编码时被拒绝。
func Or(filters ...Filter) Filter { return &OrFilter{Filters: filters} }

// Not returns a logical negation. | Not 返回逻辑非。
func Not(filter Filter) Filter { return &NotFilter{Filter: filter} }

// Equality returns an equalityMatch filter. | Equality 返回 equalityMatch 过滤器。
func Equality(attribute, value string) Filter {
	return &EqualityFilter{Attribute: attribute, Value: value}
}

// Equal is an alias for Equality. | Equal 是 Equality 的别名。
func Equal(attribute, value string) Filter { return Equality(attribute, value) }

// Substrings returns a substring filter. Empty Any elements are ignored. | Substrings
// 返回子串过滤器。空的 Any 元素会被忽略。
func Substrings(attribute, initial string, any []string, final string) Filter {
	clean := make([]string, 0, len(any))
	for _, part := range any {
		if part != "" {
			clean = append(clean, part)
		}
	}
	return &SubstringFilter{Attribute: attribute, Initial: initial, Any: clean, Final: final}
}

// Present returns an attribute presence filter. | Present 返回属性存在过滤器。
func Present(attribute string) Filter { return &PresentFilter{Attribute: attribute} }

// GreaterOrEqual returns a greaterOrEqual filter. | GreaterOrEqual 返回
// greaterOrEqual 过滤器。
func GreaterOrEqual(attribute, value string) Filter {
	return &GreaterOrEqualFilter{Attribute: attribute, Value: value}
}

// LessOrEqual returns a lessOrEqual filter. | LessOrEqual 返回 lessOrEqual 过滤器。
func LessOrEqual(attribute, value string) Filter {
	return &LessOrEqualFilter{Attribute: attribute, Value: value}
}

// Approximate returns an approximateMatch filter. | Approximate 返回
// approximateMatch 过滤器。
func Approximate(attribute, value string) Filter {
	return &ApproxFilter{Attribute: attribute, Value: value}
}

// ExtensibleMatch returns an extensibleMatch filter. | ExtensibleMatch 返回
// extensibleMatch 过滤器。
func ExtensibleMatch(matchingRule, attribute, value string, dnAttributes bool) Filter {
	return &ExtensibleMatchFilter{
		MatchingRule: matchingRule,
		Attribute:    attribute,
		Value:        value,
		DNAttributes: dnAttributes,
	}
}

// EscapeFilterValue escapes an assertion value for RFC 4515. It escapes bytes
// outside printable ASCII as hex, so the result does not depend on the input's
// UTF-8 validity. | EscapeFilterValue 为 RFC 4515 转义断言值。它把可打印 ASCII 之外的
// 字节编码为十六进制，因此结果不依赖输入的 UTF-8 合法性。
func EscapeFilterValue(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == 0x00 || c == '(' || c == ')' || c == '*' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		case c < 0x20 || c >= 0x7f:
			b.WriteByte('\\')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// String renders an RFC 4515 conjunction. | String 渲染 RFC 4515 合取。
func (f *AndFilter) String() string {
	var b strings.Builder
	b.WriteString("(&")
	if f != nil {
		for _, child := range f.Filters {
			if child == nil {
				continue
			}
			b.WriteString(child.String())
		}
	}
	b.WriteByte(')')
	return b.String()
}

// String renders an RFC 4515 disjunction. | String 渲染 RFC 4515 析取。
func (f *OrFilter) String() string {
	var b strings.Builder
	b.WriteString("(|")
	if f != nil {
		for _, child := range f.Filters {
			if child == nil {
				continue
			}
			b.WriteString(child.String())
		}
	}
	b.WriteByte(')')
	return b.String()
}

// String renders an RFC 4515 negation. | String 渲染 RFC 4515 否定。
func (f *NotFilter) String() string {
	if f == nil || f.Filter == nil {
		return "(!)"
	}
	return "(!" + f.Filter.String() + ")"
}

// String renders an RFC 4515 equality assertion. | String 渲染 RFC 4515 相等断言。
func (f *EqualityFilter) String() string {
	if f == nil {
		return "(=)"
	}
	return "(" + f.Attribute + "=" + EscapeFilterValue(f.Value) + ")"
}

// String renders an RFC 4515 substring assertion. | String 渲染 RFC 4515 子串断言。
func (f *SubstringFilter) String() string {
	if f == nil {
		return "(=)"
	}
	var b strings.Builder
	b.WriteByte('(')
	b.WriteString(f.Attribute)
	b.WriteByte('=')
	b.WriteString(EscapeFilterValue(f.Initial))
	for _, part := range f.Any {
		b.WriteByte('*')
		b.WriteString(EscapeFilterValue(part))
	}
	b.WriteByte('*')
	b.WriteString(EscapeFilterValue(f.Final))
	b.WriteByte(')')
	return b.String()
}

// String renders an RFC 4515 presence assertion. | String 渲染 RFC 4515 存在断言。
func (f *PresentFilter) String() string {
	if f == nil {
		return "(=*)"
	}
	return "(" + f.Attribute + "=*)"
}

// String renders an RFC 4515 greaterOrEqual assertion. | String 渲染 RFC 4515
// greaterOrEqual 断言。
func (f *GreaterOrEqualFilter) String() string {
	if f == nil {
		return "(>=)"
	}
	return "(" + f.Attribute + ">=" + EscapeFilterValue(f.Value) + ")"
}

// String renders an RFC 4515 lessOrEqual assertion. | String 渲染 RFC 4515
// lessOrEqual 断言。
func (f *LessOrEqualFilter) String() string {
	if f == nil {
		return "(<=)"
	}
	return "(" + f.Attribute + "<=" + EscapeFilterValue(f.Value) + ")"
}

// String renders an RFC 4515 approximate assertion. | String 渲染 RFC 4515 近似断言。
func (f *ApproxFilter) String() string {
	if f == nil {
		return "(~=)"
	}
	return "(" + f.Attribute + "~=" + EscapeFilterValue(f.Value) + ")"
}

// String renders an RFC 4515 extensible assertion. | String 渲染 RFC 4515 扩展断言。
func (f *ExtensibleMatchFilter) String() string {
	if f == nil {
		return "(:=)"
	}
	var b strings.Builder
	b.WriteByte('(')
	b.WriteString(f.Attribute)
	if f.DNAttributes {
		b.WriteString(":dn")
	}
	if f.MatchingRule != "" {
		b.WriteByte(':')
		b.WriteString(f.MatchingRule)
	}
	b.WriteString(":=")
	b.WriteString(EscapeFilterValue(f.Value))
	b.WriteByte(')')
	return b.String()
}

// appendFilter appends the BER encoding of a conjunction. | appendFilter 追加合取的 BER 编码。
func (f *AndFilter) appendFilter(e *berEncoder) {
	e.open(berClassContext, 0)
	if f != nil {
		for _, child := range f.Filters {
			encodeFilter(e, child)
		}
	}
	e.close()
}

// appendFilter appends the BER encoding of a disjunction. | appendFilter 追加析取的 BER 编码。
func (f *OrFilter) appendFilter(e *berEncoder) {
	e.open(berClassContext, 1)
	if f != nil {
		for _, child := range f.Filters {
			encodeFilter(e, child)
		}
	}
	e.close()
}

// appendFilter appends the BER encoding of a negation. | appendFilter 追加否定的 BER 编码。
func (f *NotFilter) appendFilter(e *berEncoder) {
	e.open(berClassContext, 2)
	if f != nil {
		encodeFilter(e, f.Filter)
	}
	e.close()
}

// appendFilter appends an equality assertion. | appendFilter 追加相等断言。
func (f *EqualityFilter) appendFilter(e *berEncoder) {
	attribute, value := "", ""
	if f != nil {
		attribute, value = f.Attribute, f.Value
	}
	e.open(berClassContext, 3)
	e.text(attribute)
	e.text(value)
	e.close()
}

// appendFilter appends a substring assertion. | appendFilter 追加子串断言。
func (f *SubstringFilter) appendFilter(e *berEncoder) {
	attribute := ""
	var initial, final string
	var any []string
	if f != nil {
		attribute, initial, final, any = f.Attribute, f.Initial, f.Final, f.Any
	}
	e.open(berClassContext, 4)
	e.text(attribute)
	e.open(berClassUniversal, berTagSequence)
	if initial != "" {
		e.primitive(berClassContext, 0, []byte(initial))
	}
	for _, part := range any {
		if part != "" {
			e.primitive(berClassContext, 1, []byte(part))
		}
	}
	if final != "" {
		e.primitive(berClassContext, 2, []byte(final))
	}
	e.close()
	e.close()
}

// appendFilter appends a presence assertion. | appendFilter 追加存在断言。
func (f *PresentFilter) appendFilter(e *berEncoder) {
	attribute := ""
	if f != nil {
		attribute = f.Attribute
	}
	e.primitive(berClassContext, 7, []byte(attribute))
}

// appendFilter appends a greaterOrEqual assertion. | appendFilter 追加 greaterOrEqual 断言。
func (f *GreaterOrEqualFilter) appendFilter(e *berEncoder) {
	attribute, value := "", ""
	if f != nil {
		attribute, value = f.Attribute, f.Value
	}
	appendFilterAssertion(e, 5, attribute, value)
}

// appendFilter appends a lessOrEqual assertion. | appendFilter 追加 lessOrEqual 断言。
func (f *LessOrEqualFilter) appendFilter(e *berEncoder) {
	attribute, value := "", ""
	if f != nil {
		attribute, value = f.Attribute, f.Value
	}
	appendFilterAssertion(e, 6, attribute, value)
}

// appendFilter appends an approximate assertion. | appendFilter 追加近似断言。
func (f *ApproxFilter) appendFilter(e *berEncoder) {
	attribute, value := "", ""
	if f != nil {
		attribute, value = f.Attribute, f.Value
	}
	appendFilterAssertion(e, 8, attribute, value)
}

// appendFilter appends an extensible assertion. | appendFilter 追加扩展断言。
func (f *ExtensibleMatchFilter) appendFilter(e *berEncoder) {
	var (
		rule, attribute, value string
		dnAttributes           bool
	)
	if f != nil {
		rule, attribute, value, dnAttributes = f.MatchingRule, f.Attribute, f.Value, f.DNAttributes
	}
	e.open(berClassContext, 9)
	if rule != "" {
		e.primitive(berClassContext, 1, []byte(rule))
	}
	if attribute != "" {
		e.primitive(berClassContext, 2, []byte(attribute))
	}
	e.primitive(berClassContext, 3, []byte(value))
	if dnAttributes {
		e.open(berClassContext, 4)
		e.boolean(true)
		e.close()
	}
	e.close()
}

// appendFilterAssertion appends a context-specific AttributeValueAssertion. | appendFilterAssertion
// 追加上下文相关的 AttributeValueAssertion。
func appendFilterAssertion(e *berEncoder, tag uint32, attribute, value string) {
	e.open(berClassContext, tag)
	e.text(attribute)
	e.text(value)
	e.close()
}

// encodeFilter appends one filter, ignoring nil children only at the top level
// of invalid constructors. | encodeFilter 追加一个过滤器；仅在非法构造器的顶层忽略
// nil 子项。
func encodeFilter(e *berEncoder, filter Filter) {
	if filter == nil {
		e.open(berClassContext, 0)
		e.close()
		return
	}
	filter.appendFilter(e)
}

// ValidateFilter checks protocol constraints that constructors cannot report.
// | ValidateFilter 检查构造器无法报告的协议约束。
func ValidateFilter(filter Filter) error {
	if filter == nil {
		return errs.Detail(ErrInvalidFilter, "filter is nil | 过滤器为空")
	}
	switch f := filter.(type) {
	case *AndFilter:
		if len(f.Filters) == 0 {
			return errs.Detail(ErrInvalidFilter, "and filter has no children | and 过滤器没有子项")
		}
		for _, child := range f.Filters {
			if err := ValidateFilter(child); err != nil {
				return err
			}
		}
	case *OrFilter:
		if len(f.Filters) == 0 {
			return errs.Detail(ErrInvalidFilter, "or filter has no children | or 过滤器没有子项")
		}
		for _, child := range f.Filters {
			if err := ValidateFilter(child); err != nil {
				return err
			}
		}
	case *NotFilter:
		if f.Filter == nil {
			return errs.Detail(ErrInvalidFilter, "not filter has no child | not 过滤器没有子项")
		}
		return ValidateFilter(f.Filter)
	case *EqualityFilter:
		return validateFilterAttribute(f.Attribute)
	case *SubstringFilter:
		if err := validateFilterAttribute(f.Attribute); err != nil {
			return err
		}
		if f.Initial == "" && f.Final == "" && len(f.Any) == 0 {
			return errs.Detail(ErrInvalidFilter, "substring filter has no component | 子串过滤器没有组成部分")
		}
		for _, part := range f.Any {
			if part == "" {
				return errs.Detail(ErrInvalidFilter, "substring any component is empty | 子串中间片段为空")
			}
		}
	case *PresentFilter:
		return validateFilterAttribute(f.Attribute)
	case *GreaterOrEqualFilter:
		return validateFilterAttribute(f.Attribute)
	case *LessOrEqualFilter:
		return validateFilterAttribute(f.Attribute)
	case *ApproxFilter:
		return validateFilterAttribute(f.Attribute)
	case *ExtensibleMatchFilter:
		if f.Attribute == "" && f.MatchingRule == "" {
			return errs.Detail(ErrInvalidFilter, "extensible match needs an attribute or matching rule | 扩展匹配需要属性或匹配规则")
		}
		if f.Attribute != "" {
			if err := validateFilterAttribute(f.Attribute); err != nil {
				return err
			}
		}
		if strings.TrimSpace(f.MatchingRule) == "" && f.MatchingRule != "" {
			return errs.Detail(ErrInvalidFilter, "matching rule is blank | 匹配规则为空白")
		}
	default:
		return errs.Detail(ErrInvalidFilter, "unknown filter type %T | 未知过滤器类型 %T", filter, filter)
	}
	return nil
}

// validateFilterAttribute validates an attribute description conservatively.
// | validateFilterAttribute 保守校验属性描述。
func validateFilterAttribute(attribute string) error {
	if attribute == "" {
		return errs.Detail(ErrInvalidFilter, "attribute description is empty | 属性描述为空")
	}
	for i := 0; i < len(attribute); i++ {
		c := attribute[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == ';' || c == '_':
		default:
			return errs.Detail(ErrInvalidFilter, "attribute description contains byte 0x%02x | 属性描述包含字节 0x%02x", c, c)
		}
	}
	return nil
}

// maxFilterDepth bounds recursive filter nesting so hostile filter text cannot
// exhaust the goroutine stack. | maxFilterDepth 限制过滤器递归嵌套深度，避免恶意过滤
// 文本耗尽 goroutine 栈。
const maxFilterDepth = 64

// filterParser parses RFC 4515 filter text. | filterParser 解析 RFC 4515 过滤器文本。
type filterParser struct {
	input string
	pos   int
	depth int
}

// ParseFilter parses an RFC 4515 search filter. | ParseFilter 解析 RFC 4515 搜索过滤器。
func ParseFilter(input string) (Filter, error) {
	p := &filterParser{input: strings.TrimSpace(input)}
	if p.input == "" {
		return nil, errs.Detail(ErrInvalidFilter, "empty filter | 过滤器为空")
	}
	filter, err := p.parse()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.input) {
		return nil, p.errorf("trailing data | 尾随数据")
	}
	if err := ValidateFilter(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

// parse parses one parenthesized filter. | parse 解析一个带括号过滤器。
func (p *filterParser) parse() (Filter, error) {
	if p.depth >= maxFilterDepth {
		return nil, errs.Detail(ErrInvalidFilter, "at byte %d: filter nesting exceeds %d | 位置 %d：过滤器嵌套超过 %d", p.pos, maxFilterDepth, p.pos, maxFilterDepth)
	}
	p.depth++
	defer func() { p.depth-- }()
	if !p.consume('(') {
		return nil, p.errorf("expected '(' | 期望 '('")
	}
	if p.pos >= len(p.input) {
		return nil, p.errorf("unexpected end of filter | 过滤器意外结束")
	}
	var (
		filter Filter
		err    error
	)
	switch p.input[p.pos] {
	case '&':
		p.pos++
		filter, err = p.parseFilterList(true)
	case '|':
		p.pos++
		filter, err = p.parseFilterList(false)
	case '!':
		p.pos++
		child, childErr := p.parse()
		if childErr != nil {
			return nil, childErr
		}
		filter = &NotFilter{Filter: child}
	case ')':
		return nil, p.errorf("empty filter component | 过滤器组分为空")
	default:
		filter, err = p.parseItem()
	}
	if err != nil {
		return nil, err
	}
	if !p.consume(')') {
		return nil, p.errorf("expected ')' | 期望 ')'")
	}
	return filter, nil
}

// parseFilterList parses a non-empty conjunction or disjunction. | parseFilterList
// 解析非空合取或析取。
func (p *filterParser) parseFilterList(and bool) (Filter, error) {
	var children []Filter
	for p.pos < len(p.input) && p.input[p.pos] != ')' {
		child, err := p.parse()
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if len(children) == 0 {
		return nil, p.errorf("empty filter list | 过滤器列表为空")
	}
	if and {
		return &AndFilter{Filters: children}, nil
	}
	return &OrFilter{Filters: children}, nil
}

// parseItem parses an item filter. | parseItem 解析项过滤器。
func (p *filterParser) parseItem() (Filter, error) {
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == '=' || c == '~' || c == '>' || c == '<' || c == ':' || c == ')' {
			break
		}
		p.pos++
	}
	attribute := p.input[start:p.pos]
	if attribute != "" {
		if err := validateFilterAttribute(attribute); err != nil {
			return nil, p.errorf("%v", err)
		}
	}
	if p.pos >= len(p.input) {
		return nil, p.errorf("unexpected end of item | 项意外结束")
	}
	if p.input[p.pos] == ':' {
		return p.parseExtensible(attribute)
	}
	if p.pos+1 >= len(p.input) {
		return nil, p.errorf("truncated item operator | 项操作符被截断")
	}
	op := p.input[p.pos : p.pos+2]
	if attribute == "" {
		return nil, p.errorf("missing attribute description | 缺少属性描述")
	}
	switch op {
	case "~=":
		p.pos += 2
		value, err := p.parseAssertionValue(false)
		if err != nil {
			return nil, err
		}
		return &ApproxFilter{Attribute: attribute, Value: value}, nil
	case ">=":
		p.pos += 2
		value, err := p.parseAssertionValue(false)
		if err != nil {
			return nil, err
		}
		return &GreaterOrEqualFilter{Attribute: attribute, Value: value}, nil
	case "<=":
		p.pos += 2
		value, err := p.parseAssertionValue(false)
		if err != nil {
			return nil, err
		}
		return &LessOrEqualFilter{Attribute: attribute, Value: value}, nil
	case ":=":
		return p.parseExtensible(attribute)
	}
	if p.input[p.pos] != '=' {
		return nil, p.errorf("invalid filter operator | 非法过滤器操作符")
	}
	p.pos++
	segments, stars, err := p.parseSubstringSegments()
	if err != nil {
		return nil, err
	}
	if !stars {
		return &EqualityFilter{Attribute: attribute, Value: segments[0]}, nil
	}
	if len(segments) == 2 && segments[0] == "" && segments[1] == "" {
		return &PresentFilter{Attribute: attribute}, nil
	}
	initial := segments[0]
	final := segments[len(segments)-1]
	any := segments[1 : len(segments)-1]
	for _, part := range any {
		if part == "" {
			return nil, p.errorf("empty substring component | 空子串片段")
		}
	}
	return &SubstringFilter{Attribute: attribute, Initial: initial, Any: any, Final: final}, nil
}

// parseExtensible parses the context-specific portion of an extensible match.
// | parseExtensible 解析扩展匹配的上下文相关部分。
func (p *filterParser) parseExtensible(attribute string) (Filter, error) {
	filter := &ExtensibleMatchFilter{Attribute: attribute}
	seenRule := false
	for {
		if !p.consume(':') {
			return nil, p.errorf("expected ':' in extensible match | 扩展匹配中期望 ':'")
		}
		if p.consume('=') {
			break
		}
		start := p.pos
		for p.pos < len(p.input) {
			c := p.input[p.pos]
			if c == ':' || c == '=' || c == ')' || c == '(' || c == '*' || c == '\\' {
				break
			}
			p.pos++
		}
		token := p.input[start:p.pos]
		if token == "" {
			return nil, p.errorf("empty extensible token | 扩展匹配标记为空")
		}
		if p.pos >= len(p.input) || p.input[p.pos] != ':' {
			return nil, p.errorf("expected ':=' | 期望 ':='")
		}
		if strings.EqualFold(token, "dn") {
			if filter.DNAttributes {
				return nil, p.errorf("duplicate :dn | 重复的 :dn")
			}
			filter.DNAttributes = true
			continue
		}
		if seenRule {
			return nil, p.errorf("duplicate matching rule | 重复的匹配规则")
		}
		filter.MatchingRule = token
		seenRule = true
	}
	if filter.Attribute == "" && filter.MatchingRule == "" {
		return nil, p.errorf("extensible match needs an attribute or matching rule | 扩展匹配需要属性或匹配规则")
	}
	value, err := p.parseAssertionValue(false)
	if err != nil {
		return nil, err
	}
	filter.Value = value
	return filter, nil
}

// parseSubstringSegments reads an equality/substring value split at unescaped
// asterisks. The returned bool reports whether any split occurred. | parseSubstringSegments
// 读取在未转义星号处切分的相等/子串值。返回的布尔值表示是否存在切分。
func (p *filterParser) parseSubstringSegments() ([]string, bool, error) {
	var (
		segments []string
		current  strings.Builder
		stars    bool
	)
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		switch c {
		case ')':
			segments = append(segments, current.String())
			return segments, stars, nil
		case '*':
			stars = true
			segments = append(segments, current.String())
			current.Reset()
			p.pos++
		case '\\':
			decoded, err := p.parseEscape()
			if err != nil {
				return nil, false, err
			}
			current.WriteByte(decoded)
		case 0x00:
			return nil, false, p.errorf("unescaped NUL | 未转义的 NUL")
		case '(':
			return nil, false, p.errorf("unescaped '(' | 未转义的 '('")
		default:
			current.WriteByte(c)
			p.pos++
		}
	}
	return nil, false, p.errorf("unterminated filter value | 过滤器值未结束")
}

// parseAssertionValue reads a simple assertion value. | parseAssertionValue
// 读取简单断言值。
func (p *filterParser) parseAssertionValue(allowStar bool) (string, error) {
	var b strings.Builder
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		switch c {
		case ')':
			return b.String(), nil
		case '\\':
			decoded, err := p.parseEscape()
			if err != nil {
				return "", err
			}
			b.WriteByte(decoded)
		case 0x00:
			return "", p.errorf("unescaped NUL | 未转义的 NUL")
		case '(':
			return "", p.errorf("unescaped '(' | 未转义的 '('")
		case '*':
			if !allowStar {
				return "", p.errorf("unescaped '*' in assertion value | 断言值中未转义的 '*'")
			}
			b.WriteByte(c)
			p.pos++
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return "", p.errorf("unterminated assertion value | 断言值未结束")
}

// parseEscape decodes one RFC 4515 backslash escape. | parseEscape 解码一个
// RFC 4515 反斜杠转义。
func (p *filterParser) parseEscape() (byte, error) {
	if p.pos+2 >= len(p.input) {
		return 0, p.errorf("truncated escape | 转义被截断")
	}
	hi, ok := hexDigit(p.input[p.pos+1])
	if !ok {
		return 0, p.errorf("invalid escape hex digit | 转义十六进制位非法")
	}
	lo, ok := hexDigit(p.input[p.pos+2])
	if !ok {
		return 0, p.errorf("invalid escape hex digit | 转义十六进制位非法")
	}
	p.pos += 3
	return hi<<4 | lo, nil
}

// hexDigit decodes one hexadecimal digit. | hexDigit 解码一个十六进制位。
func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// consume advances past c when it is next. | consume 在下一个字符为 c 时前进。
func (p *filterParser) consume(c byte) bool {
	if p.pos < len(p.input) && p.input[p.pos] == c {
		p.pos++
		return true
	}
	return false
}

// errorf builds a positioned filter error. | errorf 构造带位置的过滤器错误。
func (p *filterParser) errorf(format string, args ...any) error {
	return errs.Detail(ErrInvalidFilter, "at byte %d: "+format+" | 位置 %d："+format, append([]any{p.pos}, append(args, p.pos)...)...)
}
