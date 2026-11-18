package client

import "strings"

// inlineParamSlots is the number of captures stored without a slice allocation. | inlineParamSlots 是无切片分配可存放的捕获数。
const inlineParamSlots = 8

// maxMatchSteps bounds segment backtracking for one match. | maxMatchSteps 限制单次匹配的段内回溯步数。
const maxMatchSteps = 10000

// Param is one captured path parameter. | Param 是一个路径参数捕获。
type Param struct {
	// Key is the parameter name. | Key 是参数名。
	Key string
	// Value is the captured value. | Value 是捕获值。
	Value string
}

// Params is a small ordered parameter set with inline storage. | Params 是带内联存储的小型有序参数集合。
type Params struct {
	inline [inlineParamSlots]Param
	extra  []Param
	n      int
}

// capture is an internal key/value pair produced by segment matching. | capture 是段匹配产生的内部键值对。
type capture struct {
	key   string
	value string
}

// Append adds a parameter. | Append 添加一个参数。
func (p *Params) Append(key, value string) {
	if p.n < inlineParamSlots {
		p.inline[p.n] = Param{Key: key, Value: value}
	} else {
		p.extra = append(p.extra, Param{Key: key, Value: value})
	}
	p.n++
}

// Len returns the number of parameters. | Len 返回参数数量。
func (p *Params) Len() int {
	if p == nil {
		return 0
	}
	return p.n
}

// Get returns the value for key, or the empty string. | Get 返回 key 的值，不存在时返回空字符串。
func (p *Params) Get(key string) string {
	if p == nil {
		return ""
	}
	for i := 0; i < p.n; i++ {
		param := p.at(i)
		if param.Key == key {
			return param.Value
		}
	}
	return ""
}

// Has reports whether key exists. | Has 报告 key 是否存在。
func (p *Params) Has(key string) bool {
	if p == nil {
		return false
	}
	for i := 0; i < p.n; i++ {
		if p.at(i).Key == key {
			return true
		}
	}
	return false
}

// Each calls fn for every parameter in order. | Each 按顺序对每个参数调用 fn。
func (p *Params) Each(fn func(key, value string)) {
	if p == nil || fn == nil {
		return
	}
	for i := 0; i < p.n; i++ {
		param := p.at(i)
		fn(param.Key, param.Value)
	}
}

// Keys returns all parameter names in order. | Keys 按顺序返回全部参数名。
func (p *Params) Keys() []string {
	if p == nil || p.n == 0 {
		return nil
	}
	out := make([]string, p.n)
	for i := 0; i < p.n; i++ {
		out[i] = p.at(i).Key
	}
	return out
}

// Values returns all parameter values in order. | Values 按顺序返回全部参数值。
func (p *Params) Values() []string {
	if p == nil || p.n == 0 {
		return nil
	}
	out := make([]string, p.n)
	for i := 0; i < p.n; i++ {
		out[i] = p.at(i).Value
	}
	return out
}

// Truncate keeps the first n parameters. | Truncate 保留前 n 个参数。
func (p *Params) Truncate(n int) {
	if p == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	if n >= p.n {
		return
	}
	for i := n; i < p.n; i++ {
		*p.at(i) = Param{}
	}
	if n <= inlineParamSlots {
		p.extra = p.extra[:0]
	} else {
		p.extra = p.extra[:n-inlineParamSlots]
	}
	p.n = n
}

// Reset clears every parameter. | Reset 清空全部参数。
func (p *Params) Reset() {
	if p == nil {
		return
	}
	for i := 0; i < inlineParamSlots; i++ {
		p.inline[i] = Param{}
	}
	p.extra = nil
	p.n = 0
}

// at returns the parameter at index i. | at 返回索引 i 处的参数。
func (p *Params) at(i int) *Param {
	if i < inlineParamSlots {
		return &p.inline[i]
	}
	return &p.extra[i-inlineParamSlots]
}

// appendCaptures appends internal captures to a Params value. | appendCaptures 把内部捕获追加到 Params。
func appendCaptures(params *Params, captures []capture) {
	for _, item := range captures {
		params.Append(item.key, item.value)
	}
}

// matchSegment matches one compiled segment against a path segment. | matchSegment 用一个已编译段匹配路径段。
func matchSegment(seg segment, subject string) ([]capture, bool) {
	if seg.trailing {
		return nil, subject == ""
	}
	if len(seg.tokens) == 0 {
		return nil, subject == ""
	}
	steps := 0
	return matchTokens(seg.tokens, subject, 0, 0, nil, &steps)
}

// matchTokens runs token-level backtracking over one segment. | matchTokens 在单个段内执行词法级回溯匹配。
func matchTokens(tokens []token, subject string, ti, si int, captures []capture, steps *int) ([]capture, bool) {
	*steps++
	if *steps > maxMatchSteps {
		return nil, false
	}
	if ti == len(tokens) {
		return captures, si == len(subject)
	}
	tok := tokens[ti]
	switch tok.kind {
	case tokenLiteral:
		if !strings.HasPrefix(subject[si:], tok.text) {
			return nil, false
		}
		return matchTokens(tokens, subject, ti+1, si+len(tok.text), captures, steps)
	case tokenParam:
		maxLen := len(subject) - si
		for length := 1; length <= maxLen; length++ {
			candidate := subject[si : si+length]
			if tok.regex != nil && !fullMatch(tok.regex, candidate) {
				continue
			}
			next := append(captures, capture{key: tok.text, value: candidate})
			if out, ok := matchTokens(tokens, subject, ti+1, si+length, next, steps); ok {
				return out, true
			}
		}
	case tokenGlob:
		maxLen := len(subject) - si
		for length := 0; length <= maxLen; length++ {
			if out, ok := matchTokens(tokens, subject, ti+1, si+length, captures, steps); ok {
				return out, true
			}
		}
	}
	return nil, false
}
