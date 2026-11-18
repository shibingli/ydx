package client

import (
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/regexpx"
)

// tokenKind distinguishes the match units inside one path segment. | tokenKind 区分单段内的匹配单元。
type tokenKind uint8

const (
	tokenLiteral tokenKind = iota
	tokenParam
	tokenGlob
)

// token is one literal, parameter or glob inside a segment. | token 是段内的一个字面量、参数或通配符。
type token struct {
	regex *regexpx.Regexp
	text  string
	kind  tokenKind
}

// segment is one compiled path segment. | segment 是一个已编译的路径段。
type segment struct {
	raw       string
	catchName string
	tokens    []token
	catchAll  bool
	trailing  bool
}

// Pattern is a compiled path pattern. | Pattern 是已编译的路径模式。
type Pattern struct {
	raw      string
	segments []segment
	names    []string
}

// CompilePattern parses and compiles a path pattern. | CompilePattern 解析并编译路径模式。
func CompilePattern(pattern string) (*Pattern, error) {
	if pattern == "" || pattern[0] != '/' {
		return nil, errs.Detail(ErrBadPattern, "%q must start with / | %q 必须以 / 开头", pattern, pattern)
	}
	p := &Pattern{raw: pattern}
	if pattern == "/" {
		return p, nil
	}
	raws := strings.Split(pattern[1:], "/")
	seen := make(map[string]struct{}, 4)
	for i, raw := range raws {
		if raw == "" {
			if i != len(raws)-1 {
				return nil, errs.Detail(ErrBadPattern, "%q contains an empty segment | %q 含空段", pattern, pattern)
			}
			p.segments = append(p.segments, segment{trailing: true})
			continue
		}
		last := i == len(raws)-1
		seg, err := compileSegment(raw, last, seen)
		if err != nil {
			return nil, err
		}
		p.segments = append(p.segments, seg)
	}
	for name := range seen {
		p.names = append(p.names, name)
	}
	return p, nil
}

// compileSegment parses one segment, registering parameter names in seen. | compileSegment 解析单个段，并把参数名登记到 seen。
func compileSegment(raw string, last bool, seen map[string]struct{}) (segment, error) {
	seg := segment{raw: raw}
	if raw == "*" || raw == "**" {
		if !last {
			return seg, errs.Detail(ErrWildcardPosition, "%q must be the last segment | %q 必须是最后一段", raw, raw)
		}
		seg.catchAll = true
		seg.catchName = "path"
		return seg, registerName(seen, seg.catchName)
	}
	if strings.HasPrefix(raw, "*") && last && isIdent(raw[1:]) {
		seg.catchAll = true
		seg.catchName = raw[1:]
		return seg, registerName(seen, seg.catchName)
	}
	if strings.HasPrefix(raw, "*") && isIdent(raw[1:]) {
		return seg, errs.Detail(ErrWildcardPosition, "%q must be the last segment | %q 必须是最后一段", raw, raw)
	}

	var literal strings.Builder
	flush := func() {
		if literal.Len() == 0 {
			return
		}
		seg.tokens = append(seg.tokens, token{kind: tokenLiteral, text: literal.String()})
		literal.Reset()
	}
	for i := 0; i < len(raw); {
		switch raw[i] {
		case '\\':
			if i+1 >= len(raw) {
				return seg, errs.Detail(ErrDanglingEscape, "%q", raw)
			}
			next := raw[i+1]
			switch next {
			case ':', '{', '}', '*', '\\':
				literal.WriteByte(next)
			default:
				return seg, errs.Detail(ErrEscapeSequence, "\\%c in %q", next, raw)
			}
			i += 2
		case ':':
			flush()
			name, next, err := scanParamName(raw, i+1)
			if err != nil {
				return seg, err
			}
			tok := token{kind: tokenParam, text: name}
			if next < len(raw) && raw[next] == '(' {
				expr, after, err := scanParenRegex(raw, next)
				if err != nil {
					return seg, err
				}
				re, err := regexpx.Compile(expr)
				if err != nil {
					return seg, errs.WrapDetail(err, ErrBadPattern, "regex %q in %q", expr, raw)
				}
				tok.regex = re
				next = after
			}
			if err := registerName(seen, name); err != nil {
				return seg, err
			}
			seg.tokens = append(seg.tokens, tok)
			i = next
		case '{':
			flush()
			name, expr, next, err := scanBraceParam(raw, i+1)
			if err != nil {
				return seg, err
			}
			tok := token{kind: tokenParam, text: name}
			if expr != "" {
				re, err := regexpx.Compile(expr)
				if err != nil {
					return seg, errs.WrapDetail(err, ErrBadPattern, "regex %q in %q", expr, raw)
				}
				tok.regex = re
			}
			if err := registerName(seen, name); err != nil {
				return seg, err
			}
			seg.tokens = append(seg.tokens, tok)
			i = next
		case '*':
			flush()
			seg.tokens = append(seg.tokens, token{kind: tokenGlob, text: "*"})
			i++
		default:
			literal.WriteByte(raw[i])
			i++
		}
	}
	flush()
	if len(seg.tokens) == 0 {
		seg.tokens = nil
	}
	return seg, nil
}

// scanParamName reads an identifier after ':'. | scanParamName 读取 ':' 后的标识符。
func scanParamName(raw string, start int) (string, int, error) {
	i := start
	if i >= len(raw) || !isIdentStart(raw[i]) {
		return "", 0, errs.Detail(ErrParamName, "%q", raw)
	}
	i++
	for i < len(raw) && isIdentPart(raw[i]) {
		i++
	}
	return raw[start:i], i, nil
}

// scanBraceParam parses {name} or {name:regex} starting after '{'. | scanBraceParam 解析 '{' 之后的 {name} 或 {name:regex}。
func scanBraceParam(raw string, start int) (name, expr string, next int, err error) {
	i := start
	if i >= len(raw) || !isIdentStart(raw[i]) {
		return "", "", 0, errs.Detail(ErrParamName, "%q", raw)
	}
	i++
	for i < len(raw) && isIdentPart(raw[i]) {
		i++
	}
	name = raw[start:i]
	if i >= len(raw) {
		return "", "", 0, errs.Detail(ErrBadPattern, "unterminated parameter in %q | %q 中参数未闭合", raw, raw)
	}
	if raw[i] == '}' {
		return name, "", i + 1, nil
	}
	if raw[i] != ':' {
		return "", "", 0, errs.Detail(ErrBadPattern, "unexpected %q in %q", raw[i], raw)
	}
	expr, next, err = scanBraceRegex(raw, i+1)
	if err != nil {
		return "", "", 0, err
	}
	return name, expr, next, nil
}

// scanParenRegex reads a parenthesized regex, balancing nested parentheses. | scanParenRegex 读取括号正则并平衡嵌套括号。
func scanParenRegex(raw string, start int) (string, int, error) {
	return scanRegex(raw, start+1, '(', ')')
}

// scanBraceRegex reads a braced regex, balancing nested braces. | scanBraceRegex 读取花括号正则并平衡嵌套花括号。
func scanBraceRegex(raw string, start int) (string, int, error) {
	return scanRegex(raw, start, '{', '}')
}

// scanRegex reads until the matching close delimiter. | scanRegex 读取到匹配的结束分隔符。
func scanRegex(raw string, start int, open, close byte) (string, int, error) {
	depth := 1
	var expr strings.Builder
	for i := start; i < len(raw); i++ {
		ch := raw[i]
		if ch == '\\' {
			expr.WriteByte(ch)
			if i+1 < len(raw) {
				expr.WriteByte(raw[i+1])
				i++
			}
			continue
		}
		switch ch {
		case open:
			depth++
			expr.WriteByte(ch)
		case close:
			depth--
			if depth == 0 {
				if expr.Len() == 0 {
					return "", 0, errs.Detail(ErrBadPattern, "empty regex in %q | %q 中正则为空", raw, raw)
				}
				return expr.String(), i + 1, nil
			}
			expr.WriteByte(ch)
		default:
			expr.WriteByte(ch)
		}
	}
	return "", 0, errs.Detail(ErrBadPattern, "unterminated regex in %q | %q 中正则未闭合", raw, raw)
}

// registerName records a parameter name and rejects duplicates. | registerName 记录参数名并拒绝重复。
func registerName(seen map[string]struct{}, name string) error {
	if _, ok := seen[name]; ok {
		return errs.Detail(ErrDuplicateParam, "%q", name)
	}
	seen[name] = struct{}{}
	return nil
}

// isIdentStart reports whether b can start an identifier. | isIdentStart 报告 b 是否可作为标识符首字符。
func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// isIdentPart reports whether b can continue an identifier. | isIdentPart 报告 b 是否可作为标识符后续字符。
func isIdentPart(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

// isIdent reports whether s is a non-empty parameter identifier. | isIdent 报告 s 是否为非空参数标识符。
func isIdent(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentPart(s[i]) {
			return false
		}
	}
	return true
}

// Match reports whether path matches the pattern and returns its captures. | Match 报告 path 是否匹配模式并返回捕获。
func (p *Pattern) Match(path string) (Params, bool) {
	pathSegments, ok := splitMatchPath(path)
	if !ok {
		return Params{}, false
	}
	if len(p.segments) == 0 {
		if len(pathSegments) == 0 {
			return Params{}, true
		}
		return Params{}, false
	}
	last := p.segments[len(p.segments)-1]
	if last.catchAll {
		prefix := p.segments[:len(p.segments)-1]
		if len(pathSegments) < len(prefix) {
			return Params{}, false
		}
		if len(pathSegments) == len(prefix) && len(prefix) != 0 {
			return Params{}, false
		}
		var params Params
		for i, seg := range prefix {
			caps, ok := matchSegment(seg, pathSegments[i])
			if !ok {
				return Params{}, false
			}
			appendCaptures(&params, caps)
		}
		params.Append(last.catchName, strings.Join(pathSegments[len(prefix):], "/"))
		return params, true
	}
	if len(p.segments) != len(pathSegments) {
		return Params{}, false
	}
	var params Params
	for i, seg := range p.segments {
		caps, ok := matchSegment(seg, pathSegments[i])
		if !ok {
			return Params{}, false
		}
		appendCaptures(&params, caps)
	}
	return params, true
}

// splitMatchPath splits a request path, preserving the trailing empty segment. | splitMatchPath 切分请求路径，保留末尾空段。
func splitMatchPath(path string) ([]string, bool) {
	if path == "" || path[0] != '/' {
		return nil, false
	}
	if path == "/" {
		return nil, true
	}
	return strings.Split(path[1:], "/"), true
}

// Expand builds a concrete path from a compiled pattern and parameter values. | Expand 用编译模式与参数值生成具体路径。
func Expand(pattern string, params map[string]string) (string, error) {
	p, err := CompilePattern(pattern)
	if err != nil {
		return "", err
	}
	if len(p.segments) == 0 {
		return "/", nil
	}
	parts := make([]string, 0, len(p.segments))
	for _, seg := range p.segments {
		if seg.trailing {
			parts = append(parts, "")
			continue
		}
		if seg.catchAll {
			value, ok := params[seg.catchName]
			if !ok {
				return "", errs.Detail(ErrMissingParam, "%q", seg.catchName)
			}
			parts = append(parts, value)
			continue
		}
		var b strings.Builder
		for _, tok := range seg.tokens {
			switch tok.kind {
			case tokenLiteral:
				b.WriteString(tok.text)
			case tokenGlob:
				return "", errs.Detail(ErrBadPattern, "cannot expand unnamed glob in %q | 无法展开 %q 中的匿名通配符", pattern, pattern)
			case tokenParam:
				value, ok := params[tok.text]
				if !ok {
					return "", errs.Detail(ErrMissingParam, "%q", tok.text)
				}
				if strings.Contains(value, "/") {
					return "", errs.Detail(ErrParamValue, "%q contains /", value)
				}
				if tok.regex != nil && !fullMatch(tok.regex, value) {
					return "", errs.Detail(ErrParamValue, "%q does not match %q", value, tok.text)
				}
				b.WriteString(value)
			}
		}
		parts = append(parts, b.String())
	}
	return "/" + strings.Join(parts, "/"), nil
}

// fullMatch reports whether re matches all of s. | fullMatch 报告 re 是否完整匹配 s。
func fullMatch(re *regexpx.Regexp, s string) bool {
	loc := re.FindStringIndex(s)
	return loc != nil && loc[0] == 0 && loc[1] == len(s)
}
