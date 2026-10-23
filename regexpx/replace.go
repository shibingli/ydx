package regexpx

import "strings"

// ReplaceAllString replaces every match with repl and returns the result. The replacement uses Go's
// $name and ${name} rules, and a scan aborted by MatchTimeout leaves src unchanged. | ReplaceAllString
// 用 repl 替换每个匹配并返回结果。替换遵循 Go 的 $name 与 ${name} 规则；被 MatchTimeout 中止的扫描
// 原样返回 src。
func (r *Regexp) ReplaceAllString(src, repl string) string {
	out, err := r.ReplaceAllStringE(src, repl)
	if err != nil {
		return src
	}
	return out
}

// ReplaceAllStringE is ReplaceAllString with the engine error exposed. | ReplaceAllStringE 是暴露引擎
// 错误的 ReplaceAllString。
func (r *Regexp) ReplaceAllStringE(src, repl string) (string, error) {
	rows, err := r.findAll(src, -1, len(r.names)*2)
	if len(rows) == 0 {
		return src, err
	}
	var b strings.Builder
	b.Grow(len(src) + len(rows)*len(repl))
	last := 0
	for _, caps := range rows {
		b.WriteString(src[last:caps[0]])
		b.WriteString(r.expand(repl, src, caps))
		last = caps[1]
	}
	b.WriteString(src[last:])
	return b.String(), err
}

// ReplaceAllStringFunc replaces every match with the result of repl and returns the result. |
// ReplaceAllStringFunc 用 repl 的结果替换每个匹配并返回结果。
func (r *Regexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	rows, _ := r.findAll(src, -1, 2)
	if len(rows) == 0 {
		return src
	}
	var b strings.Builder
	b.Grow(len(src))
	last := 0
	for _, caps := range rows {
		b.WriteString(src[last:caps[0]])
		b.WriteString(repl(src[caps[0]:caps[1]]))
		last = caps[1]
	}
	b.WriteString(src[last:])
	return b.String()
}

// ReplaceAll replaces every match in src with repl. | ReplaceAll 用 repl 替换 src 中的每个匹配。
func (r *Regexp) ReplaceAll(src, repl []byte) []byte {
	out, err := r.ReplaceAllStringE(bytesToString(src), bytesToString(repl))
	if err != nil {
		return src
	}
	return []byte(out)
}

// ReplaceAllFunc replaces every match in src with the result of repl. | ReplaceAllFunc 用 repl 的结果
// 替换 src 中的每个匹配。
func (r *Regexp) ReplaceAllFunc(src []byte, repl func([]byte) []byte) []byte {
	rows, _ := r.findAll(bytesToString(src), -1, 2)
	if len(rows) == 0 {
		return src
	}
	var out []byte
	last := 0
	for _, caps := range rows {
		out = append(out, src[last:caps[0]]...)
		out = append(out, repl(src[caps[0]:caps[1]])...)
		last = caps[1]
	}
	return append(out, src[last:]...)
}

// Split slices s into substrings separated by matches. n limits the result count; a negative n means
// all substrings. | Split 按匹配把 s 切分为子串。n 限制结果数量，负数表示全部。
func (r *Regexp) Split(s string, n int) []string {
	if n == 0 {
		return nil
	}
	if len(r.src) > 0 && len(s) == 0 {
		return []string{""}
	}
	matches, _ := r.findAll(s, n, 2)
	out := make([]string, 0, len(matches))
	beg, end := 0, 0
	for _, match := range matches {
		if n > 0 && len(out) >= n-1 {
			break
		}
		end = match[0]
		if match[1] != 0 {
			out = append(out, s[beg:end])
		}
		beg = match[1]
	}
	if end != len(s) {
		out = append(out, s[beg:])
	}
	return out
}

// expand writes the replacement template for one match. | expand 为一次匹配写入替换模板。
func (r *Regexp) expand(repl, src string, caps []int) string {
	var b strings.Builder
	for i := 0; i < len(repl); {
		if repl[i] != '$' {
			b.WriteByte(repl[i])
			i++
			continue
		}
		if i+1 < len(repl) && repl[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		name, next, ok := extractName(repl, i+1)
		if !ok {
			b.WriteByte('$')
			i++
			continue
		}
		index := -1
		if isAllDigits(name) {
			value := 0
			for j := 0; j < len(name); j++ {
				value = value*10 + int(name[j]-'0')
				if value > len(r.names) {
					break
				}
			}
			if value < len(r.names) {
				index = value
			}
		} else if idx, found := r.nameMap[name]; found {
			index = idx
		}
		if index >= 0 {
			slot := 2 * index
			if caps[slot] >= 0 && caps[slot+1] >= 0 {
				b.WriteString(src[caps[slot]:caps[slot+1]])
			}
		}
		i = next
	}
	return b.String()
}

// extractName parses a $name or ${name} reference starting after the dollar sign. | extractName 解析
// 美元符号之后的 $name 或 ${name} 引用。
func extractName(repl string, start int) (name string, next int, ok bool) {
	if start >= len(repl) {
		return "", start, false
	}
	if repl[start] == '{' {
		end := strings.IndexByte(repl[start+1:], '}')
		if end < 0 {
			return "", start, false
		}
		name = repl[start+1 : start+1+end]
		if name == "" {
			return "", start, false
		}
		return name, start + 2 + end, true
	}
	i := start
	for i < len(repl) {
		c := repl[i]
		if c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			i++
			continue
		}
		break
	}
	if i == start {
		return "", start, false
	}
	return repl[start:i], i, true
}

// isAllDigits reports whether s is a non-empty decimal string. | isAllDigits 报告 s 是否是非空十进制串。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
