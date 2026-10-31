package regexpx

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

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
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.ReplaceAllString(src, repl), nil
		}
	}
	out := make([]byte, 0, len(src))
	last := 0
	matched := false
	err := r.forEachMatch(src, -1, len(r.names)*2, func(caps []int) bool {
		out = append(out, src[last:caps[0]]...)
		out = r.appendExpand(out, repl, nil, src, caps)
		last = caps[1]
		matched = true
		return false
	})
	if !matched {
		return src, err
	}
	out = append(out, src[last:]...)
	return string(out), err
}

// ReplaceAllStringFunc replaces every match with the result of repl and returns the result. |
// ReplaceAllStringFunc 用 repl 的结果替换每个匹配并返回结果。
func (r *Regexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.ReplaceAllStringFunc(src, repl)
		}
	}
	out := make([]byte, 0, len(src))
	last := 0
	matched := false
	_ = r.forEachMatch(src, -1, 2, func(caps []int) bool {
		out = append(out, src[last:caps[0]]...)
		out = append(out, repl(src[caps[0]:caps[1]])...)
		last = caps[1]
		matched = true
		return false
	})
	if !matched {
		return src
	}
	out = append(out, src[last:]...)
	return string(out)
}

// ReplaceAll replaces every match in src with repl. | ReplaceAll 用 repl 替换 src 中的每个匹配。
func (r *Regexp) ReplaceAll(src, repl []byte) []byte {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.ReplaceAll(src, repl)
		}
	}
	out := make([]byte, 0, len(src))
	last := 0
	matched := false
	err := r.forEachMatch(bytesToString(src), -1, len(r.names)*2, func(caps []int) bool {
		out = append(out, src[last:caps[0]]...)
		out = r.appendExpand(out, bytesToString(repl), src, "", caps)
		last = caps[1]
		matched = true
		return false
	})
	if err != nil || !matched {
		return src
	}
	return append(out, src[last:]...)
}

// ReplaceAllFunc replaces every match in src with the result of repl. | ReplaceAllFunc 用 repl 的结果
// 替换 src 中的每个匹配。
func (r *Regexp) ReplaceAllFunc(src []byte, repl func([]byte) []byte) []byte {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.ReplaceAllFunc(src, repl)
		}
	}
	out := make([]byte, 0, len(src))
	last := 0
	matched := false
	_ = r.forEachMatch(bytesToString(src), -1, 2, func(caps []int) bool {
		out = append(out, src[last:caps[0]]...)
		out = append(out, repl(src[caps[0]:caps[1]])...)
		last = caps[1]
		matched = true
		return false
	})
	if !matched {
		return src
	}
	return append(out, src[last:]...)
}

// Split slices s into substrings separated by matches. n limits the result count; a negative n means
// all substrings. | Split 按匹配把 s 切分为子串。n 限制结果数量，负数表示全部。
func (r *Regexp) Split(s string, n int) []string {
	if n == 0 {
		return nil
	}
	if len(r.prog.src) > 0 && len(s) == 0 {
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

// appendExpand appends the replacement template for one match. It mirrors regexp.Regexp.expand:
// $name and ${name} references, $$ escapes, Unicode template names, leading-zero names and the
// 1e8 numeric cap. | appendExpand 为一次匹配追加替换模板。它镜像 regexp.Regexp.expand：$name 与
// ${name} 引用、$$ 转义、Unicode 模板名、前导零名称与 1e8 数字上限。
func (r *Regexp) appendExpand(dst []byte, template string, bsrc []byte, src string, match []int) []byte {
	for len(template) > 0 {
		before, after, found := strings.Cut(template, "$")
		if !found {
			break
		}
		dst = append(dst, before...)
		template = after
		if template != "" && template[0] == '$' {
			dst = append(dst, '$')
			template = template[1:]
			continue
		}
		name, num, rest, ok := extractTemplate(template)
		if !ok {
			dst = append(dst, '$')
			continue
		}
		template = rest
		if num >= 0 {
			slot := 2 * num
			if slot+1 < len(match) && match[slot] >= 0 && match[slot+1] >= 0 {
				if bsrc != nil {
					dst = append(dst, bsrc[match[slot]:match[slot+1]]...)
				} else {
					dst = append(dst, src[match[slot]:match[slot+1]]...)
				}
			}
			continue
		}
		for i, namei := range r.names {
			if name != namei {
				continue
			}
			slot := 2 * i
			if slot+1 < len(match) && match[slot] >= 0 && match[slot+1] >= 0 {
				if bsrc != nil {
					dst = append(dst, bsrc[match[slot]:match[slot+1]]...)
				} else {
					dst = append(dst, src[match[slot]:match[slot+1]]...)
				}
			}
			break
		}
	}
	return append(dst, template...)
}

// extractTemplate parses a leading $name or ${name} reference, mirroring regexp.extract. | extractTemplate
// 解析开头的 $name 或 ${name} 引用，镜像 regexp.extract。
func extractTemplate(str string) (name string, num int, rest string, ok bool) {
	if str == "" {
		return "", 0, "", false
	}
	brace := false
	if str[0] == '{' {
		brace = true
		str = str[1:]
	}
	i := 0
	for i < len(str) {
		r, size := utf8.DecodeRuneInString(str[i:])
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			break
		}
		i += size
	}
	if i == 0 {
		return "", 0, "", false
	}
	name = str[:i]
	if brace {
		if i >= len(str) || str[i] != '}' {
			return "", 0, "", false
		}
		i++
	}
	num = 0
	for j := 0; j < len(name); j++ {
		if name[j] < '0' || name[j] > '9' || num >= 100000000 {
			num = -1
			break
		}
		num = num*10 + int(name[j]-'0')
	}
	if name[0] == '0' && len(name) > 1 {
		num = -1
	}
	return name, num, str[i:], true
}
