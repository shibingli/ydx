package waf

import "strings"

// regexSuffixNeedle extracts a literal byte sequence that every match of pattern must contain.
// It only accepts a literal run at the end of the top-level pattern, outside groups, classes and
// alternation. Anything it cannot prove is rejected, so a missing needle only loses an
// optimization and can never turn a match into a non-match. | regexSuffixNeedle 提取 pattern 的每个
// 匹配都必须包含的字面量字节序列。它只接受位于顶层模式末尾、不在分组、字符类或分支中的字面量
// 连续段；任何无法证明的构造都会放弃提取，因此缺少 needle 只会失去优化，绝不会把命中变成未命中。
func regexSuffixNeedle(pattern string) (needle string, fold, ok bool) {
	end := len(pattern)
	// Zero-width trailing assertions do not consume input; ignore them while looking for the
	// mandatory literal before them. | 尾部零宽断言不消耗输入；寻找其前面的必需字面量时忽略它们。
	for end > 0 {
		last := pattern[end-1]
		if last == '$' && !byteEscaped(pattern, end-1) {
			end--
			continue
		}
		if end >= 2 && pattern[end-2] == '\\' && !byteEscaped(pattern, end-2) &&
			isZeroWidthEscape(last) {
			end -= 2
			continue
		}
		break
	}
	if end == 0 {
		return "", false, false
	}

	run := make([]byte, 0, 16)
	reset := func() { run = run[:0] }
	depth := 0
	for i := 0; i < end; {
		c := pattern[i]
		switch c {
		case '\\':
			lit, isLiteral, advance, good := parseRegexEscape(pattern, i, end)
			if !good {
				return "", false, false
			}
			if !isLiteral {
				reset()
				i = advance
				continue
			}
			if depth == 0 {
				run = append(run, lit...)
			}
			i = advance
		case '[':
			next, good := skipRegexClass(pattern, i, end)
			if !good {
				return "", false, false
			}
			reset()
			i = next
		case '(':
			reset()
			next, group, hasFold, good := parseRegexGroup(pattern, i, end)
			if !good {
				return "", false, false
			}
			if hasFold {
				fold = true
			}
			if group {
				depth++
			}
			i = next
		case ')':
			reset()
			if depth == 0 {
				return "", false, false
			}
			depth--
			i++
		case '|':
			reset()
			if depth == 0 {
				return "", false, false
			}
			i++
		case '.', '^', '$', '*', '+', '?', '{', '}', ']':
			reset()
			i++
		default:
			if depth == 0 {
				run = append(run, c)
			}
			i++
		}
	}
	if depth != 0 || len(run) == 0 {
		return "", false, false
	}
	if len(run) == 1 && (isASCIIAlphaNumeric(run[0]) || isSpaceByte(run[0])) {
		return "", false, false
	}
	if fold && !asciiBytes(run) {
		return "", false, false
	}
	return string(run), fold, true
}

// parseRegexEscape parses one backslash escape. It returns the literal bytes to append, the next
// index, and whether to keep scanning. | parseRegexEscape 解析一个反斜杠转义，返回要追加的字面量
// 字节、下一个下标以及是否继续扫描。
func parseRegexEscape(pattern string, index, end int) (literal []byte, isLiteral bool, next int, ok bool) {
	if index+1 >= end {
		return nil, false, 0, false
	}
	escaped := pattern[index+1]
	if isSimpleEscapedLiteral(escaped) {
		return []byte{escaped}, true, index + 2, true
	}
	switch escaped {
	case 'd', 'D', 's', 'S', 'w', 'W', 'b', 'B', 'A', 'z', 'Z', 'G',
		'n', 'r', 't', 'f', 'v', 'a', 'e':
		return nil, false, index + 2, true
	case 'x':
		next = index + 2
		if next < end && pattern[next] == '{' {
			close := strings.IndexByte(pattern[next+1:end], '}')
			if close < 0 {
				return nil, false, 0, false
			}
			return nil, false, next + 1 + close + 1, true
		}
		for count := 0; count < 2 && next < end && isHexByte(pattern[next]); count++ {
			next++
		}
		return nil, false, next, true
	case 'u':
		return nil, false, advanceASCIIHex(pattern, index+2, end, 4), true
	case 'U':
		return nil, false, advanceASCIIHex(pattern, index+2, end, 8), true
	case 'p', 'P':
		next = index + 2
		if next < end && pattern[next] == '{' {
			close := strings.IndexByte(pattern[next+1:end], '}')
			if close < 0 {
				return nil, false, 0, false
			}
			return nil, false, next + 1 + close + 1, true
		}
		return nil, false, 0, false
	case '0':
		next = index + 2
		for count := 0; count < 2 && next < end && pattern[next] >= '0' && pattern[next] <= '7'; count++ {
			next++
		}
		return nil, false, next, true
	case '1', '2', '3', '4', '5', '6', '7', '8', '9':
		next = index + 2
		for next < end && pattern[next] >= '0' && pattern[next] <= '9' {
			next++
		}
		return nil, false, next, true
	case 'k':
		next = index + 2
		if next >= end || (pattern[next] != '<' && pattern[next] != '{' && pattern[next] != '\'') {
			return nil, false, 0, false
		}
		close := pattern[next]
		if close == '<' {
			close = '>'
		} else if close == '{' {
			close = '}'
		}
		index = strings.IndexByte(pattern[next+1:end], close)
		if index < 0 {
			return nil, false, 0, false
		}
		return nil, false, next + 1 + index + 1, true
	case 'c':
		if index+2 >= end {
			return nil, false, 0, false
		}
		return nil, false, index + 3, true
	case 'Q', 'E':
		return nil, false, 0, false
	default:
		return nil, false, 0, false
	}
}

// parseRegexGroup parses the group or flag introducer beginning at index. group reports whether a
// depth level was opened; hasFold reports a case-insensitive flag. | parseRegexGroup 解析 index 处的
// 分组或标志引入符；group 表示是否开启一层分组，hasFold 表示存在大小写不敏感标志。
func parseRegexGroup(pattern string, index, end int) (next int, group, hasFold, ok bool) {
	if index+1 >= end || pattern[index+1] != '?' {
		return index + 1, true, false, true
	}
	j := index + 2
	for j < end && (isASCIIAlpha(pattern[j]) || pattern[j] == '-') {
		j++
	}
	if j >= end || (pattern[j] != ':' && pattern[j] != ')') {
		// Lookaround, named group, comment or conditional: treat it as an opaque group. |
		// 环视、命名分组、注释或条件组：按普通分组处理。
		return index + 2, true, false, true
	}
	flags := pattern[index+2 : j]
	if len(flags) == 0 {
		if pattern[j] == ':' {
			return j + 1, true, false, true
		}
		return 0, false, false, false
	}
	if strings.ContainsRune(flags, 'x') {
		// Free-spacing mode changes the meaning of whitespace and comments. |
		// 自由空白模式会改变空白与注释的含义。
		return 0, false, false, false
	}
	hasFold = strings.ContainsRune(flags, 'i')
	if pattern[j] == ')' {
		return j + 1, false, hasFold, true
	}
	return j + 1, true, hasFold, true
}

// skipRegexClass returns the index just after a character class. POSIX class syntax is rejected
// because its nested brackets would make the scan ambiguous. | skipRegexClass 返回字符类之后的下标。
// POSIX 类语法会被拒绝，因为其嵌套方括号会让扫描产生歧义。
func skipRegexClass(pattern string, index, end int) (int, bool) {
	j := index + 1
	if j < end && pattern[j] == '^' {
		j++
	}
	if j < end && pattern[j] == ']' {
		j++
	}
	for j < end {
		switch pattern[j] {
		case '\\':
			j += 2
			if j > end {
				return 0, false
			}
		case ']':
			return j + 1, true
		case '[':
			if j+1 < end && (pattern[j+1] == ':' || pattern[j+1] == '.' || pattern[j+1] == '=') {
				return 0, false
			}
			j++
		default:
			j++
		}
	}
	return 0, false
}

// byteEscaped reports whether the byte at index is escaped by an odd number of backslashes.
// | byteEscaped 报告 index 处的字节是否被奇数个反斜杠转义。
func byteEscaped(pattern string, index int) bool {
	count := 0
	for i := index - 1; i >= 0 && pattern[i] == '\\'; i-- {
		count++
	}
	return count%2 == 1
}

// isZeroWidthEscape reports whether escaped byte is a zero-width assertion. | isZeroWidthEscape 报告
// 转义字节是否为零宽断言。
func isZeroWidthEscape(escaped byte) bool {
	switch escaped {
	case 'b', 'B', 'A', 'z', 'Z', 'G':
		return true
	default:
		return false
	}
}

// isSimpleEscapedLiteral reports whether escaping c yields the literal byte c. | isSimpleEscapedLiteral
// 报告转义 c 是否得到字面量 c。
func isSimpleEscapedLiteral(c byte) bool {
	return c < 0x80 && c >= 0x20 && !isASCIIAlphaNumeric(c) && c != '_' && c != 'Q' && c != 'E'
}

// advanceASCIIHex advances up to count hexadecimal bytes. | advanceASCIIHex 前进最多 count 个十六进制
// 字节。
func advanceASCIIHex(pattern string, index, end, count int) int {
	for step := 0; step < count && index < end && isHexByte(pattern[index]); step++ {
		index++
	}
	return index
}

// isHexByte reports whether b is an ASCII hexadecimal digit. | isHexByte 报告 b 是否为 ASCII 十六进制位。
func isHexByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// isASCIIAlpha reports whether b is an ASCII letter. | isASCIIAlpha 报告 b 是否为 ASCII 字母。
func isASCIIAlpha(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// isASCIIAlphaNumeric reports whether b is an ASCII letter or digit. | isASCIIAlphaNumeric 报告 b
// 是否为 ASCII 字母或数字。
func isASCIIAlphaNumeric(b byte) bool {
	return isASCIIAlpha(b) || b >= '0' && b <= '9'
}

// asciiBytes reports whether every byte is ASCII. | asciiBytes 报告是否所有字节都是 ASCII。
func asciiBytes(value []byte) bool {
	for _, b := range value {
		if b >= 0x80 {
			return false
		}
	}
	return true
}

// containsNeedle reports whether value contains needle, using ASCII case folding when fold is set.
// Non-ASCII input is not rejected under folding because regexpx may match Unicode folds that an
// ASCII scan cannot see; the regex engine remains the authority in that case. | containsNeedle 报告
// value 是否包含 needle；fold 为真时使用 ASCII 大小写折叠。折叠模式下不会拒绝非 ASCII 输入，因为
// regexpx 可能命中 ASCII 扫描看不到的 Unicode 折叠，此时仍以正则引擎为准。
func containsNeedle(value, needle string, fold bool) bool {
	if needle == "" {
		return true
	}
	if !fold {
		return strings.Contains(value, needle)
	}
	if len(needle) == 1 {
		want := lowerASCII(needle[0])
		for i := 0; i < len(value); i++ {
			if value[i] >= 0x80 {
				return true
			}
			if lowerASCII(value[i]) == want {
				return true
			}
		}
		return false
	}
	if len(value) < len(needle) {
		return true
	}
	want := lowerASCII(needle[0])
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i] >= 0x80 {
			return true
		}
		if lowerASCII(value[i]) != want {
			continue
		}
		matched := true
		for j := 1; j < len(needle); j++ {
			b := value[i+j]
			if b >= 0x80 {
				return true
			}
			if lowerASCII(b) != lowerASCII(needle[j]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	// A non-ASCII byte may appear only after the last full-length window; recheck the tail so a
	// Unicode fold is never rejected. | 非 ASCII 字节可能只出现在最后一个完整窗口之后；复查尾部，
	// 避免错误拒绝 Unicode 折叠。
	for i := len(value) - len(needle) + 1; i < len(value); i++ {
		if value[i] >= 0x80 {
			return true
		}
	}
	return false
}

// lowerASCII lowercases one ASCII letter. | lowerASCII 把一个 ASCII 字母转为小写。
func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}
