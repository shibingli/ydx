//go:build arm64 && !jsonx_std

package json

//go:noescape
func skipSpaceNEON(data []byte, start int) int

//go:noescape
func scanDigitsNEON(data []byte, start int) int

//go:noescape
func scanCompactOutsideNEON(src []byte, pos int) int

//go:noescape
func scanCompactInsideNEON(src []byte, pos int, escapeHTML bool) int

// isJSONSpaceByte reports whether c is one of the four JSON whitespace bytes. |
// isJSONSpaceByte 报告 c 是否为四种 JSON 空白字节之一。
func isJSONSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isASCIIDigit reports whether c is an ASCII decimal digit. | isASCIIDigit 报告 c 是否为 ASCII 数字。
func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// isCompactOutsideStop reports whether appendCompactJSON must handle c one byte at a time outside
// a string. | isCompactOutsideStop 报告字符串外 appendCompactJSON 是否必须逐字节处理 c。
func isCompactOutsideStop(c byte) bool { return c == '"' || isJSONSpaceByte(c) }

// isCompactInsideStop reports whether appendCompactJSON must stop a verbatim string-content run at
// c. | isCompactInsideStop 报告 appendCompactJSON 是否必须在 c 处停止原样复制的字符串内容段。
func isCompactInsideStop(c byte, escapeHTML bool) bool {
	if c == '"' || c == '\\' || c < 0x20 {
		return true
	}
	return escapeHTML && (c == '<' || c == '>' || c == '&' || c == 0xE2)
}

// isUnescapedASCIIStop reports whether c ends a string-content run that needs no unescaping. |
// isUnescapedASCIIStop 报告 c 是否结束一段无需反转义的字符串内容。
func isUnescapedASCIIStop(c byte) bool {
	return c == '"' || c == '\\' || c < 0x20 || c >= 0x80
}

// skipSpaceRun returns the first position at or after pos that is not JSON whitespace. A short
// scalar prefix rejects the common compact-JSON case and short runs cheaply; longer runs continue
// with NEON blocks, and the scalar tail pins the exact stop position. |
// skipSpaceRun 返回 pos 之后第一个不是 JSON 空白的位置。短标量前缀廉价地拒绝紧凑 JSON 与短连续段；
// 更长的连续段交给 NEON 块，标量尾部给出精确停止位置。
func skipSpaceRun(data []byte, pos int) int {
	i := pos
	for k := 0; k < 16 && i < len(data); k++ {
		if !isJSONSpaceByte(data[i]) {
			return i
		}
		i++
	}
	if k := i - pos; k == 16 && i < len(data) && isJSONSpaceByte(data[i]) && len(data)-i >= 16 {
		i = skipSpaceNEON(data, i)
	}
	for i < len(data) && isJSONSpaceByte(data[i]) {
		i++
	}
	return i
}

// scanDigits returns the first position at or after pos that is not an ASCII digit. The first
// eight digits are scanned scalar so short numbers pay no vector setup; longer runs continue with
// NEON blocks. | scanDigits 返回 pos 之后第一个不是 ASCII 数字的位置。前八位数字由标量扫描，
// 短数字不承担向量准备开销；更长的连续段交给 NEON 块。
func scanDigits(data []byte, pos int) int {
	i := pos
	for k := 0; k < 8 && i < len(data); k++ {
		if !isASCIIDigit(data[i]) {
			return i
		}
		i++
	}
	if k := i - pos; k == 8 && i < len(data) && isASCIIDigit(data[i]) && len(data)-i >= 16 {
		i = scanDigitsNEON(data, i)
	}
	for i < len(data) && isASCIIDigit(data[i]) {
		i++
	}
	return i
}

// scanCompactOutsideRun returns the first position at or after pos that is a quote or JSON
// whitespace, i.e. where appendCompactJSON must handle one byte specially. A scalar prefix keeps
// short syntax spans vector-free; longer spans continue with NEON blocks. |
// scanCompactOutsideRun 返回 pos 之后第一个引号或 JSON 空白的位置，即 appendCompactJSON 必须逐字节
// 处理的位置。标量前缀让短语法段不进入向量路径；更长的段交给 NEON 块。
func scanCompactOutsideRun(src []byte, pos int) int {
	i := pos
	for k := 0; k < 16 && i < len(src); k++ {
		if isCompactOutsideStop(src[i]) {
			return i
		}
		i++
	}
	if k := i - pos; k == 16 && i < len(src) && !isCompactOutsideStop(src[i]) && len(src)-i >= 16 {
		i = scanCompactOutsideNEON(src, i)
	}
	for i < len(src) && !isCompactOutsideStop(src[i]) {
		i++
	}
	return i
}

// scanCompactInsideRun returns the end of a string-content run that can be copied verbatim by
// appendCompactJSON. It stops before a quote, backslash, control byte, or an HTML-sensitive byte
// when escapeHTML is set. A scalar prefix keeps short strings vector-free; longer runs continue
// with NEON blocks. | scanCompactInsideRun 返回 appendCompactJSON 可原样复制的字符串内容段结束
// 位置；遇到引号、反斜杠、控制字节，或 escapeHTML 下的 HTML 敏感字节时停止。标量前缀让短字符串
// 不进入向量路径；更长的段交给 NEON 块。
func scanCompactInsideRun(src []byte, pos int, escapeHTML bool) int {
	i := pos
	for k := 0; k < 16 && i < len(src); k++ {
		if isCompactInsideStop(src[i], escapeHTML) {
			return i
		}
		i++
	}
	if k := i - pos; k == 16 && i < len(src) && !isCompactInsideStop(src[i], escapeHTML) && len(src)-i >= 16 {
		i = scanCompactInsideNEON(src, i, escapeHTML)
	}
	for i < len(src) && !isCompactInsideStop(src[i], escapeHTML) {
		i++
	}
	return i
}

// scanUnescapedASCII returns the end of an ASCII run that needs no unescaping. A scalar prefix
// keeps short segments vector-free; longer runs reuse the string-body NEON scanner, whose stop set
// is exactly this one, and the scalar tail pins the exact position. |
// scanUnescapedASCII 返回无需反转义的 ASCII 段结束位置。标量前缀让短段不进入向量路径；更长的段
// 复用停止集合完全相同的字符串体 NEON 扫描器，标量尾部给出精确位置。
func scanUnescapedASCII(data []byte, pos int) int {
	i := pos
	for k := 0; k < 16 && i < len(data); k++ {
		if isUnescapedASCIIStop(data[i]) {
			return i
		}
		i++
	}
	if k := i - pos; k == 16 && i < len(data) && !isUnescapedASCIIStop(data[i]) && len(data)-i >= 16 {
		i = scanStringBodyNEON(data, i)
	}
	for i < len(data) && !isUnescapedASCIIStop(data[i]) {
		i++
	}
	return i
}
