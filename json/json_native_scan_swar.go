//go:build (amd64 || arm64) && !jsonx_std

package json

// scanCompactOutsideRun returns the first position at or after pos that is a quote or JSON
// whitespace, i.e. where appendCompactJSON must handle one byte specially. | scanCompactOutsideRun
// 返回 pos 之后第一个引号或 JSON 空白的位置，即 appendCompactJSON 必须逐字节处理的位置。
func scanCompactOutsideRun(src []byte, pos int) int {
	for pos < len(src) {
		c := src[pos]
		if c == '"' || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			break
		}
		pos++
	}
	return pos
}

// scanCompactInsideRun returns the end of a string-content run that can be copied verbatim by
// appendCompactJSON. It stops before a quote, backslash, control byte, or an HTML-sensitive byte
// when escapeHTML is set. | scanCompactInsideRun 返回 appendCompactJSON 可原样复制的字符串内容段
// 结束位置；遇到引号、反斜杠、控制字节，或 escapeHTML 下的 HTML 敏感字节时停止。
func scanCompactInsideRun(src []byte, pos int, escapeHTML bool) int {
	for pos < len(src) {
		c := src[pos]
		if c == '"' || c == '\\' || c < 0x20 {
			break
		}
		if escapeHTML && (c == '<' || c == '>' || c == '&' || c == 0xE2) {
			break
		}
		pos++
	}
	return pos
}

// scanUnescapedASCII returns the end of an ASCII run that needs no unescaping. | scanUnescapedASCII
// 返回无需反转义的 ASCII 段结束位置。
func scanUnescapedASCII(data []byte, pos int) int {
	for pos < len(data) {
		c := data[pos]
		if c == '"' || c == '\\' || c < 0x20 || c >= 0x80 {
			break
		}
		pos++
	}
	return pos
}
