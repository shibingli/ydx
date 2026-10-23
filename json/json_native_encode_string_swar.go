//go:build !jsonx_std

package json

// appendJSONString appends one JSON string literal to buf. Strings up to 16 bytes use the escape
// tables directly; longer ones use the SSE2/NEON block scanner, and the slow path escapes rune by
// rune. | appendJSONString 把单个 JSON 字符串字面量追加到 buf。不超过 16 字节的字符串直接用转义表；
// 更长的字符串使用 SSE2/NEON 块扫描器；慢路径逐 rune 转义。
func appendJSONString(buf []byte, s string, escapeHTML bool) []byte {
	if len(s) <= 16 {
		clean := 0
		if escapeHTML {
			for clean < len(s) && !escapeTableHTML[s[clean]] {
				clean++
			}
		} else {
			for clean < len(s) && !escapeTablePlain[s[clean]] {
				clean++
			}
		}
		if clean == len(s) {
			buf = append(buf, '"')
			buf = append(buf, s...)
			buf = append(buf, '"')
			return buf
		}
		return appendJSONStringSlow(buf, s, escapeHTML)
	}
	if jsonStringNeedsEscape(s, escapeHTML) {
		return appendJSONStringSlow(buf, s, escapeHTML)
	}
	buf = append(buf, '"')
	buf = append(buf, s...)
	buf = append(buf, '"')
	return buf
}
