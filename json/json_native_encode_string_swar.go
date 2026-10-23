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
			return appendCleanString(buf, s)
		}
		return appendJSONStringSlow(buf, s, escapeHTML)
	}
	if jsonStringNeedsEscape(s, escapeHTML) {
		return appendJSONStringSlow(buf, s, escapeHTML)
	}
	return appendCleanString(buf, s)
}

// appendCleanString appends a quoted string that needs no escaping. One capacity check and one
// contiguous write replace three append calls. | appendCleanString 追加无需转义的带引号字符串：
// 一次容量检查与一次连续写入取代三次 append 调用。
func appendCleanString(buf []byte, s string) []byte {
	n := len(buf)
	if cap(buf)-n >= len(s)+2 {
		buf = buf[:n+len(s)+2]
		buf[n] = '"'
		copy(buf[n+1:], s)
		buf[n+len(s)+1] = '"'
		return buf
	}
	buf = append(buf, '"')
	buf = append(buf, s...)
	buf = append(buf, '"')
	return buf
}
