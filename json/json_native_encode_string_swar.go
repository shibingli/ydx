//go:build !jsonx_std

package json

// appendJSONString appends one JSON string literal to buf in v1 mode: HTML characters and the
// JavaScript line separators are escaped. | appendJSONString 以 v1 模式把单个 JSON 字符串字面量
// 追加到 buf：转义 HTML 字符与 JavaScript 行分隔符。
func appendJSONString(buf []byte, s string, escapeHTML bool) []byte {
	return appendJSONStringMode(buf, s, escapeHTML, true)
}

// appendJSONStringMode appends one JSON string literal to buf. Strings up to 16 bytes use the
// escape tables directly; longer ones use the SSE2/NEON block scanner, and the slow path escapes
// rune by rune. escapeJS controls JavaScript line separator escaping independently of HTML
// escaping, as encoding/json/v2's EscapeForJS does. | appendJSONStringMode 把单个 JSON 字符串字面量
// 追加到 buf。不超过 16 字节的字符串直接用转义表；更长的字符串使用 SSE2/NEON 块扫描器；慢路径逐
// rune 转义。escapeJS 独立于 HTML 转义控制 JavaScript 行分隔符，对应 encoding/json/v2 的
// EscapeForJS。
func appendJSONStringMode(buf []byte, s string, escapeHTML, escapeJS bool) []byte {
	buf, _ = appendJSONStringChecked(buf, s, escapeHTML, escapeJS)
	return buf
}

// appendJSONStringChecked appends one JSON string literal and reports whether the source was
// valid UTF-8. The ASCII scan that decides whether escaping is needed already proves validity for
// clean strings, so no extra pass runs on the common path; only the slow path (non-ASCII,
// escapes, or control bytes) decodes runes and can report an invalid byte. |
// appendJSONStringChecked 追加一个 JSON 字符串字面量并报告源字符串是否为合法 UTF-8。判断是否需要
// 转义的 ASCII 扫描已经证明了干净字符串的合法性，因此常见路径无需额外遍历；只有慢路径（非 ASCII、
// 转义或控制字节）才解码 rune 并可能报告非法字节。
func appendJSONStringChecked(buf []byte, s string, escapeHTML, escapeJS bool) ([]byte, bool) {
	if len(s) <= 16 {
		// A short clean string is the common case. The SWAR tail scan checks four bytes per
		// iteration, replacing up to sixteen table loads with a few word operations. |
		// 短且干净的字符串是常见情况。SWAR 尾部扫描每次检查四个字节，用少量字运算取代最多十六次
		// 查表。
		if !jsonStringNeedsEscapeTail(s, 0, escapeHTML) {
			return appendCleanString(buf, s), true
		}
		return appendJSONStringSlowChecked(buf, s, escapeHTML, escapeJS)
	}
	if jsonStringNeedsEscape(s, escapeHTML) {
		return appendJSONStringSlowChecked(buf, s, escapeHTML, escapeJS)
	}
	return appendCleanString(buf, s), true
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
