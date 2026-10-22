//go:build arm64 && goexperiment.simd && !jsonx_std

package json

// appendJSONString appends one JSON string literal to buf. The clean path uses the NEON escape
// scan and appends the whole string at once; the slow path escapes rune by rune. |
// appendJSONString 把单个 JSON 字符串字面量追加到 buf。干净路径用 NEON 转义扫描并一次性追加
// 整个字符串；慢路径逐 rune 转义。
func appendJSONString(buf []byte, s string, escapeHTML bool) []byte {
	if !jsonStringNeedsEscape(s, escapeHTML) {
		buf = append(buf, '"')
		buf = append(buf, s...)
		buf = append(buf, '"')
		return buf
	}
	return appendJSONStringSlow(buf, s, escapeHTML)
}
