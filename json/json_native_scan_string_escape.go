//go:build !jsonx_std && !amd64 && !arm64

package json

// jsonStringNeedsEscape reports whether s needs JSON escaping, using the same 8/4/1-byte SWAR
// scan as the encoder. | jsonStringNeedsEscape 用与编码器相同的 8/4/1 字节 SWAR 扫描判断 s
// 是否需要 JSON 转义。
func jsonStringNeedsEscape(s string, escapeHTML bool) bool {
	return jsonStringNeedsEscapeTail(s, 0, escapeHTML)
}
