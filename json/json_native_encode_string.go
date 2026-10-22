//go:build (amd64 || arm64) && !jsonx_std

package json

import "unicode/utf8"

// appendJSONStringSlow appends one JSON string literal with full escaping. It is the shared slow
// path for the SWAR and NEON scanners. | appendJSONStringSlow 用完整转义追加一个 JSON 字符串
// 字面量；它是 SWAR 与 NEON 扫描器共享的慢路径。
func appendJSONStringSlow(buf []byte, s string, escapeHTML bool) []byte {
	buf = append(buf, '"')
	for _, r := range s {
		switch r {
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\f':
			buf = append(buf, '\\', 'f')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\r':
			buf = append(buf, '\\', 'r')
		case '\t':
			buf = append(buf, '\\', 't')
		case '<', '>', '&':
			if escapeHTML {
				buf = append(buf, '\\', 'u', '0', '0', hexDigit(byte(r)>>4), hexDigit(byte(r)))
			} else {
				buf = utf8.AppendRune(buf, r)
			}
		case ' ', ' ':
			buf = append(buf, '\\', 'u', '2', '0', '2', hexDigit(byte(r)))
		default:
			if r < 0x20 {
				buf = append(buf, '\\', 'u', '0', '0', hexDigit(byte(r)>>4), hexDigit(byte(r)))
			} else {
				buf = utf8.AppendRune(buf, r)
			}
		}
	}
	buf = append(buf, '"')
	return buf
}
