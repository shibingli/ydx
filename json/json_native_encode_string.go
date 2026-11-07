//go:build !jsonx_std

package json

import "unicode/utf8"

// appendJSONStringSlowChecked is the slow escaping path with UTF-8 validation. |
// appendJSONStringSlowChecked 是带 UTF-8 校验的慢转义路径。
func appendJSONStringSlowChecked(buf []byte, s string, escapeHTML, escapeJS bool) ([]byte, bool) {
	valid := true
	buf = append(buf, '"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			valid = false
		}
		i += size
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
			if escapeJS {
				buf = append(buf, '\\', 'u', '2', '0', '2', hexDigit(byte(r)))
			} else {
				buf = utf8.AppendRune(buf, r)
			}
		default:
			if r < 0x20 {
				buf = append(buf, '\\', 'u', '0', '0', hexDigit(byte(r)>>4), hexDigit(byte(r)))
			} else {
				buf = utf8.AppendRune(buf, r)
			}
		}
	}
	buf = append(buf, '"')
	return buf, valid
}
