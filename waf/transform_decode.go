package waf

import (
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/shibingli/ydx/base64"
)

// percentDecode decodes percent escapes. When uni is true it also decodes %uXXXX sequences and
// maps full-width compatibility characters to ASCII. | percentDecode 解码百分号转义。uni 为 true
// 时同时解码 %uXXXX 序列并把全角兼容字符映射为 ASCII。
func percentDecode(s string, uni bool) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '%' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if uni && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if value, ok := parseHex(s[i+2 : i+6]); ok {
				b.WriteRune(foldFullWidth(rune(value)))
				i += 6
				continue
			}
		}
		if i+2 < len(s) {
			if value, ok := parseHex(s[i+1 : i+3]); ok {
				b.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		b.WriteByte('%')
		i++
	}
	return b.String()
}

// foldFullWidth maps full-width ASCII compatibility characters to ASCII. | foldFullWidth 把全角
// ASCII 兼容字符映射为 ASCII。
func foldFullWidth(r rune) rune {
	switch {
	case r >= 0xFF01 && r <= 0xFF5E:
		return r - 0xFEE0
	case r == 0x3000:
		return ' '
	default:
		return r
	}
}

// parseHex parses a hexadecimal token without allocating. | parseHex 以零分配方式解析十六进制标记。
func parseHex(s string) (uint64, bool) {
	if len(s) == 0 || len(s) > 8 {
		return 0, false
	}
	var value uint64
	for i := 0; i < len(s); i++ {
		digit := hexDigit(s[i])
		if digit < 0 {
			return 0, false
		}
		value = value<<4 | uint64(digit)
	}
	return value, true
}

// hexDigit returns the value of one hexadecimal digit or -1. | hexDigit 返回一个十六进制位的值或 -1。
func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// htmlEntityDecode decodes named and numeric HTML entities. | htmlEntityDecode 解码命名与数字
// HTML 实体。
func htmlEntityDecode(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		end := strings.IndexByte(s[i:], ';')
		if end < 0 || end > 32 {
			b.WriteByte('&')
			i++
			continue
		}
		entity := s[i+1 : i+end]
		if entity == "" {
			b.WriteByte('&')
			i++
			continue
		}
		if entity[0] == '#' {
			if decoded, ok := numericEntity(entity[1:]); ok {
				b.WriteRune(foldFullWidth(decoded))
				i += end + 1
				continue
			}
		} else if decoded, ok := namedEntities[strings.ToLower(entity)]; ok {
			b.WriteString(decoded)
			i += end + 1
			continue
		}
		b.WriteByte('&')
		i++
	}
	return b.String()
}

// numericEntity decodes #NN or #xNN. | numericEntity 解码 #NN 或 #xNN。
func numericEntity(entity string) (rune, bool) {
	base := 10
	if len(entity) > 1 && (entity[0] == 'x' || entity[0] == 'X') {
		base = 16
		entity = entity[1:]
	}
	if entity == "" || len(entity) > 8 {
		return 0, false
	}
	value, err := strconv.ParseUint(entity, base, 32)
	if err != nil || value > utf8.MaxRune {
		return 0, false
	}
	return rune(value), true
}

// namedEntities maps common HTML entities used by attack payloads. | namedEntities 映射攻击载荷
// 常用的 HTML 实体。
var namedEntities = map[string]string{
	"amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'",
	"nbsp": " ", "colon": ":", "lpar": "(", "rpar": ")", "sol": "/",
	"comma": ",", "period": ".", "tab": "\t", "newline": "\n", "lcub": "{",
	"rcub": "}", "semi": ";", "equals": "=", "quest": "?", "plus": "+",
	"percnt": "%", "ast": "*", "excl": "!", "num": "#", "dollar": "$",
	"commat": "@", "hyphen": "-", "lowbar": "_", "verbar": "|", "bsol": "\\",
	"lbrace": "{", "rbrace": "}", "lsqb": "[", "rsqb": "]", "grave": "`",
	"circ": "^", "tilde": "~", "nbsp;": " ",
}

// jsDecode decodes JavaScript string escapes. | jsDecode 解码 JavaScript 字符串转义。
func jsDecode(s string) string {
	if !strings.ContainsAny(s, "\\%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == '%' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if value, ok := parseHex(s[i+2 : i+6]); ok {
				b.WriteRune(rune(value))
				i += 6
				continue
			}
		}
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		next := s[i+1]
		switch next {
		case 'x', 'X':
			if i+3 < len(s) {
				if value, ok := parseHex(s[i+2 : i+4]); ok {
					b.WriteByte(byte(value))
					i += 4
					continue
				}
			}
		case 'u', 'U':
			if i+2 < len(s) && s[i+2] == '{' {
				end := strings.IndexByte(s[i+3:], '}')
				if end > 0 {
					if value, ok := parseHex(s[i+3 : i+3+end]); ok && value <= utf8.MaxRune {
						b.WriteRune(rune(value))
						i += 3 + end + 1
						continue
					}
				}
			}
			if i+5 < len(s) {
				if value, ok := parseHex(s[i+2 : i+6]); ok {
					r := rune(value)
					if r >= 0xD800 && r <= 0xDBFF && i+11 < len(s) && s[i+6] == '\\' && (s[i+7] == 'u' || s[i+7] == 'U') {
						if low, ok := parseHex(s[i+8 : i+12]); ok && low >= 0xDC00 && low <= 0xDFFF {
							r = 0x10000 + (r-0xD800)<<10 + (rune(low) - 0xDC00)
							b.WriteRune(r)
							i += 12
							continue
						}
					}
					b.WriteRune(r)
					i += 6
					continue
				}
			}
		case '0':
			b.WriteByte(0)
			i += 2
			continue
		case 'n':
			b.WriteByte('\n')
			i += 2
			continue
		case 'r':
			b.WriteByte('\r')
			i += 2
			continue
		case 't':
			b.WriteByte('\t')
			i += 2
			continue
		case 'b':
			b.WriteByte('\b')
			i += 2
			continue
		case 'f':
			b.WriteByte('\f')
			i += 2
			continue
		case 'v':
			b.WriteByte('\v')
			i += 2
			continue
		case '\\', '\'', '"', '/':
			b.WriteByte(next)
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// cssDecode decodes CSS hexadecimal escapes. | cssDecode 解码 CSS 十六进制转义。
func cssDecode(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		i++
		if i >= len(s) {
			break
		}
		if s[i] == '\n' {
			i++
			continue
		}
		start := i
		for i < len(s) && i-start < 6 && hexDigit(s[i]) >= 0 {
			i++
		}
		if i > start {
			value, _ := parseHex(s[start:i])
			if value > 0 && value <= utf8.MaxRune {
				b.WriteRune(rune(value))
			}
			if i < len(s) && isSpaceByte(s[i]) {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// escapeSeqDecode decodes C-style escape sequences. | escapeSeqDecode 解码 C 风格转义序列。
func escapeSeqDecode(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		switch next {
		case 'x', 'X':
			if i+3 < len(s) {
				if value, ok := parseHex(s[i+2 : i+4]); ok {
					b.WriteByte(byte(value))
					i += 3
					continue
				}
			}
		case 'u', 'U':
			if i+5 < len(s) {
				if value, ok := parseHex(s[i+2 : i+6]); ok {
					b.WriteRune(rune(value))
					i += 5
					continue
				}
			}
		case 'n':
			b.WriteByte('\n')
			i++
			continue
		case 'r':
			b.WriteByte('\r')
			i++
			continue
		case 't':
			b.WriteByte('\t')
			i++
			continue
		case 'b':
			b.WriteByte('\b')
			i++
			continue
		case 'f':
			b.WriteByte('\f')
			i++
			continue
		case 'v':
			b.WriteByte('\v')
			i++
			continue
		case '0', '1', '2', '3', '4', '5', '6', '7':
			start := i + 1
			end := start
			for end < len(s) && end-start < 3 && s[end] >= '0' && s[end] <= '7' {
				end++
			}
			value, _ := strconv.ParseUint(s[start:end], 8, 8)
			b.WriteByte(byte(value))
			i = end - 1
			continue
		case '\\', '\'', '"':
			b.WriteByte(next)
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// utf8toUnicode renders non-ASCII runes as %uXXXX (or a surrogate pair). | utf8toUnicode 把非
// ASCII 符文渲染为 %uXXXX（或代理对）。
func utf8toUnicode(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		if r <= 0xFFFF {
			b.WriteString("%u")
			b.WriteString(padHex4(uint16(r)))
			continue
		}
		r -= 0x10000
		high := uint16(0xD800 + (r >> 10))
		low := uint16(0xDC00 + (r & 0x3FF))
		b.WriteString("%u")
		b.WriteString(padHex4(high))
		b.WriteString("%u")
		b.WriteString(padHex4(low))
	}
	return b.String()
}

// padHex4 renders a 16-bit value as four uppercase hexadecimal digits. | padHex4 把 16 位值渲染为
// 四位大写十六进制。
func padHex4(value uint16) string {
	const digits = "0123456789ABCDEF"
	var out [4]byte
	out[0] = digits[(value>>12)&0xF]
	out[1] = digits[(value>>8)&0xF]
	out[2] = digits[(value>>4)&0xF]
	out[3] = digits[value&0xF]
	return string(out[:])
}

// normalizePath removes duplicate slashes and resolves . and .. segments without touching
// percent escapes. | normalizePath 去除重复斜杠并解析 . 与 .. 段，不处理百分号转义。
func normalizePath(s string) string {
	return cleanPath(s, false)
}

// normalizePathWin also converts backslashes to slashes before cleaning. | normalizePathWin 先
// 把反斜杠转换为斜杠再清理。
func normalizePathWin(s string) string {
	return cleanPath(s, true)
}

// cleanPath implements path cleaning that preserves a trailing slash. | cleanPath 实现保留尾部
// 斜杠的路径清理。
func cleanPath(s string, windows bool) string {
	if s == "" {
		return s
	}
	if windows {
		s = strings.ReplaceAll(s, "\\", "/")
	}
	trailing := strings.HasSuffix(s, "/")
	leading := strings.HasPrefix(s, "/")
	segments := strings.Split(s, "/")
	out := make([]string, 0, len(segments))
	for _, segment := range segments {
		switch segment {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		default:
			out = append(out, segment)
		}
	}
	result := strings.Join(out, "/")
	if leading {
		result = "/" + result
	}
	if trailing && result != "/" {
		result += "/"
	}
	if result == "" {
		return "/"
	}
	return result
}

// sqlHexDecode decodes a 0x-prefixed hexadecimal token. | sqlHexDecode 解码 0x 前缀十六进制标记。
func sqlHexDecode(s string) string {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 3 || trimmed[0] != '0' || (trimmed[1] != 'x' && trimmed[1] != 'X') {
		return s
	}
	decoded, err := hex.DecodeString(trimmed[2:])
	if err != nil {
		return s
	}
	return string(decoded)
}

// base64Decode decodes standard Base64, returning the input on failure. | base64Decode 解码标准
// Base64，失败时返回原值。
func base64Decode(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return s
		}
	}
	return string(decoded)
}

// base64DecodeExt decodes standard, URL-safe, padded and unpadded Base64 after removing
// whitespace. | base64DecodeExt 去除空白后解码标准、URL 安全、带填充与无填充 Base64。
func base64DecodeExt(s string) string {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
	if strings.ContainsAny(clean, "-_") {
		if decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(clean, "=")); err == nil {
			return string(decoded)
		}
		if decoded, err := base64.URLEncoding.DecodeString(clean); err == nil {
			return string(decoded)
		}
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "=")); err == nil {
		return string(decoded)
	}
	if decoded, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return string(decoded)
	}
	return s
}

// base64Encode encodes standard Base64. | base64Encode 编码标准 Base64。
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// hexDecode decodes hexadecimal, returning the input when malformed. | hexDecode 解码十六进制，
// 格式错误时返回原值。
func hexDecode(s string) string {
	decoded, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return s
	}
	return string(decoded)
}

// hexEncode encodes lowercase hexadecimal. | hexEncode 编码小写十六进制。
func hexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

// urlEncode percent-encodes every byte outside the unreserved set. | urlEncode 对非保留字符集之外的
// 每个字节进行百分号编码。
func urlEncode(s string) string {
	const digits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(digits[c>>4])
		b.WriteByte(digits[c&0xF])
	}
	return b.String()
}
