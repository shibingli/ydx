package xml

import (
	"unicode"
	"unicode/utf8"
)

// isInCharacterRange reports whether r is in the XML Character production. | isInCharacterRange
// 判断 r 是否位于 XML Character 产生式范围内。
func isInCharacterRange(r rune) bool {
	return r == 0x09 || r == 0x0A || r == 0x0D ||
		r >= 0x20 && r <= 0xD7FF ||
		r >= 0xE000 && r <= 0xFFFD ||
		r >= 0x10000 && r <= 0x10FFFF
}

// isNameBytes reports whether s is a valid XML Name. | isNameBytes 判断 s 是否为合法的 XML 名称。
func isNameBytes(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	r, n := utf8.DecodeRune(s)
	if r == utf8.RuneError && n == 1 {
		return false
	}
	if !unicode.Is(first, r) {
		return false
	}
	for n < len(s) {
		s = s[n:]
		r, n = utf8.DecodeRune(s)
		if r == utf8.RuneError && n == 1 {
			return false
		}
		if !unicode.Is(first, r) && !unicode.Is(second, r) {
			return false
		}
	}
	return true
}

// isNameString reports whether s is a valid XML Name. | isNameString 判断 s 是否为合法的 XML 名称。
func isNameString(s string) bool {
	if len(s) == 0 {
		return false
	}
	r, n := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && n == 1 {
		return false
	}
	if !unicode.Is(first, r) {
		return false
	}
	for n < len(s) {
		s = s[n:]
		r, n = utf8.DecodeRuneInString(s)
		if r == utf8.RuneError && n == 1 {
			return false
		}
		if !unicode.Is(first, r) && !unicode.Is(second, r) {
			return false
		}
	}
	return true
}
