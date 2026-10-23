//go:build !jsonx_std

package json

import (
	"encoding/binary"
	"unsafe"
)

// jsonStringNeedsEscapeTail scans s from i with 8/4/1-byte SWAR words and the escape tables. |
// jsonStringNeedsEscapeTail 从 i 开始用 8/4/1 字节 SWAR 字与转义表扫描 s。
func jsonStringNeedsEscapeTail(s string, i int, escapeHTML bool) bool {
	for len(s)-i >= 8 {
		x := binary.LittleEndian.Uint64(unsafe.Slice(unsafe.StringData(s[i:]), 8))
		if x&wordHi != 0 || wordHasControl(x) ||
			wordHasZero(x^wordQuote) || wordHasZero(x^wordBackslash) ||
			(escapeHTML && (wordHasZero(x^wordLessThan) || wordHasZero(x^wordGreater) || wordHasZero(x^wordAmpersand))) {
			return true
		}
		i += 8
	}
	for len(s)-i >= 4 {
		x := binary.LittleEndian.Uint32(unsafe.Slice(unsafe.StringData(s[i:]), 4))
		if x&0x80808080 != 0 || wordHasControl32(x) ||
			wordHasZero32(x^wordQuote32) || wordHasZero32(x^wordBackslash32) ||
			(escapeHTML && (wordHasZero32(x^wordLessThan32) || wordHasZero32(x^wordGreater32) || wordHasZero32(x^wordAmpersand32))) {
			return true
		}
		i += 4
	}
	if escapeHTML {
		for ; i < len(s); i++ {
			if escapeTableHTML[s[i]] {
				return true
			}
		}
	} else {
		for ; i < len(s); i++ {
			if escapeTablePlain[s[i]] {
				return true
			}
		}
	}
	return false
}
