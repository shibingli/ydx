//go:build !jsonx_std && (!arm64 || !goexperiment.simd)

package json

import (
	"encoding/binary"
	"unsafe"
)

// appendJSONString appends one JSON string literal to buf. The clean path scans with 8/4/1-byte
// SWAR words and appends the whole string at once; the slow path escapes rune by rune. |
// appendJSONString 把单个 JSON 字符串字面量追加到 buf。干净路径用 8/4/1 字节 SWAR 字扫描并
// 一次性追加整个字符串；慢路径逐 rune 转义。
func appendJSONString(buf []byte, s string, escapeHTML bool) []byte {
	i := 0
	for len(s)-i >= 8 {
		x := binary.LittleEndian.Uint64(unsafe.Slice(unsafe.StringData(s[i:]), 8))
		if x&wordHi != 0 || wordHasControl(x) ||
			wordHasZero(x^wordQuote) || wordHasZero(x^wordBackslash) ||
			(escapeHTML && (wordHasZero(x^wordLessThan) || wordHasZero(x^wordGreater) || wordHasZero(x^wordAmpersand))) {
			goto slow
		}
		i += 8
	}
	for len(s)-i >= 4 {
		x := binary.LittleEndian.Uint32(unsafe.Slice(unsafe.StringData(s[i:]), 4))
		if x&0x80808080 != 0 || wordHasControl32(x) ||
			wordHasZero32(x^wordQuote32) || wordHasZero32(x^wordBackslash32) ||
			(escapeHTML && (wordHasZero32(x^wordLessThan32) || wordHasZero32(x^wordGreater32) || wordHasZero32(x^wordAmpersand32))) {
			goto slow
		}
		i += 4
	}
	if escapeHTML {
		for ; i < len(s); i++ {
			if escapeTableHTML[s[i]] {
				goto slow
			}
		}
	} else {
		for ; i < len(s); i++ {
			if escapeTablePlain[s[i]] {
				goto slow
			}
		}
	}
	buf = append(buf, '"')
	buf = append(buf, s...)
	buf = append(buf, '"')
	return buf
slow:
	return appendJSONStringSlow(buf, s, escapeHTML)
}
