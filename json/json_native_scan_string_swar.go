//go:build (amd64 || arm64) && !jsonx_std && (!goexperiment.simd || amd64)

package json

import (
	"encoding/binary"
	"unsafe"
)

// scanStringBody finds the closing quote of a string body with 8-byte SWAR words and hands the
// tail to scanStringBodyTail. | scanStringBody 用 8 字节 SWAR 字查找字符串体的结束引号，尾部
// 交给 scanStringBodyTail。
func scanStringBody(data []byte, start int) (end int, slow bool, nonASCII bool) {
	i := start
	var high uint64
	for len(data)-i >= 8 {
		x := binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(data[i:]), 8))
		high |= x
		if wordHasZero(x^wordQuote) || wordHasZero(x^wordBackslash) || wordHasControl(x) {
			for j := 0; j < 8; j++ {
				c := data[i+j]
				if c == '"' {
					return i + j, false, high&wordHi != 0
				}
				if c == '\\' || c < 0x20 {
					return 0, true, false
				}
			}
		}
		i += 8
	}
	return scanStringBodyTail(data, i, high&wordHi != 0)
}

// jsonStringNeedsEscape reports whether s needs JSON escaping, using the same 8/4/1-byte SWAR
// scan as the encoder. | jsonStringNeedsEscape 用与编码器相同的 8/4/1 字节 SWAR 扫描判断 s
// 是否需要 JSON 转义。
func jsonStringNeedsEscape(s string, escapeHTML bool) bool {
	i := 0
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
