//go:build (amd64 || arm64) && !jsonx_std

package json

import (
	"encoding/binary"
	"unsafe"
)

// scanStringBodyTail finishes a string-body scan from start after the wide-word loop and returns
// the closing quote index, whether the slow parser is required, and whether any byte is
// non-ASCII. The nonASCII seed carries the result of the preceding wide loop. | scanStringBodyTail
// 在宽字循环之后从 start 继续扫描字符串体，返回结束引号下标、是否需要慢速解析器，以及是否
// 出现非 ASCII 字节；nonASCII 种子承接前面宽字循环的结果。
func scanStringBodyTail(data []byte, start int, nonASCII bool) (int, bool, bool) {
	i := start
	var high uint64
	for len(data)-i >= 4 {
		x := binary.LittleEndian.Uint32(unsafe.Slice(unsafe.SliceData(data[i:]), 4))
		high |= uint64(x)
		if wordHasZero32(x^wordQuote32) || wordHasZero32(x^wordBackslash32) || wordHasControl32(x) {
			for j := 0; j < 4; j++ {
				c := data[i+j]
				if c == '"' {
					return i + j, false, nonASCII || high&wordHi != 0
				}
				if c == '\\' || c < 0x20 {
					return 0, true, false
				}
			}
		}
		i += 4
	}
	for ; i < len(data); i++ {
		c := data[i]
		if c == '"' {
			return i, false, nonASCII || high&wordHi != 0
		}
		if c == '\\' || c < 0x20 {
			return 0, true, false
		}
		high |= uint64(c)
	}
	return 0, true, false
}
