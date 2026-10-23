//go:build !jsonx_std && !amd64 && !arm64

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
