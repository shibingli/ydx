//go:build !xml_std

package xml

import "encoding/binary"

// indexByteFunc scans for one byte from start and returns its index, or -1. | indexByteFunc
// 从 start 起扫描一个字节并返回下标，未找到返回 -1。
type indexByteFunc func(data []byte, start int, c byte) int

// indexAny2Func scans for either of two bytes from start and returns the first index, or -1. |
// indexAny2Func 从 start 起扫描两个字节中的任意一个并返回首个下标，未找到返回 -1。
type indexAny2Func func(data []byte, start int, c1, c2 byte) int

// indexAny3Func scans for any of three bytes from start and returns the first index, or -1. |
// indexAny3Func 从 start 起扫描三个字节中的任意一个并返回首个下标，未找到返回 -1。
type indexAny3Func func(data []byte, start int, c1, c2, c3 byte) int

// indexAny4Func scans for any of four bytes from start and returns the first index, or -1. |
// indexAny4Func 从 start 起扫描四个字节中的任意一个并返回首个下标，未找到返回 -1。
type indexAny4Func func(data []byte, start int, c1, c2, c3, c4 byte) int

// The scan variables hold the active kernels. Architecture-specific init functions replace the
// portable defaults when a wider instruction set is available. | 这些变量持有当前生效的扫描内核；
// 架构相关的 init 在更宽指令集可用时替换可移植默认实现。
var (
	scanIndexByte indexByteFunc = indexByteSWAR
	scanIndexAny2 indexAny2Func = indexAny2SWAR
	scanIndexAny3 indexAny3Func = indexAny3SWAR
	scanIndexAny4 indexAny4Func = indexAny4SWAR
)

func init() {
	if forceScalar {
		scanIndexByte = indexByteScalar
		scanIndexAny2 = indexAny2Scalar
		scanIndexAny3 = indexAny3Scalar
		scanIndexAny4 = indexAny4Scalar
	}
}

func indexByteAt(data []byte, start int, c byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	return scanIndexByte(data, start, c)
}

func indexAny2At(data []byte, start int, c1, c2 byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	return scanIndexAny2(data, start, c1, c2)
}

func indexAny3At(data []byte, start int, c1, c2, c3 byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	return scanIndexAny3(data, start, c1, c2, c3)
}

func indexAny4At(data []byte, start int, c1, c2, c3, c4 byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	return scanIndexAny4(data, start, c1, c2, c3, c4)
}

// repeatByte builds the 64-bit word whose eight bytes all equal c. | repeatByte 构造八个字节均为
// c 的 64 位字。
func repeatByte(c byte) uint64 {
	return uint64(c) * 0x0101010101010101
}

// zeroByteMask marks the zero bytes of x with 0x80 in the corresponding byte. | zeroByteMask 用
// 每字节的 0x80 标记 x 中的零字节。
func zeroByteMask(x uint64) uint64 {
	return (x - 0x0101010101010101) &^ x & 0x8080808080808080
}

func indexByteSWAR(data []byte, start int, c byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	pat := repeatByte(c)
	i := start
	for len(data)-i >= 8 {
		x := binary.LittleEndian.Uint64(data[i:])
		if zeroByteMask(x^pat) != 0 {
			for j := 0; j < 8; j++ {
				if data[i+j] == c {
					return i + j
				}
			}
		}
		i += 8
	}
	for ; i < len(data); i++ {
		if data[i] == c {
			return i
		}
	}
	return -1
}

func indexAny2SWAR(data []byte, start int, c1, c2 byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	p1, p2 := repeatByte(c1), repeatByte(c2)
	i := start
	for len(data)-i >= 8 {
		x := binary.LittleEndian.Uint64(data[i:])
		if zeroByteMask(x^p1)|zeroByteMask(x^p2) != 0 {
			for j := 0; j < 8; j++ {
				b := data[i+j]
				if b == c1 || b == c2 {
					return i + j
				}
			}
		}
		i += 8
	}
	for ; i < len(data); i++ {
		if data[i] == c1 || data[i] == c2 {
			return i
		}
	}
	return -1
}

func indexAny3SWAR(data []byte, start int, c1, c2, c3 byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	p1, p2, p3 := repeatByte(c1), repeatByte(c2), repeatByte(c3)
	i := start
	for len(data)-i >= 8 {
		x := binary.LittleEndian.Uint64(data[i:])
		if zeroByteMask(x^p1)|zeroByteMask(x^p2)|zeroByteMask(x^p3) != 0 {
			for j := 0; j < 8; j++ {
				b := data[i+j]
				if b == c1 || b == c2 || b == c3 {
					return i + j
				}
			}
		}
		i += 8
	}
	for ; i < len(data); i++ {
		b := data[i]
		if b == c1 || b == c2 || b == c3 {
			return i
		}
	}
	return -1
}

func indexAny4SWAR(data []byte, start int, c1, c2, c3, c4 byte) int {
	if start < 0 {
		start = 0
	}
	if start >= len(data) {
		return -1
	}
	p1, p2, p3, p4 := repeatByte(c1), repeatByte(c2), repeatByte(c3), repeatByte(c4)
	i := start
	for len(data)-i >= 8 {
		x := binary.LittleEndian.Uint64(data[i:])
		if zeroByteMask(x^p1)|zeroByteMask(x^p2)|zeroByteMask(x^p3)|zeroByteMask(x^p4) != 0 {
			for j := 0; j < 8; j++ {
				b := data[i+j]
				if b == c1 || b == c2 || b == c3 || b == c4 {
					return i + j
				}
			}
		}
		i += 8
	}
	for ; i < len(data); i++ {
		b := data[i]
		if b == c1 || b == c2 || b == c3 || b == c4 {
			return i
		}
	}
	return -1
}

func indexByteScalar(data []byte, start int, c byte) int {
	for i := start; i < len(data); i++ {
		if data[i] == c {
			return i
		}
	}
	return -1
}

func indexAny2Scalar(data []byte, start int, c1, c2 byte) int {
	for i := start; i < len(data); i++ {
		b := data[i]
		if b == c1 || b == c2 {
			return i
		}
	}
	return -1
}

func indexAny3Scalar(data []byte, start int, c1, c2, c3 byte) int {
	for i := start; i < len(data); i++ {
		b := data[i]
		if b == c1 || b == c2 || b == c3 {
			return i
		}
	}
	return -1
}

func indexAny4Scalar(data []byte, start int, c1, c2, c3, c4 byte) int {
	for i := start; i < len(data); i++ {
		b := data[i]
		if b == c1 || b == c2 || b == c3 || b == c4 {
			return i
		}
	}
	return -1
}
