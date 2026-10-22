//go:build arm64 && goexperiment.simd && !jsonx_std

package json

import (
	"simd/archsimd"
	"unsafe"
)

// scanStringBody finds the closing quote of a string body. Long inputs use the NEON block scan;
// short inputs stay on the scalar tail, so short strings pay no vector setup. | scanStringBody
// 查找字符串体的结束引号；长输入使用 NEON 块扫描，短输入走标量尾部，避免短字符串的向量开销。
func scanStringBody(data []byte, start int) (int, bool, bool) {
	if len(data)-start >= 16 {
		return scanStringBodyNEON(data, start)
	}
	return scanStringBodyTail(data, start, false)
}

// scanStringBodyNEON scans complete 16-byte blocks for a quote, backslash or control byte, then
// hands the tail to scanStringBodyTail. | scanStringBodyNEON 按 16 字节块扫描引号、反斜杠或控制
// 字节，尾部交给 scanStringBodyTail。
func scanStringBodyNEON(data []byte, start int) (int, bool, bool) {
	i := start
	quote := archsimd.BroadcastUint8x16('"')
	backslash := archsimd.BroadcastUint8x16('\\')
	space := archsimd.BroadcastUint8x16(0x20)
	high := archsimd.BroadcastUint8x16(0x80)
	highAcc := archsimd.BroadcastUint8x16(0)
	for len(data)-i >= 16 {
		v := archsimd.LoadUint8x16(data[i : i+16])
		highAcc = highAcc.Or(v)
		special := v.Equal(quote).Or(v.Equal(backslash)).Or(v.Less(space))
		if special.ToInt8x16().ReduceMin() != 0 {
			nonASCII := highAcc.GreaterEqual(high).ToInt8x16().ReduceMin() == -1
			for j := 0; j < 16; j++ {
				c := data[i+j]
				if c == '"' {
					return i + j, false, nonASCII
				}
				if c == '\\' || c < 0x20 {
					return 0, true, false
				}
			}
		}
		i += 16
	}
	nonASCII := highAcc.GreaterEqual(high).ToInt8x16().ReduceMin() == -1
	return scanStringBodyTail(data, i, nonASCII)
}

// jsonStringNeedsEscape reports whether s needs JSON escaping. Long strings use the NEON block
// scan; short strings use the escape tables directly. | jsonStringNeedsEscape 判断 s 是否需要
// JSON 转义；长字符串使用 NEON 块扫描，短字符串直接查转义表。
func jsonStringNeedsEscape(s string, escapeHTML bool) bool {
	if len(s) >= 16 {
		return jsonStringNeedsEscapeNEON(s, escapeHTML)
	}
	if escapeHTML {
		for i := 0; i < len(s); i++ {
			if escapeTableHTML[s[i]] {
				return true
			}
		}
	} else {
		for i := 0; i < len(s); i++ {
			if escapeTablePlain[s[i]] {
				return true
			}
		}
	}
	return false
}

// jsonStringNeedsEscapeNEON scans complete 16-byte blocks for bytes that JSON escaping must
// handle. | jsonStringNeedsEscapeNEON 按 16 字节块扫描 JSON 转义必须处理的字节。
func jsonStringNeedsEscapeNEON(s string, escapeHTML bool) bool {
	quote := archsimd.BroadcastUint8x16('"')
	backslash := archsimd.BroadcastUint8x16('\\')
	space := archsimd.BroadcastUint8x16(0x20)
	high := archsimd.BroadcastUint8x16(0x80)
	var lt, gt, amp archsimd.Uint8x16
	if escapeHTML {
		lt = archsimd.BroadcastUint8x16('<')
		gt = archsimd.BroadcastUint8x16('>')
		amp = archsimd.BroadcastUint8x16('&')
	}
	i := 0
	for len(s)-i >= 16 {
		v := archsimd.LoadUint8x16(unsafe.Slice(unsafe.StringData(s[i:]), 16))
		mask := v.Less(space).Or(v.Equal(quote)).Or(v.Equal(backslash)).Or(v.GreaterEqual(high))
		if escapeHTML {
			mask = mask.Or(v.Equal(lt)).Or(v.Equal(gt)).Or(v.Equal(amp))
		}
		if mask.ToInt8x16().ReduceMin() != 0 {
			return true
		}
		i += 16
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

// skipSpaceRun returns the first position at or after pos that is not JSON whitespace. The first
// byte rejects the common compact-JSON case; complete 16-byte whitespace blocks are skipped with
// NEON and mixed blocks fall back to the scalar loop. | skipSpaceRun 返回 pos 之后第一个不是 JSON
// 空白的位置。首字节快速拒绝常见的紧凑 JSON；完整的 16 字节空白块用 NEON 跳过，混合块回退
// 标量循环。
func skipSpaceRun(data []byte, pos int) int {
	if pos >= len(data) {
		return pos
	}
	switch data[pos] {
	case ' ', '\t', '\n', '\r':
	default:
		return pos
	}
	space := archsimd.BroadcastUint8x16(' ')
	tab := archsimd.BroadcastUint8x16('\t')
	nl := archsimd.BroadcastUint8x16('\n')
	cr := archsimd.BroadcastUint8x16('\r')
	for len(data)-pos >= 16 {
		v := archsimd.LoadUint8x16(data[pos : pos+16])
		all := v.Equal(space).Or(v.Equal(tab)).Or(v.Equal(nl)).Or(v.Equal(cr))
		if all.ToInt8x16().ReduceMax() != -1 {
			break
		}
		pos += 16
	}
	for pos < len(data) {
		switch data[pos] {
		case ' ', '\t', '\n', '\r':
			pos++
		default:
			return pos
		}
	}
	return pos
}

// scanDigits returns the first position at or after pos that is not an ASCII digit. The first
// eight digits stay scalar so short numbers pay no vector setup; longer runs use 16-byte blocks.
// | scanDigits 返回 pos 之后第一个不是 ASCII 数字的位置。前 8 位保持标量，避免短数字承担向量
// 初始化开销；更长的数字段使用 16 字节块。
func scanDigits(data []byte, pos int) int {
	n := 0
	for pos < len(data) && n < 8 && data[pos] >= '0' && data[pos] <= '9' {
		pos++
		n++
	}
	if n < 8 {
		return pos
	}
	zero := archsimd.BroadcastUint8x16('0')
	nine := archsimd.BroadcastUint8x16('9')
	for len(data)-pos >= 16 {
		v := archsimd.LoadUint8x16(data[pos : pos+16])
		digits := v.GreaterEqual(zero).And(v.LessEqual(nine))
		if digits.ToInt8x16().ReduceMax() != -1 {
			break
		}
		pos += 16
	}
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		pos++
	}
	return pos
}
