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
