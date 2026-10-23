//go:build !jsonx_std

// Fast decimal-to-float64 conversion by unrounded scaling. | 通过非舍入缩放实现的快速十进制到
// float64 转换。
//
// The scaling algorithm and the 128-bit power-of-ten table are adapted from the Go standard
// library's internal/strconv package (BSD-3-Clause); see
// https://research.swtch.com/fp and https://go.googlesource.com/go/+/refs/tags/go1.27.1/src/internal/strconv/uscale.go.
// | 缩放算法与 128 位 10 的幂表改编自 Go 标准库 internal/strconv 包（BSD-3-Clause）；
// 参见上述链接。

package json

import (
	"math"
	"math/bits"
	"strconv"
)

// bool2 converts b to 1 or 0. | bool2 把 b 转换为 1 或 0。
func bool2[T ~int | ~uint32 | ~uint64](b bool) T {
	if b {
		return 1
	}
	return 0
}

// pack64Fast packs a 53-bit mantissa and binary exponent into a float64. It reports false when the
// value overflows to infinity so the caller can defer to strconv and keep ErrRange semantics. |
// pack64Fast 把 53 位尾数与二进制指数打包成 float64；值上溢为无穷时返回 false，让调用方交给
// strconv 以保留 ErrRange 语义。
func pack64Fast(m uint64, e int) (float64, bool) {
	if m&(1<<52) == 0 {
		return math.Float64frombits(m), true
	}
	if e >= 0x7FF-1075 {
		return 0, false
	}
	return math.Float64frombits(m&^(1<<52) | uint64(1075+e)<<52), true
}

// unrounded represents a scaled value carrying two extra rounding bits. | unrounded 表示带两位
// 额外舍入位的缩放值。
type unrounded uint64

// round returns the round-half-to-even rounding of u. | round 返回 u 的银行家舍入结果。
func (u unrounded) round() uint64 { return uint64((u + 1 + (u>>2)&1) >> 2) }

// log2Pow10 returns ⌊x * log₂ 10⌋. | log2Pow10 返回 ⌊x * log₂ 10⌋。
func log2Pow10(x int) int {
	// log₂ 10 ≈ 3.32192809489 ≈ 108853 / 2^15 | log₂ 10 的定点近似
	return (x * 108853) >> 15
}

// pmHiLo represents hi<<64 - lo. | pmHiLo 表示 hi<<64 - lo。
type pmHiLo struct {
	hi uint64
	lo uint64
}

// scaler holds the derived scaling constants for an (e, p) pair. | scaler 保存 (e, p) 对应的
// 派生缩放常量。
type scaler struct {
	pmHi uint64
	pmLo uint64
	s    int
}

// prescale fills pre with the scaling constants for (e, p); lp must equal log2Pow10(p). | prescale
// 用 (e, p) 的缩放常量填充 pre；lp 必须等于 log2Pow10(p)。
func prescale(pre *scaler, e, p, lp int) {
	pre.pmHi = pow10Tab[p-pow10Min].hi
	pre.pmLo = pow10Tab[p-pow10Min].lo
	pre.s = -(e + lp + 3)
}

// uscale returns unrounded(x * 2**e * 10**p). x must be left-justified so its high bit is set,
// pre must come from prescale, and pre.s must be below 64. | uscale 返回 unrounded(x * 2**e * 10**p)。
// x 必须左对齐使最高位为 1，pre 必须由 prescale 生成，且 pre.s 必须小于 64。
func uscale(x uint64, c *scaler) unrounded {
	hi, mid := bits.Mul64(x, c.pmHi)
	s := c.s & 63
	if hi>>s<<s != hi {
		return unrounded(hi>>s | 1)
	}
	mid2, _ := bits.Mul64(x, c.pmLo)
	hi -= bool2[uint64](mid < mid2)
	return unrounded(hi>>s | bool2[uint64](mid-mid2 > 1))
}

// unmin returns the minimum unrounded value that rounds to x. | unmin 返回可舍入到 x 的最小
// unrounded 值。
func unmin(x uint64) unrounded {
	return unrounded(x<<2 - 2)
}

// parseFloat64Fast rounds d * 10**p to the nearest float64 and applies sign. d must have at most
// 19 digits. It reports false when the result overflows, leaving ErrRange handling to strconv. |
// parseFloat64Fast 把 d * 10**p 舍入为最近的 float64 并施加符号；d 最多 19 位。结果上溢时返回
// false，把 ErrRange 处理留给 strconv。
func parseFloat64Fast(d uint64, p int, sign uint64) (float64, bool) {
	if d == 0 {
		return math.Float64frombits(sign), true
	}
	// Mirror the range guards of the standard library fast path: beyond these bounds every value
	// either underflows to zero or overflows to infinity. | 与标准库快速路径的范围守卫一致：
	// 超出这些边界时，所有值要么下溢为零，要么上溢为无穷。
	if p > 310 {
		return 0, false
	}
	if p < -345 {
		return math.Float64frombits(sign), true
	}
	b := bits.Len64(d)
	lp := log2Pow10(p)
	e := min(1074, 53-b-lp)
	var pre scaler
	prescale(&pre, e-(64-b), p, lp)
	if pre.s >= 64 {
		return math.Float64frombits(sign), true
	}
	u := uscale(d<<(64-b), &pre)

	// Branch-free form of: if u.round() >= 1<<53 { u = u.rsh(1); e-- }. | 以下无分支代码等价于
	// 该条件块。
	s := bool2[int](u >= unmin(1<<53))
	u = u>>s | u&1
	e -= s

	return pack64Fast(sign|u.round(), -e)
}

// parseDecimalFloat converts a decimal literal to float64 using unrounded scaling. The literal
// must follow JSON number syntax. When more than 19 significant digits are present, the first 19
// are converted twice (d and d+1); if both round to the same float the tail cannot change the
// result. Otherwise it reports false so the caller uses strconv, which performs exact conversion. |
// parseDecimalFloat 使用非舍入缩放把十进制字面量转换为 float64；字面量必须符合 JSON 数字语法。
// 有效数字超过 19 位时，对前 19 位分别按 d 与 d+1 转换两次；若两者舍入到同一个 float，尾部数字
// 就无法改变结果。否则返回 false，由调用方交给执行精确转换的 strconv。
func parseDecimalFloat(b []byte) (float64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var sign uint64
	if b[0] == '-' {
		sign = 1 << 63
		b = b[1:]
	}
	if len(b) == 0 {
		return 0, false
	}

	var d uint64
	nd, ndMant, dp := 0, 0, 0
	sawDot, sawDigit, trunc := false, false, false
	i := 0
	for ; i < len(b); i++ {
		c := b[i]
		if c == '.' {
			if sawDot {
				return 0, false
			}
			sawDot = true
			dp = nd
			continue
		}
		if c < '0' || c > '9' {
			break
		}
		sawDigit = true
		if c == '0' && nd == 0 {
			dp--
			continue
		}
		nd++
		if ndMant < 19 {
			d = d*10 + uint64(c-'0')
			ndMant++
		} else if c != '0' {
			trunc = true
		}
	}
	if !sawDigit {
		return 0, false
	}
	if !sawDot {
		dp = nd
	}

	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		esign := 1
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			if b[i] == '-' {
				esign = -1
			}
			i++
		}
		expStart := i
		e := 0
		for ; i < len(b) && b[i] >= '0' && b[i] <= '9'; i++ {
			if e < 10000 {
				e = e*10 + int(b[i]-'0')
			}
		}
		if i == expStart {
			return 0, false
		}
		dp += e * esign
	}
	if i != len(b) {
		return 0, false
	}
	if d == 0 {
		return math.Float64frombits(sign), true
	}
	return convertDecimalDigits(d, dp-ndMant, sign, trunc)
}

// parseDecimalOrFloat64 converts a valid JSON number that missed the short-decimal envelope. It
// tries unrounded scaling first and falls back to strconv only when the truncated tail can change
// the rounding or the value overflows. Keeping this fallback out of the field decoder's closure
// preserves the short path's frame and code layout. | parseDecimalOrFloat64 转换未落入精确短十进制
// 范围的合法 JSON 数字：先尝试非舍入缩放，仅在截断尾部可能改变舍入或值溢出时回退 strconv。把该
// 回退放在字段解码闭包之外，可保持短路径的栈帧与代码布局不变。
func parseDecimalOrFloat64(b []byte) (float64, error) {
	if f, ok := parseDecimalFloat(b); ok {
		return f, nil
	}
	return strconv.ParseFloat(bytesString(b), 64)
}

// convertDecimalDigits converts d * 10**p, where d holds up to 19 significant digits. When digits
// were truncated from the literal, d and d+1 are both converted; if they round to the same float,
// the truncated tail cannot change the result and the value is returned. Otherwise it reports false
// so the caller uses strconv's exact conversion. | convertDecimalDigits 转换 d * 10**p，其中 d 最多
// 19 位有效数字。字面量存在被截断的数字时，同时转换 d 与 d+1；若两者舍入到同一个 float，截断尾部
// 就无法改变结果，直接返回该值；否则返回 false，由调用方使用 strconv 的精确转换。
func convertDecimalDigits(d uint64, p int, sign uint64, trunc bool) (float64, bool) {
	f, ok := parseFloat64Fast(d, p, sign)
	if !ok {
		return 0, false
	}
	if !trunc {
		return f, true
	}
	// If d and d+1 round to the same float, every value in [d, d+1) does too. | 若 d 与 d+1
	// 舍入到同一个 float，则 [d, d+1) 内的所有值也一样。
	f1, ok := parseFloat64Fast(d+1, p, sign)
	if ok && f == f1 {
		return f, true
	}
	return 0, false
}
