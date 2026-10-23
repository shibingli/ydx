//go:build !jsonx_std

package json

import (
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"testing"
)

// TestParseDecimalFloatMatchesStrconv verifies the unrounded-scaling path is bit-identical to
// strconv.ParseFloat for every literal it accepts, including subnormals, overflow boundaries and
// literals with more than 19 significant digits. | TestParseDecimalFloatMatchesStrconv 验证
// 非舍入缩放路径对每个接受的字符串都与 strconv.ParseFloat 位级一致，包括次正规数、溢出边界
// 以及超过 19 位有效数字的字面量。
func TestParseDecimalFloatMatchesStrconv(t *testing.T) {
	cases := []string{
		"0", "-0", "0.0", "-0.0", "1", "-1", "1.5", "-1.5", "0.1", "-0.1",
		"98.5", "2.675", "1.005", "123456789012345", "123456789012345.6",
		"0.000001", "0.0000000000000001", "9007199254740991",
		"2.3333333333333335", "0.30000000000000004", "4503599627370497.5",
		"1234567890123456789", "12345678901234567890", "9999999999999999999",
		"0.000000000000000000000123", "1.00000000000000000001",
		"123456789012345678901234567890", "0.1000000000000000000000000000001",
		"1e0", "1e5", "-1.5e-7", "1.7976931348623157e308", "2.2250738585072014e-308",
		"5e-324", "2.5e-324", "1e-323", "1e-400", "-1e-400", "0e999",
		"1234567890123456789e-320", "1234567890123456789e300",
	}
	for _, s := range cases {
		got, ok := parseDecimalFloat([]byte(s))
		want, err := strconv.ParseFloat(s, 64)
		if err != nil {
			if ok {
				t.Fatalf("parseDecimalFloat(%q) accepted an out-of-range literal | 接受了越界字面量", s)
			}
			continue
		}
		if !ok {
			t.Fatalf("parseDecimalFloat(%q) rejected a in-range literal | 拒绝了范围内字面量", s)
		}
		if math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("parseDecimalFloat(%q) = %v (%016x), want %v (%016x)",
				s, got, math.Float64bits(got), want, math.Float64bits(want))
		}
	}

	// Overflowing literals must be rejected so the caller keeps strconv's ErrRange behavior. |
	// 溢出字面量必须被拒绝，让调用方保留 strconv 的 ErrRange 行为。
	for _, s := range []string{"1e309", "-1e309", "1.7976931348623159e308", "9999999999999999999e291"} {
		if _, ok := parseDecimalFloat([]byte(s)); ok {
			t.Fatalf("parseDecimalFloat(%q) should defer overflow to strconv | 应把溢出交给 strconv", s)
		}
	}
}

// TestParseDecimalFloatRandomMatchesStrconv compares the fast path with strconv on deterministic
// random decimal literals, including truncated mantissas with up to 30 significant digits. |
// TestParseDecimalFloatRandomMatchesStrconv 在确定性随机十进制字面量上与 strconv 对比，
// 覆盖最多 30 位有效数字的截断尾数。
func TestParseDecimalFloatRandomMatchesStrconv(t *testing.T) {
	rng := rand.New(rand.NewSource(20261023))
	accepted := 0
	for range 200000 {
		nd := 1 + rng.Intn(30)
		buf := make([]byte, 0, nd+12)
		if rng.Intn(2) == 0 {
			buf = append(buf, '-')
		}
		digits := make([]byte, nd)
		digits[0] = byte('1' + rng.Intn(9))
		for j := 1; j < nd; j++ {
			digits[j] = byte('0' + rng.Intn(10))
		}
		dot := rng.Intn(nd + 1)
		buf = append(buf, digits[:dot]...)
		if dot < nd || rng.Intn(4) == 0 {
			buf = append(buf, '.')
			buf = append(buf, digits[dot:]...)
		}
		if rng.Intn(2) == 0 {
			e := rng.Intn(701) - 350
			buf = append(buf, 'e')
			buf = fmt.Appendf(buf, "%+d", e)
		}
		if _, err := strconv.ParseFloat(string(buf), 64); err != nil {
			continue
		}
		got, ok := parseDecimalFloat(buf)
		if !ok {
			continue
		}
		want, _ := strconv.ParseFloat(string(buf), 64)
		if math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("parseDecimalFloat(%q) = %v (%016x), want %v (%016x)",
				buf, got, math.Float64bits(got), want, math.Float64bits(want))
		}
		accepted++
	}
	if accepted < 50000 {
		t.Fatalf("fast path accepted only %d literals | 快速路径仅接受 %d 个字面量", accepted, accepted)
	}
}
