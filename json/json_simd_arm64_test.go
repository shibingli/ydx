//go:build arm64 && goexperiment.simd && !jsonx_std

package json

import (
	"bytes"
	stdjson "encoding/json"
	"math/rand"
	"testing"
)

// TestNEONStringScanBoundaries pins the quote, escape, control and high-byte behaviour at the
// 15/16/17 byte boundaries of the 16-byte NEON block. | TestNEONStringScanBoundaries 固定 16 字节
// NEON 块在 15/16/17 字节边界上的引号、转义、控制字节与高位字节行为。
func TestNEONStringScanBoundaries(t *testing.T) {
	for _, pos := range []int{14, 15, 16, 17, 30, 31, 32, 33} {
		data := bytes.Repeat([]byte{'a'}, 64)
		data[pos] = '"'
		end, slow, nonASCII := scanStringBody(data, 0)
		if slow || end != pos || nonASCII {
			t.Fatalf("quote at %d: end=%d slow=%v nonASCII=%v | 引号位置错误", pos, end, slow, nonASCII)
		}

		data = bytes.Repeat([]byte{'a'}, 64)
		data[pos] = '\\'
		if end, slow, _ := scanStringBody(data, 0); !slow || end != 0 {
			t.Fatalf("backslash at %d: end=%d slow=%v | 反斜杠应走慢路径", pos, end, slow)
		}

		data = bytes.Repeat([]byte{'a'}, 64)
		data[pos] = '\n'
		if end, slow, _ := scanStringBody(data, 0); !slow || end != 0 {
			t.Fatalf("control at %d: end=%d slow=%v | 控制字节应走慢路径", pos, end, slow)
		}

		data = bytes.Repeat([]byte{'a'}, 64)
		data[pos] = 0xE4
		data[50] = '"'
		end, slow, nonASCII = scanStringBody(data, 0)
		if slow || end != 50 || !nonASCII {
			t.Fatalf("high byte at %d: end=%d slow=%v nonASCII=%v | 高位字节应标记非 ASCII", pos, end, slow, nonASCII)
		}
	}
}

// TestNEONScanStringBodyDifferential compares the NEON string-body scan with a scalar reference
// over random and long inputs. | TestNEONScanStringBodyDifferential 在随机与长输入上比较 NEON
// 字符串体扫描与标量参考实现。
func TestNEONScanStringBodyDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))
	for iter := 0; iter < 4000; iter++ {
		n := rnd.Intn(256)
		if iter%10 == 0 {
			n = 1024 + rnd.Intn(4096)
		}
		data := jsonScanData(rnd, n)
		start := 0
		if len(data) > 0 {
			start = rnd.Intn(len(data) + 1)
		}
		gotEnd, gotSlow, gotNon := scanStringBody(data, start)
		wantEnd, wantSlow, wantNon := scanStringBodyRef(data, start)
		if gotEnd != wantEnd || gotSlow != wantSlow {
			t.Fatalf("iter=%d start=%d got=(%d,%v) want=(%d,%v) | NEON 字符串体扫描不一致", iter, start, gotEnd, gotSlow, wantEnd, wantSlow)
		}
		if wantNon && !gotNon {
			t.Fatalf("iter=%d start=%d non-ASCII under-reported | 少报非 ASCII", iter, start)
		}
	}
}

// TestNEONJSONStringNeedsEscapeDifferential compares the NEON escape scan with a scalar reference,
// including long strings and HTML-sensitive bytes. | TestNEONJSONStringNeedsEscapeDifferential
// 在长字符串与 HTML 敏感字节上比较 NEON 转义扫描与标量参考实现。
func TestNEONJSONStringNeedsEscapeDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(12))
	for iter := 0; iter < 4000; iter++ {
		n := rnd.Intn(128)
		if iter%10 == 0 {
			n = 1024 + rnd.Intn(4096)
		}
		data := jsonScanData(rnd, n)
		escapeHTML := rnd.Intn(2) == 0
		if got, want := jsonStringNeedsEscape(string(data), escapeHTML), jsonStringNeedsEscapeRef(string(data), escapeHTML); got != want {
			t.Fatalf("iter=%d html=%v got=%v want=%v | NEON 转义扫描不一致", iter, escapeHTML, got, want)
		}
	}
}

// stdJSONString encodes s with encoding/json using the requested HTML escaping. | stdJSONString 用
// encoding/json 按指定 HTML 转义设置编码 s。
func stdJSONString(t *testing.T, s string, escapeHTML bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := stdjson.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		t.Fatalf("stdlib encode: %v", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// TestNEONAppendJSONStringMatchesStdlib compares the NEON string encoder with encoding/json for
// quotes, escapes, HTML bytes, line separators, multibyte UTF-8 and invalid UTF-8. |
// TestNEONAppendJSONStringMatchesStdlib 对引号、转义、HTML 字节、行分隔符、多字节 UTF-8 与非法
// UTF-8 比较 NEON 字符串编码与 encoding/json。
func TestNEONAppendJSONStringMatchesStdlib(t *testing.T) {
	runes := []rune{
		'a', 'Z', '0', ' ', '"', '\\', '\b', '\f', '\n', '\r', '\t',
		'<', '>', '&', ' ', ' ', 'é', '中', '😀', 0x01,
	}
	rnd := rand.New(rand.NewSource(13))
	check := func(s string) {
		for _, escapeHTML := range []bool{false, true} {
			got := appendJSONString(nil, s, escapeHTML)
			want := stdJSONString(t, s, escapeHTML)
			if !bytes.Equal(got, want) {
				t.Fatalf("html=%v s=%q\ngot:  %q\nwant: %q | NEON 字符串编码不一致", escapeHTML, s, got, want)
			}
		}
	}
	for iter := 0; iter < 4000; iter++ {
		n := rnd.Intn(64)
		var b bytes.Buffer
		for i := 0; i < n; i++ {
			b.WriteRune(runes[rnd.Intn(len(runes))])
		}
		check(b.String())
	}
	// Invalid UTF-8 must follow encoding/json's replacement behaviour. | 非法 UTF-8 必须遵循
	// encoding/json 的替换行为。
	for _, raw := range [][]byte{
		{0xFF}, {0x80, 0x80}, {'a', 0xFF, 'b'}, {0xE2, 0x28, 0xA1}, {0xED, 0xA0, 0x80},
	} {
		check(string(raw))
	}
	for _, s := range []string{
		"", "plain", `quote"`, `back\slash`, "<>&", "  ",
		string(bytes.Repeat([]byte("long-ascii-"), 1024)),
	} {
		check(s)
	}
}

// TestNEONSkipSpaceBoundaries pins whitespace runs at 15/16/17 and larger block boundaries. |
// TestNEONSkipSpaceBoundaries 固定 15/16/17 及更大块边界上的空白段行为。
func TestNEONSkipSpaceBoundaries(t *testing.T) {
	spaces := []byte(" \t\n\r")
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1024} {
		data := make([]byte, n, n+1)
		for i := range data {
			data[i] = spaces[i%len(spaces)]
		}
		data = append(data, 'x')
		if got := skipSpaceRun(data, 0); got != n {
			t.Fatalf("n=%d: skipSpaceRun=%d, want %d | 空白扫描边界错误", n, got, n)
		}
		prefix := []byte("abc")
		withPrefix := append(append([]byte(nil), prefix...), data...)
		if got := skipSpaceRun(withPrefix, len(prefix)); got != len(prefix)+n {
			t.Fatalf("n=%d prefix: skipSpaceRun=%d, want %d | 带前缀空白扫描错误", n, got, len(prefix)+n)
		}
	}
}

// TestNEONScanDigitsBoundaries pins digit runs at the 8-digit scalar threshold and 15/16/17 byte
// block boundaries. | TestNEONScanDigitsBoundaries 固定 8 位标量阈值与 15/16/17 字节块边界上的
// 数字段行为。
func TestNEONScanDigitsBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1024} {
		data := bytes.Repeat([]byte{'7'}, n)
		data = append(data, 'x')
		if got := scanDigits(data, 0); got != n {
			t.Fatalf("n=%d: scanDigits=%d, want %d | 数字扫描边界错误", n, got, n)
		}
		prefix := []byte("abc")
		withPrefix := append(append([]byte(nil), prefix...), data...)
		if got := scanDigits(withPrefix, len(prefix)); got != len(prefix)+n {
			t.Fatalf("n=%d prefix: scanDigits=%d, want %d | 带前缀数字扫描错误", n, got, len(prefix)+n)
		}
	}
}

// TestNEONCompactOutsideBoundaries pins the compact outer scan at the 15/16/17 block boundaries.
// | TestNEONCompactOutsideBoundaries 固定压缩外部扫描在 15/16/17 块边界上的行为。
func TestNEONCompactOutsideBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1024} {
		for _, stop := range []byte{'"', ' ', '\t', '\n', '\r'} {
			data := append(bytes.Repeat([]byte{'a'}, n), stop, 'b')
			got, want := scanCompactOutsideRun(data, 0), scanCompactOutsideRunRef(data, 0)
			if got != want || got != n {
				t.Fatalf("n=%d stop=%q: got=%d want=%d | 压缩外部扫描边界错误", n, stop, got, want)
			}
		}
		clean := bytes.Repeat([]byte{'a'}, n)
		if got, want := scanCompactOutsideRun(clean, 0), scanCompactOutsideRunRef(clean, 0); got != want || got != n {
			t.Fatalf("n=%d clean: got=%d want=%d | 干净压缩段边界错误", n, got, want)
		}
	}
}

// TestNEONCompactInsideBoundaries pins the compact inner scan at the 15/16/17 block boundaries
// for both HTML modes. | TestNEONCompactInsideBoundaries 固定压缩内部扫描在两种 HTML 模式下
// 15/16/17 块边界上的行为。
func TestNEONCompactInsideBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1024} {
		for _, escapeHTML := range []bool{false, true} {
			for _, stop := range []byte{'"', '\\', '\n', '<', '>', '&', 0xE2} {
				data := append(bytes.Repeat([]byte{'a'}, n), stop, 'b')
				got, want := scanCompactInsideRun(data, 0, escapeHTML), scanCompactInsideRunRef(data, 0, escapeHTML)
				if got != want {
					t.Fatalf("n=%d html=%v stop=%q: got=%d want=%d | 压缩内部扫描边界错误", n, escapeHTML, stop, got, want)
				}
			}
			clean := bytes.Repeat([]byte{'a'}, n)
			if got, want := scanCompactInsideRun(clean, 0, escapeHTML), scanCompactInsideRunRef(clean, 0, escapeHTML); got != want || got != n {
				t.Fatalf("n=%d html=%v clean: got=%d want=%d | 干净压缩内部段边界错误", n, escapeHTML, got, want)
			}
		}
	}
}

// TestNEONUnescapedASCIIBoundaries pins the unescaped ASCII run scan at the 15/16/17 block
// boundaries. | TestNEONUnescapedASCIIBoundaries 固定未转义 ASCII 段扫描在 15/16/17 块边界上的
// 行为。
func TestNEONUnescapedASCIIBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 1024} {
		for _, stop := range []byte{'"', '\\', '\n', 0x80} {
			data := append(bytes.Repeat([]byte{'a'}, n), stop, 'b')
			got, want := scanUnescapedASCII(data, 0), scanUnescapedASCIIRef(data, 0)
			if got != want || got != n {
				t.Fatalf("n=%d stop=%q: got=%d want=%d | 未转义 ASCII 边界错误", n, stop, got, want)
			}
		}
		clean := bytes.Repeat([]byte{'a'}, n)
		if got, want := scanUnescapedASCII(clean, 0), scanUnescapedASCIIRef(clean, 0); got != want || got != n {
			t.Fatalf("n=%d clean: got=%d want=%d | 干净未转义 ASCII 段边界错误", n, got, want)
		}
	}
}
