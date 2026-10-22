//go:build (amd64 || arm64) && !jsonx_std

package json

import (
	"math/rand"
	"testing"
)

// jsonScanData builds deterministic pseudo-random input spanning control bytes, quotes,
// backslashes, whitespace, non-ASCII and ordinary text. | jsonScanData 构造确定性伪随机输入，
// 覆盖控制字节、引号、反斜杠、空白、非 ASCII 与普通文本。
func jsonScanData(rnd *rand.Rand, n int) []byte {
	data := make([]byte, n)
	for i := range data {
		switch rnd.Intn(7) {
		case 0:
			data[i] = byte(rnd.Intn(0x20))
		case 1:
			data[i] = '"'
		case 2:
			data[i] = '\\'
		case 3:
			data[i] = byte(0x80 + rnd.Intn(0x80))
		case 4:
			data[i] = " \t\n\r"[rnd.Intn(4)]
		case 5:
			data[i] = byte('0' + rnd.Intn(10))
		default:
			data[i] = byte('A' + rnd.Intn(26))
		}
	}
	return data
}

func isJSONSpaceRef(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipSpaceRunRef(data []byte, pos int) int {
	for pos < len(data) && isJSONSpaceRef(data[pos]) {
		pos++
	}
	return pos
}

func scanDigitsRef(data []byte, pos int) int {
	for pos < len(data) && data[pos] >= '0' && data[pos] <= '9' {
		pos++
	}
	return pos
}

func jsonStringNeedsEscapeRef(s string, escapeHTML bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == '"' || c == '\\' || c >= 0x80 {
			return true
		}
		if escapeHTML && (c == '<' || c == '>' || c == '&') {
			return true
		}
	}
	return false
}

func scanStringBodyRef(data []byte, start int) (end int, slow bool, nonASCII bool) {
	for i := start; i < len(data); i++ {
		c := data[i]
		if c >= 0x80 {
			nonASCII = true
		}
		switch {
		case c == '"':
			return i, false, nonASCII
		case c == '\\' || c < 0x20:
			return 0, true, false
		}
	}
	return 0, true, false
}

func scanCompactOutsideRunRef(src []byte, pos int) int {
	for pos < len(src) && src[pos] != '"' && !isJSONSpaceRef(src[pos]) {
		pos++
	}
	return pos
}

func scanCompactInsideRunRef(src []byte, pos int, escapeHTML bool) int {
	for pos < len(src) {
		c := src[pos]
		if c == '"' || c == '\\' || c < 0x20 {
			break
		}
		if escapeHTML && (c == '<' || c == '>' || c == '&' || c == 0xE2) {
			break
		}
		pos++
	}
	return pos
}

func scanUnescapedASCIIRef(data []byte, pos int) int {
	for pos < len(data) {
		c := data[pos]
		if c == '"' || c == '\\' || c < 0x20 || c >= 0x80 {
			break
		}
		pos++
	}
	return pos
}

func TestSkipSpaceRunDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for iter := 0; iter < 4000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(128))
		pos := 0
		if len(data) > 0 {
			pos = rnd.Intn(len(data) + 1)
		}
		if got, want := skipSpaceRun(data, pos), skipSpaceRunRef(data, pos); got != want {
			t.Fatalf("iter=%d pos=%d got=%d want=%d | 空白扫描不一致", iter, pos, got, want)
		}
	}
}

func TestScanDigitsDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(2))
	for iter := 0; iter < 4000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(128))
		pos := 0
		if len(data) > 0 {
			pos = rnd.Intn(len(data) + 1)
		}
		if got, want := scanDigits(data, pos), scanDigitsRef(data, pos); got != want {
			t.Fatalf("iter=%d pos=%d got=%d want=%d | 数字扫描不一致", iter, pos, got, want)
		}
	}
}

func TestJSONStringNeedsEscapeDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(3))
	for iter := 0; iter < 4000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(128))
		escapeHTML := rnd.Intn(2) == 0
		if got, want := jsonStringNeedsEscape(string(data), escapeHTML), jsonStringNeedsEscapeRef(string(data), escapeHTML); got != want {
			t.Fatalf("iter=%d html=%v data=%q got=%v want=%v | 转义扫描不一致", iter, escapeHTML, data, got, want)
		}
	}
}

func TestScanStringBodyDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(4))
	for iter := 0; iter < 4000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(128))
		start := 0
		if len(data) > 0 {
			start = rnd.Intn(len(data) + 1)
		}
		gotEnd, gotSlow, gotNonASCII := scanStringBody(data, start)
		wantEnd, wantSlow, wantNonASCII := scanStringBodyRef(data, start)
		if gotEnd != wantEnd || gotSlow != wantSlow {
			t.Fatalf("iter=%d start=%d got=(%d,%v) want=(%d,%v) | 字符串体扫描不一致", iter, start, gotEnd, gotSlow, wantEnd, wantSlow)
		}
		// The word/vector scan may over-report non-ASCII when a high byte follows the
		// closing quote inside the same word; parseString re-validates UTF-8, so an
		// over-approximation is safe but an under-approximation is not. | 按字/向量扫描时，
		// 结束引号之后的同字高位字节会多报 non-ASCII；parseString 会重新校验 UTF-8，
		// 因此多报安全，少报不安全。
		if wantNonASCII && !gotNonASCII {
			t.Fatalf("iter=%d start=%d non-ASCII under-reported | 少报了非 ASCII", iter, start)
		}
	}
}

func TestScanCompactOutsideRunDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(5))
	for iter := 0; iter < 4000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(128))
		pos := 0
		if len(data) > 0 {
			pos = rnd.Intn(len(data) + 1)
		}
		if got, want := scanCompactOutsideRun(data, pos), scanCompactOutsideRunRef(data, pos); got != want {
			t.Fatalf("iter=%d pos=%d got=%d want=%d | 压缩外部扫描不一致", iter, pos, got, want)
		}
	}
}

func TestScanCompactInsideRunDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(6))
	for iter := 0; iter < 4000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(128))
		pos := 0
		if len(data) > 0 {
			pos = rnd.Intn(len(data) + 1)
		}
		escapeHTML := rnd.Intn(2) == 0
		if got, want := scanCompactInsideRun(data, pos, escapeHTML), scanCompactInsideRunRef(data, pos, escapeHTML); got != want {
			t.Fatalf("iter=%d pos=%d html=%v got=%d want=%d | 压缩内部扫描不一致", iter, pos, escapeHTML, got, want)
		}
	}
}

func TestScanUnescapedASCIIDifferential(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	for iter := 0; iter < 4000; iter++ {
		data := jsonScanData(rnd, rnd.Intn(128))
		pos := 0
		if len(data) > 0 {
			pos = rnd.Intn(len(data) + 1)
		}
		if got, want := scanUnescapedASCII(data, pos), scanUnescapedASCIIDiffRef(data, pos); got != want {
			t.Fatalf("iter=%d pos=%d got=%d want=%d | 未转义 ASCII 扫描不一致", iter, pos, got, want)
		}
	}
}

func scanUnescapedASCIIDiffRef(data []byte, pos int) int { return scanUnescapedASCIIRef(data, pos) }
