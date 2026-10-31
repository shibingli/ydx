package regexpx

import (
	"strings"
	"testing"

	ydx "github.com/shibingli/ydx/regexpx"
)

// CRS 4.29 rule shapes used to exercise regexpx prefilters. | 用于验证 regexpx 预过滤的 CRS 4.29
// 规则形态。
const (
	crs942420 = `((?:(?:[!-\+\-:->@\[\]\^` + "`" + `\{-~]|\x{c2}\x{b4}|\x{e2}\x{80}[\x{98}\x{99}])[^!-\+\-:->@\[\]\^` + "`" + `\{-~]*?){8})`
	crs932240 = `(?i)[\-0-9_a-z]+(?:[\s\x0b]*["'][^\s\x0b"',:]+["']|(?:["']["']+|[\[-\]]+|\$+[!#\*\-0-9\?@\x5c_a-\{]+|` + "``" + `|[\$<>]\(\))[\s\x0b]*)[\-0-9_a-z]+`
)

// BenchmarkCRSRequiredByteRepetition measures a punctuation-heavy repeated class. |
// BenchmarkCRSRequiredByteRepetition 测量标点密集的重复字符类。
func BenchmarkCRSRequiredByteRepetition(b *testing.B) {
	re := ydx.MustCompile(crs942420)
	value := "value-0-hello-world"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = re.MatchString(value)
	}
}

// BenchmarkCRSRequiredByteAlternation measures a class alternation with a broad first byte. |
// BenchmarkCRSRequiredByteAlternation 测量首字节很宽、由字符类分支构成的模式。
func BenchmarkCRSRequiredByteAlternation(b *testing.B) {
	re := ydx.MustCompile(crs932240)
	value := "value-0-hello-world"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = re.MatchString(value)
	}
}

// BenchmarkMinimumLengthShort measures the minimum-length short circuit on a short input. |
// BenchmarkMinimumLengthShort 测量短输入上的最小长度短路。
func BenchmarkMinimumLengthShort(b *testing.B) {
	re := ydx.MustCompile(`(?:[a-z]{2}){3}abcdef`)
	value := strings.Repeat("abc", 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = re.MatchString(value)
	}
}

// largeAlternationPattern builds a broad command-name alternation with word boundaries. It is large
// enough for regexpx's lazy ASCII search DFA. | largeAlternationPattern 构建带单词边界的宽命令名
// 交替模式；其规模足以启用 regexpx 的惰性 ASCII 搜索 DFA。
var largeAlternationPattern = func() string {
	var b strings.Builder
	b.WriteString(`(?i)(?:^(?:json\.|\x5c)?|`)
	for i := 0; i < 120; i++ {
		if i > 0 {
			b.WriteByte('|')
		}
		b.WriteString("cmd")
		b.WriteByte(byte('a' + i%26))
		b.WriteString(`[0-9]{0,3}\b`)
	}
	b.WriteString(`)[a-z0-9_]+`)
	return b.String()
}()

// BenchmarkDFALargeAlternation measures a large alternation that exercises the lazy search DFA. |
// BenchmarkDFALargeAlternation 测量可触发惰性搜索 DFA 的大型交替模式。
func BenchmarkDFALargeAlternation(b *testing.B) {
	re := ydx.MustCompile(largeAlternationPattern)
	value := "value-0-hello-world"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = re.MatchString(value)
	}
}
