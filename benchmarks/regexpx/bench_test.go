package regexpx

import (
	"fmt"
	stdregexp "regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	grafana "github.com/grafana/regexp"
	re2 "github.com/wasilibs/go-re2"

	ydx "github.com/shibingli/ydx/regexpx"
)

// impl is one comparable regular-expression implementation. | impl 是一个可对比的正则实现。
type impl struct {
	name      string
	match     func(string) bool
	findIndex func(string) []int
	findAll   func(string, int) [][]int
}

// buildImpls compiles pattern for every implementation that accepts it. | buildImpls 为每个接受该模式的
// 实现编译模式。
func buildImpls(pattern string) []impl {
	var out []impl
	if re, err := ydx.Compile(pattern); err == nil {
		out = append(out, impl{
			name:      "ydx",
			match:     re.MatchString,
			findIndex: re.FindStringIndex,
			findAll:   re.FindAllStringIndex,
		})
	}
	if re, err := stdregexp.Compile(pattern); err == nil {
		out = append(out, impl{
			name:      "stdlib",
			match:     re.MatchString,
			findIndex: re.FindStringIndex,
			findAll:   re.FindAllStringIndex,
		})
	}
	if re, err := grafana.Compile(pattern); err == nil {
		out = append(out, impl{
			name:      "grafana",
			match:     re.MatchString,
			findIndex: re.FindStringIndex,
			findAll:   re.FindAllStringIndex,
		})
	}
	if re, err := re2.Compile(pattern); err == nil {
		out = append(out, impl{
			name:      "go-re2",
			match:     re.MatchString,
			findIndex: re.FindStringIndex,
			findAll:   re.FindAllStringIndex,
		})
	}
	if re, err := regexp2.Compile(pattern, regexp2.RE2); err == nil {
		re.MatchTimeout = 5_000_000_000
		out = append(out, impl{
			name: "regexp2",
			match: func(s string) bool {
				ok, err := re.MatchString(s)
				return err == nil && ok
			},
			findIndex: func(s string) []int {
				m, err := re.FindStringMatch(s)
				if err != nil || m == nil {
					return nil
				}
				starts := runeStarts(s)
				return []int{starts[m.Index], starts[m.Index+m.Length]}
			},
			findAll: func(s string, n int) [][]int {
				starts := runeStarts(s)
				var out [][]int
				m, err := re.FindStringMatch(s)
				for err == nil && m != nil {
					out = append(out, []int{starts[m.Index], starts[m.Index+m.Length]})
					if n > 0 && len(out) >= n {
						break
					}
					m, err = re.FindNextMatch(m)
				}
				return out
			},
		})
	}
	return out
}

// runeStarts maps rune indices to byte offsets. | runeStarts 把符文下标映射为字节偏移。
func runeStarts(s string) []int {
	starts := make([]int, 0, utf8.RuneCountInString(s)+1)
	for i := range s {
		starts = append(starts, i)
	}
	return append(starts, len(s))
}

// largeText is an English-like corpus with words, numbers, dates and punctuation. | largeText 是包含
// 单词、数字、日期与标点的英文风格语料。
var largeText = buildText(256 << 10)

// buildText builds a deterministic corpus of approximately size bytes. | buildText 构造约 size 字节的
// 确定性语料。
func buildText(size int) string {
	line := "user123@example.com 2024-07-15 https://example.com/path?q=1 foo bar baz " +
		"GET /api/v1/items 192.168.1.10 status=200 tenant-admin Sherlock Holmes 42 "
	var b strings.Builder
	b.Grow(size + len(line))
	for b.Len() < size {
		b.WriteString(line)
	}
	return b.String()
}

// unicodeText is a mixed-script corpus. | unicodeText 是混合文字语料。
var unicodeText = buildUnicodeText(128 << 10)

// buildUnicodeText repeats CJK, Greek and Latin words. | buildUnicodeText 重复中日韩、希腊与拉丁单词。
func buildUnicodeText(size int) string {
	line := "用户 世界 前缀 后缀 ΑΒΓΔ αβγδ Hello World регулярный "
	var b strings.Builder
	b.Grow(size + len(line))
	for b.Len() < size {
		b.WriteString(line)
	}
	return b.String()
}

// mixedText is a mixed-script corpus with emoji, simplified and traditional Chinese, and English.
// | mixedText 是包含表情、简繁中文与英文的混合文字语料。
var mixedText = buildMixedText(128 << 10)

// buildMixedText repeats emoji and mixed-script phrases. | buildMixedText 重复表情与混合文字短语。
func buildMixedText(size int) string {
	line := "用户😀 hello 世界👍🏽 繁體中文，English！ 2024-07-15 ❤️ 🇨🇳 👨‍👩‍👧‍👦 "
	var b strings.Builder
	b.Grow(size + len(line))
	for b.Len() < size {
		b.WriteString(line)
	}
	return b.String()
}

// caseDef is one benchmark case. | caseDef 是一个基准用例。
type caseDef struct {
	name    string
	pattern string
	input   string
}

// cases is the shared pattern corpus. | cases 是共享的模式语料。
var cases = []caseDef{
	{"literal", `Sherlock Holmes`, largeText},
	{"literal_ci", `(?i)error`, largeText},
	{"word", `\w+`, largeText},
	{"email", `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, largeText},
	{"uri", `https?://[^\s/$.?#].[^\s]*`, largeText},
	{"date", `\d{4}-\d{2}-\d{2}`, largeText},
	{"alternation", `foo|bar|baz`, largeText},
	{"captures", `(\w+)@(\w+)\.com`, largeText},
	{"anchored_id", `^[a-z][a-z0-9_-]{0,63}$`, "tenant-admin"},
	{"unicode", `\p{L}+`, unicodeText},
	{"dotstar", `(?s).*Holmes.*`, largeText},
	{"han", `\p{Han}+`, mixedText},
	{"emoji", `\p{So}+`, mixedText},
}

// BenchmarkMatchString compares boolean matching. | BenchmarkMatchString 对比布尔匹配。
func BenchmarkMatchString(b *testing.B) {
	for _, tc := range cases {
		for _, im := range buildImpls(tc.pattern) {
			b.Run(fmt.Sprintf("%s/%s", tc.name, im.name), func(b *testing.B) {
				b.SetBytes(int64(len(tc.input)))
				b.ReportAllocs()
				b.ResetTimer()
				ok := false
				for i := 0; i < b.N; i++ {
					ok = im.match(tc.input)
				}
				_ = ok
			})
		}
	}
}

// BenchmarkFindStringIndex compares first-match search. | BenchmarkFindStringIndex 对比首个匹配搜索。
func BenchmarkFindStringIndex(b *testing.B) {
	for _, tc := range cases {
		if tc.name == "dotstar" {
			continue
		}
		for _, im := range buildImpls(tc.pattern) {
			b.Run(fmt.Sprintf("%s/%s", tc.name, im.name), func(b *testing.B) {
				b.SetBytes(int64(len(tc.input)))
				b.ReportAllocs()
				b.ResetTimer()
				var result []int
				for i := 0; i < b.N; i++ {
					result = im.findIndex(tc.input)
				}
				_ = result
			})
		}
	}
}

// BenchmarkFindAll compares full scans. | BenchmarkFindAll 对比完整扫描。
func BenchmarkFindAll(b *testing.B) {
	names := map[string]bool{"word": true, "email": true, "date": true, "alternation": true, "unicode": true, "han": true, "emoji": true}
	for _, tc := range cases {
		if !names[tc.name] {
			continue
		}
		for _, im := range buildImpls(tc.pattern) {
			b.Run(fmt.Sprintf("%s/%s", tc.name, im.name), func(b *testing.B) {
				b.SetBytes(int64(len(tc.input)))
				b.ReportAllocs()
				b.ResetTimer()
				var result [][]int
				for i := 0; i < b.N; i++ {
					result = im.findAll(tc.input, -1)
				}
				_ = result
			})
		}
	}
}

// BenchmarkCompile compares pattern compilation. | BenchmarkCompile 对比模式编译。
func BenchmarkCompile(b *testing.B) {
	for _, pattern := range []string{`\d+`, `^[a-z][a-z0-9_-]{0,63}$`, `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`} {
		b.Run("ydx/"+pattern, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := ydx.Compile(pattern); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("stdlib/"+pattern, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := stdregexp.Compile(pattern); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("grafana/"+pattern, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := grafana.Compile(pattern); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
