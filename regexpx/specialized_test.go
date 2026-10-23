package regexpx

import (
	"math/rand"
	stdregexp "regexp"
	"strings"
	"testing"
)

// emailPattern is the address shape exercised by the specialized matcher. | emailPattern 是专用匹配器
// 覆盖的地址形态。
const emailPattern = `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`

// uriPattern is the URL shape exercised by the linear matcher with an optional and a trailing run. |
// uriPattern 是由带可选与尾运行的线性匹配器覆盖的 URL 形态。
const uriPattern = `https?://[^\s/$.?#].[^\s]*`

// compareAll compares every observable result for one pattern and input. | compareAll 对比一个模式与
// 输入的所有可观测结果。
func compareAll(t *testing.T, pattern, input string) {
	t.Helper()
	std, err := stdregexp.Compile(pattern)
	if err != nil {
		return
	}
	got, err := Compile(pattern)
	if err != nil {
		t.Fatalf("Compile(%q): %v", pattern, err)
	}
	if a, b := got.MatchString(input), std.MatchString(input); a != b {
		t.Fatalf("%q.MatchString(%q) = %v, stdlib %v", pattern, input, a, b)
	}
	if a, b := got.FindStringIndex(input), std.FindStringIndex(input); !equalInts(a, b) {
		t.Fatalf("%q.FindStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
	}
	if a, b := got.FindAllStringIndex(input, -1), std.FindAllStringIndex(input, -1); !equalIntsMatrix(a, b) {
		t.Fatalf("%q.FindAllStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
	}
	if a, b := got.FindAllStringSubmatchIndex(input, -1), std.FindAllStringSubmatchIndex(input, -1); !equalIntsMatrix(a, b) {
		t.Fatalf("%q.FindAllStringSubmatchIndex(%q) = %v, stdlib %v", pattern, input, a, b)
	}
	if a, b := got.ReplaceAllString(input, "<$0>"), std.ReplaceAllString(input, "<$0>"); a != b {
		t.Fatalf("%q.ReplaceAllString(%q) = %q, stdlib %q", pattern, input, a, b)
	}
	if a, b := got.Split(input, -1), std.Split(input, -1); !equalStrings(a, b) {
		t.Fatalf("%q.Split(%q) = %q, stdlib %q", pattern, input, a, b)
	}
}

// TestEmailRandomDifferential fuzzes the address shape, including separators, dots, anchors and
// non-ASCII bytes. | TestEmailRandomDifferential 模糊测试地址形态，覆盖分隔符、点号、锚点与非 ASCII
// 字节。
func TestEmailRandomDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(2026102401))
	alphabet := []string{"a", "b", "A", "B", "0", "1", ".", "@", "-", "_", "+", "%", " ", "é", "世", "😀"}
	patterns := []string{emailPattern, "^" + emailPattern + "$", emailPattern + "$", "^" + emailPattern}
	for iter := 0; iter < 8000; iter++ {
		var b strings.Builder
		n := rng.Intn(40)
		for i := 0; i < n; i++ {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		input := b.String()
		for _, pattern := range patterns {
			compareAll(t, pattern, input)
		}
	}
}

// TestLinearAnchorFallback covers anchored-end linear patterns whose leading optional or negated
// atom admits every byte, so no first-byte filter exists and the general engine must decide. |
// TestLinearAnchorFallback 覆盖锚定末尾且首个可选/否定原子放行所有字节的线性模式；它们没有首字节
// 过滤器，必须由通用引擎判断。
func TestLinearAnchorFallback(t *testing.T) {
	patterns := []string{
		`[^z]?foo$`,
		`[^\n]?foo$`,
		`[^z]?foo`,
		`\A[^z]?foo\z`,
	}
	inputs := []string{
		"", "foo", "afoo", "zfoo", "foo\n", "xfoo\n", "中foo", "éfoo", "zzfoo", "barfoo",
	}
	for _, pattern := range patterns {
		for _, input := range inputs {
			compareAll(t, pattern, input)
		}
	}
}

// TestAnchorLiteralDifferential fuzzes fixed patterns searched through a punctuation literal,
// including anchors, negated leading classes and non-ASCII input. | TestAnchorLiteralDifferential
// 模糊测试通过标点字面量搜索的固定模式，覆盖锚点、否定首类与非 ASCII 输入。
func TestAnchorLiteralDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(2026102403))
	alphabet := []string{"0", "1", "9", "a", "z", "-", ".", "@", "/", ":", " ", "\n", "é", "中"}
	patterns := []string{
		`\d{4}-\d{2}-\d{2}`,
		`\d{4}-\d{2}-\d{2}$`,
		`^\d{4}-\d{2}-\d{2}`,
		`^\d{4}-\d{2}-\d{2}$`,
		`foo-bar`,
		`a.b`,
		`[a-z][.-][0-9]`,
		`[^z]-foo`,
		`\A[^z]-foo\z`,
	}
	for iter := 0; iter < 8000; iter++ {
		var b strings.Builder
		n := rng.Intn(40)
		for i := 0; i < n; i++ {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		input := b.String()
		for _, pattern := range patterns {
			compareAll(t, pattern, input)
		}
	}
}

// TestURIRandomDifferential fuzzes the URL shape, including the optional s, trailing runs, anchors,
// newlines and non-ASCII bytes. | TestURIRandomDifferential 模糊测试 URL 形态，覆盖可选 s、尾运行、
// 锚点、换行与非 ASCII 字节。
func TestURIRandomDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(2026102402))
	pieces := []string{"http", "https", "://", ":", "/", "?", "#", ".", "a", "b", "A", "0", "-", " ", "\n", "é", "世", "😀", "ftp"}
	patterns := []string{uriPattern, "^" + uriPattern + "$", uriPattern + "$", `https?://[a-z]+`, `a?b`, `a{2,3}b`}
	for iter := 0; iter < 8000; iter++ {
		var b strings.Builder
		n := rng.Intn(20)
		for i := 0; i < n; i++ {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		input := b.String()
		for _, pattern := range patterns {
			compareAll(t, pattern, input)
		}
	}
}
