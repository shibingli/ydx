package regexpx

import (
	"math/rand"
	stdregexp "regexp"
	"strings"
	"testing"
)

// TestSearchDFAMatchesEngine compares the ASCII search DFA with the normal engine for assertions
// and constructs it supports. | TestSearchDFAMatchesEngine 对 DFA 支持的断言与构造，将 ASCII 搜索 DFA
// 与常规引擎对比。
func TestSearchDFAMatchesEngine(t *testing.T) {
	patterns := []string{
		``,
		`a`,
		`abc`,
		`a*`,
		`a|ab`,
		`(?:ab|a)+c`,
		`(?i)foo`,
		`foo\b`,
		`\bfoo\b`,
		`\Bfoo`,
		`^foo`,
		`foo$`,
		`(?:^|;)cmd`,
		`(?i)(?:^|;)cmd\b`,
		`[^\s]+`,
		`[a-c]+x`,
		`(?:foo|bar)?baz`,
		`(?i)k`,
		`^`,
		`\b`,
		`\B`,
	}
	inputs := []string{
		``, `a`, `b`, `ab`, `abc`, `foo`, `FOO`, `xfoo`, `foo!`, `foo bar`,
		`a b`, `cmd`, `;cmd`, `;cmd x`, ` cmd`, `ababc`, `aaaa`, `k`, `K`,
		"\nfoo", "foo\n", "baz", "xxbazyy", `A`, `a-cx`, `a`, "é", "aé", "\xff",
	}
	for _, pattern := range patterns {
		re := MustCompile(pattern)
		dfa := newSearchDFA(re.prog)
		if dfa == nil {
			t.Fatalf("pattern %q unexpectedly unsupported", pattern)
		}
		for _, input := range inputs {
			got, known := dfa.match(input)
			want := re.MatchString(input)
			nonASCII := false
			for i := 0; i < len(input); i++ {
				if input[i] >= 0x80 {
					nonASCII = true
					break
				}
			}
			if nonASCII {
				// A match found before the first non-ASCII byte is still a known answer. |
				// 在首个非 ASCII 字节前已找到的匹配仍然是已知答案。
				if known && got != want {
					t.Fatalf("pattern %q input %q: known DFA=%v engine=%v", pattern, input, got, want)
				}
				continue
			}
			if !known {
				t.Fatalf("pattern %q input %q: DFA unexpectedly unknown", pattern, input)
			}
			if got != want {
				t.Fatalf("pattern %q input %q: DFA=%v engine=%v", pattern, input, got, want)
			}
		}
	}
}

// TestSearchDFARejectsUnsupportedConstructs verifies unsupported assertions and backtracking
// constructs fall back to the Pike VM. | TestSearchDFARejectsUnsupportedConstructs 验证不支持的断言与
// 回溯构造会回退到 Pike VM。
func TestSearchDFARejectsUnsupportedConstructs(t *testing.T) {
	patterns := []string{
		`(?m)^foo`,
		`(?m)foo$`,
		`(?=a)a`,
		`(a)\1`,
	}
	for _, pattern := range patterns {
		re := MustCompile(pattern)
		if dfa := newSearchDFA(re.prog); dfa != nil {
			t.Fatalf("pattern %q unexpectedly enabled the ASCII search DFA", pattern)
		}
	}
}

// TestSearchDFAIntegrationLargePattern exercises the lazy DFA through the public MatchString and
// capture APIs, including the word-boundary and start-assertion paths. |
// TestSearchDFAIntegrationLargePattern 通过公开的 MatchString 与捕获 API 验证惰性 DFA，包括单词边界
// 与起始断言路径。
func TestSearchDFAIntegrationLargePattern(t *testing.T) {
	var pattern strings.Builder
	pattern.WriteString(`(?i)((?:^(?:json\.|\x5c)?|`)
	for i := 0; i < 80; i++ {
		if i > 0 {
			pattern.WriteByte('|')
		}
		pattern.WriteString(`cmd`)
		pattern.WriteByte(byte('a' + i%26))
		pattern.WriteString(`[0-9]{0,3}\b`)
	}
	pattern.WriteString(`))[a-z0-9_]+`)
	source := pattern.String()
	re := MustCompile(source)
	standard := stdregexp.MustCompile(source)
	if !re.searchDFAEligible {
		t.Fatal("large pattern did not enable the search DFA")
	}
	if re.searchDFA() == nil {
		t.Fatal("large pattern failed to build the search DFA")
	}
	inputs := []string{
		"cmdA42x", "json.cmdA42x", `\cmdA42x`, "xxcmdB7z", "hello", "cmdA42",
		"cmda999_", "CMDZ0yes", "cmdA123456x", "", "a", "cmdA42!", "écmdA42x",
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 500; i++ {
		length := rng.Intn(48)
		var b strings.Builder
		for j := 0; j < length; j++ {
			const alphabet = "abcXYZ0123_- !;\\jsoncmd"
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		inputs = append(inputs, b.String())
	}
	for _, input := range inputs {
		if got, want := re.MatchString(input), standard.MatchString(input); got != want {
			t.Fatalf("input %q: MatchString=%v want %v", input, got, want)
		}
		if !standard.MatchString(input) {
			continue
		}
		got := re.FindStringSubmatchIndex(input)
		want := standard.FindStringSubmatchIndex(input)
		if !equalInts(got, want) {
			t.Fatalf("input %q: submatch index=%v want %v", input, got, want)
		}
	}
}

// TestSearchDFARandomDifferential compares the DFA directly with the standard library over the
// package's random RE2 pattern corpus. | TestSearchDFARandomDifferential 在包的随机 RE2 模式语料上
// 直接对比 DFA 与标准库。
func TestSearchDFARandomDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20261024))
	inputs := []string{
		"", "a", "b", "ab", "aab", "abc", "ABC", "a1", "a_1", " ", "  ", "\n", "a\nb",
		"-", "a-b", "a.b", "a b", "aaab", "bbaa", "0123", "foo\nbar\n", "_", "A1_b2",
		"a\tb", "xyz", "foo", "FOO", "xfoo", "foo!", "cmd", ";cmd", "cmd42", "a-cx",
		"é", "世界", "Кк", "aé", "K", "\xff",
	}
	for iteration := 0; iteration < 2000; iteration++ {
		pattern := randomPattern(rng, 3)
		std, err := stdregexp.Compile(pattern)
		if err != nil {
			continue
		}
		re, err := Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		dfa := newSearchDFA(re.prog)
		if dfa == nil {
			continue
		}
		for _, input := range inputs {
			got, known := dfa.match(input)
			want := std.MatchString(input)
			if !known {
				continue
			}
			if got != want {
				t.Fatalf("pattern=%q input=%q DFA=%v stdlib=%v", pattern, input, got, want)
			}
		}
	}
}

// TestWarmInitializesFastPaths verifies Warm builds eligible DFA caches without changing results.
// | TestWarmInitializesFastPaths 验证 Warm 构建符合条件模式的 DFA 缓存且不改变结果。
func TestWarmInitializesFastPaths(t *testing.T) {
	var pattern strings.Builder
	pattern.WriteString(`(?i)(?:^(?:json\.|\x5c)?|`)
	for i := 0; i < 80; i++ {
		if i > 0 {
			pattern.WriteByte('|')
		}
		pattern.WriteString(`cmd`)
		pattern.WriteByte(byte('a' + i%26))
		pattern.WriteString(`[0-9]{0,3}\b`)
	}
	pattern.WriteString(`)[a-z0-9_]+`)
	re := MustCompile(pattern.String())
	want := re.MatchString("json.cmdA42x")
	re.Warm()
	if re.compat.searchDFA == nil {
		t.Fatal("Warm did not build the search DFA")
	}
	if got := re.MatchString("json.cmdA42x"); got != want {
		t.Fatalf("Warm changed MatchString: got %v want %v", got, want)
	}

	full := MustCompile(`^[a-z]+$`)
	full.Warm()
	if !full.MatchString("abc") || full.MatchString("abc1") {
		t.Fatal("Warm changed full-match results")
	}
}

// TestSearchDFAConcurrentMatch exercises concurrent access while transition rows are populated. |
// TestSearchDFAConcurrentMatch 在填充转移行时验证并发访问。
func TestSearchDFAConcurrentMatch(t *testing.T) {
	re := MustCompile(`(?i)(?:^(?:json\.|\x5c)?|(?:foo|bar|baz)[0-9]{0,3}\b)[a-z0-9_]+`)
	dfa := newSearchDFA(re.prog)
	if dfa == nil {
		t.Fatal("pattern unexpectedly unsupported")
	}
	inputs := []string{"foo123x", "bar0x", "baz999_", "hello", "json.foo1x", "other"}
	const goroutines = 8
	const iterations = 200
	done := make(chan bool, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			ok := true
			for i := 0; i < iterations; i++ {
				input := inputs[(seed+i)%len(inputs)]
				got, known := dfa.match(input)
				if !known || got != re.MatchString(input) {
					ok = false
					break
				}
			}
			done <- ok
		}(g)
	}
	for g := 0; g < goroutines; g++ {
		if !<-done {
			t.Fatal("concurrent DFA match disagreed with the engine")
		}
	}
}
