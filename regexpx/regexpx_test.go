package regexpx

import (
	"errors"
	stdregexp "regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMustCompileAndMatch covers the basic compile and match contract. | TestMustCompileAndMatch 覆盖
// 基本的编译与匹配约定。
func TestMustCompileAndMatch(t *testing.T) {
	re := MustCompile(`^[a-z][a-z0-9_-]*$`)
	cases := map[string]bool{
		"tenant-admin": true,
		"a":            true,
		"":             false,
		"Admin":        false,
		"a b":          false,
		"abc\n":        false, // $ anchors at end of text | $ 只匹配文本末尾
	}
	for in, want := range cases {
		if got := re.MatchString(in); got != want {
			t.Errorf("MatchString(%q) = %v, want %v", in, got, want)
		}
		if got := re.Match([]byte(in)); got != want {
			t.Errorf("Match(%q) = %v, want %v", in, got, want)
		}
	}
	if re.String() != `^[a-z][a-z0-9_-]*$` {
		t.Errorf("String() = %q", re.String())
	}
}

// TestCompileErrorIsSentinel verifies that syntax errors wrap ErrCompile. | TestCompileErrorIsSentinel
// 验证语法错误包装 ErrCompile。
func TestCompileErrorIsSentinel(t *testing.T) {
	for _, pattern := range []string{`(unclosed`, `[abc`, `a{2,1}`, `\p{NoSuchClass}`, `(?P<>x)`, `a**`} {
		if _, err := Compile(pattern); !errors.Is(err, ErrCompile) {
			t.Errorf("Compile(%q) err = %v, want ErrCompile", pattern, err)
		}
	}
}

// TestByteIndicesWithCJK proves that indices are byte offsets. | TestByteIndicesWithCJK 证明下标是字节
// 偏移。
func TestByteIndicesWithCJK(t *testing.T) {
	text := "前缀用户后缀"
	re := MustCompile(`用户`)
	got := re.FindStringSubmatchIndex(text)
	want := []int{6, 12}
	if !equalInts(got, want) {
		t.Fatalf("FindStringSubmatchIndex = %v, want %v", got, want)
	}
	all := re.FindAllStringIndex(text, -1)
	if len(all) != 1 || all[0][0] != 6 || all[0][1] != 12 {
		t.Fatalf("FindAllStringIndex = %v", all)
	}
}

// TestSubmatchIndicesMatchStdlibSemantics pins the -1 contract and the last-capture rule. |
// TestSubmatchIndicesMatchStdlibSemantics 钉住 -1 约定与「最后一次捕获」规则。
func TestSubmatchIndicesMatchStdlibSemantics(t *testing.T) {
	re := MustCompile(`(a+)(b)?`)
	if got := re.FindStringSubmatchIndex("xaay"); !equalInts(got, []int{1, 3, 1, 3, -1, -1}) {
		t.Errorf("FindStringSubmatchIndex = %v", got)
	}
	rep := MustCompile(`(a)+`)
	if got := rep.FindStringSubmatchIndex("aaa"); !equalInts(got, []int{0, 3, 2, 3}) {
		t.Errorf("repeated group = %v, want [0 3 2 3]", got)
	}
	if got := rep.FindStringSubmatch("aaa"); len(got) != 2 || got[0] != "aaa" || got[1] != "a" {
		t.Errorf("FindStringSubmatch = %v", got)
	}
}

// TestFindAll covers the limit and multi-match behaviour. | TestFindAll 覆盖数量限制与多匹配行为。
func TestFindAll(t *testing.T) {
	re := MustCompile(`\d+`)
	in := "a1 b22 c333"
	idx := re.FindAllStringIndex(in, -1)
	if len(idx) != 3 || in[idx[2][0]:idx[2][1]] != "333" {
		t.Fatalf("FindAllStringIndex = %v", idx)
	}
	if idx := re.FindAllStringIndex(in, 2); len(idx) != 2 {
		t.Fatalf("limited FindAllStringIndex = %v", idx)
	}
	subs := MustCompile(`([a-z])(\d+)`).FindAllStringSubmatch(in, -1)
	if len(subs) != 3 || subs[1][0] != "b22" || subs[1][1] != "b" || subs[1][2] != "22" {
		t.Fatalf("FindAllStringSubmatch = %v", subs)
	}
	subIdx := MustCompile(`([a-z])(\d+)`).FindAllStringSubmatchIndex(in, 1)
	if len(subIdx) != 1 || !equalInts(subIdx[0], []int{0, 2, 0, 1, 1, 2}) {
		t.Fatalf("FindAllStringSubmatchIndex = %v", subIdx)
	}
	if got := re.FindString(in); got != "1" {
		t.Fatalf("FindString = %q", got)
	}
	if got := re.FindAllString(in, -1); len(got) != 3 || got[1] != "22" {
		t.Fatalf("FindAllString = %v", got)
	}
	if got := MustCompile(`\d+`).ReplaceAllString(in, "#"); got != "a# b# c#" {
		t.Fatalf("ReplaceAllString = %q", got)
	}
}

// TestQuoteMeta escapes metacharacters and round-trips through a match. | TestQuoteMeta 转义元字符并通过
// 匹配往返验证。
func TestQuoteMeta(t *testing.T) {
	raw := `a.b*c(d)[e]`
	quoted := QuoteMeta(raw)
	re := MustCompile(`^` + quoted + `$`)
	if !re.MatchString(raw) {
		t.Fatalf("quoted pattern %q does not match %q", quoted, raw)
	}
	if re.MatchString("aXb*c(d)[e]") {
		t.Fatal("quoted pattern still treats '.' as a wildcard")
	}
	for _, s := range []string{"", "abc", `\`, "a.b*c(d)[e]"} {
		quoted := QuoteMeta(s)
		if !MustCompile(`^` + quoted + `$`).MatchString(s) {
			t.Errorf("QuoteMeta(%q) = %q does not round-trip", s, quoted)
		}
	}
}

// TestMatchTimeoutFailsClosed proves that catastrophic backtracking is cut off. | TestMatchTimeoutFailsClosed
// 证明灾难性回溯会被截断。
func TestMatchTimeoutFailsClosed(t *testing.T) {
	re := MustCompile(`^(a+)+(?=b)`)
	if !re.prog.info.hasBacktrack {
		t.Fatal("lookahead pattern unexpectedly used the linear engine")
	}
	in := strings.Repeat("a", 64) + "!"
	start := time.Now()
	if re.MatchString(in) {
		t.Fatal("hostile input matched")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("match took %v, timeout did not fire", elapsed)
	}
}

// TestEngineSelection pins which engine each pattern uses. | TestEngineSelection 钉住每种模式使用哪个
// 引擎。
func TestEngineSelection(t *testing.T) {
	if re := MustCompile(`^[a-z]+$`); re.prog.info.hasBacktrack {
		t.Error("ordinary pattern used the backtracking engine")
	}
	if re := MustCompile(`^(?=a)a+$`); !re.prog.info.hasBacktrack {
		t.Error("lookahead pattern did not use the backtracking engine")
	}
}

// TestDotNetConstructsSupported proves that the compatibility path supports .NET syntax. |
// TestDotNetConstructsSupported 证明兼容路径支持 .NET 语法。
func TestDotNetConstructsSupported(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
		want    bool
	}{
		{`^(a+)\1$`, "aaaa", true},
		{`^(a+)\1$`, "aaa", false},
		{`^(a+)\1$`, "aa", true},
		{`^(?=a)a+$`, "aaa", true},
		{`^(?!a)b+$`, "bbb", true},
		{`^(?!a)b+$`, "abb", false},
		{`(?<=a)b`, "ab", true},
		{`(?<=a)b`, "cb", false},
		{`(?<!a)b`, "cb", true},
		{`(?<!a)b`, "ab", false},
		{`(?<=a{1,3})b`, "aaab", true},
		{`(?<=a{1,3})b`, "cb", false},
		{`(?i)(?<word>[a-z]+)\s+\k<word>`, "Hello hello", true},
		{`(?i)(?<word>[a-z]+)\s+\k<word>`, "Hello world", false},
		{`(?>a+)a`, "aaa", false},
		{`(a+)a`, "aaa", true},
		{`a*+a`, "aaa", false},
		{`(?'x'a)(?<y>b)`, "ab", true},
	}
	for _, tc := range cases {
		re, err := Compile(tc.pattern)
		if err != nil {
			t.Errorf("Compile(%q): %v", tc.pattern, err)
			continue
		}
		if got := re.MatchString(tc.input); got != tc.want {
			t.Errorf("%q.MatchString(%q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
		}
	}
}

// TestByteIndicesOnBacktrackingPath proves byte indices for lookaround matches. |
// TestByteIndicesOnBacktrackingPath 证明环视匹配的字节下标。
func TestByteIndicesOnBacktrackingPath(t *testing.T) {
	re := MustCompile(`用户(?=后)`)
	if !re.prog.info.hasBacktrack {
		t.Fatal("lookahead pattern unexpectedly used the linear engine")
	}
	text := "前缀用户后缀"
	got := re.FindStringSubmatchIndex(text)
	if len(got) != 2 || got[0] != 6 || got[1] != 12 {
		t.Fatalf("FindStringSubmatchIndex = %v, want [6 12]", got)
	}
}

// TestNamedGroups covers group metadata accessors. | TestNamedGroups 覆盖分组元数据访问器。
func TestNamedGroups(t *testing.T) {
	re := MustCompile(`(?P<year>\d{4})-(?P<month>\d{2})`)
	if re.NumSubexp() != 2 {
		t.Fatalf("NumSubexp = %d", re.NumSubexp())
	}
	names := re.SubexpNames()
	if len(names) != 3 || names[1] != "year" || names[2] != "month" {
		t.Fatalf("SubexpNames = %v", names)
	}
	if re.SubexpIndex("month") != 2 || re.SubexpIndex("nope") != -1 {
		t.Fatalf("SubexpIndex mismatch")
	}
	if got := re.FindStringSubmatch("2024-07"); got[1] != "2024" || got[2] != "07" {
		t.Fatalf("FindStringSubmatch = %v", got)
	}
}

// TestReplaceAndSplit covers replacement expansion and splitting. | TestReplaceAndSplit 覆盖替换展开与
// 切分。
func TestReplaceAndSplit(t *testing.T) {
	re := MustCompile(`(?P<word>[a-z]+)-(\d+)`)
	if got := re.ReplaceAllString("ab-12 cd-3", "${word}:$2"); got != "ab:12 cd:3" {
		t.Fatalf("ReplaceAllString = %q", got)
	}
	if got := re.ReplaceAllString("ab-12", "$$$1"); got != "$ab" {
		t.Fatalf("dollar expansion = %q", got)
	}
	if got := re.ReplaceAllStringFunc("ab-12", strings.ToUpper); got != "AB-12" {
		t.Fatalf("ReplaceAllStringFunc = %q", got)
	}
	parts := MustCompile(`,`).Split("a,b,c", -1)
	if len(parts) != 3 || parts[0] != "a" || parts[2] != "c" {
		t.Fatalf("Split = %v", parts)
	}
}

// TestConcurrentUse exercises the wrapper under the race detector. | TestConcurrentUse 在竞态检测器下
// 验证并发使用。
func TestConcurrentUse(t *testing.T) {
	re := MustCompile(`^[a-z]+:[a-z]+$`)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if !re.MatchString("user:create") || re.MatchString("bad") {
					t.Errorf("concurrent match returned the wrong result")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestParallelMatchesSequential proves that chunked scanning returns the same matches. |
// TestParallelMatchesSequential 证明分块扫描返回相同的匹配。
func TestParallelMatchesSequential(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		b.WriteString("user")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString("42 ")
	}
	input := b.String()
	for _, pattern := range []string{`user\w*42`, `\d+`, `[a-z]+`, `user`, `(?i)USER`} {
		re := MustCompile(pattern)
		seq := re.FindAllStringIndex(input, -1)
		par := re.FindAllStringIndexParallel(input, -1)
		if len(seq) != len(par) {
			t.Fatalf("%q: parallel %d matches, sequential %d", pattern, len(par), len(seq))
		}
		for i := range seq {
			if !equalInts(seq[i], par[i]) {
				t.Fatalf("%q: match %d = %v, want %v", pattern, i, par[i], seq[i])
			}
		}
	}
}

// TestDifferentialAgainstStdlib compares the RE2 subset against the standard library. |
// TestDifferentialAgainstStdlib 把 RE2 子集与标准库做差分对比。
func TestDifferentialAgainstStdlib(t *testing.T) {
	patterns := []string{
		`^[a-z][a-z0-9_-]*$`,
		`\d+`,
		`([a-z])(\d+)`,
		`a*`,
		`a+?`,
		`(ab|a)b`,
		`a{2,4}`,
		`(?i)hello`,
		`(?m)^foo$`,
		`\bword\b`,
		`[[:alpha:]]+`,
		`[\p{L}\p{N}_]+`,
		`\x{4e16}\x{754c}`,
		`(?s).+`,
		`\Aabc\z`,
		`a|ab|abc`,
		`(?:ab)+`,
		`[^a]+`,
		`\Qa.b\E`,
		`用户`,
		`(?i)К`,
		`[a-z]{3}`,
		`\s+`,
		`\D`,
		`[[:^digit:]]+`,
		`(?U)a+`,
		`(a)(b)?`,
		`(a)+`,
		`^$`,
		`$`,
		`^`,
		`a{0,3}`,
		`[a-c-e]+`,
		`\p{Greek}+`,
		`\P{L}+`,
		`(?i)[a-z]+`,
		`\w+@\w+`,
		`(?:a|b){2}`,
		`a.*b`,
		`a.*?b`,
		`(?s).*Holmes.*`,
		`(?s).*Holmes`,
		`Holmes.*`,
		`\d{4}-\d{2}-\d{2}`,
		`\d{2}`,
		`^[a-z]+$`,
		`^[a-z]+:[a-z]+$`,
		`^abc$`,
		`abc$`,
		`^abc`,
		`(?i)error`,
		`(?i)k`,
		`(?i)A`,
		`(?i)A`,
		`A`,
		`\w*`,
		`.*`,
		`.+`,
		`\Aabc\z`,
		`[^\s]+`,
		`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		`https?://[^\s/$.?#].[^\s]*`,
		`^https?://[^\s]+$`,
		`https?://[a-z]+`,
		`a?b`,
		`a{2,3}b`,
	}
	inputs := []string{
		"", "a", "ab", "abc", "aab", "aaa", "123", "a1 b22 c333", "Hello", "hello",
		"foo\nbar", "前缀用户后缀", "Кк", "a.b", "   ", "\n", "世 界", "word word",
		"x@y", "aaaa", "abb", "abcabc", "ΑΒΓ", "123-45", "aXb", "a\nb", "foo",
		"a1b2c3", "A", "2024-07-15", "foo bar baz", "ERROR error", "K", "kK",
		"Sherlock Holmes", "xxHolmesyyHolmeszz",
		"user@example.com", "a@b.co", "a@b.c", "a.b+c@ex-ample.co.uk",
		"user@example", "user@@example.com", "user@example..com",
		"user@example.com-x", "x user@example.com y", "user@example.com.",
		"üser@example.com", "用户@例子.公司", "USER@EXAMPLE.COM",
		"a@b.c_d", "a@b.c-d", "a@b.c.d", "a@b..c", "a@.com", "@example.com",
		"http://example.com", "https://example.com/path?q=1", "http://x",
		"https://", "http://", "httpsx://a", "prefix https://example.com suffix",
		"HTTP://EXAMPLE.COM", "http://例子.公司", "https://example.com/路径?q=😀",
		"aaab", "aab", "ab", "b",
		"a.b*c(d)[e]", "a\r\nb", "\t\t", "12345", "abc123", "ΑΒΓΔ",
		"user@example.com", "no at sign", "x\ny", "a\xffb", "\x80\x81", "ok\xff",
	}
	for _, pattern := range patterns {
		want, stdErr := stdregexp.Compile(pattern)
		got, err := Compile(pattern)
		if stdErr != nil {
			if err == nil {
				t.Errorf("Compile(%q) succeeded, stdlib failed: %v", pattern, stdErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("Compile(%q): %v", pattern, err)
			continue
		}
		for _, input := range inputs {
			if a, b := got.MatchString(input), want.MatchString(input); a != b {
				t.Errorf("%q.MatchString(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindStringIndex(input), want.FindStringIndex(input); !equalInts(a, b) {
				t.Errorf("%q.FindStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindStringSubmatchIndex(input), want.FindStringSubmatchIndex(input); !equalInts(a, b) {
				t.Errorf("%q.FindStringSubmatchIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindAllStringIndex(input, -1), want.FindAllStringIndex(input, -1); !equalIntsMatrix(a, b) {
				t.Errorf("%q.FindAllStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindAllStringSubmatchIndex(input, -1), want.FindAllStringSubmatchIndex(input, -1); !equalIntsMatrix(a, b) {
				t.Errorf("%q.FindAllStringSubmatchIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.ReplaceAllString(input, "<$1>"), want.ReplaceAllString(input, "<$1>"); a != b {
				t.Errorf("%q.ReplaceAllString(%q) = %q, stdlib %q", pattern, input, a, b)
			}
			if a, b := got.Split(input, -1), want.Split(input, -1); !equalStrings(a, b) {
				t.Errorf("%q.Split(%q) = %q, stdlib %q", pattern, input, a, b)
			}
		}
	}
	for _, input := range inputs {
		if a, b := QuoteMeta(input), stdregexp.QuoteMeta(input); a != b {
			t.Errorf("QuoteMeta(%q) = %q, stdlib %q", input, a, b)
		}
	}
}

// equalInts reports whether a and b hold the same integers. | equalInts 报告 a 与 b 是否包含相同的整数。
func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// equalIntsMatrix reports whether two int matrices are identical. | equalIntsMatrix 报告两个整数矩阵是否
// 完全相同。
func equalIntsMatrix(a, b [][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalInts(a[i], b[i]) {
			return false
		}
	}
	return true
}

// TestEmptyLoopTerminates proves that nullable loops terminate in both engines. |
// TestEmptyLoopTerminates 证明两个引擎中的可空循环都会终止。
func TestEmptyLoopTerminates(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
		want    bool
	}{
		{`(?>(a?)*)a*`, "aaa", true},
		{`(?=(a?)+$)a*`, "aaa", true},
		{`(?=(a?)*b)a*`, "aaa", false},
		{`(a?)*`, "aaa", true},
		{`(a?)+`, "", true},
	}
	for _, tc := range cases {
		re := MustCompile(tc.pattern)
		done := make(chan bool, 1)
		go func() { done <- re.MatchString(tc.input) }()
		select {
		case got := <-done:
			if got != tc.want {
				t.Errorf("%q.MatchString(%q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q on %q did not terminate", tc.pattern, tc.input)
		}
	}
}

// TestFoldOrbitFirstBytes proves that folded ASCII literals also match non-ASCII fold partners. |
// TestFoldOrbitFirstBytes 证明折叠的 ASCII 字面量也能匹配非 ASCII 折叠伙伴。
func TestFoldOrbitFirstBytes(t *testing.T) {
	// U+212A KELVIN SIGN folds with k and K. | U+212A 开尔文符号与 k、K 折叠。
	if !MustCompile(`(?i)k|x`).MatchString("K") {
		t.Fatal("folded literal missed the Kelvin sign")
	}
	if !MustCompile(`(?i)[k]|x`).MatchString("K") {
		t.Fatal("folded class missed the Kelvin sign")
	}
}

// TestByteAPIs compares the byte-oriented methods with the string-oriented ones. |
// TestByteAPIs 对比字节方法与字符串方法。
func TestByteAPIs(t *testing.T) {
	re := MustCompile(`(\w+)@(\w+)`)
	input := []byte("mail user@example.com and admin@example.org")
	if a, b := re.Find(input), []byte(re.FindString(string(input))); string(a) != string(b) {
		t.Fatalf("Find = %q, string %q", a, b)
	}
	if !equalInts(re.FindIndex(input), re.FindStringIndex(string(input))) {
		t.Fatal("FindIndex differs")
	}
	sub := re.FindSubmatch(input)
	want := re.FindStringSubmatch(string(input))
	for i := range sub {
		if string(sub[i]) != want[i] {
			t.Fatalf("FindSubmatch[%d] = %q, want %q", i, sub[i], want[i])
		}
	}
	if !equalInts(re.FindSubmatchIndex(input), re.FindStringSubmatchIndex(string(input))) {
		t.Fatal("FindSubmatchIndex differs")
	}
	all := re.FindAll(input, -1)
	allStr := re.FindAllString(string(input), -1)
	if len(all) != len(allStr) {
		t.Fatalf("FindAll count = %d, want %d", len(all), len(allStr))
	}
	for i := range all {
		if string(all[i]) != allStr[i] {
			t.Fatalf("FindAll[%d] = %q, want %q", i, all[i], allStr[i])
		}
	}
	if !equalIntsMatrix(re.FindAllIndex(input, -1), re.FindAllStringIndex(string(input), -1)) {
		t.Fatal("FindAllIndex differs")
	}
	subAll := re.FindAllSubmatch(input, -1)
	if len(subAll) != 2 || string(subAll[1][1]) != "admin" {
		t.Fatalf("FindAllSubmatch = %q", subAll)
	}
	if a, b := string(re.ReplaceAll(input, []byte("<$1>"))), re.ReplaceAllString(string(input), "<$1>"); a != b {
		t.Fatalf("ReplaceAll = %q, want %q", a, b)
	}
	if a, b := string(re.ReplaceAllFunc(input, func(m []byte) []byte { return []byte("<" + string(m) + ">") })),
		re.ReplaceAllStringFunc(string(input), func(m string) string { return "<" + m + ">" }); a != b {
		t.Fatalf("ReplaceAllFunc = %q, want %q", a, b)
	}
}

// TestBacktrackingConcurrentUse exercises the backtracking engine under the race detector. |
// TestBacktrackingConcurrentUse 在竞态检测器下验证回溯引擎。
func TestBacktrackingConcurrentUse(t *testing.T) {
	re := MustCompile(`(?i)(?<w>[a-z]+)\s+\k<w>`)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if !re.MatchString("Hello hello") || re.MatchString("Hello world") {
					t.Errorf("backtracking match returned the wrong result")
					return
				}
			}
		}()
	}
	wg.Wait()
}
