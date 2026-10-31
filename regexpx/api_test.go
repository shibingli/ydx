package regexpx

import (
	"bytes"
	"errors"
	"io"
	stdregexp "regexp"
	"strings"
	"testing"
)

// stdRegexpAPI is the portion of the standard library's Regexp method set that regexpx mirrors.
// The compile-time assertion keeps future refactors from silently dropping a method. |
// stdRegexpAPI 是 regexpx 镜像的标准库 Regexp 方法集；编译期断言防止后续重构悄悄丢失方法。
type stdRegexpAPI interface {
	AppendText([]byte) ([]byte, error)
	Copy() *Regexp
	Expand([]byte, []byte, []byte, []int) []byte
	ExpandString([]byte, string, string, []int) []byte
	FindReaderIndex(io.RuneReader) []int
	FindReaderSubmatchIndex(io.RuneReader) []int
	LiteralPrefix() (string, bool)
	Longest()
	MarshalText() ([]byte, error)
	MatchReader(io.RuneReader) bool
	ReplaceAllLiteral([]byte, []byte) []byte
	ReplaceAllLiteralString(string, string) string
	UnmarshalText([]byte) error
}

var _ stdRegexpAPI = (*Regexp)(nil)

func TestPackageMatchFunctions(t *testing.T) {
	if matched, err := Match(`a+`, []byte("caa")); err != nil || !matched {
		t.Fatalf("Match = %v, %v，期望 true", matched, err)
	}
	if matched, err := MatchString(`a+`, "caa"); err != nil || !matched {
		t.Fatalf("MatchString = %v, %v，期望 true", matched, err)
	}
	if matched, err := MatchReader(`a+`, strings.NewReader("caa")); err != nil || !matched {
		t.Fatalf("MatchReader = %v, %v，期望 true", matched, err)
	}
	if _, err := MatchString(`(`, "x"); !errors.Is(err, ErrCompile) {
		t.Fatalf("非法模式错误 = %v，期望 ErrCompile", err)
	}
}

func TestCompilePOSIXUsesLongest(t *testing.T) {
	re := MustCompilePOSIX(`a|aa`)
	if got := re.FindString("aa"); got != "aa" {
		t.Fatalf("CompilePOSIX FindString = %q，期望 aa", got)
	}
	re2 := MustCompilePOSIX(`x|xy`)
	if got := re2.FindString("zxy"); got != "xy" {
		t.Fatalf("CompilePOSIX FindString = %q，期望 xy", got)
	}
}

func TestCompilePOSIXRejectsExtensions(t *testing.T) {
	rejected := []string{`\d`, `\w`, `\s`, `\b`, `\A`, `\z`, `\1`, `(?i)a`, `(?:a)`, `\Qa\E`}
	for _, pattern := range rejected {
		if _, err := stdregexp.CompilePOSIX(pattern); err == nil {
			t.Fatalf("标准库接受了测试模式 %q", pattern)
		}
		if _, err := CompilePOSIX(pattern); err == nil {
			t.Errorf("CompilePOSIX(%q) 未拒绝非 POSIX 语法", pattern)
		}
	}
	accepted := []string{`[[:alpha:]]+`, `a|b`, `a{1,2}`, `\n`, `\.`}
	for _, pattern := range accepted {
		if _, err := stdregexp.CompilePOSIX(pattern); err != nil {
			t.Fatalf("标准库拒绝了测试模式 %q: %v", pattern, err)
		}
		if _, err := CompilePOSIX(pattern); err != nil {
			t.Errorf("CompilePOSIX(%q) 失败: %v", pattern, err)
		}
	}
}

func TestLongestDifferential(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
	}{
		{`a|aa`, "aa"},
		{`x|xy`, "zxy"},
		{`a{1,2}|a{3}`, "aaa"},
		{`(a|aa)`, "aa"},
		{`a+|ab`, "ab"},
		{`a*`, "aaa"},
		{`a?`, "a"},
		{`(a|aa)*`, "aaaa"},
		{`abc`, "xabc"},
		{`\w+`, "  hello_123 "},
		{`(?s).*foo.*`, "xxfooyyfoo"},
		{`(?s).*foo`, "xxfooyyfoo"},
		{`foo(?s).*`, "xxfooyyfoo"},
		{`\d{4}-\d{2}-\d{2}`, "date 2026-10-31 end"},
		{`^abc$`, "abc"},
	}
	for _, tc := range cases {
		std := stdregexp.MustCompile(tc.pattern)
		got := MustCompile(tc.pattern)
		if a, b := got.FindString(tc.input), std.FindString(tc.input); a != b {
			t.Fatalf("%q 默认 FindString(%q) = %q，标准库 %q", tc.pattern, tc.input, a, b)
		}
		std.Longest()
		got.Longest()
		if a, b := got.FindString(tc.input), std.FindString(tc.input); a != b {
			t.Fatalf("%q Longest FindString(%q) = %q，标准库 %q", tc.pattern, tc.input, a, b)
		}
		if a, b := got.FindStringIndex(tc.input), std.FindStringIndex(tc.input); !equalInts(a, b) {
			t.Fatalf("%q Longest FindStringIndex(%q) = %v，标准库 %v", tc.pattern, tc.input, a, b)
		}
		if a, b := got.FindStringSubmatchIndex(tc.input), std.FindStringSubmatchIndex(tc.input); !equalInts(a, b) {
			t.Fatalf("%q Longest FindStringSubmatchIndex(%q) = %v，标准库 %v", tc.pattern, tc.input, a, b)
		}
		if a, b := got.FindAllString(tc.input, -1), std.FindAllString(tc.input, -1); !equalStrings(a, b) {
			t.Fatalf("%q Longest FindAllString(%q) = %q，标准库 %q", tc.pattern, tc.input, a, b)
		}
		if a, b := got.FindAllStringSubmatchIndex(tc.input, -1), std.FindAllStringSubmatchIndex(tc.input, -1); !equalIntsMatrix(a, b) {
			t.Fatalf("%q Longest FindAllStringSubmatchIndex(%q) = %v，标准库 %v",
				tc.pattern, tc.input, a, b)
		}
	}
}

func TestLongestBacktracking(t *testing.T) {
	re := MustCompile(`(a|aa)\1`)
	if got := re.FindString("aaaa"); got != "aa" {
		t.Fatalf("默认 FindString = %q，期望 aa", got)
	}
	re.Longest()
	if got := re.FindString("aaaa"); got != "aaaa" {
		t.Fatalf("Longest FindString = %q，期望 aaaa", got)
	}

	look := MustCompile(`a(?=a)|aa`)
	if got := look.FindString("aa"); got != "a" {
		t.Fatalf("默认 lookahead FindString = %q，期望 a", got)
	}
	look.Longest()
	if got := look.FindString("aa"); got != "aa" {
		t.Fatalf("Longest lookahead FindString = %q，期望 aa", got)
	}
}

func TestLiteralPrefixDifferential(t *testing.T) {
	patterns := []string{
		``, `abc`, `(?i)abc`, `abc.*`, `^abc$`, `a(bc)`, `a|b`, `abc|abd`,
		`(?:abc)`, `abc{1,2}`, `\Aabc`, `abc|abc`, `a(bc)d`, `[a]bc`,
		`a(b|c)`, `(abc)`, `abc{1}`, `(?:abc){1}`, `abc$`, `^abc`,
		`(a|ab)c`, `a(b|bc)d`, `(a|ab)`, `(ab|a)c`,
	}
	for _, pattern := range patterns {
		std := stdregexp.MustCompile(pattern)
		got := MustCompile(pattern)
		wantPrefix, wantComplete := std.LiteralPrefix()
		gotPrefix, gotComplete := got.LiteralPrefix()
		if gotPrefix != wantPrefix || gotComplete != wantComplete {
			t.Errorf("%q LiteralPrefix = (%q, %v)，标准库 (%q, %v)",
				pattern, gotPrefix, gotComplete, wantPrefix, wantComplete)
		}
	}
}

func TestExpandDifferential(t *testing.T) {
	patterns := []string{`(a)(b)`, `(?P<first>a)(?P<second>b)?`, `a+`, `(a)?b`}
	templates := []string{
		`$1-$2`, `${1}x`, `$$1`, `$first`, `${first}`, `$0`, `$10`,
		`x$`, `${missing}`, `$1x`, `${1}x`,
	}
	inputs := []string{"ab", "a", "zzab", "b"}
	for _, pattern := range patterns {
		std := stdregexp.MustCompile(pattern)
		got := MustCompile(pattern)
		for _, input := range inputs {
			stdMatch := std.FindStringSubmatchIndex(input)
			gotMatch := got.FindStringSubmatchIndex(input)
			if !equalInts(stdMatch, gotMatch) {
				t.Fatalf("%q 子匹配索引 = %v，标准库 %v", pattern, gotMatch, stdMatch)
			}
			if stdMatch == nil {
				// Expand requires a valid match; a nil match is outside its contract. | Expand
				// 需要有效匹配，nil 匹配不在其约定范围内。
				continue
			}
			for _, template := range templates {
				want := std.ExpandString(nil, template, input, stdMatch)
				if have := got.ExpandString(nil, template, input, gotMatch); !bytes.Equal(have, want) {
					t.Fatalf("%q ExpandString(%q, %q) = %q，标准库 %q",
						pattern, template, input, have, want)
				}
				want = std.Expand(nil, []byte(template), []byte(input), stdMatch)
				if have := got.Expand(nil, []byte(template), []byte(input), gotMatch); !bytes.Equal(have, want) {
					t.Fatalf("%q Expand(%q, %q) = %q，标准库 %q",
						pattern, template, input, have, want)
				}
			}
		}
	}
}

func TestReplaceAllLiteralDifferential(t *testing.T) {
	patterns := []string{`a+`, `(a)(b)`, `x?`}
	inputs := []string{"aaab", "ab", "zzz"}
	repls := []string{"$1", "$$", "X$0Y", ""}
	for _, pattern := range patterns {
		std := stdregexp.MustCompile(pattern)
		got := MustCompile(pattern)
		for _, input := range inputs {
			for _, repl := range repls {
				want := std.ReplaceAllLiteralString(input, repl)
				if have := got.ReplaceAllLiteralString(input, repl); have != want {
					t.Fatalf("%q ReplaceAllLiteralString(%q, %q) = %q，标准库 %q",
						pattern, input, repl, have, want)
				}
				wantBytes := std.ReplaceAllLiteral([]byte(input), []byte(repl))
				if haveBytes := got.ReplaceAllLiteral([]byte(input), []byte(repl)); !bytes.Equal(haveBytes, wantBytes) {
					t.Fatalf("%q ReplaceAllLiteral(%q, %q) = %q，标准库 %q",
						pattern, input, repl, haveBytes, wantBytes)
				}
			}
		}
	}
}

func TestReaderMethodsDifferential(t *testing.T) {
	pattern := `a(b+)`
	std := stdregexp.MustCompile(pattern)
	got := MustCompile(pattern)
	input := "xxabbbz"
	if a, b := got.MatchReader(strings.NewReader(input)), std.MatchReader(strings.NewReader(input)); a != b {
		t.Fatalf("MatchReader = %v，标准库 %v", a, b)
	}
	if a, b := got.FindReaderIndex(strings.NewReader(input)), std.FindReaderIndex(strings.NewReader(input)); !equalInts(a, b) {
		t.Fatalf("FindReaderIndex = %v，标准库 %v", a, b)
	}
	if a, b := got.FindReaderSubmatchIndex(strings.NewReader(input)), std.FindReaderSubmatchIndex(strings.NewReader(input)); !equalInts(a, b) {
		t.Fatalf("FindReaderSubmatchIndex = %v，标准库 %v", a, b)
	}
	if a, b := got.FindReaderIndex(strings.NewReader("zzz")), std.FindReaderIndex(strings.NewReader("zzz")); !equalInts(a, b) {
		t.Fatalf("无匹配 FindReaderIndex = %v，标准库 %v", a, b)
	}
}

func TestTextCopyAndAppend(t *testing.T) {
	re := MustCompile(`a+`)
	if b, err := re.AppendText([]byte("x")); err != nil || string(b) != "xa+" {
		t.Fatalf("AppendText = %q, %v", b, err)
	}
	if b, err := re.MarshalText(); err != nil || string(b) != "a+" {
		t.Fatalf("MarshalText = %q, %v", b, err)
	}
	var decoded Regexp
	if err := decoded.UnmarshalText([]byte(`b+`)); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if !decoded.MatchString("bbb") {
		t.Fatal("UnmarshalText 后模式未生效")
	}
	if err := decoded.UnmarshalText([]byte(`(`)); !errors.Is(err, ErrCompile) {
		t.Fatalf("UnmarshalText 非法模式错误 = %v，期望 ErrCompile", err)
	}

	original := MustCompile(`a|aa`)
	clone := original.Copy()
	clone.Longest()
	if got := original.FindString("aa"); got != "a" {
		t.Fatalf("原对象受 Copy+Longest 影响: %q", got)
	}
	if got := clone.FindString("aa"); got != "aa" {
		t.Fatalf("副本 Longest 未生效: %q", got)
	}
}
