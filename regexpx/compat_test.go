package regexpx

import (
	"bytes"
	"errors"
	"io"
	stdregexp "regexp"
	"testing"
)

// expandResult runs ExpandString and converts a panic into a test failure. | expandResult 执行
// ExpandString，并把 panic 转换为测试失败。
func expandResult(t *testing.T, re *Regexp, template, src string, match []int) (out []byte, panicked any) {
	t.Helper()
	defer func() { panicked = recover() }()
	return re.ExpandString(nil, template, src, match), nil
}

func TestExpandTemplateCompatibility(t *testing.T) {
	cases := []struct {
		pattern  string
		template string
		src      string
		match    []int
		full     bool
	}{
		{`(?P<a>a)`, `$名`, "a", nil, true},
		{`(?P<a>a)`, `${名}`, "a", nil, true},
		{`(a)(?P<01>b)`, `$01`, "ab", nil, true},
		{`(a)`, `$01`, "a", nil, true},
		{`(a)`, `$00`, "a", nil, true},
		{`(a)`, `$99999999999999999999`, "a", nil, true},
		{`(a)`, `$1`, "a", []int{0, 1}, false},
		{`(a)`, `$1x`, "a", nil, true},
		{`(a)`, `${1}x`, "a", nil, true},
	}
	for _, tc := range cases {
		std := stdregexp.MustCompile(tc.pattern)
		got, err := Compile(tc.pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", tc.pattern, err)
		}
		stdMatch, gotMatch := tc.match, tc.match
		if tc.full {
			stdMatch = std.FindStringSubmatchIndex(tc.src)
			gotMatch = got.FindStringSubmatchIndex(tc.src)
		}
		if !equalInts(stdMatch, gotMatch) {
			t.Fatalf("%q match = %v, stdlib %v", tc.pattern, gotMatch, stdMatch)
		}
		want := std.ExpandString(nil, tc.template, tc.src, stdMatch)
		have, panicked := expandResult(t, got, tc.template, tc.src, gotMatch)
		if panicked != nil {
			t.Fatalf("%q ExpandString(%q) panicked: %v", tc.pattern, tc.template, panicked)
		}
		if !bytes.Equal(have, want) {
			t.Fatalf("%q ExpandString(%q, %q) = %q, stdlib %q",
				tc.pattern, tc.template, tc.src, have, want)
		}
	}
}

func TestGroupNameCompatibility(t *testing.T) {
	patterns := []string{
		`(?P<01>a)`, `(?P<a1>a)`, `(?P<_a>a)`, `(?P<名>a)`,
	}
	for _, pattern := range patterns {
		std, stdErr := stdregexp.Compile(pattern)
		got, gotErr := Compile(pattern)
		if (stdErr == nil) != (gotErr == nil) {
			t.Fatalf("%q: regexpx error=%v, stdlib error=%v", pattern, gotErr, stdErr)
		}
		if stdErr != nil {
			continue
		}
		if a, b := got.SubexpNames(), std.SubexpNames(); !equalStrings(a, b) {
			t.Fatalf("%q SubexpNames = %q, stdlib %q", pattern, a, b)
		}
		for _, name := range []string{"01", "a1", "_a", "名"} {
			if a, b := got.SubexpIndex(name), std.SubexpIndex(name); a != b {
				t.Fatalf("%q SubexpIndex(%q) = %d, stdlib %d", pattern, name, a, b)
			}
		}
	}
}

// sizedReader returns the supplied runes with reported byte sizes. | sizedReader 按给定的上报字节
// 大小返回符文。
type sizedReader struct {
	runes []rune
	sizes []int
	i     int
}

func (r *sizedReader) ReadRune() (rune, int, error) {
	if r.i >= len(r.runes) {
		return 0, 0, io.EOF
	}
	r.i++
	return r.runes[r.i-1], r.sizes[r.i-1], nil
}

// errorAfterReader returns one rune and then a non-EOF error. | errorAfterReader 返回一个符文后返回
// 非 EOF 错误。
type errorAfterReader struct{ i int }

func (r *errorAfterReader) ReadRune() (rune, int, error) {
	if r.i == 0 {
		r.i++
		return 'a', 1, nil
	}
	return 0, 0, errors.New("read failed")
}

func TestReaderCompatibility(t *testing.T) {
	patterns := []string{`a`, `世a`, `(a)`, `a(b+)`, `^a$`, `^$`}
	inputs := []struct {
		name string
		new  func() io.RuneReader
	}{
		{"sized-ascii", func() io.RuneReader { return &sizedReader{runes: []rune("xabbbz"), sizes: []int{1, 1, 1, 1, 1, 1}} }},
		{"sized-short", func() io.RuneReader { return &sizedReader{runes: []rune{'世', 'a'}, sizes: []int{1, 1}} }},
		{"sized-utf8", func() io.RuneReader { return &sizedReader{runes: []rune{'世', 'a'}, sizes: []int{3, 1}} }},
		{"error-after-match", func() io.RuneReader { return &errorAfterReader{} }},
		{"error-only", func() io.RuneReader { return &errReader{} }},
	}
	for _, pattern := range patterns {
		std := stdregexp.MustCompile(pattern)
		got := MustCompile(pattern)
		for _, input := range inputs {
			if a, b := got.MatchReader(input.new()), std.MatchReader(input.new()); a != b {
				t.Fatalf("%q/%s MatchReader = %v, stdlib %v", pattern, input.name, a, b)
			}
			if a, b := got.FindReaderIndex(input.new()), std.FindReaderIndex(input.new()); !equalInts(a, b) {
				t.Fatalf("%q/%s FindReaderIndex = %v, stdlib %v", pattern, input.name, a, b)
			}
			if a, b := got.FindReaderSubmatchIndex(input.new()), std.FindReaderSubmatchIndex(input.new()); !equalInts(a, b) {
				t.Fatalf("%q/%s FindReaderSubmatchIndex = %v, stdlib %v", pattern, input.name, a, b)
			}
		}
	}
}

// errReader always returns a non-EOF error. | errReader 总是返回非 EOF 错误。
type errReader struct{}

func (*errReader) ReadRune() (rune, int, error) { return 0, 0, errors.New("read failed") }

func TestLiteralPrefixRepeatCompatibility(t *testing.T) {
	patterns := []string{
		`a{2}`, `a{2,3}`, `a{2,}`, `(ab){2}`, `(ab){2,3}`,
		`a{0}`, `a{0,2}`, `(a|ab){2}`, `(?:ab){2}c`,
	}
	for _, pattern := range patterns {
		std := stdregexp.MustCompile(pattern)
		got := MustCompile(pattern)
		wantPrefix, wantComplete := std.LiteralPrefix()
		gotPrefix, gotComplete := got.LiteralPrefix()
		if gotPrefix != wantPrefix || gotComplete != wantComplete {
			t.Fatalf("%q LiteralPrefix = (%q, %v), stdlib (%q, %v)",
				pattern, gotPrefix, gotComplete, wantPrefix, wantComplete)
		}
	}
}

func TestCompilePOSIXParity(t *testing.T) {
	patterns := []string{
		`\d`, `\w`, `\s`, `\A`, `\b`, `\1`, `(?i)a`, `(?:a)`, `\Qa\E`,
		`\x41`, `\0`, `\8`, `a*?`, `a*+`, `a++`, `a?+`,
		`[[:alpha:]]`, `[[:word:]]`, `\p{L}`, `\P{L}`, `\C`, `\R`, `\Z`, `\z`, `\G`, `\K`,
		`\n`, `\t`, `\r`, `\f`, `\v`, `\a`, `a{1,2}`, `a{,2}`, `a{2,}`, `a{1,2}?`,
		`[.a.]`, `[=a=]`, `[a-z]`, `[^a]`, `a|b`, `(a)(b)`, `\x{41}`,
	}
	inputs := []string{"", "a", "A", "0", "a b", "世", "a\n", "aaa"}
	for _, pattern := range patterns {
		std, stdErr := stdregexp.CompilePOSIX(pattern)
		got, gotErr := CompilePOSIX(pattern)
		if (stdErr == nil) != (gotErr == nil) {
			t.Fatalf("%q: regexpx error=%v, stdlib error=%v", pattern, gotErr, stdErr)
		}
		if stdErr != nil {
			continue
		}
		for _, input := range inputs {
			if a, b := got.FindString(input), std.FindString(input); a != b {
				t.Fatalf("%q FindString(%q) = %q, stdlib %q", pattern, input, a, b)
			}
		}
	}
}

func TestCopySharesProgram(t *testing.T) {
	original := MustCompile(`a|aa`)
	clone := original.Copy()
	if clone.prog != original.prog {
		t.Fatal("Copy recompiled the program instead of sharing it")
	}
	clone.Longest()
	if got := original.FindString("aa"); got != "a" {
		t.Fatalf("original changed by clone.Longest: %q", got)
	}
	if got := clone.FindString("aa"); got != "aa" {
		t.Fatalf("clone Longest = %q, want aa", got)
	}
}

func TestExpandBytesCompatibility(t *testing.T) {
	re := MustCompile(`(a)(b)`)
	std := stdregexp.MustCompile(`(a)(b)`)
	match := re.FindStringSubmatchIndex("ab")
	stdMatch := std.FindStringSubmatchIndex("ab")
	for _, template := range []string{`$1-$2`, `$$`, `$0`, `${1}`} {
		want := std.Expand(nil, []byte(template), []byte("ab"), stdMatch)
		have := re.Expand(nil, []byte(template), []byte("ab"), match)
		if !bytes.Equal(have, want) {
			t.Fatalf("Expand(%q) = %q, stdlib %q", template, have, want)
		}
	}
}

func TestLiteralPrefixUnicodeAndClasses(t *testing.T) {
	patterns := []string{`[a]bc`, `[a-a]bc`, `[^\n]bc`, `(?i)[a]bc`, `(?m)^abc`, `(?s)^abc$`, `abc\z`}
	for _, pattern := range patterns {
		std := stdregexp.MustCompile(pattern)
		got := MustCompile(pattern)
		wantPrefix, wantComplete := std.LiteralPrefix()
		gotPrefix, gotComplete := got.LiteralPrefix()
		if gotPrefix != wantPrefix || gotComplete != wantComplete {
			t.Fatalf("%q LiteralPrefix = (%q, %v), stdlib (%q, %v)",
				pattern, gotPrefix, gotComplete, wantPrefix, wantComplete)
		}
	}
}

// countingReader returns a fixed number of 'a' runes and records how many were read. |
// countingReader 返回固定数量的 'a'，并记录已读取数量。
type countingReader struct {
	read  int
	total int
}

func (r *countingReader) ReadRune() (rune, int, error) {
	if r.read >= r.total {
		return 0, 0, io.EOF
	}
	r.read++
	return 'a', 1, nil
}

func TestMatchReaderStopsEarly(t *testing.T) {
	reader := &countingReader{total: 100000}
	if !MustCompile(`a`).MatchReader(reader) {
		t.Fatal("MatchReader did not find the early match")
	}
	if reader.read != 1 {
		t.Fatalf("MatchReader read %d runes, want the first rune", reader.read)
	}

	anchored := &countingReader{total: 5000}
	if MustCompile(`b$`).MatchReader(anchored) {
		// All runes are 'a', so b$ cannot match; the point is that the reader must be consumed to
		// decide. | 全是 'a'，因此 b$ 不匹配；关键在于必须读完才能判定。
		t.Fatal("a$ unexpectedly matched")
	}
	if anchored.read != anchored.total {
		t.Fatalf("end-anchored MatchReader read %d/%d runes", anchored.read, anchored.total)
	}
}

func TestFindReaderIndexStopsEarly(t *testing.T) {
	reader := &countingReader{total: 100000}
	index := MustCompile(`a`).FindReaderIndex(reader)
	if !equalInts(index, []int{0, 1}) {
		t.Fatalf("FindReaderIndex = %v, want [0 1]", index)
	}
	if reader.read != 1 {
		t.Fatalf("FindReaderIndex read %d runes, want the first rune", reader.read)
	}
}

func TestProgInfoLengthBounds(t *testing.T) {
	cases := []struct {
		pattern string
		min     int
		max     int
	}{
		{`a|aa`, 1, 2},
		{`a(?=a)|aa`, 1, 2},
		{`a{2,3}`, 2, 3},
		{`(ab){2,3}`, 4, 6},
		{`a*`, 0, -1},
		{`a{0}`, 0, 0},
	}
	for _, tc := range cases {
		re := MustCompile(tc.pattern)
		if re.prog.info.minLen != tc.min || re.prog.info.maxLen != tc.max {
			t.Fatalf("%q length = (%d, %d), want (%d, %d)", tc.pattern,
				re.prog.info.minLen, re.prog.info.maxLen, tc.min, tc.max)
		}
	}
}
