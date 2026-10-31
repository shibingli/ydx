package regexpx

import (
	"bytes"
	"math/rand"
	stdregexp "regexp"
	"testing"
)

// TestRandomAPICompatibility extends the existing differential corpus to the compatibility APIs
// added for regexp parity. | TestRandomAPICompatibility 把现有差分语料扩展到为 regexp 兼容性新增的
// API。
func TestRandomAPICompatibility(t *testing.T) {
	rng := rand.New(rand.NewSource(20261031))
	inputs := []string{
		"", "a", "b", "ab", "aab", "abc", "ABC", "a1", "a_1", " ", "  ", "\n",
		"a\nb", "-", "a-b", "a.b", "a b", "é", "世界", "Кк", "aé", "aaab",
		"bbaa", "0123", "foo\nbar\n", "_", "A1_b2", "a\tb", "xyz", "😀", "a😀b",
	}
	for iter := 0; iter < 1500; iter++ {
		pattern := randomPattern(rng, 2)
		std, err := stdregexp.Compile(pattern)
		if err != nil {
			continue
		}
		got, err := Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		stdPrefix, stdComplete := std.LiteralPrefix()
		gotPrefix, gotComplete := got.LiteralPrefix()
		if gotPrefix != stdPrefix || gotComplete != stdComplete {
			t.Fatalf("%q LiteralPrefix = (%q, %v), stdlib (%q, %v)",
				pattern, gotPrefix, gotComplete, stdPrefix, stdComplete)
		}
		std.Longest()
		got.Longest()
		for _, input := range inputs {
			if a, b := got.FindString(input), std.FindString(input); a != b {
				t.Fatalf("%q Longest FindString(%q) = %q, stdlib %q", pattern, input, a, b)
			}
			if a, b := got.FindStringIndex(input), std.FindStringIndex(input); !equalInts(a, b) {
				t.Fatalf("%q Longest FindStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindStringSubmatchIndex(input), std.FindStringSubmatchIndex(input); !equalInts(a, b) {
				t.Fatalf("%q Longest FindStringSubmatchIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindAllString(input, -1), std.FindAllString(input, -1); !equalStrings(a, b) {
				t.Fatalf("%q Longest FindAllString(%q) = %q, stdlib %q", pattern, input, a, b)
			}
			if a, b := got.FindAllStringSubmatchIndex(input, -1), std.FindAllStringSubmatchIndex(input, -1); !equalIntsMatrix(a, b) {
				t.Fatalf("%q Longest FindAllStringSubmatchIndex(%q) = %v, stdlib %v",
					pattern, input, a, b)
			}
		}
	}
}

// TestRandomExpandCompatibility compares replacement templates against the standard library. |
// TestRandomExpandCompatibility 与标准库比较替换模板。
func TestRandomExpandCompatibility(t *testing.T) {
	patterns := []string{`(a)(b)?`, `(?P<x>a)(b)`, `(a|ab)(b*)`, `a+`, `(a)?(b)?`, `(?P<a1>a)`}
	templates := []string{
		"$0", "$1", "$2", "${1}", "$1x", "${1}x", "$$", "$01", "$10",
		"$名", "${名}", "$", "${1", "x$", "$1-$2", "$$1", "${missing}",
	}
	inputs := []string{"", "a", "ab", "aab", "b", "zzab"}
	for _, pattern := range patterns {
		std := stdregexp.MustCompile(pattern)
		got := MustCompile(pattern)
		for _, input := range inputs {
			stdMatch := std.FindStringSubmatchIndex(input)
			gotMatch := got.FindStringSubmatchIndex(input)
			if !equalInts(stdMatch, gotMatch) {
				t.Fatalf("%q match = %v, stdlib %v", pattern, gotMatch, stdMatch)
			}
			if stdMatch == nil {
				continue
			}
			for _, template := range templates {
				want := std.ExpandString(nil, template, input, stdMatch)
				have := got.ExpandString(nil, template, input, gotMatch)
				if !bytes.Equal(have, want) {
					t.Fatalf("%q ExpandString(%q, %q) = %q, stdlib %q",
						pattern, template, input, have, want)
				}
			}
		}
	}
}

// TestRandomPOSIXCompatibility generates POSIX-valid and intentionally invalid patterns. |
// TestRandomPOSIXCompatibility 生成 POSIX 合法与故意非法的模式。
func TestRandomPOSIXCompatibility(t *testing.T) {
	rng := rand.New(rand.NewSource(20261032))
	inputs := []string{"", "a", "b", "ab", "aab", "abc", "a1", "\n", "a\n", "世", "aaa"}
	for iter := 0; iter < 1000; iter++ {
		pattern := randomPOSIXPattern(rng, 2)
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
			if a, b := got.FindAllString(input, -1), std.FindAllString(input, -1); !equalStrings(a, b) {
				t.Fatalf("%q FindAllString(%q) = %q, stdlib %q", pattern, input, a, b)
			}
		}
	}
}

// randomPOSIXPattern builds a POSIX ERE pattern. | randomPOSIXPattern 构造 POSIX ERE 模式。
func randomPOSIXPattern(rng *rand.Rand, depth int) string {
	atoms := []string{
		"a", "b", "c", ".", "[a-c]", "[^a]", "[[:alpha:]]", "[[:digit:]]",
		`\n`, `\.`, "0",
	}
	if depth <= 0 {
		atom := atoms[rng.Intn(len(atoms))]
		if rng.Intn(3) == 0 {
			switch rng.Intn(4) {
			case 0:
				atom += "*"
			case 1:
				atom += "+"
			case 2:
				atom += "?"
			default:
				atom += "{1,2}"
			}
		}
		return atom
	}
	switch rng.Intn(5) {
	case 0:
		return randomPOSIXPattern(rng, 0)
	case 1:
		return "(" + randomPOSIXPattern(rng, depth-1) + ")"
	case 2:
		return randomPOSIXPattern(rng, depth-1) + randomPOSIXPattern(rng, depth-1)
	case 3:
		return "(" + randomPOSIXPattern(rng, depth-1) + "|" + randomPOSIXPattern(rng, depth-1) + ")"
	default:
		return "^" + randomPOSIXPattern(rng, depth-1) + "$"
	}
}

// TestRandomReaderCompatibility compares reader offsets for arbitrary reported rune sizes. |
// TestRandomReaderCompatibility 对任意上报符文大小比较 reader 偏移。
func TestRandomReaderCompatibility(t *testing.T) {
	rng := rand.New(rand.NewSource(20261033))
	runes := []rune{'a', 'b', '世', '😀', '\n'}
	patterns := []string{`a`, `b`, `a+`, `[ab]+`, `a(b+)`, `世`, `😀`, `(a)(b)?`}
	for iter := 0; iter < 500; iter++ {
		n := 1 + rng.Intn(8)
		rs := make([]rune, n)
		sizes := make([]int, n)
		for i := range rs {
			rs[i] = runes[rng.Intn(len(runes))]
			sizes[i] = 1 + rng.Intn(4)
		}
		newReader := func() *sizedReader { return &sizedReader{runes: rs, sizes: sizes} }
		for _, pattern := range patterns {
			std := stdregexp.MustCompile(pattern)
			got := MustCompile(pattern)
			if a, b := got.MatchReader(newReader()), std.MatchReader(newReader()); a != b {
				t.Fatalf("%q runes=%q sizes=%v MatchReader = %v, stdlib %v",
					pattern, string(rs), sizes, a, b)
			}
			if a, b := got.FindReaderIndex(newReader()), std.FindReaderIndex(newReader()); !equalInts(a, b) {
				t.Fatalf("%q runes=%q sizes=%v FindReaderIndex = %v, stdlib %v",
					pattern, string(rs), sizes, a, b)
			}
			if a, b := got.FindReaderSubmatchIndex(newReader()), std.FindReaderSubmatchIndex(newReader()); !equalInts(a, b) {
				t.Fatalf("%q runes=%q sizes=%v FindReaderSubmatchIndex = %v, stdlib %v",
					pattern, string(rs), sizes, a, b)
			}
		}
	}
}
