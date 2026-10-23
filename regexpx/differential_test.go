package regexpx

import (
	"math/rand"
	stdregexp "regexp"
	"testing"
)

// TestRandomDifferential generates a large pattern corpus and compares every observable result with
// the standard library. The generator only uses RE2 syntax, so the standard library is an exact
// oracle. | TestRandomDifferential 生成大量模式语料，并把每个可观测结果与标准库对比。生成器只用
// RE2 语法，因此标准库是精确的 oracle。
func TestRandomDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20261023))
	inputs := []string{
		"", "a", "b", "ab", "aab", "abc", "ABC", "a1", "a_1", " ", "  ", "\n", "a\nb",
		"-", "a-b", "a.b", "a b", "é", "世界", "Кк", "aé", "K", "aaab", "bbaa", "0123",
		"foo\nbar\n", "_", "A1_b2", "a\tb", "xyz",
		"😀", "a😀b", "用户😀世界", "👍🏽", "👨‍👩‍👧‍👦", "简体中文，繁體中文",
	}
	for iter := 0; iter < 3000; iter++ {
		pattern := randomPattern(rng, 2)
		std, err := stdregexp.Compile(pattern)
		if err != nil {
			continue
		}
		got, err := Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		for _, input := range inputs {
			if a, b := got.MatchString(input), std.MatchString(input); a != b {
				t.Fatalf("%q.MatchString(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindStringIndex(input), std.FindStringIndex(input); !equalInts(a, b) {
				t.Fatalf("%q.FindStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindStringSubmatchIndex(input), std.FindStringSubmatchIndex(input); !equalInts(a, b) {
				t.Fatalf("%q.FindStringSubmatchIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindAllStringIndex(input, -1), std.FindAllStringIndex(input, -1); !equalIntsMatrix(a, b) {
				t.Fatalf("%q.FindAllStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindAllStringSubmatchIndex(input, -1), std.FindAllStringSubmatchIndex(input, -1); !equalIntsMatrix(a, b) {
				t.Fatalf("%q.FindAllStringSubmatchIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindAllString(input, 2), std.FindAllString(input, 2); !equalStrings(a, b) {
				t.Fatalf("%q.FindAllString(%q, 2) = %q, stdlib %q", pattern, input, a, b)
			}
		}
	}
}

// randomPattern builds one random RE2 pattern with bounded depth. | randomPattern 构造一个深度受限的
// 随机 RE2 模式。
func randomPattern(rng *rand.Rand, depth int) string {
	if depth <= 0 {
		return randomAtom(rng, false)
	}
	switch rng.Intn(6) {
	case 0, 1:
		return randomAtom(rng, true)
	case 2:
		return randomConcat(rng, depth)
	case 3:
		return randomAlternation(rng, depth)
	case 4:
		return randomRepeated(rng, depth)
	default:
		return randomConcat(rng, depth)
	}
}

// randomAtom returns one atom, optionally quantified by the caller. | randomAtom 返回一个原子，可由调用方
// 添加量词。
func randomAtom(rng *rand.Rand, allowRepeat bool) string {
	atoms := []string{
		"a", "b", "A", "0", "_", " ", "-", ".", `\d`, `\w`, `\s`, `\D`, `\W`, `\S`,
		"[a-c]", "[^ab]", "[A-Za-z0-9_]", "[[:alpha:]]", `\p{L}`, "é", "世",
	}
	atom := atoms[rng.Intn(len(atoms))]
	if rng.Intn(8) == 0 {
		atom = "(?i)" + atom
	}
	if rng.Intn(6) == 0 {
		atom = "(" + randomPattern(rng, 1) + ")"
	}
	if rng.Intn(8) == 0 {
		atom = "(?:" + randomPattern(rng, 1) + ")"
	}
	if allowRepeat && rng.Intn(3) == 0 {
		switch rng.Intn(5) {
		case 0:
			atom += "*"
		case 1:
			atom += "+"
		case 2:
			atom += "?"
		case 3:
			atom += "{0,2}"
		default:
			atom += "{1,2}"
		}
		if rng.Intn(3) == 0 {
			atom += "?"
		}
	}
	return atom
}

// randomConcat joins two or three pieces. | randomConcat 连接两到三个片段。
func randomConcat(rng *rand.Rand, depth int) string {
	n := 2 + rng.Intn(2)
	out := ""
	for i := 0; i < n; i++ {
		out += randomPattern(rng, depth-1)
	}
	if rng.Intn(6) == 0 {
		out = "^" + out
	}
	if rng.Intn(6) == 0 {
		out += "$"
	}
	if rng.Intn(8) == 0 {
		out = `\b` + out
	}
	return out
}

// randomAlternation joins two or three branches. | randomAlternation 连接两到三个分支。
func randomAlternation(rng *rand.Rand, depth int) string {
	n := 2 + rng.Intn(2)
	out := randomPattern(rng, depth-1)
	for i := 1; i < n; i++ {
		out += "|" + randomPattern(rng, depth-1)
	}
	return "(?:" + out + ")"
}

// randomRepeated wraps a pattern in a bounded or unbounded repetition. | randomRepeated 用有界或无界重复
// 包裹一个模式。
func randomRepeated(rng *rand.Rand, depth int) string {
	body := "(?:" + randomPattern(rng, depth-1) + ")"
	switch rng.Intn(5) {
	case 0:
		return body + "*"
	case 1:
		return body + "+"
	case 2:
		return body + "?"
	case 3:
		return body + "{0,2}"
	default:
		return body + "{1,3}"
	}
}

// equalStrings reports whether two string slices are identical. | equalStrings 报告两个字符串切片是否
// 完全相同。
func equalStrings(a, b []string) bool {
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
