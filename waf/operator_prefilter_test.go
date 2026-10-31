package waf

import (
	"math/rand"
	"testing"

	"github.com/shibingli/ydx/regexpx"
)

// TestRegexSuffixNeedle pins the conservative extraction rules. | TestRegexSuffixNeedle 固定保守提取规则。
func TestRegexSuffixNeedle(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		needle  string
		fold    bool
		ok      bool
	}{
		{name: "literal", pattern: "foo", needle: "foo", ok: true},
		{name: "after-group", pattern: "(?:a|b);", needle: ";", ok: true},
		{name: "after-class", pattern: `[a-z]+-\d-attack`, needle: "-attack", ok: true},
		{name: "folded-suffix", pattern: "(?i)(?:a|b)javascript", needle: "javascript", fold: true, ok: true},
		{name: "scoped-fold-is-conservative", pattern: "(?i:foo)bar", needle: "bar", fold: true, ok: true},
		{name: "escaped-paren", pattern: `x\(`, needle: "x(", ok: true},
		{name: "escaped-dot", pattern: `x\.y`, needle: "x.y", ok: true},
		{name: "dollar-anchor", pattern: "foo$", needle: "foo", ok: true},
		{name: "word-boundary", pattern: `foo\b`, needle: "foo", ok: true},
		{name: "text-end", pattern: `foo\z`, needle: "foo", ok: true},
		{name: "literal-dollar", pattern: `foo\$`, needle: "foo$", ok: true},
		{name: "semicolon", pattern: "^x;", needle: "x;", ok: true},
		{name: "after-optional-group", pattern: "(?:a|b)?baz", needle: "baz", ok: true},
		{name: "after-lookahead", pattern: "(?=a)baz", needle: "baz", ok: true},
		{name: "after-named-group", pattern: "(?P<name>a)baz", needle: "baz", ok: true},
		{name: "after-comment", pattern: "(?#note)baz", needle: "baz", ok: true},
		{name: "after-hex", pattern: `\x41baz`, needle: "baz", ok: true},
		{name: "after-property", pattern: `\p{L}baz`, needle: "baz", ok: true},
		{name: "after-backref", pattern: `\1baz`, needle: "baz", ok: true},
		{name: "no-optional", pattern: "foo?", ok: false},
		{name: "no-star", pattern: "foo*", ok: false},
		{name: "no-alternation", pattern: "foo|bar", ok: false},
		{name: "no-group-only", pattern: "(?:foo|bar)", ok: false},
		{name: "no-class-only", pattern: "[a-z]+", ok: false},
		{name: "no-quoted", pattern: `\Qfoo\E`, ok: false},
		{name: "no-free-spacing", pattern: "(?x)foo", ok: false},
		{name: "no-free-spacing-inline", pattern: "(?ix)foo", ok: false},
		{name: "no-unknown-escape", pattern: `foo\qbar`, ok: false},
		{name: "no-posix-class", pattern: "[[:alpha:]]foo", ok: false},
		{name: "empty", pattern: "", ok: false},
		{name: "single-alnum", pattern: "x", ok: false},
		{name: "folded-non-ascii", pattern: "(?i)é", ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			needle, fold, ok := regexSuffixNeedle(test.pattern)
			if ok != test.ok {
				t.Fatalf("ok = %v, want %v (needle=%q fold=%v)", ok, test.ok, needle, fold)
			}
			if !ok {
				return
			}
			if needle != test.needle || fold != test.fold {
				t.Fatalf("needle=%q fold=%v, want %q/%v", needle, fold, test.needle, test.fold)
			}
		})
	}
}

// TestRegexSuffixNeedleSoundness checks that no matching string is rejected by the prefilter.
// | TestRegexSuffixNeedleSoundness 检查任何命中字符串都不会被预过滤拒绝。
func TestRegexSuffixNeedleSoundness(t *testing.T) {
	patterns := []string{
		"foo", "(?:a|b);", `[a-z]+-\d-attack`, "(?i)(?:a|b)javascript",
		`x\(`, `x\.y`, "foo$", `foo\b`, `foo\z`, `foo\$`, "(?:a|b)?baz",
		"(?=a)baz", "(?P<name>a)baz", "(?#note)baz", `\x41baz`, `\p{L}baz`,
		`\1baz`, `[a-z]+(?:x|y)end`, `(?:a|b)+tail`, "(?i)url\\(javascript",
	}
	alphabet := []byte("abcjurlpestx012;:/()-. '")
	random := rand.New(rand.NewSource(42))
	for _, pattern := range patterns {
		needle, fold, ok := regexSuffixNeedle(pattern)
		if !ok {
			continue
		}
		compiled, err := regexpx.Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		for iteration := 0; iteration < 5000; iteration++ {
			length := random.Intn(10)
			value := make([]byte, length)
			for index := range value {
				value[index] = alphabet[random.Intn(len(alphabet))]
			}
			text := string(value)
			if compiled.MatchString(text) && !containsNeedle(text, needle, fold) {
				t.Fatalf("pattern=%q needle=%q fold=%v value=%q matched but prefilter rejected", pattern, needle, fold, text)
			}
		}
	}
}
