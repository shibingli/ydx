package waf

import (
	"math/rand"
	"testing"

	"github.com/shibingli/ydx/regexpx"
)

// TestRegexRequiredNeedles pins the structured extraction cases. | TestRegexRequiredNeedles 固定结构化
// 提取用例。
func TestRegexRequiredNeedles(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		ok       bool
		fold     bool
		contains string
	}{
		{name: "literal", pattern: "foo", ok: true, contains: "foo"},
		{name: "alternation", pattern: "foo|bar", ok: true, contains: "foo"},
		{name: "alternation-suffix", pattern: "(?:foo|bar)baz", ok: true, contains: "baz"},
		{name: "optional-then-literal", pattern: "foo?bar", ok: true, contains: "bar"},
		{name: "mandatory-group", pattern: "(?:get|post|put)", ok: true, contains: "post"},
		{name: "repeat-mandatory", pattern: "(?:foo|bar)+", ok: true, contains: "bar"},
		{name: "capture", pattern: "(?P<name>foo)bar", ok: true, contains: "foo"},
		{name: "lookahead-outside", pattern: "(?=foo)bar", ok: true, contains: "bar"},
		{name: "lookbehind-outside", pattern: "(?<=foo)bar", ok: true, contains: "bar"},
		{name: "fold", pattern: "(?i)foo", ok: true, fold: true, contains: "foo"},
		{name: "scoped-fold", pattern: "(?i:foo)bar", ok: true, fold: true, contains: "foo"},
		{name: "class-only", pattern: "[a-z]+", ok: false},
		{name: "optional-only", pattern: "foo?", ok: false},
		{name: "empty-branch", pattern: "foo|", ok: false},
		{name: "free-spacing", pattern: "(?x)foo", ok: false},
		{name: "quoted", pattern: `\Qfoo\E`, ok: false},
		{name: "hex-only", pattern: `\x41`, ok: false},
		{name: "backreference-only", pattern: `\1`, ok: false},
		{name: "folded-non-ascii", pattern: "(?i)é", ok: false},
		{name: "pcree-verb", pattern: "(*SKIP)foo", ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			needles, fold, ok := regexRequiredNeedles(test.pattern)
			if ok != test.ok {
				t.Fatalf("ok=%v want=%v needles=%v fold=%v", ok, test.ok, needles, fold)
			}
			if !ok {
				return
			}
			if fold != test.fold {
				t.Fatalf("fold=%v want=%v", fold, test.fold)
			}
			found := false
			for _, needle := range needles {
				if needle == test.contains {
					found = true
				}
			}
			if !found {
				t.Fatalf("needles=%v missing %q", needles, test.contains)
			}
		})
	}
}

// TestNeedleFilterSoundness checks that a matching value is never rejected by the filter.
// | TestNeedleFilterSoundness 检查命中值绝不会被过滤器拒绝。
func TestNeedleFilterSoundness(t *testing.T) {
	patterns := []string{
		"foo", "(?:get|post|put)", "(?:foo|bar)baz", `[a-z]+-\d-attack`,
		"(?i)(?:select|union|insert)", "(?:jsessionid|jwsession|phpsessid)",
		"(?:__proto__|constructor|prototype)", "\x28\x3f\x69\x29\x2e\x2a",
		"(?:a|b|c|d|e|f|g|h|i|j)+tail",
	}
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;:/()-._ ")
	random := rand.New(rand.NewSource(7))
	for _, pattern := range patterns {
		needles, fold, ok := regexRequiredNeedles(pattern)
		if !ok {
			continue
		}
		compiled, err := regexpx.Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		var filter *needleFilter
		if len(needles) > 1 {
			filter = newNeedleFilter(needles, fold)
		}
		for iteration := 0; iteration < 10000; iteration++ {
			length := random.Intn(16)
			value := make([]byte, length)
			for index := range value {
				value[index] = alphabet[random.Intn(len(alphabet))]
			}
			text := string(value)
			if !compiled.MatchString(text) {
				continue
			}
			if len(needles) == 1 {
				if !containsNeedle(text, needles[0], fold) {
					t.Fatalf("pattern=%q needle=%q value=%q matched but prefilter rejected", pattern, needles[0], text)
				}
				continue
			}
			if filter == nil || !filter.match(text) {
				t.Fatalf("pattern=%q needles=%v value=%q matched but filter rejected", pattern, needles, text)
			}
		}
	}
}

// TestRegexAnalysisMinLen pins conservative minimum match lengths. | TestRegexAnalysisMinLen 固定
// 保守的最小匹配长度。
func TestRegexAnalysisMinLen(t *testing.T) {
	tests := []struct {
		pattern string
		minLen  int
	}{
		{"foo", 3},
		{"foo|bar", 3},
		{"a[0-9]+", 2},
		{"[a-z]+", 1},
		{"foo?", 0},
		{"foo{2,3}", 6},
		{"(?:foo|bar)+", 3},
		{`\d{4}`, 4},
		{`\bfoo\b`, 3},
		{"(?=foo)bar", 3},
		{`(?:x)\d`, 2},
		{"a|", 0},
		{`.`, 1},
		{`\1foo`, 3},
		{"(?i)foo", 3},
		{"(?i)ſ", 0},
	}
	for _, test := range tests {
		_, _, _, minLen := regexAnalysis(test.pattern)
		if minLen != test.minLen {
			t.Fatalf("pattern=%q minLen=%d want=%d", test.pattern, minLen, test.minLen)
		}
	}
}

// TestMinLenSoundness checks that no value shorter than minLen can match. | TestMinLenSoundness 检查
// 任何短于 minLen 的取值都不可能匹配。
func TestMinLenSoundness(t *testing.T) {
	patterns := []string{
		"foo", "foo|bar", "a[0-9]+", "foo?", "foo{2,3}", "(?:foo|bar)+",
		`\d{4}`, `\bfoo\b`, "(?=foo)bar", `(?:x)\d`, `\1foo`, "(?i)foo",
		`[a-z]+-\d-attack`, "(?:get|post|put)", "(?:foo|bar)baz",
	}
	alphabet := []byte("abcdefghijklmnopqrstuvwxyz0123456789;:/()-._ ")
	random := rand.New(rand.NewSource(123))
	for _, pattern := range patterns {
		_, _, _, minLen := regexAnalysis(pattern)
		if minLen <= 0 {
			continue
		}
		compiled, err := regexpx.Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		for iteration := 0; iteration < 10000; iteration++ {
			length := random.Intn(minLen)
			value := make([]byte, length)
			for index := range value {
				value[index] = alphabet[random.Intn(len(alphabet))]
			}
			if compiled.MatchString(string(value)) {
				t.Fatalf("pattern=%q minLen=%d matched short value %q", pattern, minLen, value)
			}
		}
	}
}

// TestRegexByteSet pins byte-set extraction. | TestRegexByteSet 固定字节集提取。
func TestRegexByteSet(t *testing.T) {
	tests := []struct {
		pattern string
		byte    byte
		has     bool
		fold    bool
	}{
		{pattern: `["']foo`, byte: '"', has: true},
		{pattern: `[a-z]+`, byte: 'm', has: true},
		{pattern: `foo`, byte: 'f', has: true},
		{pattern: `(?:foo|bar)baz`, byte: 'z', has: true},
		{pattern: `(?i)[a]`, byte: 'A', has: true, fold: true},
		{pattern: `[^a]`, has: false},
		{pattern: `\d+`, has: false},
		{pattern: `[\s\S]`, has: false},
		{pattern: `[[:alpha:]]`, has: false},
	}
	for _, test := range tests {
		analysis := analyzeRegex(test.pattern)
		if analysis.hasBytes != test.has {
			t.Fatalf("pattern=%q hasBytes=%v want=%v", test.pattern, analysis.hasBytes, test.has)
		}
		if !test.has {
			continue
		}
		if !byteSetHas(analysis.bytes, test.byte) {
			t.Fatalf("pattern=%q set=%v missing %q", test.pattern, analysis.bytes, test.byte)
		}
		if test.fold && !analysis.fold {
			t.Fatalf("pattern=%q fold=false want=true", test.pattern)
		}
	}
}

// TestByteSetSoundness checks that matching values always contain a required byte. | TestByteSetSoundness
// 检查命中值始终包含必需字节。
func TestByteSetSoundness(t *testing.T) {
	patterns := []string{
		`["']foo`, `[a-z]+`, `foo`, `(?:foo|bar)baz`, `(?i)[a]`, `[\[-\]]`,
		`(?:["']|[a-z])tail`, `[!#*]+end`, `[0-9]{2}`, `\.xml$`,
	}
	alphabet := []byte("abcXYZ012\"'[]!#*._- ")
	random := rand.New(rand.NewSource(321))
	for _, pattern := range patterns {
		analysis := analyzeRegex(pattern)
		if !analysis.hasBytes {
			continue
		}
		compiled, err := regexpx.Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		for iteration := 0; iteration < 10000; iteration++ {
			length := random.Intn(12)
			value := make([]byte, length)
			for index := range value {
				value[index] = alphabet[random.Intn(len(alphabet))]
			}
			text := string(value)
			if compiled.MatchString(text) && !containsByteSet(text, analysis.bytes, analysis.fold) {
				t.Fatalf("pattern=%q set=%v fold=%v value=%q matched but byte set rejected", pattern, analysis.bytes, analysis.fold, text)
			}
		}
	}
}
