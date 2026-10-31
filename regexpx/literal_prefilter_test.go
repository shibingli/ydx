package regexpx

import (
	"math/rand"
	"testing"
)

// TestRequiredLiteralsAnalysis pins required-literal extraction. | TestRequiredLiteralsAnalysis 固定
// 必需字面量提取。
func TestRequiredLiteralsAnalysis(t *testing.T) {
	tests := []struct {
		pattern string
		literal string
		fold    bool
		ok      bool
	}{
		{pattern: `[a-z]+-attack`, literal: "-attack", ok: true},
		{pattern: `(?:foo|bar)baz`, literal: "baz", ok: true},
		{pattern: `(?i)ABC`, literal: "ABC", fold: true, ok: true},
		{pattern: `[a-z]+`, ok: false},
		{pattern: `a[0-9]b`, literal: "a", ok: true},
		{pattern: `(?i)é`, ok: false},
	}
	for _, test := range tests {
		ast, _, _, err := parsePatternWithMode(test.pattern, false)
		if err != nil {
			t.Fatalf("parse %q: %v", test.pattern, err)
		}
		req := analyzeRequiredLiterals(ast)
		if req.ok != test.ok {
			t.Fatalf("pattern=%q ok=%v want=%v values=%v", test.pattern, req.ok, test.ok, req.values)
		}
		if !test.ok {
			continue
		}
		found := false
		for _, value := range req.values {
			if value == test.literal {
				found = true
			}
		}
		if !found || req.fold != test.fold {
			t.Fatalf("pattern=%q values=%v fold=%v want %q/%v", test.pattern, req.values, req.fold, test.literal, test.fold)
		}
	}
}

// TestRequiredLiteralsSoundness checks that matching values always satisfy the literal filter. |
// TestRequiredLiteralsSoundness 检查命中值始终满足字面量过滤。
func TestRequiredLiteralsSoundness(t *testing.T) {
	patterns := []string{
		`[a-z]+-attack`, `(?:foo|bar)baz`, `(?i)ABC`,
		`(?:alpha|beta|gamma)`, `(?:command0|command1|command2)`,
		`x(?:foo|bar)y`, `(?i:prefix)suffix`, `[!#]+needle`,
	}
	alphabet := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-!# ")
	random := rand.New(rand.NewSource(77))
	for _, pattern := range patterns {
		re := MustCompile(pattern)
		filter := re.prog.info.literals
		if !filter.ok {
			continue
		}
		for iteration := 0; iteration < 20000; iteration++ {
			length := random.Intn(24)
			value := make([]byte, length)
			for index := range value {
				value[index] = alphabet[random.Intn(len(alphabet))]
			}
			text := string(value)
			if re.MatchString(text) && !filter.matches(text) {
				t.Fatalf("pattern=%q value=%q matched but literal filter rejected", pattern, text)
			}
		}
	}
}

// TestRequiredLiteralFilterQuality pins filter construction and rejection. |
// TestRequiredLiteralFilterQuality 固定过滤器构建与拒绝行为。
// TestContainsLiteralFolded verifies the SIMD fold-pair path, including negative values with many
// first-pair candidates and the conservative non-ASCII fallback. | TestContainsLiteralFolded 验证
// SIMD 折叠字节对路径，包括含大量首字节对候选的否定值与非 ASCII 保守回退。
func TestContainsLiteralFolded(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"xxERRORyy", true},
		{"error", true},
		{"prefix-error", true},
		{"user123 user456 user789", false},
		{"ERR", false},
		{"erroré", true},
		{"éuser", true},
		{"", false},
	}
	for _, test := range tests {
		if got := containsLiteral(test.value, "error", true); got != test.want {
			t.Fatalf("containsLiteral(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestRequiredLiteralFilterQuality(t *testing.T) {
	re := MustCompile(`[a-z]+-attack`)
	if !re.prog.info.literals.ok {
		t.Fatal("suffix filter not built")
	}
	if re.prog.info.literals.matches("value-0-hello-world") {
		t.Fatal("benign value passed suffix filter")
	}
	if !re.prog.info.literals.matches("xx-attack") {
		t.Fatal("candidate value rejected")
	}
	weak := MustCompile(`a[0-9]b`)
	if weak.prog.info.literals.ok {
		t.Fatal("single-letter filter should be rejected")
	}
	fold := MustCompile(`(?i)ABC`)
	if fold.prog.info.literals.ok {
		t.Fatal("literal filter duplicating the prefix should be dropped")
	}
	if !fold.MatchString("xxabc") {
		t.Fatal("folded prefix search failed")
	}
}
