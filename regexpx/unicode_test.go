package regexpx

import (
	stdregexp "regexp"
	"strings"
	"testing"
)

// emojiAndMixedInputs covers emoji, ZWJ sequences, skin tones, flags, variation selectors,
// combining marks, simplified and traditional Chinese, and mixed Chinese/English text. |
// emojiAndMixedInputs 覆盖表情、ZWJ 序列、肤色、旗帜、变体选择符、组合字符、简繁中文与中英混排。
var emojiAndMixedInputs = []string{
	"😀", "😀😁😂", "a😀b", "👍🏽", "❤️", "🇨🇳", "👨‍👩‍👧‍👦",
	"简体中文，繁體中文，English 123！", "中文 English 123", "用户中心",
	"é", "前缀用户后缀", "😀用户👍🏽世界", "繁體中文與简体中文並存。",
	"Hello 世界！How are you？", "ΑΒΓ 中文 😀", "straße STRASSE", "希腊ΑΒΓ",
}

// emojiAndMixedPatterns are RE2 patterns exercised against the standard library. |
// emojiAndMixedPatterns 是与标准库对照的 RE2 模式。
var emojiAndMixedPatterns = []string{
	`😀`, `😀+`, `👍🏽`, `❤️`, `👨‍👩‍👧‍👦`, `[\x{1F600}-\x{1F64F}]+`, `\p{So}+`,
	`.`, `..`, `^..$`, `[\p{Han}]+`, `\p{Han}+`, `[，。！？]+`,
	`中文`, `用户`, `English`, `\bEnglish\b`, `\d+`, `\w+`, `(?i)straße`,
	"é", `希腊ΑΒΓ`, `^😀`, `😀$`, `(?s).*😀.*`,
}

// TestEmojiAndMixedDifferential compares emoji and mixed-script matching with the standard library.
// | TestEmojiAndMixedDifferential 把表情与混合文字匹配同标准库对比。
func TestEmojiAndMixedDifferential(t *testing.T) {
	for _, pattern := range emojiAndMixedPatterns {
		std, err := stdregexp.Compile(pattern)
		if err != nil {
			continue
		}
		got, err := Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		for _, input := range emojiAndMixedInputs {
			if a, b := got.MatchString(input), std.MatchString(input); a != b {
				t.Errorf("%q.MatchString(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindStringIndex(input), std.FindStringIndex(input); !equalInts(a, b) {
				t.Errorf("%q.FindStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindStringSubmatchIndex(input), std.FindStringSubmatchIndex(input); !equalInts(a, b) {
				t.Errorf("%q.FindStringSubmatchIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.FindAllStringIndex(input, -1), std.FindAllStringIndex(input, -1); !equalIntsMatrix(a, b) {
				t.Errorf("%q.FindAllStringIndex(%q) = %v, stdlib %v", pattern, input, a, b)
			}
			if a, b := got.ReplaceAllString(input, "<$0>"), std.ReplaceAllString(input, "<$0>"); a != b {
				t.Errorf("%q.ReplaceAllString(%q) = %q, stdlib %q", pattern, input, a, b)
			}
			if a, b := got.Split(input, -1), std.Split(input, -1); !equalStrings(a, b) {
				t.Errorf("%q.Split(%q) = %q, stdlib %q", pattern, input, a, b)
			}
		}
	}
}

// TestEmojiByteIndices pins byte offsets for four-byte runes, skin tones and flags. |
// TestEmojiByteIndices 钉住四字节符文、肤色与旗帜的字节偏移。
func TestEmojiByteIndices(t *testing.T) {
	text := "a😀b👍🏽c"
	cases := []struct {
		pattern string
		want    []int
	}{
		{`a`, []int{0, 1}},
		{`😀`, []int{1, 5}},
		{`b`, []int{5, 6}},
		{`👍`, []int{6, 10}},
		{`👍🏽`, []int{6, 14}},
		{`c`, []int{14, 15}},
	}
	for _, tc := range cases {
		got, err := Compile(tc.pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", tc.pattern, err)
		}
		if idx := got.FindStringIndex(text); !equalInts(idx, tc.want) {
			t.Errorf("%q.FindStringIndex = %v, want %v", tc.pattern, idx, tc.want)
		}
	}
	// Dot matches each code point, including combining marks and ZWJ members. | 点号匹配每个码点，
	// 包括组合字符与 ZWJ 成员。
	dot := MustCompile(`.`)
	seq := "👨‍👩‍👧‍👦"
	all := dot.FindAllStringIndex(seq, -1)
	if len(all) == 0 || all[0][0] != 0 || all[0][1] != 4 {
		t.Fatalf("dot on ZWJ family = %v", all)
	}
	if last := all[len(all)-1]; last[1] != len(seq) {
		t.Fatalf("dot last match = %v, want end %d", last, len(seq))
	}
}

// TestEmojiBacktracking covers lookaround and backreferences around multi-byte runes. |
// TestEmojiBacktracking 覆盖多字节符文周围的环视与反向引用。
func TestEmojiBacktracking(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
		want    bool
	}{
		{`(?<=😀)👍`, "😀👍", true},
		{`(?<=😀)👍`, "x👍", false},
		{`(?<!😀)👍`, "x👍", true},
		{`(?<!😀)👍`, "😀👍", false},
		{`(😀)\1`, "😀😀", true},
		{`(😀)\1`, "😀👍", false},
		{`(?=😀)😀`, "😀", true},
		{`(?i)(?<w>[a-z]+)\s+\k<w>`, "Hello hello", true},
		{`(?'e'👍🏽)\k<e>`, "👍🏽👍🏽", true},
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

// TestEmojiLargeText compares bulk scans on mixed emoji and Chinese text with the standard library.
// | TestEmojiLargeText 在表情与中文混合文本上把批量扫描与标准库对比。
func TestEmojiLargeText(t *testing.T) {
	text := strings.Repeat("用户😀 hello 世界👍🏽 繁體中文，English！ 2024-07-15 ❤️ 🇨🇳 ", 4000)
	patterns := []string{`\p{Han}+`, `\p{So}+`, `[\x{1F600}-\x{1F64F}]+`, `用户`, `.`, `\w+`, `[，。！？]+`, `English`, `\d{4}-\d{2}-\d{2}`}
	for _, pattern := range patterns {
		std, err := stdregexp.Compile(pattern)
		if err != nil {
			continue
		}
		re, err := Compile(pattern)
		if err != nil {
			t.Fatalf("Compile(%q): %v", pattern, err)
		}
		want := std.FindAllStringIndex(text, -1)
		got := re.FindAllStringIndex(text, -1)
		if !equalIntsMatrix(got, want) {
			t.Fatalf("%q: got %d matches, want %d", pattern, len(got), len(want))
		}
		if par := re.FindAllStringIndexParallel(text, -1); !equalIntsMatrix(par, got) {
			t.Fatalf("%q: parallel result differs", pattern)
		}
	}
}
