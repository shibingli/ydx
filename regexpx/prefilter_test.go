package regexpx

import (
	"math/rand"
	"testing"
)

// TestRequiredBytesAnalysis pins conservative byte conditions. | TestRequiredBytesAnalysis 固定保守
// 字节条件。
func TestRequiredBytesAnalysis(t *testing.T) {
	tests := []struct {
		pattern  string
		ok       bool
		minCount int
		byte     byte
	}{
		{pattern: `abcdef`, ok: true, minCount: 6, byte: 'c'},
		{pattern: `(?:abc|def)`, ok: true, minCount: 3, byte: 'e'},
		{pattern: `(?:ab){3}`, ok: true, minCount: 6, byte: 'a'},
		{pattern: `\d{4}`, ok: true, minCount: 4, byte: '7'},
		{pattern: `[a-z]+`, ok: true, minCount: 1, byte: 'm'},
		{pattern: `[a-z]{2,}`, ok: true, minCount: 2, byte: 'm'},
		{pattern: `(?i)abc`, ok: true, minCount: 3, byte: 'A'},
		{pattern: `é`, ok: true, minCount: 1},
		{pattern: `[^a]`, ok: false},
		{pattern: `.*`, ok: false},
		{pattern: `\p{L}+`, ok: false},
	}
	for _, test := range tests {
		re := MustCompile(test.pattern)
		req := re.prog.info.required
		if req.ok != test.ok {
			t.Fatalf("pattern=%q ok=%v want=%v", test.pattern, req.ok, test.ok)
		}
		if !test.ok {
			continue
		}
		if req.minCount != test.minCount {
			t.Fatalf("pattern=%q minCount=%d want=%d", test.pattern, req.minCount, test.minCount)
		}
		if test.byte != 0 && req.ascii[test.byte>>6]&(uint64(1)<<uint(test.byte&63)) == 0 {
			t.Fatalf("pattern=%q set missing %q", test.pattern, test.byte)
		}
	}
}

// TestRequiredBytesSoundness checks that matching inputs always satisfy the condition. |
// TestRequiredBytesSoundness 检查命中输入始终满足该条件。
func TestRequiredBytesSoundness(t *testing.T) {
	patterns := []string{
		`abcdef`, `(?:abc|def)`, `(?:ab){3}`, `\d{4}`, `[a-z]+`, `[a-z]{2,}`,
		`(?i)abc`, `é`, `\p{L}+`, `(?:foo|bar)baz`, `[!#*]{3}`, `\w{2,5}`,
		`(?i:ab)c`, `a[0-9]b`, `(?:x|y|z){2}`,
	}
	alphabet := []byte("abcXYZ019é日! #*-_ \t")
	random := rand.New(rand.NewSource(2026))
	for _, pattern := range patterns {
		re := MustCompile(pattern)
		req := re.prog.info.required
		if !req.ok {
			continue
		}
		for iteration := 0; iteration < 20000; iteration++ {
			length := random.Intn(20)
			value := make([]byte, length)
			for index := range value {
				value[index] = alphabet[random.Intn(len(alphabet))]
			}
			text := string(value)
			if re.MatchString(text) && !req.matches(text) {
				t.Fatalf("pattern=%q value=%q matched but required bytes rejected", pattern, text)
			}
		}
	}
}

// TestRequiredBytesLargeRepetition pins the punctuation-heavy CRS shape. |
// TestRequiredBytesLargeRepetition 固定标点密集的 CRS 形态。
func TestRequiredBytesLargeRepetition(t *testing.T) {
	pattern := `((?:(?:[!-\+\-:->@\[\]\^` + "`" + `\{-~]|\x{c2}\x{b4}|\x{e2}\x{80}[\x{98}\x{99}])[^!-\+\-:->@\[\]\^` + "`" + `\{-~]*?){8})`
	re := MustCompile(pattern)
	req := re.prog.info.required
	if !req.ok || req.minCount < 8 {
		t.Fatalf("required=%+v", req)
	}
	if re.MatchString("value-0-hello-world") {
		t.Fatal("benign value matched")
	}
	if req.matches("value-0-hello-world") {
		t.Fatalf("benign value passed required-byte filter: min=%d anyHigh=%v ascii0=%064b ascii1=%064b", req.minCount, req.anyHigh, req.ascii[0], req.ascii[1])
	}
}

// TestRequiredBytesCaptureAndStart verifies the prefilter is transparent to capture, find-all and
// lookbehind paths. | TestRequiredBytesCaptureAndStart 验证预过滤对捕获、批量查找与后行路径透明。
func TestRequiredBytesCaptureAndStart(t *testing.T) {
	re := MustCompile(`[!#]{3}`)
	if groups := re.FindStringSubmatch("--!!!x"); len(groups) == 0 || groups[0] != "!!!" {
		t.Fatalf("capture = %v", groups)
	}
	if matches := re.FindAllString("--!!!x--###", -1); len(matches) != 2 {
		t.Fatalf("find all = %v", matches)
	}
	look := MustCompile(`(?<=a)[!#]{3}`)
	if groups := look.FindStringSubmatch("a!!!"); len(groups) == 0 || groups[0] != "!!!" {
		t.Fatalf("lookbehind capture = %v", groups)
	}
}

// TestRequiredByteConditionsSoundness checks every conjunctive condition against matching inputs. |
// TestRequiredByteConditionsSoundness 对命中输入检查每个合取条件。
func TestRequiredByteConditionsSoundness(t *testing.T) {
	patterns := []string{
		`abcdef`, `(?:abc|def)`, `(?:ab){3}`, `\d{4}`, `[a-z]+`, `[a-z]{2,}`,
		`(?i)abc`, `é`, `\p{L}+`, `(?:foo|bar)baz`, `[!#*]{3}`, `\w{2,5}`,
		`(?i:ab)c`, `a[0-9]b`, `(?:x|y|z){2}`, `(?:a!|b!)`, `(?:a!|b\?)`,
		`(?:foo[!]|bar[!])`, `(?:a[0-9]|b[0-9])c`, `(?:^|;)cmd[!]`,
	}
	alphabet := []byte("abcXYZ019é日!?#*-_ \t;")
	random := rand.New(rand.NewSource(2027))
	for _, pattern := range patterns {
		re := MustCompile(pattern)
		conditions := re.prog.info.requiredConditions
		if conditions.count == 0 {
			continue
		}
		for iteration := 0; iteration < 20000; iteration++ {
			length := random.Intn(24)
			value := make([]byte, length)
			for index := range value {
				value[index] = alphabet[random.Intn(len(alphabet))]
			}
			text := string(value)
			if !re.MatchString(text) {
				continue
			}
			for i := uint8(0); i < conditions.count; i++ {
				if !conditions.conditions[i].matches(text) {
					t.Fatalf("pattern=%q value=%q matched but condition %d rejected", pattern, text, i)
				}
			}
		}
	}
}

// TestRequiredByteConditionsCommonSuffix verifies that a condition common to every alternation
// branch survives composition. | TestRequiredByteConditionsCommonSuffix 验证每个分支共有的条件在组合后
// 仍会保留。
func TestRequiredByteConditionsCommonSuffix(t *testing.T) {
	re := MustCompile(`(?:a[!]|b[!])`)
	conditions := re.prog.info.requiredConditions
	if conditions.count == 0 {
		t.Fatal("common branch condition was dropped")
	}
	found := false
	for i := uint8(0); i < conditions.count; i++ {
		condition := conditions.conditions[i]
		if condition.ascii == (byteSet{0: uint64(1) << uint('!'&63)}) && condition.minCount >= 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("conditions=%+v do not include the common '!' condition", conditions)
	}
}

// TestRequiredBytesUnicodeFold verifies high-byte handling under simple folding. |
// TestRequiredBytesUnicodeFold 验证简单折叠下的高位字节处理。
func TestRequiredBytesUnicodeFold(t *testing.T) {
	re := MustCompile(`(?i)k`)
	if !re.MatchString("K") {
		t.Fatal("Unicode fold match rejected")
	}
	re = MustCompile(`[\x{00e9}]`)
	if !re.MatchString("é") {
		t.Fatal("Latin-1 class match rejected")
	}
}
