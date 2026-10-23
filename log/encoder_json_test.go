package log

import "testing"

// TestAppendJSONString exercises the clean-ASCII fast path, every short escape, the 0x7f
// boundary, multi-byte UTF-8 and invalid UTF-8 replacement. | TestAppendJSONString 覆盖纯 ASCII
// 快速路径、各类短转义、0x7f 边界、多字节 UTF-8 与非法 UTF-8 替换。
func TestAppendJSONString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", `""`},
		{"GET", `"GET"`},
		{"/api/v1/users", `"/api/v1/users"`},
		{"quote\"inside", `"quote\"inside"`},
		{"back\\slash", `"back\\slash"`},
		{"line\nbreak", `"line\nbreak"`},
		{"carriage\rreturn", `"carriage\rreturn"`},
		{"tab\there", `"tab\there"`},
		{"back\bspace", `"back\bspace"`},
		{"form\ffeed", `"form\ffeed"`},
		{"ctrl\x01char", `"ctrl\u0001char"`},
		{"del\x7fchar", "\"del\x7fchar\""},
		{"中文文本", `"中文文本"`},
		{"mixed 中文 and ascii", `"mixed 中文 and ascii"`},
		{"bad\xffbyte", "\"bad�byte\""},
	}
	for _, c := range cases {
		got := string(appendJSONString(nil, c.in))
		if got != c.want {
			t.Fatalf("appendJSONString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestJSONCleanString checks the word-at-a-time scan at lengths around the eight-byte boundary
// and confirms that each byte class requiring escaping is rejected. | TestJSONCleanString 检查
// 八字节边界附近的按字扫描，并确认每一种需要转义的字节类别都会被拒绝。
func TestJSONCleanString(t *testing.T) {
	clean := []string{
		"", "a", "abcdefg", "abcdefgh", "abcdefghi", "GET /api/v1/users HTTP/1.1",
		"~!@#$%^&*()_+-=[]{};':,.<>/?", "del\x7f",
	}
	for _, s := range clean {
		if !jsonCleanString(s) {
			t.Fatalf("jsonCleanString(%q) = false, want true", s)
		}
	}
	dirty := []string{
		"\"", "\\", "\x00", "\x1f", "abcdefg\"", "abcdefgh\\", "abcdefgh\x1f",
		"中文", "é", "\x80", "abcdefg\x80",
	}
	for _, s := range dirty {
		if jsonCleanString(s) {
			t.Fatalf("jsonCleanString(%q) = true, want false", s)
		}
	}
}
