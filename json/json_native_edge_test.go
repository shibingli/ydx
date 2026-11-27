package json

import (
	"strings"
	"testing"
)

// TestValidRejectsUnitSeparator covers every scanner kernel including AVX-512,
// which previously compared with unsigned-less rather than less-or-equal. |
// TestValidRejectsUnitSeparator 覆盖所有扫描内核（包括 AVX-512），后者此前使用
// 无符号小于而非小于等于。
func TestValidRejectsUnitSeparator(t *testing.T) {
	raw := []byte(`"` + strings.Repeat("a", 10) + "\x1f" + strings.Repeat("a", 100) + `"`)
	if Valid(raw) {
		t.Fatal("Valid accepted a raw 0x1F control byte")
	}
	var v string
	if err := Unmarshal(raw, &v); err == nil {
		t.Fatal("Unmarshal accepted a raw 0x1F control byte")
	}
}

// TestMarshalEscapesUnitSeparator verifies the long-string fast path escapes
// 0x1F instead of emitting invalid JSON. | TestMarshalEscapesUnitSeparator 验证长
// 字符串快速路径转义 0x1F，而不是输出非法 JSON。
func TestMarshalEscapesUnitSeparator(t *testing.T) {
	value := strings.Repeat("a", 100) + "\x1f"
	out, err := Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(string(out), 0x1f) {
		t.Fatalf("Marshal emitted a raw 0x1F: %q", out)
	}
	if !Valid(out) {
		t.Fatalf("Marshal produced invalid JSON: %q", out)
	}
}

// TestV2SkippedStringRejectsInvalidUTF8 verifies the slow skip path validates
// non-ASCII bytes even when the string contains an escape. |
// TestV2SkippedStringRejectsInvalidUTF8 验证含转义的慢路径仍校验非 ASCII 字节。
func TestV2SkippedStringRejectsInvalidUTF8(t *testing.T) {
	var v struct{}
	raw := []byte("{\"x\":\"\n\xff\"}")
	if err := Unmarshal(raw, &v, DefaultOptionsV2()); err == nil {
		t.Fatal("v2 accepted invalid UTF-8 in a skipped string")
	}
}
