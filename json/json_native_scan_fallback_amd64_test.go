//go:build amd64 && !jsonx_std

package json

import (
	"strings"
	"testing"
)

// TestSSE2Fallback forces the AVX2 flag off and compares the SSE2 kernels with the portable tail
// scanner, covering quotes, escapes, control bytes, non-ASCII bytes and block boundaries. |
// TestSSE2Fallback 关闭 AVX2 标志，将 SSE2 内核与可移植尾部扫描器对拍，覆盖引号、转义、控制字节、
// 非 ASCII 字节与块边界。
func TestSSE2Fallback(t *testing.T) {
	if !useAVX2 {
		t.Skip("AVX2 not reported by this CPU | 该 CPU 未报告 AVX2")
	}
	useAVX2 = false
	defer func() { useAVX2 = true }()

	bodies := []string{
		"", "plain", "bench-user", strings.Repeat("a", 15), strings.Repeat("b", 16),
		strings.Repeat("c", 31), strings.Repeat("d", 32), strings.Repeat("e", 33),
		strings.Repeat("f", 63), strings.Repeat("g", 64), strings.Repeat("h", 65),
		`a\"b`, `\n\t`, "a\x01b", `quote"here`, "héllo", "日本語", `end\\`,
	}
	for _, body := range bodies {
		data := []byte(`"` + body + `",tail-padding-to-cover-blocks`)
		gotEnd, gotSlow, gotNon := scanStringBody(data, 1)
		wantEnd, wantSlow, wantNon := scanStringBodyTail(data, 1, false)
		if gotEnd != wantEnd || gotSlow != wantSlow || gotNon != wantNon {
			t.Fatalf("scanStringBody(%q) = (%d,%v,%v), want (%d,%v,%v)",
				body, gotEnd, gotSlow, gotNon, wantEnd, wantSlow, wantNon)
		}
		for _, html := range []bool{false, true} {
			got := jsonStringNeedsEscape(body, html)
			want := jsonStringNeedsEscapeTail(body, 0, html)
			if got != want {
				t.Fatalf("jsonStringNeedsEscape(%q, html=%v) = %v, want %v", body, html, got, want)
			}
		}
	}
}
