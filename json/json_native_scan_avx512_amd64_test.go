//go:build amd64 && !jsonx_std

package json

import (
	"strings"
	"testing"
)

// TestAVX512Kernels exercises the 64-byte AVX-512 blocks when the host reports AVX-512BW,
// comparing both scanners with the portable tail across block boundaries and special bytes. |
// TestAVX512Kernels 在主机报告 AVX-512BW 时覆盖 64 字节 AVX-512 块，跨块边界与特殊字节对比两个
// 扫描器与可移植尾部。
func TestAVX512Kernels(t *testing.T) {
	if !useAVX512BW {
		t.Skip("AVX-512BW not reported by this CPU | 该 CPU 未报告 AVX-512BW")
	}
	if !haveAVX512VL || !haveAVX512VBM || !haveAVX512VB2 {
		t.Logf("AVX-512 feature subset: vl=%v vbmi=%v vbmi2=%v", haveAVX512VL, haveAVX512VBM, haveAVX512VB2)
	}
	base := strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789", 6) // 216 bytes
	specials := []struct {
		name string
		body string
	}{
		{"quote-at-63", base[:63] + `"` + base[63:]},
		{"quote-at-64", base[:64] + `"` + base[64:]},
		{"quote-at-127", base[:127] + `"` + base[127:]},
		{"escape-at-64", base[:64] + `\n` + base[66:]},
		{"control-at-70", base[:70] + "\x01" + base[71:]},
		{"high-at-80", base[:80] + "é" + base[82:]},
		{"clean-216", base},
	}
	for _, tc := range specials {
		data := []byte(`"` + tc.body + `",padding-to-cover-blocks`)
		gotEnd, gotSlow, gotNon := scanStringBody(data, 1)
		wantEnd, wantSlow, wantNon := scanStringBodyTail(data, 1, false)
		if gotEnd != wantEnd || gotSlow != wantSlow || gotNon != wantNon {
			t.Fatalf("%s: scanStringBody = (%d,%v,%v), want (%d,%v,%v)",
				tc.name, gotEnd, gotSlow, gotNon, wantEnd, wantSlow, wantNon)
		}
		for _, html := range []bool{false, true} {
			got := jsonStringNeedsEscape(tc.body, html)
			want := jsonStringNeedsEscapeTail(tc.body, 0, html)
			if got != want {
				t.Fatalf("%s: jsonStringNeedsEscape(html=%v) = %v, want %v", tc.name, html, got, want)
			}
		}
	}
}
