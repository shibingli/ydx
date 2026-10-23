//go:build amd64 && !jsonx_std

package json

//go:noescape
func stringNeedsEscapeSSE2(s string, escapeHTML bool) (scan int, needs int)

//go:noescape
func stringNeedsEscapeAVX2(s string, escapeHTML bool) (scan int, needs int)

//go:noescape
func stringNeedsEscapeAVX512(s string, escapeHTML bool) (scan int, needs int)

// jsonStringNeedsEscape scans full blocks with AVX2 when available and SSE2 otherwise, then
// finishes the tail with the portable SWAR scanner. | jsonStringNeedsEscape 在可用时用 AVX2、否则用
// SSE2 扫描完整块，尾部交给可移植 SWAR 扫描器。
func jsonStringNeedsEscape(s string, escapeHTML bool) bool {
	var scan, needs int
	switch {
	case useAVX512BW && len(s) >= 64:
		scan, needs = stringNeedsEscapeAVX512(s, escapeHTML)
	case useAVX2 && len(s) >= 32:
		scan, needs = stringNeedsEscapeAVX2(s, escapeHTML)
	case len(s) >= 16:
		scan, needs = stringNeedsEscapeSSE2(s, escapeHTML)
	}
	if needs != 0 {
		return true
	}
	return jsonStringNeedsEscapeTail(s, scan, escapeHTML)
}
