//go:build arm64 && !jsonx_std

package json

//go:noescape
func stringNeedsEscapeNEON(s string, escapeHTML bool) (scan int, needs int)

// jsonStringNeedsEscape scans full 16-byte blocks with NEON and finishes the tail with the portable
// SWAR scanner. | jsonStringNeedsEscape 用 NEON 扫描完整 16 字节块，尾部交给可移植 SWAR 扫描器。
func jsonStringNeedsEscape(s string, escapeHTML bool) bool {
	scan, needs := stringNeedsEscapeNEON(s, escapeHTML)
	if needs != 0 {
		return true
	}
	return jsonStringNeedsEscapeTail(s, scan, escapeHTML)
}
