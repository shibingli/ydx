//go:build arm64 && !jsonx_std

package json

//go:noescape
func scanStringBodyNEON(data []byte, start int) int

// scanStringBody scans full 16-byte blocks with NEON until one contains a quote, backslash, control
// byte or non-ASCII byte, then finishes with the portable tail scanner. NEON is the arm64 baseline,
// so no runtime feature check or Go-version-specific SIMD package is involved. |
// scanStringBody 用 NEON 扫描完整 16 字节块，遇到含引号、反斜杠、控制字节或非 ASCII 字节的块后交给
// 可移植尾部扫描器。NEON 是 arm64 基线，因此不需要运行时特性检测，也不依赖特定 Go 版本的 SIMD 包。
func scanStringBody(data []byte, start int) (end int, slow bool, nonASCII bool) {
	i := start
	if len(data)-i >= 16 {
		i = scanStringBodyNEON(data, start)
	}
	return scanStringBodyTail(data, i, false)
}
