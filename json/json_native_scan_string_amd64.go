//go:build amd64 && !jsonx_std

package json

//go:noescape
func scanStringBodySSE2(data []byte, start int) int

//go:noescape
func scanStringBodyAVX2(data []byte, start int) int

//go:noescape
func scanStringBodyAVX512(data []byte, start int) int

// scanStringBody scans full blocks with the highest available kernel: AVX2 when the CPU and OS
// expose it, otherwise the SSE2 baseline. Both are hand-written assembly; the portable tail
// finishes the block that contains a quote, backslash, control byte or non-ASCII byte. |
// scanStringBody 用当前可用的最高优先级内核扫描完整块：CPU 与操作系统提供 AVX2 时用 AVX2，否则用
// SSE2 基线。两者都是手写汇编；可移植尾部完成含引号、反斜杠、控制字节或非 ASCII 字节的块。
func scanStringBody(data []byte, start int) (end int, slow bool, nonASCII bool) {
	i := start
	if n := len(data) - i; n >= 16 {
		switch {
		case useAVX512BW && n >= 64:
			i = scanStringBodyAVX512(data, start)
		case useAVX2 && n >= 32:
			i = scanStringBodyAVX2(data, start)
		default:
			i = scanStringBodySSE2(data, start)
		}
	}
	return scanStringBodyTail(data, i, false)
}
