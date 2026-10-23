//go:build amd64 && !jsonx_std

package json

//go:noescape
func cpuID(eax, ecx uint32) (a, b, c, d uint32)

//go:noescape
func xgetbv(index uint32) uint64

// useAVX2 reports whether the CPU and OS expose the AVX2 state; SSE2 remains the guaranteed
// baseline and the portable tail covers every other machine. | useAVX2 报告 CPU 与操作系统是否提供
// AVX2 状态；SSE2 始终是保证可用的基线，其余机器由可移植尾部处理。
var useAVX2 = detectAVX2()

func detectAVX2() bool {
	_, _, c, _ := cpuID(1, 0)
	const osxsave, avx = 1 << 27, 1 << 28
	if c&(osxsave|avx) != osxsave|avx {
		return false
	}
	if xgetbv(0)&0x6 != 0x6 {
		return false
	}
	_, b, _, _ := cpuID(7, 0)
	return b&(1<<5) != 0
}
