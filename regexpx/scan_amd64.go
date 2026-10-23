//go:build amd64

package regexpx

// cpuID and xgetbv are the CPU feature probes. | cpuID 与 xgetbv 是 CPU 特性探测指令。
//
//go:noescape
func cpuID(eax, ecx uint32) (a, b, c, d uint32)

//go:noescape
func xgetbv() (eax, edx uint32)

// indexByteSSE42, indexByteSSE41 and friends are the 16-byte kernels for CPUs without AVX2. The
// SSE4.2 entry shares the fast byte-compare loop with SSE4.1; the set kernel uses nibble tables. |
// indexByteSSE42、indexByteSSE41 等函数是用于不支持 AVX2 的 CPU 的 16 字节内核。SSE4.2 入口与
// SSE4.1 共用快速字节比较循环；集合内核使用半字节表。
//
//go:noescape
func indexByteSSE42(s string, c byte, from int) int

//go:noescape
func indexByteSetSSE42(s string, t *[128]byte, from int) int

//go:noescape
func indexFoldPairSSE42(s string, c0, c1 byte, from int) int

//go:noescape
func indexByteSSE41(s string, c byte, from int) int

//go:noescape
func indexByteSetSSE41(s string, t *[128]byte, from int) int

//go:noescape
func indexFoldPairSSE41(s string, c0, c1 byte, from int) int

// indexByteAVX2 and friends scan full blocks only and return the first match or -1. |
// indexByteAVX2 等函数只扫描完整块，返回首个匹配或 -1。
//
//go:noescape
func indexByteAVX2(s string, c byte, from int) int

//go:noescape
func indexByteAVX512(s string, c byte, from int) int

//go:noescape
func indexByteSetAVX2(s string, t *[128]byte, from int) int

//go:noescape
func indexByteSetAVX512(s string, t *[128]byte, from int) int

//go:noescape
func indexFoldPairAVX2(s string, c0, c1 byte, from int) int

//go:noescape
func indexFoldPairAVX512(s string, c0, c1 byte, from int) int

// init installs the widest available SIMD kernels. | init 安装可用的最宽 SIMD 内核。
func init() {
	installScanKernels(detectScanCPU())
}

// installScanKernels selects the kernels for the detected instruction sets, preferring AVX-512BW,
// then AVX2, then SSE4.2, then SSE4.1, and finally the portable scalar code. | installScanKernels 按
// 检测到的指令集选择内核，依次优先 AVX-512BW、AVX2、SSE4.2、SSE4.1，最后回退到可移植标量代码。
func installScanKernels(sse41, sse42, avx2, avx512bw bool) {
	switch {
	case avx512bw:
		indexByteFn, indexByteBlock = indexByteAVX512, 64
		indexByteSetFn, indexByteSetBlock = indexByteSetAVX512, 64
		indexFoldPairFn, indexFoldPairBlock = indexFoldPairAVX512, 64
	case avx2:
		indexByteFn, indexByteBlock = indexByteAVX2, 32
		indexByteSetFn, indexByteSetBlock = indexByteSetAVX2, 32
		indexFoldPairFn, indexFoldPairBlock = indexFoldPairAVX2, 32
	case sse42:
		indexByteFn, indexByteBlock = indexByteSSE42, 16
		indexByteSetFn, indexByteSetBlock = indexByteSetSSE42, 16
		indexFoldPairFn, indexFoldPairBlock = indexFoldPairSSE42, 16
	case sse41:
		indexByteFn, indexByteBlock = indexByteSSE41, 16
		indexByteSetFn, indexByteSetBlock = indexByteSetSSE41, 16
		indexFoldPairFn, indexFoldPairBlock = indexFoldPairSSE41, 16
	default:
		indexByteFn, indexByteBlock = indexByteScalar, 1
		indexByteSetFn, indexByteSetBlock = indexByteSetScalar, 1
		indexFoldPairFn, indexFoldPairBlock = indexFoldPairScalar, 1
	}
}

// detectScanCPU reports whether SSE4.1, SSE4.2, AVX2 and AVX-512BW are usable. AVX states also
// require OS register support. | detectScanCPU 报告 SSE4.1、SSE4.2、AVX2 与 AVX-512BW 是否可用。AVX
// 状态还要求操作系统寄存器支持。
func detectScanCPU() (sse41, sse42, avx2, avx512bw bool) {
	maxLeaf, _, _, _ := cpuID(0, 0)
	_, _, c1, d1 := cpuID(1, 0)
	// SSE4.1 implies SSSE3 and SSE2 on every shipping implementation; check all three so a
	// malformed CPUID cannot install an unsupported kernel. SSE4.2 also requires SSE4.1. | 所有已上市
	// 的 SSE4.1 实现都包含 SSSE3 与 SSE2；三者同时检查，避免异常的 CPUID 安装不受支持的内核。
	// SSE4.2 还要求 SSE4.1。
	const sse2, ssse3, sse41Bit, sse42Bit = 1 << 26, 1 << 9, 1 << 19, 1 << 20
	sse41 = d1&sse2 != 0 && c1&(ssse3|sse41Bit) == ssse3|sse41Bit
	sse42 = sse41 && c1&sse42Bit != 0
	const osxsave, avx = 1 << 27, 1 << 28
	if maxLeaf < 7 || c1&(osxsave|avx) != osxsave|avx {
		return sse41, sse42, false, false
	}
	eax, edx := xgetbv()
	xcr0 := uint64(edx)<<32 | uint64(eax)
	if xcr0&0x6 != 0x6 {
		return sse41, sse42, false, false
	}
	_, b7, _, _ := cpuID(7, 0)
	avx2 = b7&(1<<5) != 0
	const avx512f, avx512bwBit = 1 << 16, 1 << 30
	avx512bw = xcr0&0xE6 == 0xE6 && b7&(avx512f|avx512bwBit) == avx512f|avx512bwBit
	return sse41, sse42, avx2, avx512bw
}
