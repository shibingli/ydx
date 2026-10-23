//go:build amd64 && !jsonx_std

package json

//go:noescape
func cpuID(eax, ecx uint32) (a, b, c, d uint32)

//go:noescape
func xgetbv(index uint32) uint64

// The scanner kernels use AVX-512F + AVX-512BW. VBMI/VBMI2 and VL are detected for reporting and
// future kernels, but these byte-mask scans gain nothing from them; the dispatch picks the widest
// *complete* feature set: AVX-512BW (64 bytes) > AVX2 (32) > SSE2 (16). |
// 扫描内核使用 AVX-512F + AVX-512BW。VBMI/VBMI2 与 VL 会被检测以供报告和后续内核使用，但这些字节
// 掩码扫描用不到它们；分派选择最宽的完整特性集：AVX-512BW（64 字节）> AVX2（32）> SSE2（16）。
var (
	useAVX2       bool
	useAVX512BW   bool
	haveAVX512VL  bool
	haveAVX512VBM bool
	haveAVX512VB2 bool
)

func init() {
	useAVX2, useAVX512BW, haveAVX512VL, haveAVX512VBM, haveAVX512VB2 = detectCPU()
}

func detectCPU() (avx2, avx512bw, avx512vl, vbmi, vbmi2 bool) {
	maxLeaf, _, _, _ := cpuID(0, 0)
	_, _, c1, _ := cpuID(1, 0)
	const osxsave, avx = 1 << 27, 1 << 28
	if maxLeaf < 7 || c1&(osxsave|avx) != osxsave|avx {
		return
	}
	xcr0 := xgetbv(0)
	if xcr0&0x6 != 0x6 {
		return
	}
	_, b7, c7, _ := cpuID(7, 0)
	avx2 = b7&(1<<5) != 0
	const avx512f, avx512bwBit, avx512vlBit = 1 << 16, 1 << 30, 1 << 31
	avx512vl = b7&avx512vlBit != 0
	if xcr0&0xE6 == 0xE6 && b7&(avx512f|avx512bwBit) == avx512f|avx512bwBit {
		avx512bw = true
	}
	vbmi = c7&(1<<1) != 0
	vbmi2 = c7&(1<<6) != 0
	return
}
