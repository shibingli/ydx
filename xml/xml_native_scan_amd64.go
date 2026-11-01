//go:build amd64 && !xml_std

package xml

//go:noescape
func indexByteSSE2(data []byte, start int, c byte) int

//go:noescape
func indexAny2SSE2(data []byte, start int, c1, c2 byte) int

//go:noescape
func indexAny3SSE2(data []byte, start int, c1, c2, c3 byte) int

//go:noescape
func indexAny4SSE2(data []byte, start int, c1, c2, c3, c4 byte) int

//go:noescape
func indexByteAVX2(data []byte, start int, c byte) int

//go:noescape
func indexAny2AVX2(data []byte, start int, c1, c2 byte) int

//go:noescape
func indexAny3AVX2(data []byte, start int, c1, c2, c3 byte) int

//go:noescape
func indexAny4AVX2(data []byte, start int, c1, c2, c3, c4 byte) int

//go:noescape
func indexByteAVX512(data []byte, start int, c byte) int

//go:noescape
func indexAny2AVX512(data []byte, start int, c1, c2 byte) int

//go:noescape
func indexAny3AVX512(data []byte, start int, c1, c2, c3 byte) int

//go:noescape
func indexAny4AVX512(data []byte, start int, c1, c2, c3, c4 byte) int

//go:noescape
func cpuID(eax, ecx uint32) (a, b, c, d uint32)

//go:noescape
func xgetbv(index uint32) uint64

// The scan kernels use SSE2 (16 bytes), AVX2 (32 bytes) and AVX-512F+BW (64 bytes). Dispatch
// picks the widest complete feature set available at runtime. | 扫描内核使用 SSE2（16 字节）、
// AVX2（32 字节）与 AVX-512F+BW（64 字节）；分派选择运行时最宽的完整特性集。
var (
	useAVX2     bool
	useAVX512BW bool
)

func init() {
	if forceScalar {
		return
	}
	useAVX2, useAVX512BW = detectCPU()
	switch {
	case useAVX512BW:
		scanIndexByte = indexByteAVX512
		scanIndexAny2 = indexAny2AVX512
		scanIndexAny3 = indexAny3AVX512
		scanIndexAny4 = indexAny4AVX512
	case useAVX2:
		scanIndexByte = indexByteAVX2
		scanIndexAny2 = indexAny2AVX2
		scanIndexAny3 = indexAny3AVX2
		scanIndexAny4 = indexAny4AVX2
	default:
		scanIndexByte = indexByteSSE2
		scanIndexAny2 = indexAny2SSE2
		scanIndexAny3 = indexAny3SSE2
		scanIndexAny4 = indexAny4SSE2
	}
}

func detectCPU() (avx2, avx512bw bool) {
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
	_, b7, _, _ := cpuID(7, 0)
	avx2 = b7&(1<<5) != 0
	const avx512f, avx512bwBit = 1 << 16, 1 << 30
	if xcr0&0xE6 == 0xE6 && b7&(avx512f|avx512bwBit) == avx512f|avx512bwBit {
		avx512bw = true
	}
	return
}
