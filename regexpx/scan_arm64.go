//go:build arm64

package regexpx

// indexByteNEON and indexByteSetNEON scan full 16-byte blocks and return a candidate offset or -1.
// NEON is mandatory on arm64, so the kernels are installed unconditionally. | indexByteNEON 与
// indexByteSetNEON 扫描完整 16 字节块并返回候选偏移或 -1。arm64 强制要求 NEON，因此无条件安装内核。
//
//go:noescape
func indexByteNEON(s string, c byte, from int) int

//go:noescape
func indexByteSetNEON(s string, t *[128]byte, from int) int

//go:noescape
func indexFoldPairNEON(s string, c0, c1 byte, from int) int

// init installs the NEON kernels. | init 安装 NEON 内核。
func init() {
	indexByteFn, indexByteBlock = indexByteNEON, 16
	indexByteSetFn, indexByteSetBlock = indexByteSetNEON, 16
	indexFoldPairFn, indexFoldPairBlock = indexFoldPairNEON, 16
}
