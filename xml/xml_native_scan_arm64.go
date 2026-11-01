//go:build arm64 && !xml_std

package xml

//go:noescape
func indexByteNEON(data []byte, start int, c byte) int

//go:noescape
func indexAny2NEON(data []byte, start int, c1, c2 byte) int

//go:noescape
func indexAny3NEON(data []byte, start int, c1, c2, c3 byte) int

//go:noescape
func indexAny4NEON(data []byte, start int, c1, c2, c3, c4 byte) int

// NEON is mandatory in the ARMv8-A baseline, so the NEON kernels are always available on arm64.
// | NEON 是 ARMv8-A 基线的必备特性，因此 arm64 上始终可用 NEON 内核。
func init() {
	if forceScalar {
		return
	}
	scanIndexByte = indexByteNEON
	scanIndexAny2 = indexAny2NEON
	scanIndexAny3 = indexAny3NEON
	scanIndexAny4 = indexAny4NEON
}
