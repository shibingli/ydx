//go:build arm64 && goexperiment.simd && !b64x_std

package base64

// NEON gather and pack tables. | NEON 收集与打包表。
var (
	// simdShufNEON places each three-byte group in the low 24 bits of a 32-bit lane.
	// | simdShufNEON 把每个三字节组放进一个 32 位通道的低 24 位。
	simdShufNEON = [16]uint8{0, 1, 2, 0, 3, 4, 5, 0, 6, 7, 8, 0, 9, 10, 11, 0}

	// simdPackNEON compacts the four 3-byte lanes of a decoded group into 12 consecutive bytes.
	// | simdPackNEON 把解码后的四个 3 字节通道压成 12 个连续字节。
	simdPackNEON = [16]uint8{0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0, 0, 0, 0}
)
