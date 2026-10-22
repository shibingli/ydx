//go:build arm64 && !goexperiment.simd && !b64x_std

package base64

//go:noescape
func encodeNEONAsm(dst, src []byte, url uint64) int

//go:noescape
func decodeNEONAsm(dst, src []byte, lut1, lut2 *[64]byte) int

// Decode lookup tables built at startup for the standard and URL alphabets. | 启动时构建的标准与
// URL 字母表解码查找表。
var (
	decodeLUT1Std, decodeLUT2Std [64]byte
	decodeLUT1URL, decodeLUT2URL [64]byte
)

func init() {
	for i := range decodeLUT1Std {
		decodeLUT1Std[i] = 0xFF
		decodeLUT1URL[i] = 0xFF
	}
	decodeLUT1Std['+'], decodeLUT1Std['/'] = 62, 63
	decodeLUT1URL['-'] = 62
	for c := byte('0'); c <= '9'; c++ {
		decodeLUT1Std[c] = c - '0' + 52
		decodeLUT1URL[c] = c - '0' + 52
	}
	for i := range decodeLUT2Std {
		decodeLUT2Std[i] = 0xFF
		decodeLUT2URL[i] = 0xFF
	}
	decodeLUT2Std[0], decodeLUT2URL[0] = 0, 0
	for c := byte('A'); c <= 'Z'; c++ {
		decodeLUT2Std[c-63] = c - 'A'
		decodeLUT2URL[c-63] = c - 'A'
	}
	for c := byte('a'); c <= 'z'; c++ {
		decodeLUT2Std[c-63] = c - 'a' + 26
		decodeLUT2URL[c-63] = c - 'a' + 26
	}
	decodeLUT2URL['_'-63] = 63

	if !forceScalar {
		simdEncode = encodeSIMDNEONAsm
		simdDecode = decodeSIMDNEONAsm
	}
}

// encodeSIMDNEONAsm adapts the assembly encoder to the SIMD dispatch signature. The assembly
// processes 48-byte blocks; the scalar tail handles the remainder and padding. |
// encodeSIMDNEONAsm 把汇编编码器适配到 SIMD 分派签名；汇编处理 48 字节块，标量尾部处理余量与填充。
func encodeSIMDNEONAsm(dst, src []byte, url, padded bool, pad byte) (int, int) {
	if len(src) < 48 || len(dst) < 64 {
		return 0, 0
	}
	n := encodeNEONAsm(dst, src, boolToUint64(url))
	return n, n / 48 * 64
}

// decodeSIMDNEONAsm adapts the assembly decoder to the SIMD dispatch signature. The assembly
// processes 64-character blocks; the scalar tail handles the remainder, padding and errors. |
// decodeSIMDNEONAsm 把汇编解码器适配到 SIMD 分派签名；汇编处理 64 字符块，标量尾部处理余量、
// 填充与错误。
func decodeSIMDNEONAsm(dst, src []byte, url, raw bool) (int, int) {
	if len(src) < 64 || len(dst) < 48 {
		return 0, 0
	}
	lut1, lut2 := &decodeLUT1Std, &decodeLUT2Std
	if url {
		lut1, lut2 = &decodeLUT1URL, &decodeLUT2URL
	}
	n := decodeNEONAsm(dst, src, lut1, lut2)
	return n, n / 64 * 48
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
