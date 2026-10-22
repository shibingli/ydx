//go:build amd64 && !goexperiment.simd && !b64x_std

package base64

import "encoding/binary"

//go:noescape
func encodeAVX2Asm(dst, src []byte, c *avx2EncConsts) int

//go:noescape
func decodeAVX2Asm(dst, src []byte, c *avx2DecConsts) int

//go:noescape
func cpuID(eax, ecx uint32) (a, b, c, d uint32)

//go:noescape
func xgetbv(index uint32) uint64

type avx2EncConsts struct {
	shuf                         [32]byte
	maskLo, maskHi, mulHi, mulLo [32]byte
	lut                          [32]byte
	b51, b26, b13                [32]byte
}

type avx2DecConsts struct {
	loLUT, hiLUT, rollLUT [32]byte
	loMask, hiMask        [32]byte
	mul, pack             [32]byte
	dwordIdx              [32]byte
	eqChar, eqVal, zero   [32]byte
}

var (
	avx2EncStd, avx2EncURL avx2EncConsts
	avx2DecStd, avx2DecURL avx2DecConsts
)

func init() {
	avx2EncStd = makeEncConsts(false)
	avx2EncURL = makeEncConsts(true)
	avx2DecStd = makeDecConsts(false)
	avx2DecURL = makeDecConsts(true)
	if !forceScalar && hasAVX2() {
		simdEncode = encodeSIMDAsm
		simdDecode = decodeSIMDAsm
	}
}

func makeEncConsts(url bool) avx2EncConsts {
	var c avx2EncConsts
	shuf16 := [16]byte{1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10}
	for i := 0; i < 16; i++ {
		c.shuf[i] = shuf16[i] + 4
		c.shuf[16+i] = shuf16[i]
	}
	for j := 0; j < 16; j++ {
		lo, hi, mh, ml := uint16(0x0fc0), uint16(0x003f), uint16(0x0400), uint16(0x0100)
		if j&1 == 0 {
			lo, hi, mh, ml = 0xfc00, 0x03f0, 0x0040, 0x0010
		}
		binary.LittleEndian.PutUint16(c.maskLo[j*2:], lo)
		binary.LittleEndian.PutUint16(c.maskHi[j*2:], hi)
		binary.LittleEndian.PutUint16(c.mulHi[j*2:], mh)
		binary.LittleEndian.PutUint16(c.mulLo[j*2:], ml)
	}
	lut16 := [16]int8{71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 65, 0, 0}
	if url {
		lut16[11], lut16[12] = -17, 32
	}
	for i := 0; i < 32; i++ {
		c.lut[i] = byte(lut16[i%16])
		c.b51[i], c.b26[i], c.b13[i] = 51, 26, 13
	}
	return c
}

func alphabetHas(alphabet string, c byte) bool {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == c {
			return true
		}
	}
	return false
}

func buildDecodeLUTs32(loLUT, hiLUT, rollLUT *[32]byte, alphabet string, rollBase [16]int8) {
	var loBase, hiBase [16]int8
	for hi := 0; hi < 16; hi++ {
		hiBase[hi] = -128
		if hi >= 2 && hi <= 7 {
			hiBase[hi] = int8(1 << uint(hi-2))
		}
	}
	for lo := 0; lo < 16; lo++ {
		v := int8(-128)
		for hi := 2; hi <= 7; hi++ {
			if !alphabetHas(alphabet, byte(hi<<4|lo)) {
				v |= int8(1 << uint(hi-2))
			}
		}
		loBase[lo] = v
	}
	for j := 0; j < 32; j++ {
		loLUT[j] = byte(loBase[j&15])
		hiLUT[j] = byte(hiBase[j&15])
		rollLUT[j] = byte(rollBase[j&15])
	}
}

func makeDecConsts(url bool) avx2DecConsts {
	var c avx2DecConsts
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	rollBase := [16]int8{2: 16, 3: 4, 4: -65, 5: -65, 6: -71, 7: -71}
	if url {
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		rollBase = [16]int8{2: 17, 3: 4, 4: -65, 5: -65, 6: -71, 7: -71}
	}
	buildDecodeLUTs32(&c.loLUT, &c.hiLUT, &c.rollLUT, alphabet, rollBase)
	for i := 0; i < 32; i++ {
		c.loMask[i], c.hiMask[i] = 0x0F, 0x0F
		if i&1 == 0 {
			c.mul[i] = 64
		} else {
			c.mul[i] = 1
		}
	}
	pack16 := [16]byte{2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 15, 15, 15, 15}
	for i := 0; i < 32; i++ {
		c.pack[i] = pack16[i%16]
	}
	dwords := [8]uint32{0, 1, 2, 4, 5, 6, 7, 7}
	for i, v := range dwords {
		binary.LittleEndian.PutUint32(c.dwordIdx[i*4:], v)
	}
	eqChar, eqVal := byte('+'), byte(62)
	if url {
		eqChar, eqVal = '_', 63
	}
	for i := 0; i < 32; i++ {
		c.eqChar[i], c.eqVal[i] = eqChar, eqVal
	}
	return c
}

// hasAVX2 reports whether the CPU and OS support the AVX2 state. | hasAVX2 报告 CPU 与操作系统是否
// 支持 AVX2 状态。
func hasAVX2() bool {
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

// encodeSIMDAsm adapts the AVX2 encoder to the SIMD dispatch signature. A 12-byte scalar-vector
// head seeds the 24-byte block loop; the scalar tail handles the remainder and padding. |
// encodeSIMDAsm 把 AVX2 编码器适配到 SIMD 分派签名。12 字节向量头部引导 24 字节块循环，标量尾部
// 处理余量与填充。
func encodeSIMDAsm(dst, src []byte, url, padded bool, pad byte) (int, int) {
	if len(src) < 16 || len(dst) < 16 {
		return 0, 0
	}
	c := &avx2EncStd
	if url {
		c = &avx2EncURL
	}
	n := encodeAVX2Asm(dst, src, c)
	if n < 12 {
		return 0, 0
	}
	return n, 16 + (n-12)/24*32
}

// decodeSIMDAsm adapts the AVX2 decoder to the SIMD dispatch signature. It processes 32-character
// blocks and writes exactly 24 bytes per block. | decodeSIMDAsm 把 AVX2 解码器适配到 SIMD 分派
// 签名；它处理 32 字符块，每块精确写入 24 字节。
func decodeSIMDAsm(dst, src []byte, url, raw bool) (int, int) {
	if len(src) < 32 || len(dst) < 24 {
		return 0, 0
	}
	c := &avx2DecStd
	if url {
		c = &avx2DecURL
	}
	n := decodeAVX2Asm(dst, src, c)
	return n, n / 32 * 24
}
