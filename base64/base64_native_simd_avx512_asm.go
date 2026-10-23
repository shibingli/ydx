//go:build amd64 && !b64x_std

package base64

import "encoding/binary"

//go:noescape
func encodeAVX512VBMIAsm(dst, src []byte, c *vbmiEncConsts) int

// vbmiEncConsts holds the 64-byte AVX-512 VBMI encode tables. | vbmiEncConsts 保存 AVX-512
// VBMI 编码使用的 64 字节常量表。
type vbmiEncConsts struct {
	inShuf                       [64]byte
	maskLo, maskHi, mulHi, mulLo [64]byte
	lut                          [64]byte
	b51, b26, b13                [64]byte
}

var (
	vbmiEncStd, vbmiEncURL vbmiEncConsts
)

func init() {
	vbmiEncStd = makeVBMIEncConsts(false)
	vbmiEncURL = makeVBMIEncConsts(true)
	if !forceScalar && hasAVX512VBMI() {
		installEncode(3, encodeSIMD512VBMI)
	}
}

func makeVBMIEncConsts(url bool) vbmiEncConsts {
	var c vbmiEncConsts
	shuf16 := [16]byte{1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10}
	for g := 0; g < 4; g++ {
		for j := 0; j < 16; j++ {
			c.inShuf[g*16+j] = byte(g*12) + shuf16[j]
		}
	}
	for j := 0; j < 32; j++ {
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
	for j := 0; j < 64; j++ {
		c.lut[j] = byte(lut16[j&15])
		c.b51[j], c.b26[j], c.b13[j] = 51, 26, 13
	}
	return c
}

// hasAVX512VBMI reports whether AVX-512F, AVX-512BW and VBMI are usable. | hasAVX512VBMI 报告
// AVX-512F、AVX-512BW 与 VBMI 是否可用。
func hasAVX512VBMI() bool {
	_, _, c1, _ := cpuID(1, 0)
	const osxsave, avx = 1 << 27, 1 << 28
	if c1&(osxsave|avx) != osxsave|avx {
		return false
	}
	if xgetbv(0)&0xE6 != 0xE6 {
		return false
	}
	_, b7, c7, _ := cpuID(7, 0)
	const f, bw = 1 << 16, 1 << 30
	return b7&(f|bw) == f|bw && c7&(1<<1) != 0
}

// encodeSIMD512VBMI encodes complete 48-byte blocks with AVX-512 VBMI and leaves the tail to the
// scalar path. | encodeSIMD512VBMI 用 AVX-512 VBMI 编码完整 48 字节块，尾部交给标量路径。
func encodeSIMD512VBMI(dst, src []byte, url, padded bool, pad byte) (int, int) {
	if len(src) < 48 || len(dst) < 64 {
		return 0, 0
	}
	c := &vbmiEncStd
	if url {
		c = &vbmiEncURL
	}
	n := encodeAVX512VBMIAsm(dst, src, c)
	return n, n / 48 * 64
}

// vbmiDecConsts holds the 64-byte AVX-512 VBMI2 decode tables. | vbmiDecConsts 保存 AVX-512
// VBMI2 解码使用的 64 字节常量表。
type vbmiDecConsts struct {
	hiMask, loMask              [64]byte
	loLUT, hiLUT, rollLUT       [64]byte
	mul, pack                   [64]byte
	b62, b63, plus, slash, zero [64]byte
}

var vbmiDecStd vbmiDecConsts

func init() {
	vbmiDecStd = makeVBMIDecConsts()
	if !forceScalar && hasAVX512VBMI2() {
		installDecode(4, decodeSIMD512VBMI2)
	}
}

func makeVBMIDecConsts() vbmiDecConsts {
	var c vbmiDecConsts
	var loBase, hiBase [16]int8
	rollBase := [16]int8{2: 16, 3: 4, 4: -65, 5: -65, 6: -71, 7: -71}
	for hi := 0; hi < 16; hi++ {
		hiBase[hi] = -128
		if hi >= 2 && hi <= 7 {
			hiBase[hi] = int8(1 << uint(hi-2))
		}
	}
	for lo := 0; lo < 16; lo++ {
		v := int8(-128)
		for hi := 2; hi <= 7; hi++ {
			if !alphabetHas(stdAlpha, byte(hi<<4|lo)) {
				v |= int8(1 << uint(hi-2))
			}
		}
		loBase[lo] = v
	}
	pack16 := [16]byte{2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, 15, 15, 15, 15}
	for j := 0; j < 64; j++ {
		c.hiMask[j], c.loMask[j] = 0x0f, 0x0f
		c.loLUT[j] = byte(loBase[j&15])
		c.hiLUT[j] = byte(hiBase[j&15])
		c.rollLUT[j] = byte(rollBase[j&15])
		if j&1 == 0 {
			c.mul[j] = 64
		} else {
			c.mul[j] = 1
		}
		c.pack[j] = byte(j&^15) + pack16[j&15]
		c.b62[j], c.b63[j] = 62, 63
		c.plus[j], c.slash[j] = '+', '/'
	}
	return c
}

// hasAVX512VBMI2 reports whether AVX-512F, AVX-512BW and VBMI2 are usable. | hasAVX512VBMI2 报告
// AVX-512F、AVX-512BW 与 VBMI2 是否可用。
func hasAVX512VBMI2() bool {
	_, _, c1, _ := cpuID(1, 0)
	const osxsave, avx = 1 << 27, 1 << 28
	if c1&(osxsave|avx) != osxsave|avx {
		return false
	}
	if xgetbv(0)&0xE6 != 0xE6 {
		return false
	}
	_, b7, c7, _ := cpuID(7, 0)
	const f, bw = 1 << 16, 1 << 30
	return b7&(f|bw) == f|bw && c7&(1<<6) != 0
}

// decodeSIMD512VBMI2 decodes 64-character standard-alphabet blocks with AVX-512 VBMI2. URL input
// stays on the AVX2 kernel, and the scalar path finishes any tail or validation failure. |
// decodeSIMD512VBMI2 用 AVX-512 VBMI2 解码 64 字符标准字母表块；URL 输入继续走 AVX2 内核，
// 尾部或校验失败由标量路径完成。
func decodeSIMD512VBMI2(dst, src []byte, url, raw bool) (int, int) {
	if url {
		return decodeSIMDAsm(dst, src, url, raw)
	}
	if len(src) < 64 || len(dst) < 48 {
		return 0, 0
	}
	n := decodeAVX512VBMI2Asm(dst, src, &vbmiDecStd)
	return n, n / 64 * 48
}

//go:noescape
func decodeAVX512VBMI2Asm(dst, src []byte, c *vbmiDecConsts) int
