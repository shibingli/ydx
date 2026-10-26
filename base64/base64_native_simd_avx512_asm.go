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
	// tailMask[i] selects the first i input bytes; tailStore[i] selects the
	// first RawEncodedLen(i) output bytes. The tail kernel only needs i < 48:
	// the 48-byte masked block consumes the larger remainder first. | tailMask[i]
	// 选择前 i 个输入字节；tailStore[i] 选择前 RawEncodedLen(i) 个输出字节。
	// 尾部内核只需要 i < 48：48 字节掩码块会先消费更大的余量。
	tailMask  [64]uint64
	tailStore [64]uint64
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
	for i := 0; i < 48; i++ {
		c.tailMask[i] = (uint64(1) << uint(i)) - 1
		rawOut := (i*8 + 5) / 6
		c.tailStore[i] = (uint64(1) << uint(rawOut)) - 1
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

// encodeSIMD512VBMI encodes all of src with AVX-512 VBMI: complete 48-byte blocks in the main
// loop and the remaining 0..63 bytes with masked loads and stores; the wrapper writes padding. |
// encodeSIMD512VBMI 用 AVX-512 VBMI 编码全部 src：主循环处理完整 48 字节块，剩余 0..63 字节
// 由掩码加载/存储完成；填充由包装层写入。
func encodeSIMD512VBMI(dst, src []byte, url, padded bool, pad byte) (int, int) {
	if len(src) < 48 || len(dst) < 64 {
		return 0, 0
	}
	c := &vbmiEncStd
	if url {
		c = &vbmiEncURL
	}
	n := encodeAVX512VBMIAsm(dst, src, c)
	if n != len(src) {
		// A kernel that stops early leaves the remainder to the scalar path. |
		// 内核提前停止时，余量交给标量路径。
		return n, n / 48 * 64
	}
	var out int
	if padded {
		out = (len(src) + 2) / 3 * 4
	} else {
		out = (len(src)*8 + 5) / 6
	}
	if padded {
		switch len(src) % 3 {
		case 1:
			dst[out-2], dst[out-1] = pad, pad
		case 2:
			dst[out-1] = pad
		}
	}
	return n, out
}

// bwDecConsts holds the lane-local AVX-512BW decode tables. | bwDecConsts 保存按 128 位通道局部
// 查表的 AVX-512BW 解码常量。
type bwDecConsts struct {
	hiMask, loMask, loLUT, hiLUT, rollLUT [64]byte
	mul, pack, dwordIdx                   [64]byte
	eqChar, eqVal                         [64]byte
	// tailMask[i] selects the first i input bytes; tailStore[i] selects the
	// first 3*(i/4) decoded bytes. The tail only receives multiples of four. |
	// tailMask[i] 选择前 i 个输入字节；tailStore[i] 选择前 3*(i/4) 个解码字节。
	// 尾部只会收到 4 的整数倍。
	tailMask  [64]uint64
	tailStore [64]uint64
}

var bwDecStd bwDecConsts

func init() {
	bwDecStd = makeBWDecConsts()
	if !forceScalar && hasAVX512BW() {
		installDecode(2, decodeSIMD512BW)
	}
}

func makeBWDecConsts() bwDecConsts {
	var c bwDecConsts
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
	dwords := [16]uint32{0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 14, 14, 14, 14}
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
		c.pack[j] = pack16[j&15]
		c.eqChar[j], c.eqVal[j] = '+', 62
	}
	for j, v := range dwords {
		binary.LittleEndian.PutUint32(c.dwordIdx[j*4:], v)
	}
	for i := 0; i < 64; i++ {
		c.tailMask[i] = (uint64(1) << uint(i)) - 1
		c.tailStore[i] = (uint64(1) << uint(i/4*3)) - 1
	}
	return c
}

// hasAVX512BW reports whether AVX-512F and AVX-512BW are usable. | hasAVX512BW 报告 AVX-512F 与
// AVX-512BW 是否可用。
func hasAVX512BW() bool {
	_, _, c1, _ := cpuID(1, 0)
	const osxsave, avx = 1 << 27, 1 << 28
	if c1&(osxsave|avx) != osxsave|avx {
		return false
	}
	if xgetbv(0)&0xE6 != 0xE6 {
		return false
	}
	_, b7, _, _ := cpuID(7, 0)
	const f, bw = 1 << 16, 1 << 30
	return b7&(f|bw) == f|bw
}

// decodeSIMD512BW decodes standard-alphabet input with the 512-bit lane-local LUT kernel once
// a complete 64-character block is available; shorter input and URL input stay on AVX2. The
// kernel handles complete blocks plus a masked 4..63-character tail, so the 512-bit path wins
// from one block onward on the reference AVX-512 host; only the padding group (or the raw 2-3
// character partial group) remains for the scalar path. |
// decodeSIMD512BW 在至少一个完整 64 字符块时用 512 位按通道局部查表的内核解码标准字母表
// 输入；更短输入与 URL 输入继续走 AVX2。内核处理完整块与 4..63 字符的掩码尾，因此参考
// AVX-512 主机上从一个块起 512 位路径即领先；只有填充组（或 raw 的 2–3 字符残组）留给
// 标量路径。
func decodeSIMD512BW(dst, src []byte, url, raw bool) (int, int) {
	if url || len(src) < 64 || len(dst) < 48 {
		return decodeSIMDAsm(dst, src, url, raw)
	}
	// Exclude the final partial group and, for padded input, the padding group.
	// The scalar path after the kernel validates them. | 排除末尾残组；带填充输入
	// 还排除填充组，由内核之后的标量路径校验。
	simdLen := len(src) &^ 3
	if !raw && len(src)%4 == 0 && hasPadGroup(src[len(src)-4:]) {
		simdLen -= 4
	}
	if simdLen < 64 {
		return decodeSIMDAsm(dst, src, url, raw)
	}
	n := decodeAVX512BWAsm(dst, src[:simdLen], &bwDecStd)
	if n == 0 {
		return decodeSIMDAsm(dst, src, url, raw)
	}
	return n, n/64*48 + n%64/4*3
}

// hasPadGroup reports whether a four-character group contains '='. | hasPadGroup 报告四字符组
// 是否包含 '='。
func hasPadGroup(g []byte) bool {
	return g[0] == '=' || g[1] == '=' || g[2] == '=' || g[3] == '='
}

//go:noescape
func decodeAVX512BWAsm(dst, src []byte, c *bwDecConsts) int

// bwEncConsts holds the lane-local AVX-512BW encode tables. | bwEncConsts 保存按 128 位通道局部
// 查表的 AVX-512BW 编码常量。
type bwEncConsts struct {
	shuf32                       [32]byte
	maskLo, maskHi, mulHi, mulLo [64]byte
	lut                          [64]byte
	b51, b26, b13                [64]byte
}

var (
	bwEncStd, bwEncURL bwEncConsts
)

func init() {
	bwEncStd = makeBWEncConsts(false)
	bwEncURL = makeBWEncConsts(true)
	if !forceScalar && hasAVX512BW() {
		installEncode(2, encodeSIMD512BW)
	}
}

func makeBWEncConsts(url bool) bwEncConsts {
	var c bwEncConsts
	shuf16 := [16]byte{1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10}
	for j := 0; j < 16; j++ {
		c.shuf32[j] = shuf16[j] + 4
		c.shuf32[16+j] = shuf16[j]
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

// encodeSIMD512BW encodes a 12-byte head and complete 48-byte blocks with baseline AVX-512BW,
// leaving the tail to the scalar path. | encodeSIMD512BW 用基础 AVX-512BW 编码 12 字节头部与完整
// 48 字节块，尾部交给标量路径。
func encodeSIMD512BW(dst, src []byte, url, padded bool, pad byte) (int, int) {
	if len(src) < 52 || len(dst) < 64 {
		return encodeSIMDAsm(dst, src, url, padded, pad)
	}
	n, o := encodeSIMDAsm(dst, src[:16], url, padded, pad)
	if n < 12 {
		return 0, 0
	}
	c := &bwEncStd
	if url {
		c = &bwEncURL
	}
	k := encodeAVX512BWAsm(dst[o:], src[8:], c)
	return n + k, o + k/48*64
}

//go:noescape
func encodeAVX512BWAsm(dst, src []byte, c *bwEncConsts) int
