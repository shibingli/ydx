//go:build arm64 && goexperiment.simd && !b64x_std

package base64

import (
	"encoding/binary"
	"simd/archsimd"
)

// init installs the NEON kernels unless the force-scalar build disables them. | init 在未禁用
// NEON 的构建中安装 NEON 内核。
func init() {
	if forceScalar {
		return
	}
	simdEncode = encodeSIMDNEON
	simdDecode = decodeSIMDNEON
}

// encodeSIMDNEON encodes complete 12-byte groups with NEON and returns the input bytes consumed
// and output bytes written. Padding and the final partial group stay on the scalar path. |
// encodeSIMDNEON 用 NEON 编码完整的 12 字节组，返回消耗的输入字节数与写入的输出字节数；
// 填充与最后一个不完整组由标量路径处理。
func encodeSIMDNEON(dst, src []byte, url, padded bool, pad byte) (int, int) {
	_ = padded
	_ = pad
	if len(src) < 16 || len(dst) < 16 {
		return 0, 0
	}
	shuf := archsimd.LoadUint8x16(simdShufNEON[:])
	m3f := archsimd.BroadcastUint32x4(0x3F)
	m30 := archsimd.BroadcastUint32x4(0x30)
	m0f := archsimd.BroadcastUint32x4(0x0F)
	m3c := archsimd.BroadcastUint32x4(0x3C)
	m03 := archsimd.BroadcastUint32x4(0x03)
	c26 := archsimd.BroadcastUint8x16(26)
	c52 := archsimd.BroadcastUint8x16(52)
	cA := archsimd.BroadcastUint8x16('A')
	c71 := archsimd.BroadcastUint8x16(71)
	c4 := archsimd.BroadcastUint8x16(4)
	c62 := archsimd.BroadcastUint8x16(62)
	c63 := archsimd.BroadcastUint8x16(63)
	plus, slash := byte('+'), byte('/')
	if url {
		plus, slash = '-', '_'
	}
	cPlus := archsimd.BroadcastUint8x16(plus)
	cSlash := archsimd.BroadcastUint8x16(slash)

	i, o := 0, 0
	// Four independent groups per iteration hide the shift/map latency behind ILP.
	// | 每次迭代处理四个独立分组，用指令级并行隐藏移位/映射延迟。
	for len(src)-i >= 52 && len(dst)-o >= 64 {
		g0 := archsimd.LoadUint8x16(src[i : i+16]).LookupOrZero(shuf)
		g1 := archsimd.LoadUint8x16(src[i+12 : i+28]).LookupOrZero(shuf)
		g2 := archsimd.LoadUint8x16(src[i+24 : i+40]).LookupOrZero(shuf)
		g3 := archsimd.LoadUint8x16(src[i+36 : i+52]).LookupOrZero(shuf)
		x0, x1 := g0.ReshapeToUint32s(), g1.ReshapeToUint32s()
		x2, x3 := g2.ReshapeToUint32s(), g3.ReshapeToUint32s()

		v0 := x0.ShiftAllRight(2).And(m3f).
			Or(x0.ShiftAllLeft(4).And(m30).Or(x0.ShiftAllRight(12).And(m0f)).ShiftAllLeft(8)).
			Or(x0.ShiftAllRight(6).And(m3c).Or(x0.ShiftAllRight(22).And(m03)).ShiftAllLeft(16)).
			Or(x0.ShiftAllRight(16).And(m3f).ShiftAllLeft(24)).ReshapeToUint8s()
		v1 := x1.ShiftAllRight(2).And(m3f).
			Or(x1.ShiftAllLeft(4).And(m30).Or(x1.ShiftAllRight(12).And(m0f)).ShiftAllLeft(8)).
			Or(x1.ShiftAllRight(6).And(m3c).Or(x1.ShiftAllRight(22).And(m03)).ShiftAllLeft(16)).
			Or(x1.ShiftAllRight(16).And(m3f).ShiftAllLeft(24)).ReshapeToUint8s()
		v2 := x2.ShiftAllRight(2).And(m3f).
			Or(x2.ShiftAllLeft(4).And(m30).Or(x2.ShiftAllRight(12).And(m0f)).ShiftAllLeft(8)).
			Or(x2.ShiftAllRight(6).And(m3c).Or(x2.ShiftAllRight(22).And(m03)).ShiftAllLeft(16)).
			Or(x2.ShiftAllRight(16).And(m3f).ShiftAllLeft(24)).ReshapeToUint8s()
		v3 := x3.ShiftAllRight(2).And(m3f).
			Or(x3.ShiftAllLeft(4).And(m30).Or(x3.ShiftAllRight(12).And(m0f)).ShiftAllLeft(8)).
			Or(x3.ShiftAllRight(6).And(m3c).Or(x3.ShiftAllRight(22).And(m03)).ShiftAllLeft(16)).
			Or(x3.ShiftAllRight(16).And(m3f).ShiftAllLeft(24)).ReshapeToUint8s()

		encodeCharsNEON(v0, c26, c52, cA, c71, c4, c62, c63, cPlus, cSlash).Store(dst[o : o+16])
		encodeCharsNEON(v1, c26, c52, cA, c71, c4, c62, c63, cPlus, cSlash).Store(dst[o+16 : o+32])
		encodeCharsNEON(v2, c26, c52, cA, c71, c4, c62, c63, cPlus, cSlash).Store(dst[o+32 : o+48])
		encodeCharsNEON(v3, c26, c52, cA, c71, c4, c62, c63, cPlus, cSlash).Store(dst[o+48 : o+64])
		i += 48
		o += 64
	}
	for len(src)-i >= 16 && len(dst)-o >= 16 {
		group := archsimd.LoadUint8x16(src[i : i+16]).LookupOrZero(shuf)
		x := group.ReshapeToUint32s()
		i0 := x.ShiftAllRight(2).And(m3f)
		i1 := x.ShiftAllLeft(4).And(m30).Or(x.ShiftAllRight(12).And(m0f))
		i2 := x.ShiftAllRight(6).And(m3c).Or(x.ShiftAllRight(22).And(m03))
		i3 := x.ShiftAllRight(16).And(m3f)
		values := i0.Or(i1.ShiftAllLeft(8)).Or(i2.ShiftAllLeft(16)).Or(i3.ShiftAllLeft(24)).ReshapeToUint8s()
		encodeCharsNEON(values, c26, c52, cA, c71, c4, c62, c63, cPlus, cSlash).Store(dst[o : o+16])
		i += 12
		o += 16
	}
	return i, o
}

// encodeCharsNEON maps six-bit values to the selected Base64 alphabet. | encodeCharsNEON 把 6 位值
// 映射到所选 Base64 字母表。
func encodeCharsNEON(values, c26, c52, cA, c71, c4, c62, c63, cPlus, cSlash archsimd.Uint8x16) archsimd.Uint8x16 {
	ge26 := values.GreaterEqual(c26)
	ge52 := values.GreaterEqual(c52)
	chars := values.Add(cA)
	chars = values.Add(c71).IfElse(ge26, chars)
	chars = values.Sub(c4).IfElse(ge52, chars)
	chars = cPlus.IfElse(values.Equal(c62), chars)
	chars = cSlash.IfElse(values.Equal(c63), chars)
	return chars
}

// decodeSIMDNEON decodes complete 16-character blocks and returns the characters consumed and
// bytes written. Invalid characters, padding, and CR/LF stop the loop so the scalar path keeps
// the exact error and padding semantics. | decodeSIMDNEON 解码完整的 16 字符块，返回消耗的字符
// 数与写入的字节数；非法字符、填充符与 CR/LF 会停止循环，由标量路径保持精确的错误与填充语义。
func decodeSIMDNEON(dst, src []byte, url, raw bool) (int, int) {
	_ = raw
	if len(src) < 16 || len(dst) < 12 {
		return 0, 0
	}
	cA := archsimd.BroadcastUint8x16('A')
	cZ := archsimd.BroadcastUint8x16('Z')
	ca := archsimd.BroadcastUint8x16('a')
	cz := archsimd.BroadcastUint8x16('z')
	c0 := archsimd.BroadcastUint8x16('0')
	c9 := archsimd.BroadcastUint8x16('9')
	plus, slash := byte('+'), byte('/')
	if url {
		plus, slash = '-', '_'
	}
	cPlus := archsimd.BroadcastUint8x16(plus)
	cSlash := archsimd.BroadcastUint8x16(slash)
	c71 := archsimd.BroadcastUint8x16(71)
	c4 := archsimd.BroadcastUint8x16(4)
	c62 := archsimd.BroadcastUint8x16(62)
	c63 := archsimd.BroadcastUint8x16(63)
	mfc := archsimd.BroadcastUint32x4(0xFC)
	m0f := archsimd.BroadcastUint32x4(0x0F)
	mf0 := archsimd.BroadcastUint32x4(0xF0)
	m3f := archsimd.BroadcastUint32x4(0x3F)
	mc0 := archsimd.BroadcastUint32x4(0xC0)
	pack := archsimd.LoadUint8x16(simdPackNEON[:])

	i, o := 0, 0
	for len(src)-i >= 16 && len(dst)-o >= 12 {
		c := archsimd.LoadUint8x16(src[i : i+16])
		upper := c.GreaterEqual(cA).And(c.LessEqual(cZ))
		lower := c.GreaterEqual(ca).And(c.LessEqual(cz))
		digit := c.GreaterEqual(c0).And(c.LessEqual(c9))
		isPlus := c.Equal(cPlus)
		isSlash := c.Equal(cSlash)
		valid := upper.Or(lower).Or(digit).Or(isPlus).Or(isSlash)
		if valid.ToInt8x16().ReduceMax() != -1 {
			break
		}

		values := c.Sub(cA)
		values = c.Sub(c71).IfElse(lower, values)
		values = c.Add(c4).IfElse(digit, values)
		values = c62.IfElse(isPlus, values)
		values = c63.IfElse(isSlash, values)

		x := values.ReshapeToUint32s()
		b0 := x.ShiftAllLeft(2).And(mfc).Or(x.ShiftAllRight(12).And(m0f))
		b1 := x.ShiftAllRight(4).And(mf0).Or(x.ShiftAllRight(18).And(m3f))
		b2 := x.ShiftAllRight(10).And(mc0).Or(x.ShiftAllRight(24).And(m3f))
		packed := b0.Or(b1.ShiftAllLeft(8)).Or(b2.ShiftAllLeft(16)).ReshapeToUint8s().LookupOrZero(pack)

		// Store exactly 12 bytes. | 精确写入 12 字节。
		g64 := packed.ReshapeToUint64s()
		binary.LittleEndian.PutUint64(dst[o:o+8], g64.GetElem(0))
		binary.LittleEndian.PutUint32(dst[o+8:o+12], uint32(g64.GetElem(1)))
		i += 16
		o += 12
	}
	return i, o
}
