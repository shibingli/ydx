//go:build !b64x_std

package base64

import (
	"encoding/binary"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// Encoding is the self-developed Base64 codec used on every architecture unless
// b64x_std is set. | Encoding 是除 b64x_std 构建外所有架构上默认使用的自研 Base64
// 编解码器。
type Encoding struct {
	pair     *encodePairLUT
	quad     *decodeQuadLUT
	decode   [256]uint8
	alphabet [64]byte
	pad      byte
	raw      bool
	strict   bool
	simd     uint8
}

// encodePairLUT maps a 12-bit input chunk to its two Base64 characters packed little-endian, so a
// three-byte group needs two lookups and one 32-bit store instead of four lookups and three
// stores. The two alphabets share one table each. | encodePairLUT 把 12 位输入块映射为按小端打包的
// 两个 Base64 字符，使一个三字节组只需两次查表与一次 32 位存储，而非四次查表与三次存储；两种字母表
// 各共享一张表。
type encodePairLUT [4096]uint16

func makeEncodePairLUT(alpha string) *encodePairLUT {
	t := new(encodePairLUT)
	for i := 0; i < 4096; i++ {
		t[i] = uint16(alpha[i>>6]) | uint16(alpha[i&63])<<8
	}
	return t
}

var (
	stdEncodePairs = makeEncodePairLUT(stdAlpha)
	urlEncodePairs = makeEncodePairLUT(urlAlpha)
)

// decodeQuadLUT pre-shifts every character into its position in a 24-bit group and sets bit 24
// for invalid characters. One 4-character group then needs four loads and three ORs, and eight
// characters two more ORs, with no per-character shifting on the decode path. The two alphabets
// share one table each. | decodeQuadLUT 把每个字符预移位到 24 位组中的位置，非法字符置第 24 位。
// 一个 4 字符组只需四次加载与三次 OR，八个字符再多两次 OR，解码路径无需逐字符移位；两种字母表
// 各共享一张表。
type decodeQuadLUT [4][256]uint32

// decodeInvalidBit marks a character outside the alphabet inside a quad lookup result. |
// decodeInvalidBit 在四元组查表结果中标记字母表之外的字符。
const decodeInvalidBit = 1 << 24

func makeDecodeQuadLUT(alpha string) *decodeQuadLUT {
	q := new(decodeQuadLUT)
	for i := range q[0] {
		q[0][i], q[1][i], q[2][i], q[3][i] = decodeInvalidBit, decodeInvalidBit, decodeInvalidBit, decodeInvalidBit
	}
	for i := 0; i < len(alpha); i++ {
		v := uint32(i)
		q[0][alpha[i]] = v << 18
		q[1][alpha[i]] = v << 12
		q[2][alpha[i]] = v << 6
		q[3][alpha[i]] = v
	}
	return q
}

var (
	stdDecodeQuads = makeDecodeQuadLUT(stdAlpha)
	urlDecodeQuads = makeDecodeQuadLUT(urlAlpha)
)

// simdEncode and simdDecode are installed by the optional SIMD build. | simdEncode 与 simdDecode
// 由可选的 SIMD 构建安装；未启用时保持 nil 并走标量路径。
var (
	simdEncode func(dst, src []byte, url, padded bool, pad byte) (int, int)
	simdDecode func(dst, src []byte, url, raw bool) (int, int)
	// simdEncode32 is the dedicated full-vector 32-byte encoder. It takes the alphabet and
	// padding options packed into mode (bit 0 URL alphabet, bit 1 padded, bits 8-15 pad byte) and
	// returns the consumed input and produced output; it is nil on architectures without a
	// 32-byte kernel. | simdEncode32 是专用的 32 字节全向量编码器。选项打包在 mode 中（第 0 位
	// URL 字母表、第 1 位填充、第 8-15 位填充字节），返回消耗的输入与产生的输出；没有 32 字节内核的
	// 架构上为 nil。
	simdEncode32 func(dst, src []byte, mode uint64) (int, int)
	// simdDecode32 is the dedicated 32-character decoder; mode bit 0 selects the URL alphabet.
	// It returns (32, 24) on success and (0, 0) when the scalar path must validate the input. |
	// simdDecode32 是专用的 32 字符解码器；mode 第 0 位选择 URL 字母表。成功返回 (32, 24)，
	// 需要标量路径校验输入时返回 (0, 0)。
	simdDecode32 func(dst, src []byte, mode uint64) (int, int)
	// Instruction-set levels select the widest available kernel independently of init order:
	// 1 = AVX2/NEON, 2 = AVX-512BW, 3 = AVX-512 VBMI (encoding only). | 指令集级别与 init
	// 顺序无关地选择最宽可用内核：1 = AVX2/NEON，2 = AVX-512BW，3 = AVX-512 VBMI（仅编码）。
	simdEncodeLevel int
	simdDecodeLevel int
)

// installEncode installs the encoder when its instruction-set level is at least the current one. |
// installEncode 在指令集级别不低于当前级别时安装编码器。
func installEncode(level int, fn func(dst, src []byte, url, padded bool, pad byte) (int, int)) {
	if level >= simdEncodeLevel {
		simdEncode = fn
		simdEncodeLevel = level
	}
}

// installDecode installs the decoder when its instruction-set level is at least the current one. |
// installDecode 在指令集级别不低于当前级别时安装解码器。
func installDecode(level int, fn func(dst, src []byte, url, raw bool) (int, int)) {
	if level >= simdDecodeLevel {
		simdDecode = fn
		simdDecodeLevel = level
	}
}

// newEncoding builds one encoding from its alphabet. | newEncoding 根据字母表构造一个编码器。
func newEncoding(alpha string, padded bool) *Encoding {
	e := &Encoding{raw: !padded}
	switch alpha {
	case stdAlpha:
		e.simd = 1
		e.pair = stdEncodePairs
		e.quad = stdDecodeQuads
	case urlAlpha:
		e.simd = 2
		e.pair = urlEncodePairs
		e.quad = urlDecodeQuads
	}
	copy(e.alphabet[:], alpha)
	for i := range e.decode {
		e.decode[i] = 0xFF
	}
	for i := 0; i < len(alpha); i++ {
		e.decode[alpha[i]] = uint8(i)
	}
	if padded {
		e.pad = '='
	}
	return e
}

var (
	// StdEncoding is the standard Base64 encoding defined by RFC 4648. | StdEncoding 是 RFC 4648 定义的标准 Base64 编码。
	StdEncoding = newEncoding(stdAlpha, true)
	// RawStdEncoding is the standard Base64 encoding without padding. | RawStdEncoding 是省略填充的标准 Base64 编码。
	RawStdEncoding = newEncoding(stdAlpha, false)
	// URLEncoding is the URL-safe Base64 encoding with padding. | URLEncoding 是带填充的 URL 安全 Base64 编码。
	URLEncoding = newEncoding(urlAlpha, true)
	// RawURLEncoding is the URL-safe Base64 encoding without padding. | RawURLEncoding 是省略填充的 URL 安全 Base64 编码。
	RawURLEncoding = newEncoding(urlAlpha, false)
)

// Backend returns the active backend name for this build. | Backend 返回当前构建使用的后端名称。
func Backend() string { return "yd-native" }

// NewEncoding returns an Encoding built from a 64-byte alphabet with '=' padding. Invalid
// alphabets return nil instead of panicking, following the repository no-panic policy. |
// NewEncoding 使用 64 字节字母表与 '=' 填充构造 Encoding；非法字母表返回 nil 而不是 panic，
// 遵循仓库的禁止 panic 约束。
func NewEncoding(encoder string) *Encoding {
	if !validAlphabet(encoder) {
		return nil
	}
	e := newEncoding(encoder, true)
	if e.pair == nil {
		e.pair = makeEncodePairLUT(encoder)
	}
	if e.quad == nil {
		e.quad = makeDecodeQuadLUT(encoder)
	}
	return e
}

// Strict returns a copy of the encoding that rejects non-zero trailing padding bits, matching
// encoding/base64. | Strict 返回拒绝非零尾部填充位的编码副本，与 encoding/base64 一致。
func (e Encoding) Strict() *Encoding {
	e.strict = true
	return &e
}

// WithPadding returns a copy of the encoding using padding, or NoPadding for an unpadded
// encoding. Invalid padding returns nil instead of panicking. | WithPadding 返回使用 padding 的
// 编码副本，NoPadding 表示无填充；非法填充返回 nil 而不是 panic。
func (e Encoding) WithPadding(padding rune) *Encoding {
	if !validPadding(string(e.alphabet[:]), padding) {
		return nil
	}
	if padding == NoPadding {
		e.raw, e.pad = true, 0
	} else {
		e.raw, e.pad = false, byte(padding)
	}
	return &e
}

// isRaw reports whether padding is disabled. | isRaw 判断是否关闭填充。
func (e *Encoding) isRaw() bool { return e.raw }

// corrupt builds a CorruptInputError at pos classified as ErrInvalidData. | corrupt 构造位于 pos
// 的 CorruptInputError，并归类为 ErrInvalidData。
func (e *Encoding) corrupt(pos int) error {
	return errs.Wrap(CorruptInputError(pos), ErrInvalidData)
}

// EncodedLen returns the encoded length of an n-byte source. | EncodedLen 返回 n 字节源码编码后的长度。
func (e *Encoding) EncodedLen(n int) int {
	if e.raw {
		return (n*8 + 5) / 6
	}
	return (n + 2) / 3 * 4
}

// DecodedLen returns the maximum decoded length of n bytes of Base64 text. | DecodedLen 返回 n 字节 Base64 文本解码后的最大长度。
func (e *Encoding) DecodedLen(n int) int {
	if e.raw {
		return n * 6 / 8
	}
	return n / 4 * 3
}

// encodeScalar writes src into dst without invoking SIMD or retaining either
// slice. Keeping it separate lets the escape analyser prove that a short
// stack buffer passed to it does not escape. | encodeScalar 在不调用 SIMD、也不
// 保留任一切片的前提下把 src 写入 dst；独立出来后，逃逸分析可证明传给它的栈上
// 短缓冲不会逃逸。
func (e *Encoding) encodeScalar(dst, src []byte) {
	pair := e.pair
	// One big-endian 32-bit load per 3-byte group (each reading one byte into the next group)
	// replaces three byte loads and two shifts; one 64-bit store carries the eight characters of
	// two groups. | 每个 3 字节组用一次大端 32 位加载（各多读一个字节到相邻组），取代三次字节
	// 加载与两次移位；一次 64 位存储写入两组的八个字符。
	for len(src) >= 16 {
		v0 := uint32(binary.BigEndian.Uint32(src[0:4]) >> 8)
		v1 := uint32(binary.BigEndian.Uint32(src[3:7]) >> 8)
		v2 := uint32(binary.BigEndian.Uint32(src[6:10]) >> 8)
		v3 := uint32(binary.BigEndian.Uint32(src[9:13]) >> 8)
		p0 := uint64(pair[(v0>>12)&4095]) | uint64(pair[v0&4095])<<16
		p1 := uint64(pair[(v1>>12)&4095]) | uint64(pair[v1&4095])<<16
		p2 := uint64(pair[(v2>>12)&4095]) | uint64(pair[v2&4095])<<16
		p3 := uint64(pair[(v3>>12)&4095]) | uint64(pair[v3&4095])<<16
		binary.LittleEndian.PutUint64(dst[0:8], p0|p1<<32)
		binary.LittleEndian.PutUint64(dst[8:16], p2|p3<<32)
		src, dst = src[12:], dst[16:]
	}
	for len(src) >= 8 {
		v0 := uint32(binary.BigEndian.Uint32(src[0:4]) >> 8)
		v1 := uint32(binary.BigEndian.Uint32(src[3:7]) >> 8)
		p0 := uint64(pair[(v0>>12)&4095]) | uint64(pair[v0&4095])<<16
		p1 := uint64(pair[(v1>>12)&4095]) | uint64(pair[v1&4095])<<16
		binary.LittleEndian.PutUint64(dst[0:8], p0|p1<<32)
		src, dst = src[6:], dst[8:]
	}
	for len(src) >= 3 {
		v := uint(src[0])<<16 | uint(src[1])<<8 | uint(src[2])
		p := uint32(pair[(v>>12)&4095]) | uint32(pair[v&4095])<<16
		binary.LittleEndian.PutUint32(dst, p)
		src, dst = src[3:], dst[4:]
	}
	switch len(src) {
	case 1:
		v := uint(src[0]) << 16
		binary.LittleEndian.PutUint16(dst, pair[(v>>12)&4095])
		if !e.raw {
			dst[2], dst[3] = e.pad, e.pad
		}
	case 2:
		v := uint(src[0])<<16 | uint(src[1])<<8
		binary.LittleEndian.PutUint16(dst, pair[(v>>12)&4095])
		dst[2] = byte(pair[v&4095])
		if !e.raw {
			dst[3] = e.pad
		}
	}
}

// simdEncodeMin is the smallest source length that beats the scalar encoder through the block
// kernel. Measured on the reference AVX-512 host: 33–60 B are still faster on the scalar path,
// while 64 B and above win on SIMD. Exactly 32 B bypasses this threshold through the dedicated
// full-vector kernel. | simdEncodeMin 是块内核开始胜过标量编码器的最小源长度。参考 AVX-512
// 主机实测：33–60 B 仍以标量路径更快，64 B 起 SIMD 领先；恰好 32 B 通过专用全向量内核绕过
// 该阈值。
const simdEncodeMin = 64

// simdDecodeMin is the smallest encoded length that beats the scalar decoder. Measured on the
// reference host: 44–60 characters are faster on the scalar path, while 64 characters and above
// win on SIMD. | simdDecodeMin 是标量解码器被 SIMD 反超的最小编码长度。参考主机实测：
// 44–60 字符标量更快，64 字符起 SIMD 领先。
const simdDecodeMin = 64

// decodeAlignedMin is the smallest input for which the scalar prologue that
// aligns the source pointer is worth its cost. | decodeAlignedMin 是源地址对齐
// 前导值得付出其成本的最小输入。
const decodeAlignedMin = 4096

// decodeAlignedPrefix decodes complete 4-character groups until src is 64-byte
// aligned. A 4-character group is indivisible, so alignment is possible only
// when the source pointer is itself 4-byte aligned; other offsets fall back to
// the ordinary SIMD path. The prefix is validated with the same quad LUT as
// the scalar loop, so padding, CR/LF and invalid bytes also fall back. On
// success it returns the consumed input and produced output. | decodeAlignedPrefix
// 解码完整的 4 字符组，直到 src 达到 64 字节对齐。4 字符组不可拆分，因此只有源指针
// 本身按 4 字节对齐时才能对齐；其它偏移回退普通 SIMD 路径。前导沿用标量循环的
// quad LUT 校验，填充、CR/LF 与非法字节都会回退。成功时返回消耗的输入与产生的输出。
func (e *Encoding) decodeAlignedPrefix(dst, src []byte) (i, out int, ok bool) {
	if len(src) < decodeAlignedMin {
		return 0, 0, false
	}
	addr := uintptr(unsafe.Pointer(&src[0]))
	off := int(addr & 63)
	if off == 0 || off&3 != 0 {
		// Already aligned, or a 4-byte group cannot reach a 64-byte boundary.
		// | 已经对齐，或 4 字符组无法到达 64 字节边界。
		return 0, 0, false
	}
	n := 64 - off
	if n+simdDecodeMin > len(src) {
		return 0, 0, false
	}
	quad := e.quad
	for j := 0; j < n; j += 4 {
		s := src[j : j+4]
		r := quad[0][s[0]] | quad[1][s[1]] | quad[2][s[2]] | quad[3][s[3]]
		if r&decodeInvalidBit != 0 {
			return 0, 0, false
		}
		dst[out] = byte(r >> 16)
		dst[out+1] = byte(r >> 8)
		dst[out+2] = byte(r)
		out += 3
	}
	return n, out, true
}

// Encode writes the encoding of src into dst. It writes nothing when dst is too short. | Encode 把 src 编码写入 dst；dst 过短时不写入任何内容。
func (e *Encoding) Encode(dst, src []byte) {
	if len(dst) < e.EncodedLen(len(src)) {
		return
	}
	// Short inputs stay scalar: the SIMD dispatch and per-group vector setup cost more
	// than the table lookups they replace. | 短输入保持标量：SIMD 分派与每组向量初始化的
	// 成本高于它们替代的查表。
	if len(src) == 32 && simdEncode32 != nil && e.simd != 0 {
		var mode uint64
		if e.simd == 2 {
			mode |= 1
		}
		if !e.raw {
			mode |= 2
		}
		mode |= uint64(e.pad) << 8
		if n, _ := simdEncode32(dst, src, mode); n == 32 {
			return
		}
	}
	if len(src) >= simdEncodeMin && simdEncode != nil && e.simd != 0 {
		n, out := simdEncode(dst, src, e.simd == 2, !e.raw, e.pad)
		// A kernel that consumed the whole input must not pay for its scalar tail. |
		// 已消费全部输入的内核不应再为标量尾部付出开销。
		if n == len(src) {
			return
		}
		src = src[n:]
		dst = dst[out:]
	}
	e.encodeScalar(dst, src)
}

// AppendEncode appends the encoding of src to dst. | AppendEncode 把 src 的编码结果追加到 dst。
func (e *Encoding) AppendEncode(dst, src []byte) []byte {
	n := e.EncodedLen(len(src))
	old := len(dst)
	if cap(dst)-old < n {
		dst = append(dst, make([]byte, n)...)
	} else {
		dst = dst[:old+n]
	}
	e.Encode(dst[old:], src)
	return dst
}

// encodeToStringStackMax is the largest result that takes the direct scalar path in
// EncodeToString. 128 bytes cover SHA-1/SHA-256 digests and other short handshake material,
// where the result allocation is the only allocation. | encodeToStringStackMax 是
// EncodeToString 走直接标量路径的最大结果；128 字节覆盖 SHA-1/SHA-256 摘要等短握手数据，
// 此时结果分配是唯一一次分配。
const encodeToStringStackMax = 128

// EncodeToString returns the Base64-encoded string of src. | EncodeToString 返回 src 的 Base64 编码字符串。
func (e *Encoding) EncodeToString(src []byte) string {
	n := e.EncodedLen(len(src))
	if n == 0 {
		return ""
	}
	b := make([]byte, n)
	if n <= encodeToStringStackMax && len(src) < simdEncodeMin {
		// Short inputs cannot reach a block kernel, so call the scalar encoder directly and
		// skip the length re-check and SIMD dispatch. | 短输入到不了块内核，直接调用标量编码器，
		// 省去长度复检与 SIMD 分派。
		e.encodeScalar(b, src)
	} else {
		e.Encode(b, src)
	}
	// b is freshly allocated and never retained, so the string can take ownership without a copy. |
	// b 是全新分配且不再被保留，字符串可直接接管其存储而无需复制。
	return unsafe.String(unsafe.SliceData(b), n)
}

// Decode decodes Base64 text into dst and returns the number of bytes written. On malformed
// input it returns the bytes decoded before the error together with a CorruptInputError that
// carries the same byte offset as encoding/base64. | Decode 把 Base64 文本解码到 dst 并返回
// 写入字节数。输入非法时返回出错前已解码的字节，以及与 encoding/base64 字节偏移相同的
// CorruptInputError。
func (e *Encoding) Decode(dst, src []byte) (int, error) {
	if len(src) == 0 {
		return 0, nil
	}
	if len(dst) < e.DecodedLen(len(src)) {
		return 0, ErrShortBuffer
	}
	out, i := 0, 0
	// The block kernels assume '=' padding and do not verify strict trailing bits, so custom
	// padding and Strict() take the scalar path. | 块内核假定 '=' 填充且不校验 strict 尾部比特，
	// 因此自定义填充与 Strict() 走标量路径。
	simdOK := e.simd != 0 && !e.strict && (e.raw || e.pad == '=')
	if len(src) >= 32 && len(src) < simdDecodeMin && simdDecode32 != nil && simdOK {
		var mode uint64
		if e.simd == 2 {
			mode = 1
		}
		// Decode the first 32 characters with the 128-bit kernel; the scalar loop below finishes
		// any remainder. This keeps the cheap block path for 32–63-character inputs whose full
		// scalar loop would be slower. | 用 128 位内核解码前 32 个字符，余量交给下面的标量循环。
		// 这样 32–63 字符的输入也能走低成本块路径，而不是整段标量循环。
		if n, out32 := simdDecode32(dst, src, mode); n == 32 {
			i, out = 32, out32
		}
	}
	// Every block SIMD decoder handles at least 64 characters; shorter inputs skip the indirect
	// call and its immediate no-op return. | 所有块 SIMD 解码器至少处理 64 个字符，更短的输入跳过
	// 间接调用及其立即空返回。
	if len(src) >= simdDecodeMin && simdDecode != nil && simdOK {
		// Align the source before the block kernel: unaligned 32/64-byte loads
		// cross cache lines on every iteration, while a short scalar prologue
		// costs almost nothing on a large input. | 在块内核之前对齐源地址：
		// 未对齐的 32/64 字节加载会在每轮跨缓存行，而大输入上的短标量前导几乎无成本。
		if ai, ao, ok := e.decodeAlignedPrefix(dst, src); ok {
			i, out = ai, ao
		}
		n, produced := simdDecode(dst[out:], src[i:], e.simd == 2, e.raw)
		i += n
		out += produced
		// A kernel that consumed the whole input has already validated it, so
		// the scalar tail loop would only repeat empty work. | 已消费全部输入的
		// 内核已完成校验，标量尾部循环只会重复空工作。
		if i == len(src) {
			return out, nil
		}
	}
	quad := e.quad
	for i+16 <= len(src) {
		s := src[i : i+16]
		// The pre-shifted tables turn each 4-character group into four loads and three ORs; bit 24
		// flags an invalid character without a separate table lookup. | 预移位表把每个 4 字符组
		// 降为四次加载与三次 OR；第 24 位直接标记非法字符，无需额外查表。
		r0 := quad[0][s[0]] | quad[1][s[1]] | quad[2][s[2]] | quad[3][s[3]]
		r1 := quad[0][s[4]] | quad[1][s[5]] | quad[2][s[6]] | quad[3][s[7]]
		r2 := quad[0][s[8]] | quad[1][s[9]] | quad[2][s[10]] | quad[3][s[11]]
		r3 := quad[0][s[12]] | quad[1][s[13]] | quad[2][s[14]] | quad[3][s[15]]
		if (r0|r1|r2|r3)&decodeInvalidBit != 0 {
			break
		}
		// Two 24-bit groups form a 48-bit word whose big-endian bytes are the six decoded bytes,
		// so two stores replace twelve per-byte stores. | 两个 24 位组合成 48 位字，其大端字节序
		// 恰为六个解码字节；两次存储取代十二次逐字节存储。
		w0 := uint64(r0)<<24 | uint64(r1)
		w1 := uint64(r2)<<24 | uint64(r3)
		binary.BigEndian.PutUint32(dst[out:], uint32(w0>>16))
		binary.BigEndian.PutUint16(dst[out+4:], uint16(w0))
		binary.BigEndian.PutUint32(dst[out+6:], uint32(w1>>16))
		binary.BigEndian.PutUint16(dst[out+10:], uint16(w1))
		i += 16
		out += 12
	}
	for i+4 <= len(src) {
		r := quad[0][src[i]] | quad[1][src[i+1]] | quad[2][src[i+2]] | quad[3][src[i+3]]
		if r&decodeInvalidBit != 0 {
			break
		}
		dst[out] = byte(r >> 16)
		dst[out+1] = byte(r >> 8)
		dst[out+2] = byte(r)
		i += 4
		out += 3
	}
	if i == len(src) {
		return out, nil
	}
	// Raw encodings end in a 2- or 3-character group, which is the common JWT shape; decoding it
	// here avoids the general slow path with its per-character state machine. | 原始编码以 2 或 3
	// 字符组结尾，这是 JWT 的常见形态；在此直接解码可避免带逐字符状态机的通用慢路径。
	if e.raw {
		switch len(src) - i {
		case 2:
			a := e.decode[src[i]]
			b := e.decode[src[i+1]]
			if (a|b)&0x80 == 0 {
				if e.strict && b&0x0F != 0 {
					return out, e.corrupt(i)
				}
				dst[out] = a<<2 | b>>4
				return out + 1, nil
			}
		case 3:
			a := e.decode[src[i]]
			b := e.decode[src[i+1]]
			c := e.decode[src[i+2]]
			if (a|b|c)&0x80 == 0 {
				if e.strict && c&0x03 != 0 {
					return out, e.corrupt(i + 2)
				}
				dst[out] = a<<2 | b>>4
				dst[out+1] = b<<4 | c>>2
				return out + 2, nil
			}
		}
	}
	// Canonical padded tails are the common case for hashes and keys; decoding them here avoids
	// the general slow path with its per-character state machine. | 规范填充尾部是摘要与密钥的常见
	// 情形；在此直接解码可避免带逐字符状态机的通用慢路径。
	if !e.raw && len(src)-i == 4 {
		switch {
		case src[i+2] == e.pad && src[i+3] == e.pad:
			a := e.decode[src[i]]
			b := e.decode[src[i+1]]
			if (a|b)&0x80 == 0 {
				if e.strict && b&0x0F != 0 {
					return out, e.corrupt(i + 2)
				}
				dst[out] = a<<2 | b>>4
				return out + 1, nil
			}
		case src[i+3] == e.pad:
			a := e.decode[src[i]]
			b := e.decode[src[i+1]]
			c := e.decode[src[i+2]]
			if (a|b|c)&0x80 == 0 {
				if e.strict && c&0x03 != 0 {
					return out, e.corrupt(i + 3)
				}
				dst[out] = a<<2 | b>>4
				dst[out+1] = b<<4 | c>>2
				return out + 2, nil
			}
		}
	}
	n, err := e.decodeSlow(dst[out:], src[i:], i)
	if err != nil {
		return out + n, err
	}
	return out + n, nil
}

// decodeSlow handles padding, CR/LF and invalid input after the fast path. base is the absolute
// offset of src within the caller's input, so error positions match encoding/base64 exactly. On
// error it returns the bytes decoded before the error, following encoding/base64. | decodeSlow
// 处理快路径之后的填充、CR/LF 与非法输入；base 是 src 在调用方输入中的绝对偏移，使错误位置与
// encoding/base64 完全一致。出错时返回已解码的字节，与 encoding/base64 一致。
func (e *Encoding) decodeSlow(dst, src []byte, base int) (int, error) {
	si, out := 0, 0
	for si < len(src) {
		nsi, n, err := e.decodeQuantum(dst[out:], src, si, base)
		out += n
		si = nsi
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// decodeQuantum decodes up to one four-character quantum starting at si, mirroring
// encoding/base64's decoder so that padding, CR/LF, strict trailing-bit checks and error
// positions all agree with the standard library. | decodeQuantum 从 si 开始解码至多一个四字符
// 组，逐条对齐 encoding/base64 的解码器，使填充、CR/LF、strict 尾部比特校验与错误位置都与标准库
// 一致。
func (e *Encoding) decodeQuantum(dst, src []byte, si, base int) (nsi, n int, err error) {
	var dbuf [4]uint8
	dlen := 4
	for j := 0; j < 4; j++ {
		if len(src) == si {
			switch {
			case j == 0:
				return si, 0, nil
			case j == 1, !e.raw:
				return si, 0, e.corrupt(base + si - j)
			}
			dlen = j
			break
		}
		in := src[si]
		si++
		out := e.decode[in]
		if out != 0xFF {
			dbuf[j] = out
			continue
		}
		if in == 13 || in == 10 {
			j--
			continue
		}
		if e.raw || in != e.pad {
			return si, 0, e.corrupt(base + si - 1)
		}
		switch j {
		case 0, 1:
			return si, 0, e.corrupt(base + si - 1)
		case 2:
			for si < len(src) && (src[si] == 13 || src[si] == 10) {
				si++
			}
			if si == len(src) {
				return si, 0, e.corrupt(base + len(src))
			}
			if src[si] != e.pad {
				return si, 0, e.corrupt(base + si - 1)
			}
			si++
		}
		for si < len(src) && (src[si] == 13 || src[si] == 10) {
			si++
		}
		if si < len(src) {
			err = e.corrupt(base + si)
		}
		dlen = j
		break
	}
	val := uint(dbuf[0])<<18 | uint(dbuf[1])<<12 | uint(dbuf[2])<<6 | uint(dbuf[3])
	dbuf[2], dbuf[1], dbuf[0] = byte(val), byte(val>>8), byte(val>>16)
	switch dlen {
	case 4:
		dst[2] = dbuf[2]
		dbuf[2] = 0
		fallthrough
	case 3:
		dst[1] = dbuf[1]
		if e.strict && dbuf[2] != 0 {
			return si, 0, e.corrupt(base + si - 1)
		}
		dbuf[1] = 0
		fallthrough
	case 2:
		dst[0] = dbuf[0]
		if e.strict && (dbuf[1] != 0 || dbuf[2] != 0) {
			return si, 0, e.corrupt(base + si - 2)
		}
	}
	return si, dlen - 1, err
}

// DecodeString returns the decoded bytes of Base64 text s; on failure it returns the partial
// result together with the error, exactly like encoding/base64. | DecodeString 返回 Base64
// 文本 s 的解码字节；失败时连同错误一起返回部分结果，与 encoding/base64 完全一致。
func (e *Encoding) DecodeString(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	out := make([]byte, e.DecodedLen(len(s)))
	n, err := e.Decode(out, unsafe.Slice(unsafe.StringData(s), len(s)))
	return out[:n], err
}

// AppendDecodeString appends the decoded bytes of the Base64 text s to dst without converting s to a
// []byte; the string is only read, so the zero-copy view never escapes. | AppendDecodeString 把
// Base64 文本 s 的解码结果追加到 dst，且不把 s 转换成 []byte；字符串只被读取，零拷贝视图不会逃逸。
func (e *Encoding) AppendDecodeString(dst []byte, s string) ([]byte, error) {
	if len(s) == 0 {
		return dst, nil
	}
	return e.AppendDecode(dst, unsafe.Slice(unsafe.StringData(s), len(s)))
}

// AppendDecode appends the decoded bytes of src to dst; on failure it returns dst extended by
// the partial result together with the error, exactly like encoding/base64. | AppendDecode 把
// src 的解码结果追加到 dst；失败时返回追加了部分结果的 dst 与错误，与 encoding/base64 完全一致。
func (e *Encoding) AppendDecode(dst, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return dst, nil
	}
	need := e.DecodedLen(len(src))
	old := len(dst)
	if cap(dst)-old < need {
		buf := make([]byte, old+need)
		copy(buf, dst)
		n, err := e.Decode(buf[old:], src)
		return buf[:old+n], err
	}
	grown := dst[:old+need]
	n, err := e.Decode(grown[old:], src)
	return grown[:old+n], err
}
