//go:build !b64x_std

package base64

import (
	"encoding/binary"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// errCorrupt is the underlying error for malformed Base64 input. | errCorrupt 是非法 Base64 输入的底层错误。
var errCorrupt = errs.New("b64x: corrupt Base64 input | b64x：损坏的 Base64 输入")

// Encoding is the self-developed Base64 codec used on every architecture unless
// b64x_std is set. | Encoding 是除 b64x_std 构建外所有架构上默认使用的自研 Base64
// 编解码器。
type Encoding struct {
	alphabet [64]byte
	decode   [256]uint8
	pair     *encodePairLUT
	pad      byte
	raw      bool
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

// simdEncode and simdDecode are installed by the optional SIMD build. | simdEncode 与 simdDecode
// 由可选的 SIMD 构建安装；未启用时保持 nil 并走标量路径。
var (
	simdEncode func(dst, src []byte, url, padded bool, pad byte) (int, int)
	simdDecode func(dst, src []byte, url, raw bool) (int, int)
)

const (
	stdAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	urlAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// newEncoding builds one encoding from its alphabet. | newEncoding 根据字母表构造一个编码器。
func newEncoding(alpha string, padded bool) *Encoding {
	e := &Encoding{raw: !padded}
	switch alpha {
	case stdAlpha:
		e.simd = 1
		e.pair = stdEncodePairs
	case urlAlpha:
		e.simd = 2
		e.pair = urlEncodePairs
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
	di := 0
	pair := e.pair
	for len(src) >= 12 {
		s := src[:12]
		d := dst[di : di+16]
		v0 := uint(s[0])<<16 | uint(s[1])<<8 | uint(s[2])
		v1 := uint(s[3])<<16 | uint(s[4])<<8 | uint(s[5])
		v2 := uint(s[6])<<16 | uint(s[7])<<8 | uint(s[8])
		v3 := uint(s[9])<<16 | uint(s[10])<<8 | uint(s[11])
		p0 := uint32(pair[(v0>>12)&4095]) | uint32(pair[v0&4095])<<16
		p1 := uint32(pair[(v1>>12)&4095]) | uint32(pair[v1&4095])<<16
		p2 := uint32(pair[(v2>>12)&4095]) | uint32(pair[v2&4095])<<16
		p3 := uint32(pair[(v3>>12)&4095]) | uint32(pair[v3&4095])<<16
		binary.LittleEndian.PutUint32(d[0:4], p0)
		binary.LittleEndian.PutUint32(d[4:8], p1)
		binary.LittleEndian.PutUint32(d[8:12], p2)
		binary.LittleEndian.PutUint32(d[12:16], p3)
		src, di = src[12:], di+16
	}
	for len(src) >= 3 {
		v := uint(src[0])<<16 | uint(src[1])<<8 | uint(src[2])
		p := uint32(pair[(v>>12)&4095]) | uint32(pair[v&4095])<<16
		binary.LittleEndian.PutUint32(dst[di:], p)
		src, di = src[3:], di+4
	}
	switch len(src) {
	case 1:
		v := uint(src[0]) << 16
		binary.LittleEndian.PutUint16(dst[di:], pair[(v>>12)&4095])
		if !e.raw {
			dst[di+2], dst[di+3] = e.pad, e.pad
		}
	case 2:
		v := uint(src[0])<<16 | uint(src[1])<<8
		binary.LittleEndian.PutUint16(dst[di:], pair[(v>>12)&4095])
		dst[di+2] = byte(pair[v&4095])
		if !e.raw {
			dst[di+3] = e.pad
		}
	}
}

// Encode writes the encoding of src into dst. It writes nothing when dst is too short. | Encode 把 src 编码写入 dst；dst 过短时不写入任何内容。
func (e *Encoding) Encode(dst, src []byte) {
	if len(dst) < e.EncodedLen(len(src)) {
		return
	}
	// Short inputs stay scalar: the SIMD dispatch and per-group vector setup cost more
	// than the table lookups they replace. | 短输入保持标量：SIMD 分派与每组向量初始化的
	// 成本高于它们替代的查表。
	if simdEncode != nil && e.simd != 0 && len(src) >= 28 {
		n, out := simdEncode(dst, src, e.simd == 2, !e.raw, e.pad)
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

// encodeToStringStackMax is the largest encoded result staged on the stack.
// 128 bytes cover SHA-1/SHA-256 digests and other short handshake material, so
// the string conversion is the only allocation. | encodeToStringStackMax 是栈上
// 暂存的最大编码结果；128 字节覆盖 SHA-1/SHA-256 摘要等短握手数据，使字符串
// 转换成为唯一一次分配。
const encodeToStringStackMax = 128

// EncodeToString returns the Base64-encoded string of src. | EncodeToString 返回 src 的 Base64 编码字符串。
func (e *Encoding) EncodeToString(src []byte) string {
	n := e.EncodedLen(len(src))
	if n <= encodeToStringStackMax {
		var buf [encodeToStringStackMax]byte
		e.encodeScalar(buf[:n], src)
		return string(buf[:n])
	}
	b := make([]byte, n)
	e.Encode(b, src)
	return string(b)
}

// Decode decodes Base64 text into dst and returns the number of bytes written. | Decode 把 Base64 文本解码到 dst 并返回写入字节数。
func (e *Encoding) Decode(dst, src []byte) (int, error) {
	if len(src) == 0 {
		return 0, nil
	}
	if len(dst) < e.DecodedLen(len(src)) {
		return 0, ErrShortBuffer
	}
	out, i := 0, 0
	if simdDecode != nil && e.simd != 0 {
		i, out = simdDecode(dst, src, e.simd == 2, e.raw)
	}
	for i+16 <= len(src) {
		s := src[i : i+16]
		a0 := e.decode[s[0]]
		b0 := e.decode[s[1]]
		c0 := e.decode[s[2]]
		d0 := e.decode[s[3]]
		a1 := e.decode[s[4]]
		b1 := e.decode[s[5]]
		c1 := e.decode[s[6]]
		d1 := e.decode[s[7]]
		a2 := e.decode[s[8]]
		b2 := e.decode[s[9]]
		c2 := e.decode[s[10]]
		d2 := e.decode[s[11]]
		a3 := e.decode[s[12]]
		b3 := e.decode[s[13]]
		c3 := e.decode[s[14]]
		d3 := e.decode[s[15]]
		if (a0|b0|c0|d0|a1|b1|c1|d1|a2|b2|c2|d2|a3|b3|c3|d3)&0x80 != 0 {
			break
		}
		d := dst[out : out+12]
		d[0] = a0<<2 | b0>>4
		d[1] = b0<<4 | c0>>2
		d[2] = c0<<6 | d0
		d[3] = a1<<2 | b1>>4
		d[4] = b1<<4 | c1>>2
		d[5] = c1<<6 | d1
		d[6] = a2<<2 | b2>>4
		d[7] = b2<<4 | c2>>2
		d[8] = c2<<6 | d2
		d[9] = a3<<2 | b3>>4
		d[10] = b3<<4 | c3>>2
		d[11] = c3<<6 | d3
		i += 16
		out += 12
	}
	for i+4 <= len(src) {
		a := e.decode[src[i]]
		b := e.decode[src[i+1]]
		c := e.decode[src[i+2]]
		d := e.decode[src[i+3]]
		if (a|b|c|d)&0x80 != 0 {
			break
		}
		dst[out] = a<<2 | b>>4
		dst[out+1] = b<<4 | c>>2
		dst[out+2] = c<<6 | d
		i += 4
		out += 3
	}
	if i == len(src) {
		return out, nil
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
				dst[out] = a<<2 | b>>4
				return out + 1, nil
			}
		case src[i+3] == e.pad:
			a := e.decode[src[i]]
			b := e.decode[src[i+1]]
			c := e.decode[src[i+2]]
			if (a|b|c)&0x80 == 0 {
				dst[out] = a<<2 | b>>4
				dst[out+1] = b<<4 | c>>2
				return out + 2, nil
			}
		}
	}
	n, err := e.decodeSlow(dst[out:], src[i:])
	if err != nil {
		return 0, err
	}
	return out + n, nil
}

// decodeSlow handles padding, CR/LF and invalid input after the fast path. | decodeSlow 处理快路径之后的填充、CR/LF 与非法输入。
func (e *Encoding) decodeSlow(dst, src []byte) (int, error) {
	var quad [4]uint8
	q, out, padAt := 0, 0, -1
	padDone := false
	for _, c := range src {
		if c == '\r' || c == '\n' {
			continue
		}
		if padDone {
			return 0, errs.Wrap(errCorrupt, ErrInvalidData)
		}
		if c == e.pad {
			if e.raw {
				return 0, errs.Wrap(errCorrupt, ErrInvalidData)
			}
			if padAt >= 0 {
				if padAt != 2 || q != 3 {
					return 0, errs.Wrap(errCorrupt, ErrInvalidData)
				}
				quad[3] = 64
				q = 4
			} else {
				if q < 2 {
					return 0, errs.Wrap(errCorrupt, ErrInvalidData)
				}
				padAt = q
				quad[q] = 64
				q++
			}
		} else {
			if padAt >= 0 {
				return 0, errs.Wrap(errCorrupt, ErrInvalidData)
			}
			v := e.decode[c]
			if v == 0xFF {
				return 0, errs.Wrap(errCorrupt, ErrInvalidData)
			}
			quad[q] = v
			q++
		}
		if q == 4 {
			real := 4
			switch padAt {
			case 2:
				real = 2
			case 3:
				real = 3
			}
			n, ok := e.decodeQuad(dst[out:], quad, real)
			if !ok {
				return 0, errs.Wrap(errCorrupt, ErrInvalidData)
			}
			out += n
			q = 0
			if padAt >= 0 {
				padDone, padAt = true, -1
			}
		}
	}
	if q != 0 {
		if e.raw {
			if q == 1 {
				return 0, errs.Wrap(errCorrupt, ErrInvalidData)
			}
			n, ok := e.decodeQuad(dst[out:], quad, q)
			if !ok {
				return 0, errs.Wrap(errCorrupt, ErrInvalidData)
			}
			out += n
		} else {
			return 0, errs.Wrap(errCorrupt, ErrInvalidData)
		}
	}
	return out, nil
}

// decodeQuad writes the decoded bytes of one quartet into dst. | decodeQuad 把一个四元组的解码结果写入 dst。
func (e *Encoding) decodeQuad(dst []byte, quad [4]uint8, real int) (int, bool) {
	switch real {
	case 2:
		if len(dst) < 1 {
			return 0, false
		}
		dst[0] = quad[0]<<2 | quad[1]>>4
		return 1, true
	case 3:
		if len(dst) < 2 {
			return 0, false
		}
		dst[0] = quad[0]<<2 | quad[1]>>4
		dst[1] = quad[1]<<4 | quad[2]>>2
		return 2, true
	case 4:
		if len(dst) < 3 {
			return 0, false
		}
		dst[0] = quad[0]<<2 | quad[1]>>4
		dst[1] = quad[1]<<4 | quad[2]>>2
		dst[2] = quad[2]<<6 | quad[3]
		return 3, true
	default:
		return 0, false
	}
}

// DecodeString returns the decoded bytes of Base64 text s. | DecodeString 返回 Base64 文本 s 的解码字节。
func (e *Encoding) DecodeString(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	out := make([]byte, e.DecodedLen(len(s)))
	n, err := e.Decode(out, unsafe.Slice(unsafe.StringData(s), len(s)))
	if err != nil {
		return nil, err
	}
	return out[:n], nil
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

// AppendDecode appends the decoded bytes of src to dst. | AppendDecode 把 src 的解码结果追加到 dst。
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
		if err != nil {
			return dst, err
		}
		return buf[:old+n], nil
	}
	grown := dst[:old+need]
	n, err := e.Decode(grown[old:], src)
	if err != nil {
		return dst, err
	}
	return grown[:old+n], nil
}
