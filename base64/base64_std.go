//go:build b64x_std

package base64

import (
	"encoding/base64"
	"errors"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// Encoding is a Base64 codec that delegates to the standard library encoding/base64 when the
// b64x_std tag is specified. Its method set is exactly the same as the native backend, and the
// two are directly interchangeable. | Encoding 是在指定 b64x_std 标签时委托给标准库
// encoding/base64 的 Base64 编解码器。方法集与自研后端完全一致，可直接互换。
type Encoding struct {
	enc      *base64.Encoding // underlying standard library codec | 底层标准库编解码器
	alphabet string           // 64-byte alphabet, kept for WithPadding validation | 64 字节字母表，供 WithPadding 校验
	pad      rune             // padding character, or NoPadding | 填充字符，或 NoPadding
	raw      bool             // whether padding is disabled | 是否关闭填充
}

var (
	// StdEncoding is the standard Base64 encoding defined by RFC 4648 (alphabet A-Za-z0-9+/, '=' padding). | StdEncoding 是 RFC 4648 定义的标准 Base64 编码（字母表 A-Za-z0-9+/，'=' 填充）。
	StdEncoding = &Encoding{enc: base64.StdEncoding, alphabet: stdAlpha, pad: StdPadding}
	// RawStdEncoding is the standard Base64 encoding with '=' padding omitted. | RawStdEncoding 是省略 '=' 填充的标准 Base64 编码。
	RawStdEncoding = &Encoding{enc: base64.RawStdEncoding, alphabet: stdAlpha, pad: NoPadding, raw: true}
	// URLEncoding is the URL- and filename-safe Base64 encoding (the alphabet replaces '+' and '/' with '-' and '_', with '=' padding). | URLEncoding 是 URL 与文件名安全的 Base64 编码（字母表把 '+'、'/' 换成 '-'、'_'，'=' 填充）。
	URLEncoding = &Encoding{enc: base64.URLEncoding, alphabet: urlAlpha, pad: StdPadding}
	// RawURLEncoding is the URL-safe Base64 encoding with '=' padding omitted. | RawURLEncoding 是省略 '=' 填充的 URL 安全 Base64 编码。
	RawURLEncoding = &Encoding{enc: base64.RawURLEncoding, alphabet: urlAlpha, pad: NoPadding, raw: true}
)

// NewEncoding returns an Encoding built from a 64-byte alphabet with '=' padding. Invalid
// alphabets return nil instead of panicking, following the repository no-panic policy. |
// NewEncoding 使用 64 字节字母表与 '=' 填充构造 Encoding；非法字母表返回 nil 而不是 panic，
// 遵循仓库的禁止 panic 约束。
func NewEncoding(encoder string) *Encoding {
	if !validAlphabet(encoder) {
		return nil
	}
	return &Encoding{enc: base64.NewEncoding(encoder), alphabet: encoder, pad: StdPadding}
}

// Strict returns a copy of the encoding that rejects non-zero trailing padding bits, matching
// encoding/base64. | Strict 返回拒绝非零尾部填充位的编码副本，与 encoding/base64 一致。
func (e Encoding) Strict() *Encoding {
	e.enc = e.enc.Strict()
	return &e
}

// WithPadding returns a copy of the encoding using padding, or NoPadding for an unpadded
// encoding. Invalid padding returns nil instead of panicking. | WithPadding 返回使用 padding 的
// 编码副本，NoPadding 表示无填充；非法填充返回 nil 而不是 panic。
func (e Encoding) WithPadding(padding rune) *Encoding {
	if !validPadding(e.alphabet, padding) {
		return nil
	}
	e.enc = e.enc.WithPadding(padding)
	e.pad = padding
	e.raw = padding == NoPadding
	return &e
}

// isRaw reports whether padding is disabled. | isRaw 判断是否关闭填充。
func (e *Encoding) isRaw() bool { return e.raw }

// wrapDecodeErr converts a standard library CorruptInputError into this package's
// CorruptInputError so callers observe the same error type on both backends. | wrapDecodeErr 把
// 标准库的 CorruptInputError 转换为本包的 CorruptInputError，使两个后端返回同一错误类型。
func wrapDecodeErr(err error) error {
	var cie base64.CorruptInputError
	if errors.As(err, &cie) {
		return errs.Wrap(CorruptInputError(cie), ErrInvalidData)
	}
	return errs.Wrap(err, ErrInvalidData)
}

// Backend returns the name of the backend used by the current build. On architectures without a third-party backend or with the b64x_std tag specified it is "encoding/base64". | Backend 返回当前构建使用的后端名称。没有第三方后端的架构或指定 b64x_std 标签时为 "encoding/base64"。
func Backend() string { return "encoding/base64" }

// EncodedLen returns the encoded length of an n-byte source, exactly matching encoding/base64.Encoding.EncodedLen. | EncodedLen 返回 n 字节源码编码后的长度，与 encoding/base64.Encoding.EncodedLen 完全一致。
func (e *Encoding) EncodedLen(n int) int { return e.enc.EncodedLen(n) }

// DecodedLen returns the maximum number of bytes after decoding Base64 text of length n, exactly matching | DecodedLen 返回长度 n 的 Base64 文本解码后的最大字节数，与
// encoding/base64.Encoding.DecodedLen. | encoding/base64.Encoding.DecodedLen 完全一致。
func (e *Encoding) DecodedLen(n int) int { return e.enc.DecodedLen(n) }

// Encode writes the encoding of src into dst; it requires len(dst) >= EncodedLen(len(src)), otherwise it panics (consistent with the standard library). | Encode 把 src 编码写入 dst，要求 len(dst) >= EncodedLen(len(src))，否则 panic（与标准库一致）。
func (e *Encoding) Encode(dst, src []byte) { e.enc.Encode(dst, src) }

// AppendEncode appends the encoding of src to dst and returns the extended slice. | AppendEncode 把 src 的编码结果追加到 dst 并返回扩展后的切片。
// When cap(dst)-len(dst) >= EncodedLen(len(src)) it reuses the underlying array of dst, producing no new allocation. | 当 cap(dst)-len(dst) >= EncodedLen(len(src)) 时复用 dst 的底层数组，不产生新的分配。
func (e *Encoding) AppendEncode(dst, src []byte) []byte { return e.enc.AppendEncode(dst, src) }

// EncodeToString returns the Base64-encoded string of src. | EncodeToString 返回 src 的 Base64 编码字符串。
func (e *Encoding) EncodeToString(src []byte) string { return e.enc.EncodeToString(src) }

// Decode decodes the Base64 text src into dst and returns the number of bytes written. | Decode 把 Base64 文本 src 解码写入 dst，返回写入的字节数。
// It requires len(dst) >= DecodedLen(len(src)), otherwise it returns ErrShortBuffer without writing any data. | 要求 len(dst) >= DecodedLen(len(src))，否则返回 ErrShortBuffer 且不写入任何数据。
// On decode failure it returns the bytes decoded before the error and a CorruptInputError-based error, exactly like encoding/base64. | 解码失败时返回出错前已解码的字节与基于 CorruptInputError 的错误，与 encoding/base64 完全一致。
// As with encoding/base64, newline characters '\r' and '\n' in the input are ignored. | 与 encoding/base64 一致，输入中的换行符 '\r'、'\n' 会被忽略。
func (e *Encoding) Decode(dst, src []byte) (int, error) {
	if len(src) == 0 {
		return 0, nil
	}
	if len(dst) < e.enc.DecodedLen(len(src)) {
		return 0, ErrShortBuffer
	}
	n, err := e.enc.Decode(dst, src)
	if err != nil {
		return n, wrapDecodeErr(err)
	}
	return n, nil
}

// DecodeString returns the decoded bytes of the Base64 text s; on decode failure it returns the partial result together with the error, exactly like encoding/base64. | DecodeString 返回 Base64 文本 s 解码后的字节；解码失败时连同错误一起返回部分结果，与 encoding/base64 完全一致。
// As with encoding/base64, newline characters '\r' and '\n' in the input are ignored. | 与 encoding/base64 一致，输入中的换行符 '\r'、'\n' 会被忽略。
func (e *Encoding) DecodeString(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	out, err := e.enc.DecodeString(s)
	if err != nil {
		return out, wrapDecodeErr(err)
	}
	return out, nil
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

// AppendDecode appends the decode result of the Base64 text src to dst and returns the extended slice. | AppendDecode 把 Base64 文本 src 的解码结果追加到 dst 并返回扩展后的切片。
// When the available capacity can hold the decode result it reuses the underlying array of dst, producing no new allocation. | 当可用容量足够容纳解码结果时复用 dst 的底层数组，不产生新的分配。
// On decode failure it returns dst extended by the partial result together with the error, exactly like encoding/base64. | 解码失败时返回追加了部分结果的 dst 与错误，与 encoding/base64 完全一致。
// As with encoding/base64, newline characters '\r' and '\n' in the input are ignored. | 与 encoding/base64 一致，输入中的换行符 '\r'、'\n' 会被忽略。
func (e *Encoding) AppendDecode(dst, src []byte) ([]byte, error) {
	if len(src) == 0 {
		return dst, nil
	}
	out, err := e.enc.AppendDecode(dst, src)
	if err != nil {
		return out, wrapDecodeErr(err)
	}
	return out, nil
}
