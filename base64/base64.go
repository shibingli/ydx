package base64

import (
	"strconv"

	"github.com/shibingli/ydx/errs"
)

// decodeWriteSlack is spare capacity reserved for SIMD decoders, which may write a
// few bytes past DecodedLen while filling a block. It is never exposed in the
// returned slice. | decodeWriteSlack 是给 SIMD 解码器预留的额外容量：填充块时可能写
// 过 DecodedLen 几个字节，但它绝不会出现在返回切片中。
const decodeWriteSlack = 4

var (
	// ErrShortBuffer indicates the destination buffer is shorter than DecodedLen(len(src)) and cannot hold the decode result. | ErrShortBuffer 表示目标缓冲区长度小于 DecodedLen(len(src))，无法容纳解码结果。
	ErrShortBuffer = errs.New("b64x: destination buffer is too short | b64x：目标缓冲区过短")

	// ErrInvalidData indicates the input is not valid Base64 data; the underlying backend's original error is also annotated | ErrInvalidData 表示输入不是合法的 Base64 数据；底层后端的原始错误通过
	// with errs.Wrap, so it can be matched with errors.Is. | errs.Wrap 一并注解，可用 errors.Is 匹配。
	ErrInvalidData = errs.New("b64x: invalid Base64 data | b64x：非法的 Base64 数据")
)

// Padding options shared with encoding/base64. | 与 encoding/base64 一致的填充选项。
const (
	// StdPadding is the standard Base64 padding character. | StdPadding 是标准 Base64 填充字符。
	StdPadding rune = '='
	// NoPadding disables padding. | NoPadding 关闭填充。
	NoPadding rune = -1
)

const (
	stdAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	urlAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// CorruptInputError reports the position of illegal Base64 data, matching
// encoding/base64.CorruptInputError. | CorruptInputError 报告非法 Base64 数据的位置，与
// encoding/base64.CorruptInputError 一致。
type CorruptInputError int64

// Error returns the encoding/base64-compatible error text. | Error 返回与
// encoding/base64 兼容的错误文本。
func (e CorruptInputError) Error() string {
	return "illegal base64 data at input byte " + strconv.FormatInt(int64(e), 10)
}

// validAlphabet reports whether encoder is a usable 64-byte Base64 alphabet.
// Invalid alphabets make NewEncoding return nil instead of panicking. |
// validAlphabet 判断 encoder 是否为可用的 64 字节 Base64 字母表；非法字母表使
// NewEncoding 返回 nil 而不是 panic。
func validAlphabet(encoder string) bool {
	if len(encoder) != 64 {
		return false
	}
	var seen [256]bool
	for i := 0; i < len(encoder); i++ {
		c := encoder[i]
		if c == 13 || c == 10 || seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

// validPadding reports whether padding can be applied to alphabet. | validPadding
// 判断 padding 是否可以应用于 alphabet。
func validPadding(alphabet string, padding rune) bool {
	if padding < NoPadding || padding == 13 || padding == 10 || padding > 0xff {
		return false
	}
	if padding == NoPadding {
		return true
	}
	for i := 0; i < len(alphabet); i++ {
		if rune(alphabet[i]) == padding {
			return false
		}
	}
	return true
}
