package b64x

import "github.com/shibingli/ydx/errs"

// decodeWriteSlack is spare capacity reserved for SIMD decoders, which may write a
// few bytes past DecodedLen while filling a block. It is never exposed in the
// returned slice. | decodeWriteSlack 是给 SIMD 解码器预留的额外容量：填充块时可能写
// 过 DecodedLen 几个字节，但它绝不会出现在返回切片中。
const decodeWriteSlack = 4

var (
	// ErrShortBuffer indicates the destination buffer is shorter than DecodedLen(len(src)) and cannot hold the decode result. | ErrShortBuffer 表示目标缓冲区长度小于 DecodedLen(len(src))，无法容纳解码结果。
	ErrShortBuffer = errx.New("b64x: destination buffer is too short | b64x：目标缓冲区过短")

	// ErrInvalidData indicates the input is not valid Base64 data; the underlying backend's original error is also annotated | ErrInvalidData 表示输入不是合法的 Base64 数据；底层后端的原始错误通过
	// with errx.Wrap, so it can be matched with errors.Is. | errx.Wrap 一并注解，可用 errors.Is 匹配。
	ErrInvalidData = errx.New("b64x: invalid Base64 data | b64x：非法的 Base64 数据")
)
