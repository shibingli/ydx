package jsonx

import (
	"github.com/shibingli/ydx/errs"
)

var (
	// ErrSyntax indicates the input is not valid JSON text. | ErrSyntax 表示输入不是合法的 JSON 文本。
	//
	// The syntax error types of the backends (yd-native / go-json / encoding/json) are mutually incompatible, so jsonx | 各后端（yd-native / go-json / encoding/json）的语法错误类型互不兼容，jsonx 会在
	// classifies them uniformly on the error path; therefore errors.Is(err, jsonx.ErrSyntax) holds under any backend; | 错误路径上统一归类，因此 errors.Is(err, jsonx.ErrSyntax) 在任意后端下都成立；
	// the original backend error is still preserved in the error chain by errx.Wrap, and can be further inspected with errors.Is/As. | 后端原始错误依旧通过 errx.Wrap 保留在错误链中，可用 errors.Is/As 进一步判定。
	ErrSyntax = errx.New("jsonx: invalid JSON syntax | jsonx：非法的 JSON 语法")

	// ErrTypeMismatch indicates the JSON text itself is valid but does not match the target Go type | ErrTypeMismatch 表示 JSON 文本本身合法，但与目标 Go 类型不匹配
	// (for example, parsing a string into an int, or an array into a struct). | （例如把字符串解析进 int、把数组解析进 struct）。
	//
	// Like ErrSyntax, this classification stays consistent across all backends. | 与 ErrSyntax 一样，该判定在各后端间保持一致。
	ErrTypeMismatch = errx.New("jsonx: JSON value does not match target Go type | jsonx：JSON 值与目标 Go 类型不匹配")
)

// wrapDecodeError performs a one-time cross-backend classification of the parse error returned by a backend on the error path: | wrapDecodeError 在错误路径上对后端返回的解析错误做一次跨后端归类：
// when the input is not valid JSON it is wrapped as ErrSyntax, otherwise as ErrTypeMismatch. | 输入不是合法 JSON 时包装为 ErrSyntax，否则包装为 ErrTypeMismatch。
//
// The classification is based on the shared Valid re-check (performed only on the error path, so normal-path performance is unaffected), | 归类依据是共享的 Valid 复检（仅在出错时执行，不影响正常路径性能），因此不依赖
// so it depends on no backend-private error type. Both errors are annotated with errx.Wrap, leaving the original backend error intact in the error chain. | 任何后端私有错误类型。两个错误均以 errx.Wrap 注解，原始后端错误保持不变地保留在错误链中。
func wrapDecodeError(data []byte, err error) error {
	if err == nil {
		return nil
	}
	if !Valid(data) {
		return errx.Wrap(err, ErrSyntax)
	}
	return errx.Wrap(err, ErrTypeMismatch)
}
