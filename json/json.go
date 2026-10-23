package json

import (
	"github.com/shibingli/ydx/errs"
)

var (
	// ErrSyntax indicates the input is not valid JSON text. | ErrSyntax 表示输入不是合法的 JSON 文本。
	//
	// The syntax error types of the backends (yd-native / encoding/json) are mutually incompatible, so jsonx | 各后端（yd-native / encoding/json）的语法错误类型互不兼容，jsonx 会在
	// classifies them uniformly on the error path; therefore errors.Is(err, json.ErrSyntax) holds under any backend; | 错误路径上统一归类，因此 errors.Is(err, json.ErrSyntax) 在任意后端下都成立；
	// the original backend error is still preserved in the error chain by errs.Wrap, and can be further inspected with errors.Is/As. | 后端原始错误依旧通过 errs.Wrap 保留在错误链中，可用 errors.Is/As 进一步判定。
	ErrSyntax = errs.New("jsonx: invalid JSON syntax | jsonx：非法的 JSON 语法")

	// ErrTypeMismatch indicates the JSON text itself is valid but does not match the target Go type | ErrTypeMismatch 表示 JSON 文本本身合法，但与目标 Go 类型不匹配
	// (for example, parsing a string into an int, or an array into a struct). | （例如把字符串解析进 int、把数组解析进 struct）。
	//
	// Like ErrSyntax, this classification stays consistent across all backends. | 与 ErrSyntax 一样，该判定在各后端间保持一致。
	ErrTypeMismatch = errs.New("jsonx: JSON value does not match target Go type | jsonx：JSON 值与目标 Go 类型不匹配")
)

// Prewarm compiles and installs the encoding and decoding plans for the given samples, moving
// plan construction out of the first request. Pass a value or pointer to warm the encoder for its
// type; pass a typed nil pointer such as (*User)(nil) to warm the decoder for the type it points
// to, the same shape Unmarshal receives. Nested struct, slice, array and pointer types reachable
// from a sample are warmed recursively, and map key/value types are warmed as well. Prewarm is
// idempotent and safe to call concurrently; under the jsonx_std backend it is a no-op because the
// standard library owns its own caches. |
// Prewarm 为给定样本编译并安装编解码计划，把计划构建成本移出首个请求。传入值或指针可预热其
// 类型的编码器；传入 (*User)(nil) 这类类型化 nil 指针可预热其指向类型的解码器，与 Unmarshal
// 接收的指针形态一致。样本可达的嵌套结构体、切片、数组与指针类型会递归预热，映射的键与值
// 类型也会预热。Prewarm 幂等且可并发调用；jsonx_std 后端下为空操作，因为标准库管理自己的缓存。
func Prewarm(samples ...any) {
	prewarm(samples...)
}

// wrapDecodeError performs a one-time cross-backend classification of the parse error returned by a backend on the error path: | wrapDecodeError 在错误路径上对后端返回的解析错误做一次跨后端归类：
// when the input is not valid JSON it is wrapped as ErrSyntax, otherwise as ErrTypeMismatch. | 输入不是合法 JSON 时包装为 ErrSyntax，否则包装为 ErrTypeMismatch。
//
// The classification is based on the shared Valid re-check (performed only on the error path, so normal-path performance is unaffected), | 归类依据是共享的 Valid 复检（仅在出错时执行，不影响正常路径性能），因此不依赖
// so it depends on no backend-private error type. Both errors are annotated with errs.Wrap, leaving the original backend error intact in the error chain. | 任何后端私有错误类型。两个错误均以 errs.Wrap 注解，原始后端错误保持不变地保留在错误链中。
func wrapDecodeError(data []byte, err error) error {
	if err == nil {
		return nil
	}
	if !Valid(data) {
		return errs.Wrap(err, ErrSyntax)
	}
	return errs.Wrap(err, ErrTypeMismatch)
}
