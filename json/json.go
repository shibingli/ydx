package json

import (
	stdjson "encoding/json"
	"errors"
	"reflect"

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
//
// On the error path only, the native backend also recovers the standard library's *SyntaxError
// or *UnmarshalTypeError form, so errors.As keeps working with the encoding/json error types
// documented by this package; the target value is not touched again on success. | 仅在错误路径上，
// 自研后端还会取得标准库的 *SyntaxError 或 *UnmarshalTypeError 形态，使 errors.As 与本包文档所列的
// encoding/json 错误类型保持兼容；成功路径不会再次触碰目标值。
func wrapDecodeError(data []byte, v any, err error) error {
	if err == nil {
		return nil
	}
	if !Valid(data) {
		return errs.Wrap(standardSyntaxError(data, err), ErrSyntax)
	}
	return errs.Wrap(standardTypeError(data, v, err), ErrTypeMismatch)
}

// standardSyntaxError returns err when it already carries a standard *SyntaxError, otherwise
// re-validates data with encoding/json to obtain the same error type, message and offset. |
// standardSyntaxError 在 err 已携带标准 *SyntaxError 时原样返回，否则用 encoding/json 重新校验
// data，取得相同类型、文案与偏移的错误。
func standardSyntaxError(data []byte, err error) error {
	var se *stdjson.SyntaxError
	if errors.As(err, &se) {
		return err
	}
	return stdSyntaxError(data)
}

// standardTypeError returns err when it already carries a standard *UnmarshalTypeError,
// otherwise decodes data into a fresh value of the same type to recover the standard library's
// error. A panic from an UnmarshalJSON implementation during that probe is recovered and the
// original error is kept. | standardTypeError 在 err 已携带标准 *UnmarshalTypeError 时原样返回，
// 否则把 data 解码进同类型的新值以取得标准库错误；探针过程中 UnmarshalJSON 发生的 panic 会被
// 恢复并保留原始错误。
func standardTypeError(data []byte, v any, err error) error {
	var ute *stdjson.UnmarshalTypeError
	if errors.As(err, &ute) {
		return err
	}
	t := reflect.TypeOf(v)
	if t == nil || t.Kind() != reflect.Pointer {
		return err
	}
	if probeErr := probeStdUnmarshal(data, t.Elem()); probeErr != nil {
		return probeErr
	}
	return err
}

// standardMarshalError attaches the standard library's typed marshal error
// (*UnsupportedTypeError, *UnsupportedValueError or *MarshalerError) to the backend error when
// encoding/json reports one, so errors.As keeps working with the encoding/json error types
// documented by this package. Both chains are preserved through errors.Join. A panic raised by
// a MarshalJSON implementation during the probe is recovered and the original error is kept. |
// standardMarshalError 在 encoding/json 报告带类型的编码错误（*UnsupportedTypeError、
// *UnsupportedValueError 或 *MarshalerError）时把它附加到后端错误上，使 errors.As 与本包文档
// 所列的 encoding/json 错误类型兼容，两条错误链经 errors.Join 一并保留。探针过程中
// MarshalJSON 发生的 panic 会被恢复并保留原始错误。
func standardMarshalError(v any, err error) (out error) {
	if err == nil {
		return nil
	}
	var ute *stdjson.UnsupportedTypeError
	var uve *stdjson.UnsupportedValueError
	var me *stdjson.MarshalerError
	if errors.As(err, &ute) || errors.As(err, &uve) || errors.As(err, &me) {
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			out = err
		}
	}()
	if _, e := stdjson.Marshal(v); e != nil {
		if errors.As(e, &ute) || errors.As(e, &uve) || errors.As(e, &me) {
			return errors.Join(err, e)
		}
	}
	return err
}

// probeStdUnmarshal decodes data into a fresh value of type t and returns the error only when it
// is a standard library type error; any other outcome keeps the caller's original error. |
// probeStdUnmarshal 把 data 解码进 t 类型的新值，仅当结果是标准库类型错误时返回该错误；其他结果
// 都保留调用方原有的错误。
func probeStdUnmarshal(data []byte, t reflect.Type) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = nil
		}
	}()
	if e := stdjson.Unmarshal(data, reflect.New(t).Interface()); e != nil {
		var ute *stdjson.UnmarshalTypeError
		if errors.As(e, &ute) {
			return e
		}
	}
	return nil
}
