package json

import (
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"
	"io"
	"reflect"
	"sync"
)

// The v2 API surface below mirrors encoding/json/v2 exactly. Types that must interoperate with
// the standard library (options, errors, jsontext handles) are aliases, while every marshal,
// unmarshal and option decision is implemented by this package. |
// 下面的 v2 API 面与 encoding/json/v2 完全对应。必须与标准库互操作的类型（选项、错误、
// jsontext 句柄）采用别名，而所有编解码与选项判定都由本包自行实现。

type (
	// MarshalerTo is implemented by types that can marshal themselves directly to a
	// jsontext.Encoder, exactly as in encoding/json/v2. | MarshalerTo 由可直接写入
	// jsontext.Encoder 的类型实现，与 encoding/json/v2 完全一致。
	MarshalerTo = stdjsonv2.MarshalerTo
	// UnmarshalerFrom is implemented by types that can unmarshal themselves directly from a
	// jsontext.Decoder, exactly as in encoding/json/v2. | UnmarshalerFrom 由可直接从
	// jsontext.Decoder 读取的类型实现，与 encoding/json/v2 完全一致。
	UnmarshalerFrom = stdjsonv2.UnmarshalerFrom
	// Marshalers is a list of type-specific marshal functions, exactly as in
	// encoding/json/v2. Construct values with this package's MarshalFunc / MarshalToFunc /
	// JoinMarshalers so they can be executed natively. | Marshalers 是类型专用编码函数列表，与
	// encoding/json/v2 完全一致。请用本包的 MarshalFunc / MarshalToFunc / JoinMarshalers 构造，
	// 以便原生执行。
	Marshalers = stdjsonv2.Marshalers
	// Unmarshalers is a list of type-specific unmarshal functions, exactly as in
	// encoding/json/v2. Construct values with this package's UnmarshalFunc / UnmarshalFromFunc /
	// JoinUnmarshalers so they can be executed natively. | Unmarshalers 是类型专用解码函数列表，
	// 与 encoding/json/v2 完全一致。请用本包的 UnmarshalFunc / UnmarshalFromFunc /
	// JoinUnmarshalers 构造，以便原生执行。
	Unmarshalers = stdjsonv2.Unmarshalers
	// SemanticError describes an error determining the meaning of JSON data as Go data or vice
	// versa, exactly as in encoding/json/v2. | SemanticError 描述 JSON 数据与 Go 数据语义转换的
	// 错误，与 encoding/json/v2 完全一致。
	SemanticError = stdjsonv2.SemanticError
)

// ErrUnknownName indicates that a JSON object member could not be unmarshaled because the name
// is not known to the target Go struct, exactly as in encoding/json/v2. |
// ErrUnknownName 表示 JSON 对象成员名对目标 Go 结构体未知，与 encoding/json/v2 完全一致。
var ErrUnknownName = stdjsonv2.ErrUnknownName

// DefaultOptionsV2 is the full set of options that define v2 semantics. | DefaultOptionsV2 是定义
// v2 语义的完整选项集合。
func DefaultOptionsV2() Options { return stdjsonv2.DefaultOptionsV2() }

// Deterministic specifies that marshaling the same input value always produces the same output. |
// Deterministic 指定同一输入值总是产生相同输出。
func Deterministic(v bool) Options { return stdjsonv2.Deterministic(v) }

// FormatNilMapAsNull specifies that a nil Go map marshals as a JSON null instead of an empty
// object. | FormatNilMapAsNull 指定 nil map 编码为 JSON null 而不是空对象。
func FormatNilMapAsNull(v bool) Options { return stdjsonv2.FormatNilMapAsNull(v) }

// FormatNilSliceAsNull specifies that a nil Go slice marshals as a JSON null instead of an empty
// array. | FormatNilSliceAsNull 指定 nil 切片编码为 JSON null 而不是空数组。
func FormatNilSliceAsNull(v bool) Options { return stdjsonv2.FormatNilSliceAsNull(v) }

// JoinOptions coalesces the provided options; later options override earlier ones. |
// JoinOptions 合并选项，后者覆盖前者。
func JoinOptions(srcs ...Options) Options { return stdjsonv2.JoinOptions(srcs...) }

// MatchCaseInsensitiveNames specifies that JSON object names are matched case-insensitively. |
// MatchCaseInsensitiveNames 指定 JSON 对象名按大小写不敏感匹配。
func MatchCaseInsensitiveNames(v bool) Options {
	return stdjsonv2.MatchCaseInsensitiveNames(v)
}

// OmitZeroStructFields specifies that zero-valued struct fields are omitted during marshal. |
// OmitZeroStructFields 指定编码时省略零值结构体字段。
func OmitZeroStructFields(v bool) Options { return stdjsonv2.OmitZeroStructFields(v) }

// RejectUnknownMembers specifies that unknown object members are rejected during unmarshal. |
// RejectUnknownMembers 指定解码时拒绝未知对象成员。
func RejectUnknownMembers(v bool) Options { return stdjsonv2.RejectUnknownMembers(v) }

// StringifyNumbers specifies that numbers are encoded as JSON strings and decoded from strings. |
// StringifyNumbers 指定数字编码为 JSON 字符串并从字符串解码。
func StringifyNumbers(v bool) Options { return stdjsonv2.StringifyNumbers(v) }

// WithMarshalers specifies type-specific marshal functions. | WithMarshalers 指定类型专用编码函数。
func WithMarshalers(v *Marshalers) Options { return stdjsonv2.WithMarshalers(v) }

// WithUnmarshalers specifies type-specific unmarshal functions. | WithUnmarshalers 指定类型专用
// 解码函数。
func WithUnmarshalers(v *Unmarshalers) Options { return stdjsonv2.WithUnmarshalers(v) }

// GetOption returns the value stored in opts with the provided setter. | GetOption 返回 opts 中
// 由 setter 指定的选项值。
func GetOption[T any](opts Options, setter func(T) Options) (T, bool) {
	return stdjsonv2.GetOption(opts, setter)
}

// marshalerEntry is one native type-specific marshal function. | marshalerEntry 是一个原生类型专用
// 编码函数。
type marshalerEntry struct {
	typ     reflect.Type
	marshal func(reflect.Value) ([]byte, error)
	to      func(*jsontext.Encoder, reflect.Value) error
}

// unmarshalerEntry is one native type-specific unmarshal function. | unmarshalerEntry 是一个原生
// 类型专用解码函数。
type unmarshalerEntry struct {
	typ       reflect.Type
	unmarshal func([]byte, reflect.Value) error
	from      func(*jsontext.Decoder, reflect.Value) error
}

var (
	marshalerRegistry   sync.Map // map[*Marshalers][]marshalerEntry
	unmarshalerRegistry sync.Map // map[*Unmarshalers][]unmarshalerEntry
)

// MarshalFunc constructs a type-specific marshal function from fn, exactly as in
// encoding/json/v2. The returned value is executed natively by this package. |
// MarshalFunc 用 fn 构造类型专用编码函数，与 encoding/json/v2 一致；返回值由本包原生执行。
func MarshalFunc[T any](fn func(T) ([]byte, error)) *Marshalers {
	ms := stdjsonv2.MarshalFunc(fn)
	registerMarshalers(ms, marshalerEntry{
		typ: reflect.TypeFor[T](),
		marshal: func(v reflect.Value) ([]byte, error) {
			return fn(v.Interface().(T))
		},
	})
	return ms
}

// MarshalToFunc constructs a type-specific marshal function that writes to a jsontext.Encoder,
// exactly as in encoding/json/v2. | MarshalToFunc 构造写入 jsontext.Encoder 的类型专用编码函数，
// 与 encoding/json/v2 一致。
func MarshalToFunc[T any](fn func(*jsontext.Encoder, T) error) *Marshalers {
	ms := stdjsonv2.MarshalToFunc(fn)
	registerMarshalers(ms, marshalerEntry{
		typ: reflect.TypeFor[T](),
		to: func(enc *jsontext.Encoder, v reflect.Value) error {
			return fn(enc, v.Interface().(T))
		},
	})
	return ms
}

// UnmarshalFunc constructs a type-specific unmarshal function from fn, exactly as in
// encoding/json/v2. | UnmarshalFunc 用 fn 构造类型专用解码函数，与 encoding/json/v2 一致。
func UnmarshalFunc[T any](fn func([]byte, T) error) *Unmarshalers {
	us := stdjsonv2.UnmarshalFunc(fn)
	registerUnmarshalers(us, unmarshalerEntry{
		typ: reflect.TypeFor[T](),
		unmarshal: func(data []byte, v reflect.Value) error {
			return fn(data, v.Interface().(T))
		},
	})
	return us
}

// UnmarshalFromFunc constructs a type-specific unmarshal function that reads from a
// jsontext.Decoder, exactly as in encoding/json/v2. | UnmarshalFromFunc 构造从 jsontext.Decoder
// 读取的类型专用解码函数，与 encoding/json/v2 一致。
func UnmarshalFromFunc[T any](fn func(*jsontext.Decoder, T) error) *Unmarshalers {
	us := stdjsonv2.UnmarshalFromFunc(fn)
	registerUnmarshalers(us, unmarshalerEntry{
		typ: reflect.TypeFor[T](),
		from: func(dec *jsontext.Decoder, v reflect.Value) error {
			return fn(dec, v.Interface().(T))
		},
	})
	return us
}

// JoinMarshalers constructs a flattened list of marshal functions. | JoinMarshalers 构造扁平化的
// 编码函数列表。
func JoinMarshalers(ms ...*Marshalers) *Marshalers {
	out := stdjsonv2.JoinMarshalers(ms...)
	var entries []marshalerEntry
	for _, m := range ms {
		entries = append(entries, lookupMarshalers(m)...)
	}
	registerMarshalers(out, entries...)
	return out
}

// JoinUnmarshalers constructs a flattened list of unmarshal functions. | JoinUnmarshalers 构造
// 扁平化的解码函数列表。
func JoinUnmarshalers(us ...*Unmarshalers) *Unmarshalers {
	out := stdjsonv2.JoinUnmarshalers(us...)
	var entries []unmarshalerEntry
	for _, u := range us {
		entries = append(entries, lookupUnmarshalers(u)...)
	}
	registerUnmarshalers(out, entries...)
	return out
}

func registerMarshalers(ms *Marshalers, entries ...marshalerEntry) {
	if ms == nil {
		return
	}
	if existing, ok := marshalerRegistry.Load(ms); ok {
		entries = append(existing.([]marshalerEntry), entries...)
	}
	marshalerRegistry.Store(ms, entries)
}

func registerUnmarshalers(us *Unmarshalers, entries ...unmarshalerEntry) {
	if us == nil {
		return
	}
	if existing, ok := unmarshalerRegistry.Load(us); ok {
		entries = append(existing.([]unmarshalerEntry), entries...)
	}
	unmarshalerRegistry.Store(us, entries)
}

func lookupMarshalers(ms *Marshalers) []marshalerEntry {
	if ms == nil {
		return nil
	}
	if v, ok := marshalerRegistry.Load(ms); ok {
		return v.([]marshalerEntry)
	}
	return nil
}

func lookupUnmarshalers(us *Unmarshalers) []unmarshalerEntry {
	if us == nil {
		return nil
	}
	if v, ok := unmarshalerRegistry.Load(us); ok {
		return v.([]unmarshalerEntry)
	}
	return nil
}

// MarshalWrite serializes in into out according to the options, matching
// encoding/json/v2.MarshalWrite. | MarshalWrite 按选项把 in 序列化到 out，与
// encoding/json/v2.MarshalWrite 一致。
func MarshalWrite(out io.Writer, in any, opts ...Options) error {
	b, err := Marshal(in, opts...)
	if err != nil {
		return err
	}
	_, err = out.Write(b)
	return err
}

// UnmarshalRead reads all JSON text from in and unmarshals it into out according to the options,
// matching encoding/json/v2.UnmarshalRead. | UnmarshalRead 读取 in 中的全部 JSON 文本并按选项
// 解码到 out，与 encoding/json/v2.UnmarshalRead 一致。
func UnmarshalRead(in io.Reader, out any, opts ...Options) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	return Unmarshal(data, out, opts...)
}

// MarshalEncode marshals in as a single JSON value written to out, matching
// encoding/json/v2.MarshalEncode. | MarshalEncode 把 in 编码为单个 JSON 值写入 out，与
// encoding/json/v2.MarshalEncode 一致。
func MarshalEncode(out *jsontext.Encoder, in any, opts ...Options) error {
	b, err := Marshal(in, opts...)
	if err != nil {
		return err
	}
	return out.WriteValue(b)
}

// UnmarshalDecode reads a single JSON value from in and unmarshals it into out, matching
// encoding/json/v2.UnmarshalDecode. | UnmarshalDecode 从 in 读取单个 JSON 值并解码到 out，与
// encoding/json/v2.UnmarshalDecode 一致。
func UnmarshalDecode(in *jsontext.Decoder, out any, opts ...Options) error {
	b, err := in.ReadValue()
	if err != nil {
		return err
	}
	return Unmarshal(b, out, opts...)
}
