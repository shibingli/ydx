package json

import (
	"bytes"
	stdjson "encoding/json"
)

// The following type aliases make github.com/shibingli/ydx/json a drop-in replacement for
// encoding/json: values and errors produced by either backend satisfy the same types, so
// callers keep using json.Number, json.RawMessage, json.Marshaler and errors.As with
// json.SyntaxError / json.UnmarshalTypeError unchanged. | 以下类型别名使
// github.com/shibingli/ydx/json 可直接替代 encoding/json：任一后端产生的值与错误都满足同一
// 类型，调用方可以原样使用 json.Number、json.RawMessage、json.Marshaler，以及
// errors.As 与 json.SyntaxError / json.UnmarshalTypeError。
type (
	// Number is a JSON number literal, exactly as in encoding/json. | Number 是 JSON 数字
	// 字面量，与 encoding/json 完全一致。
	Number = stdjson.Number
	// RawMessage is a raw encoded JSON value, exactly as in encoding/json. | RawMessage 是
	// 未解析的 JSON 原始值，与 encoding/json 完全一致。
	RawMessage = stdjson.RawMessage
	// Delim is a JSON array or object delimiter, exactly as in encoding/json. | Delim 是
	// JSON 数组或对象的分隔符，与 encoding/json 完全一致。
	Delim = stdjson.Delim
	// Token holds a value returned by Decoder.Token, exactly as in encoding/json. | Token 是
	// Decoder.Token 返回的值，与 encoding/json 完全一致。
	Token = stdjson.Token
	// Marshaler is the interface implemented by types that can marshal themselves, exactly as
	// in encoding/json. | Marshaler 是自行编码类型实现的接口，与 encoding/json 完全一致。
	Marshaler = stdjson.Marshaler
	// Unmarshaler is the interface implemented by types that can unmarshal themselves, exactly
	// as in encoding/json. | Unmarshaler 是自行解码类型实现的接口，与 encoding/json 完全一致。
	Unmarshaler = stdjson.Unmarshaler
	// SyntaxError describes a JSON syntax error, exactly as in encoding/json. | SyntaxError 描述
	// JSON 语法错误，与 encoding/json 完全一致。
	SyntaxError = stdjson.SyntaxError
	// UnmarshalTypeError describes a JSON value that is not appropriate for a Go type, exactly
	// as in encoding/json. | UnmarshalTypeError 描述与 Go 类型不匹配的 JSON 值，与
	// encoding/json 完全一致。
	UnmarshalTypeError = stdjson.UnmarshalTypeError
	// InvalidUnmarshalError describes an invalid argument passed to Unmarshal or Decode,
	// exactly as in encoding/json. | InvalidUnmarshalError 描述传给 Unmarshal 或 Decode 的
	// 非法参数，与 encoding/json 完全一致。
	InvalidUnmarshalError = stdjson.InvalidUnmarshalError
	// UnsupportedTypeError is returned by Marshal when attempting to encode an unsupported
	// value type, exactly as in encoding/json. | UnsupportedTypeError 是 Marshal 编码不支持
	// 的类型时返回的错误，与 encoding/json 完全一致。
	UnsupportedTypeError = stdjson.UnsupportedTypeError
	// UnsupportedValueError is returned by Marshal when attempting to encode an unsupported
	// value, exactly as in encoding/json. | UnsupportedValueError 是 Marshal 编码不支持的值时
	// 返回的错误，与 encoding/json 完全一致。
	UnsupportedValueError = stdjson.UnsupportedValueError
	// MarshalerError represents an error from calling a MarshalJSON or MarshalText method,
	// exactly as in encoding/json. | MarshalerError 表示调用 MarshalJSON 或 MarshalText 方法
	// 时的错误，与 encoding/json 完全一致。
	MarshalerError = stdjson.MarshalerError
	// InvalidUTF8Error is the deprecated UTF-8 error type kept by encoding/json; the alias keeps
	// source compatibility for callers that still reference it. | InvalidUTF8Error 是
	// encoding/json 保留的已弃用 UTF-8 错误类型；该别名为仍引用它的调用方保持源码兼容。
	InvalidUTF8Error = stdjson.InvalidUTF8Error
	// UnmarshalFieldError is the deprecated field error type kept by encoding/json; the alias
	// keeps source compatibility for callers that still reference it. | UnmarshalFieldError 是
	// encoding/json 保留的已弃用字段错误类型；该别名为仍引用它的调用方保持源码兼容。
	UnmarshalFieldError = stdjson.UnmarshalFieldError
	// Options configures the v2 JSON packages for v1 semantics, exactly as in Go 1.27's
	// encoding/json. | Options 为 v2 JSON 包配置 v1 语义，与 Go 1.27 的 encoding/json 完全一致。
	Options = stdjson.Options
)

// The option constructors below mirror encoding/json's v1/v2 compatibility helpers verbatim;
// they configure encoding/json/v2, which this package does not wrap, and exist so code that
// references them keeps compiling after switching the import. | 以下选项构造函数与
// encoding/json 的 v1/v2 兼容辅助函数逐一对应；它们配置本包未包装的 encoding/json/v2，存在的
// 目的是让引用它们的代码在替换导入后仍可编译。
func CallMethodsWithLegacySemantics(v bool) Options { return stdjson.CallMethodsWithLegacySemantics(v) }
func DefaultOptionsV1() Options                     { return stdjson.DefaultOptionsV1() }
func FormatByteArrayAsArray(v bool) Options         { return stdjson.FormatByteArrayAsArray(v) }
func FormatBytesWithLegacySemantics(v bool) Options {
	return stdjson.FormatBytesWithLegacySemantics(v)
}
func FormatDurationAsNano(v bool) Options { return stdjson.FormatDurationAsNano(v) }
func MatchCaseSensitiveDelimiter(v bool) Options {
	return stdjson.MatchCaseSensitiveDelimiter(v)
}
func MergeWithLegacySemantics(v bool) Options { return stdjson.MergeWithLegacySemantics(v) }
func OmitEmptyWithLegacySemantics(v bool) Options {
	return stdjson.OmitEmptyWithLegacySemantics(v)
}
func ParseBytesWithLooseRFC4648(v bool) Options { return stdjson.ParseBytesWithLooseRFC4648(v) }
func ParseTimeWithLooseRFC3339(v bool) Options  { return stdjson.ParseTimeWithLooseRFC3339(v) }
func ReportErrorsWithLegacySemantics(v bool) Options {
	return stdjson.ReportErrorsWithLegacySemantics(v)
}
func StringifyWithLegacySemantics(v bool) Options {
	return stdjson.StringifyWithLegacySemantics(v)
}
func UnmarshalArrayFromAnyLength(v bool) Options {
	return stdjson.UnmarshalArrayFromAnyLength(v)
}

// Compact appends to dst the JSON-encoded src with insignificant space characters elided,
// matching encoding/json.Compact. | Compact 把省略无意义空白后的 JSON 追加到 dst，与
// encoding/json.Compact 一致。
func Compact(dst *bytes.Buffer, src []byte) error {
	if err := validateForFormat(src); err != nil {
		return err
	}
	dst.Write(appendCompact(dst.AvailableBuffer(), src))
	return nil
}

// Indent appends to dst an indented form of the JSON-encoded src, matching encoding/json.Indent:
// each element begins on a new line led by prefix and one or more copies of indent, leading
// whitespace is dropped, and trailing whitespace is preserved. | Indent 把缩进后的 JSON 追加到
// dst，与 encoding/json.Indent 一致：每个元素另起一行，由 prefix 与一层或多层 indent 引导；
// 前导空白被丢弃，尾部空白原样保留。
func Indent(dst *bytes.Buffer, src []byte, prefix, indent string) error {
	if err := validateForFormat(src); err != nil {
		return err
	}
	dst.Write(appendIndent(dst.AvailableBuffer(), src, prefix, indent))
	return nil
}

// HTMLEscape appends to dst the JSON-encoded src with <, >, & and U+2028/U+2029 characters
// escaped, matching encoding/json.HTMLEscape. | HTMLEscape 把转义 <、>、& 与 U+2028/U+2029 后的
// JSON 追加到 dst，与 encoding/json.HTMLEscape 一致。
func HTMLEscape(dst *bytes.Buffer, src []byte) {
	dst.Write(appendHTMLEscape(dst.AvailableBuffer(), src))
}

// validateForFormat validates src and returns a standard-library-compatible syntax error with
// the same type, message and offset when it is not a single valid JSON value. | validateForFormat
// 校验 src；当它不是单个合法 JSON 值时，返回类型、文案与偏移都与标准库一致的语法错误。
func validateForFormat(src []byte) error {
	if Valid(src) {
		return nil
	}
	return stdSyntaxError(src)
}

// stdSyntaxError recovers the standard library's *SyntaxError for invalid input. It runs only on
// the error path. | stdSyntaxError 在错误路径上取得标准库的 *SyntaxError。
func stdSyntaxError(src []byte) error {
	var raw RawMessage
	if err := stdjson.Unmarshal(src, &raw); err != nil {
		return err
	}
	return &SyntaxError{} // unreachable for input rejected by Valid; keeps a concrete error type
}

// appendCompact removes insignificant whitespace outside strings. src must already be valid. |
// appendCompact 删除字符串之外的无意义空白；src 必须已通过校验。
func appendCompact(dst, src []byte) []byte {
	start := 0
	inString := false
	escaped := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case ' ', '\t', '\n', '\r':
			if start < i {
				dst = append(dst, src[start:i]...)
			}
			start = i + 1
		}
	}
	return append(dst, src[start:]...)
}

// appendIndent formats valid JSON exactly like encoding/json.Indent does: byte order is kept,
// strings are copied verbatim, and only inter-token whitespace is rewritten. | appendIndent 按
// encoding/json.Indent 的方式格式化合法 JSON：保持字节顺序、字符串原样复制，只重写记号之间的
// 空白。
func appendIndent(dst, src []byte, prefix, indent string) []byte {
	end := len(src)
	for end > 0 {
		switch src[end-1] {
		case ' ', '\t', '\n', '\r':
			end--
			continue
		}
		break
	}
	trailing := src[end:]
	inString := false
	escaped := false
	needIndent := false
	depth := 0
	newline := func() {
		dst = append(dst, '\n')
		dst = append(dst, prefix...)
		for i := 0; i < depth; i++ {
			dst = append(dst, indent...)
		}
	}
	for i := 0; i < end; i++ {
		c := src[i]
		if inString {
			dst = append(dst, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case ',':
			dst = append(dst, c)
			newline()
		case ':':
			dst = append(dst, c, ' ')
		case '{', '[':
			if needIndent {
				needIndent = false
				depth++
				newline()
			}
			dst = append(dst, c)
			needIndent = true
		case '}', ']':
			if needIndent {
				needIndent = false
			} else {
				depth--
				newline()
			}
			dst = append(dst, c)
		case '"':
			if needIndent {
				needIndent = false
				depth++
				newline()
			}
			dst = append(dst, c)
			inString = true
		default:
			if needIndent {
				needIndent = false
				depth++
				newline()
			}
			dst = append(dst, c)
		}
	}
	return append(dst, trailing...)
}

// appendHTMLEscape escapes <, >, & and U+2028/U+2029 outside and inside strings, exactly as
// encoding/json.HTMLEscape does. | appendHTMLEscape 与 encoding/json.HTMLEscape 一样转义 <、>、&
// 与 U+2028/U+2029。
func appendHTMLEscape(dst, src []byte) []byte {
	const hexDigits = "0123456789abcdef"
	start := 0
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '<' || c == '>' || c == '&' {
			dst = append(dst, src[start:i]...)
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			start = i + 1
			continue
		}
		if c == 0xE2 && i+2 < len(src) && src[i+1] == 0x80 && src[i+2]&^1 == 0xA8 {
			dst = append(dst, src[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[src[i+2]&0xF])
			i += 2
			start = i + 1
		}
	}
	return append(dst, src[start:]...)
}
