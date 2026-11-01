//go:build jsonx_std

// This file is the jsonx standard-library implementation: setting the jsonx_std build tag switches entirely to encoding/json, | 本文件是 jsonx 的标准库实现：设置 jsonx_std 构建标签后整体切换到 encoding/json，
// for troubleshooting, compatibility comparison, and minimal-dependency builds in extreme environments. | 用于排障、兼容性对照与极端环境下的最小依赖构建。
//
// The build constraint `jsonx_std` is mutually exclusive with `!jsonx_std` of the native
// backend files, so duplicate symbols cannot occur. | 构建约束 `jsonx_std` 与自研后端文件的
// `!jsonx_std` 互斥，因此不会出现重复符号。

package json

import (
	stdjson "encoding/json"
	"io"
)

// Backend returns the name of the currently active JSON backend; with the jsonx_std tag set it is always "encoding/json". | Backend 返回当前生效的 JSON 后端名称；设置 jsonx_std 标签时恒为 "encoding/json"。
func Backend() string {
	return "encoding/json"
}

// Marshal returns the JSON encoding of v (standard library encoding/json semantics). | Marshal 返回 v 的 JSON 编码（标准库 encoding/json 语义）。
func Marshal(v any) ([]byte, error) {
	return stdjson.Marshal(v)
}

// Unmarshal parses JSON-encoded data and stores the result in the value pointed to by v. | Unmarshal 解析 JSON 编码的数据并将其存入 v 指向的值。
//
// The error returned on failure can be matched with errors.Is against ErrSyntax or ErrTypeMismatch. | 出错时返回的错误可用 errors.Is 判定为 ErrSyntax 或 ErrTypeMismatch。
func Unmarshal(data []byte, v any) error {
	return wrapDecodeError(data, v, stdjson.Unmarshal(data, v))
}

// MarshalIndent is like Marshal but indents the output according to prefix and indent. | MarshalIndent 与 Marshal 类似，但按 prefix 与 indent 缩进输出。
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return stdjson.MarshalIndent(v, prefix, indent)
}

// Valid reports whether data is valid JSON text. | Valid 报告 data 是否是合法的 JSON 文本。
func Valid(data []byte) bool {
	return stdjson.Valid(data)
}

// Encoder streams JSON values to an io.Writer, terminating each message with a newline. | Encoder 将 JSON 值流式写入 io.Writer，每条消息以换行结尾。
type Encoder struct {
	enc *stdjson.Encoder
}

// NewEncoder returns an Encoder writing to w, escaping HTML characters by default. | NewEncoder 返回写入 w 的 Encoder，默认转义 HTML 字符。
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{enc: stdjson.NewEncoder(w)}
}

// Encode writes the JSON encoding of v to the underlying io.Writer and appends a newline. | Encode 将 v 的 JSON 编码写入底层 io.Writer，并追加一个换行符。
func (e *Encoder) Encode(v any) error {
	return e.enc.Encode(v)
}

// SetEscapeHTML specifies whether to escape HTML characters such as & < > inside JSON strings; | SetEscapeHTML 指定是否在 JSON 字符串中转义 & < > 等 HTML 字符；
// turning it off makes the output more readable, but unsuitable for embedding directly into HTML. | 关闭后输出更易读，但不适合直接嵌入 HTML。
func (e *Encoder) SetEscapeHTML(on bool) {
	e.enc.SetEscapeHTML(on)
}

// SetIndent instructs the Encoder to use the standard library's indented output. | SetIndent
// 让 Encoder 使用标准库的缩进输出。
func (e *Encoder) SetIndent(prefix, indent string) {
	e.enc.SetIndent(prefix, indent)
}

// Decoder reads and parses JSON values from an io.Reader, and can read several values in a row from the stream. | Decoder 从 io.Reader 读取并解析 JSON 值，可连续读取流中的多个值。
type Decoder struct {
	dec *stdjson.Decoder
}

// NewDecoder returns a Decoder that reads from r. | NewDecoder 返回从 r 读取的 Decoder。
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{dec: stdjson.NewDecoder(r)}
}

// Decode reads the next JSON value from the input stream and stores it in the value pointed to by v; | Decode 从输入流读取下一个 JSON 值并存入 v 指向的值；
// it returns io.EOF when the stream is exhausted. | 流耗尽时返回 io.EOF。
func (d *Decoder) Decode(v any) error {
	return d.dec.Decode(v)
}

// UseNumber causes Decode to parse numbers as json.Number (preserving the original text) instead of float64. | UseNumber 使 Decode 把数字解析为 json.Number（保留原始文本）而不是 float64。
func (d *Decoder) UseNumber() {
	d.dec.UseNumber()
}

// DisallowUnknownFields causes Decode to return an error when the destination is a struct and
// the input contains object keys that do not match any destination struct field. |
// DisallowUnknownFields 使 Decode 在目标为结构体且输入含有不匹配任何目标字段的对象键时返回错误。
func (d *Decoder) DisallowUnknownFields() {
	d.dec.DisallowUnknownFields()
}

// More reports whether there is another element in the current array or object being parsed. |
// More 报告当前解析中的数组或对象是否还有下一个元素。
func (d *Decoder) More() bool {
	return d.dec.More()
}

// Token returns the next JSON token in the input stream. | Token 返回输入流中的下一个 JSON 记号。
func (d *Decoder) Token() (Token, error) {
	return d.dec.Token()
}

// Buffered returns a reader of the data remaining in the decoder's buffer. | Buffered 返回解码器
// 缓冲区中剩余数据的读取器。
func (d *Decoder) Buffered() io.Reader {
	return d.dec.Buffered()
}

// InputOffset returns the input stream byte offset of the current decoder position. |
// InputOffset 返回当前解码位置在输入流中的字节偏移。
func (d *Decoder) InputOffset() int64 {
	return d.dec.InputOffset()
}
