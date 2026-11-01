//go:build !jsonx_std

package json

import (
	"bytes"
	"io"
	"strconv"
)

// tokenFrame is one open JSON container while Decoder.Token walks the stream. state tracks what
// the grammar expects next: 0 fresh, 1 after a comma, 2 after a value, 3 after an object key
// (expect ':'), 4 after ':' (expect a value). | tokenFrame 表示 Decoder.Token 遍历流时打开的一层
// JSON 容器。state 记录语法下一步的期望：0 初始、1 逗号之后、2 值之后、3 对象键之后（期望 ':'）、
// 4 ':' 之后（期望值）。
type tokenFrame struct {
	open  byte
	state uint8
}

// DisallowUnknownFields causes Decode to return an error when the destination is a struct and
// the input contains object keys that do not match any destination struct field, following
// encoding/json.Decoder.DisallowUnknownFields. | DisallowUnknownFields 使 Decode 在目标为结构体
// 且输入含有不匹配任何目标字段的对象键时返回错误，行为与
// encoding/json.Decoder.DisallowUnknownFields 一致。
func (d *Decoder) DisallowUnknownFields() { d.disallowUnknown = true }

// InputOffset returns the input stream byte offset of the current decoder position, exactly as
// in encoding/json.Decoder.InputOffset. | InputOffset 返回当前解码位置在输入流中的字节偏移，与
// encoding/json.Decoder.InputOffset 完全一致。
func (d *Decoder) InputOffset() int64 { return int64(d.pos) }

// Buffered returns a reader of the data remaining in the decoder's buffer, exactly as in
// encoding/json.Decoder.Buffered. The reader is valid until the next call to Decode. | Buffered
// 返回解码器缓冲区中剩余数据的读取器，与 encoding/json.Decoder.Buffered 一致；该读取器在下次
// 调用 Decode 前有效。
func (d *Decoder) Buffered() io.Reader { return bytes.NewReader(d.data[d.pos:]) }

// More reports whether there is another element in the current array or object being parsed,
// exactly as in encoding/json.Decoder.More. | More 报告当前解析中的数组或对象是否还有下一个
// 元素，与 encoding/json.Decoder.More 完全一致。
func (d *Decoder) More() bool {
	if err := d.load(); err != nil || len(d.tokens) == 0 {
		return false
	}
	dec := &decoder{data: d.data, pos: d.pos}
	dec.skipSpace()
	if dec.pos >= len(dec.data) {
		return false
	}
	return dec.data[dec.pos] != ']' && dec.data[dec.pos] != '}'
}

// Token returns the next JSON token in the input stream, exactly as in
// encoding/json.Decoder.Token: a Delim for [ ] { }, a bool, a float64 or Number, a string, or
// nil for the null literal. | Token 返回输入流中的下一个 JSON 记号，与
// encoding/json.Decoder.Token 完全一致：[]、{} 返回 Delim，其余为 bool、float64 或 Number、
// string，null 字面量返回 nil。
func (d *Decoder) Token() (Token, error) {
	if err := d.load(); err != nil {
		return nil, err
	}
	dec := &decoder{data: d.data, pos: d.pos, useNumber: d.useNumber}
	tok, err := d.nextToken(dec)
	d.pos = dec.pos
	return tok, err
}

// nextToken implements the Token grammar state machine. | nextToken 实现 Token 的语法状态机。
func (d *Decoder) nextToken(dec *decoder) (Token, error) {
	for {
		dec.skipSpace()
		if dec.pos >= len(dec.data) {
			if len(d.tokens) > 0 {
				return nil, syntaxErr("unexpected end of JSON input | JSON 输入意外结束")
			}
			return nil, io.EOF
		}
		c := dec.data[dec.pos]
		if len(d.tokens) == 0 {
			switch c {
			case ']', '}', ',', ':':
				return nil, syntaxErr("invalid character %q looking for beginning of value | 期望值的起始字符时遇到非法字符 %q", c, c)
			}
			return d.valueToken(dec, nil)
		}
		top := &d.tokens[len(d.tokens)-1]
		switch top.state {
		case 3:
			if c != ':' {
				return nil, syntaxErr("missing ':' after object key | 对象键之后缺少 ':'")
			}
			dec.pos++
			top.state = 4
		case 2:
			switch c {
			case ',':
				dec.pos++
				top.state = 1
			case ']':
				if top.open != '[' {
					return nil, syntaxErr("unexpected ']' in object | 对象中意外出现 ']'")
				}
				dec.pos++
				d.tokens = d.tokens[:len(d.tokens)-1]
				return Delim(']'), nil
			case '}':
				if top.open != '{' {
					return nil, syntaxErr("unexpected '}' in array | 数组中意外出现 '}'")
				}
				dec.pos++
				d.tokens = d.tokens[:len(d.tokens)-1]
				return Delim('}'), nil
			default:
				return nil, syntaxErr("invalid character %q after element | 元素之后遇到非法字符 %q", c, c)
			}
		case 0, 1:
			if top.open == '{' {
				if c == '}' {
					if top.state == 1 {
						return nil, syntaxErr("invalid character '}' after object key-value separator | 对象成员分隔符之后遇到非法字符 '}'")
					}
					dec.pos++
					d.tokens = d.tokens[:len(d.tokens)-1]
					return Delim('}'), nil
				}
				if c != '"' {
					return nil, syntaxErr("invalid character %q looking for beginning of object key string | 期望对象键时遇到非法字符 %q", c, c)
				}
				key, err := dec.parseString()
				if err != nil {
					return nil, err
				}
				top.state = 3
				return key, nil
			}
			if c == ']' {
				if top.state == 1 {
					return nil, syntaxErr("invalid character ']' after array element separator | 数组元素分隔符之后遇到非法字符 ']'")
				}
				dec.pos++
				d.tokens = d.tokens[:len(d.tokens)-1]
				return Delim(']'), nil
			}
			return d.valueToken(dec, top)
		default: // state 4: a value after ':' | 冒号之后的值
			return d.valueToken(dec, top)
		}
	}
}

// valueToken parses one scalar token or opens one container. | valueToken 解析一个标量记号，或
// 打开一层容器。
func (d *Decoder) valueToken(dec *decoder, parent *tokenFrame) (Token, error) {
	c := dec.data[dec.pos]
	if parent != nil {
		parent.state = 2
	}
	switch c {
	case '{', '[':
		dec.pos++
		d.tokens = append(d.tokens, tokenFrame{open: c})
		return Delim(c), nil
	case '"':
		return dec.parseString()
	case 'n':
		if err := dec.literal("null"); err != nil {
			return nil, err
		}
		return nil, nil
	case 't', 'f':
		return dec.parseBool()
	default:
		b, err := dec.parseNumberBytes()
		if err != nil {
			return nil, err
		}
		if dec.useNumber {
			return Number(string(b)), nil
		}
		f, err := parseFloatToken(b)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
}

// parseFloatToken converts a validated number literal to float64, matching the value type that
// encoding/json returns from Decoder.Token. | parseFloatToken 把已校验的数字字面量转换为
// float64，与 encoding/json 的 Decoder.Token 返回值类型一致。
func parseFloatToken(b []byte) (float64, error) {
	if f, ok := parseShortDecimalFloat(b); ok {
		return f, nil
	}
	f, err := strconv.ParseFloat(bytesString(b), 64)
	if err != nil {
		return 0, syntaxErr("invalid number %q | 非法数字 %q", bytesString(b), bytesString(b))
	}
	return f, nil
}
