//go:build !jsonx_std

package json

import (
	"encoding/binary"
	stdjson "encoding/json"
	"math/bits"
	"strconv"
	"strings"
	"unicode/utf8"
	"unsafe"
)

func (d *decoder) valueAny() (any, error) {
	d.skipSpace()
	if d.pos >= len(d.data) {
		return nil, syntaxErr("unexpected end of JSON input | JSON 输入意外结束")
	}
	switch d.data[d.pos] {
	case 'n':
		return nil, d.literal("null")
	case 't', 'f':
		return d.parseBool()
	case '"':
		return d.parseString()
	case '{':
		return d.anyObject()
	case '[':
		return d.anyArray()
	default:
		b, err := d.parseNumberBytes()
		if err != nil {
			return nil, err
		}
		if d.useNumber {
			return stdjson.Number(string(b)), nil
		}
		if f, ok := parseShortDecimalFloat(b); ok {
			return f, nil
		}
		f, err := strconv.ParseFloat(bytesString(b), 64)
		if err != nil {
			return nil, syntaxErr("invalid number %q | 非法数字 %q", bytesString(b), bytesString(b))
		}
		return f, nil
	}
}

func (d *decoder) anyObject() (any, error) {
	if err := d.enter(); err != nil {
		return nil, err
	}
	defer d.leave()
	d.pos++
	out := make(map[string]any)
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == '}' {
		d.pos++
		return out, nil
	}
	for {
		d.skipSpace()
		if d.pos >= len(d.data) || d.data[d.pos] != '"' {
			return nil, syntaxErr("expected object key | 期望对象键")
		}
		key, err := d.parseString()
		if err != nil {
			return nil, err
		}
		d.skipSpace()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return nil, syntaxErr("expected ':' after object key | 对象键之后期望 ':'")
		}
		d.pos++
		val, err := d.valueAny()
		if err != nil {
			return nil, err
		}
		out[key] = val
		d.skipSpace()
		if d.pos >= len(d.data) {
			return nil, syntaxErr("unexpected end of object | 对象意外结束")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
		case '}':
			d.pos++
			return out, nil
		default:
			return nil, syntaxErr("expected ',' or '}' in object | 对象中期望 ',' 或 '}'")
		}
	}
}

func (d *decoder) anyArray() (any, error) {
	if err := d.enter(); err != nil {
		return nil, err
	}
	defer d.leave()
	d.pos++
	out := make([]any, 0)
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		return out, nil
	}
	for {
		val, err := d.valueAny()
		if err != nil {
			return nil, err
		}
		out = append(out, val)
		d.skipSpace()
		if d.pos >= len(d.data) {
			return nil, syntaxErr("unexpected end of array | 数组意外结束")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
		case ']':
			d.pos++
			return out, nil
		default:
			return nil, syntaxErr("expected ',' or ']' in array | 数组中期望 ',' 或 ']'")
		}
	}
}

func (d *decoder) literal(s string) error {
	if len(d.data)-d.pos < len(s) || string(d.data[d.pos:d.pos+len(s)]) != s {
		return syntaxErr("invalid literal | 非法字面量")
	}
	d.pos += len(s)
	return nil
}

func (d *decoder) parseBool() (bool, error) {
	if d.pos < len(d.data) && d.data[d.pos] == 't' {
		if err := d.literal("true"); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := d.literal("false"); err != nil {
		return false, err
	}
	return false, nil
}

// parseCleanString scans and copies a string body in one pass. It accepts only ASCII bytes that
// need no JSON unescaping: a closing quote reached before any backslash, control byte or
// non-ASCII byte. On success it advances d.pos past the quote and returns the copied string;
// otherwise it restores the arena and leaves d.pos unchanged for the general parser. |
// parseCleanString 单遍扫描并复制字符串体，仅接受无需 JSON 反转义且为 ASCII 的内容：在反斜杠、
// 控制字节或非 ASCII 字节之前遇到结束引号。成功时把 d.pos 推进到引号之后并返回复制后的字符串；
// 否则恢复 arena 且不改变 d.pos，交给通用解析器。
func (d *decoder) parseCleanString(start int) (string, bool) {
	data := d.data
	if start < len(data) && data[start] == '"' {
		d.pos = start + 1
		return "", true
	}
	d.ensureArena()
	d.ensureArenaSpare(minArenaChunk)
	chunk := d.arena
	arenaStart := len(chunk)
	i := start
	written := 0
	for len(data)-i >= 8 {
		x := binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(data[i:]), 8))
		if x&wordHi != 0 || wordHasControl(x) || wordHasZero(x^wordQuote) || wordHasZero(x^wordBackslash) {
			// The lowest flagged byte is always a true special byte: false positives from the
			// borrow trick can only follow an earlier true hit. | 最低的标记字节必定是真实的特殊
			// 字节：借位技巧的假阳性只会出现在更早的真实命中之后。
			all := wordZeroMask(x^wordQuote) | wordZeroMask(x^wordBackslash) | wordControlMask(x) | (x & wordHi)
			j := bits.TrailingZeros64(all) >> 3
			if data[i+j] != '"' {
				d.arena = chunk[:arenaStart]
				return "", false
			}
			if j > 0 {
				if cap(d.arena)-len(d.arena) < 8 {
					d.arena = chunk[:arenaStart]
					return "", false
				}
				dst := d.arena[len(d.arena) : len(d.arena)+8]
				binary.LittleEndian.PutUint64(dst, x)
				d.arena = d.arena[:len(d.arena)+j]
				written += j
			}
			d.pos = i + j + 1
			return unsafe.String(unsafe.SliceData(d.arena[arenaStart:]), written), true
		}
		if cap(d.arena)-len(d.arena) < 8 {
			d.arena = chunk[:arenaStart]
			return "", false
		}
		dst := d.arena[len(d.arena) : len(d.arena)+8]
		binary.LittleEndian.PutUint64(dst, x)
		d.arena = d.arena[:len(d.arena)+8]
		written += 8
		i += 8
	}
	for ; i < len(data); i++ {
		c := data[i]
		if c == '"' {
			d.pos = i + 1
			return unsafe.String(unsafe.SliceData(d.arena[arenaStart:]), written), true
		}
		if c == '\\' || c < 0x20 || c >= utf8.RuneSelf {
			d.arena = chunk[:arenaStart]
			return "", false
		}
		if cap(d.arena)-len(d.arena) < 1 {
			d.arena = chunk[:arenaStart]
			return "", false
		}
		d.arena = append(d.arena, c)
		written++
	}
	d.arena = chunk[:arenaStart]
	return "", false
}

func (d *decoder) parseString() (string, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != '"' {
		return "", syntaxErr("expected string | 期望字符串")
	}
	start := d.pos + 1
	if s, ok := d.parseCleanString(start); ok {
		return s, nil
	}
	if end, slow, nonASCII := scanStringBody(d.data, start); !slow && (!nonASCII || utf8.Valid(d.data[start:end])) {
		d.pos = end + 1
		return d.copyString(d.data[start:end]), nil
	}
	d.pos = start
	var b strings.Builder
	for d.pos < len(d.data) {
		c := d.data[d.pos]
		switch c {
		case '"':
			d.pos++
			return b.String(), nil
		case '\\':
			d.pos++
			if d.pos >= len(d.data) {
				return "", syntaxErr("unfinished escape sequence | 未完成的转义序列")
			}
			esc := d.data[d.pos]
			d.pos++
			switch esc {
			case '"', '\\', '/':
				b.WriteByte(esc)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, err := d.parseUnicodeEscape()
				if err != nil {
					return "", err
				}
				b.WriteRune(r)
			default:
				return "", syntaxErr("invalid escape character %q | 非法转义字符 %q", esc, esc)
			}
		default:
			if c < 0x20 {
				return "", syntaxErr("invalid control character in string | 字符串中包含非法控制字符")
			}
			if c < utf8.RuneSelf {
				end := scanUnescapedASCII(d.data, d.pos)
				b.Write(d.data[d.pos:end])
				d.pos = end
				continue
			}
			r, size := utf8.DecodeRune(d.data[d.pos:])
			if r == utf8.RuneError && size == 1 {
				b.WriteRune('�')
				d.pos++
				continue
			}
			b.Write(d.data[d.pos : d.pos+size])
			d.pos += size
		}
	}
	return "", syntaxErr("unexpected end of string | 字符串意外结束")
}

// parseKey parses an object key without copying when it has no escapes. | parseKey 解析对象键；
// 没有转义时不复制。该视图只在解码期间使用，不会存入结果。
func (d *decoder) parseKey() (string, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != '"' {
		return "", syntaxErr("expected string | 期望字符串")
	}
	start := d.pos + 1
	if end, slow, _ := scanStringBody(d.data, start); !slow {
		d.pos = end + 1
		return unsafe.String(unsafe.SliceData(d.data[start:end]), end-start), nil
	}
	return d.parseString()
}

// skipString validates one string token without allocating or decoding it. | skipString 在不分配、
// 不解码的前提下校验一个字符串 token。
func (d *decoder) skipString() error {
	if d.pos >= len(d.data) || d.data[d.pos] != '"' {
		return syntaxErr("expected string | 期望字符串")
	}
	start := d.pos + 1
	if end, slow, _ := scanStringBody(d.data, start); !slow {
		d.pos = end + 1
		return nil
	}
	i := start
	for i < len(d.data) {
		c := d.data[i]
		switch {
		case c == '"':
			d.pos = i + 1
			return nil
		case c == '\\':
			i++
			if i >= len(d.data) {
				return syntaxErr("unfinished escape sequence | 未完成的转义序列")
			}
			switch d.data[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if i+4 >= len(d.data) {
					return syntaxErr("unfinished unicode escape | 未完成的 Unicode 转义")
				}
				if _, ok := parseHex4(d.data[i+1 : i+5]); !ok {
					return syntaxErr("invalid unicode escape | 非法 Unicode 转义")
				}
				i += 4
			default:
				return syntaxErr("invalid escape character %q | 非法转义字符 %q", d.data[i], d.data[i])
			}
			i++
		case c < 0x20:
			return syntaxErr("invalid control character in string | 字符串中包含非法控制字符")
		default:
			i++
		}
	}
	return syntaxErr("unexpected end of string | 字符串意外结束")
}

// parseHex4 decodes exactly four hexadecimal digits. | parseHex4 解码恰好四位十六进制数字。
func parseHex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var v rune
	for i := 0; i < 4; i++ {
		c := b[i]
		var digit rune
		switch {
		case c >= '0' && c <= '9':
			digit = rune(c - '0')
		case c >= 'a' && c <= 'f':
			digit = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			digit = rune(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | digit
	}
	return v, true
}

func (d *decoder) parseUnicodeEscape() (rune, error) {
	if d.pos+4 > len(d.data) {
		return 0, syntaxErr("unfinished unicode escape | 未完成的 Unicode 转义")
	}
	v, ok := parseHex4(d.data[d.pos : d.pos+4])
	if !ok {
		return 0, syntaxErr("invalid unicode escape | 非法 Unicode 转义")
	}
	d.pos += 4
	r := v
	if r >= 0xD800 && r <= 0xDBFF {
		// A following low surrogate is consumed only when it forms a valid pair; otherwise it is
		// left for the next iteration so each invalid surrogate yields its own replacement rune,
		// exactly like encoding/json. | 仅当后续低代理项构成合法对时才消费；否则留给下一轮，
		// 使每个非法代理项各自产生一个替换符，与 encoding/json 完全一致。
		if d.pos+6 <= len(d.data) && d.data[d.pos] == '\\' && d.data[d.pos+1] == 'u' {
			if v2, ok2 := parseHex4(d.data[d.pos+2 : d.pos+6]); ok2 {
				r2 := v2
				if r2 >= 0xDC00 && r2 <= 0xDFFF {
					d.pos += 6
					return (r-0xD800)<<10 + (r2 - 0xDC00) + 0x10000, nil
				}
			}
		}
		return '�', nil
	}
	if r >= 0xDC00 && r <= 0xDFFF {
		return '�', nil
	}
	return r, nil
}

func (d *decoder) parseNumber() (string, error) {
	b, err := d.parseNumberBytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parseNumberBytes scans a JSON number and returns a view into the input. | parseNumberBytes 扫描
// JSON 数字并返回输入中的视图，不复制。
func (d *decoder) parseNumberBytes() ([]byte, error) {
	start := d.pos
	if d.pos < len(d.data) && d.data[d.pos] == '-' {
		d.pos++
	}
	digits := d.pos
	d.pos = scanDigits(d.data, d.pos)
	if d.pos == digits {
		return nil, syntaxErr("invalid number | 非法数字")
	}
	if d.data[digits] == '0' && d.pos-digits > 1 {
		return nil, syntaxErr("invalid leading zero | 非法前导零")
	}
	if d.pos < len(d.data) && d.data[d.pos] == '.' {
		d.pos++
		frac := d.pos
		d.pos = scanDigits(d.data, d.pos)
		if d.pos == frac {
			return nil, syntaxErr("invalid number fraction | 非法数字小数部分")
		}
	}
	if d.pos < len(d.data) && (d.data[d.pos] == 'e' || d.data[d.pos] == 'E') {
		d.pos++
		if d.pos < len(d.data) && (d.data[d.pos] == '+' || d.data[d.pos] == '-') {
			d.pos++
		}
		exp := d.pos
		d.pos = scanDigits(d.data, d.pos)
		if d.pos == exp {
			return nil, syntaxErr("invalid number exponent | 非法数字指数")
		}
	}
	return d.data[start:d.pos], nil
}

// bytesString returns a read-only string view of b without copying. | bytesString 返回 b 的只读字符串
// 视图，不复制。
func bytesString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func (d *decoder) captureValue() ([]byte, error) {
	view, err := d.captureValueView()
	if err != nil {
		return nil, err
	}
	raw := make([]byte, len(view))
	copy(raw, view)
	return raw, nil
}

// captureValueView returns the raw value as a view into the input. The caller must not retain it
// beyond the current call. | captureValueView 以输入视图返回原始值；调用方不得在本次调用之后保留它。
func (d *decoder) captureValueView() ([]byte, error) {
	start := d.pos
	if err := d.skipValue(); err != nil {
		return nil, err
	}
	return d.data[start:d.pos], nil
}

func (d *decoder) skipValue() error {
	d.skipSpace()
	if d.pos >= len(d.data) {
		return syntaxErr("unexpected end of JSON input | JSON 输入意外结束")
	}
	switch d.data[d.pos] {
	case 'n':
		return d.literal("null")
	case 't':
		return d.literal("true")
	case 'f':
		return d.literal("false")
	case '"':
		return d.skipString()
	case '{':
		if err := d.enter(); err != nil {
			return err
		}
		defer d.leave()
		d.pos++
		d.skipSpace()
		if d.pos < len(d.data) && d.data[d.pos] == '}' {
			d.pos++
			return nil
		}
		for {
			d.skipSpace()
			if err := d.skipString(); err != nil {
				return err
			}
			d.skipSpace()
			if d.pos >= len(d.data) || d.data[d.pos] != ':' {
				return syntaxErr("expected ':' | 期望 ':'")
			}
			d.pos++
			if err := d.skipValue(); err != nil {
				return err
			}
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of object | 对象意外结束")
			}
			if d.data[d.pos] == ',' {
				d.pos++
				continue
			}
			if d.data[d.pos] == '}' {
				d.pos++
				return nil
			}
			return syntaxErr("expected ',' or '}' | 期望 ',' 或 '}'")
		}
	case '[':
		if err := d.enter(); err != nil {
			return err
		}
		defer d.leave()
		d.pos++
		d.skipSpace()
		if d.pos < len(d.data) && d.data[d.pos] == ']' {
			d.pos++
			return nil
		}
		for {
			if err := d.skipValue(); err != nil {
				return err
			}
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of array | 数组意外结束")
			}
			if d.data[d.pos] == ',' {
				d.pos++
				continue
			}
			if d.data[d.pos] == ']' {
				d.pos++
				return nil
			}
			return syntaxErr("expected ',' or ']' | 期望 ',' 或 ']'")
		}
	default:
		_, err := d.parseNumber()
		return err
	}
}
