//go:build !jsonx_std

package json

import (
	"bytes"
	"encoding/json/jsontext"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf8"
)

// appendV2Raw parses one raw JSON value and re-emits it according to the v2 syntactic options.
// The semantic layer of encoding/json/v2 rewrites strings and, when requested, canonicalizes
// numbers and reorders object members; Marshaler and jsontext.Value output must follow the same
// rules. | appendV2Raw 解析一个原始 JSON 值并按 v2 语法选项重新输出。encoding/json/v2 的语义层会
// 重写字符串，并在要求时规范化数字、重排对象成员；Marshaler 与 jsontext.Value 的输出必须遵循
// 相同规则。
func appendV2Raw(dst, src []byte, cfg *v2Config) ([]byte, error) {
	d := &decoder{data: src, v2: cfg}
	d.skipSpace()
	out, err := appendV2Value(dst, d, cfg)
	if err != nil {
		return dst, err
	}
	d.skipSpace()
	if d.pos != len(src) {
		return dst, syntaxErr("invalid character %q after top-level value | 顶层值之后的非法字符 %q", src[d.pos], src[d.pos])
	}
	return out, nil
}

// appendV2Value re-emits one value from d. | appendV2Value 从 d 重新输出一个值。
func appendV2Value(dst []byte, d *decoder, cfg *v2Config) ([]byte, error) {
	d.skipSpace()
	if d.pos >= len(d.data) {
		return dst, syntaxErr("unexpected end of JSON input | JSON 输入意外结束")
	}
	switch d.data[d.pos] {
	case '"':
		s, err := d.parseString()
		if err != nil {
			return dst, err
		}
		return appendJSONStringMode(dst, s, cfg.escapeHTML, cfg.escapeJS), nil
	case '{':
		return appendV2Object(dst, d, cfg, false)
	case '[':
		return appendV2Array(dst, d, cfg)
	case 'n':
		return append(dst, "null"...), d.literal("null")
	case 't':
		return append(dst, "true"...), d.literal("true")
	case 'f':
		return append(dst, "false"...), d.literal("false")
	default:
		raw, err := d.parseNumberBytes()
		if err != nil {
			return dst, err
		}
		return appendV2Number(dst, raw, cfg), nil
	}
}

// appendV2Number re-emits one number literal, optionally canonicalized. |
// appendV2Number 重新输出一个数字字面量，可选择规范化。
func appendV2Number(dst, raw []byte, cfg *v2Config) []byte {
	integer := true
	for _, c := range raw {
		if c == '.' || c == 'e' || c == 'E' {
			integer = false
			break
		}
	}
	if integer && cfg.canonicalizeRawInts {
		if n, err := strconv.ParseInt(bytesString(raw), 10, 64); err == nil {
			return strconv.AppendInt(dst, n, 10)
		}
		if n, err := strconv.ParseUint(bytesString(raw), 10, 64); err == nil {
			return strconv.AppendUint(dst, n, 10)
		}
		return append(dst, raw...)
	}
	if !integer && cfg.canonicalizeRawFloats {
		if f, err := strconv.ParseFloat(bytesString(raw), 64); err == nil {
			if out, ferr := appendFloat(dst, f, 64); ferr == nil {
				return out
			}
		}
	}
	return append(dst, raw...)
}

// appendV2Object re-emits an object, checking duplicate names and optionally reordering members. |
// appendV2Object 重新输出对象，检查重复名并可选择重排成员。
func appendV2Object(dst []byte, d *decoder, cfg *v2Config, _ bool) ([]byte, error) {
	if err := d.enter(); err != nil {
		return dst, err
	}
	defer d.leave()
	type member struct {
		name string
		raw  []byte
	}
	var members []member
	seen := make(map[string]struct{}, 8)
	d.pos++
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == '}' {
		d.pos++
		return append(dst, "{}"...), nil
	}
	if !cfg.reorderRawObjects {
		dst = append(dst, '{')
	}
	first := true
	for {
		d.skipSpace()
		if d.pos >= len(d.data) || d.data[d.pos] != '"' {
			return dst, syntaxErr("expected object key | 期望对象键")
		}
		name, err := d.parseString()
		if err != nil {
			return dst, err
		}
		if !cfg.allowDuplicateNames {
			if _, dup := seen[name]; dup {
				return dst, d.duplicateName(name)
			}
			seen[name] = struct{}{}
		}
		d.skipSpace()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return dst, syntaxErr("expected ':' after object key | 对象键之后期望 ':'")
		}
		d.pos++
		if cfg.reorderRawObjects {
			val, verr := appendV2Value(nil, d, cfg)
			if verr != nil {
				return dst, verr
			}
			members = append(members, member{name: name, raw: val})
		} else {
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = appendJSONStringMode(dst, name, cfg.escapeHTML, cfg.escapeJS)
			dst = append(dst, ':')
			dst, err = appendV2Value(dst, d, cfg)
			if err != nil {
				return dst, err
			}
		}
		d.skipSpace()
		if d.pos >= len(d.data) {
			return dst, syntaxErr("unexpected end of object | 对象意外结束")
		}
		if d.data[d.pos] == ',' {
			d.pos++
			continue
		}
		if d.data[d.pos] == '}' {
			d.pos++
			break
		}
		return dst, syntaxErr("expected ',' or '}' | 期望 ',' 或 '}'")
	}
	if !cfg.reorderRawObjects {
		return append(dst, '}'), nil
	}
	sort.SliceStable(members, func(i, j int) bool { return members[i].name < members[j].name })
	dst = append(dst, '{')
	for i, m := range members {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONStringMode(dst, m.name, cfg.escapeHTML, cfg.escapeJS)
		dst = append(dst, ':')
		dst = append(dst, m.raw...)
	}
	return append(dst, '}'), nil
}

// appendV2Array re-emits an array. | appendV2Array 重新输出数组。
func appendV2Array(dst []byte, d *decoder, cfg *v2Config) ([]byte, error) {
	if err := d.enter(); err != nil {
		return dst, err
	}
	defer d.leave()
	d.pos++
	dst = append(dst, '[')
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		return append(dst, ']'), nil
	}
	for first := true; ; first = false {
		if !first {
			dst = append(dst, ',')
		}
		var err error
		dst, err = appendV2Value(dst, d, cfg)
		if err != nil {
			return dst, err
		}
		d.skipSpace()
		if d.pos >= len(d.data) {
			return dst, syntaxErr("unexpected end of array | 数组意外结束")
		}
		if d.data[d.pos] == ',' {
			d.pos++
			continue
		}
		if d.data[d.pos] == ']' {
			d.pos++
			return append(dst, ']'), nil
		}
		return dst, syntaxErr("expected ',' or ']' | 期望 ',' 或 ']'")
	}
}

// marshalerFor returns the first type-specific marshal function registered for t. |
// marshalerFor 返回为 t 注册的第一个类型专用编码函数。
func (c *v2Config) marshalerFor(t reflect.Type) *marshalerEntry {
	for i := range c.marshalers {
		if c.marshalers[i].typ == t {
			return &c.marshalers[i]
		}
	}
	return nil
}

// unmarshalerFor returns the first type-specific unmarshal function registered for t. |
// unmarshalerFor 返回为 t 注册的第一个类型专用解码函数。
func (c *v2Config) unmarshalerFor(t reflect.Type) *unmarshalerEntry {
	for i := range c.unmarshalers {
		if c.unmarshalers[i].typ == t {
			return &c.unmarshalers[i]
		}
	}
	return nil
}

// applyMarshaler executes one type-specific marshal function and validates its output. |
// applyMarshaler 执行一个类型专用编码函数并校验其输出。
// marshalTarget resolves a type-specific marshal function for v. A function written for *T
// applies to an addressable T as well, matching the standard library's dispatch. |
// marshalTarget 为 v 解析类型专用编码函数。为 *T 编写的函数同样适用于可寻址的 T，与标准库分派
// 一致。
func (e *encoder) marshalTarget(v reflect.Value) (*marshalerEntry, reflect.Value) {
	if m := e.v2.marshalerFor(v.Type()); m != nil {
		return m, v
	}
	if v.CanAddr() {
		if m := e.v2.marshalerFor(reflect.PointerTo(v.Type())); m != nil {
			return m, v.Addr()
		}
	}
	return nil, v
}

func (e *encoder) applyMarshaler(m *marshalerEntry, v reflect.Value) error {
	var data []byte
	var err error
	if m.marshal != nil {
		data, err = m.marshal(v)
	} else {
		var buf bytes.Buffer
		enc := jsontext.NewEncoder(&buf, e.v2.opts)
		if err = m.to(enc, v); err == nil {
			data = buf.Bytes()
		}
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		encodeNull(e)
		return nil
	}
	if e.v2 != nil && !e.v2.allowInvalidUTF8 && !utf8.Valid(data) {
		return newMarshalInvalidUTF8Error()
	}
	if e.v2 != nil {
		e.buf, err = appendV2Raw(e.buf, data, e.v2)
	} else {
		e.buf, err = appendCompactJSONMode(e.buf, data, e.escapeHTML, true)
	}
	return err
}

// v2DisallowsFastStruct reports whether the resolved options need per-field decisions that the
// branch-free fast struct plan cannot make. | v2DisallowsFastStruct 报告解析后的选项是否需要
// 无分支快速结构体计划无法做出的逐字段判定。
func (e *encoder) v2DisallowsFastStruct() bool {
	c := e.v2
	return c != nil && (c.omitZeroStructFields || c.stringifyNumbers || len(c.marshalers) > 0)
}

// v2FastFieldDisallowed reports whether a per-field direct-memory encoder must be bypassed. |
// v2FastFieldDisallowed 报告是否必须绕过逐字段直接按内存编码器。
func (e *encoder) v2FastFieldDisallowed() bool {
	c := e.v2
	return c != nil && (c.stringifyNumbers || len(c.marshalers) > 0)
}

// elemValue encodes one container element, honoring type-specific marshal functions. |
// elemValue 编码一个容器元素，并遵循类型专用编码函数。
func (e *encoder) elemValue(v reflect.Value) error {
	if e.v2 != nil && len(e.v2.marshalers) > 0 {
		return e.value(v)
	}
	return encoderFor(v.Type())(e, v)
}

// emptyV2 reports whether v would encode as a JSON null, empty string, empty object or empty
// array, which is the v2 definition of "empty" used by the omitempty option. |
// emptyV2 报告 v 是否会编码为 JSON null、空字符串、空对象或空数组，即 v2 中 omitempty 使用的
// “空”定义。
func emptyV2(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return true
		}
		return emptyV2(v.Elem())
	case reflect.String, reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.Array:
		return v.Len() == 0
	case reflect.Struct:
		return structEncodesEmpty(v)
	}
	return false
}

// structEncodesEmpty reports whether every field of the struct is omitted, so the struct would
// encode as an empty JSON object. | structEncodesEmpty 报告结构体的所有字段都被省略，从而编码为
// 空 JSON 对象。
func structEncodesEmpty(v reflect.Value) bool {
	fields := cachedStruct(v.Type()).fields
	for i := range fields {
		f := &fields[i]
		fv, ok := fieldByIndex(v, f.index)
		if !ok {
			continue
		}
		if f.omitEmpty && emptyV2(fv) {
			continue
		}
		if f.omitZero {
			if f.isZero == nil {
				if fv.IsZero() {
					continue
				}
			} else if f.isZero(fv) {
				continue
			}
		}
		return false
	}
	return true
}
