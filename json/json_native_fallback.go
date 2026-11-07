//go:build !jsonx_std

package json

import (
	"bytes"
	"encoding/json/jsontext"
	"reflect"
	"sort"
)

// encodeFallback emits the members of an embedded fallback field after the regular struct
// fields. A string-keyed map contributes one member per entry; a jsontext.Value contributes the
// members of its raw JSON object. Duplicate names are rejected under v2's default options. |
// encodeFallback 在常规结构体字段之后输出嵌入回退字段的成员。字符串键 map 每个条目贡献一个成员；
// jsontext.Value 贡献其原始 JSON 对象的成员。v2 默认选项下重复名会被拒绝。
func (e *encoder) encodeFallback(fb *fieldInfo, v reflect.Value, names map[string]struct{}, first *bool) error {
	if fb.index == nil {
		return nil
	}
	fv, ok := fieldByIndex(v, fb.index)
	if !ok {
		return nil
	}
	if fb.typ == rawMessageType || (fb.typ.Kind() == reflect.Slice && fb.typ.Elem().Kind() == reflect.Uint8) {
		return e.encodeFallbackValue(fb, fv.Bytes(), names, first)
	}
	if fb.typ.Kind() != reflect.Map || fb.typ.Key().Kind() != reflect.String {
		return nil
	}
	if fv.IsNil() {
		return nil
	}
	type entry struct {
		key string
		val reflect.Value
	}
	entries := make([]entry, 0, fv.Len())
	iter := fv.MapRange()
	for iter.Next() {
		key := iter.Key().String()
		if _, dup := names[key]; dup && e.strictOutputNames() {
			return newDuplicateNameError(0, jsontext.Pointer("/"+escapePointerToken(key)))
		}
		entries = append(entries, entry{key: key, val: iter.Value()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	enc := encoderFor(fb.typ.Elem())
	for _, ent := range entries {
		if !*first {
			e.buf = append(e.buf, ',')
		}
		*first = false
		e.str(ent.key)
		e.buf = append(e.buf, ':')
		if e.v2 != nil && len(e.v2.marshalers) > 0 {
			if err := e.elemValue(ent.val); err != nil {
				return err
			}
		} else if err := enc(e, ent.val); err != nil {
			return err
		}
	}
	return nil
}

// strictOutputNames reports whether duplicate object names must be rejected. |
// strictOutputNames 报告是否必须拒绝重复对象名。
func (e *encoder) strictOutputNames() bool {
	return e.v2 != nil && !e.v2.allowDuplicateNames
}

// encodeFallbackValue merges the members of a raw JSON object into the current struct object. |
// encodeFallbackValue 把原始 JSON 对象的成员并入当前结构体对象。
func (e *encoder) encodeFallbackValue(fb *fieldInfo, raw []byte, names map[string]struct{}, first *bool) error {
	if len(raw) == 0 {
		return nil
	}
	var compact []byte
	var err error
	if e.v2 != nil {
		compact, err = appendV2Raw(nil, raw, e.v2)
	} else {
		compact, err = appendCompactJSONMode(nil, raw, e.escapeHTML, true)
	}
	if err != nil {
		return err
	}
	compact = bytes.TrimSpace(compact)
	if len(compact) == 0 || bytes.Equal(compact, []byte("null")) || bytes.Equal(compact, []byte("{}")) {
		return nil
	}
	if compact[0] != '{' || compact[len(compact)-1] != '}' {
		return newMarshalSemanticError(fb.typ, "embedded fallback must be a JSON object")
	}
	if err := e.checkFallbackValueNames(compact, names); err != nil {
		return err
	}
	body := compact[1 : len(compact)-1]
	if len(body) == 0 {
		return nil
	}
	if !*first {
		e.buf = append(e.buf, ',')
	}
	e.buf = append(e.buf, body...)
	*first = false
	return nil
}

// checkFallbackValueNames scans the top-level member names of a raw JSON object and rejects names
// that a regular field already emits. | checkFallbackValueNames 扫描原始 JSON 对象的顶层成员名，
// 拒绝常规字段已输出的名字。
func (e *encoder) checkFallbackValueNames(raw []byte, names map[string]struct{}) error {
	if !e.strictOutputNames() {
		return nil
	}
	d := &decoder{data: raw}
	d.pos = 1 // after '{'
	d.skipSpace()
	for d.pos < len(raw) && d.data[d.pos] != '}' {
		key, err := d.parseKey()
		if err != nil {
			return err
		}
		if _, dup := names[key]; dup {
			return newDuplicateNameError(0, jsontext.Pointer("/"+escapePointerToken(key)))
		}
		d.skipSpace()
		if d.pos >= len(raw) || d.data[d.pos] != ':' {
			return syntaxErr("expected ':' | 期望 ':'")
		}
		d.pos++
		if err := d.skipValue(); err != nil {
			return err
		}
		d.skipSpace()
		if d.pos < len(raw) && d.data[d.pos] == ',' {
			d.pos++
			d.skipSpace()
		}
	}
	return nil
}

// decodeFallbackMap decodes one unknown object member into an embedded map fallback. |
// decodeFallbackMap 把一个未知对象成员解码进嵌入 map 回退。
func (d *decoder) decodeFallbackMap(fb *fieldInfo, v reflect.Value, key string) error {
	fv, ok, err := fieldByIndexAlloc(v, fb.index)
	if err != nil {
		return err
	}
	if !ok {
		return d.skipValue()
	}
	if fv.IsNil() {
		fv.Set(reflect.MakeMap(fb.typ))
	}
	elem := reflect.New(fb.typ.Elem()).Elem()
	d.skipSpace()
	if err := d.value(elem); err != nil {
		return err
	}
	mapKey := reflect.New(fb.typ.Key()).Elem()
	mapKey.SetString(key)
	fv.SetMapIndex(mapKey, elem)
	return nil
}

// setFallbackValue stores accumulated unknown members in an embedded jsontext.Value fallback. |
// setFallbackValue 把累积的未知成员存入嵌入 jsontext.Value 回退。
func (d *decoder) setFallbackValue(fb *fieldInfo, v reflect.Value, members []byte) {
	if len(members) == 0 {
		return
	}
	fv, ok, err := fieldByIndexAlloc(v, fb.index)
	if err != nil || !ok {
		return
	}
	buf := make([]byte, 0, len(members)+2)
	buf = append(buf, '{')
	buf = append(buf, members...)
	buf = append(buf, '}')
	fv.SetBytes(buf)
}
