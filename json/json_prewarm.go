//go:build !jsonx_std

package json

import "reflect"

// prewarm builds the encoder plan for every sample type and the decoder plan for the type each
// pointer sample points to. | prewarm 为每个样本类型构建编码计划，并为每个指针样本所指向的
// 类型构建解码计划。
func prewarm(samples ...any) {
	encSeen := make(map[reflect.Type]bool)
	decSeen := make(map[reflect.Type]bool)
	for _, s := range samples {
		if s == nil {
			continue
		}
		t := reflect.TypeOf(s)
		warmEncode(t, encSeen)
		if t.Kind() == reflect.Pointer {
			warmDecode(t.Elem(), decSeen)
		}
	}
}

// warmEncode installs the encoder plan for t and recurses into the element, key, value and field
// types the encoder reads. | warmEncode 安装 t 的编码计划，并递归进入编码器会读取的元素、键、
// 值与字段类型。
func warmEncode(t reflect.Type, seen map[reflect.Type]bool) {
	if t == nil || seen[t] {
		return
	}
	seen[t] = true
	tr := cachedTraits(t)
	// Values implementing Marshaler or TextMarshaler encode through their method, so their
	// fields never reach the reflective encoder. | 实现 Marshaler 或 TextMarshaler 的值通过
	// 自身方法编码，字段不会进入反射编码器。
	if tr.marshaler || tr.textMarshaler {
		encoderFor(t)
		return
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		warmEncode(t.Elem(), seen)
	case reflect.Map:
		warmEncode(t.Key(), seen)
		warmEncode(t.Elem(), seen)
	case reflect.Struct:
		for _, f := range cachedStruct(t).fields {
			warmEncode(f.typ, seen)
		}
	}
	encoderFor(t)
	if t.Kind() == reflect.Struct {
		// fastStructFor builds the direct-memory plan and stores it when every field qualifies. |
		// fastStructFor 构建按内存直接编码的计划，并在所有字段都满足条件时存入缓存。
		fastStructFor(t)
	}
}

// warmDecode installs the decoder plan for t and recurses into the element, key, value and field
// types the decoder reads. | warmDecode 安装 t 的解码计划，并递归进入解码器会读取的元素、键、
// 值与字段类型。
func warmDecode(t reflect.Type, seen map[reflect.Type]bool) {
	if t == nil || seen[t] {
		return
	}
	seen[t] = true
	tr := cachedTraits(t)
	// Unmarshaler and TextUnmarshaler always take precedence, so no field decoder is ever
	// resolved for these types. | Unmarshaler 与 TextUnmarshaler 始终优先，这些类型不会解析
	// 任何字段解码器。
	if tr.unmarshaler || tr.textUnmarshaler {
		decoderFor(t)
		return
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		warmDecode(t.Elem(), seen)
	case reflect.Map:
		warmDecode(t.Key(), seen)
		warmDecode(t.Elem(), seen)
	case reflect.Struct:
		// Struct field decoders are resolved lazily, so a parent plan alone does not build the
		// nested plans; walking the fields installs them before the first request. | 结构体字段
		// 解码器延迟解析，因此只构建父计划不会建立嵌套计划；遍历字段可在首个请求前安装它们。
		for _, f := range cachedStruct(t).fields {
			warmDecode(f.typ, seen)
		}
	}
	decoderFor(t)
	if t.Kind() == reflect.Struct {
		fastStructDecFor(t)
	}
}
