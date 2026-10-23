//go:build !jsonx_std

package json

import (
	"encoding"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

func buildKindDecoder(t reflect.Type) decodeFunc {
	switch t.Kind() {
	case reflect.Bool:
		return func(d *decoder, v reflect.Value) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			x, err := d.parseBool()
			if err != nil {
				return err
			}
			v.SetBool(x)
			return nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bits := t.Bits()
		return func(d *decoder, v reflect.Value) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			if d.data[d.pos] == '"' {
				return typeErr("cannot unmarshal string into %s | 无法把字符串解析进 %s", t, t)
			}
			b, err := d.parseNumberBytes()
			if err != nil {
				return err
			}
			s := bytesString(b)
			if strings.ContainsAny(s, ".eE") {
				return typeErr("cannot unmarshal number %s into %s | 无法把数字 %s 解析进 %s", s, t, s, t)
			}
			n, err := strconv.ParseInt(s, 10, bits)
			if err != nil {
				return typeErr("number %s overflows %s | 数字 %s 超出 %s", s, t, s, t)
			}
			v.SetInt(n)
			return nil
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		bits := t.Bits()
		return func(d *decoder, v reflect.Value) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			if d.data[d.pos] == '"' {
				return typeErr("cannot unmarshal string into %s | 无法把字符串解析进 %s", t, t)
			}
			b, err := d.parseNumberBytes()
			if err != nil {
				return err
			}
			s := bytesString(b)
			if strings.ContainsAny(s, ".eE-") {
				return typeErr("cannot unmarshal number %s into %s | 无法把数字 %s 解析进 %s", s, t, s, t)
			}
			n, err := strconv.ParseUint(s, 10, bits)
			if err != nil {
				return typeErr("number %s overflows %s | 数字 %s 超出 %s", s, t, s, t)
			}
			v.SetUint(n)
			return nil
		}
	case reflect.Float32, reflect.Float64:
		bits := t.Bits()
		return func(d *decoder, v reflect.Value) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			b, err := d.parseNumberBytes()
			if err != nil {
				return err
			}
			s := bytesString(b)
			n, err := strconv.ParseFloat(s, bits)
			if err != nil {
				return typeErr("number %s overflows %s | 数字 %s 超出 %s", s, t, s, t)
			}
			v.SetFloat(n)
			return nil
		}
	case reflect.String:
		return func(d *decoder, v reflect.Value) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			if d.data[d.pos] != '"' {
				return typeErr("cannot unmarshal non-string into %s | 无法把非字符串解析进 %s", t, t)
			}
			s, err := d.parseString()
			if err != nil {
				return err
			}
			v.SetString(s)
			return nil
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return func(d *decoder, v reflect.Value) error {
				if d.data[d.pos] == 'n' {
					if err := d.literal("null"); err != nil {
						return err
					}
					v.SetZero()
					return nil
				}
				if d.data[d.pos] != '"' {
					return typeErr("cannot unmarshal non-string into %s | 无法把非字符串解析进 %s", t, t)
				}
				s, err := d.parseString()
				if err != nil {
					return err
				}
				out, err := base64.StdEncoding.DecodeString(s)
				if err != nil {
					return errs.Wrap(err, ErrTypeMismatch)
				}
				v.SetBytes(out)
				return nil
			}
		}
		return buildSliceDecoder(t)
	case reflect.Array:
		return buildArrayDecoder(t)
	case reflect.Map:
		return buildMapDecoder(t)
	case reflect.Struct:
		return buildStructDecoder(t)
	default:
		return func(d *decoder, v reflect.Value) error {
			return typeErr("cannot unmarshal into %s | 无法解析进 %s", t, t)
		}
	}
}

func buildSliceDecoder(t reflect.Type) decodeFunc {
	elem := lazyDecoder(t.Elem())
	if info := fastStructDecFor(t.Elem()); info != nil {
		var pool sync.Pool
		pool.New = func() any {
			return &structBufHolder{slice: reflect.MakeSlice(t, 0, 64)}
		}
		return func(d *decoder, v reflect.Value) error {
			if v.CanAddr() {
				if v.IsNil() {
					return decodeFastStructSlicePooled(d, v, t, info, &pool)
				}
				return decodeFastStructSlice(d, v, t, info)
			}
			return decodeSlice(d, v, t, elem)
		}
	}
	return func(d *decoder, v reflect.Value) error {
		return decodeSlice(d, v, t, elem)
	}
}

// structBufHolder is a pooled scratch slice whose length is changed through its own header, so no
// reflect.Value slice header is allocated per element or per call. | structBufHolder 是池化的暂存
// 切片，长度经自身头部调整，因此不会按元素或按调用分配 reflect.Value 切片头。
type structBufHolder struct {
	hdr   unsafeSliceHeader
	slice reflect.Value
}

// reset prepares the holder for a decode, seeding the header from the typed backing slice on first
// use. | reset 为一次解码准备持有者，首次使用时用带类型的后备切片填充头部。
func (b *structBufHolder) reset() {
	if b.hdr.data == nil {
		b.hdr.data = b.slice.UnsafePointer()
		b.hdr.cap = b.slice.Cap()
	}
	b.hdr.len = 0
}

// value returns an addressable []T view over the holder's header. | value 返回持有者头部上的可寻址
// []T 视图。
func (b *structBufHolder) value(t reflect.Type) reflect.Value {
	return reflect.NewAt(t, unsafe.Pointer(&b.hdr)).Elem()
}

// failStructBuf copies the decoded prefix into v, clears the scratch buffer, returns its holder to
// the pool, and returns err. | failStructBuf 把已解码前缀复制进 v，清空暂存缓冲、归还其持有者并
// 返回 err。
func failStructBuf(v reflect.Value, t reflect.Type, pool *sync.Pool, b *structBufHolder, count int, err error) error {
	if count == 0 {
		v.Set(reflect.MakeSlice(t, 0, 0))
	} else {
		b.hdr.len = count
		src := b.value(t)
		v.Grow(count)
		v.SetLen(count)
		reflect.Copy(v, src)
		src.Clear()
	}
	b.hdr.len = 0
	pool.Put(b)
	return err
}

// decodeFastStructSlicePooled decodes into a reusable scratch buffer and allocates the destination
// exactly once at the end, so the result has no excess capacity and the per-call allocation count
// matches its true size. | decodeFastStructSlicePooled 解码到可复用暂存缓冲，结束时只分配一次精确
// 大小的目标切片，使结果没有多余容量、每次分配次数与真实大小一致。
func decodeFastStructSlicePooled(d *decoder, v reflect.Value, t reflect.Type, info *fastStructDecInfo, pool *sync.Pool) error {
	b := pool.Get().(*structBufHolder)
	b.reset()
	if b.hdr.cap < 4 {
		b.slice = reflect.MakeSlice(t, 4, 4)
		b.hdr = unsafeSliceHeader{data: b.slice.UnsafePointer(), cap: 4}
	}
	if d.data[d.pos] == 'n' {
		if err := d.literal("null"); err != nil {
			pool.Put(b)
			return err
		}
		v.SetZero()
		pool.Put(b)
		return nil
	}
	if err := d.enter(); err != nil {
		pool.Put(b)
		return err
	}
	if d.data[d.pos] != '[' {
		pool.Put(b)
		return typeErr("cannot unmarshal non-array into %s | 无法把非数组解析进 %s", t, t)
	}
	d.skipLen = false
	d.pos++
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		v.Set(reflect.MakeSlice(t, 0, 0))
		pool.Put(b)
		d.leave()
		return nil
	}
	elemSize := info.size
	data := b.hdr.data
	capacity := b.hdr.cap
	n := 0
	started := false
	for {
		if n == capacity {
			newCap := capacity * 2
			if newCap < 4 {
				newCap = 4
			}
			if newCap <= capacity {
				newCap = n + 1
			}
			nv := reflect.MakeSlice(t, newCap, newCap)
			b.hdr.len = n
			reflect.Copy(nv, b.value(t))
			b.slice = nv
			b.hdr = unsafeSliceHeader{data: nv.UnsafePointer(), cap: newCap}
			data = b.hdr.data
			capacity = newCap
		}
		if d.pos >= len(d.data) {
			return failStructBuf(v, t, pool, b, n, syntaxErr("unexpected end of array | 数组意外结束"))
		}
		started = true
		if err := info.dec(d, unsafe.Add(data, uintptr(n)*elemSize)); err != nil {
			return failStructBuf(v, t, pool, b, n+1, err)
		}
		started = false
		n++
		if d.pos < len(d.data) {
			switch d.data[d.pos] {
			case ',':
				d.pos++
				d.skipSpace()
				continue
			case ']':
				d.pos++
				b.hdr.len = n
				src := b.value(t)
				v.Grow(n)
				v.SetLen(n)
				reflect.Copy(v, src)
				src.Clear()
				b.hdr.len = 0
				pool.Put(b)
				d.leave()
				return nil
			}
		}
		d.skipSpace()
		if d.pos >= len(d.data) {
			count := n
			if started {
				count++
			}
			return failStructBuf(v, t, pool, b, count, syntaxErr("unexpected end of array | 数组意外结束"))
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipSpace()
		case ']':
			d.pos++
			b.hdr.len = n
			src := b.value(t)
			v.Grow(n)
			v.SetLen(n)
			reflect.Copy(v, src)
			src.Clear()
			b.hdr.len = 0
			pool.Put(b)
			d.leave()
			return nil
		default:
			count := n
			if started {
				count++
			}
			return failStructBuf(v, t, pool, b, count, syntaxErr("expected ',' or ']' in array | 数组中期望 ',' 或 ']'"))
		}
	}
}

// decodeSlice is the reflection-based array decoder used for every element type without a direct
// memory decoder. | decodeSlice 是用于所有没有直接按内存解码器的元素类型的基于反射的数组解码器。
func decodeSlice(d *decoder, v reflect.Value, t reflect.Type, elem func() decodeFunc) error {
	if d.data[d.pos] == 'n' {
		if err := d.literal("null"); err != nil {
			return err
		}
		v.SetZero()
		return nil
	}
	if err := d.enter(); err != nil {
		return err
	}
	defer d.leave()
	if d.data[d.pos] != '[' {
		return typeErr("cannot unmarshal non-array into %s | 无法把非数组解析进 %s", t, t)
	}
	enc := elem()
	n := -1
	if d.skipLen {
		d.skipLen = false
		n = v.Len()
	}
	d.pos++
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		if v.IsNil() {
			v.Set(reflect.MakeSlice(t, 0, 0))
		} else {
			v.SetLen(0)
		}
		return nil
	}
	if n >= 0 {
		if v.IsNil() || v.Cap() < n {
			v.Set(reflect.MakeSlice(t, n, n))
		} else {
			v.SetLen(n)
		}
	} else if v.IsNil() {
		v.Set(reflect.MakeSlice(t, 0, 4))
	} else {
		v.SetLen(0)
	}
	i := 0
	for {
		if i >= v.Len() {
			v.Grow(1)
			v.SetLen(i + 1)
		}
		if d.pos >= len(d.data) {
			return syntaxErr("unexpected end of array | 数组意外结束")
		}
		if err := enc(d, v.Index(i)); err != nil {
			return err
		}
		i++
		if d.pos < len(d.data) {
			switch d.data[d.pos] {
			case ',':
				d.pos++
				d.skipSpace()
				continue
			case ']':
				d.pos++
				if i < v.Len() {
					v.SetLen(i)
				}
				return nil
			}
		}
		d.skipSpace()
		if d.pos >= len(d.data) {
			return syntaxErr("unexpected end of array | 数组意外结束")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipSpace()
		case ']':
			d.pos++
			if i < v.Len() {
				v.SetLen(i)
			}
			return nil
		default:
			return syntaxErr("expected ',' or ']' in array | 数组中期望 ',' 或 ']'")
		}
	}
}

// unsafeSliceHeader mirrors the runtime representation of a slice header. |
// unsafeSliceHeader 对应切片的运行时头部表示。
type unsafeSliceHeader struct {
	data unsafe.Pointer
	len  int
	cap  int
}

// decodeFastStructSlice decodes a []struct whose element type has a direct-memory decoder. It
// grows the destination geometrically with typed allocations and advances the slice header
// directly, so each element costs one decoder call instead of reflect.Index, reflect.Grow,
// reflect.SetLen and a decoder lookup. | decodeFastStructSlice 解码元素类型具有直接按内存解码器的
// []struct：以带类型的分配按几何级数扩容，并直接推进切片头，因此每个元素只需一次解码器调用，
// 而不必执行 reflect.Index、reflect.Grow、reflect.SetLen 与解码器查找。
func decodeFastStructSlice(d *decoder, v reflect.Value, t reflect.Type, info *fastStructDecInfo) error {
	if d.data[d.pos] == 'n' {
		if err := d.literal("null"); err != nil {
			return err
		}
		v.SetZero()
		return nil
	}
	if err := d.enter(); err != nil {
		return err
	}
	if d.data[d.pos] != '[' {
		return typeErr("cannot unmarshal non-array into %s | 无法把非数组解析进 %s", t, t)
	}
	// The preallocated length chosen by Unmarshal is only a capacity hint here. | Unmarshal 预留的
	// 长度在这里只作为容量提示。
	d.skipLen = false
	d.pos++
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		if v.IsNil() {
			v.Set(reflect.MakeSlice(t, 0, 0))
		} else {
			v.SetLen(0)
		}
		d.leave()
		return nil
	}
	if v.IsNil() {
		v.Set(reflect.MakeSlice(t, 4, 4))
	}
	sh := (*unsafeSliceHeader)(unsafe.Pointer(v.UnsafeAddr()))
	sh.len = 0
	elemSize := info.size
	i := 0
	for {
		if i == sh.cap {
			newCap := sh.cap * 2
			if newCap < 4 {
				newCap = 4
			}
			if newCap <= sh.cap {
				newCap = i + 1
			}
			nv := reflect.MakeSlice(t, newCap, newCap)
			reflect.Copy(nv, v)
			v.Set(nv)
			sh = (*unsafeSliceHeader)(unsafe.Pointer(v.UnsafeAddr()))
			sh.len = i
		}
		if d.pos >= len(d.data) {
			return syntaxErr("unexpected end of array | 数组意外结束")
		}
		// Publish the element before decoding it so a decode error leaves the same partial
		// slice the reflection path leaves. | 解码前先发布元素长度，使解码错误留下与反射路径
		// 相同的部分切片。
		sh.len = i + 1
		if err := info.dec(d, unsafe.Add(sh.data, uintptr(i)*elemSize)); err != nil {
			return err
		}
		i++
		if d.pos < len(d.data) {
			switch d.data[d.pos] {
			case ',':
				d.pos++
				d.skipSpace()
				continue
			case ']':
				d.pos++
				d.leave()
				return nil
			}
		}
		d.skipSpace()
		if d.pos >= len(d.data) {
			return syntaxErr("unexpected end of array | 数组意外结束")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipSpace()
		case ']':
			d.pos++
			d.leave()
			return nil
		default:
			return syntaxErr("expected ',' or ']' in array | 数组中期望 ',' 或 ']'")
		}
	}
}

func buildArrayDecoder(t reflect.Type) decodeFunc {
	elem := lazyDecoder(t.Elem())
	return func(d *decoder, v reflect.Value) error {
		if d.data[d.pos] == 'n' {
			return d.literal("null")
		}
		if err := d.enter(); err != nil {
			return err
		}
		defer d.leave()
		if d.data[d.pos] != '[' {
			return typeErr("cannot unmarshal non-array into %s | 无法把非数组解析进 %s", t, t)
		}
		enc := elem()
		d.pos++
		d.skipSpace()
		if d.pos < len(d.data) && d.data[d.pos] == ']' {
			d.pos++
			return nil
		}
		i := 0
		for {
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of array | 数组意外结束")
			}
			if i < v.Len() {
				if err := enc(d, v.Index(i)); err != nil {
					return err
				}
			} else if err := d.skipValue(); err != nil {
				return err
			}
			i++
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of array | 数组意外结束")
			}
			switch d.data[d.pos] {
			case ',':
				d.pos++
			case ']':
				d.pos++
				return nil
			default:
				return syntaxErr("expected ',' or ']' in array | 数组中期望 ',' 或 ']'")
			}
		}
	}
}

// mapKeySetter returns a function that converts one JSON object key to a map key, mirroring
// encoding/json: string keys (honouring encoding.TextUnmarshaler) and every integer kind.
// | mapKeySetter 返回把 JSON 对象键转换为 map 键的函数，语义对齐 encoding/json：字符串键
// （支持 encoding.TextUnmarshaler）与全部整数种类。
func mapKeySetter(keyType reflect.Type) (func(string, reflect.Value) error, bool) {
	textUnmarshaler := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	switch {
	case keyType.Implements(textUnmarshaler):
		return func(key string, v reflect.Value) error {
			if err := v.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(key)); err != nil {
				return typeErr("cannot unmarshal object key %[1]q into %[2]s: %[3]v | 无法把对象键 %[1]q 解析进 %[2]s：%[3]v", key, keyType, err)
			}
			return nil
		}, true
	case reflect.PointerTo(keyType).Implements(textUnmarshaler):
		return func(key string, v reflect.Value) error {
			ptr := reflect.New(keyType)
			if err := ptr.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(key)); err != nil {
				return typeErr("cannot unmarshal object key %[1]q into %[2]s: %[3]v | 无法把对象键 %[1]q 解析进 %[2]s：%[3]v", key, keyType, err)
			}
			v.Set(ptr.Elem())
			return nil
		}, true
	}
	switch keyType.Kind() {
	case reflect.String:
		return func(key string, v reflect.Value) error { v.SetString(key); return nil }, true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bits := keyType.Bits()
		return func(key string, v reflect.Value) error {
			n, err := strconv.ParseInt(key, 10, bits)
			if err != nil {
				return typeErr("cannot unmarshal object key %q into %s | 无法把对象键 %q 解析进 %s", key, keyType, key, keyType)
			}
			v.SetInt(n)
			return nil
		}, true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		bits := keyType.Bits()
		return func(key string, v reflect.Value) error {
			n, err := strconv.ParseUint(key, 10, bits)
			if err != nil {
				return typeErr("cannot unmarshal object key %q into %s | 无法把对象键 %q 解析进 %s", key, keyType, key, keyType)
			}
			v.SetUint(n)
			return nil
		}, true
	}
	return nil, false
}

func buildMapDecoder(t reflect.Type) decodeFunc {
	setKey, ok := mapKeySetter(t.Key())
	if !ok {
		return func(d *decoder, v reflect.Value) error {
			return typeErr("unsupported map key type %s | 不支持的 map 键类型 %s", t.Key(), t.Key())
		}
	}
	elem := lazyDecoder(t.Elem())
	keyType := t.Key()
	return func(d *decoder, v reflect.Value) error {
		if d.data[d.pos] == 'n' {
			if err := d.literal("null"); err != nil {
				return err
			}
			v.SetZero()
			return nil
		}
		if err := d.enter(); err != nil {
			return err
		}
		defer d.leave()
		if d.data[d.pos] != '{' {
			return typeErr("cannot unmarshal non-object into %s | 无法把非对象解析进 %s", t, t)
		}
		enc := elem()
		if v.IsNil() {
			v.Set(reflect.MakeMap(t))
		}
		d.pos++
		d.skipSpace()
		if d.pos < len(d.data) && d.data[d.pos] == '}' {
			d.pos++
			return nil
		}
		for {
			d.skipSpace()
			if d.pos >= len(d.data) || d.data[d.pos] != '"' {
				return syntaxErr("expected object key | 期望对象键")
			}
			key, err := d.parseString()
			if err != nil {
				return err
			}
			d.skipSpace()
			if d.pos >= len(d.data) || d.data[d.pos] != ':' {
				return syntaxErr("expected ':' after object key | 对象键之后期望 ':'")
			}
			d.pos++
			elemValue := reflect.New(t.Elem()).Elem()
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of object | 对象意外结束")
			}
			if err := enc(d, elemValue); err != nil {
				return err
			}
			mapKey := reflect.New(keyType).Elem()
			if err := setKey(key, mapKey); err != nil {
				return err
			}
			v.SetMapIndex(mapKey, elemValue)
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of object | 对象意外结束")
			}
			switch d.data[d.pos] {
			case ',':
				d.pos++
			case '}':
				d.pos++
				return nil
			default:
				return syntaxErr("expected ',' or '}' in object | 对象中期望 ',' 或 '}'")
			}
		}
	}
}

// fastFieldDec parses a JSON value directly into a field's memory. | fastFieldDec 直接把 JSON 值
// 解析进字段内存。
