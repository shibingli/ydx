//go:build !jsonx_std

package json

import (
	"bytes"
	"encoding"
	stdjson "encoding/json"
	stdjsonv2 "encoding/json/v2"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// timeCacheEntry caches one formatted RFC 3339 timestamp. | timeCacheEntry 缓存一个已格式化的
// RFC 3339 时间戳。
type timeCacheEntry struct {
	k       time.Time
	b       [40]byte
	full    [64]byte
	key     [16]byte
	n       uint8
	keyLen  uint8
	fullLen uint8
}

type encoder struct {
	err        error
	v2         *v2Config
	buf        []byte
	timeCache  [4]timeCacheEntry
	depth      int
	escapeHTML bool
}

// enter marks entry into one value level and enforces the encoder nesting limit. | enter 标记进入一层值并
// 执行编码嵌套上限校验。
func (e *encoder) enter() error {
	e.depth++
	if e.depth > maxNestingDepth {
		e.depth--
		return errs.Detail(errUnsupported, "exceeded max depth of %d | 嵌套深度超过上限 %d", maxNestingDepth, maxNestingDepth)
	}
	return nil
}

// leave marks exit from one value level. | leave 标记退出一层值。
func (e *encoder) leave() { e.depth-- }

func syntaxErr(format string, args ...any) error {
	return errs.Detail(ErrSyntax, format, args...)
}

func typeErr(format string, args ...any) error {
	return errs.Detail(ErrTypeMismatch, format, args...)
}

var errUnsupported = errs.New("jsonx: unsupported value | jsonx：不支持的值")

// encodeFunc encodes one value of a fixed Go type. | encodeFunc 编码一个固定 Go 类型的值。
type encodeFunc func(*encoder, reflect.Value) error

// encodeCache maps each reflected type to its compiled encoder. | encodeCache 把反射类型映射到已编译的编码器。
var encodeCache sync.Map

// encodeFast is a small direct-mapped front cache over encodeCache. The hot path resolves the same
// handful of types on every call, and a sync.Map lookup hashes a reflect.Type interface (about
// 20 ns), so an atomic slot with an interface comparison removes that cost from every value while
// still falling back to the shared map for the rest. | encodeFast 是 encodeCache 之上的小型直接映射
// 前置缓存。热路径每次调用只解析固定几种类型，而 sync.Map 查找需要对 reflect.Type 接口做哈希
// （约 20 ns），因此用原子槽加接口比较即可把这个成本从每个值上移除，其余类型仍回退共享映射。
const encodeFastSlots = 4

type encodeFastEntry struct {
	typ reflect.Type
	fn  encodeFunc
}

var (
	encodeFast  [encodeFastSlots]atomic.Pointer[encodeFastEntry]
	encodeFastN atomic.Uint32
	encodeFastL atomic.Uint32 // index of the most recent slot, a lookup hint | 最近使用槽位的索引，仅作查找提示
)

// encoderFor returns the cached encoder for t, building it on first use. | encoderFor 返回 t 的缓存编码器，
// 首次调用时构建。
func encoderFor(t reflect.Type) encodeFunc {
	// The hint makes the steady-state single-type case one atomic load and one comparison.
	// A stale hint is harmless because the slot is still compared by type. | 提示位让常见的单一类型
	// 稳态只需一次原子加载与一次比较；提示过期也无害，因为槽位仍按类型比较。
	last := encodeFastL.Load()
	if last < encodeFastSlots {
		if e := encodeFast[last].Load(); e != nil && e.typ == t {
			return e.fn
		}
	}
	for i := range encodeFast {
		if uint32(i) == last {
			continue
		}
		if e := encodeFast[i].Load(); e != nil && e.typ == t {
			return e.fn
		}
	}
	var f encodeFunc
	if v, ok := encodeCache.Load(t); ok {
		f = v.(encodeFunc)
	} else {
		f = buildEncoder(t)
		encodeCache.Store(t, f)
	}
	slot := encodeFastN.Add(1) % encodeFastSlots
	encodeFast[slot].Store(&encodeFastEntry{typ: t, fn: f})
	encodeFastL.Store(slot)
	return f
}

func (e *encoder) value(v reflect.Value) error {
	if !v.IsValid() {
		e.buf = append(e.buf, "null"...)
		return nil
	}
	if e.v2 != nil && len(e.v2.marshalers) > 0 {
		if m, target := e.marshalTarget(v); m != nil {
			return e.applyMarshaler(m, target)
		}
	}
	if err := e.enter(); err != nil {
		return err
	}
	err := encoderFor(v.Type())(e, v)
	e.leave()
	return err
}

func encodeNull(e *encoder) {
	e.buf = append(e.buf, "null"...)
}

func buildEncoder(t reflect.Type) encodeFunc {
	if t == numberType {
		return func(e *encoder, v reflect.Value) error {
			s := v.String()
			if s == "" {
				// The zero json.Number encodes as 0, matching encoding/json. | 零值 json.Number
				// 编码为 0，与 encoding/json 一致。
				s = "0"
			}
			if !isValidNumber(s) {
				return errs.Detail(errUnsupported, "invalid number %q | 非法数字 %q", s, s)
			}
			if e.v2 != nil && e.v2.stringifyNumbers {
				e.buf = append(e.buf, '"')
				e.buf = append(e.buf, s...)
				e.buf = append(e.buf, '"')
				return nil
			}
			e.buf = append(e.buf, s...)
			return nil
		}
	}
	if t == durationType {
		return func(e *encoder, v reflect.Value) error {
			if e.v2 != nil && !e.v2.formatDurationAsNano {
				if e.err == nil {
					e.err = newMarshalSemanticError(t, "no default representation")
				}
				return e.err
			}
			e.buf = strconv.AppendInt(e.buf, v.Int(), 10)
			return nil
		}
	}
	if t.Kind() == reflect.Interface {
		return func(e *encoder, v reflect.Value) error {
			if v.IsNil() {
				encodeNull(e)
				return nil
			}
			return e.value(v.Elem())
		}
	}
	tr := cachedTraits(t)
	// The ordinary kind encoder is built lazily: building it eagerly for a struct caches a fast
	// struct plan, which the top-level non-addressable fast path would then pick even though the
	// type's marshal method must take precedence. | 常规 kind 编码器延迟构建：对结构体提前构建会
	// 缓存快速结构体计划，顶层不可寻址快速路径随后会选中它，从而绕过类型必须优先的编码方法。
	var normOnce sync.Once
	var norm encodeFunc
	normFn := func() encodeFunc {
		normOnce.Do(func() { norm = buildKindEncoder(t) })
		return norm
	}
	if t.Kind() == reflect.Pointer {
		switch {
		case tr.marshalerTo:
			return func(e *encoder, v reflect.Value) error {
				if v.IsNil() {
					encodeNull(e)
					return nil
				}
				if e.v2 != nil {
					return e.marshalerTo(v.Interface().(stdjsonv2.MarshalerTo))
				}
				if tr.marshaler {
					return e.marshaler(v.Interface().(stdjson.Marshaler))
				}
				if tr.textMarshaler {
					return encodeText(e, v)
				}
				return e.value(v.Elem())
			}
		case tr.marshaler:
			return func(e *encoder, v reflect.Value) error {
				if v.IsNil() {
					encodeNull(e)
					return nil
				}
				return e.marshaler(v.Interface().(stdjson.Marshaler))
			}
		case tr.textMarshaler:
			return func(e *encoder, v reflect.Value) error {
				if v.IsNil() {
					encodeNull(e)
					return nil
				}
				return encodeText(e, v)
			}
		default:
			return func(e *encoder, v reflect.Value) error {
				if v.IsNil() {
					encodeNull(e)
					return nil
				}
				return e.value(v.Elem())
			}
		}
	}
	if tr.marshalerTo {
		return func(e *encoder, v reflect.Value) error {
			if e.v2 != nil {
				return e.marshalerTo(v.Interface().(stdjsonv2.MarshalerTo))
			}
			if tr.marshaler {
				return e.marshaler(v.Interface().(stdjson.Marshaler))
			}
			if tr.textMarshaler {
				return encodeText(e, v)
			}
			return normFn()(e, v)
		}
	}
	if tr.marshaler {
		return func(e *encoder, v reflect.Value) error {
			return e.marshaler(v.Interface().(stdjson.Marshaler))
		}
	}
	if tr.textMarshaler {
		return func(e *encoder, v reflect.Value) error {
			return encodeText(e, v)
		}
	}
	ptrMarshalerTo := reflect.PointerTo(t).Implements(marshalerToType)
	ptrMarshaler := reflect.PointerTo(t).Implements(marshalerType)
	if ptrMarshalerTo {
		return func(e *encoder, v reflect.Value) error {
			if v.CanAddr() {
				if e.v2 != nil {
					return e.marshalerTo(v.Addr().Interface().(stdjsonv2.MarshalerTo))
				}
				if ptrMarshaler {
					return e.marshaler(v.Addr().Interface().(stdjson.Marshaler))
				}
			}
			return normFn()(e, v)
		}
	}
	if ptrMarshaler {
		return func(e *encoder, v reflect.Value) error {
			if v.CanAddr() {
				return e.marshaler(v.Addr().Interface().(stdjson.Marshaler))
			}
			return normFn()(e, v)
		}
	}
	return normFn()
}

func encodeText(e *encoder, v reflect.Value) error {
	text, err := v.Interface().(encoding.TextMarshaler).MarshalText()
	if err != nil {
		return err
	}
	e.str(string(text))
	return nil
}

func buildKindEncoder(t reflect.Type) encodeFunc {
	switch t.Kind() {
	case reflect.Bool:
		return func(e *encoder, v reflect.Value) error {
			e.buf = strconv.AppendBool(e.buf, v.Bool())
			return nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return func(e *encoder, v reflect.Value) error {
			if e.v2 != nil && e.v2.stringifyNumbers {
				e.buf = append(e.buf, '"')
				e.buf = strconv.AppendInt(e.buf, v.Int(), 10)
				e.buf = append(e.buf, '"')
				return nil
			}
			e.buf = strconv.AppendInt(e.buf, v.Int(), 10)
			return nil
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return func(e *encoder, v reflect.Value) error {
			if e.v2 != nil && e.v2.stringifyNumbers {
				e.buf = append(e.buf, '"')
				e.buf = strconv.AppendUint(e.buf, v.Uint(), 10)
				e.buf = append(e.buf, '"')
				return nil
			}
			e.buf = strconv.AppendUint(e.buf, v.Uint(), 10)
			return nil
		}
	case reflect.Float32:
		return func(e *encoder, v reflect.Value) error {
			return e.floatMode(v.Float(), 32)
		}
	case reflect.Float64:
		return func(e *encoder, v reflect.Value) error {
			return e.floatMode(v.Float(), 64)
		}
	case reflect.String:
		return func(e *encoder, v reflect.Value) error {
			e.str(v.String())
			return nil
		}
	case reflect.Slice:
		return buildSliceEncoder(t)
	case reflect.Array:
		return buildArrayEncoder(t)
	case reflect.Map:
		return buildMapEncoder(t)
	case reflect.Struct:
		return buildStructEncoder(t)
	default:
		return func(e *encoder, v reflect.Value) error {
			if e.v2 != nil {
				return newMarshalSemanticError(t, "")
			}
			return errs.Detail(errUnsupported, "unsupported type %s | 不支持的类型 %s", t, t)
		}
	}
}

// buildQuotedEncoder replicates encoding/json's ,string encoding for one field type. Only the
// builtin bool/int/uint/float/string encoders honor the quoted option; Marshaler and
// TextMarshaler output is never quoted, nil pointers stay null, and a pointer-receiver marshaler
// is only selected when the field value is addressable, exactly like condAddrEncoder. | buildQuotedEncoder
// 复现 encoding/json 对单个字段类型的 ,string 编码。只有内置的 bool/int/uint/float/string 编码器
// 会应用引号；Marshaler 与 TextMarshaler 的输出从不加引号；nil 指针保持 null；指针接收者
// Marshaler 仅在字段值可寻址时选用，与 condAddrEncoder 完全一致。
func buildQuotedEncoder(t reflect.Type) func(*encoder, reflect.Value) error {
	tr := cachedTraits(t)
	normal := encoderFor(t)
	if tr.marshaler || tr.textMarshaler {
		return normal
	}
	if t.Kind() == reflect.Pointer {
		elem := cachedTraits(t.Elem())
		if elem.marshaler || elem.textMarshaler {
			return normal
		}
		return func(e *encoder, v reflect.Value) error {
			if v.IsNil() {
				encodeNull(e)
				return nil
			}
			return e.quotedValue(v.Elem())
		}
	}
	if reflect.PointerTo(t).Implements(marshalerType) || reflect.PointerTo(t).Implements(textMarshalerType) {
		return func(e *encoder, v reflect.Value) error {
			if v.CanAddr() {
				return normal(e, v)
			}
			return e.quotedValue(v)
		}
	}
	return func(e *encoder, v reflect.Value) error { return e.quotedValue(v) }
}

// lazyEncoder defers resolving an element encoder until the first value is encoded.
// 延迟到首次编码时才解析元素编码器，使递归类型不会在构建期无限递归。
func lazyEncoder(t reflect.Type) func() encodeFunc {
	var slot atomic.Pointer[encodeFunc]
	return func() encodeFunc {
		if f := slot.Load(); f != nil {
			return *f
		}
		f := encoderFor(t)
		slot.Store(&f)
		return f
	}
}

func buildSliceEncoder(t reflect.Type) encodeFunc {
	if t.Elem().Kind() == reflect.Uint8 {
		return func(e *encoder, v reflect.Value) error {
			if v.IsNil() && nilSliceAsNull(e) {
				encodeNull(e)
				return nil
			}
			e.str(base64.StdEncoding.EncodeToString(v.Bytes()))
			return nil
		}
	}
	elem := lazyEncoder(t.Elem())
	var fastSlot atomic.Pointer[fastStructInfo]
	fast := func() *fastStructInfo {
		if p := fastSlot.Load(); p != nil {
			return p
		}
		info := fastStructFor(t.Elem())
		if info == nil {
			info = &fastStructInfo{}
		}
		fastSlot.Store(info)
		return info
	}
	return func(e *encoder, v reflect.Value) error {
		if v.IsNil() {
			if nilSliceAsNull(e) {
				encodeNull(e)
			} else {
				e.buf = append(e.buf, '[', ']')
			}
			return nil
		}
		if err := e.enter(); err != nil {
			return err
		}
		e.buf = append(e.buf, '[')
		if sf := fast(); sf.enc != nil && !e.v2DisallowsFastStruct() {
			n := v.Len()
			if n > 0 {
				base := unsafe.Pointer(v.Pointer())
				if sf.encSlice != nil {
					buf, err := sf.encSlice(e, e.buf, base, n)
					if err != nil {
						e.leave()
						return err
					}
					e.buf = buf
				} else {
					size := sf.size
					for i := 0; i < n; i++ {
						if i > 0 {
							e.buf = append(e.buf, ',')
						}
						if err := sf.enc(e, unsafe.Add(base, uintptr(i)*size)); err != nil {
							e.leave()
							return err
						}
					}
				}
			}
			e.buf = append(e.buf, ']')
			e.leave()
			return nil
		}
		enc := elem()
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			var ferr error
			if e.v2 != nil && len(e.v2.marshalers) > 0 {
				ferr = e.elemValue(v.Index(i))
			} else {
				ferr = enc(e, v.Index(i))
			}
			if ferr != nil {
				e.leave()
				return ferr
			}
		}
		e.buf = append(e.buf, ']')
		e.leave()
		return nil
	}
}

func buildArrayEncoder(t reflect.Type) encodeFunc {
	elem := lazyEncoder(t.Elem())
	encodeArray := func(e *encoder, v reflect.Value) error {
		if err := e.enter(); err != nil {
			return err
		}
		enc := elem()
		e.buf = append(e.buf, '[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			var ferr error
			if e.v2 != nil && len(e.v2.marshalers) > 0 {
				ferr = e.elemValue(v.Index(i))
			} else {
				ferr = enc(e, v.Index(i))
			}
			if ferr != nil {
				e.leave()
				return ferr
			}
		}
		e.buf = append(e.buf, ']')
		e.leave()
		return nil
	}
	if t.Elem().Kind() == reflect.Uint8 {
		return func(e *encoder, v reflect.Value) error {
			if e.v2 != nil && !e.v2.formatByteArrayAsArray {
				e.str(base64.StdEncoding.EncodeToString(arrayBytes(v)))
				return nil
			}
			return encodeArray(e, v)
		}
	}
	return encodeArray
}

// arrayBytes returns the bytes of a [N]byte value for base64 encoding. Addressable arrays are
// viewed without copying; a non-addressable array (for example a value passed directly to
// Marshal) is copied through its elements. | arrayBytes 返回 [N]byte 的字节用于 Base64 编码。可寻址
// 数组零拷贝视图；不可寻址数组（例如直接传给 Marshal 的值）经元素复制。
func arrayBytes(v reflect.Value) []byte {
	n := v.Len()
	if v.CanAddr() {
		return v.Slice(0, n).Bytes()
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(v.Index(i).Uint())
	}
	return b
}

func buildMapKeyEncoder(t reflect.Type) func(reflect.Value) (string, error) {
	switch t.Kind() {
	case reflect.String:
		return func(k reflect.Value) (string, error) { return k.String(), nil }
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return func(k reflect.Value) (string, error) { return strconv.FormatInt(k.Int(), 10), nil }
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return func(k reflect.Value) (string, error) { return strconv.FormatUint(k.Uint(), 10), nil }
	}
	if t.Implements(textMarshalerType) {
		return func(k reflect.Value) (string, error) {
			text, err := k.Interface().(encoding.TextMarshaler).MarshalText()
			if err != nil {
				return "", err
			}
			return string(text), nil
		}
	}
	return func(k reflect.Value) (string, error) {
		return "", errs.Detail(errUnsupported, "unsupported map key type %s | 不支持的 map 键类型 %s", t, t)
	}
}

func buildMapEncoder(t reflect.Type) encodeFunc {
	key := buildMapKeyEncoder(t.Key())
	elem := lazyEncoder(t.Elem())
	type kv struct {
		key string
		val reflect.Value
	}
	return func(e *encoder, v reflect.Value) error {
		if v.IsNil() {
			if e.v2 == nil || e.v2.formatNilMapAsNull {
				encodeNull(e)
			} else {
				e.buf = append(e.buf, '{', '}')
			}
			return nil
		}
		if err := e.enter(); err != nil {
			return err
		}
		defer e.leave()
		enc := elem()
		entries := make([]kv, 0, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			name, err := key(iter.Key())
			if err != nil {
				return err
			}
			entries = append(entries, kv{key: name, val: iter.Value()})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
		e.buf = append(e.buf, '{')
		for i, entry := range entries {
			if i > 0 {
				e.buf = append(e.buf, ',')
			}
			e.str(entry.key)
			e.buf = append(e.buf, ':')
			var ferr error
			if e.v2 != nil && len(e.v2.marshalers) > 0 {
				ferr = e.elemValue(entry.val)
			} else {
				ferr = enc(e, entry.val)
			}
			if ferr != nil {
				return ferr
			}
		}
		e.buf = append(e.buf, '}')
		return nil
	}
}

// fastStructInfo describes a struct whose every field has a direct-memory encoder.
// fastStructInfo 描述所有字段都可直接按内存编码的结构体。
type fastStructInfo struct {
	enc func(*encoder, unsafe.Pointer) error
	// encBuf encodes one struct into a local buffer and returns it. It writes e.buf only once,
	// for fields that still need the encoder, instead of after every append. |
	// encBuf 把单个结构体编码进局部缓冲并返回；只在仍需 encoder 的字段上回写 e.buf，
	// 而不是每次 append 都回写。
	encBuf   func(*encoder, []byte, unsafe.Pointer) ([]byte, error)
	encSlice func(*encoder, []byte, unsafe.Pointer, int) ([]byte, error)
	size     uintptr
}

var (
	fastStructCache sync.Map
	fastStructLast  atomic.Pointer[fastStructEntry]
)

// fastStructEntry caches the most recently resolved fast struct plan, including a nil decision,
// so repeated Marshal calls of one type avoid hashing the reflect.Type through sync.Map. |
// fastStructEntry 缓存最近解析的快速结构体计划（含 nil 判定），使同一类型的连续 Marshal 不必每次
// 经 sync.Map 哈希 reflect.Type。
type fastStructEntry struct {
	typ  reflect.Type
	info *fastStructInfo
}

// fastStructFor returns the fast struct encoder for t, if one was built. | fastStructFor 返回 t 的快速
// 结构体编码器（若已构建）。
func fastStructFor(t reflect.Type) *fastStructInfo {
	if e := fastStructLast.Load(); e != nil && e.typ == t {
		return e.info
	}
	info := lookupFastStruct(t)
	fastStructLast.Store(&fastStructEntry{typ: t, info: info})
	return info
}

func lookupFastStruct(t reflect.Type) *fastStructInfo {
	if v, ok := fastStructCache.Load(t); ok {
		return v.(*fastStructInfo)
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	encoderFor(t)
	if v, ok := fastStructCache.Load(t); ok {
		return v.(*fastStructInfo)
	}
	return nil
}

func buildStructEncoder(t reflect.Type) encodeFunc {
	info := cachedStruct(t)
	fields, fallback := info.fields, info.fallback
	if len(fields) == 0 && t.NumField() > 0 && !hasExplicitJSONTag(t) {
		// v2 rejects a non-empty struct without any JSON-representable fields unless the type
		// opts in with an explicit tag; v1 emits an empty object. | v2 拒绝没有任何可表示字段的
		// 非空结构体，除非类型用显式 tag 声明可表示；v1 输出空对象。
		return func(e *encoder, v reflect.Value) error {
			if e.v2 != nil {
				return newMarshalSemanticError(t, "Go struct has no exported fields")
			}
			e.buf = append(e.buf, '{', '}')
			return nil
		}
	}
	type encField struct {
		typ         reflect.Type
		fast        func(*encoder, unsafe.Pointer) error
		fastEmpty   func(unsafe.Pointer) bool
		enc         encodeFunc
		quotedEnc   func(*encoder, reflect.Value) error
		isZero      func(reflect.Value) bool
		full        func(*encoder, unsafe.Pointer) error
		key         []byte
		fastKey     []byte
		keyHTML     []byte
		fastKeyHTML []byte
		index       []int
		offset      uintptr
		direct      int
		keyPad      [16]byte
		keyPadHTML  [16]byte
		omitEmpty   bool
		omitZero    bool
		quoted      bool
		fastOK      bool
		keyFixed    bool
		keyHTMLKey  bool
		htmlKey     bool
		kind        uint8
	}

	list := make([]encField, len(fields))
	nameSet := make(map[string]struct{}, len(fields))
	for i := range fields {
		nameSet[fields[i].name] = struct{}{}
	}
	allFast := fallback == nil
	for i, f := range fields {
		direct := -1
		if len(f.index) == 1 {
			direct = f.index[0]
		}
		var ke encoder
		ke.str(f.name)
		ke.buf = append(ke.buf, ':')
		offset, fastOK := fieldOffset(t, f.index)
		fast := buildFastFieldEncoder(f.typ)
		fastKey := ke.buf
		if i > 0 {
			fastKey = append([]byte{','}, ke.buf...)
		}
		// Keys of at most 16 bytes are pre-padded so the fast path can write them with one
		// fixed-size store instead of a variable-length memmove. | 不超过 16 字节的键预先填充，
		// 使快速路径用一次定长存储代替变长 memmove。
		var keyPad [16]byte
		if len(fastKey) <= len(keyPad) {
			copy(keyPad[:], fastKey)
		}
		// Tags containing HTML-sensitive characters have a second precomputed key for
		// Encoder.SetEscapeHTML(true); all other tags share one key across both modes. |
		// 含 HTML 敏感字符的标签为 Encoder.SetEscapeHTML(true) 额外预计算一份键；其余标签在两种
		// 模式下共用同一份键。
		htmlKey := strings.ContainsAny(f.name, "<>&") ||
			strings.ContainsRune(f.name, ' ') || strings.ContainsRune(f.name, ' ')
		var keyHTML, fastKeyHTML []byte
		var keyPadHTML [16]byte
		if htmlKey {
			var keh encoder
			keh.escapeHTML = true
			keh.str(f.name)
			keh.buf = append(keh.buf, ':')
			keyHTML = keh.buf
			fastKeyHTML = keyHTML
			if i > 0 {
				fastKeyHTML = append([]byte{','}, keyHTML...)
			}
			if len(fastKeyHTML) <= len(keyPadHTML) {
				copy(keyPadHTML[:], fastKeyHTML)
			}
		}
		kind := uint8(fieldKindNone)
		if fastOK && fast != nil && f.typ != durationType {
			kind = fastFieldKind(f.typ)
		}
		var quotedEnc func(*encoder, reflect.Value) error
		if f.quoted {
			quotedEnc = buildQuotedEncoder(f.typ)
		}
		list[i] = encField{
			key:         ke.buf,
			fastKey:     fastKey,
			keyHTML:     keyHTML,
			fastKeyHTML: fastKeyHTML,
			typ:         f.typ,
			index:       f.index,
			offset:      offset,
			direct:      direct,
			fast:        fast,
			fastEmpty:   buildFastEmpty(f.typ),
			enc:         encoderFor(f.typ),
			isZero:      f.isZero,
			quotedEnc:   quotedEnc,
			keyPad:      keyPad,
			keyPadHTML:  keyPadHTML,
			omitEmpty:   f.omitEmpty,
			omitZero:    f.omitZero,
			quoted:      f.quoted,
			fastOK:      fastOK && !f.quoted,
			keyFixed:    len(fastKey) <= len(keyPad),
			keyHTMLKey:  len(fastKeyHTML) <= len(keyPadHTML),
			htmlKey:     htmlKey,
			kind:        kind,
		}
		// HTML-sensitive tag names use the reflective path, so the common fast loops keep
		// their original branch-free key writes; such names are rare. | 含 HTML 敏感字符的标签名
		// 走反射路径，使常见类型的快速循环保持无分支的键写入；这类标签名很少见。
		if !fastOK || fast == nil || f.omitEmpty || f.omitZero || f.quoted || htmlKey {
			allFast = false
		}
	}
	for i := range list {
		f := &list[i]
		if f.typ != timeType || !f.fastOK || f.omitEmpty || f.omitZero || f.quoted || f.htmlKey || len(f.fastKey) > 16 {
			continue
		}
		key := append([]byte(nil), f.fastKey...)
		f.full = func(e *encoder, p unsafe.Pointer) error {
			tt := (*time.Time)(p)
			entry := &e.timeCache[uint64(tt.UnixNano())&3]
			if entry.fullLen != 0 && entry.k == *tt && int(entry.keyLen) == len(key) && bytes.Equal(entry.key[:len(key)], key) {
				e.buf = append(e.buf, entry.full[:entry.fullLen]...)
				return nil
			}
			if y := tt.Year(); y < 0 || y >= 10000 {
				return errs.Detail(errUnsupported, "time year %d out of range | 时间年份 %d 超出范围", y, y)
			}
			var full [64]byte
			n := copy(full[:], key)
			full[n] = '"'
			n++
			formatted := tt.AppendFormat(full[n:n], time.RFC3339Nano)
			if len(formatted) > cap(full)-n {
				return errs.Detail(errUnsupported, "time formatting overflow | 时间格式化溢出")
			}
			copy(full[n:], formatted)
			n += len(formatted)
			full[n] = '"'
			n++
			e.buf = append(e.buf, full[:n]...)
			copy(entry.full[:], full[:n])
			entry.fullLen = uint8(n)
			entry.keyLen = uint8(len(key))
			copy(entry.key[:], key)
			entry.k = *tt
			return nil
		}
	}
	fastEnc := func(e *encoder, base unsafe.Pointer) error {
		e.buf = append(e.buf, '{')
		for i := range list {
			f := &list[i]
			p := unsafe.Add(base, f.offset)
			if f.full != nil {
				if err := f.full(e, p); err != nil {
					return err
				}
				continue
			}
			if f.keyFixed && cap(e.buf)-len(e.buf) >= len(f.keyPad) {
				// One 16-byte store replaces the memmove append; the padding lies beyond the
				// new length and is overwritten by the value that follows. | 一次 16 字节存储
				// 取代 memmove 追加；填充部分位于新长度之外，会被随后的值覆盖。
				dst := unsafe.Add(unsafe.Pointer(unsafe.SliceData(e.buf)), len(e.buf))
				*(*[16]byte)(dst) = f.keyPad
				e.buf = e.buf[:len(e.buf)+len(f.fastKey)]
			} else {
				e.buf = append(e.buf, f.fastKey...)
			}
			// Primitive kinds are encoded inline; the indirect call remains for composites and
			// special types such as []string and time.Time. | 基础类型就地编码；复合类型与
			// []string、time.Time 等特殊类型仍走间接调用。
			switch f.kind {
			case fieldKindString:
				e.str(*(*string)(p))
			case fieldKindBool:
				e.buf = strconv.AppendBool(e.buf, *(*bool)(p))
			case fieldKindInt:
				e.buf = appendIntFast(e.buf, int64(*(*int)(p)))
			case fieldKindInt8:
				e.buf = appendIntFast(e.buf, int64(*(*int8)(p)))
			case fieldKindInt16:
				e.buf = appendIntFast(e.buf, int64(*(*int16)(p)))
			case fieldKindInt32:
				e.buf = appendIntFast(e.buf, int64(*(*int32)(p)))
			case fieldKindInt64:
				e.buf = appendIntFast(e.buf, *(*int64)(p))
			case fieldKindUint:
				e.buf = appendUintFast(e.buf, uint64(*(*uint)(p)))
			case fieldKindUint8:
				e.buf = appendUintFast(e.buf, uint64(*(*uint8)(p)))
			case fieldKindUint16:
				e.buf = appendUintFast(e.buf, uint64(*(*uint16)(p)))
			case fieldKindUint32:
				e.buf = appendUintFast(e.buf, uint64(*(*uint32)(p)))
			case fieldKindUint64:
				e.buf = appendUintFast(e.buf, *(*uint64)(p))
			case fieldKindUintptr:
				e.buf = appendUintFast(e.buf, uint64(*(*uintptr)(p)))
			case fieldKindFloat32:
				if err := e.float(float64(*(*float32)(p)), 32); err != nil {
					return err
				}
			case fieldKindFloat64:
				if err := e.float(*(*float64)(p), 64); err != nil {
					return err
				}
			default:
				if err := f.fast(e, p); err != nil {
					return err
				}
			}
		}
		e.buf = append(e.buf, '}')
		return nil
	}
	// encBody encodes one struct into a local buffer and returns it. Writing back e.buf once
	// instead of once per append removes the write barriers that dominate multi-core Marshal
	// profiles. A nil e is valid for plans whose fields need neither a timestamp cache nor a
	// fallback encoder. | encBody 把单个结构体编码进局部缓冲并返回：只回写一次 e.buf，而不是
	// 每次 append 都回写，从而消除多核 Marshal 剖析中的主要写屏障。字段既不需要时间戳缓存、
	// 也不需要回退编码器时，e 可以为 nil。
	var encBody func([]byte, unsafe.Pointer, *encoder, bool, bool) ([]byte, error)
	var encBuf func(*encoder, []byte, unsafe.Pointer) ([]byte, error)
	// encSlice encodes a whole []T by repeating encBody with one write-back per slice. |
	// encSlice 通过重复调用 encBody 编码整个 []T，每个切片只回写一次。
	var encSlice func(*encoder, []byte, unsafe.Pointer, int) ([]byte, error)
	if allFast {
		size := t.Size()
		encBody = func(buf []byte, base unsafe.Pointer, e *encoder, escapeHTML, escapeJS bool) ([]byte, error) {
			buf = append(buf, '{')
			for j := range list {
				f := &list[j]
				p := unsafe.Add(base, f.offset)
				if f.keyFixed && cap(buf)-len(buf) >= len(f.keyPad) {
					dst := unsafe.Add(unsafe.Pointer(unsafe.SliceData(buf)), len(buf))
					*(*[16]byte)(dst) = f.keyPad
					buf = buf[:len(buf)+len(f.fastKey)]
				} else {
					buf = append(buf, f.fastKey...)
				}
				switch f.kind {
				case fieldKindString:
					var valid bool
					buf, valid = appendJSONStringChecked(buf, *(*string)(p), escapeHTML, escapeJS)
					if !valid && e != nil && e.v2 != nil && !e.v2.allowInvalidUTF8 {
						return buf, newMarshalInvalidUTF8Error()
					}
				case fieldKindBool:
					buf = strconv.AppendBool(buf, *(*bool)(p))
				case fieldKindInt:
					buf = appendIntFast(buf, int64(*(*int)(p)))
				case fieldKindInt8:
					buf = appendIntFast(buf, int64(*(*int8)(p)))
				case fieldKindInt16:
					buf = appendIntFast(buf, int64(*(*int16)(p)))
				case fieldKindInt32:
					buf = appendIntFast(buf, int64(*(*int32)(p)))
				case fieldKindInt64:
					buf = appendIntFast(buf, *(*int64)(p))
				case fieldKindUint:
					buf = appendUintFast(buf, uint64(*(*uint)(p)))
				case fieldKindUint8:
					buf = appendUintFast(buf, uint64(*(*uint8)(p)))
				case fieldKindUint16:
					buf = appendUintFast(buf, uint64(*(*uint16)(p)))
				case fieldKindUint32:
					buf = appendUintFast(buf, uint64(*(*uint32)(p)))
				case fieldKindUint64:
					buf = appendUintFast(buf, *(*uint64)(p))
				case fieldKindUintptr:
					buf = appendUintFast(buf, uint64(*(*uintptr)(p)))
				case fieldKindFloat32:
					var err error
					buf, err = appendFloat(buf, float64(*(*float32)(p)), 32)
					if err != nil {
						return buf, err
					}
				case fieldKindFloat64:
					var err error
					buf, err = appendFloat(buf, *(*float64)(p), 64)
					if err != nil {
						return buf, err
					}
				default:
					switch f.typ {
					case timeType:
						var err error
						buf, err = appendTimeValue(buf, e, (*time.Time)(p))
						if err != nil {
							return buf, err
						}
					case stringSliceType:
						var valid bool
						buf, valid = appendStringSliceChecked(buf, *(*[]string)(p), escapeHTML, escapeJS, nilSliceAsNull(e))
						if !valid && e != nil && e.v2 != nil && !e.v2.allowInvalidUTF8 {
							return buf, newMarshalInvalidUTF8Error()
						}
					default:
						if f.fast == nil {
							return buf, errUnsupported
						}
						e.buf = buf
						err := f.fast(e, p)
						buf = e.buf
						if err != nil {
							return buf, err
						}
					}
				}
			}
			buf = append(buf, '}')
			return buf, nil
		}
		encBuf = func(e *encoder, buf []byte, base unsafe.Pointer) ([]byte, error) {
			return encBody(buf, base, e, e.escapeHTML, escapeJSFor(e))
		}
		encSlice = func(e *encoder, buf []byte, base unsafe.Pointer, n int) ([]byte, error) {
			js := escapeJSFor(e)
			for i := 0; i < n; i++ {
				if i > 0 {
					buf = append(buf, ',')
				}
				var err error
				buf, err = encBody(buf, unsafe.Add(base, uintptr(i)*size), e, e.escapeHTML, js)
				if err != nil {
					return buf, err
				}
			}
			return buf, nil
		}
	}
	if allFast {
		fastStructCache.Store(t, &fastStructInfo{enc: fastEnc, encBuf: encBuf, encSlice: encSlice, size: t.Size()})
	}
	return func(e *encoder, v reflect.Value) error {
		if allFast && v.CanAddr() && !e.v2DisallowsFastStruct() {
			return fastEnc(e, unsafe.Pointer(v.UnsafeAddr()))
		}
		var base unsafe.Pointer
		if v.CanAddr() {
			base = unsafe.Pointer(v.UnsafeAddr())
		}
		e.buf = append(e.buf, '{')
		first := true
		for i := range list {
			f := &list[i]
			var fv reflect.Value
			var fieldPtr unsafe.Pointer
			if base != nil && f.fastOK {
				fieldPtr = unsafe.Add(base, f.offset)
			} else if f.direct >= 0 {
				fv = v.Field(f.direct)
			} else {
				var ok bool
				fv, ok = fieldByIndex(v, f.index)
				if !ok {
					continue
				}
			}
			if f.omitEmpty {
				if e.v2 != nil && !e.v2.omitEmptyWithLegacy {
					if !fv.IsValid() {
						fv = reflect.NewAt(f.typ, unsafe.Add(base, f.offset)).Elem()
					}
					if emptyV2(fv) {
						continue
					}
				} else if fieldPtr != nil && f.fastEmpty != nil {
					if f.fastEmpty(fieldPtr) {
						continue
					}
				} else {
					if !fv.IsValid() {
						fv = reflect.NewAt(f.typ, unsafe.Add(base, f.offset)).Elem()
					}
					if isEmptyValue(fv) {
						continue
					}
				}
			}
			if f.omitZero || (e.v2 != nil && e.v2.omitZeroStructFields) {
				if !fv.IsValid() {
					fv = reflect.NewAt(f.typ, fieldPtr).Elem()
				}
				if f.isZero == nil {
					if fv.IsZero() {
						continue
					}
				} else if f.isZero(fv) {
					continue
				}
			}
			if !first {
				e.buf = append(e.buf, ',')
			}
			first = false
			if f.htmlKey && e.escapeHTML {
				e.buf = append(e.buf, f.keyHTML...)
			} else {
				e.buf = append(e.buf, f.key...)
			}
			if e.v2 != nil && len(e.v2.marshalers) > 0 {
				if !fv.IsValid() {
					fv = reflect.NewAt(f.typ, unsafe.Add(base, f.offset)).Elem()
				}
				if err := e.value(fv); err != nil {
					return err
				}
			} else if f.quotedEnc != nil {
				if !fv.IsValid() {
					fv = reflect.NewAt(f.typ, fieldPtr).Elem()
				}
				if err := f.quotedEnc(e, fv); err != nil {
					return err
				}
			} else if fieldPtr != nil && f.fast != nil && !e.v2FastFieldDisallowed() {
				if err := f.fast(e, fieldPtr); err != nil {
					return err
				}
			} else {
				if !fv.IsValid() {
					fv = reflect.NewAt(f.typ, unsafe.Add(base, f.offset)).Elem()
				}
				if err := f.enc(e, fv); err != nil {
					return err
				}
			}
		}
		if fallback != nil {
			if err := e.encodeFallback(fallback, v, nameSet, &first); err != nil {
				return err
			}
		}
		e.buf = append(e.buf, '}')
		return nil
	}
}

// fieldOffset returns the fixed byte offset of an index path, if every intermediate is a struct value.
// fieldOffset 返回索引路径的固定字节偏移；若中间经过指针则返回 false。
