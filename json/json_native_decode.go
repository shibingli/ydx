//go:build !jsonx_std

package json

import (
	"bytes"
	"encoding"
	"encoding/binary"
	stdjson "encoding/json"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// maxNestingDepth aligns with encoding/json's scanner limit. | maxNestingDepth 与 encoding/json 的扫描器上限一致。
const maxNestingDepth = 10000

type decoder struct {
	timeVal   time.Time
	data      []byte
	arena     []byte
	pos       int
	depth     int
	timeRaw   [40]byte
	timeLen   uint8
	useNumber bool
	skipLen   bool
}

// enter marks entry into one container and enforces the nesting limit. | enter 标记进入一层容器并执行嵌套上限校验。
func (d *decoder) enter() error {
	d.depth++
	if d.depth > maxNestingDepth {
		d.depth--
		return errs.Detail(ErrSyntax, "exceeded max depth of %d | 嵌套深度超过上限 %d", maxNestingDepth, maxNestingDepth)
	}
	return nil
}

// leave marks exit from one container. | leave 标记退出一层容器。
func (d *decoder) leave() { d.depth-- }

const (
	// minArenaChunk is the first arena chunk size. | minArenaChunk 是 arena 首块的大小。
	minArenaChunk = 64
	// maxArenaChunk bounds one arena chunk; longer strings get an exact-size chunk. |
	// maxArenaChunk 限制单个 arena 块；更长的字符串使用精确大小的块。
	maxArenaChunk = 16 << 10
	// maxArenaRetain bounds the arena kept by one pooled decoder. | maxArenaRetain 限制单个池化
	// 解码器保留的 arena。
	maxArenaRetain = 64 << 10
)

// ensureArena allocates the decoder's string arena on first use. Decoded strings are a fraction
// of the input (keys are not copied and structural bytes take space), so a third of the input is
// a good first guess. | ensureArena 在首次使用时分配解码器的字符串 arena。解码出的字符串只占输入
// 的一部分（键不复制、结构字节也占空间），取输入的三分之一作为初始估算。
func (d *decoder) ensureArena() {
	if d.arena != nil {
		return
	}
	hint := len(d.data) / 3
	if hint < minArenaChunk {
		hint = minArenaChunk
	}
	if hint > maxArenaChunk {
		hint = maxArenaChunk
	}
	d.arena = make([]byte, 0, hint)
}

// ensureArenaSpare makes room for n more bytes. The arena is append-only: bytes before its length
// are referenced by strings already returned, so an exhausted arena is replaced by a fresh chunk
// instead of being grown in place. | ensureArenaSpare 为 n 字节腾出空间。arena 只追加：长度之前的
// 字节已被返回的字符串引用，因此空间不足时换用新块，而不是原地扩容。
func (d *decoder) ensureArenaSpare(n int) {
	if cap(d.arena)-len(d.arena) >= n {
		return
	}
	size := 2 * cap(d.arena)
	if size < minArenaChunk {
		size = minArenaChunk
	}
	if size < n {
		size = n
	}
	if size > maxArenaChunk && n <= maxArenaChunk {
		size = maxArenaChunk
	}
	d.arena = make([]byte, 0, size)
}

// copyString copies b into the decoder's string arena and returns a string over it. Strings keep
// the arena alive through interior pointers, so the result stays valid after Unmarshal returns and
// never aliases the caller's input. | copyString 把 b 复制进解码器的字符串 arena 并返回其字符串；
// 字符串经内部指针保持 arena 存活，因此结果在 Unmarshal 返回后仍有效，也不会别名调用方输入。
func (d *decoder) copyString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	d.ensureArena()
	n := len(b)
	// Short strings are copied with fixed-size stores. b keeps the input's capacity, so an
	// eight-byte load may read bytes past its length but never past its capacity; the extra bytes
	// land beyond the new arena length and are overwritten or ignored. | 短字符串用定长存储复制。
	// b 保留输入的容量，因此 8 字节加载可能越过长度但绝不会越过容量；多余字节落在新 arena 长度
	// 之外，会被后续覆盖或忽略。
	if n <= 16 && cap(b) >= 8 {
		start := len(d.arena)
		need := n
		if n < 8 {
			need = 8
		}
		if cap(d.arena)-start >= need {
			dst := d.arena[start : start+need]
			if n >= 8 {
				binary.LittleEndian.PutUint64(dst, binary.LittleEndian.Uint64(b[:8]))
				binary.LittleEndian.PutUint64(dst[n-8:], binary.LittleEndian.Uint64(b[n-8:n]))
			} else {
				binary.LittleEndian.PutUint64(dst, binary.LittleEndian.Uint64(b[:8]))
			}
			d.arena = d.arena[:start+n]
			return unsafe.String(unsafe.SliceData(d.arena[start:]), n)
		}
	}
	d.ensureArenaSpare(n)
	start := len(d.arena)
	d.arena = append(d.arena, b...)
	return unsafe.String(unsafe.SliceData(d.arena[start:]), n)
}

// decoderPool reuses decoder state across Unmarshal calls. The string arena is append-only and is
// kept between calls, so a warmed decoder allocates no string storage; bytes referenced by strings
// already returned are never overwritten, and an oversized arena is dropped instead of retained. |
// decoderPool 在多次 Unmarshal 调用间复用解码器状态。字符串 arena 只追加并在调用间保留，因此预热
// 后的解码器不再为字符串分配存储；已返回字符串引用的字节绝不会被覆盖，过大的 arena 会被丢弃而不是
// 保留。
var decoderPool = sync.Pool{New: func() any { return new(decoder) }}

// Unmarshal parses data and stores the result in the value pointed to by v. | Unmarshal 解析 data 并写入 v 指向的值。
func Unmarshal(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errs.Detail(ErrTypeMismatch, "jsonx: Unmarshal target must be a non-nil pointer | jsonx：Unmarshal 目标必须是非 nil 指针")
	}
	d := decoderPool.Get().(*decoder)
	// Keep the append-only string arena and reset only the fields that carry state between
	// values; the timestamp cache is invalidated by timeLen. | 保留只追加的字符串 arena，只重置
	// 跨值携带状态的字段；时间戳缓存由 timeLen 失效。
	d.data = data
	d.pos = 0
	d.depth = 0
	d.useNumber = false
	d.skipLen = false
	d.timeLen = 0
	err := d.unmarshal(rv)
	d.data = nil
	if cap(d.arena) > maxArenaRetain {
		d.arena = nil
	}
	decoderPool.Put(d)
	// Classify the backend error so errors.Is(ErrSyntax/ErrTypeMismatch) behaves identically on
	// every backend; the native path used to return it raw. | 对后端错误归类，使
	// errors.Is(ErrSyntax/ErrTypeMismatch) 在各后端行为一致；原生路径过去直接返回原始错误。
	return wrapDecodeError(data, err)
}

// unmarshal decodes one top-level value into rv. | unmarshal 把一个顶层值解码进 rv。
func (d *decoder) unmarshal(rv reflect.Value) error {
	d.skipSpace()
	if d.pos >= len(d.data) {
		return syntaxErr("unexpected end of JSON input | JSON 输入意外结束")
	}
	target := rv.Elem()
	if target.Kind() == reflect.Slice && target.IsNil() && d.data[d.pos] == '[' &&
		fastStructDecFor(target.Type().Elem()) == nil {
		// Bound the guess by bytes, not by element count: guessing 1<<20 elements of a 32 KiB
		// struct would allocate ~32 GiB before parsing a single byte. | 以字节数而不是元素个数限定预分配：
		// 对 32 KiB 的结构体猜 1<<20 个元素，会在解析第一个字节前分配约 32 GiB。
		const maxPreallocBytes = 4 << 20
		elemSize := int(target.Type().Elem().Size())
		if elemSize <= 0 {
			elemSize = 1
		}
		maxElems := maxPreallocBytes / elemSize
		// 64 bytes per element matches a typical compact object and deliberately over-guesses
		// rather than triggering a doubling growth that would allocate both the guess and its
		// replacement; maxElems and the 4 MiB ceiling bound the over-allocation. | 每个元素按
		// 64 字节估算，符合常见紧凑对象，并有意偏大，避免触发一次会让估算数组和替代数组同时
		// 分配的翻倍扩容；maxElems 与 4 MiB 上限约束过度分配。
		guess := len(d.data) / 64
		if guess > maxElems {
			guess = maxElems
		}
		if guess > 0 {
			target.Set(reflect.MakeSlice(target.Type(), guess, guess))
			d.skipLen = true
		}
	}
	if err := d.decodeTarget(target); err != nil {
		return err
	}
	d.skipSpace()
	if d.pos != len(d.data) {
		return syntaxErr("invalid character %q after top-level value | 顶层值之后的非法字符 %q", d.data[d.pos], d.data[d.pos])
	}
	return nil
}

// decodeTarget decodes into a top-level target, using the direct-memory struct decoder when the
// destination is an addressable struct and the type has no competing unmarshal method. This skips
// the decoder lookup and reflection wrapper that steady-state struct decodes otherwise pay. |
// decodeTarget 解码顶层目标：当目标是可寻址结构体且类型没有竞争的解码方法时，直接使用按内存的
// 结构体解码器，省去稳态结构体解码原本要付出的解码器查找与反射包装。
func (d *decoder) decodeTarget(target reflect.Value) error {
	if target.Kind() == reflect.Struct && target.CanAddr() {
		if info := fastStructDecFor(target.Type()); info != nil {
			return info.dec(d, unsafe.Pointer(target.UnsafeAddr()))
		}
	}
	return d.value(target)
}

// skipSpace advances past JSON whitespace. | skipSpace 跳过 JSON 空白。
func (d *decoder) skipSpace() {
	d.pos = skipSpaceRun(d.data, d.pos)
}

// decodeFunc decodes one JSON value into a fixed Go type. | decodeFunc 把一个 JSON 值解析进固定 Go 类型。
type decodeFunc func(*decoder, reflect.Value) error

// decodeCache maps each reflected type to its compiled decoder. | decodeCache 把反射类型映射到已编译的解码器。
var decodeCache sync.Map

// decodeFast mirrors encodeFast for decoders: the hot path resolves the same few types on every
// call, so a handful of atomic slots avoids hashing a reflect.Type via sync.Map each time.
// | decodeFast 是解码器侧与 encodeFast 对应的前置缓存：热路径每次只解析固定几种类型，几个原子槽
// 即可避免每次都经 sync.Map 哈希 reflect.Type。
const decodeFastSlots = 4

type decodeFastEntry struct {
	typ reflect.Type
	fn  decodeFunc
}

var (
	decodeFast  [decodeFastSlots]atomic.Pointer[decodeFastEntry]
	decodeFastN atomic.Uint32
	decodeFastL atomic.Uint32 // index of the most recent slot, a lookup hint | 最近使用槽位的索引，仅作查找提示
)

// decoderFor returns the cached decoder for t, building it on first use. | decoderFor 返回 t 的缓存解码器，
// 首次调用时构建。
func decoderFor(t reflect.Type) decodeFunc {
	// See encoderFor: the hint turns the steady single-type case into one atomic load and one
	// comparison, and a stale hint stays correct because the slot is compared by type. | 参见
	// encoderFor：提示位把单一类型稳态降为一次原子加载与一次比较，提示过期也仍正确，因为槽位按类型比较。
	last := decodeFastL.Load()
	if last < decodeFastSlots {
		if e := decodeFast[last].Load(); e != nil && e.typ == t {
			return e.fn
		}
	}
	for i := range decodeFast {
		if uint32(i) == last {
			continue
		}
		if e := decodeFast[i].Load(); e != nil && e.typ == t {
			return e.fn
		}
	}
	var f decodeFunc
	if v, ok := decodeCache.Load(t); ok {
		f = v.(decodeFunc)
	} else {
		f = buildDecoder(t)
		decodeCache.Store(t, f)
	}
	slot := decodeFastN.Add(1) % decodeFastSlots
	decodeFast[slot].Store(&decodeFastEntry{typ: t, fn: f})
	decodeFastL.Store(slot)
	return f
}

func (d *decoder) value(v reflect.Value) error {
	d.skipSpace()
	if d.pos >= len(d.data) {
		return syntaxErr("unexpected end of JSON input | JSON 输入意外结束")
	}
	return decoderFor(v.Type())(d, v)
}

// lazyDecoder defers resolving an element decoder until the first value is decoded.
// 延迟到首次解码时才解析元素解码器，使递归类型不会在构建期无限递归。
func lazyDecoder(t reflect.Type) func() decodeFunc {
	var slot atomic.Pointer[decodeFunc]
	return func() decodeFunc {
		if f := slot.Load(); f != nil {
			return *f
		}
		f := decoderFor(t)
		slot.Store(&f)
		return f
	}
}

func buildDecoder(t reflect.Type) decodeFunc {
	if t == rawMessageType {
		return func(d *decoder, v reflect.Value) error {
			raw, err := d.captureValue()
			if err != nil {
				return err
			}
			v.SetBytes(raw)
			return nil
		}
	}
	if t == numberType {
		return func(d *decoder, v reflect.Value) error {
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of JSON input | JSON 输入意外结束")
			}
			if d.data[d.pos] == 'n' {
				// null leaves json.Number untouched and is not an error, matching encoding/json.
				// | null 不修改 json.Number 且不算错误，与 encoding/json 一致。
				return d.literal("null")
			}
			if d.data[d.pos] == '"' {
				s, err := d.parseString()
				if err != nil {
					return err
				}
				// A quoted value must still be a number; accepting "abc" would defer the
				// failure to Int64/Float64 and lose the original context. | 引号内的取值仍必须是
				// 数字；接受 "abc" 只会把失败推迟到 Int64/Float64，并丢掉原始上下文。
				if !isValidNumber(s) {
					return typeErr("invalid number literal %q | 非法数字字面量 %q", s, s)
				}
				v.SetString(s)
				return nil
			}
			s, err := d.parseNumber()
			if err != nil {
				return err
			}
			v.SetString(s)
			return nil
		}
	}
	if t.Kind() == reflect.Interface {
		if t.NumMethod() == 0 {
			return func(d *decoder, v reflect.Value) error {
				x, err := d.valueAny()
				if err != nil {
					return err
				}
				if x == nil {
					v.SetZero()
				} else {
					v.Set(reflect.ValueOf(x))
				}
				return nil
			}
		}
		return func(d *decoder, v reflect.Value) error {
			if err := d.literal("null"); err == nil {
				v.SetZero()
				return nil
			}
			return typeErr("cannot unmarshal into non-empty interface %s | 无法解析进非空接口 %s", t, t)
		}
	}
	tr := cachedTraits(t)
	if t.Kind() == reflect.Pointer {
		elem := lazyDecoder(t.Elem())
		switch {
		case tr.unmarshaler:
			return func(d *decoder, v reflect.Value) error {
				if d.data[d.pos] == 'n' {
					if err := d.literal("null"); err != nil {
						return err
					}
					v.SetZero()
					return nil
				}
				if v.IsNil() {
					v.Set(reflect.New(t.Elem()))
				}
				return decodeUnmarshaler(d, v)
			}
		case tr.textUnmarshaler:
			return func(d *decoder, v reflect.Value) error {
				if d.data[d.pos] == 'n' {
					if err := d.literal("null"); err != nil {
						return err
					}
					v.SetZero()
					return nil
				}
				if d.data[d.pos] == '"' {
					if v.IsNil() {
						v.Set(reflect.New(t.Elem()))
					}
					return decodeTextUnmarshaler(d, v)
				}
				if v.IsNil() {
					v.Set(reflect.New(t.Elem()))
				}
				return elem()(d, v.Elem())
			}
		default:
			return func(d *decoder, v reflect.Value) error {
				if d.data[d.pos] == 'n' {
					if err := d.literal("null"); err != nil {
						return err
					}
					v.SetZero()
					return nil
				}
				if v.IsNil() {
					v.Set(reflect.New(t.Elem()))
				}
				return elem()(d, v.Elem())
			}
		}
	}
	if tr.unmarshaler {
		return func(d *decoder, v reflect.Value) error {
			return decodeUnmarshaler(d, v)
		}
	}
	norm := buildKindDecoder(t)
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return func(d *decoder, v reflect.Value) error {
			if v.CanAddr() {
				return decodeUnmarshaler(d, v.Addr())
			}
			return norm(d, v)
		}
	}
	if tr.textUnmarshaler {
		return func(d *decoder, v reflect.Value) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			if d.data[d.pos] == '"' {
				return decodeTextUnmarshaler(d, v)
			}
			return typeErr("cannot unmarshal non-string into %s | 无法把非字符串解析进 %s", t, t)
		}
	}
	if reflect.PointerTo(t).Implements(textUnmarshalerType) {
		return func(d *decoder, v reflect.Value) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			if d.data[d.pos] == '"' {
				if v.CanAddr() {
					return decodeTextUnmarshaler(d, v.Addr())
				}
				return norm(d, v)
			}
			return typeErr("cannot unmarshal non-string into %s | 无法把非字符串解析进 %s", t, t)
		}
	}
	return norm
}

func decodeUnmarshaler(d *decoder, v reflect.Value) error {
	raw, err := d.captureValueView()
	if err != nil {
		return err
	}
	return v.Interface().(stdjson.Unmarshaler).UnmarshalJSON(raw)
}

func decodeTextUnmarshaler(d *decoder, v reflect.Value) error {
	s, err := d.parseString()
	if err != nil {
		return err
	}
	return v.Interface().(encoding.TextUnmarshaler).UnmarshalText([]byte(s))
}

// fastStructDecInfo describes a struct whose every field has a direct-memory decoder. |
// fastStructDecInfo 描述所有字段都可直接按内存解码的结构体。
type fastStructDecInfo struct {
	dec  func(*decoder, unsafe.Pointer) error
	size uintptr
}

var (
	fastStructDecCache sync.Map
	fastStructDecLast  atomic.Pointer[fastStructDecEntry]
)

// fastStructDecEntry is the most recently resolved type, including a nil decision, so repeated
// decodes of one type avoid the map lookup. | fastStructDecEntry 保存最近解析的类型（含 nil 判定），
// 使同一类型的连续解码免去映射查找。
type fastStructDecEntry struct {
	typ  reflect.Type
	info *fastStructDecInfo
}

// fastStructDecFor returns the direct-memory struct decoder for t, if one was built and the
// type's own unmarshal methods do not take precedence. | fastStructDecFor 返回 t 的直接按内存解码器
// （若已构建且类型自身的解码方法不优先）。
func fastStructDecFor(t reflect.Type) *fastStructDecInfo {
	if e := fastStructDecLast.Load(); e != nil && e.typ == t {
		return e.info
	}
	info := lookupFastStructDec(t)
	fastStructDecLast.Store(&fastStructDecEntry{typ: t, info: info})
	return info
}

func lookupFastStructDec(t reflect.Type) *fastStructDecInfo {
	if v, ok := fastStructDecCache.Load(t); ok {
		return v.(*fastStructDecInfo)
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	tr := cachedTraits(t)
	if tr.unmarshaler || tr.textUnmarshaler ||
		reflect.PointerTo(t).Implements(unmarshalerType) ||
		reflect.PointerTo(t).Implements(textUnmarshalerType) {
		return nil
	}
	decoderFor(t)
	if v, ok := fastStructDecCache.Load(t); ok {
		return v.(*fastStructDecInfo)
	}
	return nil
}

func buildStructDecoder(t reflect.Type) decodeFunc {
	info := cachedStruct(t)
	type decField struct {
		fast      fastFieldDec
		dec       func() decodeFunc
		index     []int
		offset    uintptr
		fastOK    bool
		quoted    bool
		rawQuoted bool
	}
	fields := make([]*decField, len(info.fields))
	names := make([]string, len(info.fields))
	anyFast := false
	allFast := true
	for i, f := range info.fields {
		offset, fastOK := fieldOffset(t, f.index)
		fast := buildFastFieldDecoder(f.typ)
		// A field with the ,string option must go through the destring wrapper, never the direct
		// fast-field decoder. Custom unmarshal methods take precedence over the option, exactly
		// like encoding/json. | 带 ,string 选项的字段必须走 destring 包装，绝不能走直接快速字段
		// 解码器；自定义解码方法优先于该选项，与 encoding/json 一致。
		destring := f.quoted && !hasUnmarshalMethod(f.typ)
		isFast := fastOK && fast != nil && !destring
		fields[i] = &decField{
			index: f.index, offset: offset, fast: fast, dec: lazyDecoder(f.typ),
			fastOK: isFast, quoted: destring, rawQuoted: f.quoted && !destring,
		}
		names[i] = f.name
		if isFast {
			anyFast = true
		} else {
			allFast = false
		}
	}
	var lookup func(string) (*decField, bool)
	var matchKey func(*decoder) (*decField, bool)
	matchKey = func(*decoder) (*decField, bool) { return nil, false }
	if len(names) <= 8 {
		var byLen [33][]int
		var byFirst [256][]int
		var single [256]int16 // index+1 for first-byte buckets with one candidate | 单候选首字节桶的索引+1
		keyBytes := make([][]byte, len(names))
		keyWords := make([]uint64, len(names))
		keyTails := make([]uint64, len(names))
		keyMasks := make([]uint64, len(names))
		keyLens := make([]int, len(names))
		for i, name := range names {
			kb := make([]byte, 0, len(name)+2)
			kb = append(kb, name...)
			kb = append(kb, '"', ':')
			keyBytes[i] = kb
			l := len(kb)
			keyLens[i] = l
			// Keys up to eight bytes are compared with one masked word. Longer keys use the first
			// and last eight bytes, which avoids a memequal call for the common 9-16 byte names. |
			// 不超过八字节的键用一次掩码比较；更长的键比较首尾两个八字，避免为常见的 9-16 字节
			// 字段名走 memequal。
			if l >= 8 {
				keyWords[i] = binary.LittleEndian.Uint64(kb)
				keyTails[i] = binary.LittleEndian.Uint64(kb[l-8:])
				keyMasks[i] = ^uint64(0)
			} else {
				var w uint64
				for j := 0; j < l; j++ {
					w |= uint64(kb[j]) << (8 * j)
				}
				keyWords[i] = w
				keyMasks[i] = uint64(1)<<(8*l) - 1
			}
			if l := len(name); l < len(byLen) {
				byLen[l] = append(byLen[l], i)
			}
			if len(name) > 0 {
				byFirst[name[0]] = append(byFirst[name[0]], i)
			}
		}
		for b := range byFirst {
			if len(byFirst[b]) == 1 {
				single[b] = int16(byFirst[b][0]) + 1
			}
		}
		matchKey = func(d *decoder) (*decField, bool) {
			if d.pos+1 >= len(d.data) {
				return nil, false
			}
			rem := d.data[d.pos+1:]
			if si := single[d.data[d.pos+1]]; si != 0 {
				// Most first-byte buckets hold exactly one field. Match it directly and fail
				// without scanning when it does not match, since no other candidate exists. |
				// 多数首字节桶只含一个字段：直接匹配；不匹配时无需扫描即可失败，因为没有其他候选。
				i := int(si - 1)
				l := keyLens[i]
				if l <= 8 {
					if len(rem) >= 8 {
						x := binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(rem), 8)) ^ keyWords[i]
						if x&keyMasks[i] == 0 {
							d.pos += 1 + l
							return fields[i], true
						}
						return nil, false
					}
				} else if len(rem) >= l {
					if binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(rem), 8)) == keyWords[i] &&
						binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(rem[l-8:]), 8)) == keyTails[i] {
						d.pos += 1 + l
						return fields[i], true
					}
					return nil, false
				}
				if len(rem) >= l && bytes.HasPrefix(rem, keyBytes[i]) {
					d.pos += 1 + l
					return fields[i], true
				}
				return nil, false
			}
			for _, i := range byFirst[d.data[d.pos+1]] {
				l := keyLens[i]
				if l <= 8 {
					if len(rem) >= 8 {
						x := binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(rem), 8)) ^ keyWords[i]
						if x&keyMasks[i] == 0 {
							d.pos += 1 + l
							return fields[i], true
						}
						continue
					}
				} else if len(rem) >= l {
					if binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(rem), 8)) == keyWords[i] &&
						binary.LittleEndian.Uint64(unsafe.Slice(unsafe.SliceData(rem[l-8:]), 8)) == keyTails[i] {
						d.pos += 1 + l
						return fields[i], true
					}
					continue
				}
				kb := keyBytes[i]
				if len(rem) >= l && bytes.HasPrefix(rem, kb) {
					d.pos += 1 + l
					return fields[i], true
				}
			}
			return nil, false
		}
		lookup = func(key string) (*decField, bool) {
			if l := len(key); l < len(byLen) {
				for _, i := range byLen[l] {
					if key == names[i] {
						return fields[i], true
					}
				}
			} else {
				for i := range names {
					if key == names[i] {
						return fields[i], true
					}
				}
			}
			for i := range names {
				if strings.EqualFold(key, names[i]) {
					return fields[i], true
				}
			}
			return nil, false
		}
	} else {
		byName := make(map[string]int, len(names))
		for i, name := range names {
			byName[name] = i
		}
		// Exact matches use the map; case-insensitive matches must use strings.EqualFold rather
		// than a lower-cased map, because Unicode simple folding (e.g. 'ſ' and 's') is not the
		// same relation as ToLower equality. | 精确匹配走映射；大小写不敏感匹配必须使用
		// strings.EqualFold，而不能用转小写映射——Unicode 简单折叠（如 'ſ' 与 's'）与
		// ToLower 相等的语义并不相同。
		lookup = func(key string) (*decField, bool) {
			if i, ok := byName[key]; ok {
				return fields[i], true
			}
			for i := range names {
				if strings.EqualFold(key, names[i]) {
					return fields[i], true
				}
			}
			return nil, false
		}
	}
	var fastDec func(*decoder, unsafe.Pointer) error
	if allFast {
		// The all-fast loop writes every field through the pointer base, with no reflect.Value,
		// no per-field capability checks and no deferred leave on the success path. It is shared
		// by addressable struct values and by the direct-memory []struct decoder. | 全快速循环
		// 通过指针基址写入每个字段，不创建 reflect.Value、不逐字段检查能力，成功路径也不使用
		// defer 收尾；可寻址结构体值与直接按内存解码的 []struct 解码器共享该循环。
		fastDec = func(d *decoder, base unsafe.Pointer) error {
			if d.data[d.pos] == 'n' {
				return d.literal("null")
			}
			if err := d.enter(); err != nil {
				return err
			}
			if d.data[d.pos] != '{' {
				return typeErr("cannot unmarshal non-object into %s | 无法把非对象解析进 %s", t, t)
			}
			d.pos++
			d.skipSpace()
			if d.pos < len(d.data) && d.data[d.pos] == '}' {
				d.pos++
				d.leave()
				return nil
			}
			for {
				if d.pos >= len(d.data) || d.data[d.pos] != '"' {
					return syntaxErr("expected object key | 期望对象键")
				}
				f, ok := matchKey(d)
				if !ok {
					key, err := d.parseKey()
					if err != nil {
						return err
					}
					d.skipSpace()
					if d.pos >= len(d.data) || d.data[d.pos] != ':' {
						return syntaxErr("expected ':' after object key | 对象键之后期望 ':'")
					}
					d.pos++
					f, ok = lookup(key)
				}
				d.skipSpace()
				if d.pos >= len(d.data) {
					return syntaxErr("unexpected end of object | 对象意外结束")
				}
				if !ok {
					if err := d.skipValue(); err != nil {
						return err
					}
				} else if err := f.fast(d, unsafe.Add(base, f.offset)); err != nil {
					return err
				}
				if d.pos < len(d.data) {
					switch d.data[d.pos] {
					case ',':
						d.pos++
						d.skipSpace()
						continue
					case '}':
						d.pos++
						d.leave()
						return nil
					}
				}
				d.skipSpace()
				if d.pos >= len(d.data) {
					return syntaxErr("unexpected end of object | 对象意外结束")
				}
				switch d.data[d.pos] {
				case ',':
					d.pos++
					d.skipSpace()
				case '}':
					d.pos++
					d.leave()
					return nil
				default:
					return syntaxErr("expected ',' or '}' in object | 对象中期望 ',' 或 '}'")
				}
			}
		}
		fastStructDecCache.Store(t, &fastStructDecInfo{dec: fastDec, size: t.Size()})
	}
	return func(d *decoder, v reflect.Value) error {
		if allFast && v.CanAddr() {
			return fastDec(d, unsafe.Pointer(v.UnsafeAddr()))
		}
		if d.data[d.pos] == 'n' {
			return d.literal("null")
		}
		if err := d.enter(); err != nil {
			return err
		}
		defer d.leave()
		if d.data[d.pos] != '{' {
			return typeErr("cannot unmarshal non-object into %s | 无法把非对象解析进 %s", t, t)
		}
		var base unsafe.Pointer
		if anyFast && v.CanAddr() {
			base = unsafe.Pointer(v.UnsafeAddr())
		}
		d.pos++
		d.skipSpace()
		if d.pos < len(d.data) && d.data[d.pos] == '}' {
			d.pos++
			return nil
		}
		for {
			if d.pos >= len(d.data) || d.data[d.pos] != '"' {
				return syntaxErr("expected object key | 期望对象键")
			}
			f, ok := matchKey(d)
			if !ok {
				key, err := d.parseKey()
				if err != nil {
					return err
				}
				d.skipSpace()
				if d.pos >= len(d.data) || d.data[d.pos] != ':' {
					return syntaxErr("expected ':' after object key | 对象键之后期望 ':'")
				}
				d.pos++
				f, ok = lookup(key)
			}
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of object | 对象意外结束")
			}
			if !ok {
				if err := d.skipValue(); err != nil {
					return err
				}
			} else if base != nil && f.fastOK {
				if err := f.fast(d, unsafe.Add(base, f.offset)); err != nil {
					return err
				}
			} else {
				fv, ok, err := fieldByIndexAlloc(v, f.index)
				if err != nil {
					return err
				}
				if !ok {
					if err := d.skipValue(); err != nil {
						return err
					}
				} else if f.quoted {
					if err := d.decodeQuotedField(fv); err != nil {
						return err
					}
				} else {
					start := -1
					if f.rawQuoted && fv.Kind() == reflect.Pointer {
						start = d.pos
					}
					if err := f.dec()(d, fv); err != nil {
						return err
					}
					// The pointer wrapper keeps the legacy quoted-null post-step even when a custom
					// method consumed the value. | 即使由自定义方法消费值，指针包装的旧版带引号 null 收尾仍然生效。
					if start >= 0 && string(d.data[start:d.pos]) == `"null"` {
						fv.SetZero()
					}
				}
			}
			if d.pos < len(d.data) {
				switch d.data[d.pos] {
				case ',':
					d.pos++
					d.skipSpace()
					continue
				case '}':
					d.pos++
					return nil
				}
			}
			d.skipSpace()
			if d.pos >= len(d.data) {
				return syntaxErr("unexpected end of object | 对象意外结束")
			}
			switch d.data[d.pos] {
			case ',':
				d.pos++
				d.skipSpace()
			case '}':
				d.pos++
				return nil
			default:
				return syntaxErr("expected ',' or '}' in object | 对象中期望 ',' 或 '}'")
			}
		}
	}
}

// fieldByIndexAlloc walks an index path and allocates nil embedded pointers on the way. It reports
// an error for an embedded pointer to an unexported struct type, which cannot be allocated through
// reflection; this matches encoding/json's behavior. | fieldByIndexAlloc 遍历索引路径，并在途中
// 分配为 nil 的嵌入指针；若嵌入指针指向未导出结构体类型（反射无法分配），则返回错误，与
// encoding/json 的行为一致。
func fieldByIndexAlloc(v reflect.Value, index []int) (reflect.Value, bool, error) {
	for _, i := range index {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				if !v.CanSet() {
					elem := v.Type().Elem()
					return reflect.Value{}, false, typeErr("cannot set embedded pointer to unexported struct %s | 无法设置指向未导出结构体的嵌入指针 %s", elem, elem)
				}
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct || i >= v.NumField() {
			return reflect.Value{}, false, nil
		}
		v = v.Field(i)
	}
	return v, v.CanSet(), nil
}
