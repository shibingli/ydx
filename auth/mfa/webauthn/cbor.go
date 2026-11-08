package webauthn

import (
	"bytes"
	"math"
	"sort"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
)

// Default CBOR decoding limits. | CBOR 解码的默认限制。
const (
	// DefaultMaxCBORDepth is the default maximum container nesting depth. | DefaultMaxCBORDepth 是默认的最大容器嵌套深度。
	DefaultMaxCBORDepth = 32
	// DefaultMaxCBORBytes is the default maximum input size accepted by Decode. | DefaultMaxCBORBytes 是 Decode 默认接受的最大输入长度。
	DefaultMaxCBORBytes = 1 << 20
	// maxCBOREncodeDepth bounds recursion while encoding caller-built values. | maxCBOREncodeDepth 限制编码调用方构造值时的递归深度。
	maxCBOREncodeDepth = 64
)

// Kind identifies a CBOR data item kind. | Kind 标识一种 CBOR 数据项类型。
type Kind uint8

// The CBOR data item kinds supported by this package. | 本包支持的 CBOR 数据项类型。
const (
	// KindUint is a major type 0 unsigned integer. | KindUint 是主类型 0 的无符号整数。
	KindUint Kind = iota + 1
	// KindNegInt is a major type 1 negative integer. | KindNegInt 是主类型 1 的负整数。
	KindNegInt
	// KindBytes is a major type 2 byte string. | KindBytes 是主类型 2 的字节串。
	KindBytes
	// KindText is a major type 3 text string. | KindText 是主类型 3 的文本串。
	KindText
	// KindArray is a major type 4 array. | KindArray 是主类型 4 的数组。
	KindArray
	// KindMap is a major type 5 map. | KindMap 是主类型 5 的映射。
	KindMap
	// KindTag is a major type 6 tag. | KindTag 是主类型 6 的标签。
	KindTag
	// KindSimple is a major type 7 simple value, including false, true, null and undefined. | KindSimple 是主类型 7 的简单值，包括 false、true、null 与 undefined。
	KindSimple
	// KindFloat is a major type 7 floating-point value. | KindFloat 是主类型 7 的浮点数。
	KindFloat
)

// Pair is one key/value entry of a CBOR map. | Pair 是 CBOR 映射的一个键值对。
type Pair struct {
	// Key is the encoded map key. | Key 是映射键。
	Key *Value
	// Value is the encoded map value. | Value 是映射值。
	Value *Value
}

// Value is a decoded or caller-built CBOR data item. | Value 是解码得到或调用方构造的 CBOR 数据项。
//
// Only the fields relevant to Kind are meaningful. Byte slices returned by the decoder are copies,
// so a Value never aliases the input buffer. | 只有与 Kind 相关的字段有意义。解码器返回的字节切片
// 均为副本，因此 Value 不会引用输入缓冲区。
type Value struct {
	// Kind is the data item kind. | Kind 是数据项类型。
	Kind Kind
	// UInt holds the value of a KindUint item. | UInt 保存 KindUint 项的值。
	UInt uint64
	// Neg holds the value of a KindNegInt item, encoding -1-Neg. | Neg 保存 KindNegInt 项的值，编码为 -1-Neg。
	Neg uint64
	// Bytes holds a KindBytes item. | Bytes 保存 KindBytes 项。
	Bytes []byte
	// Text holds a KindText item. | Text 保存 KindText 项。
	Text string
	// Array holds a KindArray item. | Array 保存 KindArray 项。
	Array []*Value
	// Pairs holds a KindMap item in encoded order. | Pairs 按编码顺序保存 KindMap 项。
	Pairs []Pair
	// Tag is the tag number of a KindTag item. | Tag 是 KindTag 项的标签号。
	Tag uint64
	// Inner is the tagged item of a KindTag item. | Inner 是 KindTag 项的内层数据。
	Inner *Value
	// Simple is the simple value of a KindSimple item. | Simple 是 KindSimple 项的简单值。
	Simple uint8
	// Float is the number of a KindFloat item. | Float 是 KindFloat 项的数值。
	Float float64
}

// NewUint returns an unsigned integer value. | NewUint 返回无符号整数值。
func NewUint(v uint64) *Value { return &Value{Kind: KindUint, UInt: v} }

// NewInt returns an integer value, choosing the unsigned or negative representation. | NewInt 返回整数值，自动选择无符号或负数表示。
func NewInt(v int64) *Value {
	if v >= 0 {
		return &Value{Kind: KindUint, UInt: uint64(v)}
	}
	return &Value{Kind: KindNegInt, Neg: uint64(-(v + 1))}
}

// NewBytes returns a byte string value holding a copy of b. | NewBytes 返回保存 b 副本的字节串值。
func NewBytes(b []byte) *Value {
	return &Value{Kind: KindBytes, Bytes: append([]byte(nil), b...)}
}

// NewText returns a text string value. | NewText 返回文本串值。
func NewText(s string) *Value { return &Value{Kind: KindText, Text: s} }

// NewArray returns an array value. | NewArray 返回数组值。
func NewArray(items ...*Value) *Value { return &Value{Kind: KindArray, Array: items} }

// NewMap returns a map value. Duplicate keys are rejected by Encode. | NewMap 返回映射值。Encode 会拒绝重复键。
func NewMap(pairs ...Pair) *Value {
	return &Value{Kind: KindMap, Pairs: append([]Pair(nil), pairs...)}
}

// NewBool returns a CBOR true or false value. | NewBool 返回 CBOR true 或 false 值。
func NewBool(v bool) *Value {
	if v {
		return &Value{Kind: KindSimple, Simple: 21}
	}
	return &Value{Kind: KindSimple, Simple: 20}
}

// NewNull returns the CBOR null value. | NewNull 返回 CBOR null 值。
func NewNull() *Value { return &Value{Kind: KindSimple, Simple: 22} }

// NewFloat returns a floating-point value. | NewFloat 返回浮点数值。
func NewFloat(v float64) *Value { return &Value{Kind: KindFloat, Float: v} }

// NewTag returns a tagged value. | NewTag 返回带标签的值。
func NewTag(number uint64, inner *Value) *Value {
	return &Value{Kind: KindTag, Tag: number, Inner: inner}
}

// IsNull reports whether v is the CBOR null value. | IsNull 报告 v 是否为 CBOR null 值。
func (v *Value) IsNull() bool {
	return v != nil && v.Kind == KindSimple && v.Simple == 22
}

// AsInt64 returns the integer value of v when it fits in int64. | 当 v 的整数可用 int64 表示时，AsInt64 返回该值。
func (v *Value) AsInt64() (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch v.Kind {
	case KindUint:
		if v.UInt <= math.MaxInt64 {
			return int64(v.UInt), true
		}
	case KindNegInt:
		if v.Neg <= math.MaxInt64 {
			return -1 - int64(v.Neg), true
		}
	}
	return 0, false
}

// AsUint64 returns the unsigned value of a non-negative integer. | AsUint64 返回非负整数的无符号值。
func (v *Value) AsUint64() (uint64, bool) {
	if v == nil || v.Kind != KindUint {
		return 0, false
	}
	return v.UInt, true
}

// AsBytes returns the byte string value of v. | AsBytes 返回 v 的字节串值。
func (v *Value) AsBytes() ([]byte, bool) {
	if v == nil || v.Kind != KindBytes {
		return nil, false
	}
	return v.Bytes, true
}

// AsText returns the text string value of v. | AsText 返回 v 的文本串值。
func (v *Value) AsText() (string, bool) {
	if v == nil || v.Kind != KindText {
		return "", false
	}
	return v.Text, true
}

// MapGetText returns the value stored under a text key. | MapGetText 返回文本键对应的值。
func (v *Value) MapGetText(key string) (*Value, bool) {
	if v == nil || v.Kind != KindMap {
		return nil, false
	}
	for i := range v.Pairs {
		if v.Pairs[i].Key != nil && v.Pairs[i].Key.Kind == KindText && v.Pairs[i].Key.Text == key {
			return v.Pairs[i].Value, true
		}
	}
	return nil, false
}

// MapGetInt returns the value stored under an integer key. | MapGetInt 返回整数键对应的值。
func (v *Value) MapGetInt(key int64) (*Value, bool) {
	if v == nil || v.Kind != KindMap {
		return nil, false
	}
	for i := range v.Pairs {
		k := v.Pairs[i].Key
		if k == nil {
			continue
		}
		switch k.Kind {
		case KindUint:
			if key >= 0 && k.UInt == uint64(key) {
				return v.Pairs[i].Value, true
			}
		case KindNegInt:
			if key < 0 && k.Neg == uint64(-(key+1)) {
				return v.Pairs[i].Value, true
			}
		}
	}
	return nil, false
}

// DecodeOptions bounds CBOR decoding. The zero value selects the package defaults. | DecodeOptions 约束 CBOR 解码；零值使用包默认限制。
type DecodeOptions struct {
	// MaxDepth is the maximum container nesting depth. | MaxDepth 是最大容器嵌套深度。
	MaxDepth int
	// MaxBytes is the maximum input size. | MaxBytes 是最大输入长度。
	MaxBytes int
}

func (o DecodeOptions) normalized() DecodeOptions {
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxCBORDepth
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxCBORBytes
	}
	return o
}

// Decode decodes exactly one CBOR data item from data. | Decode 从 data 解码恰好一个 CBOR 数据项。
//
// Trailing bytes are rejected. Malformed input never panics; it returns ErrInvalidCBOR, and input
// exceeding the depth or size limits returns ErrCBORLimit. | 尾随字节会被拒绝。非法输入不会 panic，
// 而是返回 ErrInvalidCBOR；超过深度或大小限制时返回 ErrCBORLimit。
func Decode(data []byte, opts ...DecodeOptions) (*Value, error) {
	v, n, err := DecodeFirst(data, opts...)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, errs.Detail(ErrInvalidCBOR, "%d trailing bytes | %d 个尾随字节", len(data)-n, len(data)-n)
	}
	return v, nil
}

// DecodeFirst decodes one CBOR data item and returns it with the number of consumed bytes. | DecodeFirst 解码一个 CBOR 数据项，并返回该值及消费的字节数。
func DecodeFirst(data []byte, opts ...DecodeOptions) (*Value, int, error) {
	o := DecodeOptions{}
	if len(opts) > 0 {
		o = opts[0]
	}
	o = o.normalized()
	if len(data) > o.MaxBytes {
		return nil, 0, errs.Detail(ErrCBORLimit, "input is %d bytes, limit is %d | 输入 %d 字节，限制 %d", len(data), o.MaxBytes, len(data), o.MaxBytes)
	}
	d := &decoder{data: data, maxDepth: o.MaxDepth}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.off, nil
}

// Encode encodes v using deterministic (canonical) CBOR. | Encode 使用确定性（规范）CBOR 编码 v。
//
// Maps are sorted by the bytewise lexicographic order of their encoded keys, and duplicate keys
// are rejected. The encoding prefers the shortest floating-point representation. Indefinite-length
// items are never produced. | 映射按键的编码字节按字典序排序，重复键会被拒绝。浮点数采用最短可
// 往返表示。编码结果不会包含不定长度项。
func Encode(v *Value) ([]byte, error) {
	return appendCBOR(nil, v, 0)
}

func appendCBOR(dst []byte, v *Value, depth int) ([]byte, error) {
	if v == nil {
		return nil, errs.Detail(ErrInvalidCBOR, "nil value | 空值")
	}
	if depth > maxCBOREncodeDepth {
		return nil, errs.Detail(ErrCBORLimit, "encoding depth exceeds %d | 编码深度超过 %d", maxCBOREncodeDepth, maxCBOREncodeDepth)
	}
	switch v.Kind {
	case KindUint:
		return appendHead(dst, 0, v.UInt), nil
	case KindNegInt:
		return appendHead(dst, 1, v.Neg), nil
	case KindBytes:
		dst = appendHead(dst, 2, uint64(len(v.Bytes)))
		return append(dst, v.Bytes...), nil
	case KindText:
		if !utf8.ValidString(v.Text) {
			return nil, errs.Detail(ErrInvalidCBOR, "text string is not valid UTF-8 | 文本串不是合法 UTF-8")
		}
		dst = appendHead(dst, 3, uint64(len(v.Text)))
		return append(dst, v.Text...), nil
	case KindArray:
		dst = appendHead(dst, 4, uint64(len(v.Array)))
		var err error
		for _, item := range v.Array {
			dst, err = appendCBOR(dst, item, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return dst, nil
	case KindMap:
		return appendMap(dst, v.Pairs, depth)
	case KindTag:
		dst = appendHead(dst, 6, v.Tag)
		return appendCBOR(dst, v.Inner, depth+1)
	case KindSimple:
		if v.Simple <= 23 {
			return append(dst, 0xe0|v.Simple), nil
		}
		if v.Simple >= 24 && v.Simple <= 31 {
			return nil, errs.Detail(ErrInvalidCBOR, "simple value %d is reserved | 简单值 %d 为保留值", v.Simple, v.Simple)
		}
		return append(dst, 0xf8, v.Simple), nil
	case KindFloat:
		return appendFloat(dst, v.Float), nil
	default:
		return nil, errs.Detail(ErrInvalidCBOR, "unknown kind %d | 未知类型 %d", v.Kind, v.Kind)
	}
}

type encodedPair struct {
	key []byte
	val []byte
}

func appendMap(dst []byte, pairs []Pair, depth int) ([]byte, error) {
	encoded := make([]encodedPair, 0, len(pairs))
	for i := range pairs {
		kb, err := appendCBOR(nil, pairs[i].Key, depth+1)
		if err != nil {
			return nil, err
		}
		vb, err := appendCBOR(nil, pairs[i].Value, depth+1)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, encodedPair{key: kb, val: vb})
	}
	sort.Slice(encoded, func(i, j int) bool { return bytes.Compare(encoded[i].key, encoded[j].key) < 0 })
	for i := 1; i < len(encoded); i++ {
		if bytes.Equal(encoded[i-1].key, encoded[i].key) {
			return nil, errs.Detail(ErrInvalidCBOR, "duplicate map key | 重复的映射键")
		}
	}
	dst = appendHead(dst, 5, uint64(len(encoded)))
	for i := range encoded {
		dst = append(dst, encoded[i].key...)
		dst = append(dst, encoded[i].val...)
	}
	return dst, nil
}

func appendHead(dst []byte, major byte, arg uint64) []byte {
	switch {
	case arg < 24:
		return append(dst, major<<5|byte(arg))
	case arg <= math.MaxUint8:
		return append(dst, major<<5|24, byte(arg))
	case arg <= math.MaxUint16:
		return append(dst, major<<5|25, byte(arg>>8), byte(arg))
	case arg <= math.MaxUint32:
		return append(dst, major<<5|26, byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	default:
		return append(dst, major<<5|27,
			byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
}

func appendFloat(dst []byte, f float64) []byte {
	if math.IsNaN(f) {
		return append(dst, 0xf9, 0x7e, 0x00)
	}
	if h, ok := float64ToHalf(f); ok {
		return append(dst, 0xf9, byte(h>>8), byte(h))
	}
	if f32 := float32(f); float64(f32) == f {
		bits := math.Float32bits(f32)
		return append(dst, 0xfa, byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
	}
	bits := math.Float64bits(f)
	return append(dst, 0xfb,
		byte(bits>>56), byte(bits>>48), byte(bits>>40), byte(bits>>32),
		byte(bits>>24), byte(bits>>16), byte(bits>>8), byte(bits))
}

// float64ToHalf converts f to IEEE 754 binary16, reporting whether the conversion round-trips
// exactly. NaN converts to the canonical quiet NaN. | float64ToHalf 把 f 转换为 IEEE 754 binary16，
// 并报告转换是否精确往返。NaN 转换为规范静默 NaN。
func float64ToHalf(f float64) (uint16, bool) {
	if math.IsNaN(f) {
		return 0x7e00, true
	}
	f32 := float32(f)
	if float64(f32) != f {
		return 0, false
	}
	bits := math.Float32bits(f32)
	sign := uint16((bits>>31)&1) << 15
	exp := int((bits >> 23) & 0xff)
	mant := bits & 0x7fffff
	if exp == 0xff {
		if mant != 0 {
			return 0x7e00, true
		}
		return sign | 0x7c00, true
	}
	if exp == 0 {
		// Every non-zero float32 subnormal is smaller than the smallest binary16 subnormal, so no
		// binary16 value can represent it exactly. | 非零 float32 次正规数都小于 binary16 的最小
		// 次正规数，因此任何 binary16 值都无法精确表示。
		if mant != 0 {
			return 0, false
		}
		return sign, true
	}
	e := exp - 127
	var h uint16
	switch {
	case e > 15:
		return 0, false
	case e >= -14:
		m := mant >> 13
		rem := mant & 0x1fff
		h = uint16(e+15)<<10 | uint16(m)
		if rem > 0x1000 || (rem == 0x1000 && m&1 == 1) {
			h++
		}
		if (h>>10)&0x1f == 0x1f {
			return 0, false
		}
	case e >= -24:
		shift := uint(-e - 1)
		base := uint32(1)<<23 | mant
		h = uint16(base >> shift)
		rem := base & ((uint32(1) << shift) - 1)
		halfway := uint32(1) << (shift - 1)
		if rem > halfway || (rem == halfway && h&1 == 1) {
			h++
		}
	default:
		return 0, false
	}
	h |= sign
	if halfToFloat64(h) != f {
		return 0, false
	}
	return h, true
}

func halfToFloat64(h uint16) float64 {
	sign := uint64(h>>15) << 63
	exp := int((h >> 10) & 0x1f)
	frac := uint64(h & 0x3ff)
	switch exp {
	case 0:
		if frac == 0 {
			return math.Float64frombits(sign)
		}
		value := math.Ldexp(float64(frac), -24)
		if sign != 0 {
			value = -value
		}
		return value
	case 0x1f:
		if frac == 0 {
			if sign != 0 {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		return math.NaN()
	default:
		value := math.Ldexp(1+float64(frac)/1024, exp-15)
		if sign != 0 {
			value = -value
		}
		return value
	}
}

type decoder struct {
	data     []byte
	off      int
	maxDepth int
}

func (d *decoder) remaining() int { return len(d.data) - d.off }

func (d *decoder) readByte() (byte, error) {
	if d.off >= len(d.data) {
		return 0, errs.Detail(ErrInvalidCBOR, "unexpected end of input | 输入意外结束")
	}
	b := d.data[d.off]
	d.off++
	return b, nil
}

func (d *decoder) readN(n int) ([]byte, error) {
	if n < 0 || n > d.remaining() {
		return nil, errs.Detail(ErrInvalidCBOR, "truncated input | 输入被截断")
	}
	b := d.data[d.off : d.off+n]
	d.off += n
	return b, nil
}

func (d *decoder) head() (major byte, ai byte, arg uint64, indef bool, err error) {
	b, err := d.readByte()
	if err != nil {
		return 0, 0, 0, false, err
	}
	major = b >> 5
	ai = b & 0x1f
	switch {
	case ai < 24:
		return major, ai, uint64(ai), false, nil
	case ai == 24:
		v, err := d.readByte()
		if err != nil {
			return 0, 0, 0, false, err
		}
		return major, ai, uint64(v), false, nil
	case ai == 25:
		v, err := d.readN(2)
		if err != nil {
			return 0, 0, 0, false, err
		}
		return major, ai, uint64(v[0])<<8 | uint64(v[1]), false, nil
	case ai == 26:
		v, err := d.readN(4)
		if err != nil {
			return 0, 0, 0, false, err
		}
		return major, ai, uint64(v[0])<<24 | uint64(v[1])<<16 | uint64(v[2])<<8 | uint64(v[3]), false, nil
	case ai == 27:
		v, err := d.readN(8)
		if err != nil {
			return 0, 0, 0, false, err
		}
		var x uint64
		for i := 0; i < 8; i++ {
			x = x<<8 | uint64(v[i])
		}
		return major, ai, x, false, nil
	case ai == 31:
		return major, ai, 0, true, nil
	default:
		return 0, 0, 0, false, errs.Detail(ErrInvalidCBOR, "reserved additional information %d | 保留的附加信息 %d", ai, ai)
	}
}

func (d *decoder) item(depth int) (*Value, error) {
	if depth > d.maxDepth {
		return nil, errs.Detail(ErrCBORLimit, "nesting exceeds %d | 嵌套超过 %d", d.maxDepth, d.maxDepth)
	}
	major, ai, arg, indef, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if indef {
			return nil, errs.Detail(ErrInvalidCBOR, "indefinite unsigned integer | 不定长无符号整数")
		}
		return &Value{Kind: KindUint, UInt: arg}, nil
	case 1:
		if indef {
			return nil, errs.Detail(ErrInvalidCBOR, "indefinite negative integer | 不定长负整数")
		}
		return &Value{Kind: KindNegInt, Neg: arg}, nil
	case 2:
		if indef {
			return d.indefiniteBytes()
		}
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		b, err := d.readN(n)
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindBytes, Bytes: append([]byte(nil), b...)}, nil
	case 3:
		if indef {
			return d.indefiniteText()
		}
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		b, err := d.readN(n)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, errs.Detail(ErrInvalidCBOR, "text string is not valid UTF-8 | 文本串不是合法 UTF-8")
		}
		return &Value{Kind: KindText, Text: string(b)}, nil
	case 4:
		if indef {
			return d.indefiniteArray(depth)
		}
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		if n > d.remaining() {
			return nil, errs.Detail(ErrInvalidCBOR, "array length exceeds input | 数组长度超过输入")
		}
		items := make([]*Value, 0, n)
		for i := 0; i < n; i++ {
			item, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return &Value{Kind: KindArray, Array: items}, nil
	case 5:
		if indef {
			return d.indefiniteMap(depth)
		}
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		if n > d.remaining()/2 {
			return nil, errs.Detail(ErrInvalidCBOR, "map length exceeds input | 映射长度超过输入")
		}
		pairs := make([]Pair, 0, n)
		for i := 0; i < n; i++ {
			key, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			value, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, Pair{Key: key, Value: value})
		}
		return d.finishMap(pairs)
	case 6:
		if indef {
			return nil, errs.Detail(ErrInvalidCBOR, "indefinite tag | 不定长标签")
		}
		inner, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindTag, Tag: arg, Inner: inner}, nil
	case 7:
		return d.simple(ai, arg, indef)
	default:
		return nil, errs.Detail(ErrInvalidCBOR, "unknown major type %d | 未知主类型 %d", major, major)
	}
}

func (d *decoder) length(arg uint64) (int, error) {
	if arg > uint64(d.remaining()) {
		return 0, errs.Detail(ErrInvalidCBOR, "declared length %d exceeds remaining input | 声明长度 %d 超过剩余输入", arg, arg)
	}
	return int(arg), nil
}

func (d *decoder) finishMap(pairs []Pair) (*Value, error) {
	keys := make([][]byte, len(pairs))
	order := make([]int, len(pairs))
	for i := range pairs {
		kb, err := appendCBOR(nil, pairs[i].Key, 0)
		if err != nil {
			return nil, err
		}
		keys[i] = kb
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return bytes.Compare(keys[order[a]], keys[order[b]]) < 0 })
	for i := 1; i < len(order); i++ {
		if bytes.Equal(keys[order[i-1]], keys[order[i]]) {
			return nil, errs.Detail(ErrInvalidCBOR, "duplicate map key | 重复的映射键")
		}
	}
	return &Value{Kind: KindMap, Pairs: pairs}, nil
}

func (d *decoder) simple(ai byte, arg uint64, indef bool) (*Value, error) {
	if indef {
		return nil, errs.Detail(ErrInvalidCBOR, "unexpected break | 意外的 break 标记")
	}
	switch ai {
	case 25:
		return &Value{Kind: KindFloat, Float: halfToFloat64(uint16(arg))}, nil
	case 26:
		return &Value{Kind: KindFloat, Float: float64(math.Float32frombits(uint32(arg)))}, nil
	case 27:
		return &Value{Kind: KindFloat, Float: math.Float64frombits(arg)}, nil
	case 24:
		if arg < 32 {
			return nil, errs.Detail(ErrInvalidCBOR, "non-preferred simple value %d | 非规范简单值 %d", arg, arg)
		}
		return &Value{Kind: KindSimple, Simple: uint8(arg)}, nil
	}
	if ai >= 28 && ai <= 31 {
		return nil, errs.Detail(ErrInvalidCBOR, "reserved simple value encoding %d | 保留的简单值编码 %d", ai, ai)
	}
	return &Value{Kind: KindSimple, Simple: ai}, nil
}

func (d *decoder) peekBreak() (bool, error) {
	if d.off >= len(d.data) {
		return false, errs.Detail(ErrInvalidCBOR, "unexpected end of indefinite item | 不定长项意外结束")
	}
	return d.data[d.off] == 0xff, nil
}

func (d *decoder) consumeBreak() error {
	b, err := d.readByte()
	if err != nil {
		return err
	}
	if b != 0xff {
		return errs.Detail(ErrInvalidCBOR, "expected break | 期望 break 标记")
	}
	return nil
}

func (d *decoder) indefiniteBytes() (*Value, error) {
	var out []byte
	for {
		stop, err := d.peekBreak()
		if err != nil {
			return nil, err
		}
		if stop {
			if err := d.consumeBreak(); err != nil {
				return nil, err
			}
			return &Value{Kind: KindBytes, Bytes: out}, nil
		}
		major, _, arg, indef, err := d.head()
		if err != nil {
			return nil, err
		}
		if major != 2 || indef {
			return nil, errs.Detail(ErrInvalidCBOR, "indefinite byte string chunk is not a byte string | 不定长字节串分块不是字节串")
		}
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		b, err := d.readN(n)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
}

func (d *decoder) indefiniteText() (*Value, error) {
	var out []byte
	for {
		stop, err := d.peekBreak()
		if err != nil {
			return nil, err
		}
		if stop {
			if err := d.consumeBreak(); err != nil {
				return nil, err
			}
			if !utf8.Valid(out) {
				return nil, errs.Detail(ErrInvalidCBOR, "text string is not valid UTF-8 | 文本串不是合法 UTF-8")
			}
			return &Value{Kind: KindText, Text: string(out)}, nil
		}
		major, _, arg, indef, err := d.head()
		if err != nil {
			return nil, err
		}
		if major != 3 || indef {
			return nil, errs.Detail(ErrInvalidCBOR, "indefinite text chunk is not a text string | 不定长文本分块不是文本串")
		}
		n, err := d.length(arg)
		if err != nil {
			return nil, err
		}
		b, err := d.readN(n)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
}

func (d *decoder) indefiniteArray(depth int) (*Value, error) {
	var items []*Value
	for {
		stop, err := d.peekBreak()
		if err != nil {
			return nil, err
		}
		if stop {
			if err := d.consumeBreak(); err != nil {
				return nil, err
			}
			return &Value{Kind: KindArray, Array: items}, nil
		}
		item, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
}

func (d *decoder) indefiniteMap(depth int) (*Value, error) {
	var pairs []Pair
	for {
		stop, err := d.peekBreak()
		if err != nil {
			return nil, err
		}
		if stop {
			if err := d.consumeBreak(); err != nil {
				return nil, err
			}
			return d.finishMap(pairs)
		}
		key, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		stop, err = d.peekBreak()
		if err != nil {
			return nil, err
		}
		if stop {
			return nil, errs.Detail(ErrInvalidCBOR, "indefinite map key without value | 不定长映射键缺少值")
		}
		value, err := d.item(depth + 1)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, Pair{Key: key, Value: value})
	}
}
