package kmip

import (
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"time"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
)

// ttlvHeaderSize is the size of a TTLV item header in bytes. | ttlvHeaderSize 是 TTLV 项头的字节数。
const ttlvHeaderSize = 8

// Item is a single TTLV item. | Item 是单个 TTLV 项。
//
// Value holds the wire value bytes without the zero padding. Structure items keep their children in Children and leave
// Value empty. Unknown tags are preserved verbatim so that a decoded tree can be re-encoded without losing vendor
// extensions. | Value 保存不含零填充的线路值字节；Structure 项的子树放在 Children 中且 Value 为空。未知标签会原样保留，
// 因此解码后的树可重新编码而不丢失厂商扩展。
type Item struct {
	// Tag is the 24-bit item tag. | Tag 是 24 位项标签。
	Tag Tag
	// Type is the item type. | Type 是项类型。
	Type Type
	// Value is the unpadded value bytes. It is empty for structures. | Value 是不含填充的值字节；结构类型为空。
	Value []byte
	// Children holds the direct children of a structure item. | Children 保存结构项的直接子项。
	Children []Item
}

// NewStructure builds a structure item. | NewStructure 构造结构项。
func NewStructure(tag Tag, children ...Item) Item {
	return Item{Tag: tag, Type: TypeStructure, Children: children}
}

// NewInteger builds a signed 64-bit integer item. | NewInteger 构造有符号 64 位整数项。
func NewInteger(tag Tag, value int64) Item {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(value))
	return Item{Tag: tag, Type: TypeInteger, Value: b}
}

// NewLongInteger builds a signed 32-bit long-integer item. | NewLongInteger 构造有符号 32 位长整数项。
func NewLongInteger(tag Tag, value int32) Item {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(value))
	return Item{Tag: tag, Type: TypeLongInteger, Value: b}
}

// NewBigInteger builds a signed big-integer item from v. | NewBigInteger 由 v 构造有符号大整数项。
//
// The wire form is a two's-complement big-endian encoding whose length is a multiple of eight, as KMIP requires.
// Zero is encoded as eight zero bytes. | 线路形式是长度为 8 的倍数的二进制补码大端编码（KMIP 要求）；零编码为 8 个零字节。
func NewBigInteger(tag Tag, v *big.Int) Item {
	if v == nil {
		v = new(big.Int)
	}
	if v.Sign() == 0 {
		return Item{Tag: tag, Type: TypeBigInteger, Value: make([]byte, 8)}
	}
	negative := v.Sign() < 0
	mag := new(big.Int).Abs(v).Bytes()
	length := len(mag)
	if !negative && mag[0]&0x80 != 0 {
		length++
	} else if negative {
		length++
	}
	length = (length + 7) &^ 7
	if length == 0 {
		length = 8
	}
	out := make([]byte, length)
	if negative {
		mod := new(big.Int).Lsh(big.NewInt(1), uint(8*length))
		value := new(big.Int).Add(mod, v)
		value.FillBytes(out)
	} else {
		copy(out[length-len(mag):], mag)
	}
	return Item{Tag: tag, Type: TypeBigInteger, Value: out}
}

// NewBigIntegerBytes builds a big-integer item from an already encoded two's-complement value. | NewBigIntegerBytes 由已编码的二进制补码值构造大整数项。
//
// The slice is copied and its length must be a multiple of eight; Encode rejects any other length. | 切片会被复制，长度必须是 8 的倍数；其它长度会被 Encode 拒绝。
func NewBigIntegerBytes(tag Tag, value []byte) Item {
	b := append([]byte(nil), value...)
	return Item{Tag: tag, Type: TypeBigInteger, Value: b}
}

// NewEnumeration builds an enumeration item. | NewEnumeration 构造枚举项。
func NewEnumeration(tag Tag, value uint32) Item {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, value)
	return Item{Tag: tag, Type: TypeEnumeration, Value: b}
}

// NewBoolean builds a boolean item. | NewBoolean 构造布尔项。
func NewBoolean(tag Tag, value bool) Item {
	b := make([]byte, 8)
	if value {
		b[7] = 1
	}
	return Item{Tag: tag, Type: TypeBoolean, Value: b}
}

// NewTextString builds a UTF-8 text-string item. | NewTextString 构造 UTF-8 文本字符串项。
func NewTextString(tag Tag, value string) Item {
	return Item{Tag: tag, Type: TypeTextString, Value: []byte(value)}
}

// NewByteString builds a byte-string item and copies value. | NewByteString 构造字节串项并复制 value。
func NewByteString(tag Tag, value []byte) Item {
	return Item{Tag: tag, Type: TypeByteString, Value: append([]byte(nil), value...)}
}

// NewDateTime builds a date-time item from t, truncated to seconds and normalized to UTC. | NewDateTime 由 t 构造日期时间项，截断到秒并规范化为 UTC。
func NewDateTime(tag Tag, t time.Time) Item {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()))
	return Item{Tag: tag, Type: TypeDateTime, Value: b}
}

// NewDateTimeExtended builds a date-time-extended item from t. | NewDateTimeExtended 由 t 构造扩展日期时间项。
func NewDateTimeExtended(tag Tag, t time.Time) Item {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()))
	binary.BigEndian.PutUint32(b[8:], uint32(t.Nanosecond()/1000))
	return Item{Tag: tag, Type: TypeDateTimeExtended, Value: b}
}

// NewInterval builds an interval item from d. | NewInterval 由 d 构造间隔项。
//
// Negative durations are encoded as zero and durations longer than math.MaxUint32 seconds are saturated. | 负时长编码为零，
// 超过 math.MaxUint32 秒的时长会饱和。
func NewInterval(tag Tag, d time.Duration) Item {
	seconds := int64(d / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	if seconds > math.MaxUint32 {
		seconds = math.MaxUint32
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(seconds))
	return Item{Tag: tag, Type: TypeInterval, Value: b}
}

// Child returns the first direct child with the given tag. | Child 返回第一个具有给定标签的直接子项。
func (it Item) Child(tag Tag) (Item, bool) {
	for i := range it.Children {
		if it.Children[i].Tag == tag {
			return it.Children[i], true
		}
	}
	return Item{}, false
}

// ChildrenOf returns all direct children with the given tag in document order. | ChildrenOf 按文档顺序返回具有给定标签的全部直接子项。
func (it Item) ChildrenOf(tag Tag) []Item {
	var out []Item
	for i := range it.Children {
		if it.Children[i].Tag == tag {
			out = append(out, it.Children[i])
		}
	}
	return out
}

// RequireChild returns the first direct child with the given tag or an ErrMalformed error. | RequireChild 返回第一个具有给定标签的直接子项，不存在时返回 ErrMalformed。
func (it Item) RequireChild(tag Tag) (Item, error) {
	child, ok := it.Child(tag)
	if !ok {
		return Item{}, errs.Detail(ErrMalformed, "missing tag 0x%06X | 缺少标签 0x%06X", uint32(tag), uint32(tag))
	}
	return child, nil
}

// typeMismatch builds a typed decoding error. | typeMismatch 构造类型解码错误。
func (it Item) typeMismatch(want Type) error {
	return errs.Detail(ErrMalformed, "tag 0x%06X has type %s, want %s | 标签 0x%06X 的类型为 %s，需要 %s",
		uint32(it.Tag), it.Type, want, uint32(it.Tag), it.Type, want)
}

// AsInteger decodes the item as a signed 64-bit integer. | AsInteger 把项解码为有符号 64 位整数。
func (it Item) AsInteger() (int64, error) {
	if it.Type != TypeInteger || len(it.Value) != 8 {
		return 0, it.typeMismatch(TypeInteger)
	}
	return int64(binary.BigEndian.Uint64(it.Value)), nil
}

// AsLongInteger decodes the item as a signed 32-bit long integer. | AsLongInteger 把项解码为有符号 32 位长整数。
func (it Item) AsLongInteger() (int32, error) {
	if it.Type != TypeLongInteger || len(it.Value) != 4 {
		return 0, it.typeMismatch(TypeLongInteger)
	}
	return int32(binary.BigEndian.Uint32(it.Value)), nil
}

// AsBigInteger decodes the item as a signed big integer. | AsBigInteger 把项解码为有符号大整数。
func (it Item) AsBigInteger() (*big.Int, error) {
	if it.Type != TypeBigInteger || len(it.Value)%8 != 0 {
		return nil, it.typeMismatch(TypeBigInteger)
	}
	if len(it.Value) == 0 {
		return new(big.Int), nil
	}
	v := new(big.Int).SetBytes(it.Value)
	if it.Value[0]&0x80 != 0 {
		mod := new(big.Int).Lsh(big.NewInt(1), uint(8*len(it.Value)))
		v.Sub(v, mod)
	}
	return v, nil
}

// AsEnumeration decodes the item as an unsigned 32-bit enumeration. | AsEnumeration 把项解码为无符号 32 位枚举。
func (it Item) AsEnumeration() (uint32, error) {
	if it.Type != TypeEnumeration || len(it.Value) != 4 {
		return 0, it.typeMismatch(TypeEnumeration)
	}
	return binary.BigEndian.Uint32(it.Value), nil
}

// AsBoolean decodes the item as a boolean. | AsBoolean 把项解码为布尔值。
func (it Item) AsBoolean() (bool, error) {
	if it.Type != TypeBoolean || len(it.Value) != 8 {
		return false, it.typeMismatch(TypeBoolean)
	}
	for _, b := range it.Value[:7] {
		if b != 0 {
			return false, errs.Detail(ErrMalformed, "non-canonical boolean value | 非规范布尔值")
		}
	}
	switch it.Value[7] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errs.Detail(ErrMalformed, "non-canonical boolean value | 非规范布尔值")
	}
}

// AsTextString decodes the item as a UTF-8 string. | AsTextString 把项解码为 UTF-8 字符串。
func (it Item) AsTextString() (string, error) {
	if it.Type != TypeTextString || !utf8.Valid(it.Value) {
		return "", it.typeMismatch(TypeTextString)
	}
	return string(it.Value), nil
}

// AsByteString returns the item's byte string. | AsByteString 返回项的字节串。
//
// The returned slice aliases the item; callers must not modify it. | 返回的切片与项共享底层数组；调用方不得修改。
func (it Item) AsByteString() ([]byte, error) {
	if it.Type != TypeByteString {
		return nil, it.typeMismatch(TypeByteString)
	}
	return it.Value, nil
}

// AsDateTime decodes the item as a UTC time truncated to seconds. | AsDateTime 把项解码为截断到秒的 UTC 时间。
func (it Item) AsDateTime() (time.Time, error) {
	if it.Type != TypeDateTime || len(it.Value) != 8 {
		return time.Time{}, it.typeMismatch(TypeDateTime)
	}
	return time.Unix(int64(binary.BigEndian.Uint64(it.Value)), 0).UTC(), nil
}

// AsDateTimeExtended decodes the item as a UTC time with microsecond precision. | AsDateTimeExtended 把项解码为微秒精度的 UTC 时间。
func (it Item) AsDateTimeExtended() (time.Time, error) {
	if it.Type != TypeDateTimeExtended || len(it.Value) != 12 {
		return time.Time{}, it.typeMismatch(TypeDateTimeExtended)
	}
	seconds := int64(binary.BigEndian.Uint64(it.Value))
	micros := int64(binary.BigEndian.Uint32(it.Value[8:]))
	return time.Unix(seconds, micros*1000).UTC(), nil
}

// AsInterval decodes the item as a duration in seconds. | AsInterval 把项解码为以秒为单位的时长。
func (it Item) AsInterval() (time.Duration, error) {
	if it.Type != TypeInterval || len(it.Value) != 4 {
		return 0, it.typeMismatch(TypeInterval)
	}
	return time.Duration(binary.BigEndian.Uint32(it.Value)) * time.Second, nil
}

// AsStructure returns the direct children of a structure item. | AsStructure 返回结构项的直接子项。
func (it Item) AsStructure() ([]Item, error) {
	if it.Type != TypeStructure {
		return nil, it.typeMismatch(TypeStructure)
	}
	return it.Children, nil
}

// decoder carries the decode budget shared by one message. | decoder 承载单个消息共享的解码预算。
type decoder struct {
	data   []byte
	limits Limits
	items  int
}

// decode reads one item at off and returns the offset just past its padding. | decode 读取 off 处的一个项，返回跳过填充后的偏移。
func (d *decoder) decode(off, depth int) (Item, int, error) {
	if depth > d.limits.MaxDepth {
		return Item{}, 0, errs.Detail(ErrLimitExceeded, "structure depth exceeds %d | 结构深度超过 %d", d.limits.MaxDepth, d.limits.MaxDepth)
	}
	if off < 0 || off+ttlvHeaderSize > len(d.data) {
		return Item{}, 0, errs.Detail(ErrMalformed, "truncated TTLV header at offset %d | 偏移 %d 处的 TTLV 头被截断", off, off)
	}
	d.items++
	if d.items > d.limits.MaxItems {
		return Item{}, 0, errs.Detail(ErrLimitExceeded, "item count exceeds %d | 项数量超过 %d", d.limits.MaxItems, d.limits.MaxItems)
	}

	tag := Tag(uint32(d.data[off])<<16 | uint32(d.data[off+1])<<8 | uint32(d.data[off+2]))
	if tag == 0 {
		return Item{}, 0, errs.Detail(ErrMalformed, "zero tag at offset %d | 偏移 %d 处标签为零", off, off)
	}
	typ := Type(d.data[off+3])
	if !typ.valid() {
		return Item{}, 0, errs.Detail(ErrMalformed, "unknown TTLV type 0x%02X for tag 0x%06X | 标签 0x%06X 的 TTLV 类型 0x%02X 未知", uint8(typ), uint32(tag), uint32(tag), uint8(typ))
	}
	length := uint64(binary.BigEndian.Uint32(d.data[off+4 : off+8]))
	if length > uint64(d.limits.MaxSize) {
		return Item{}, 0, errs.Detail(ErrLimitExceeded, "value length %d exceeds limit %d | 值长度 %d 超过限制 %d", length, d.limits.MaxSize, length, d.limits.MaxSize)
	}
	padded := (length + 7) &^ 7
	valueStart := uint64(off) + ttlvHeaderSize
	valueEnd := valueStart + length
	next := valueStart + padded
	if next > uint64(len(d.data)) {
		return Item{}, 0, errs.Detail(ErrMalformed, "truncated value for tag 0x%06X at offset %d | 标签 0x%06X 在偏移 %d 处的值被截断", uint32(tag), off, uint32(tag), off)
	}
	for i := valueEnd; i < next; i++ {
		if d.data[i] != 0 {
			return Item{}, 0, errs.Detail(ErrMalformed, "non-zero padding for tag 0x%06X | 标签 0x%06X 的填充非零", uint32(tag), uint32(tag))
		}
	}
	value := d.data[valueStart:valueEnd]

	switch typ {
	case TypeStructure:
		if length%8 != 0 {
			return Item{}, 0, errs.Detail(ErrMalformed, "structure length %d is not a multiple of 8 | 结构长度 %d 不是 8 的倍数", length, length)
		}
		children := make([]Item, 0, 4)
		pos := int(valueStart)
		end := int(valueEnd)
		for pos < end {
			child, nextPos, err := d.decode(pos, depth+1)
			if err != nil {
				return Item{}, 0, err
			}
			if nextPos > end {
				return Item{}, 0, errs.Detail(ErrMalformed, "child item overruns structure | 子项越过结构边界")
			}
			children = append(children, child)
			pos = nextPos
		}
		return Item{Tag: tag, Type: typ, Children: children}, int(next), nil
	case TypeInteger, TypeDateTime:
		if length != 8 {
			return Item{}, 0, errs.Detail(ErrMalformed, "tag 0x%06X: %s length %d, want 8 | 标签 0x%06X：%s 长度 %d，需要 8", uint32(tag), typ, length, uint32(tag), typ, length)
		}
	case TypeLongInteger, TypeEnumeration, TypeInterval:
		if length != 4 {
			return Item{}, 0, errs.Detail(ErrMalformed, "tag 0x%06X: %s length %d, want 4 | 标签 0x%06X：%s 长度 %d，需要 4", uint32(tag), typ, length, uint32(tag), typ, length)
		}
	case TypeBigInteger:
		if length%8 != 0 {
			return Item{}, 0, errs.Detail(ErrMalformed, "big integer length %d is not a multiple of 8 | 大整数长度 %d 不是 8 的倍数", length, length)
		}
	case TypeBoolean:
		if length != 8 {
			return Item{}, 0, errs.Detail(ErrMalformed, "boolean length %d, want 8 | 布尔长度 %d，需要 8", length, length)
		}
		for _, b := range value[:7] {
			if b != 0 {
				return Item{}, 0, errs.Detail(ErrMalformed, "non-canonical boolean value | 非规范布尔值")
			}
		}
		if value[7] > 1 {
			return Item{}, 0, errs.Detail(ErrMalformed, "non-canonical boolean value | 非规范布尔值")
		}
	case TypeTextString:
		if !utf8.Valid(value) {
			return Item{}, 0, errs.Detail(ErrMalformed, "invalid UTF-8 in text string | 文本字符串包含非法 UTF-8")
		}
	case TypeDateTimeExtended:
		if length != 12 {
			return Item{}, 0, errs.Detail(ErrMalformed, "date-time-extended length %d, want 12 | 扩展日期时间长度 %d，需要 12", length, length)
		}
	}
	return Item{Tag: tag, Type: typ, Value: value}, int(next), nil
}

// encoder carries the encode budget shared by one message. | encoder 承载单个消息共享的编码预算。
type encoder struct {
	buf    []byte
	base   int
	limits Limits
	items  int
}

// reserve grows the buffer by n bytes, enforcing the size limit. | reserve 把缓冲区增长 n 字节并检查长度限制。
func (e *encoder) reserve(n int) error {
	if n < 0 || len(e.buf)-e.base+n > e.limits.MaxSize {
		return errs.Detail(ErrLimitExceeded, "encoded size exceeds %d bytes | 编码长度超过 %d 字节", e.limits.MaxSize, e.limits.MaxSize)
	}
	e.buf = append(e.buf, make([]byte, n)...)
	return nil
}

// appendItem encodes item at depth and appends it to the buffer. | appendItem 在给定深度编码 item 并追加到缓冲区。
func (e *encoder) appendItem(item Item, depth int) error {
	if depth > e.limits.MaxDepth {
		return errs.Detail(ErrLimitExceeded, "structure depth exceeds %d | 结构深度超过 %d", e.limits.MaxDepth, e.limits.MaxDepth)
	}
	if item.Tag == 0 || uint32(item.Tag) > 0xFFFFFF {
		return errs.Detail(ErrMalformed, "invalid tag 0x%X | 标签 0x%X 非法", uint32(item.Tag), uint32(item.Tag))
	}
	if !item.Type.valid() {
		return errs.Detail(ErrMalformed, "tag 0x%06X has unknown type 0x%02X | 标签 0x%06X 的类型 0x%02X 未知", uint32(item.Tag), uint8(item.Type), uint32(item.Tag), uint8(item.Type))
	}
	e.items++
	if e.items > e.limits.MaxItems {
		return errs.Detail(ErrLimitExceeded, "item count exceeds %d | 项数量超过 %d", e.limits.MaxItems, e.limits.MaxItems)
	}

	if err := e.reserve(ttlvHeaderSize); err != nil {
		return err
	}
	header := len(e.buf) - ttlvHeaderSize
	valueStart := len(e.buf)

	switch item.Type {
	case TypeStructure:
		if len(item.Value) != 0 {
			return errs.Detail(ErrMalformed, "structure tag 0x%06X carries a value | 结构标签 0x%06X 不应携带值", uint32(item.Tag), uint32(item.Tag))
		}
		for i := range item.Children {
			if err := e.appendItem(item.Children[i], depth+1); err != nil {
				return err
			}
		}
	case TypeInteger, TypeDateTime:
		if len(item.Value) != 8 {
			return errs.Detail(ErrMalformed, "tag 0x%06X: %s length %d, want 8 | 标签 0x%06X：%s 长度 %d，需要 8", uint32(item.Tag), item.Type, len(item.Value), uint32(item.Tag), item.Type, len(item.Value))
		}
		if err := e.reserve(8); err != nil {
			return err
		}
		copy(e.buf[valueStart:], item.Value)
	case TypeLongInteger, TypeEnumeration, TypeInterval:
		if len(item.Value) != 4 {
			return errs.Detail(ErrMalformed, "tag 0x%06X: %s length %d, want 4 | 标签 0x%06X：%s 长度 %d，需要 4", uint32(item.Tag), item.Type, len(item.Value), uint32(item.Tag), item.Type, len(item.Value))
		}
		if err := e.reserve(4); err != nil {
			return err
		}
		copy(e.buf[valueStart:], item.Value)
	case TypeBigInteger:
		if len(item.Value)%8 != 0 {
			return errs.Detail(ErrMalformed, "big integer length %d is not a multiple of 8 | 大整数长度 %d 不是 8 的倍数", len(item.Value), len(item.Value))
		}
		if err := e.reserve(len(item.Value)); err != nil {
			return err
		}
		copy(e.buf[valueStart:], item.Value)
	case TypeBoolean:
		if len(item.Value) != 8 {
			return errs.Detail(ErrMalformed, "boolean length %d, want 8 | 布尔长度 %d，需要 8", len(item.Value), len(item.Value))
		}
		if item.Value[7] > 1 {
			return errs.Detail(ErrMalformed, "non-canonical boolean value | 非规范布尔值")
		}
		for _, b := range item.Value[:7] {
			if b != 0 {
				return errs.Detail(ErrMalformed, "non-canonical boolean value | 非规范布尔值")
			}
		}
		if err := e.reserve(8); err != nil {
			return err
		}
		copy(e.buf[valueStart:], item.Value)
	case TypeTextString:
		if !utf8.Valid(item.Value) {
			return errs.Detail(ErrMalformed, "invalid UTF-8 in text string | 文本字符串包含非法 UTF-8")
		}
		if err := e.reserve(len(item.Value)); err != nil {
			return err
		}
		copy(e.buf[valueStart:], item.Value)
	case TypeByteString:
		if err := e.reserve(len(item.Value)); err != nil {
			return err
		}
		copy(e.buf[valueStart:], item.Value)
	case TypeDateTimeExtended:
		if len(item.Value) != 12 {
			return errs.Detail(ErrMalformed, "date-time-extended length %d, want 12 | 扩展日期时间长度 %d，需要 12", len(item.Value), len(item.Value))
		}
		if err := e.reserve(12); err != nil {
			return err
		}
		copy(e.buf[valueStart:], item.Value)
	default:
		return errs.Detail(ErrMalformed, "unknown TTLV type 0x%02X | TTLV 类型 0x%02X 未知", uint8(item.Type), uint8(item.Type))
	}

	if item.Type != TypeStructure {
		pad := (8 - len(item.Value)%8) % 8
		if err := e.reserve(pad); err != nil {
			return err
		}
	}
	length := len(item.Value)
	if item.Type == TypeStructure {
		length = len(e.buf) - valueStart
	}
	if uint64(length) > math.MaxUint32 {
		return errs.Detail(ErrLimitExceeded, "value length %d exceeds TTLV maximum | 值长度 %d 超过 TTLV 上限", length, length)
	}
	e.buf[header] = byte(uint32(item.Tag) >> 16)
	e.buf[header+1] = byte(uint32(item.Tag) >> 8)
	e.buf[header+2] = byte(item.Tag)
	e.buf[header+3] = byte(item.Type)
	binary.BigEndian.PutUint32(e.buf[header+4:header+8], uint32(length))
	return nil
}

// Encode encodes one TTLV item using the default limits. | Encode 使用默认限制编码一个 TTLV 项。
func Encode(item Item) ([]byte, error) {
	return EncodeWithLimits(item, DefaultLimits())
}

// EncodeWithLimits encodes one TTLV item under the given resource limits. | EncodeWithLimits 在给定资源限制下编码一个 TTLV 项。
func EncodeWithLimits(item Item, limits Limits) ([]byte, error) {
	return AppendItemWithLimits(nil, item, limits)
}

// AppendItem appends the encoding of item to dst using the default limits. | AppendItem 使用默认限制把 item 的编码追加到 dst。
//
// The size limit applies to the encoded item only, not to the bytes already present in dst. | 长度限制只作用于编码后的项，不作用于 dst 中已有的字节。
func AppendItem(dst []byte, item Item) ([]byte, error) {
	return AppendItemWithLimits(dst, item, DefaultLimits())
}

// AppendItemWithLimits appends the encoding of item to dst under the given limits. | AppendItemWithLimits 在给定限制下把 item 的编码追加到 dst。
func AppendItemWithLimits(dst []byte, item Item, limits Limits) ([]byte, error) {
	limits = limits.normalized()
	e := &encoder{buf: dst, base: len(dst), limits: limits}
	if err := e.appendItem(item, 0); err != nil {
		return nil, err
	}
	return e.buf, nil
}

// Decode decodes exactly one TTLV item using the default limits. | Decode 使用默认限制解码恰好一个 TTLV 项。
//
// The returned item's Value slices alias data, so data must not be modified while the item is in use. | 返回项的 Value 切片
// 与 data 共享底层数组，因此项在使用期间不得修改 data。
func Decode(data []byte) (Item, error) {
	return DecodeWithLimits(data, DefaultLimits())
}

// DecodeWithLimits decodes exactly one TTLV item under the given limits. | DecodeWithLimits 在给定限制下解码恰好一个 TTLV 项。
func DecodeWithLimits(data []byte, limits Limits) (Item, error) {
	limits = limits.normalized()
	if len(data) > limits.MaxSize {
		return Item{}, errs.Detail(ErrLimitExceeded, "message size %d exceeds limit %d | 消息长度 %d 超过限制 %d", len(data), limits.MaxSize, len(data), limits.MaxSize)
	}
	d := &decoder{data: data, limits: limits}
	item, next, err := d.decode(0, 0)
	if err != nil {
		return Item{}, err
	}
	if next != len(data) {
		return Item{}, errs.Detail(ErrMalformed, "%d trailing bytes after TTLV item | TTLV 项后存在 %d 个多余字节", len(data)-next, len(data)-next)
	}
	return item, nil
}

// ReadItem reads exactly one TTLV item from r using the default limits. | ReadItem 使用默认限制从 r 读取恰好一个 TTLV 项。
func ReadItem(r io.Reader, limits Limits) (Item, error) {
	limits = limits.normalized()
	var header [ttlvHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return Item{}, errs.Wrap(err, ErrMalformed)
		}
		return Item{}, err
	}
	tag := Tag(uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2]))
	if tag == 0 {
		return Item{}, errs.Detail(ErrMalformed, "zero tag in TTLV header | TTLV 头中的标签为零")
	}
	typ := Type(header[3])
	if !typ.valid() {
		return Item{}, errs.Detail(ErrMalformed, "unknown TTLV type 0x%02X | TTLV 类型 0x%02X 未知", uint8(typ), uint8(typ))
	}
	length := uint64(binary.BigEndian.Uint32(header[4:]))
	if length > uint64(limits.MaxSize) {
		return Item{}, errs.Detail(ErrLimitExceeded, "value length %d exceeds limit %d | 值长度 %d 超过限制 %d", length, limits.MaxSize, length, limits.MaxSize)
	}
	padded := (length + 7) &^ 7
	total := uint64(ttlvHeaderSize) + padded
	if total > uint64(limits.MaxSize) {
		return Item{}, errs.Detail(ErrLimitExceeded, "message size %d exceeds limit %d | 消息长度 %d 超过限制 %d", total, limits.MaxSize, total, limits.MaxSize)
	}
	buf := make([]byte, total)
	copy(buf, header[:])
	// Read the padding too so that a stream of TTLV items stays aligned. | 连同填充一起读取，
	// 使连续 TTLV 项的流保持对齐。
	if _, err := io.ReadFull(r, buf[ttlvHeaderSize:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return Item{}, errs.Wrap(err, ErrMalformed)
		}
		return Item{}, err
	}
	item, err := DecodeWithLimits(buf, limits)
	if err != nil {
		return Item{}, err
	}
	if item.Tag != tag || item.Type != typ {
		return Item{}, errs.Detail(ErrMalformed, "TTLV header changed while decoding | 解码期间 TTLV 头发生变化")
	}
	return item, nil
}

// WriteItem writes exactly one TTLV item to w using the default limits. | WriteItem 使用默认限制向 w 写入恰好一个 TTLV 项。
func WriteItem(w io.Writer, item Item) error {
	return WriteItemWithLimits(w, item, DefaultLimits())
}

// WriteItemWithLimits writes exactly one TTLV item to w under the given limits. | WriteItemWithLimits 在给定限制下向 w 写入恰好一个 TTLV 项。
func WriteItemWithLimits(w io.Writer, item Item, limits Limits) error {
	encoded, err := EncodeWithLimits(item, limits)
	if err != nil {
		return err
	}
	defer zeroize(encoded)
	for len(encoded) > 0 {
		n, err := w.Write(encoded)
		if err != nil {
			return errs.WrapDetail(err, ErrClosed, "TTLV write failed | TTLV 写入失败")
		}
		if n <= 0 {
			return errs.Wrap(io.ErrShortWrite, ErrClosed)
		}
		encoded = encoded[n:]
	}
	return nil
}
