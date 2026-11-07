package ldap

import (
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// BER tag classes. | BER 标签类别。
type berClass uint8

const (
	// berClassUniversal identifies universal ASN.1 types. | berClassUniversal 标识通用 ASN.1 类型。
	berClassUniversal berClass = 0
	// berClassApplication identifies LDAP protocol operations. | berClassApplication 标识 LDAP 协议操作。
	berClassApplication berClass = 1
	// berClassContext identifies context-specific protocol fields. | berClassContext 标识上下文相关协议字段。
	berClassContext berClass = 2
)

// Universal BER tags used by LDAP. | LDAP 使用的通用 BER 标签。
const (
	berTagBoolean     uint32 = 1
	berTagInteger     uint32 = 2
	berTagOctetString uint32 = 4
	berTagNull        uint32 = 5
	berTagEnumerated  uint32 = 10
	berTagSequence    uint32 = 16
	berTagSet         uint32 = 17
)

const (
	// maxBERDepth bounds nested constructed values. | maxBERDepth 限制嵌套构造值的深度。
	maxBERDepth = 64
	// berReservedLength holds the nine bytes reserved for a definite length while encoding. |
	// berReservedLength 是编码期间为定长字段预留的九个字节。
	berReservedLength = 9
)

// berTag identifies one BER tag. | berTag 标识一个 BER 标签。
type berTag struct {
	// Class is the tag class. | Class 是标签类别。
	Class berClass
	// Constructed reports the constructed bit. | Constructed 表示构造位。
	Constructed bool
	// Number is the tag number. | Number 是标签号。
	Number uint32
}

// berElement is one decoded tag-length-value triple. Value aliases the source
// buffer and is only valid while that buffer is retained. | berElement 是一个解码后的
// 标签-长度-值三元组。Value 引用源缓冲区，仅在源缓冲区保留期间有效。
type berElement struct {
	Tag   berTag
	Value []byte
}

// berReader parses a bounded BER byte slice. It never panics on malformed input.
// | berReader 在受限 BER 字节切片上解析，对畸形输入绝不 panic。
type berReader struct {
	data  []byte
	off   int
	depth int
}

// newBERReader returns a reader over data at nesting depth zero. | newBERReader
// 返回位于嵌套深度零的 data 读取器。
func newBERReader(data []byte) *berReader {
	return &berReader{data: data}
}

// newBERSubReader returns a child reader over a constructed value. | newBERSubReader
// 返回构造值上的子读取器。
func newBERSubReader(data []byte, depth int) (*berReader, error) {
	if depth > maxBERDepth {
		return nil, errs.Detail(ErrProtocolError, "BER nesting exceeds %d | BER 嵌套超过 %d", maxBERDepth, maxBERDepth)
	}
	return &berReader{data: data, depth: depth}, nil
}

// remaining reports unread bytes. | remaining 返回未读字节数。
func (r *berReader) remaining() int { return len(r.data) - r.off }

// next decodes the next TLV and advances past it. | next 解码下一个 TLV 并越过它。
func (r *berReader) next() (berElement, error) {
	tag, err := r.readTag()
	if err != nil {
		return berElement{}, err
	}
	length, err := r.readLength()
	if err != nil {
		return berElement{}, err
	}
	if length > r.remaining() {
		return berElement{}, errs.Detail(ErrProtocolError, "BER value length %d exceeds %d remaining bytes | BER 值长度 %d 超过剩余 %d 字节", length, r.remaining(), length, r.remaining())
	}
	start := r.off
	r.off += length
	return berElement{Tag: tag, Value: r.data[start:r.off]}, nil
}

// peekTag decodes a tag header without consuming it. | peekTag 解码标签头但不消费。
func (r *berReader) peekTag() (berTag, error) {
	off := r.off
	tag, err := r.readTag()
	r.off = off
	return tag, err
}

// readTag decodes one tag header. | readTag 解码一个标签头。
func (r *berReader) readTag() (berTag, error) {
	if r.off >= len(r.data) {
		return berTag{}, errs.Detail(ErrProtocolError, "truncated BER tag | BER 标签被截断")
	}
	first := r.data[r.off]
	r.off++
	tag := berTag{
		Class:       berClass(first >> 6),
		Constructed: first&0x20 != 0,
		Number:      uint32(first & 0x1f),
	}
	if tag.Number != 0x1f {
		return tag, nil
	}
	tag.Number = 0
	var (
		count int
		seen  bool
	)
	for {
		if r.off >= len(r.data) {
			return berTag{}, errs.Detail(ErrProtocolError, "truncated high-tag-number form | 高标签号形式被截断")
		}
		b := r.data[r.off]
		r.off++
		if !seen && b == 0x80 {
			return berTag{}, errs.Detail(ErrProtocolError, "non-minimal high-tag-number form | 非最小高标签号形式")
		}
		seen = true
		if tag.Number > (^uint32(0) >> 7) {
			return berTag{}, errs.Detail(ErrProtocolError, "BER tag number overflows uint32 | BER 标签号溢出 uint32")
		}
		tag.Number = tag.Number<<7 | uint32(b&0x7f)
		count++
		if b&0x80 == 0 {
			break
		}
		if count >= 5 {
			return berTag{}, errs.Detail(ErrProtocolError, "BER tag number is too long | BER 标签号过长")
		}
	}
	if tag.Number < 0x1f {
		return berTag{}, errs.Detail(ErrProtocolError, "non-minimal high-tag-number form | 非最小高标签号形式")
	}
	return tag, nil
}

// readLength decodes a definite BER length. Indefinite lengths are rejected
// because LDAP requires definite form. | readLength 解码定长 BER 长度。LDAP 要求定长
// 形式，因此拒绝不定长。
func (r *berReader) readLength() (int, error) {
	if r.off >= len(r.data) {
		return 0, errs.Detail(ErrProtocolError, "truncated BER length | BER 长度被截断")
	}
	first := r.data[r.off]
	r.off++
	if first < 0x80 {
		return int(first), nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, errs.Detail(ErrProtocolError, "indefinite BER length is not allowed in LDAP | LDAP 不允许不定长 BER 长度")
	}
	if count > 8 {
		return 0, errs.Detail(ErrProtocolError, "BER length uses %d octets | BER 长度占用 %d 字节", count, count)
	}
	if count > r.remaining() {
		return 0, errs.Detail(ErrProtocolError, "truncated BER long-form length | 长形式 BER 长度被截断")
	}
	if count == 1 && r.data[r.off] < 0x80 {
		return 0, errs.Detail(ErrProtocolError, "non-minimal BER length | 非最小 BER 长度")
	}
	if count > 1 && r.data[r.off] == 0 {
		return 0, errs.Detail(ErrProtocolError, "non-minimal BER length | 非最小 BER 长度")
	}
	var (
		length uint64
		i      int
	)
	for i = 0; i < count; i++ {
		length = length<<8 | uint64(r.data[r.off+i])
	}
	r.off += count
	if length > uint64(^uint(0)>>1) {
		return 0, errs.Detail(ErrProtocolError, "BER length overflows int | BER 长度溢出 int")
	}
	return int(length), nil
}

// expect consumes one TLV and verifies its class, constructed bit and tag number.
// | expect 消费一个 TLV 并校验类别、构造位与标签号。
func (r *berReader) expect(class berClass, constructed bool, number uint32) (berElement, error) {
	tag, err := r.peekTag()
	if err != nil {
		return berElement{}, err
	}
	if tag.Class != class || tag.Constructed != constructed || tag.Number != number {
		return berElement{}, errs.Detail(ErrProtocolError, "unexpected tag class=%d constructed=%t number=%d | 意外标签 class=%d constructed=%t number=%d", tag.Class, tag.Constructed, tag.Number, tag.Class, tag.Constructed, tag.Number)
	}
	return r.next()
}

// expectSequence consumes a universal SEQUENCE. | expectSequence 消费一个通用 SEQUENCE。
func (r *berReader) expectSequence() (berElement, error) {
	return r.expect(berClassUniversal, true, berTagSequence)
}

// expectSet consumes a universal SET. | expectSet 消费一个通用 SET。
func (r *berReader) expectSet() (berElement, error) {
	return r.expect(berClassUniversal, true, berTagSet)
}

// subReader opens a child reader over a constructed element. | subReader 在构造元素上打开子读取器。
func (r *berReader) subReader(element berElement) (*berReader, error) {
	if !element.Tag.Constructed {
		return nil, errs.Detail(ErrProtocolError, "primitive value used as constructed | 原始值被当作构造值使用")
	}
	return newBERSubReader(element.Value, r.depth+1)
}

// readOctetString consumes a universal OCTET STRING. | readOctetString 消费通用 OCTET STRING。
func (r *berReader) readOctetString() ([]byte, error) {
	element, err := r.expect(berClassUniversal, false, berTagOctetString)
	if err != nil {
		return nil, err
	}
	return element.Value, nil
}

// readString consumes a universal OCTET STRING and returns it as a string without
// copying. | readString 消费通用 OCTET STRING，并在不复制的情况下返回字符串。
func (r *berReader) readString() (string, error) {
	value, err := r.readOctetString()
	if err != nil {
		return "", err
	}
	return string(value), nil
}

// readBoolean consumes a universal BOOLEAN. | readBoolean 消费通用 BOOLEAN。
func (r *berReader) readBoolean() (bool, error) {
	element, err := r.expect(berClassUniversal, false, berTagBoolean)
	if err != nil {
		return false, err
	}
	if len(element.Value) != 1 {
		return false, errs.Detail(ErrProtocolError, "BOOLEAN has %d bytes | BOOLEAN 长度为 %d 字节", len(element.Value), len(element.Value))
	}
	return element.Value[0] != 0, nil
}

// readInt consumes a universal INTEGER or ENUMERATED and returns a signed value.
// | readInt 消费通用 INTEGER 或 ENUMERATED 并返回有符号值。
func (r *berReader) readInt(enum bool) (int64, error) {
	number := berTagInteger
	if enum {
		number = berTagEnumerated
	}
	element, err := r.expect(berClassUniversal, false, number)
	if err != nil {
		return 0, err
	}
	return decodeBERInt(element.Value)
}

// decodeBERInt decodes a minimal two's-complement integer of at most eight bytes.
// | decodeBERInt 解码最多八字节的最小二进制补码整数。
func decodeBERInt(value []byte) (int64, error) {
	if len(value) == 0 {
		return 0, errs.Detail(ErrProtocolError, "empty BER integer | BER 整数为空")
	}
	if len(value) > 8 {
		return 0, errs.Detail(ErrProtocolError, "BER integer has %d bytes | BER 整数长度为 %d 字节", len(value), len(value))
	}
	var n uint64
	for _, b := range value {
		n = n<<8 | uint64(b)
	}
	if value[0]&0x80 != 0 && len(value) < 8 {
		n |= ^uint64(0) << (uint(len(value)) * 8)
	}
	return int64(n), nil
}

// expectEnd verifies that no unread elements remain. | expectEnd 校验没有剩余元素。
func (r *berReader) expectEnd() error {
	if r.remaining() != 0 {
		return errs.Detail(ErrProtocolError, "%d trailing BER bytes | 剩余 %d 个尾随 BER 字节", r.remaining(), r.remaining())
	}
	return nil
}

// berFrame records an open constructed value in berEncoder. | berFrame 记录
// berEncoder 中打开的构造值。
type berFrame struct {
	start   int
	content int
}

// berEncoder builds definite-length BER values. It reserves room for the
// largest length and compacts the value when the frame closes, so nested
// encoders always produce canonical short lengths. | berEncoder 构建定长 BER 值。
// 它为最大长度预留空间，并在帧关闭时压缩内容，因此嵌套编码始终产生规范短长度。
type berEncoder struct {
	buf    []byte
	frames []berFrame
}

// newBEREncoder returns an encoder with the requested initial capacity. | newBEREncoder
// 返回带有所需初始容量的编码器。
func newBEREncoder(capacity int) *berEncoder {
	return &berEncoder{buf: make([]byte, 0, capacity)}
}

// open starts a constructed TLV. | open 开始一个构造 TLV。
func (e *berEncoder) open(class berClass, number uint32) {
	start := len(e.buf)
	e.buf = appendBERTag(e.buf, class, true, number)
	content := len(e.buf)
	e.buf = append(e.buf, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	e.frames = append(e.frames, berFrame{start: start, content: content})
}

// close finishes the innermost constructed TLV. | close 结束最内层构造 TLV。
func (e *berEncoder) close() {
	if len(e.frames) == 0 {
		return
	}
	frame := e.frames[len(e.frames)-1]
	e.frames = e.frames[:len(e.frames)-1]
	payloadStart := frame.content + berReservedLength
	contentLen := len(e.buf) - payloadStart
	if contentLen < 0 {
		return
	}
	var lengthBuffer [8]byte
	lengthBytes := encodeBERLength(lengthBuffer[:0], contentLen)
	copy(e.buf[frame.content:], lengthBytes)
	newContent := frame.content + len(lengthBytes)
	if newContent != payloadStart {
		copy(e.buf[newContent:], e.buf[payloadStart:])
	}
	e.buf = e.buf[:newContent+contentLen]
}

// primitive appends a complete primitive TLV. | primitive 追加一个完整的原始 TLV。
func (e *berEncoder) primitive(class berClass, number uint32, value []byte) {
	e.buf = appendBERTag(e.buf, class, false, number)
	e.buf = appendBERLength(e.buf, len(value))
	e.buf = append(e.buf, value...)
}

// boolean appends a universal BOOLEAN. | boolean 追加通用 BOOLEAN。
func (e *berEncoder) boolean(value bool) {
	if value {
		e.primitive(berClassUniversal, berTagBoolean, []byte{0xff})
		return
	}
	e.primitive(berClassUniversal, berTagBoolean, []byte{0x00})
}

// integer appends a universal INTEGER. | integer 追加通用 INTEGER。
func (e *berEncoder) integer(value int64) {
	e.buf = appendBERTag(e.buf, berClassUniversal, false, berTagInteger)
	e.buf = appendBERIntegerValue(e.buf, value)
}

// enumerated appends a universal ENUMERATED. | enumerated 追加通用 ENUMERATED。
func (e *berEncoder) enumerated(value int64) {
	e.buf = appendBERTag(e.buf, berClassUniversal, false, berTagEnumerated)
	e.buf = appendBERIntegerValue(e.buf, value)
}

// octetString appends a universal OCTET STRING. | octetString 追加通用 OCTET STRING。
func (e *berEncoder) octetString(value []byte) {
	e.primitive(berClassUniversal, berTagOctetString, value)
}

// text appends a universal OCTET STRING from a string. | text 从字符串追加通用 OCTET STRING。
func (e *berEncoder) text(value string) {
	e.primitive(berClassUniversal, berTagOctetString, []byte(value))
}

// bytes returns the encoded value. | bytes 返回编码结果。
func (e *berEncoder) bytes() []byte { return e.buf }

// appendBERTag appends a tag header. | appendBERTag 追加标签头。
func appendBERTag(dst []byte, class berClass, constructed bool, number uint32) []byte {
	first := byte(class) << 6
	if constructed {
		first |= 0x20
	}
	if number < 0x1f {
		return append(dst, first|byte(number))
	}
	dst = append(dst, first|0x1f)
	var encoded [5]byte
	i := len(encoded)
	for {
		i--
		encoded[i] = byte(number & 0x7f)
		number >>= 7
		if number == 0 {
			break
		}
	}
	for ; i < len(encoded)-1; i++ {
		dst = append(dst, encoded[i]|0x80)
	}
	return append(dst, encoded[len(encoded)-1])
}

// appendBERLength appends a minimal definite length. | appendBERLength 追加最小定长长度。
func appendBERLength(dst []byte, length int) []byte {
	return encodeBERLength(dst, length)
}

// encodeBERLength appends the minimal definite length bytes to dst and returns
// the extended slice. A negative length emits nothing. | encodeBERLength 把最小定长
// 长度字节追加到 dst 并返回扩展后的切片；负长度不输出任何字节。
func encodeBERLength(dst []byte, length int) []byte {
	if length < 0 {
		return dst
	}
	if length < 0x80 {
		return append(dst, byte(length))
	}
	var encoded [8]byte
	i := len(encoded)
	for value := length; value > 0; value >>= 8 {
		i--
		encoded[i] = byte(value)
	}
	count := len(encoded) - i
	dst = append(dst, 0x80|byte(count))
	return append(dst, encoded[i:]...)
}

// appendBERIntegerValue appends a minimal two's-complement integer body. | appendBERIntegerValue
// 追加最小二进制补码整数主体。
func appendBERIntegerValue(dst []byte, value int64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(value))
	i := 0
	for i < len(raw)-1 {
		if raw[i] == 0x00 && raw[i+1]&0x80 == 0 {
			i++
			continue
		}
		if raw[i] == 0xff && raw[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	body := raw[i:]
	dst = appendBERLength(dst, len(body))
	return append(dst, body...)
}
