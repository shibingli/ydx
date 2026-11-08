package kerberos

import (
	"encoding/binary"
	mathbits "math/bits"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DER tag bytes used by Kerberos V5 and GSS-API. | Kerberos V5 与 GSS-API 使用的
// DER 标签字节。
const (
	derTagInteger          = 0x02
	derTagBitString        = 0x03
	derTagOctetString      = 0x04
	derTagNull             = 0x05
	derTagOID              = 0x06
	derTagEnumerated       = 0x0A
	derTagUTF8String       = 0x0C
	derTagSequence         = 0x30
	derTagGeneralString    = 0x1B
	derTagGeneralizedTime  = 0x18
	derTagApplicationBase  = 0x60
	derTagContextBase      = 0xA0
	derMaxLengthOctets     = 4
	derMaxIntegerOctets    = 8
	derMaxGeneralizedTime  = 32
	derBitStringUnusedBits = 0x00
)

// errASN1 builds a bilingual ASN.1 error detail. | errASN1 构建双语的 ASN.1 错误细节。
func errASN1(format string, args ...any) error {
	return errs.Detail(ErrASN1, format, args...)
}

// derLength appends a DER definite length. | derLength 追加 DER 定长长度。
func derLength(dst []byte, n int) []byte {
	if n < 0x80 {
		return append(dst, byte(n))
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	i := 0
	for i < len(buf) && buf[i] == 0 {
		i++
	}
	count := len(buf) - i
	dst = append(dst, 0x80|byte(count))
	return append(dst, buf[i:]...)
}

// derAppendTLV appends one tag-length-value element. | derAppendTLV 追加一个
// 标签-长度-值元素。
func derAppendTLV(dst []byte, tag byte, content []byte) []byte {
	dst = append(dst, tag)
	dst = derLength(dst, len(content))
	return append(dst, content...)
}

// derAppendSequence appends a SEQUENCE built from already encoded members. | derAppendSequence
// 追加由已编码成员构建的 SEQUENCE。
func derAppendSequence(dst []byte, parts ...[]byte) []byte {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	content := make([]byte, 0, size)
	for _, part := range parts {
		content = append(content, part...)
	}
	return derAppendTLV(dst, derTagSequence, content)
}

// derAppendContext appends an explicitly tagged context-specific value. | derAppendContext
// 追加显式标记的上下文特定值。
func derAppendContext(dst []byte, number int, content []byte) []byte {
	return derAppendTLV(dst, byte(derTagContextBase|number), content)
}

// derAppendApplication appends an APPLICATION tagged value. | derAppendApplication
// 追加 APPLICATION 标记的值。
func derAppendApplication(dst []byte, number int, content []byte) []byte {
	return derAppendTLV(dst, byte(derTagApplicationBase|number), content)
}

// derAppendInteger appends a minimally encoded signed 32-bit INTEGER. | derAppendInteger
// 追加最小编码的有符号 32 位 INTEGER。
func derAppendInteger(dst []byte, value int32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(value))
	start := 0
	for start < 3 {
		if raw[start] == 0x00 && raw[start+1]&0x80 == 0 {
			start++
			continue
		}
		if raw[start] == 0xFF && raw[start+1]&0x80 != 0 {
			start++
			continue
		}
		break
	}
	return derAppendTLV(dst, derTagInteger, raw[start:])
}

// derAppendUnsigned appends a non-negative INTEGER. | derAppendUnsigned 追加非负 INTEGER。
func derAppendUnsigned(dst []byte, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	start := 0
	for start < 3 && raw[start] == 0 {
		start++
	}
	body := raw[start:]
	if body[0]&0x80 != 0 {
		body = append([]byte{0x00}, body...)
	}
	return derAppendTLV(dst, derTagInteger, body)
}

// derAppendOctetString appends an OCTET STRING. | derAppendOctetString 追加 OCTET STRING。
func derAppendOctetString(dst []byte, value []byte) []byte {
	return derAppendTLV(dst, derTagOctetString, value)
}

// derAppendGeneralString appends a KerberosString as GeneralString. | derAppendGeneralString
// 以 GeneralString 追加 KerberosString。
func derAppendGeneralString(dst []byte, value string) []byte {
	return derAppendTLV(dst, derTagGeneralString, []byte(value))
}

// derAppendGeneralizedTime appends a UTC GeneralizedTime without fractional
// seconds. | derAppendGeneralizedTime 追加不带小数秒的 UTC GeneralizedTime。
func derAppendGeneralizedTime(dst []byte, value time.Time) []byte {
	return derAppendTLV(dst, derTagGeneralizedTime, []byte(value.UTC().Format("20060102150405Z")))
}

// derAppendKerberosFlags appends a KerberosFlags BIT STRING. The flag constants
// use the RFC 4120 bit numbers as mask positions, while the wire format numbers
// bits from the most significant bit, so the mask is reversed here. |
// derAppendKerberosFlags 追加 KerberosFlags BIT STRING。标志常量把 RFC 4120 的位号
// 用作掩码位置，而线缆格式从最高位开始编号，因此这里反转掩码。
func derAppendKerberosFlags(dst []byte, flags uint32) []byte {
	content := make([]byte, 5)
	content[0] = derBitStringUnusedBits
	binary.BigEndian.PutUint32(content[1:], mathbits.Reverse32(flags))
	return derAppendTLV(dst, derTagBitString, content)
}

// derAppendEnumerated appends a DER ENUMERATED. | derAppendEnumerated 追加 DER ENUMERATED。
func derAppendEnumerated(dst []byte, value int) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(int32(value)))
	start := 0
	for start < 3 {
		if raw[start] == 0x00 && raw[start+1]&0x80 == 0 {
			start++
			continue
		}
		if raw[start] == 0xFF && raw[start+1]&0x80 != 0 {
			start++
			continue
		}
		break
	}
	return derAppendTLV(dst, derTagEnumerated, raw[start:])
}

// derAppendOID appends an OBJECT IDENTIFIER from its numeric arcs. | derAppendOID
// 按键值弧追加 OBJECT IDENTIFIER。
func derAppendOID(dst []byte, arcs []uint32) []byte {
	content := derOIDContent(arcs)
	return derAppendTLV(dst, derTagOID, content)
}

// derOIDContent encodes OID arcs without the outer tag. | derOIDContent 编码不带外层标签的
// OID 弧。
func derOIDContent(arcs []uint32) []byte {
	if len(arcs) < 2 {
		return nil
	}
	content := make([]byte, 0, len(arcs)*3)
	content = appendBase128(content, arcs[0]*40+arcs[1])
	for _, arc := range arcs[2:] {
		content = appendBase128(content, arc)
	}
	return content
}

// appendBase128 appends an unsigned base-128 integer with continuation bits. | appendBase128
// 追加带续位的无符号 base-128 整数。
func appendBase128(dst []byte, value uint32) []byte {
	var raw [5]byte
	i := len(raw) - 1
	raw[i] = byte(value & 0x7F)
	for value >>= 7; value != 0; value >>= 7 {
		i--
		raw[i] = byte(value&0x7F) | 0x80
	}
	return append(dst, raw[i:]...)
}

// parseOIDContent decodes OID arcs from tag content. | parseOIDContent 从标签内容解码 OID 弧。
func parseOIDContent(content []byte) ([]uint32, error) {
	if len(content) == 0 {
		return nil, errASN1("empty object identifier | 空对象标识符")
	}
	arcs := make([]uint32, 0, 4)
	var current uint32
	inArc := false
	for _, b := range content {
		if !inArc && b == 0x80 {
			return nil, errASN1("non-minimal object identifier arc | 非最小对象标识符弧")
		}
		if current > (1<<28)-1 {
			return nil, errASN1("object identifier arc overflow | 对象标识符弧溢出")
		}
		current = current<<7 | uint32(b&0x7F)
		inArc = b&0x80 != 0
		if inArc {
			continue
		}
		if len(arcs) == 0 {
			first, second := current/40, current%40
			if first > 2 {
				first, second = 2, current-80
			}
			arcs = append(arcs, first, second)
		} else {
			arcs = append(arcs, current)
		}
		current = 0
	}
	if inArc {
		return nil, errASN1("truncated object identifier | 对象标识符被截断")
	}
	return arcs, nil
}

// equalOID reports whether two numeric OID arc lists are equal. | equalOID 报告两个数值 OID
// 弧列表是否相等。
func equalOID(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// formatOID renders a numeric OID in dotted form. | formatOID 用点分形式渲染数值 OID。
func formatOID(arcs []uint32) string {
	var b strings.Builder
	for i, arc := range arcs {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(arc), 10))
	}
	return b.String()
}

// contextContent unwraps the single explicitly tagged value in value and verifies
// its inner tag. | contextContent 解包 value 中唯一显式标记的值并校验其内部标签。
func contextContent(value []byte, tag byte) ([]byte, error) {
	r := newDERReader(value)
	content, err := r.expect(tag)
	if err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return content, nil
}

// readContextInt32 decodes an explicitly tagged INTEGER. | readContextInt32 解码显式标记
// 的 INTEGER。
func readContextInt32(value []byte) (int32, error) {
	content, err := contextContent(value, derTagInteger)
	if err != nil {
		return 0, err
	}
	return readInt32(content)
}

// readContextUint32 decodes an explicitly tagged non-negative INTEGER. | readContextUint32
// 解码显式标记的非负 INTEGER。
func readContextUint32(value []byte) (uint32, error) {
	content, err := contextContent(value, derTagInteger)
	if err != nil {
		return 0, err
	}
	return readUint32(content)
}

// readContextString decodes an explicitly tagged KerberosString. | readContextString 解码
// 显式标记的 KerberosString。
func readContextString(value []byte) (string, error) {
	r := newDERReader(value)
	text, err := readString(r)
	if err != nil {
		return "", err
	}
	if err := r.end(); err != nil {
		return "", err
	}
	return text, nil
}

// readContextOctets decodes an explicitly tagged OCTET STRING. | readContextOctets 解码
// 显式标记的 OCTET STRING。
func readContextOctets(value []byte) ([]byte, error) {
	content, err := contextContent(value, derTagOctetString)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), content...), nil
}

// readContextGeneralizedTime decodes an explicitly tagged KerberosTime. | readContextGeneralizedTime
// 解码显式标记的 KerberosTime。
func readContextGeneralizedTime(value []byte) (time.Time, error) {
	content, err := contextContent(value, derTagGeneralizedTime)
	if err != nil {
		return time.Time{}, err
	}
	return readGeneralizedTime(content)
}

// readContextKerberosFlags decodes an explicitly tagged KerberosFlags. | readContextKerberosFlags
// 解码显式标记的 KerberosFlags。
func readContextKerberosFlags(value []byte) (uint32, error) {
	content, err := contextContent(value, derTagBitString)
	if err != nil {
		return 0, err
	}
	return readKerberosFlags(content)
}

// derReader walks a concatenation of DER values. | derReader 遍历 DER 值串联。
type derReader struct {
	buf []byte
	off int
}

// newDERReader wraps buf. | newDERReader 包装 buf。
func newDERReader(buf []byte) *derReader { return &derReader{buf: buf} }

// remaining reports how many unread bytes are left. | remaining 报告剩余未读字节数。
func (r *derReader) remaining() int { return len(r.buf) - r.off }

// next returns the next tag and its content. | next 返回下一个标签及其内容。
func (r *derReader) next() (byte, []byte, error) {
	if r.off >= len(r.buf) {
		return 0, nil, errASN1("unexpected end of DER data | DER 数据意外结束")
	}
	tag := r.buf[r.off]
	r.off++
	if tag&0x1F == 0x1F {
		return 0, nil, errASN1("high-tag-number form is not supported | 不支持高标签号形式")
	}
	if r.off >= len(r.buf) {
		return 0, nil, errASN1("truncated DER length | DER 长度被截断")
	}
	lengthByte := r.buf[r.off]
	r.off++
	var length int
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		count := int(lengthByte & 0x7F)
		if count == 0 {
			return 0, nil, errASN1("indefinite DER length is not allowed | 不允许不定长 DER 长度")
		}
		if count > derMaxLengthOctets {
			return 0, nil, errASN1("DER length uses %d octets, maximum %d | DER 长度使用 %d 字节，最多 %d",
				count, derMaxLengthOctets, count, derMaxLengthOctets)
		}
		if r.remaining() < count {
			return 0, nil, errASN1("truncated DER length | DER 长度被截断")
		}
		if r.buf[r.off] == 0 {
			return 0, nil, errASN1("non-minimal DER length | 非最小 DER 长度")
		}
		for i := 0; i < count; i++ {
			length = length<<8 | int(r.buf[r.off+i])
		}
		r.off += count
	}
	if length < 0 || length > r.remaining() {
		return 0, nil, errASN1("DER length %d exceeds remaining %d | DER 长度 %d 超过剩余 %d",
			length, r.remaining(), length, r.remaining())
	}
	content := r.buf[r.off : r.off+length]
	r.off += length
	return tag, content, nil
}

// expect returns the content of a value with the exact tag. | expect 返回标签完全匹配的值内容。
func (r *derReader) expect(tag byte) ([]byte, error) {
	got, content, err := r.next()
	if err != nil {
		return nil, err
	}
	if got != tag {
		return nil, errASN1("unexpected DER tag 0x%02x, want 0x%02x | DER 标签 0x%02x 不符合预期 0x%02x",
			got, tag, got, tag)
	}
	return content, nil
}

// end verifies that no bytes remain. | end 校验没有剩余字节。
func (r *derReader) end() error {
	if r.remaining() != 0 {
		return errs.Detail(ErrTrailingData, "%d unexpected octets | 有 %d 个多余字节", r.remaining(), r.remaining())
	}
	return nil
}

// sequenceContent verifies that data is a single SEQUENCE and returns its
// content. | sequenceContent 校验 data 是单个 SEQUENCE 并返回其内容。
func sequenceContent(data []byte) ([]byte, error) {
	r := newDERReader(data)
	content, err := r.expect(derTagSequence)
	if err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return content, nil
}

// applicationContent verifies an APPLICATION tag wrapping a SEQUENCE and returns
// the sequence content. | applicationContent 校验包裹 SEQUENCE 的 APPLICATION 标签并返回
// 序列内容。
func applicationContent(data []byte, number int) ([]byte, error) {
	r := newDERReader(data)
	content, err := r.expect(byte(derTagApplicationBase | number))
	if err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return sequenceContent(content)
}

// readInt32 decodes a signed INTEGER fitting in 32 bits. | readInt32 解码适合 32 位的有符号
// INTEGER。
func readInt32(content []byte) (int32, error) {
	if len(content) == 0 {
		return 0, errASN1("empty INTEGER | 空 INTEGER")
	}
	if len(content) > derMaxIntegerOctets {
		return 0, errASN1("INTEGER uses %d octets | INTEGER 使用 %d 字节", len(content), len(content))
	}
	var value int64
	if content[0]&0x80 != 0 {
		value = -1
	}
	for _, b := range content {
		value = value<<8 | int64(b)
	}
	if value < -1<<31 || value > 1<<31-1 {
		return 0, errASN1("INTEGER %d overflows int32 | INTEGER %d 超出 int32", value, value)
	}
	return int32(value), nil
}

// readUint32 decodes a non-negative INTEGER fitting in 32 bits. | readUint32 解码适合 32 位的
// 非负 INTEGER。
func readUint32(content []byte) (uint32, error) {
	if len(content) == 0 {
		return 0, errASN1("empty INTEGER | 空 INTEGER")
	}
	if len(content) > derMaxIntegerOctets {
		return 0, errASN1("INTEGER uses %d octets | INTEGER 使用 %d 字节", len(content), len(content))
	}
	if content[0]&0x80 != 0 {
		return 0, errASN1("negative unsigned INTEGER | 无符号 INTEGER 为负")
	}
	var value uint64
	for _, b := range content {
		value = value<<8 | uint64(b)
	}
	if value > 1<<32-1 {
		return 0, errASN1("INTEGER %d overflows uint32 | INTEGER %d 超出 uint32", value, value)
	}
	return uint32(value), nil
}

// readString decodes a KerberosString, accepting GeneralString, UTF8String,
// IA5String, and PrintableString encodings. | readString 解码 KerberosString，接受
// GeneralString、UTF8String、IA5String 与 PrintableString 编码。
func readString(r *derReader) (string, error) {
	tag, content, err := r.next()
	if err != nil {
		return "", err
	}
	switch tag {
	case derTagGeneralString, derTagUTF8String, 0x16, 0x13:
		return string(content), nil
	default:
		return "", errASN1("unexpected string tag 0x%02x | 字符串标签 0x%02x 不符合预期", tag, tag)
	}
}

// readGeneralizedTime decodes a KerberosTime. | readGeneralizedTime 解码 KerberosTime。
func readGeneralizedTime(content []byte) (time.Time, error) {
	if len(content) == 0 || len(content) > derMaxGeneralizedTime {
		return time.Time{}, errs.Detail(ErrTime, "GeneralizedTime length %d | GeneralizedTime 长度 %d", len(content), len(content))
	}
	text := string(content)
	for _, layout := range []string{"20060102150405Z", "20060102150405.999999999Z", "20060102150405"} {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errs.Detail(ErrTime, "invalid GeneralizedTime %q | 非法 GeneralizedTime %q", text, text)
}

// readKerberosFlags decodes a KerberosFlags BIT STRING. | readKerberosFlags 解码
// KerberosFlags BIT STRING。
func readKerberosFlags(content []byte) (uint32, error) {
	if len(content) == 0 {
		return 0, nil
	}
	unused := content[0]
	if unused > 7 {
		return 0, errASN1("invalid unused bit count %d | 无效未用位计数 %d", unused, unused)
	}
	bits := content[1:]
	if len(bits) > 4 {
		return 0, errASN1("flags use %d octets | 标志使用 %d 字节", len(bits), len(bits))
	}
	var value uint32
	for _, b := range bits {
		value = value<<8 | uint32(b)
	}
	if len(bits) < 4 {
		value <<= 8 * uint(4-len(bits))
	}
	if unused > 0 && len(bits) > 0 {
		mask := uint32(1)<<unused - 1
		if value&mask != 0 {
			value &^= mask
		}
	}
	return mathbits.Reverse32(value), nil
}

// readBitStringContent decodes a BIT STRING into its octets and pads to the
// requested size. | readBitStringContent 解码 BIT STRING 的字节并填充到请求长度。
func readBitStringContent(content []byte, size int) ([]byte, error) {
	if len(content) == 0 {
		return nil, errASN1("empty BIT STRING | 空 BIT STRING")
	}
	if content[0] > 7 {
		return nil, errASN1("invalid unused bit count %d | 无效未用位计数 %d", content[0], content[0])
	}
	bits := content[1:]
	if len(bits) == 0 {
		return nil, errASN1("empty BIT STRING | 空 BIT STRING")
	}
	if len(bits) > size {
		return nil, errASN1("BIT STRING is %d octets, maximum %d | BIT STRING 为 %d 字节，最多 %d",
			len(bits), size, len(bits), size)
	}
	out := make([]byte, size)
	copy(out[size-len(bits):], bits)
	return out, nil
}

// marshalContextSequence builds an APPLICATION-tagged SEQUENCE. | marshalContextSequence
// 构建 APPLICATION 标记的 SEQUENCE。
func marshalContextSequence(application int, parts ...[]byte) []byte {
	body := derAppendSequence(nil, parts...)
	return derAppendApplication(nil, application, body)
}

// appendIntContext appends a context-specific explicit INTEGER. | appendIntContext
// 追加上下文特定显式 INTEGER。
func appendIntContext(dst []byte, number int, value int32) []byte {
	return derAppendContext(dst, number, derAppendInteger(nil, value))
}

// appendUintContext appends a context-specific explicit non-negative INTEGER. | appendUintContext
// 追加上下文特定显式非负 INTEGER。
func appendUintContext(dst []byte, number int, value uint32) []byte {
	return derAppendContext(dst, number, derAppendUnsigned(nil, value))
}

// appendOctetsContext appends a context-specific explicit OCTET STRING. | appendOctetsContext
// 追加上下文特定显式 OCTET STRING。
func appendOctetsContext(dst []byte, number int, value []byte) []byte {
	return derAppendContext(dst, number, derAppendOctetString(nil, value))
}

// appendStringContext appends a context-specific explicit KerberosString. | appendStringContext
// 追加上下文特定显式 KerberosString。
func appendStringContext(dst []byte, number int, value string) []byte {
	return derAppendContext(dst, number, derAppendGeneralString(nil, value))
}

// appendTimeContext appends a context-specific explicit KerberosTime. | appendTimeContext
// 追加上下文特定显式 KerberosTime。
func appendTimeContext(dst []byte, number int, value time.Time) []byte {
	return derAppendContext(dst, number, derAppendGeneralizedTime(nil, value))
}

// appendFlagsContext appends a context-specific explicit KerberosFlags. | appendFlagsContext
// 追加上下文特定显式 KerberosFlags。
func appendFlagsContext(dst []byte, number int, value uint32) []byte {
	return derAppendContext(dst, number, derAppendKerberosFlags(nil, value))
}
