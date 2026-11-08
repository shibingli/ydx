package radius

import (
	"encoding/binary"
	"net"

	"github.com/shibingli/ydx/errs"
)

// Packet is a decoded RADIUS packet (RFC 2865 section 3). | Packet 是已解码的 RADIUS 报文
// （RFC 2865 第 3 节）。
//
// Code, Identifier, Length and Authenticator form the fixed 20-octet header; Attributes carries
// the attribute list. Length is derived from the encoded attributes during MarshalBinary and is
// validated during UnmarshalBinary. | Code、Identifier、Length 与 Authenticator 构成固定的 20 字节
// 头部；Attributes 携带属性列表。Length 在 MarshalBinary 时由编码后的属性推导，并在
// UnmarshalBinary 时校验。
type Packet struct {
	// Code is the packet type. | Code 是报文类型。
	Code Code
	// Identifier matches requests with responses. | Identifier 用于匹配请求与响应。
	Identifier uint8
	// Authenticator is the Request or Response Authenticator. | Authenticator 是请求或响应认证符。
	Authenticator [16]byte
	// Attributes is the ordered attribute list. | Attributes 是有序属性列表。
	Attributes Attributes
}

// MarshalBinary encodes p to its RFC 2865 wire form. | MarshalBinary 将 p 编码为 RFC 2865 线格式。
func (p *Packet) MarshalBinary() ([]byte, error) {
	return marshalPacket(p)
}

// UnmarshalBinary decodes data into p. | UnmarshalBinary 从 data 解码到 p。
func (p *Packet) UnmarshalBinary(data []byte) error {
	parsed, err := parsePacket(data)
	if err != nil {
		return err
	}
	*p = *parsed
	return nil
}

// MarshalPacket encodes p to its RFC 2865 wire form. | MarshalPacket 将 p 编码为 RFC 2865 线格式。
func MarshalPacket(p *Packet) ([]byte, error) {
	return marshalPacket(p)
}

// ParsePacket decodes a RADIUS packet and validates its structure. | ParsePacket 解码 RADIUS 报文
// 并校验其结构。
//
// Octets beyond the Length field are ignored as padding, as required by RFC 2865 section 3.
// Truncated headers, impossible lengths, malformed attributes and duplicate Message-Authenticator
// attributes are rejected with ErrInvalidPacket or ErrInvalidAttribute. | 按 RFC 2865 第 3 节要求，
// Length 字段之外的字节作为填充忽略。截断的头部、不可能的长度、畸形属性与重复的
// Message-Authenticator 属性会以 ErrInvalidPacket 或 ErrInvalidAttribute 拒绝。
func ParsePacket(data []byte) (*Packet, error) {
	return parsePacket(data)
}

// marshalPacket implements Packet encoding. | marshalPacket 实现报文编码。
func marshalPacket(p *Packet) ([]byte, error) {
	if p == nil {
		return nil, errs.Detail(ErrInvalidPacket, "nil packet")
	}
	if p.Code == 0 {
		return nil, errs.Detail(ErrInvalidPacket, "code 0 is reserved")
	}
	buf := make([]byte, HeaderLength, HeaderLength+64)
	buf[0] = byte(p.Code)
	buf[1] = p.Identifier
	copy(buf[4:HeaderLength], p.Authenticator[:])
	var err error
	buf, err = appendAttributes(buf, p.Attributes)
	if err != nil {
		return nil, err
	}
	if len(buf) > MaxPacketLength {
		return nil, errs.Detail(ErrInvalidPacket, "packet length %d exceeds %d", len(buf), MaxPacketLength)
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	return buf, nil
}

// appendAttributes appends the encoded attribute list to dst. | appendAttributes 将编码后的属性列表追加到 dst。
func appendAttributes(dst []byte, attrs Attributes) ([]byte, error) {
	for _, attr := range attrs {
		var err error
		dst, err = appendAttribute(dst, attr)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// appendAttribute appends one TLV to dst. | appendAttribute 将一个 TLV 追加到 dst。
func appendAttribute(dst []byte, attr Attribute) ([]byte, error) {
	if attr.Type == 0 {
		return nil, errs.Detail(ErrInvalidAttribute, "attribute type 0 is reserved")
	}
	var value []byte
	if attr.Type == AttrVendorSpecific {
		if attr.raw {
			value = attr.Value
		} else {
			if attr.VendorID == 0 {
				return nil, errs.Detail(ErrInvalidAttribute, "vendor ID 0 is reserved")
			}
			subLength := 2 + len(attr.Value)
			if subLength > 255 {
				return nil, errs.Detail(ErrInvalidAttribute, "vendor attribute length %d exceeds 255", subLength)
			}
			value = make([]byte, 4+subLength)
			binary.BigEndian.PutUint32(value[:4], attr.VendorID)
			value[4] = attr.VendorType
			value[5] = byte(subLength)
			copy(value[6:], attr.Value)
		}
	} else {
		if err := validateAttributeValue(attr.Type, attr.Value); err != nil {
			return nil, err
		}
		value = attr.Value
	}
	total := 2 + len(value)
	if total > 255 {
		return nil, errs.Detail(ErrInvalidAttribute, "attribute %d length %d exceeds 255", uint8(attr.Type), total)
	}
	dst = append(dst, byte(attr.Type), byte(total))
	dst = append(dst, value...)
	return dst, nil
}

// parsePacket implements Packet decoding. | parsePacket 实现报文解码。
func parsePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderLength {
		return nil, errs.Detail(ErrInvalidPacket, "packet length %d is below %d", len(data), HeaderLength)
	}
	code := Code(data[0])
	if code == 0 {
		return nil, errs.Detail(ErrInvalidPacket, "code 0 is reserved")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < HeaderLength {
		return nil, errs.Detail(ErrInvalidPacket, "declared length %d is below %d", length, HeaderLength)
	}
	if length > MaxPacketLength {
		return nil, errs.Detail(ErrInvalidPacket, "declared length %d exceeds %d", length, MaxPacketLength)
	}
	if length > len(data) {
		return nil, errs.Detail(ErrInvalidPacket, "declared length %d exceeds received %d", length, len(data))
	}
	p := &Packet{Code: code, Identifier: data[1]}
	copy(p.Authenticator[:], data[4:HeaderLength])
	attrs, err := parseAttributes(data[HeaderLength:length])
	if err != nil {
		return nil, err
	}
	p.Attributes = attrs
	return p, nil
}

// parseAttributes decodes the attribute block. | parseAttributes 解码属性块。
func parseAttributes(raw []byte) (Attributes, error) {
	var attrs Attributes
	messageAuthenticators := 0
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < 2 {
			return nil, errs.Detail(ErrInvalidAttribute, "truncated attribute header at offset %d", offset)
		}
		t := AttributeType(raw[offset])
		length := int(raw[offset+1])
		if t == 0 {
			return nil, errs.Detail(ErrInvalidAttribute, "attribute type 0 is reserved")
		}
		if length < 2 {
			return nil, errs.Detail(ErrInvalidAttribute, "attribute %d length %d is below 2", uint8(t), length)
		}
		if length > len(raw)-offset {
			return nil, errs.Detail(ErrInvalidAttribute, "attribute %d length %d exceeds remaining %d", uint8(t), length, len(raw)-offset)
		}
		value := raw[offset+2 : offset+length]
		if t == AttrVendorSpecific {
			vendor, err := decodeVendorAttributes(value)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, vendor...)
		} else {
			if err := validateAttributeValue(t, value); err != nil {
				return nil, err
			}
			if t == AttrMessageAuthenticator {
				messageAuthenticators++
				if messageAuthenticators > 1 {
					return nil, errs.Detail(ErrInvalidAttribute, "duplicate Message-Authenticator attribute")
				}
			}
			attrs = append(attrs, Attribute{Type: t, Value: append([]byte(nil), value...)})
		}
		offset += length
	}
	return attrs, nil
}

// decodeVendorAttributes splits a Vendor-Specific value into sub-attributes. | decodeVendorAttributes
// 将 Vendor-Specific 值拆分为子属性。
//
// A value carrying only the Vendor-Id is preserved verbatim so a round trip is lossless. The
// reserved Vendor-Id 0 is rejected consistently with MarshalPacket, and values with structurally
// invalid sub-attribute lengths are rejected. | 仅携带 Vendor-Id 的值会原样保留，保证往返无损。
// 保留值 Vendor-Id 0 与 MarshalPacket 一致地被拒绝；子属性长度结构非法的值也会被拒绝。
func decodeVendorAttributes(value []byte) (Attributes, error) {
	if len(value) < 4 {
		return nil, errs.Detail(ErrInvalidAttribute, "vendor-specific value length %d is below 4", len(value))
	}
	vendorID := binary.BigEndian.Uint32(value[:4])
	if vendorID == 0 {
		return nil, errs.Detail(ErrInvalidAttribute, "vendor ID 0 is reserved")
	}
	if len(value) == 4 {
		return Attributes{{
			Type:     AttrVendorSpecific,
			Value:    append([]byte(nil), value...),
			VendorID: vendorID,
			raw:      true,
		}}, nil
	}
	rest := value[4:]
	var attrs Attributes
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, errs.Detail(ErrInvalidAttribute, "truncated vendor attribute for vendor %d", vendorID)
		}
		vendorType := rest[0]
		length := int(rest[1])
		if length < 2 {
			return nil, errs.Detail(ErrInvalidAttribute, "vendor %d attribute %d length %d is below 2", vendorID, vendorType, length)
		}
		if length > len(rest) {
			return nil, errs.Detail(ErrInvalidAttribute, "vendor %d attribute %d length %d exceeds remaining %d", vendorID, vendorType, length, len(rest))
		}
		attrs = append(attrs, Attribute{
			Type:       AttrVendorSpecific,
			Value:      append([]byte(nil), rest[2:length]...),
			VendorID:   vendorID,
			VendorType: vendorType,
		})
		rest = rest[length:]
	}
	return attrs, nil
}

// validateAttributeValue enforces the length rules of well-known attributes. | validateAttributeValue
// 强制执行已知属性的长度规则。
func validateAttributeValue(t AttributeType, value []byte) error {
	switch t {
	case AttrUserPassword:
		if len(value) < 16 || len(value) > 128 || len(value)%16 != 0 {
			return errs.Detail(ErrInvalidAttribute, "User-Password length %d must be a multiple of 16 in [16,128]", len(value))
		}
	case AttrCHAPPassword:
		if len(value) != 17 {
			return errs.Detail(ErrInvalidAttribute, "CHAP-Password length %d must be 17", len(value))
		}
	case AttrNASIPAddress, AttrFramedIPAddress, AttrLoginIPHost:
		if len(value) != net.IPv4len {
			return errs.Detail(ErrInvalidAttribute, "attribute %d length %d must be 4", uint8(t), len(value))
		}
	case AttrNASPort, AttrServiceType, AttrFramedProtocol, AttrFramedMTU,
		AttrSessionTimeout, AttrIdleTimeout, AttrTerminationAction,
		AttrAcctStatusType, AttrAcctDelayTime, AttrAcctInputOctets, AttrAcctOutputOctets,
		AttrAcctAuthentic, AttrAcctSessionTime, AttrAcctInputPackets, AttrAcctOutputPackets,
		AttrAcctTerminateCause, AttrAcctLinkCount, AttrAcctInputGigawords, AttrAcctOutputGigawords,
		AttrEventTimestamp, AttrNASPortType, AttrPortLimit, AttrErrorCause:
		if len(value) != 4 {
			return errs.Detail(ErrInvalidAttribute, "attribute %d length %d must be 4", uint8(t), len(value))
		}
	case AttrMessageAuthenticator:
		if len(value) != 16 {
			return errs.Detail(ErrInvalidAttribute, "Message-Authenticator length %d must be 16", len(value))
		}
	case AttrTunnelType, AttrTunnelMediumType:
		if len(value) != 4 && len(value) != 5 {
			return errs.Detail(ErrInvalidAttribute, "attribute %d length %d must be 4 or 5", uint8(t), len(value))
		}
	case AttrCHAPChallenge:
		if len(value) < 5 {
			return errs.Detail(ErrInvalidAttribute, "CHAP-Challenge length %d must be at least 5", len(value))
		}
	case AttrEAPMessage:
		if len(value) < 1 {
			return errs.Detail(ErrInvalidAttribute, "EAP-Message must not be empty")
		}
	case AttrUserName, AttrState, AttrClass, AttrProxyState, AttrAcctSessionID,
		AttrAcctMultiSessionID, AttrTunnelPrivateGroupID, AttrReplyMessage, AttrFilterID,
		AttrCalledStationID, AttrCallingStationID, AttrNASIdentifier:
		if len(value) < 1 {
			return errs.Detail(ErrInvalidAttribute, "attribute %d must not be empty", uint8(t))
		}
	}
	if len(value) > MaxAttributeValueLength {
		return errs.Detail(ErrInvalidAttribute, "attribute %d value length %d exceeds %d", uint8(t), len(value), MaxAttributeValueLength)
	}
	return nil
}
