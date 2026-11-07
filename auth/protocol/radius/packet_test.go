package radius

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// rawPacket builds a structurally valid raw packet around the given attribute TLVs. | rawPacket
// 围绕给定属性 TLV 构建结构合法的原始报文。
func rawPacket(code Code, identifier uint8, attribs ...[]byte) []byte {
	length := HeaderLength
	for _, attribute := range attribs {
		length += len(attribute)
	}
	raw := make([]byte, HeaderLength, length)
	raw[0] = byte(code)
	raw[1] = identifier
	binary.BigEndian.PutUint16(raw[2:4], uint16(length))
	for i := 4; i < HeaderLength; i++ {
		raw[i] = byte(i)
	}
	for _, attribute := range attribs {
		raw = append(raw, attribute...)
	}
	return raw
}

// tlv builds one attribute TLV. | tlv 构建一个属性 TLV。
func tlv(t AttributeType, value []byte) []byte {
	out := make([]byte, 2, 2+len(value))
	out[0] = byte(t)
	out[1] = byte(2 + len(value))
	return append(out, value...)
}

func TestPacketRoundTrip(t *testing.T) {
	var authenticator [16]byte
	for i := range authenticator {
		authenticator[i] = byte(0xa0 + i)
	}
	packet := &Packet{
		Code:          CodeAccessRequest,
		Identifier:    0x42,
		Authenticator: authenticator,
		Attributes: Attributes{
			NewAttribute(AttrUserName, []byte("alice")),
			NewAttribute(AttrNASIPAddress, []byte{192, 0, 2, 1}),
			NewVendorAttribute(VendorMicrosoft, VendorMSCHAPChallenge, bytes.Repeat([]byte{7}, 16)),
			NewAttribute(AttributeType(200), []byte("unknown")),
		},
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	if length := int(binary.BigEndian.Uint16(raw[2:4])); length != len(raw) {
		t.Fatalf("declared length %d != encoded length %d", length, len(raw))
	}
	parsed, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if parsed.Code != packet.Code || parsed.Identifier != packet.Identifier || parsed.Authenticator != packet.Authenticator {
		t.Fatalf("header mismatch: %+v", parsed)
	}
	if len(parsed.Attributes) != len(packet.Attributes) {
		t.Fatalf("attribute count %d != %d", len(parsed.Attributes), len(packet.Attributes))
	}
	for i, expected := range packet.Attributes {
		actual := parsed.Attributes[i]
		if actual.Type != expected.Type || actual.VendorID != expected.VendorID || actual.VendorType != expected.VendorType || !bytes.Equal(actual.Value, expected.Value) {
			t.Fatalf("attribute %d mismatch: got %+v want %+v", i, actual, expected)
		}
	}
}

func TestPacketIgnoresTrailingPadding(t *testing.T) {
	raw := rawPacket(CodeAccessAccept, 7, tlv(AttrReplyMessage, []byte("ok")))
	padded := append(append([]byte(nil), raw...), 0, 1, 2, 3)
	parsed, err := ParsePacket(padded)
	if err != nil {
		t.Fatalf("ParsePacket with padding: %v", err)
	}
	if parsed.Code != CodeAccessAccept || parsed.Identifier != 7 {
		t.Fatalf("unexpected packet: %+v", parsed)
	}
	if messages := parsed.Attributes.Strings(AttrReplyMessage); len(messages) != 1 || messages[0] != "ok" {
		t.Fatalf("unexpected attributes: %+v", parsed.Attributes)
	}
}

func TestPacketPreservesUnknownAttributes(t *testing.T) {
	value := []byte{0, 1, 2, 3, 4}
	raw := rawPacket(CodeAccessRequest, 1, tlv(AttributeType(201), value))
	parsed, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	attribute, ok := parsed.Attributes.Get(AttributeType(201))
	if !ok || !bytes.Equal(attribute.Value, value) {
		t.Fatalf("unknown attribute not preserved: %+v", parsed.Attributes)
	}
	roundTrip, err := MarshalPacket(parsed)
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	if !bytes.Equal(roundTrip, raw) {
		t.Fatalf("round trip mismatch:\n got %x\nwant %x", roundTrip, raw)
	}
}

func TestParsePacketRejectsMalformed(t *testing.T) {
	duplicateMA := rawPacket(CodeAccessRequest, 1,
		tlv(AttrMessageAuthenticator, make([]byte, 16)),
		tlv(AttrMessageAuthenticator, make([]byte, 16)))
	badVendorShort := rawPacket(CodeAccessRequest, 1, []byte{byte(AttrVendorSpecific), 4, 0, 0, 0})
	badVendorSubLength := rawPacket(CodeAccessRequest, 1,
		[]byte{byte(AttrVendorSpecific), 9, 0, 0, 0, 9, 1, 1, 0x58})
	shortPassword := rawPacket(CodeAccessRequest, 1, tlv(AttrUserPassword, make([]byte, 15)))
	shortCHAP := rawPacket(CodeAccessRequest, 1, tlv(AttrCHAPPassword, make([]byte, 16)))

	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "empty", raw: nil, want: ErrInvalidPacket},
		{name: "short header", raw: make([]byte, HeaderLength-1), want: ErrInvalidPacket},
		{name: "zero code", raw: func() []byte {
			raw := rawPacket(CodeAccessRequest, 1)
			raw[0] = 0
			return raw
		}(), want: ErrInvalidPacket},
		{name: "length below header", raw: func() []byte {
			raw := rawPacket(CodeAccessRequest, 1)
			binary.BigEndian.PutUint16(raw[2:4], HeaderLength-1)
			return raw
		}(), want: ErrInvalidPacket},
		{name: "length above maximum", raw: func() []byte {
			raw := rawPacket(CodeAccessRequest, 1)
			binary.BigEndian.PutUint16(raw[2:4], MaxPacketLength+1)
			return raw
		}(), want: ErrInvalidPacket},
		{name: "length above received", raw: func() []byte {
			raw := rawPacket(CodeAccessRequest, 1)
			binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)+1))
			return raw
		}(), want: ErrInvalidPacket},
		{name: "truncated attribute header", raw: rawPacket(CodeAccessRequest, 1, []byte{1}), want: ErrInvalidAttribute},
		{name: "attribute type zero", raw: rawPacket(CodeAccessRequest, 1, []byte{0, 2}), want: ErrInvalidAttribute},
		{name: "attribute length below two", raw: rawPacket(CodeAccessRequest, 1, []byte{1, 1, 0x41}), want: ErrInvalidAttribute},
		{name: "attribute length above remaining", raw: rawPacket(CodeAccessRequest, 1, []byte{1, 5, 0x41}), want: ErrInvalidAttribute},
		{name: "duplicate message authenticator", raw: duplicateMA, want: ErrInvalidAttribute},
		{name: "vendor value below four", raw: badVendorShort, want: ErrInvalidAttribute},
		{name: "vendor sub-attribute length", raw: badVendorSubLength, want: ErrInvalidAttribute},
		{name: "user password length", raw: shortPassword, want: ErrInvalidAttribute},
		{name: "chap password length", raw: shortCHAP, want: ErrInvalidAttribute},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParsePacket(testCase.raw); !errors.Is(err, testCase.want) {
				t.Fatalf("ParsePacket error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestMarshalPacketValidation(t *testing.T) {
	cases := []struct {
		name   string
		packet *Packet
		want   error
	}{
		{name: "nil packet", packet: nil, want: ErrInvalidPacket},
		{name: "zero code", packet: &Packet{Code: 0}, want: ErrInvalidPacket},
		{name: "attribute type zero", packet: &Packet{Code: CodeAccessRequest, Attributes: Attributes{{Type: 0, Value: []byte{1}}}}, want: ErrInvalidAttribute},
		{name: "empty user name", packet: &Packet{Code: CodeAccessRequest, Attributes: Attributes{NewAttribute(AttrUserName, nil)}}, want: ErrInvalidAttribute},
		{name: "oversized value", packet: &Packet{Code: CodeAccessRequest, Attributes: Attributes{NewAttribute(AttrReplyMessage, make([]byte, MaxAttributeValueLength+1))}}, want: ErrInvalidAttribute},
		{name: "oversized vendor", packet: &Packet{Code: CodeAccessRequest, Attributes: Attributes{NewVendorAttribute(VendorCisco, VendorCiscoAVPair, make([]byte, 254))}}, want: ErrInvalidAttribute},
		{name: "vendor id zero", packet: &Packet{Code: CodeAccessRequest, Attributes: Attributes{{Type: AttrVendorSpecific, Value: []byte{1}}}}, want: ErrInvalidAttribute},
		{name: "packet too long", packet: &Packet{Code: CodeAccessRequest, Attributes: func() Attributes {
			attributes := make(Attributes, 0, 16)
			for i := 0; i < 16; i++ {
				attributes = append(attributes, NewAttribute(AttrReplyMessage, make([]byte, MaxAttributeValueLength)))
			}
			return attributes
		}()}, want: ErrInvalidPacket},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := MarshalPacket(testCase.packet); !errors.Is(err, testCase.want) {
				t.Fatalf("MarshalPacket error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestMarshalPacketAtMaximumLength(t *testing.T) {
	attributes := make(Attributes, 0, 16)
	for i := 0; i < 15; i++ {
		attributes = append(attributes, NewAttribute(AttrReplyMessage, make([]byte, MaxAttributeValueLength)))
	}
	attributes = append(attributes, NewAttribute(AttrReplyMessage, make([]byte, MaxAttributeValueLength-4)))
	raw, err := MarshalPacket(&Packet{Code: CodeAccessAccept, Attributes: attributes})
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	if len(raw) != MaxPacketLength {
		t.Fatalf("packet length %d != %d", len(raw), MaxPacketLength)
	}
	if _, err := ParsePacket(raw); err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
}

func TestVendorAttributeRoundTrip(t *testing.T) {
	value := []byte{1, 2, 3, 4, 5}
	raw, err := MarshalPacket(&Packet{
		Code:       CodeAccessRequest,
		Attributes: Attributes{NewVendorAttribute(VendorMicrosoft, VendorMSCHAPChallenge, value)},
	})
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	parsed, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	attribute, ok := parsed.Attributes.Vendor(VendorMicrosoft, VendorMSCHAPChallenge)
	if !ok {
		t.Fatalf("vendor attribute missing: %+v", parsed.Attributes)
	}
	if !bytes.Equal(attribute.Value, value) {
		t.Fatalf("vendor value = %x, want %x", attribute.Value, value)
	}
}
