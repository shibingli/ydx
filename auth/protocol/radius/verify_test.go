package radius

import (
	"bytes"
	"crypto/md5"
	"errors"
	"testing"
)

func testAuthenticator(seed byte) [16]byte {
	var authenticator [16]byte
	for i := range authenticator {
		authenticator[i] = seed + byte(i)
	}
	return authenticator
}

func TestMessageAuthenticatorRequest(t *testing.T) {
	secret := []byte("testing-secret")
	requestAuthenticator := testAuthenticator(0x10)
	packet := &Packet{
		Code:          CodeAccessRequest,
		Identifier:    7,
		Authenticator: requestAuthenticator,
		Attributes: Attributes{
			NewAttribute(AttrUserName, []byte("alice")),
			NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
		},
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	if err := signMessageAuthenticator(raw, secret, requestAuthenticator); err != nil {
		t.Fatalf("signMessageAuthenticator: %v", err)
	}
	attribute, ok := mustParse(t, raw).Attributes.Get(AttrMessageAuthenticator)
	if !ok {
		t.Fatal("Message-Authenticator missing")
	}
	if bytes.Equal(attribute.Value, make([]byte, 16)) {
		t.Fatal("Message-Authenticator was not filled")
	}
	present, valid, err := verifyMessageAuthenticatorRaw(raw, secret, requestAuthenticator)
	if err != nil || !present || !valid {
		t.Fatalf("verifyMessageAuthenticatorRaw = %v, %v, %v", present, valid, err)
	}

	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	present, valid, err = verifyMessageAuthenticatorRaw(tampered, secret, requestAuthenticator)
	if err != nil || !present || valid {
		t.Fatalf("tampered verify = %v, %v, %v", present, valid, err)
	}

	without := &Packet{
		Code:          CodeAccessRequest,
		Identifier:    7,
		Authenticator: requestAuthenticator,
		Attributes:    Attributes{NewAttribute(AttrUserName, []byte("alice"))},
	}
	withoutRaw, err := MarshalPacket(without)
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	present, valid, err = verifyMessageAuthenticatorRaw(withoutRaw, secret, requestAuthenticator)
	if err != nil || present || valid {
		t.Fatalf("missing verify = %v, %v, %v", present, valid, err)
	}
	if err := signMessageAuthenticator(withoutRaw, secret, requestAuthenticator); !errors.Is(err, ErrMessageAuthenticator) {
		t.Fatalf("sign without attribute error = %v", err)
	}

	duplicate := rawPacket(CodeAccessRequest, 1,
		tlv(AttrMessageAuthenticator, make([]byte, 16)),
		tlv(AttrMessageAuthenticator, make([]byte, 16)))
	if err := signMessageAuthenticator(duplicate, secret, requestAuthenticator); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("duplicate signing error = %v", err)
	}
}

func TestMessageAuthenticatorResponse(t *testing.T) {
	secret := []byte("testing-secret")
	requestAuthenticator := testAuthenticator(0x20)
	packet := &Packet{
		Code:          CodeAccessAccept,
		Identifier:    9,
		Authenticator: requestAuthenticator,
		Attributes: Attributes{
			NewAttribute(AttrReplyMessage, []byte("welcome")),
			NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
		},
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	if err := signMessageAuthenticator(raw, secret, requestAuthenticator); err != nil {
		t.Fatalf("signMessageAuthenticator: %v", err)
	}
	if err := applyResponseAuthenticator(raw, secret); err != nil {
		t.Fatalf("applyResponseAuthenticator: %v", err)
	}
	if bytes.Equal(raw[4:HeaderLength], requestAuthenticator[:]) {
		t.Fatal("Response Authenticator was not applied")
	}
	if err := verifyResponseAuthenticator(raw, secret, requestAuthenticator); err != nil {
		t.Fatalf("verifyResponseAuthenticator: %v", err)
	}
	present, valid, err := verifyMessageAuthenticatorRaw(raw, secret, requestAuthenticator)
	if err != nil || !present || !valid {
		t.Fatalf("response Message-Authenticator = %v, %v, %v", present, valid, err)
	}
	if err := verifyResponseAuthenticator(raw, []byte("wrong-secret"), requestAuthenticator); !errors.Is(err, ErrAuthenticator) {
		t.Fatalf("wrong secret error = %v", err)
	}

	tampered := append([]byte(nil), raw...)
	tampered[HeaderLength+2] ^= 0xff
	if err := verifyResponseAuthenticator(tampered, secret, requestAuthenticator); !errors.Is(err, ErrAuthenticator) {
		t.Fatalf("tampered response error = %v", err)
	}
	present, valid, err = verifyMessageAuthenticatorRaw(tampered, secret, requestAuthenticator)
	if err != nil || !present || valid {
		t.Fatalf("tampered Message-Authenticator = %v, %v, %v", present, valid, err)
	}
}

func TestResponseAuthenticatorMatchesMD5(t *testing.T) {
	secret := []byte("testing-secret")
	requestAuthenticator := testAuthenticator(0x30)
	packet := &Packet{
		Code:          CodeAccessReject,
		Identifier:    11,
		Authenticator: requestAuthenticator,
		Attributes:    Attributes{NewAttribute(AttrReplyMessage, []byte("denied"))},
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	expected, err := responseAuthenticator(raw, secret, requestAuthenticator)
	if err != nil {
		t.Fatalf("responseAuthenticator: %v", err)
	}
	input := append(append([]byte(nil), raw...), secret...)
	copy(input[4:HeaderLength], requestAuthenticator[:])
	manual := md5.Sum(input)
	if expected != manual {
		t.Fatalf("response authenticator = %x, want %x", expected, manual)
	}
	if err := applyResponseAuthenticator(raw, secret); err != nil {
		t.Fatalf("applyResponseAuthenticator: %v", err)
	}
	if !bytes.Equal(raw[4:HeaderLength], expected[:]) {
		t.Fatalf("applied authenticator = %x, want %x", raw[4:HeaderLength], expected)
	}
}

func TestAccountingRequestAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	packet := &Packet{
		Code:       CodeAccountingRequest,
		Identifier: 13,
		Attributes: Attributes{
			NewAttribute(AttrAcctStatusType, []byte{0, 0, 0, 1}),
			NewAttribute(AttrAcctSessionID, []byte("session-1")),
		},
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	expected, err := accountingRequestAuthenticator(raw, secret)
	if err != nil {
		t.Fatalf("accountingRequestAuthenticator: %v", err)
	}
	manual := md5.Sum(append(append([]byte(nil), raw...), secret...))
	if expected != manual {
		t.Fatalf("accounting authenticator = %x, want %x", expected, manual)
	}
	copy(raw[4:HeaderLength], expected[:])
	if err := verifyAccountingRequestAuthenticator(raw, secret); err != nil {
		t.Fatalf("verifyAccountingRequestAuthenticator: %v", err)
	}
	raw[HeaderLength+2] ^= 0xff
	if err := verifyAccountingRequestAuthenticator(raw, secret); !errors.Is(err, ErrAuthenticator) {
		t.Fatalf("tampered accounting request error = %v", err)
	}
}

// mustParse parses raw or fails the test. | mustParse 解析 raw，失败时终止测试。
func mustParse(t *testing.T, raw []byte) *Packet {
	t.Helper()
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	return packet
}
