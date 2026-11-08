package radius

import (
	"bytes"
	"errors"
	"testing"
)

func TestEAPPacketRoundTrip(t *testing.T) {
	packet := &EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: 7,
		Type:       EAPTypeIdentity,
		Data:       []byte("alice@example.test"),
	}
	raw, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if int(packet.Length) != 0 {
		t.Fatalf("MarshalBinary mutated Length = %d", packet.Length)
	}
	if len(raw) != EAPHeaderLength+1+len(packet.Data) {
		t.Fatalf("encoded length = %d", len(raw))
	}
	parsed, err := ParseEAPPacket(raw)
	if err != nil {
		t.Fatalf("ParseEAPPacket: %v", err)
	}
	if parsed.Code != packet.Code || parsed.Identifier != packet.Identifier ||
		parsed.Type != packet.Type || !bytes.Equal(parsed.Data, packet.Data) {
		t.Fatalf("parsed packet = %+v", parsed)
	}
	identity, err := EAPResponseIdentity(&EAPPacket{
		Code:       EAPCodeResponse,
		Identifier: 8,
		Type:       EAPTypeIdentity,
		Data:       []byte("bob"),
	})
	if err != nil || identity != "bob" {
		t.Fatalf("EAPResponseIdentity = %q, %v", identity, err)
	}
	if _, err := EAPResponseIdentity(parsed); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("EAPResponseIdentity on a Request = %v, want ErrInvalidRequest", err)
	}
	if _, err := EAPResponseIdentity(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("EAPResponseIdentity(nil) = %v, want ErrInvalidRequest", err)
	}

	success, err := newEAPSuccess(9).MarshalBinary()
	if err != nil {
		t.Fatalf("Success MarshalBinary: %v", err)
	}
	if !bytes.Equal(success, []byte{byte(EAPCodeSuccess), 9, 0, EAPHeaderLength}) {
		t.Fatalf("Success encoding = %x", success)
	}
	failure, err := ParseEAPPacket([]byte{byte(EAPCodeFailure), 10, 0, EAPHeaderLength})
	if err != nil {
		t.Fatalf("ParseEAPPacket Failure: %v", err)
	}
	if failure.Code != EAPCodeFailure || failure.Type != 0 || len(failure.Data) != 0 {
		t.Fatalf("Failure = %+v", failure)
	}
	if _, err := (&EAPPacket{Code: EAPCodeSuccess, Data: []byte{1}}).MarshalBinary(); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Success with data error = %v, want ErrInvalidPacket", err)
	}
	if _, err := (&EAPPacket{Code: EAPCodeRequest}).MarshalBinary(); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Request without type error = %v, want ErrInvalidPacket", err)
	}
}

func TestParseEAPPacketValidation(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "short", raw: []byte{1, 2, 3}},
		{name: "invalid code", raw: []byte{0, 1, 0, 4}},
		{name: "declared longer", raw: []byte{1, 1, 0, 9, byte(EAPTypeIdentity)}},
		{name: "declared shorter", raw: []byte{1, 1, 0, 4, byte(EAPTypeIdentity)}},
		{name: "success with type", raw: []byte{byte(EAPCodeSuccess), 1, 0, 5, byte(EAPTypeIdentity)}},
		{name: "request without type", raw: []byte{1, 1, 0, 4}},
		{name: "reserved type", raw: []byte{1, 1, 0, 5, 0}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParseEAPPacket(testCase.raw); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("error = %v, want ErrInvalidPacket", err)
			}
		})
	}
}

func TestEAPMessageFragmentation(t *testing.T) {
	message, err := (&EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: 3,
		Type:       EAPTypeTLS,
		Data:       bytes.Repeat([]byte{0xab}, 300),
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	fragments, err := SplitEAPMessage(message, 7)
	if err != nil {
		t.Fatalf("SplitEAPMessage: %v", err)
	}
	if len(fragments) != (len(message)+6)/7 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	var joined []byte
	for index, fragment := range fragments {
		if len(fragment) > 7 || len(fragment) == 0 {
			t.Fatalf("fragment %d length = %d", index, len(fragment))
		}
		joined = append(joined, fragment...)
	}
	if !bytes.Equal(joined, message) {
		t.Fatal("concatenated fragments do not reconstruct the EAP message")
	}

	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	if err := AppendEAPMessage(&attributes, message); err != nil {
		t.Fatalf("AppendEAPMessage: %v", err)
	}
	attributes.AddString(AttrNASIdentifier, "nas")
	values := attributes.GetAll(AttrEAPMessage)
	if len(values) != 2 {
		t.Fatalf("EAP-Message attribute count = %d, want 2", len(values))
	}
	reassembled, err := ReassembleEAPMessages(attributes)
	if err != nil {
		t.Fatalf("ReassembleEAPMessages: %v", err)
	}
	if !bytes.Equal(reassembled, message) {
		t.Fatal("reassembled EAP message differs")
	}
	parsed, err := ParseEAPPacket(reassembled)
	if err != nil || parsed.Type != EAPTypeTLS {
		t.Fatalf("reassembled packet = %+v, %v", parsed, err)
	}

	if _, err := SplitEAPMessage(nil, 1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty message error = %v, want ErrInvalidRequest", err)
	}
	if _, err := SplitEAPMessage(message, -1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative fragment error = %v, want ErrInvalidRequest", err)
	}
	if _, err := SplitEAPMessage(message, MaxAttributeValueLength+1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized fragment error = %v, want ErrInvalidRequest", err)
	}
	if err := AppendEAPMessage(nil, message); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("AppendEAPMessage nil attributes error = %v, want ErrInvalidRequest", err)
	}
	if _, err := ReassembleEAPMessages(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ReassembleEAPMessages empty error = %v, want ErrInvalidRequest", err)
	}
}
