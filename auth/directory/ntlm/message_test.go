package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// putTestUint16 writes a little-endian uint16 at offset. | putTestUint16 在 offset
// 处写入小端 uint16。
func putTestUint16(data []byte, offset int, value uint16) {
	binary.LittleEndian.PutUint16(data[offset:offset+2], value)
}

// putTestUint32 writes a little-endian uint32 at offset. | putTestUint32 在 offset
// 处写入小端 uint32。
func putTestUint32(data []byte, offset int, value uint32) {
	binary.LittleEndian.PutUint32(data[offset:offset+4], value)
}

// cloneTestBytes returns a mutable copy. | cloneTestBytes 返回可变副本。
func cloneTestBytes(data []byte) []byte {
	return append([]byte(nil), data...)
}

func TestNegotiateRoundTrip(t *testing.T) {
	version := DefaultVersion()
	original := &NegotiateMessage{
		Flags:       FlagUnicode | FlagOEM | FlagRequestTarget | FlagNTLM | FlagTargetInfo | FlagVersion,
		Domain:      "EXAMPLE",
		Workstation: "WS01",
		Version:     &version,
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeNegotiate(encoded)
	if err != nil {
		t.Fatalf("DecodeNegotiate: %v", err)
	}
	if decoded.Flags != original.Flags {
		t.Fatalf("flags = %#x, want %#x", decoded.Flags, original.Flags)
	}
	if decoded.Domain != original.Domain || decoded.Workstation != original.Workstation {
		t.Fatalf("domain/workstation = %q/%q", decoded.Domain, decoded.Workstation)
	}
	if decoded.Version == nil || *decoded.Version != version {
		t.Fatalf("version = %#v, want %#v", decoded.Version, version)
	}
}

func TestNegotiateRoundTripOEM(t *testing.T) {
	original := &NegotiateMessage{
		Flags:       FlagOEM | FlagNTLM,
		Domain:      "EXAMPLE",
		Workstation: "WS01",
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeNegotiate(encoded)
	if err != nil {
		t.Fatalf("DecodeNegotiate: %v", err)
	}
	if decoded.Domain != "EXAMPLE" || decoded.Workstation != "WS01" {
		t.Fatalf("domain/workstation = %q/%q", decoded.Domain, decoded.Workstation)
	}
	if decoded.Version != nil {
		t.Fatalf("version = %#v, want nil", decoded.Version)
	}
}

func TestNegotiateDefaultVersion(t *testing.T) {
	original := &NegotiateMessage{Flags: FlagUnicode | FlagNTLM | FlagVersion}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeNegotiate(encoded)
	if err != nil {
		t.Fatalf("DecodeNegotiate: %v", err)
	}
	if decoded.Version == nil || *decoded.Version != DefaultVersion() {
		t.Fatalf("version = %#v, want default %#v", decoded.Version, DefaultVersion())
	}
}

func TestNegotiateEncodeErrors(t *testing.T) {
	version := DefaultVersion()
	cases := []struct {
		name    string
		message *NegotiateMessage
		want    error
	}{
		{name: "nil", message: nil, want: ErrMessage},
		{name: "no charset", message: &NegotiateMessage{Flags: FlagNTLM}, want: ErrMessage},
		{name: "large domain", message: &NegotiateMessage{Flags: FlagUnicode, Domain: strings.Repeat("a", 40000)}, want: ErrMessage},
		{name: "large workstation", message: &NegotiateMessage{Flags: FlagUnicode, Workstation: strings.Repeat("a", 40000)}, want: ErrMessage},
		{name: "version present", message: &NegotiateMessage{Flags: FlagUnicode | FlagVersion, Version: &version}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.message.Encode()
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if test.want == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNegotiateDecodeErrors(t *testing.T) {
	version := DefaultVersion()
	encoded, err := (&NegotiateMessage{
		Flags:       FlagUnicode | FlagVersion,
		Domain:      "EXAMPLE",
		Workstation: "WS01",
		Version:     &version,
	}).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty", data: nil, want: ErrMessage},
		{name: "signature", data: mutateTestBytes(encoded, 0, []byte("X")), want: ErrMessage},
		{name: "type", data: mutateTestBytes(encoded, 8, []byte{2, 0, 0, 0}), want: ErrMessage},
		{name: "truncated header", data: encoded[:31], want: ErrMessage},
		{name: "domain offset below header", data: mutateTestBytes(encoded, 20, []byte{8, 0, 0, 0}), want: ErrMessage},
		{name: "domain max below length", data: mutateTestBytes(encoded, 18, []byte{0, 0}), want: ErrMessage},
		{name: "odd UTF-16 domain", data: mutateTestBytes(mutateTestBytes(encoded, 16, []byte{1, 0}), 18, []byte{1, 0}), want: ErrMessage},
		{name: "workstation out of range", data: mutateTestBytes(mutateTestBytes(encoded, 24, []byte{0xff, 0xff}), 26, []byte{0xff, 0xff}), want: ErrMessage},
		{name: "version truncated", data: encoded[:32], want: ErrMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeNegotiate(test.data)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

// mutateTestBytes returns data with value copied at offset. | mutateTestBytes
// 返回在 offset 处复制 value 后的 data。
func mutateTestBytes(data []byte, offset int, value []byte) []byte {
	out := cloneTestBytes(data)
	copy(out[offset:], value)
	return out
}

// testTargetInfo returns a representative AV pair set without the terminator. |
// testTargetInfo 返回不含终止符的代表性 AV 对集合。
func testTargetInfo() TargetInfo {
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, AVFlagMICPresent)
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, filetimeFromTime(testTimestamp()))
	bindings := bytes.Repeat([]byte{0x11}, 16)
	return TargetInfo{
		{Type: AVNbComputerName, Value: encodeString("SERVER", true)},
		{Type: AVNbDomainName, Value: encodeString("Domain", true)},
		{Type: AVDNSComputerName, Value: encodeString("server.example.com", true)},
		{Type: AVFlags, Value: flags},
		{Type: AVTimestamp, Value: timestamp},
		{Type: AVChannelBindings, Value: bindings},
	}
}

// testTimestamp is a stable timestamp used by fixtures. | testTimestamp 是夹具使用的
// 稳定时间戳。
func testTimestamp() time.Time {
	return time.Unix(1_700_000_000, 123_456_700).UTC()
}

func TestChallengeRoundTrip(t *testing.T) {
	version := DefaultVersion()
	original := &ChallengeMessage{
		Flags:           FlagUnicode | FlagNTLM | FlagTargetInfo | FlagVersion,
		ServerChallenge: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		TargetName:      "EXAMPLE",
		TargetInfo:      testTargetInfo(),
		Version:         &version,
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeChallenge(encoded)
	if err != nil {
		t.Fatalf("DecodeChallenge: %v", err)
	}
	if decoded.Flags != original.Flags {
		t.Fatalf("flags = %#x, want %#x", decoded.Flags, original.Flags)
	}
	if decoded.ServerChallenge != original.ServerChallenge {
		t.Fatalf("server challenge = %x", decoded.ServerChallenge)
	}
	if decoded.TargetName != original.TargetName {
		t.Fatalf("target name = %q", decoded.TargetName)
	}
	wantInfo, err := original.TargetInfo.Encode()
	if err != nil {
		t.Fatalf("encode want target info: %v", err)
	}
	gotInfo, err := decoded.TargetInfo.withoutEndOfList().Encode()
	if err != nil {
		t.Fatalf("encode got target info: %v", err)
	}
	if !bytes.Equal(gotInfo, wantInfo) {
		t.Fatalf("target info mismatch: %x != %x", gotInfo, wantInfo)
	}
	if decoded.Version == nil || *decoded.Version != version {
		t.Fatalf("version = %#v", decoded.Version)
	}
}

func TestChallengeRoundTripOEMWithoutVersion(t *testing.T) {
	original := &ChallengeMessage{
		Flags:           FlagOEM | FlagNTLM,
		ServerChallenge: [8]byte{9, 9, 9, 9, 9, 9, 9, 9},
		TargetName:      "EXAMPLE",
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeChallenge(encoded)
	if err != nil {
		t.Fatalf("DecodeChallenge: %v", err)
	}
	if decoded.TargetName != "EXAMPLE" {
		t.Fatalf("target name = %q", decoded.TargetName)
	}
	if len(decoded.TargetInfo.withoutEndOfList()) != 0 {
		t.Fatalf("target info = %#v, want empty", decoded.TargetInfo)
	}
	if decoded.Version != nil {
		t.Fatalf("version = %#v, want nil", decoded.Version)
	}
}

func TestChallengeEncodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		message *ChallengeMessage
		want    error
	}{
		{name: "nil", message: nil, want: ErrMessage},
		{name: "no charset", message: &ChallengeMessage{Flags: FlagNTLM}, want: ErrMessage},
		{name: "large target name", message: &ChallengeMessage{Flags: FlagUnicode, TargetName: strings.Repeat("a", 40000)}, want: ErrMessage},
		{name: "invalid target info", message: &ChallengeMessage{Flags: FlagUnicode, TargetInfo: TargetInfo{{Type: AVFlags, Value: make([]byte, 3)}}}, want: ErrTargetInfo},
		{name: "oversized AV value", message: &ChallengeMessage{Flags: FlagUnicode, TargetInfo: TargetInfo{{Type: AVNbDomainName, Value: make([]byte, 65536)}}}, want: ErrMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.message.Encode()
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestChallengeDecodeErrors(t *testing.T) {
	version := DefaultVersion()
	encoded, err := (&ChallengeMessage{
		Flags:           FlagUnicode | FlagNTLM | FlagTargetInfo | FlagVersion,
		ServerChallenge: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		TargetName:      "EXAMPLE",
		TargetInfo:      testTargetInfo(),
		Version:         &version,
	}).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	targetInfoOffset := int(binary.LittleEndian.Uint32(encoded[44:48]))
	targetInfoLength := int(binary.LittleEndian.Uint16(encoded[40:42]))
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty", data: nil, want: ErrMessage},
		{name: "signature", data: mutateTestBytes(encoded, 0, []byte("X")), want: ErrMessage},
		{name: "type", data: mutateTestBytes(encoded, 8, []byte{3, 0, 0, 0}), want: ErrMessage},
		{name: "truncated header", data: encoded[:47], want: ErrMessage},
		{name: "target name out of range", data: mutateTestBytes(encoded, 36, []byte{0xff, 0xff, 0xff, 0x7f}), want: ErrMessage},
		{name: "odd target name", data: mutateTestBytes(mutateTestBytes(encoded, 32, []byte{1, 0}), 34, []byte{1, 0}), want: ErrMessage},
		{name: "target info out of range", data: mutateTestBytes(encoded, 44, []byte{0xff, 0xff, 0xff, 0x7f}), want: ErrMessage},
		{name: "target info nonzero EOL", data: overwriteTargetInfo(encoded, targetInfoOffset, targetInfoLength, []byte{0, 0, 1, 0}), want: ErrTargetInfo},
		{name: "target info missing EOL", data: overwriteTargetInfo(encoded, targetInfoOffset, targetInfoLength, []byte{2, 0, 0, 0}), want: ErrTargetInfo},
		{name: "version truncated", data: encoded[:48], want: ErrMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeChallenge(test.data)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

// overwriteTargetInfo replaces the target-info buffer with raw and adjusts its
// security buffer. | overwriteTargetInfo 用 raw 替换目标信息缓冲区并调整其安全缓冲区。
func overwriteTargetInfo(data []byte, offset, length int, raw []byte) []byte {
	out := cloneTestBytes(data)
	copy(out[offset:offset+length], raw)
	putTestUint16(out, 40, uint16(len(raw)))
	putTestUint16(out, 42, uint16(len(raw)))
	return out
}

func TestAuthenticateRoundTripWithMIC(t *testing.T) {
	version := DefaultVersion()
	mic := bytes.Repeat([]byte{0xab}, micSize)
	original := &AuthenticateMessage{
		LMResponse:  bytes.Repeat([]byte{0x01}, 24),
		NTResponse:  bytes.Repeat([]byte{0x02}, 64),
		Domain:      "EXAMPLE",
		Username:    "alice",
		Workstation: "WS01",
		SessionKey:  bytes.Repeat([]byte{0x03}, 16),
		Flags:       FlagUnicode | FlagNTLM | FlagVersion,
		Version:     &version,
		MIC:         mic,
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeAuthenticate(encoded)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	if !bytes.Equal(decoded.LMResponse, original.LMResponse) || !bytes.Equal(decoded.NTResponse, original.NTResponse) {
		t.Fatalf("responses mismatch")
	}
	if decoded.Domain != original.Domain || decoded.Username != original.Username || decoded.Workstation != original.Workstation {
		t.Fatalf("strings mismatch: %#v", decoded)
	}
	if !bytes.Equal(decoded.SessionKey, original.SessionKey) {
		t.Fatalf("session key mismatch")
	}
	if decoded.Flags != original.Flags {
		t.Fatalf("flags = %#x, want %#x", decoded.Flags, original.Flags)
	}
	if decoded.Version == nil || *decoded.Version != version {
		t.Fatalf("version = %#v", decoded.Version)
	}
	if !bytes.Equal(decoded.MIC, mic) {
		t.Fatalf("MIC = %x, want %x", decoded.MIC, mic)
	}
}

func TestAuthenticateRoundTripWithoutMIC(t *testing.T) {
	original := &AuthenticateMessage{
		NTResponse: bytes.Repeat([]byte{0x02}, 32),
		Domain:     "EXAMPLE",
		Username:   "alice",
		Flags:      FlagUnicode | FlagNTLM,
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeAuthenticate(encoded)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	if decoded.MIC != nil {
		t.Fatalf("MIC = %x, want nil", decoded.MIC)
	}
	if decoded.Domain != "EXAMPLE" || decoded.Username != "alice" || decoded.Workstation != "" {
		t.Fatalf("strings mismatch: %#v", decoded)
	}
	if decoded.LMResponse != nil || decoded.SessionKey != nil {
		t.Fatalf("unexpected empty fields: %#v", decoded)
	}
}

func TestAuthenticateMICWithOnlyEmptyFields(t *testing.T) {
	mic := bytes.Repeat([]byte{0xcd}, micSize)
	original := &AuthenticateMessage{Flags: FlagUnicode | FlagNTLM, MIC: mic}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeAuthenticate(encoded)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	if !bytes.Equal(decoded.MIC, mic) {
		t.Fatalf("MIC = %x, want %x", decoded.MIC, mic)
	}
}

func TestAuthenticateOEMRoundTrip(t *testing.T) {
	original := &AuthenticateMessage{
		NTResponse: []byte{1, 2, 3},
		Domain:     "EXAMPLE",
		Username:   "alice",
		Flags:      FlagOEM | FlagNTLM,
	}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeAuthenticate(encoded)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	if decoded.Username != "alice" || !bytes.Equal(decoded.NTResponse, []byte{1, 2, 3}) {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestAuthenticateEncodeErrors(t *testing.T) {
	tests := []struct {
		name    string
		message *AuthenticateMessage
		want    error
	}{
		{name: "nil", message: nil, want: ErrMessage},
		{name: "no charset", message: &AuthenticateMessage{Flags: FlagNTLM}, want: ErrMessage},
		{name: "short MIC", message: &AuthenticateMessage{Flags: FlagUnicode, MIC: make([]byte, 15)}, want: ErrMessage},
		{name: "large LM response", message: &AuthenticateMessage{Flags: FlagUnicode, LMResponse: make([]byte, 65536)}, want: ErrMessage},
		{name: "large NT response", message: &AuthenticateMessage{Flags: FlagUnicode, NTResponse: make([]byte, 65536)}, want: ErrMessage},
		{name: "large domain", message: &AuthenticateMessage{Flags: FlagUnicode, Domain: strings.Repeat("a", 40000)}, want: ErrMessage},
		{name: "large username", message: &AuthenticateMessage{Flags: FlagUnicode, Username: strings.Repeat("a", 40000)}, want: ErrMessage},
		{name: "large workstation", message: &AuthenticateMessage{Flags: FlagUnicode, Workstation: strings.Repeat("a", 40000)}, want: ErrMessage},
		{name: "large session key", message: &AuthenticateMessage{Flags: FlagUnicode, SessionKey: make([]byte, 65536)}, want: ErrMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.message.Encode()
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuthenticateDecodeErrors(t *testing.T) {
	version := DefaultVersion()
	encoded, err := (&AuthenticateMessage{
		LMResponse:  bytes.Repeat([]byte{1}, 24),
		NTResponse:  bytes.Repeat([]byte{2}, 48),
		Domain:      "EXAMPLE",
		Username:    "alice",
		Workstation: "WS01",
		Flags:       FlagUnicode | FlagNTLM | FlagVersion,
		Version:     &version,
	}).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty", data: nil, want: ErrMessage},
		{name: "signature", data: mutateTestBytes(encoded, 0, []byte("X")), want: ErrMessage},
		{name: "type", data: mutateTestBytes(encoded, 8, []byte{1, 0, 0, 0}), want: ErrMessage},
		{name: "truncated header", data: encoded[:63], want: ErrMessage},
		{name: "NT response out of range", data: mutateTestBytes(mutateTestBytes(encoded, 20, []byte{0xff, 0xff}), 22, []byte{0xff, 0xff}), want: ErrMessage},
		{name: "odd UTF-16 username", data: mutateTestBytes(mutateTestBytes(encoded, 36, []byte{1, 0}), 38, []byte{1, 0}), want: ErrMessage},
		{name: "version truncated", data: encoded[:64], want: ErrMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeAuthenticate(test.data)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSecurityBufferValue(t *testing.T) {
	if value, err := (securityBuffer{}).value(make([]byte, 32), 8); err != nil || value != nil {
		t.Fatalf("empty buffer = %v, %v", value, err)
	}
	header := 16
	data := make([]byte, 32)
	copy(data[header:], []byte("payload"))
	buffer := securityBuffer{length: 7, maxLength: 7, offset: uint32(header)}
	value, err := buffer.value(data, header)
	if err != nil || string(value) != "payload" {
		t.Fatalf("value = %q, %v", value, err)
	}
	value[0] = 'X'
	if data[header] != 'p' {
		t.Fatalf("value did not copy: %q", data[header:])
	}
	cases := []securityBuffer{
		{length: 7, maxLength: 6, offset: uint32(header)},
		{length: 7, maxLength: 7, offset: uint32(header - 1)},
		{length: 7, maxLength: 7, offset: uint32(len(data) - 6)},
	}
	for _, item := range cases {
		if _, err := item.value(data, header); !errors.Is(err, ErrMessage) {
			t.Fatalf("buffer %#v error = %v", item, err)
		}
	}
}

func TestDecodeSecurityBufferTruncated(t *testing.T) {
	if _, err := decodeSecurityBuffer(make([]byte, 7), 0); !errors.Is(err, ErrMessage) {
		t.Fatalf("error = %v", err)
	}
	if _, err := decodeSecurityBuffer(make([]byte, 8), -1); !errors.Is(err, ErrMessage) {
		t.Fatalf("negative offset error = %v", err)
	}
}

func TestDecodeVersionTruncated(t *testing.T) {
	if _, err := decodeVersion(make([]byte, 7), 0); !errors.Is(err, ErrMessage) {
		t.Fatalf("error = %v", err)
	}
	if _, err := decodeVersion(make([]byte, 8), -1); !errors.Is(err, ErrMessage) {
		t.Fatalf("negative offset error = %v", err)
	}
}

func TestCheckFieldSize(t *testing.T) {
	if err := checkFieldSize("field", make([]byte, 0xffff)); err != nil {
		t.Fatalf("65535 bytes: %v", err)
	}
	if err := checkFieldSize("field", make([]byte, 0x10000)); !errors.Is(err, ErrMessage) {
		t.Fatalf("65536 bytes: %v", err)
	}
}
