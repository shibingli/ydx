package ntlm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// mechListTypesDER is the canonical DER SEQUENCE OF OID for the NTLMSSP
// mechanism. | mechListTypesDER 是 NTLMSSP 机制的规范 DER SEQUENCE OF OID。
const mechListTypesDER = "300c060a2b06010401823702020a"

func TestMechListMICVectors(t *testing.T) {
	der := mustHex(t, mechListTypesDER)
	encoded, err := EncodeMechTypeList([][]byte{ntlmMechOID})
	if err != nil {
		t.Fatalf("EncodeMechTypeList: %v", err)
	}
	if !bytes.Equal(encoded, der) {
		t.Fatalf("mechTypes DER = %x, want %x", encoded, der)
	}
	responseKey := NTLMv2Hash("Password", "User", "Domain")
	if got := hex.EncodeToString(responseKey); got != "0c868a403bfd7a93a3001ef22ef02e3f" {
		t.Fatalf("NTLMv2Hash = %s", got)
	}
	response, err := ComputeNTLMv2Response(
		responseKey,
		[]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		mustHex(t, clientChallengeHex),
		time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
		mustHex(t, clientTargetInfoHex),
	)
	if err != nil {
		t.Fatalf("ComputeNTLMv2Response: %v", err)
	}
	if got := hex.EncodeToString(response.SessionBaseKey); got != "8de40ccadbc14a82f15cb0ad0de95ca3" {
		t.Fatalf("SessionBaseKey = %s", got)
	}
	input := append(append([]byte(nil), []byte(Signature)...), der...)
	if got := hex.EncodeToString(testHMACMD5(response.SessionBaseKey, input)); got != "9c354f8929ea32f3fe81c1dcab232f89" {
		t.Fatalf("independent HMAC = %s", got)
	}
	mic, err := ComputeMechListMIC(response.SessionBaseKey, der, 0)
	if err != nil {
		t.Fatalf("ComputeMechListMIC: %v", err)
	}
	if got := hex.EncodeToString(mic); got != "9c354f8929ea32f3fe81c1dcab232f89" {
		t.Fatalf("mechListMIC = %s", got)
	}
	if err := VerifyMechListMIC(response.SessionBaseKey, der, mic, 0); err != nil {
		t.Fatalf("VerifyMechListMIC: %v", err)
	}
	if err := VerifyMechListMIC(response.SessionBaseKey, der, mic, FlagKeyExchange); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("flags mismatch error = %v", err)
	}

	encapsulated, err := ComputeMechListMIC(response.SessionBaseKey, der, FlagKeyExchange)
	if err != nil {
		t.Fatalf("ComputeMechListMIC RC4: %v", err)
	}
	if got := hex.EncodeToString(encapsulated); got != "0cbac88833761e363f1a8860f5bfaae2" {
		t.Fatalf("RC4 mechListMIC = %s", got)
	}
	if err := VerifyMechListMIC(response.SessionBaseKey, der, encapsulated, FlagKeyExchange); err != nil {
		t.Fatalf("VerifyMechListMIC RC4: %v", err)
	}

	bad := append([]byte(nil), mic...)
	bad[0] ^= 0xff
	if err := VerifyMechListMIC(response.SessionBaseKey, der, bad, 0); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("tampered MIC error = %v", err)
	}
	if err := VerifyMechListMIC(response.SessionBaseKey, der, mic[:15], 0); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("short MIC error = %v", err)
	}
	if err := VerifyMechListMIC(response.SessionBaseKey, der, nil, 0); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("nil MIC error = %v", err)
	}
}

func TestEncodeMechTypeList(t *testing.T) {
	if _, err := EncodeMechTypeList(nil); !errors.Is(err, ErrSPNEGO) {
		t.Fatalf("empty list error = %v", err)
	}
	if _, err := EncodeMechTypeList([][]byte{ntlmMechOID, nil}); !errors.Is(err, ErrSPNEGO) {
		t.Fatalf("empty OID error = %v", err)
	}
	encoded, err := EncodeMechTypeList([][]byte{spnegoMechOID, ntlmMechOID})
	if err != nil {
		t.Fatalf("EncodeMechTypeList: %v", err)
	}
	want := mustHex(t, "301406062b0601050502060a2b06010401823702020a")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("two-mechanism DER = %x, want %x", encoded, want)
	}
}

func TestComputeMechListMICValidation(t *testing.T) {
	key := make([]byte, md4Size)
	tests := []struct {
		name string
		key  []byte
		der  []byte
	}{
		{name: "nil key", der: mustHex(t, mechListTypesDER)},
		{name: "short key", key: key[:15], der: mustHex(t, mechListTypesDER)},
		{name: "nil list", key: key},
		{name: "wrong tag", key: key, der: []byte{0x31, 0x00}},
		{name: "trailing bytes", key: key, der: append(mustHex(t, mechListTypesDER), 0x00)},
		{name: "entry not OID", key: key, der: []byte{0x30, 0x02, 0x04, 0x00}},
		{name: "empty OID", key: key, der: []byte{0x30, 0x02, 0x06, 0x00}},
		{name: "empty list", key: key, der: []byte{0x30, 0x00}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ComputeMechListMIC(test.key, test.der, 0); !errors.Is(err, ErrMechListMIC) {
				t.Fatalf("error = %v, want ErrMechListMIC", err)
			}
		})
	}
}

func TestClientMechListMIC(t *testing.T) {
	der := mustHex(t, mechListTypesDER)
	server := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	config := clientConfig()
	config.ForceMIC = true
	client := clientCreate(t, config)
	type1, err := client.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	challenge := clientChallengeBytes(t, clientServerFlags(), server, clientOfficialTargetInfo(t))
	type3, err := client.Authenticate(challenge)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	message, err := DecodeAuthenticate(type3)
	if err != nil {
		t.Fatalf("DecodeAuthenticate: %v", err)
	}
	if message.MIC == nil {
		t.Fatalf("Type 3 MIC is missing")
	}
	if !client.UsedMIC() {
		t.Fatalf("UsedMIC = false")
	}
	flags, err := client.NegotiatedFlags()
	if err != nil {
		t.Fatalf("NegotiatedFlags: %v", err)
	}
	if !flags.Has(FlagUnicode) || !flags.Has(FlagNTLM) {
		t.Fatalf("negotiated flags = %#x", flags)
	}
	mic, err := client.MechListMIC(der)
	if err != nil {
		t.Fatalf("MechListMIC: %v", err)
	}
	if got := hex.EncodeToString(mic); got != "9c354f8929ea32f3fe81c1dcab232f89" {
		t.Fatalf("client mechListMIC = %s", got)
	}
	if err := client.VerifyMechListMIC(der, mic); err != nil {
		t.Fatalf("VerifyMechListMIC: %v", err)
	}
	bad := append([]byte(nil), mic...)
	bad[0] ^= 0x01
	if err := client.VerifyMechListMIC(der, bad); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("tampered client MIC error = %v", err)
	}
	if _, err := client.MechListMIC([]byte{0x31, 0x00}); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("malformed mechTypes error = %v", err)
	}

	// The Type 1 message must not be affected by computing the session MIC. |
	// 计算会话 MIC 不得影响 Type 1 消息。
	decoded, err := DecodeNegotiate(type1)
	if err != nil {
		t.Fatalf("DecodeNegotiate: %v", err)
	}
	if !decoded.Flags.Has(FlagNTLM) {
		t.Fatalf("Type 1 flags = %#x", decoded.Flags)
	}
}

func TestClientMechListMICLegacyUnavailable(t *testing.T) {
	der := mustHex(t, mechListTypesDER)
	config := clientConfig()
	config.ResponseMode = ResponseNTLMv1
	config.AllowLegacy = true
	client := clientCreate(t, config)
	if _, err := client.Negotiate(); err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	flags := clientServerFlags() &^ FlagExtendedSessionSecurity
	challenge := clientChallengeBytes(t, flags, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, clientDomainTargetInfo())
	if _, err := client.Authenticate(challenge); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := client.MechListMIC(der); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("MechListMIC error = %v", err)
	}
	if err := client.VerifyMechListMIC(der, make([]byte, MechListMICSize)); !errors.Is(err, ErrMechListMIC) {
		t.Fatalf("VerifyMechListMIC error = %v", err)
	}
}

func TestClientMechListMICStateOrder(t *testing.T) {
	der := mustHex(t, mechListTypesDER)
	client := clientCreate(t, clientConfig())
	if _, err := client.MechListMIC(der); !errors.Is(err, ErrClientState) {
		t.Fatalf("MechListMIC before Authenticate error = %v", err)
	}
	if err := client.VerifyMechListMIC(der, nil); !errors.Is(err, ErrClientState) {
		t.Fatalf("VerifyMechListMIC before Authenticate error = %v", err)
	}
	if _, err := client.NegotiatedFlags(); !errors.Is(err, ErrClientState) {
		t.Fatalf("NegotiatedFlags before Authenticate error = %v", err)
	}
	if client.UsedMIC() {
		t.Fatalf("UsedMIC = true before Authenticate")
	}
	if _, err := client.Negotiate(); err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if _, err := client.MechListMIC(der); !errors.Is(err, ErrClientState) {
		t.Fatalf("MechListMIC after Negotiate error = %v", err)
	}
}
