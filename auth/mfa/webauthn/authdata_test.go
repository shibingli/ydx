package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func minimalAuthData(rpID string, flags Flags, signCount uint32) []byte {
	hash := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37)
	out = append(out, hash[:]...)
	out = append(out, byte(flags))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], signCount)
	out = append(out, count[:]...)
	return out
}

func TestParseAuthenticatorDataMinimal(t *testing.T) {
	raw := minimalAuthData(testRPID, FlagUserPresent, 7)
	data, err := ParseAuthenticatorData(raw)
	if err != nil {
		t.Fatalf("ParseAuthenticatorData: %v", err)
	}
	if data.Flags != FlagUserPresent || data.SignCount != 7 {
		t.Fatalf("parsed = %#v", data)
	}
	if !data.Flags.UserPresent() || data.Flags.UserVerified() {
		t.Fatalf("flags = %#x", data.Flags)
	}
	if !bytes.Equal(data.Raw, raw) {
		t.Fatal("Raw does not copy the input")
	}
	if data.CredentialID != nil || data.CredentialPublicKey != nil || data.Extensions != nil {
		t.Fatalf("minimal data has unexpected fields: %#v", data)
	}
	if !data.AAGUIDIsZero() {
		t.Fatal("minimal data AAGUID is not zero")
	}
	if err := data.VerifyRPIDHash(testRPID); err != nil {
		t.Fatalf("VerifyRPIDHash: %v", err)
	}
	if err := data.VerifyRPIDHash("other.example"); !errors.Is(err, ErrRPIDMismatch) {
		t.Fatalf("mismatched RP ID error = %v", err)
	}
	var nilData *AuthenticatorData
	if err := nilData.VerifyRPIDHash(testRPID); err == nil {
		t.Fatal("nil authenticator data passed RP ID verification")
	}
	if !nilData.AAGUIDIsZero() {
		t.Fatal("nil authenticator data AAGUID is not zero")
	}
}

func TestParseAuthenticatorDataAttestedCredential(t *testing.T) {
	signer := newECSigner(t)
	aaguid := [16]byte{9, 8, 7, 6}
	credID := []byte("credential-id-123")
	raw := buildAuthData(t, testRPID, FlagUserPresent|FlagUserVerified|FlagAttestedCredentialData, 12, aaguid, credID, signer.coseKey(t), nil)
	data, err := ParseAuthenticatorData(raw)
	if err != nil {
		t.Fatalf("ParseAuthenticatorData: %v", err)
	}
	if data.AAGUID != aaguid {
		t.Fatalf("AAGUID = %x", data.AAGUID)
	}
	if !bytes.Equal(data.CredentialID, credID) {
		t.Fatalf("CredentialID = %x", data.CredentialID)
	}
	if data.CredentialPublicKey == nil || data.CredentialPublicKey.Alg != AlgES256 {
		t.Fatalf("CredentialPublicKey = %#v", data.CredentialPublicKey)
	}
	if len(data.CredentialPublicKeyRaw) == 0 {
		t.Fatal("CredentialPublicKeyRaw is empty")
	}
	reparsed, err := ParseCOSEKey(data.CredentialPublicKeyRaw)
	if err != nil {
		t.Fatalf("ParseCOSEKey(raw): %v", err)
	}
	if reparsed.Alg != AlgES256 {
		t.Fatalf("raw key algorithm = %d", reparsed.Alg)
	}
	if !data.Flags.UserPresent() || !data.Flags.UserVerified() || !data.Flags.AttestedCredentialData() {
		t.Fatalf("flags = %#x", data.Flags)
	}
	if data.AAGUIDIsZero() {
		t.Fatal("non-zero AAGUID reported as zero")
	}
}

func TestParseAuthenticatorDataExtensions(t *testing.T) {
	extensions := NewMap(
		Pair{Key: NewText("credProtect"), Value: NewText("userVerificationRequired")},
		Pair{Key: NewText("credProps"), Value: NewMap(Pair{Key: NewText("rk"), Value: NewBool(true)})},
		Pair{Key: NewText("uvm"), Value: NewArray(NewUint(2))},
		Pair{Key: NewText("enabled"), Value: NewBool(true)},
	)
	raw := buildAuthData(t, testRPID, FlagUserPresent|FlagExtensionData, 0, [16]byte{}, nil, nil, extensions)
	data, err := ParseAuthenticatorData(raw)
	if err != nil {
		t.Fatalf("ParseAuthenticatorData: %v", err)
	}
	if data.Extensions == nil || len(data.Extensions.Pairs) != 4 {
		t.Fatalf("Extensions = %#v", data.Extensions)
	}
	if value, ok := data.CredentialProtection(); !ok || value != "userVerificationRequired" {
		t.Fatalf("CredentialProtection = %q, %v", value, ok)
	}
	if value, ok := data.ExtensionString("credProtect"); !ok || value != "userVerificationRequired" {
		t.Fatalf("ExtensionString = %q, %v", value, ok)
	}
	if value, ok := data.ExtensionBool("enabled"); !ok || !value {
		t.Fatalf("ExtensionBool = %v, %v", value, ok)
	}
	if _, ok := data.ExtensionBool("credProtect"); ok {
		t.Fatal("text extension reported as boolean")
	}
	if _, ok := data.Extension("missing"); ok {
		t.Fatal("missing extension found")
	}
	names := data.ExtensionNames()
	want := []string{"credProps", "credProtect", "enabled", "uvm"}
	if len(names) != len(want) {
		t.Fatalf("ExtensionNames = %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("ExtensionNames = %v, want %v", names, want)
		}
	}
	var nilData *AuthenticatorData
	if names := nilData.ExtensionNames(); names != nil {
		t.Fatalf("nil ExtensionNames = %v", names)
	}
	if _, ok := nilData.Extension("credProtect"); ok {
		t.Fatal("nil authenticator data returned an extension")
	}
}

func TestParseAuthenticatorDataInvalid(t *testing.T) {
	signer := newECSigner(t)
	withAT := buildAuthData(t, testRPID, FlagUserPresent|FlagAttestedCredentialData, 0, [16]byte{}, []byte("cred"), signer.coseKey(t), nil)
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty", data: nil, want: ErrInvalidAuthenticatorData},
		{name: "short", data: make([]byte, 36), want: ErrInvalidAuthenticatorData},
		{name: "BS without BE", data: minimalAuthData(testRPID, FlagUserPresent|FlagBackupState, 0), want: ErrInvalidAuthenticatorData},
		{name: "trailing bytes", data: append(minimalAuthData(testRPID, FlagUserPresent, 0), 0x00), want: ErrInvalidAuthenticatorData},
		{name: "truncated AAGUID", data: minimalAuthData(testRPID, FlagUserPresent|FlagAttestedCredentialData, 0), want: ErrInvalidAuthenticatorData},
		{name: "zero credential ID", data: buildAuthData(t, testRPID, FlagUserPresent|FlagAttestedCredentialData, 0, [16]byte{}, nil, signer.coseKey(t), nil), want: ErrInvalidAuthenticatorData},
		{name: "credential ID length overflow", data: func() []byte {
			data := minimalAuthData(testRPID, FlagUserPresent|FlagAttestedCredentialData, 0)
			data = append(data, make([]byte, 16)...)
			data = append(data, 0xff, 0xff)
			return data
		}(), want: ErrInvalidAuthenticatorData},
		{name: "truncated credential ID", data: func() []byte {
			data := minimalAuthData(testRPID, FlagUserPresent|FlagAttestedCredentialData, 0)
			data = append(data, make([]byte, 16)...)
			data = append(data, 0x00, 0x10, 0x01, 0x02)
			return data
		}(), want: ErrInvalidAuthenticatorData},
		{name: "invalid COSE key", data: func() []byte {
			data := minimalAuthData(testRPID, FlagUserPresent|FlagAttestedCredentialData, 0)
			data = append(data, make([]byte, 16)...)
			data = append(data, 0x00, 0x01, 0x01)
			data = append(data, 0x01)
			return data
		}(), want: ErrInvalidCOSEKey},
		{name: "extensions not a map", data: append(minimalAuthData(testRPID, FlagUserPresent|FlagExtensionData, 0), 0x01), want: ErrInvalidAuthenticatorData},
		{name: "truncated extensions", data: append(minimalAuthData(testRPID, FlagUserPresent|FlagExtensionData, 0), 0xa1, 0x61), want: ErrInvalidAuthenticatorData},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseAuthenticatorData(test.data); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if _, err := ParseAuthenticatorData(append(withAT, 0x00)); !errors.Is(err, ErrInvalidAuthenticatorData) {
		t.Fatalf("trailing AT bytes error = %v", err)
	}
}

func TestFlagsHelpers(t *testing.T) {
	flags := FlagUserPresent | FlagUserVerified | FlagBackupEligible | FlagBackupState | FlagAttestedCredentialData | FlagExtensionData
	if !flags.UserPresent() || !flags.UserVerified() || !flags.BackupEligible() ||
		!flags.BackupState() || !flags.AttestedCredentialData() || !flags.ExtensionsPresent() {
		t.Fatalf("flag helpers disagree with %#x", flags)
	}
	var none Flags
	if none.UserPresent() || none.UserVerified() || none.BackupEligible() ||
		none.BackupState() || none.AttestedCredentialData() || none.ExtensionsPresent() {
		t.Fatalf("zero flags reported bits set")
	}
}
