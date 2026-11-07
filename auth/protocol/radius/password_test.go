package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"testing"
)

// decodeHex decodes a hexadecimal test vector. | decodeHex 解码十六进制测试向量。
func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

func TestUserPasswordRFC2865Vector(t *testing.T) {
	secret := []byte("xyzzy5461")
	requestAuthenticator := decodeHex(t, "0f403f9473978057bd83d5cb98f4227a")
	expected := decodeHex(t, "0dbe708d93d413ce3196e43f782a0aee")

	encrypted, err := EncryptUserPassword(secret, requestAuthenticator, []byte("arctangent"))
	if err != nil {
		t.Fatalf("EncryptUserPassword: %v", err)
	}
	if !bytes.Equal(encrypted, expected) {
		t.Fatalf("ciphertext = %x, want %x", encrypted, expected)
	}
	plaintext, err := DecryptUserPassword(secret, requestAuthenticator, expected)
	if err != nil {
		t.Fatalf("DecryptUserPassword: %v", err)
	}
	if string(plaintext) != "arctangent" {
		t.Fatalf("plaintext = %q, want %q", plaintext, "arctangent")
	}
	if !VerifyUserPassword(secret, requestAuthenticator, expected, []byte("arctangent")) {
		t.Fatal("VerifyUserPassword rejected the correct password")
	}
	if VerifyUserPassword(secret, requestAuthenticator, expected, []byte("wrong")) {
		t.Fatal("VerifyUserPassword accepted a wrong password")
	}
}

func TestUserPasswordRoundTrip(t *testing.T) {
	secret := []byte("shared-test-secret")
	requestAuthenticator := bytes.Repeat([]byte{0x3c}, 16)
	for _, password := range []string{"", "a", "sixteen-bytes-abc", "a password that is longer than sixteen octets"} {
		encrypted, err := EncryptUserPassword(secret, requestAuthenticator, []byte(password))
		if err != nil {
			t.Fatalf("EncryptUserPassword(%q): %v", password, err)
		}
		if len(encrypted) < 16 || len(encrypted) > 128 || len(encrypted)%16 != 0 {
			t.Fatalf("ciphertext length %d for %q is invalid", len(encrypted), password)
		}
		plaintext, err := DecryptUserPassword(secret, requestAuthenticator, encrypted)
		if err != nil {
			t.Fatalf("DecryptUserPassword(%q): %v", password, err)
		}
		if string(plaintext) != password {
			t.Fatalf("round trip = %q, want %q", plaintext, password)
		}
	}
}

func TestUserPasswordValidation(t *testing.T) {
	secret := []byte("secret")
	authenticator := make([]byte, 16)
	if _, err := EncryptUserPassword(nil, authenticator, []byte("x")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty secret error = %v", err)
	}
	if _, err := EncryptUserPassword(secret, make([]byte, 15), []byte("x")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short authenticator error = %v", err)
	}
	if _, err := EncryptUserPassword(secret, authenticator, make([]byte, 129)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long password error = %v", err)
	}
	if _, err := DecryptUserPassword(secret, authenticator, make([]byte, 15)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short ciphertext error = %v", err)
	}
	if _, err := DecryptUserPassword(secret, authenticator, make([]byte, 144)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long ciphertext error = %v", err)
	}
}

func TestCHAPResponse(t *testing.T) {
	ident := uint8(0x2a)
	password := []byte("chap-secret")
	challenge := []byte("a-chap-challenge")
	input := append(append([]byte{ident}, password...), challenge...)
	expected := md5.Sum(input)

	response := CHAPResponse(ident, password, challenge)
	if response != expected {
		t.Fatalf("CHAPResponse = %x, want %x", response, expected)
	}
	if !VerifyCHAPResponse(ident, password, challenge, response[:]) {
		t.Fatal("VerifyCHAPResponse rejected the correct response")
	}
	if VerifyCHAPResponse(ident, []byte("wrong"), challenge, response[:]) {
		t.Fatal("VerifyCHAPResponse accepted a wrong password")
	}
	if VerifyCHAPResponse(ident+1, password, challenge, response[:]) {
		t.Fatal("VerifyCHAPResponse accepted a wrong identifier")
	}
	if VerifyCHAPResponse(ident, password, challenge, response[:15]) {
		t.Fatal("VerifyCHAPResponse accepted a short response")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Fatal("equal slices reported different")
	}
	if constantTimeEqual([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Fatal("different slices reported equal")
	}
	if constantTimeEqual([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Fatal("different lengths reported equal")
	}
	if constantTimeEqual(nil, nil) != true {
		t.Fatal("two empty slices reported different")
	}
}
