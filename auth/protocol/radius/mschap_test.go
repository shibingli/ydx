package radius

import (
	"bytes"
	"errors"
	"math/bits"
	"testing"
)

func TestMSCHAPv2RFC2759Vector(t *testing.T) {
	authenticatorChallenge := decodeHex(t, "5b5d7c7d7b3f2f3e3c2c602132262628")
	peerChallenge := decodeHex(t, "21402324255e262a28295f2b3a337c7e")
	expectedChallenge := decodeHex(t, "d02e4386bce91226")
	expectedPasswordHash := decodeHex(t, "44ebba8d5312b8d611474411f56989ae")
	expectedPasswordHashHash := decodeHex(t, "41c00c584bd2d91c4017a2a12fa59f3f")
	expectedNTResponse := decodeHex(t, "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df")

	challenge := msCHAPv2ChallengeHash("User", authenticatorChallenge, peerChallenge)
	if !bytes.Equal(challenge, expectedChallenge) {
		t.Fatalf("ChallengeHash = %x, want %x", challenge, expectedChallenge)
	}
	passwordHash := ntPasswordHash("clientPass")
	if !bytes.Equal(passwordHash[:], expectedPasswordHash) {
		t.Fatalf("PasswordHash = %x, want %x", passwordHash, expectedPasswordHash)
	}
	passwordHashHash := md4Sum(passwordHash[:])
	if !bytes.Equal(passwordHashHash[:], expectedPasswordHashHash) {
		t.Fatalf("PasswordHashHash = %x, want %x", passwordHashHash, expectedPasswordHashHash)
	}

	response, err := MSCHAPv2Response("User", "clientPass", authenticatorChallenge, peerChallenge, 0x11)
	if err != nil {
		t.Fatalf("MSCHAPv2Response: %v", err)
	}
	if len(response) != msCHAPv2ResponseLength {
		t.Fatalf("response length %d != %d", len(response), msCHAPv2ResponseLength)
	}
	if response[0] != 0x11 {
		t.Fatalf("Ident = %d, want 17", response[0])
	}
	if response[1] != 0 {
		t.Fatalf("Flags = %d, want 0", response[1])
	}
	if !bytes.Equal(response[2:18], peerChallenge) {
		t.Fatalf("Peer-Challenge = %x, want %x", response[2:18], peerChallenge)
	}
	if !bytes.Equal(response[18:26], make([]byte, 8)) {
		t.Fatalf("Reserved = %x, want zeros", response[18:26])
	}
	if !bytes.Equal(response[26:50], expectedNTResponse) {
		t.Fatalf("NT-Response = %x, want %x", response[26:50], expectedNTResponse)
	}

	valid, err := VerifyMSCHAPv2Response("User", "clientPass", authenticatorChallenge, response)
	if err != nil || !valid {
		t.Fatalf("VerifyMSCHAPv2Response = %v, %v", valid, err)
	}
	valid, err = VerifyMSCHAPv2Response("User", "wrongPass", authenticatorChallenge, response)
	if err != nil {
		t.Fatalf("VerifyMSCHAPv2Response wrong password: %v", err)
	}
	if valid {
		t.Fatal("VerifyMSCHAPv2Response accepted a wrong password")
	}
	valid, err = VerifyMSCHAPv2Response("Other", "clientPass", authenticatorChallenge, response)
	if err != nil {
		t.Fatalf("VerifyMSCHAPv2Response wrong user: %v", err)
	}
	if valid {
		t.Fatal("VerifyMSCHAPv2Response accepted a wrong user name")
	}
}

func TestMSCHAPv2Validation(t *testing.T) {
	challenge := make([]byte, 16)
	if _, err := MSCHAPv2Response("User", "pass", make([]byte, 15), challenge, 1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short authenticator challenge error = %v", err)
	}
	if _, err := MSCHAPv2Response("User", "pass", challenge, make([]byte, 15), 1); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short peer challenge error = %v", err)
	}
	if _, err := VerifyMSCHAPv2Response("User", "pass", challenge, make([]byte, 49)); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("short response error = %v", err)
	}
	if _, err := VerifyMSCHAPv2Response("User", "pass", make([]byte, 16), make([]byte, 50)); err != nil {
		t.Fatalf("well-shaped response error = %v", err)
	}
}

func TestExpandDESKeyParity(t *testing.T) {
	input := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd}
	var output [8]byte
	expandDESKey(input, output[:])
	for i, value := range output {
		if bits.OnesCount8(value)%2 != 1 {
			t.Fatalf("key octet %d = %02x lacks odd parity", i, value)
		}
	}
}
