package ntlm

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestLMHashVector(t *testing.T) {
	hash, err := lmHash("Password")
	if err != nil {
		t.Fatalf("lmHash: %v", err)
	}
	if got := hex.EncodeToString(hash); got != "e52cac67419a9a224a3b108f3fa6cb6d" {
		t.Fatalf("LM hash = %s", got)
	}
}

func TestLMHashTruncatesToFourteenBytes(t *testing.T) {
	long, err := lmHash("PasswordPassword")
	if err != nil {
		t.Fatalf("lmHash(long): %v", err)
	}
	short, err := lmHash("PasswordPasswo")
	if err != nil {
		t.Fatalf("lmHash(short): %v", err)
	}
	if hex.EncodeToString(long) != hex.EncodeToString(short) {
		t.Fatalf("LM hash did not truncate: %x != %x", long, short)
	}
}

func TestNTHashVector(t *testing.T) {
	if got := hex.EncodeToString(ntHash("Password")); got != "a4f49c406510bdcab6824ee7c30fd852" {
		t.Fatalf("NT hash = %s", got)
	}
}

func TestNTLMv1ResponsesVector(t *testing.T) {
	challenge := mustHex(t, "0123456789abcdef")
	ntResponse, err := ntlmV1Response(ntHash("Password"), challenge)
	if err != nil {
		t.Fatalf("ntlmV1Response (NT): %v", err)
	}
	if got := hex.EncodeToString(ntResponse); got != "67c43011f30298a2ad35ece64f16331c44bdbed927841f94" {
		t.Fatalf("NT response = %s", got)
	}
	lmPasswordHash, err := lmHash("Password")
	if err != nil {
		t.Fatalf("lmHash: %v", err)
	}
	lmResponse, err := ntlmV1Response(lmPasswordHash, challenge)
	if err != nil {
		t.Fatalf("ntlmV1Response (LM): %v", err)
	}
	if got := hex.EncodeToString(lmResponse); got != "98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13" {
		t.Fatalf("LM response = %s", got)
	}
}

func TestNTLM2SessionResponseVector(t *testing.T) {
	serverChallenge := mustHex(t, "0123456789abcdef")
	clientChallenge := mustHex(t, "aaaaaaaaaaaaaaaa")
	ntResponse, lmResponse, err := ntlm2SessionResponse(ntHash("Password"), serverChallenge, clientChallenge)
	if err != nil {
		t.Fatalf("ntlm2SessionResponse: %v", err)
	}
	if got := hex.EncodeToString(ntResponse); got != "05e87ab9c858ae0acd5d16d157c35ad2ac4e307723418155" {
		t.Fatalf("NT response = %s", got)
	}
	wantLM := "aaaaaaaaaaaaaaaa" + "00000000000000000000000000000000"
	if got := hex.EncodeToString(lmResponse); got != wantLM {
		t.Fatalf("LM response = %s, want %s", got, wantLM)
	}
}

func TestLegacyResponseValidation(t *testing.T) {
	challenge := mustHex(t, "0123456789abcdef")
	clientChallenge := mustHex(t, "aaaaaaaaaaaaaaaa")
	if _, err := ntlmV1Response(make([]byte, 15), challenge); !errors.Is(err, ErrCredentials) {
		t.Fatalf("short NTLMv1 hash error = %v", err)
	}
	if _, err := ntlmV1Response(make([]byte, 16), challenge[:7]); !errors.Is(err, ErrChallenge) {
		t.Fatalf("short server challenge error = %v", err)
	}
	if _, _, err := ntlm2SessionResponse(make([]byte, 15), challenge, clientChallenge); !errors.Is(err, ErrCredentials) {
		t.Fatalf("short NTLM2 hash error = %v", err)
	}
	if _, _, err := ntlm2SessionResponse(make([]byte, 16), challenge[:7], clientChallenge); !errors.Is(err, ErrChallenge) {
		t.Fatalf("short NTLM2 server challenge error = %v", err)
	}
	if _, _, err := ntlm2SessionResponse(make([]byte, 16), challenge, clientChallenge[:7]); !errors.Is(err, ErrCredentials) {
		t.Fatalf("short NTLM2 client challenge error = %v", err)
	}
	if _, err := desEncrypt(make([]byte, 7), challenge); !errors.Is(err, ErrCredentials) {
		t.Fatalf("short DES key error = %v", err)
	}
	if _, err := desEncrypt(make([]byte, 8), make([]byte, 7)); !errors.Is(err, ErrCredentials) {
		t.Fatalf("short DES block error = %v", err)
	}
}
