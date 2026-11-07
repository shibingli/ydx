package federation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/shibingli/ydx/base64"
)

func generateRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return key, string(encoded)
}

func verifyRSASHA256(t *testing.T, content, signature string, public *rsa.PublicKey) {
	t.Helper()
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signatureBytes); err != nil {
		t.Fatalf("verify RSA2 signature: %v", err)
	}
}

func TestSignAlipayRSA2(t *testing.T) {
	key, privatePEM := generateRSAKey(t)
	params := map[string]string{
		"b":     "second value",
		"a":     "first",
		"empty": "",
		"sign":  "ignored",
	}
	signature, err := SignAlipayRSA2(params, privatePEM)
	if err != nil {
		t.Fatalf("SignAlipayRSA2: %v", err)
	}
	if want := "a=first&b=second value"; alipayCanonicalString(params) != want {
		t.Fatalf("canonical string = %q, want %q", alipayCanonicalString(params), want)
	}
	verifyRSASHA256(t, "a=first&b=second value", signature, &key.PublicKey)
}

func TestParseAlipayPrivateKeyFormats(t *testing.T) {
	key, pkcs8PEM := generateRSAKey(t)
	formats := map[string]string{
		"pkcs8-pem": pkcs8PEM,
		"pkcs1-pem": string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})),
		"pkcs8-der-base64": base64.StdEncoding.EncodeToString(mustPKCS8DER(t, key)),
	}
	params := map[string]string{"app_id": "2021000000000000", "method": "alipay.system.oauth.token"}
	for name, privateKey := range formats {
		t.Run(name, func(t *testing.T) {
			signature, err := SignAlipayRSA2(params, privateKey)
			if err != nil {
				t.Fatalf("SignAlipayRSA2: %v", err)
			}
			verifyRSASHA256(t, alipayCanonicalString(params), signature, &key.PublicKey)
		})
	}
}

func TestSignAlipayRSA2RejectsInvalidKey(t *testing.T) {
	if _, err := SignAlipayRSA2(map[string]string{"a": "1"}, "not-a-key"); !errors.Is(err, ErrSigning) {
		t.Fatalf("invalid key error = %v", err)
	}
	if _, err := SignAlipayRSA2(map[string]string{"a": "1"}, ""); !errors.Is(err, ErrSigning) {
		t.Fatalf("empty key error = %v", err)
	}
}

func mustPKCS8DER(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return der
}
