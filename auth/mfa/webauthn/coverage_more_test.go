package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// TestAAGUIDExtension validates the optional FIDO AAGUID certificate extension. |
// TestAAGUIDExtension 校验可选的 FIDO AAGUID 证书扩展。
func TestAAGUIDExtension(t *testing.T) {
	var aaguid [16]byte
	aaguid[0] = 0x11
	encode := func(value []byte) []byte {
		der, err := asn1.Marshal(value)
		if err != nil {
			t.Fatalf("asn1.Marshal: %v", err)
		}
		return der
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{}, aaguid); err != nil {
		t.Fatalf("no extensions: %v", err)
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{Extensions: []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{1}},
	}}, aaguid); err != nil {
		t.Fatalf("unrelated extension: %v", err)
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{Extensions: []pkix.Extension{
		{Id: fidoAAGUIDOID, Critical: true, Value: encode(aaguid[:])},
	}}, aaguid); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("critical extension err = %v", err)
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{Extensions: []pkix.Extension{
		{Id: fidoAAGUIDOID, Value: []byte{0x02, 0x01, 0x01}},
	}}, aaguid); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("invalid DER err = %v", err)
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{Extensions: []pkix.Extension{
		{Id: fidoAAGUIDOID, Value: append(encode(aaguid[:]), 0x05, 0x00)},
	}}, aaguid); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("trailing DER err = %v", err)
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{Extensions: []pkix.Extension{
		{Id: fidoAAGUIDOID, Value: encode([]byte{1, 2})},
	}}, aaguid); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("short AAGUID err = %v", err)
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{Extensions: []pkix.Extension{
		{Id: fidoAAGUIDOID, Value: encode(make([]byte, 16))},
	}}, aaguid); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("mismatched AAGUID err = %v", err)
	}
	if err := verifyAAGUIDExtension(&x509.Certificate{Extensions: []pkix.Extension{
		{Id: fidoAAGUIDOID, Value: encode(aaguid[:])},
	}}, aaguid); err != nil {
		t.Fatalf("matching AAGUID: %v", err)
	}
}

// TestPublicKeyHelpers covers key comparison and credential key lookup. |
// TestPublicKeyHelpers 覆盖公钥比较与凭据公钥查找。
func TestPublicKeyHelpers(t *testing.T) {
	if samePublicKey(nil, nil) || samePublicKey(ed25519.PublicKey(make([]byte, 32)), nil) {
		t.Fatal("nil public key matched")
	}
	keyA := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	keyB := ed25519.PublicKey(append(make([]byte, ed25519.PublicKeySize-1), 1))
	if samePublicKey(keyA, keyB) || !samePublicKey(keyA, keyA) {
		t.Fatal("public key comparison mismatch")
	}
	if samePublicKey(keyA, 1) {
		t.Fatal("integer public key matched")
	}
	if samePublicKey(1, keyB) {
		t.Fatal("invalid first public key matched")
	}
	if _, err := attestationCredentialPublicKey(nil); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("nil authData err = %v", err)
	}
	if _, err := attestationCredentialPublicKey(&AuthenticatorData{}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("nil credential key err = %v", err)
	}
	key := &COSEKey{Kty: KeyTypeOKP, Alg: AlgEdDSA}
	if got, err := attestationCredentialPublicKey(&AuthenticatorData{CredentialPublicKey: key}); err != nil || got != key {
		t.Fatalf("credential key = %+v, %v", got, err)
	}
	if value, ok := asn1String("text"); !ok || value != "text" {
		t.Fatal("string conversion failed")
	}
	if value, ok := asn1String([]byte("bytes")); !ok || value != "bytes" {
		t.Fatalf("byte conversion = %q, %v", value, ok)
	}
	if _, ok := asn1String(42); ok {
		t.Fatal("integer conversion succeeded")
	}
	var nilKey *COSEKey
	if nilKey.Algorithm() != 0 {
		t.Fatal("nil key algorithm")
	}
}

// TestTPMSkipHelpers covers TPM scheme, symmetric and KDF skipping. |
// TestTPMSkipHelpers 覆盖 TPM 方案、对称与 KDF 跳过。
func TestTPMSkipHelpers(t *testing.T) {
	if err := skipTPMSymmetric(&tpmReader{data: []byte{0x00, 0x10}}); err != nil {
		t.Fatalf("NULL symmetric: %v", err)
	}
	if err := skipTPMSymmetric(&tpmReader{data: []byte{0x00, 0x06, 0x00, 0x80, 0x00, 0x43}}); err != nil {
		t.Fatalf("symmetric: %v", err)
	}
	if err := skipTPMSymmetric(&tpmReader{data: []byte{0x00, 0x06, 0x00, 0x80}}); err == nil {
		t.Fatal("truncated symmetric accepted")
	}
	if err := skipTPMSymmetric(&tpmReader{}); err == nil {
		t.Fatal("empty symmetric accepted")
	}
	if err := skipTPMScheme(&tpmReader{data: []byte{0x00, 0x10}}); err != nil {
		t.Fatalf("NULL scheme: %v", err)
	}
	if err := skipTPMScheme(&tpmReader{data: []byte{0x00, 0x18, 0x00, 0x0b}}, tpmAlgECDSA); err != nil {
		t.Fatalf("known scheme: %v", err)
	}
	if err := skipTPMScheme(&tpmReader{data: []byte{0x00, 0x18}}, tpmAlgECDSA); err == nil {
		t.Fatal("truncated scheme accepted")
	}
	if err := skipTPMScheme(&tpmReader{data: []byte{0x00, 0x19, 0x00, 0x0b}}, tpmAlgECDSA); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unknown scheme err = %v", err)
	}
	if err := skipTPMScheme(&tpmReader{}); err == nil {
		t.Fatal("empty scheme accepted")
	}
	if err := skipTPMKDF(&tpmReader{data: []byte{0x00, 0x10}}); err != nil {
		t.Fatalf("NULL KDF: %v", err)
	}
	if err := skipTPMKDF(&tpmReader{data: []byte{0x00, 0x20, 0x00, 0x0b}}); err != nil {
		t.Fatalf("known KDF: %v", err)
	}
	if err := skipTPMKDF(&tpmReader{data: []byte{0x00, 0x22}}); err == nil {
		t.Fatal("truncated KDF accepted")
	}
	if err := skipTPMKDF(&tpmReader{data: []byte{0x00, 0x23}}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unknown KDF err = %v", err)
	}
}

// TestVerifySignatureBranches covers algorithm, key type and encoding branches. |
// TestVerifySignatureBranches 覆盖算法、密钥类型与编码分支。
func TestVerifySignatureBranches(t *testing.T) {
	message := []byte("message")
	if err := VerifySignature(AlgES256, nil, message, nil); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("empty signature err = %v", err)
	}
	if err := VerifySignature(12345, nil, message, []byte{1}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported algorithm err = %v", err)
	}
	if err := VerifySignature(AlgES256, 1, message, []byte{1}); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("non-ECDSA key err = %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384: %v", err)
	}
	if err := VerifySignature(AlgES256, &p384.PublicKey, message, []byte{1}); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("curve mismatch err = %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256: %v", err)
	}
	digest := sha256.Sum256(message)
	der, err := ecdsa.SignASN1(rand.Reader, p256, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	if err := VerifySignature(AlgES256, &p256.PublicKey, message, der); err != nil {
		t.Fatalf("DER signature: %v", err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, p256, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	fixed := make([]byte, 64)
	r.FillBytes(fixed[:32])
	s.FillBytes(fixed[32:])
	if err := VerifySignature(AlgES256, &p256.PublicKey, message, fixed); err != nil {
		t.Fatalf("fixed-width signature: %v", err)
	}
	if err := VerifySignature(AlgES256, &p256.PublicKey, []byte("other"), der); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong message err = %v", err)
	}
	badFixed := append([]byte(nil), fixed...)
	badFixed[0] ^= 0xff
	if err := VerifySignature(AlgES256, &p256.PublicKey, message, badFixed); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("bad fixed-width err = %v", err)
	}
	if err := VerifySignature(AlgEdDSA, ed25519.PublicKey(make([]byte, 31)), message, []byte{1}); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("short Ed25519 key err = %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519: %v", err)
	}
	signature := ed25519.Sign(edPriv, message)
	if err := VerifySignature(AlgEdDSA, edPub, message, signature); err != nil {
		t.Fatalf("EdDSA signature: %v", err)
	}
	if err := VerifySignature(AlgEdDSA, edPub, []byte("other"), signature); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("bad EdDSA err = %v", err)
	}
	if err := VerifySignature(AlgEdDSA, 1, message, signature); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("non-Ed25519 key err = %v", err)
	}
	var nilKey *COSEKey
	if err := nilKey.Verify(AlgES256, message, der); !errors.Is(err, ErrInvalidCOSEKey) {
		t.Fatalf("nil key verify err = %v", err)
	}
	if err := p256Key(t).Verify(AlgES384, message, der); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("algorithm mismatch err = %v", err)
	}
}

// p256Key returns a COSE key for the given P-256 key. | p256Key 返回给定 P-256 密钥的 COSE 密钥。
func p256Key(t *testing.T) *COSEKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &COSEKey{
		Kty: KeyTypeEC2,
		Alg: AlgES256,
		Crv: CurveP256,
		X:   key.X.FillBytes(make([]byte, 32)),
		Y:   key.Y.FillBytes(make([]byte, 32)),
	}
}

// TestChallengeStoreCapacityCleanup exercises the lazy cleanup at the capacity limit. |
// TestChallengeStoreCapacityCleanup 覆盖容量上限的惰性清理。
func TestChallengeStoreCapacityCleanup(t *testing.T) {
	fixed := time.Now()
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return fixed })
	for i := 0; i < 1024; i++ {
		challenge := []byte{byte(i), byte(i >> 8), 1}
		if err := store.Put(context.Background(), &Ceremony{Challenge: challenge, ExpiresAt: fixed.Add(-time.Minute)}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if store.Len() != 1024 {
		t.Fatalf("len = %d", store.Len())
	}
	fresh := []byte{9, 9, 9}
	if err := store.Put(context.Background(), &Ceremony{Challenge: fresh, ExpiresAt: fixed.Add(time.Minute)}); err != nil {
		t.Fatalf("put fresh: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("expired entries retained: %d", store.Len())
	}
	if _, err := store.Consume(context.Background(), base64.RawURLEncoding.EncodeToString(fresh)); err != nil {
		t.Fatalf("consume fresh: %v", err)
	}
}
