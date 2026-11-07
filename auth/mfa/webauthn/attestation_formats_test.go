package webauthn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// fidoU2FStatement signs the fido-u2f verification message. | fidoU2FStatement 签名 fido-u2f 校验消息。
func fidoU2FStatement(credentialSigner, attestationSigner *ecSigner, cert *x509.Certificate) attestationBuilder {
	return func(t *testing.T, authData, clientDataHash []byte) []Pair {
		t.Helper()
		key := credentialSigner.coseKey(t)
		message := make([]byte, 0, 1+32+len(clientDataHash)+len("attested-credential")+65)
		message = append(message, 0x00)
		message = append(message, authData[:32]...)
		message = append(message, clientDataHash...)
		message = append(message, []byte("attested-credential")...)
		message = append(message, 0x04)
		message = append(message, key.X...)
		message = append(message, key.Y...)
		return []Pair{
			{Key: NewText("sig"), Value: NewBytes(attestationSigner.sign(t, message))},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	}
}

func TestAttestationVerifyFIDOU2F(t *testing.T) {
	credentialSigner := newECSigner(t)
	attestationSigner := newECSigner(t)
	cert := newTestAttestationCert(t, attestationSigner)
	object, hash := buildTestAttestation(t, credentialSigner, FormatFIDOU2F, fidoU2FStatement(credentialSigner, attestationSigner, cert))
	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		Roots:       certificateRoots(cert),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeBasic || result.Format != FormatFIDOU2F {
		t.Fatalf("result = %#v", result)
	}
	if len(result.TrustPath) != 1 || !result.TrustVerified {
		t.Fatalf("trust path = %v verified = %v", len(result.TrustPath), result.TrustVerified)
	}

	wrongSigner := newECSigner(t)
	badObject, badHash := buildTestAttestation(t, credentialSigner, FormatFIDOU2F, fidoU2FStatement(credentialSigner, wrongSigner, cert))
	if _, err := badObject.Verify(context.Background(), badHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong U2F signing key error = %v, want ErrSignatureInvalid", err)
	}

	edCredential := newEdSigner(t)
	edObject, edHash := buildTestAttestation(t, edCredential, FormatFIDOU2F, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{
			{Key: NewText("sig"), Value: NewBytes([]byte{1})},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	})
	if _, err := edObject.Verify(context.Background(), edHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("non-P-256 credential error = %v, want ErrUnsupportedKey", err)
	}
}

// newAppleAttestationCert returns a certificate carrying the Apple nonce extension. |
// newAppleAttestationCert 返回携带 Apple nonce 扩展的证书。
func newAppleAttestationCert(t *testing.T, signer *ecSigner, nonce []byte) *x509.Certificate {
	t.Helper()
	value, err := asn1.Marshal(struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}{Nonce: nonce})
	if err != nil {
		t.Fatalf("marshal apple nonce: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Apple Attestation"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: appleNonceOID, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.key.Public(), signer.key)
	if err != nil {
		t.Fatalf("create apple certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse apple certificate: %v", err)
	}
	return cert
}

func TestAttestationVerifyApple(t *testing.T) {
	credentialSigner := newECSigner(t)
	var leaf *x509.Certificate
	object, hash := buildTestAttestation(t, credentialSigner, FormatApple, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		leaf = newAppleAttestationCert(t, credentialSigner, nonce[:])
		return []Pair{{Key: NewText("x5c"), Value: NewArray(NewBytes(leaf.Raw))}}
	})
	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		Roots:       certificateRoots(leaf),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeBasic || !result.TrustVerified {
		t.Fatalf("result = %#v", result)
	}

	wrongObject, wrongHash := buildTestAttestation(t, credentialSigner, FormatApple, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		cert := newAppleAttestationCert(t, credentialSigner, make([]byte, sha256.Size))
		return []Pair{{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))}}
	})
	if _, err := wrongObject.Verify(context.Background(), wrongHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("wrong apple nonce error = %v, want ErrInvalidAttestation", err)
	}

	otherSigner := newECSigner(t)
	mismatch, mismatchHash := buildTestAttestation(t, credentialSigner, FormatApple, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		cert := newAppleAttestationCert(t, otherSigner, nonce[:])
		return []Pair{{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))}}
	})
	if _, err := mismatch.Verify(context.Background(), mismatchHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("apple key mismatch error = %v, want ErrInvalidAttestation", err)
	}
}

// androidAuthorizationListDER builds the AuthorizationList fields the verifier inspects. |
// androidAuthorizationListDER 构建校验器检查的 AuthorizationList 字段。
func androidAuthorizationListDER(t *testing.T, purpose, origin int) []byte {
	t.Helper()
	purposeDER, err := asn1.Marshal(purpose)
	if err != nil {
		t.Fatalf("marshal purpose: %v", err)
	}
	set := append([]byte{0x31, byte(len(purposeDER))}, purposeDER...)
	field := append([]byte{0xa1, byte(len(set))}, set...)
	originDER, err := asn1.Marshal(asn1.RawValue{Class: derClassContext, Tag: 702, Bytes: []byte{byte(origin)}})
	if err != nil {
		t.Fatalf("marshal origin: %v", err)
	}
	return append(field, originDER...)
}

// newAndroidKeyAttestationCert returns an android-key certificate bound to challenge. |
// newAndroidKeyAttestationCert 返回绑定 challenge 的 android-key 证书。
func newAndroidKeyAttestationCert(t *testing.T, signer *ecSigner, challenge []byte) *x509.Certificate {
	t.Helper()
	description := struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		TEEEnforced              asn1.RawValue
	}{
		AttestationVersion:       3,
		AttestationSecurityLevel: 1,
		KeymasterVersion:         4,
		KeymasterSecurityLevel:   1,
		AttestationChallenge:     challenge,
		SoftwareEnforced: asn1.RawValue{
			Class:      derClassContext,
			Tag:        1,
			IsCompound: true,
			Bytes:      androidAuthorizationListDER(t, kmPurposeSign, kmOriginGenerated),
		},
		TEEEnforced: asn1.RawValue{Class: derClassContext, Tag: 1, IsCompound: true},
	}
	value, err := asn1.Marshal(description)
	if err != nil {
		t.Fatalf("marshal android key description: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(12),
		Subject:               pkix.Name{CommonName: "Android Key Attestation"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: androidKeyAttestationOID, Value: value}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.key.Public(), signer.key)
	if err != nil {
		t.Fatalf("create android-key certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse android-key certificate: %v", err)
	}
	return cert
}

func TestAttestationVerifyAndroidKey(t *testing.T) {
	credentialSigner := newECSigner(t)
	var leaf *x509.Certificate
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		leaf = newAndroidKeyAttestationCert(t, credentialSigner, clientDataHash)
		signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(leaf.Raw))},
		}
	})
	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		Roots:       certificateRoots(leaf),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeBasic || !result.TrustVerified {
		t.Fatalf("result = %#v", result)
	}

	wrongChallenge, wrongHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		cert := newAndroidKeyAttestationCert(t, credentialSigner, make([]byte, sha256.Size))
		signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	})
	if _, err := wrongChallenge.Verify(context.Background(), wrongHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("challenge mismatch error = %v, want ErrInvalidAttestation", err)
	}

	otherSigner := newECSigner(t)
	mismatch, mismatchHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		cert := newAndroidKeyAttestationCert(t, otherSigner, clientDataHash)
		signature := otherSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	})
	if _, err := mismatch.Verify(context.Background(), mismatchHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("android-key key mismatch error = %v, want ErrInvalidAttestation", err)
	}
}

// safetyNetJWS builds a compact JWS with the given certificate and payload. | safetyNetJWS 用给定证书与载荷构建紧凑 JWS。
func buildSafetyNetJWS(t *testing.T, cert *x509.Certificate, nonce []byte, timestamp int64, cts bool, signer *rsa.PrivateKey) []byte {
	t.Helper()
	header := struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}{
		Alg: "RS256",
		X5C: []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
	payload := struct {
		Nonce          string `json:"nonce"`
		TimestampMs    int64  `json:"timestampMs"`
		APKPackageName string `json:"apkPackageName"`
		CTSProfile     bool   `json:"ctsProfileMatch"`
	}{
		Nonce:          base64.StdEncoding.EncodeToString(nonce),
		TimestampMs:    timestamp,
		APKPackageName: "com.example.app",
		CTSProfile:     cts,
	}
	input := b64(mustMarshal(t, header)) + "." + b64(mustMarshal(t, payload))
	if signer == nil {
		return []byte(input + "." + b64([]byte("unsigned")))
	}
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign SafetyNet JWS: %v", err)
	}
	return []byte(input + "." + b64(signature))
}

func newSafetyNetCertificate(t *testing.T, signer *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(13),
		Subject:               pkix.Name{CommonName: "SafetyNet Attestation"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &signer.PublicKey, signer)
	if err != nil {
		t.Fatalf("create SafetyNet certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse SafetyNet certificate: %v", err)
	}
	return cert
}

func TestAttestationVerifyAndroidSafetyNet(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.UnixMilli(), true, key))},
		}
	})
	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		Roots:       certificateRoots(cert),
		ClientData:  &ClientData{AndroidPackageName: "com.example.app"},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeBasic || !result.TrustVerified {
		t.Fatalf("result = %#v", result)
	}

	unsigned, unsignedHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.UnixMilli(), true, nil))},
		}
	})
	if _, err := unsigned.Verify(context.Background(), unsignedHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("unsigned JWS error = %v, want ErrSignatureInvalid", err)
	}
}

func TestAttestationVerifyAndroidSafetyNetPolicy(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)

	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.UnixMilli(), false, key))},
		}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("failed CTS profile error = %v, want ErrInvalidAttestation", err)
	}

	stale, staleHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.Add(-time.Hour).UnixMilli(), true, key))},
		}
	})
	if _, err := stale.Verify(context.Background(), staleHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("stale timestamp error = %v, want ErrInvalidAttestation", err)
	}

	packageMismatch, packageHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.UnixMilli(), true, key))},
		}
	})
	if _, err := packageMismatch.Verify(context.Background(), packageHash, AttestationOptions{
		CurrentTime: testNow,
		ClientData:  &ClientData{AndroidPackageName: "com.other.app"},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("package mismatch error = %v, want ErrInvalidAttestation", err)
	}
}

func TestAttestationVerifyAndroidSafetyNetCustomVerifier(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)
	var expectedNonce []byte
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		expectedNonce = append([]byte(nil), nonce[:]...)
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.UnixMilli(), true, nil))},
		}
	})
	called := false
	verifier := SafetyNetVerifierFunc(func(ctx context.Context, response, nonce []byte) error {
		called = true
		if len(response) == 0 {
			return errors.New("empty response")
		}
		if !constantTimeEqual(nonce, expectedNonce) {
			return errors.New("nonce mismatch")
		}
		return nil
	})
	result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, SafetyNetVerifier: verifier})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !called || result.Type != AttestationTypeBasic {
		t.Fatalf("verifier called = %v, result = %#v", called, result)
	}

	rejecting := SafetyNetVerifierFunc(func(context.Context, []byte, []byte) error {
		return errors.New("rejected")
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, SafetyNetVerifier: rejecting}); !errors.Is(err, ErrUntrustedAttestation) {
		t.Fatalf("rejecting verifier error = %v, want ErrUntrustedAttestation", err)
	}
}

func TestSafetyNetMalformedJWS(t *testing.T) {
	credentialSigner := newECSigner(t)
	cases := []struct {
		name     string
		response string
	}{
		{name: "not compact", response: "not-a-jws"},
		{name: "bad header", response: "!!!.e30.!!!"},
		{name: "header without alg", response: b64(mustMarshal(t, map[string]any{"x5c": []string{}})) + "." + b64([]byte(`{}`)) + ".eA"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
				return []Pair{
					{Key: NewText("ver"), Value: NewText("1.0")},
					{Key: NewText("response"), Value: NewBytes([]byte(test.response))},
				}
			})
			if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}
}

// TestAttestationStatementText exercises the text accessor through SafetyNet and TPM. |
// TestAttestationStatementText 通过 SafetyNet 与 TPM 覆盖文本访问器。
func TestAttestationStatementText(t *testing.T) {
	credentialSigner := newECSigner(t)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{{Key: NewText("ver"), Value: NewBytes([]byte("1.0"))}}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("non-text ver error = %v", err)
	}
	object, hash = buildTestAttestation(t, credentialSigner, FormatTPM, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{{Key: NewText("ver"), Value: NewText("1.2")}}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrUnsupportedAttestation) {
		t.Fatalf("TPM version error = %v", err)
	}
}
