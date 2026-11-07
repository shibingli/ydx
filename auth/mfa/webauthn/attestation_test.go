package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// buildTestAttestation assembles and parses an attestation object for direct verification. |
// buildTestAttestation 组装并解析用于直接校验的认证声明对象。
func buildTestAttestation(t *testing.T, credentialSigner testSigner, format string, statement attestationBuilder) (*AttestationObject, []byte) {
	t.Helper()
	authData := buildAuthData(t, testRPID, FlagUserPresent|FlagAttestedCredentialData, 3,
		[16]byte{1, 2, 3}, []byte("attested-credential"), credentialSigner.coseKey(t), nil)
	clientDataJSON := mustMarshal(t, &ClientData{
		Type:      ClientDataTypeCreate,
		Challenge: b64([]byte("challenge")),
		Origin:    testOrigin,
	})
	hash := sha256.Sum256(clientDataJSON)
	var pairs []Pair
	if statement != nil {
		pairs = statement(t, authData, hash[:])
	}
	object, err := ParseAttestationObject(makeAttestationObject(t, format, pairs, authData))
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}
	return object, hash[:]
}

// packedX5CStatement signs the attestation data with an attestation certificate key. |
// packedX5CStatement 使用认证证书密钥签名认证声明数据。
func packedX5CStatement(signer *ecSigner, cert *x509.Certificate) attestationBuilder {
	return func(t *testing.T, authData, clientDataHash []byte) []Pair {
		t.Helper()
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(int64(AlgES256))},
			{Key: NewText("sig"), Value: NewBytes(signer.sign(t, signedAttestationData(authData, clientDataHash)))},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	}
}

// newTestCACertificate returns a self-signed CA attestation certificate. |
// newTestCACertificate 返回自签名 CA 认证证书。
func newTestCACertificate(t *testing.T, signer *ecSigner) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Attestation CA"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.key.Public(), signer.key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert
}

func TestParseAttestationObjectInvalid(t *testing.T) {
	signer := newECSigner(t)
	authData := buildAuthData(t, testRPID, FlagUserPresent|FlagAttestedCredentialData, 0, [16]byte{}, []byte("cred"), signer.coseKey(t), nil)
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "malformed CBOR", raw: []byte{0xff}},
		{name: "not a map", raw: mustEncodeCBOR(t, NewUint(1))},
		{name: "missing fmt", raw: mustEncodeCBOR(t, NewMap(
			Pair{Key: NewText("attStmt"), Value: NewMap()},
			Pair{Key: NewText("authData"), Value: NewBytes(authData)},
		))},
		{name: "empty fmt", raw: mustEncodeCBOR(t, NewMap(
			Pair{Key: NewText("fmt"), Value: NewText("")},
			Pair{Key: NewText("attStmt"), Value: NewMap()},
			Pair{Key: NewText("authData"), Value: NewBytes(authData)},
		))},
		{name: "missing attStmt", raw: mustEncodeCBOR(t, NewMap(
			Pair{Key: NewText("fmt"), Value: NewText("none")},
			Pair{Key: NewText("authData"), Value: NewBytes(authData)},
		))},
		{name: "attStmt not a map", raw: mustEncodeCBOR(t, NewMap(
			Pair{Key: NewText("fmt"), Value: NewText("none")},
			Pair{Key: NewText("attStmt"), Value: NewUint(1)},
			Pair{Key: NewText("authData"), Value: NewBytes(authData)},
		))},
		{name: "missing authData", raw: mustEncodeCBOR(t, NewMap(
			Pair{Key: NewText("fmt"), Value: NewText("none")},
			Pair{Key: NewText("attStmt"), Value: NewMap()},
		))},
		{name: "authData not bytes", raw: mustEncodeCBOR(t, NewMap(
			Pair{Key: NewText("fmt"), Value: NewText("none")},
			Pair{Key: NewText("attStmt"), Value: NewMap()},
			Pair{Key: NewText("authData"), Value: NewText("data")},
		))},
		{name: "invalid authData", raw: mustEncodeCBOR(t, NewMap(
			Pair{Key: NewText("fmt"), Value: NewText("none")},
			Pair{Key: NewText("attStmt"), Value: NewMap()},
			Pair{Key: NewText("authData"), Value: NewBytes(make([]byte, 10))},
		))},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseAttestationObject(test.raw); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}
}

func TestAttestationVerifyNone(t *testing.T) {
	signer := newECSigner(t)
	object, hash := buildTestAttestation(t, signer, FormatNone, nil)
	result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeNone || result.Format != FormatNone {
		t.Fatalf("result = %#v", result)
	}
	if len(result.TrustPath) != 0 || result.TrustVerified {
		t.Fatalf("none attestation has a trust path: %#v", result)
	}
	if len(result.CredentialID) == 0 || result.CredentialPublicKey == nil {
		t.Fatalf("result lacks credential material: %#v", result)
	}
	if result.SignCount != 3 || result.AAGUID != [16]byte{1, 2, 3} {
		t.Fatalf("result = %#v", result)
	}
	if _, err := object.Verify(context.Background(), hash[:16], AttestationOptions{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short hash error = %v", err)
	}
	var nilObject *AttestationObject
	if _, err := nilObject.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("nil object error = %v", err)
	}
	nonEmpty, _ := buildTestAttestation(t, signer, FormatNone, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{{Key: NewText("alg"), Value: NewInt(AlgES256)}}
	})
	if _, err := nonEmpty.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("non-empty none attStmt error = %v", err)
	}
}

func TestAttestationVerifyNoneRequiresAttestedCredentialData(t *testing.T) {
	authData := minimalAuthData(testRPID, FlagUserPresent, 0)
	raw := makeAttestationObject(t, FormatNone, nil, authData)
	object, err := ParseAttestationObject(raw)
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}
	hash := sha256.Sum256([]byte("client data"))
	if _, err := object.Verify(context.Background(), hash[:], AttestationOptions{}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("error = %v, want ErrInvalidAttestation", err)
	}
}

func TestAttestationVerifyPackedSelf(t *testing.T) {
	signer := newECSigner(t)
	object, hash := buildTestAttestation(t, signer, FormatPacked, packedSelfStatement(signer))
	result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeSelf {
		t.Fatalf("attestation type = %q, want self", result.Type)
	}
	if len(result.TrustPath) != 0 {
		t.Fatalf("self attestation has a trust path: %v", result.TrustPath)
	}
}

func TestAttestationVerifyPackedSelfWrongKey(t *testing.T) {
	credentialSigner := newECSigner(t)
	attacker := newECSigner(t)
	object, hash := buildTestAttestation(t, credentialSigner, FormatPacked, packedSelfStatement(attacker))
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("error = %v, want ErrSignatureInvalid", err)
	}
}

func TestAttestationVerifyPackedCertificate(t *testing.T) {
	credentialSigner := newECSigner(t)
	attestationSigner := newECSigner(t)
	cert := newTestAttestationCert(t, attestationSigner)
	object, hash := buildTestAttestation(t, credentialSigner, FormatPacked, packedX5CStatement(attestationSigner, cert))

	result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow})
	if err != nil {
		t.Fatalf("Verify without roots: %v", err)
	}
	if result.Type != AttestationTypeBasic {
		t.Fatalf("attestation type = %q, want basic", result.Type)
	}
	if len(result.TrustPath) != 1 || result.TrustVerified {
		t.Fatalf("trust path = %v, verified = %v", len(result.TrustPath), result.TrustVerified)
	}

	trusted, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		Roots:       certificateRoots(cert),
	})
	if err != nil {
		t.Fatalf("Verify with roots: %v", err)
	}
	if !trusted.TrustVerified {
		t.Fatal("certificate chain was not marked trusted")
	}

	other := newTestAttestationCert(t, newECSigner(t))
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		Roots:       certificateRoots(other),
	}); !errors.Is(err, ErrUntrustedAttestation) {
		t.Fatalf("untrusted chain error = %v", err)
	}

	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow.Add(48 * time.Hour),
	}); !errors.Is(err, ErrUntrustedAttestation) {
		t.Fatalf("expired certificate error = %v", err)
	}

	wrongSigner := newECSigner(t)
	badObject, badHash := buildTestAttestation(t, credentialSigner, FormatPacked, packedX5CStatement(wrongSigner, cert))
	if _, err := badObject.Verify(context.Background(), badHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong attestation key error = %v", err)
	}
}

func TestAttestationVerifyPackedAttCA(t *testing.T) {
	credentialSigner := newECSigner(t)
	attestationSigner := newECSigner(t)
	cert := newTestCACertificate(t, attestationSigner)
	object, hash := buildTestAttestation(t, credentialSigner, FormatPacked, packedX5CStatement(attestationSigner, cert))
	result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeAttCA {
		t.Fatalf("attestation type = %q, want attca", result.Type)
	}
}

func TestAttestationVerifyPackedMalformed(t *testing.T) {
	signer := newECSigner(t)
	object, hash := buildTestAttestation(t, signer, FormatPacked, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{{Key: NewText("sig"), Value: NewBytes([]byte{1})}}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing alg error = %v", err)
	}

	object, hash = buildTestAttestation(t, signer, FormatPacked, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes([]byte{1})},
			{Key: NewText("x5c"), Value: NewArray()},
		}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("empty x5c error = %v", err)
	}

	object, hash = buildTestAttestation(t, signer, FormatPacked, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(9999)},
			{Key: NewText("sig"), Value: NewBytes([]byte{1})},
		}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unknown algorithm error = %v", err)
	}

	object, hash = buildTestAttestation(t, signer, FormatPacked, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES384)},
			{Key: NewText("sig"), Value: NewBytes([]byte{1})},
		}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("self algorithm mismatch error = %v", err)
	}
}

func TestAttestationVerifyUnsupportedFormats(t *testing.T) {
	signer := newECSigner(t)
	object, hash := buildTestAttestation(t, signer, FormatECDA, nil)
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrUnsupportedAttestation) {
		t.Fatalf("ecdaa error = %v, want ErrUnsupportedAttestation", err)
	}
	object, hash = buildTestAttestation(t, signer, "unknown-format", nil)
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{}); !errors.Is(err, ErrUnsupportedAttestation) {
		t.Fatalf("unknown format error = %v, want ErrUnsupportedAttestation", err)
	}
}

func TestAttestationVerifyFIDOU2FAndAppleRequireX5C(t *testing.T) {
	signer := newECSigner(t)
	for _, format := range []string{FormatFIDOU2F, FormatAndroidKey, FormatApple} {
		t.Run(format, func(t *testing.T) {
			object, hash := buildTestAttestation(t, signer, format, func(t *testing.T, authData, clientDataHash []byte) []Pair {
				return []Pair{
					{Key: NewText("alg"), Value: NewInt(AlgES256)},
					{Key: NewText("sig"), Value: NewBytes([]byte{1})},
				}
			})
			if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}
}
