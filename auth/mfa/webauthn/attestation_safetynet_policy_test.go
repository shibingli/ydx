package webauthn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// testSafetyNetPayload is a fully configurable SafetyNet JWS payload. | testSafetyNetPayload 是
// 可完整配置的 SafetyNet JWS 载荷。
type testSafetyNetPayload struct {
	Nonce                   string   `json:"nonce"`
	TimestampMs             int64    `json:"timestampMs"`
	APKPackageName          string   `json:"apkPackageName"`
	APKCertificateDigestSHA []string `json:"apkCertificateDigestSha256"`
	CTSProfileMatch         bool     `json:"ctsProfileMatch"`
	BasicIntegrity          bool     `json:"basicIntegrity"`
	EvaluationType          string   `json:"evaluationType"`
}

// signSafetyNetPolicyJWS signs a SafetyNet JWS with RS256. | signSafetyNetPolicyJWS 使用 RS256 签名
// SafetyNet JWS。
func signSafetyNetPolicyJWS(t *testing.T, cert *x509.Certificate, key *rsa.PrivateKey, payload testSafetyNetPayload) []byte {
	t.Helper()
	header := struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}{
		Alg: "RS256",
		X5C: []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
	input := b64(mustMarshal(t, header)) + "." + b64(mustMarshal(t, payload))
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign SafetyNet JWS: %v", err)
	}
	return []byte(input + "." + b64(signature))
}

// buildSafetyNetPolicyObject builds an android-safetynet attestation object carrying the configured
// JWS payload. | buildSafetyNetPolicyObject 构建携带配置 JWS 载荷的 android-safetynet 认证声明对象。
func buildSafetyNetPolicyObject(t *testing.T, credentialSigner testSigner, cert *x509.Certificate, key *rsa.PrivateKey, ver string, adjust func(*testSafetyNetPayload)) (*AttestationObject, []byte) {
	t.Helper()
	return buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		digest := make([]byte, sha256.Size)
		for index := range digest {
			digest[index] = 0xab
		}
		payload := testSafetyNetPayload{
			Nonce:                   base64.StdEncoding.EncodeToString(nonce[:]),
			TimestampMs:             testNow.UnixMilli(),
			APKPackageName:          "com.example.app",
			APKCertificateDigestSHA: []string{base64.StdEncoding.EncodeToString(digest)},
			CTSProfileMatch:         true,
			BasicIntegrity:          true,
			EvaluationType:          "BASIC",
		}
		if adjust != nil {
			adjust(&payload)
		}
		return []Pair{
			{Key: NewText("ver"), Value: NewText(ver)},
			{Key: NewText("response"), Value: NewBytes(signSafetyNetPolicyJWS(t, cert, key, payload))},
		}
	})
}

// TestSafetyNetPolicyBasicIntegrity covers the basicIntegrity requirement. | TestSafetyNetPolicyBasicIntegrity
// 覆盖 basicIntegrity 要求。
func TestSafetyNetPolicyBasicIntegrity(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)
	policy := SafetyNetPolicy{RequireBasicIntegrity: true}

	passing, passingHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", nil)
	if _, err := passing.Verify(context.Background(), passingHash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: policy,
	}); err != nil {
		t.Fatalf("basicIntegrity true: %v", err)
	}

	failing, failingHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", func(payload *testSafetyNetPayload) {
		payload.BasicIntegrity = false
	})
	if _, err := failing.Verify(context.Background(), failingHash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: policy,
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("basicIntegrity false error = %v, want ErrInvalidAttestation", err)
	}

	// The zero policy keeps the baseline behavior and does not require basicIntegrity. |
	// 零值策略保持基线行为，不要求 basicIntegrity。
	if _, err := failing.Verify(context.Background(), failingHash, AttestationOptions{CurrentTime: testNow}); err != nil {
		t.Fatalf("zero policy: %v", err)
	}
}

// TestSafetyNetPolicyCertificateDigests covers the APK certificate digest allowlist. |
// TestSafetyNetPolicyCertificateDigests 覆盖 APK 证书摘要允许列表。
func TestSafetyNetPolicyCertificateDigests(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)
	allowed := make([]byte, sha256.Size)
	for index := range allowed {
		allowed[index] = 0xab
	}
	other := make([]byte, sha256.Size)
	for index := range other {
		other[index] = 0xcd
	}
	hexAllowed := hex.EncodeToString(allowed)
	base64Allowed := base64.StdEncoding.EncodeToString(allowed)

	object, hash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", nil)
	for _, entry := range []string{hexAllowed, base64Allowed} {
		if _, err := object.Verify(context.Background(), hash, AttestationOptions{
			CurrentTime:     testNow,
			SafetyNetPolicy: SafetyNetPolicy{AllowedAPKCertificateDigests: []string{entry}},
		}); err != nil {
			t.Fatalf("allowed digest %q: %v", entry, err)
		}
	}

	mismatch, mismatchHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", func(payload *testSafetyNetPayload) {
		payload.APKCertificateDigestSHA = []string{base64.StdEncoding.EncodeToString(other)}
	})
	if _, err := mismatch.Verify(context.Background(), mismatchHash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: SafetyNetPolicy{AllowedAPKCertificateDigests: []string{hexAllowed}},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("unlisted digest error = %v, want ErrInvalidAttestation", err)
	}

	empty, emptyHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", func(payload *testSafetyNetPayload) {
		payload.APKCertificateDigestSHA = nil
	})
	if _, err := empty.Verify(context.Background(), emptyHash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: SafetyNetPolicy{AllowedAPKCertificateDigests: []string{hexAllowed}},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing digest error = %v, want ErrInvalidAttestation", err)
	}

	malformed, malformedHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", func(payload *testSafetyNetPayload) {
		payload.APKCertificateDigestSHA = []string{"not base64!"}
	})
	if _, err := malformed.Verify(context.Background(), malformedHash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: SafetyNetPolicy{AllowedAPKCertificateDigests: []string{hexAllowed}},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("malformed digest error = %v, want ErrInvalidAttestation", err)
	}
}

// TestSafetyNetPolicyEvaluationAndVersion covers the evaluationType and ver allowlists. |
// TestSafetyNetPolicyEvaluationAndVersion 覆盖 evaluationType 与 ver 允许列表。
func TestSafetyNetPolicyEvaluationAndVersion(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)

	object, hash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", nil)
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		SafetyNetPolicy: SafetyNetPolicy{
			AllowedEvaluationTypes: []string{"BASIC", "HARDWARE_BACKED"},
			AllowedVersions:        []string{"1.0"},
		},
	}); err != nil {
		t.Fatalf("allowed evaluation and version: %v", err)
	}

	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: SafetyNetPolicy{AllowedEvaluationTypes: []string{"HARDWARE_BACKED"}},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("disallowed evaluation error = %v, want ErrInvalidAttestation", err)
	}

	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: SafetyNetPolicy{AllowedVersions: []string{"2.0"}},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("disallowed version error = %v, want ErrInvalidAttestation", err)
	}
}

// TestSafetyNetPolicyTimestampTolerance covers the configurable timestamp window. |
// TestSafetyNetPolicyTimestampTolerance 覆盖可配置时间戳窗口。
func TestSafetyNetPolicyTimestampTolerance(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)

	object, hash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", func(payload *testSafetyNetPayload) {
		payload.TimestampMs = testNow.Add(-5 * time.Minute).UnixMilli()
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: SafetyNetPolicy{TimestampTolerance: 10 * time.Minute},
	}); err != nil {
		t.Fatalf("five minute old timestamp with ten minute tolerance: %v", err)
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: SafetyNetPolicy{TimestampTolerance: 4 * time.Minute},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("five minute old timestamp with four minute tolerance error = %v, want ErrInvalidAttestation", err)
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("default tolerance error = %v, want ErrInvalidAttestation", err)
	}
}

// TestSafetyNetPolicyInvalidConfiguration covers malformed policy rejection. |
// TestSafetyNetPolicyInvalidConfiguration 覆盖非法策略拒绝。
func TestSafetyNetPolicyInvalidConfiguration(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)
	object, hash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", nil)

	policies := []SafetyNetPolicy{
		{TimestampTolerance: -time.Second},
		{AllowedAPKCertificateDigests: []string{"not base64!"}},
		{AllowedAPKCertificateDigests: []string{""}},
		{AllowedEvaluationTypes: []string{" "}},
		{AllowedVersions: []string{""}},
	}
	for _, policy := range policies {
		if _, err := object.Verify(context.Background(), hash, AttestationOptions{
			CurrentTime:     testNow,
			SafetyNetPolicy: policy,
		}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("policy %+v error = %v, want ErrInvalidConfig", policy, err)
		}
	}
}

// TestSafetyNetPolicyKeepsMandatoryChecks verifies that policies do not weaken the mandatory
// signature, nonce and ctsProfileMatch checks. | TestSafetyNetPolicyKeepsMandatoryChecks 验证策略不会
// 削弱强制的签名、nonce 与 ctsProfileMatch 校验。
func TestSafetyNetPolicyKeepsMandatoryChecks(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)
	policy := SafetyNetPolicy{
		RequireBasicIntegrity:        true,
		AllowedEvaluationTypes:       []string{"BASIC"},
		AllowedVersions:              []string{"1.0"},
		TimestampTolerance:           time.Minute,
		AllowedAPKCertificateDigests: []string{hex.EncodeToString(make([]byte, sha256.Size))},
	}

	failedCTS, failedCTSHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", func(payload *testSafetyNetPayload) {
		payload.CTSProfileMatch = false
	})
	if _, err := failedCTS.Verify(context.Background(), failedCTSHash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: policy,
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("ctsProfileMatch false error = %v, want ErrInvalidAttestation", err)
	}

	unsigned, unsignedHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.UnixMilli(), true, nil))},
		}
	})
	if _, err := unsigned.Verify(context.Background(), unsignedHash, AttestationOptions{
		CurrentTime:     testNow,
		SafetyNetPolicy: policy,
	}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("unsigned JWS error = %v, want ErrSignatureInvalid", err)
	}
}
