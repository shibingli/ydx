package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

// androidPolicyBaseFields returns the baseline purpose and origin fields. | androidPolicyBaseFields
// 返回基线 purpose 与 origin 字段。
func androidPolicyBaseFields(t *testing.T) []byte {
	t.Helper()
	return testConcat(
		explicitAndroidField(t, androidTagPurpose, testDERSet(explicitAndroidInteger(t, kmPurposeSign))),
		explicitAndroidField(t, androidTagOrigin, explicitAndroidInteger(t, kmOriginGenerated)),
	)
}

// androidPolicyRootOfTrust encodes a rootOfTrust with the given verified boot state. |
// androidPolicyRootOfTrust 编码携带给定验证启动状态的 rootOfTrust。
func androidPolicyRootOfTrust(t *testing.T, state int) []byte {
	t.Helper()
	sequence := testDERSequence(
		testDEROctetString([]byte{1, 2, 3}),
		testDERElement(derTagBoolean, []byte{0x00}),
		testDERElement(derTagEnumerated, []byte{byte(state)}),
	)
	return explicitAndroidField(t, androidTagRootOfTrust, sequence)
}

// newAndroidPolicyAttestationCert creates an android-key attestation certificate with the supplied
// AuthorizationList fields and certificate public key. | newAndroidPolicyAttestationCert 使用给定
// AuthorizationList 字段与证书公钥创建 android-key 认证证书。
func newAndroidPolicyAttestationCert(t *testing.T, signer *ecSigner, challenge, fields []byte) *x509.Certificate {
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
			Bytes:      fields,
		},
		TEEEnforced: asn1.RawValue{Class: derClassContext, Tag: 2, IsCompound: true},
	}
	value, err := asn1.Marshal(description)
	if err != nil {
		t.Fatalf("marshal android key description: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(31),
		Subject:               pkix.Name{CommonName: "Android Key Policy Attestation"},
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

// androidPolicyAppIDField returns an attestationApplicationId field for packageName. |
// androidPolicyAppIDField 返回 packageName 的 attestationApplicationId 字段。
func androidPolicyAppIDField(t *testing.T, packageName string) []byte {
	t.Helper()
	return explicitAndroidField(t, androidTagAttestationApplicationID,
		testDEROctetString(androidAttestationApplicationIDDER(t, packageName)))
}

// TestAndroidKeyPolicyBaselineAndAllApplications covers the documented zero-value baseline and the
// configurable allApplications override. | TestAndroidKeyPolicyBaselineAndAllApplications 覆盖已文档化
// 的零值基线与可配置 allApplications 覆盖。
func TestAndroidKeyPolicyBaselineAndAllApplications(t *testing.T) {
	signer := newECSigner(t)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	base := testConcat(androidPolicyBaseFields(t), androidPolicyAppIDField(t, "com.example.app"))
	cert := newAndroidPolicyAttestationCert(t, signer, challenge, base)
	if err := verifyAndroidKeyExtensionWithPolicy(cert, challenge, "com.example.app", AndroidKeyPolicy{}); err != nil {
		t.Fatalf("zero policy baseline: %v", err)
	}

	allApplications := testConcat(
		androidPolicyBaseFields(t),
		explicitAndroidField(t, androidTagAllApplications, nil),
	)
	allCert := newAndroidPolicyAttestationCert(t, signer, challenge, allApplications)
	if err := verifyAndroidKeyExtensionWithPolicy(allCert, challenge, "", AndroidKeyPolicy{}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("default allApplications error = %v, want ErrInvalidAttestation", err)
	}
	if err := verifyAndroidKeyExtensionWithPolicy(allCert, challenge, "", AndroidKeyPolicy{AllowAllApplications: true}); err != nil {
		t.Fatalf("AllowAllApplications: %v", err)
	}
}

// TestAndroidKeyPolicyVerifiedBoot covers the verified boot state requirement. |
// TestAndroidKeyPolicyVerifiedBoot 覆盖验证启动状态要求。
func TestAndroidKeyPolicyVerifiedBoot(t *testing.T) {
	signer := newECSigner(t)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	policy := AndroidKeyPolicy{RequireVerifiedBoot: true}

	verifiedFields := testConcat(androidPolicyBaseFields(t), androidPolicyRootOfTrust(t, androidVerifiedBootVerified))
	verified := newAndroidPolicyAttestationCert(t, signer, challenge, verifiedFields)
	if err := verifyAndroidKeyExtensionWithPolicy(verified, challenge, "", policy); err != nil {
		t.Fatalf("verified boot state: %v", err)
	}

	unverifiedFields := testConcat(androidPolicyBaseFields(t), androidPolicyRootOfTrust(t, 2))
	unverified := newAndroidPolicyAttestationCert(t, signer, challenge, unverifiedFields)
	if err := verifyAndroidKeyExtensionWithPolicy(unverified, challenge, "", policy); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("unverified boot state error = %v, want ErrInvalidAttestation", err)
	}

	missing := newAndroidPolicyAttestationCert(t, signer, challenge, androidPolicyBaseFields(t))
	if err := verifyAndroidKeyExtensionWithPolicy(missing, challenge, "", policy); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing rootOfTrust error = %v, want ErrInvalidAttestation", err)
	}
}

// TestAndroidKeyPolicyOSLevels covers the OS version and patch level minimums. |
// TestAndroidKeyPolicyOSLevels 覆盖 OS 版本与补丁级别下限。
func TestAndroidKeyPolicyOSLevels(t *testing.T) {
	signer := newECSigner(t)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	policy := AndroidKeyPolicy{MinOSVersion: 202401, MinOSPatchLevel: 202401}

	fields := testConcat(
		androidPolicyBaseFields(t),
		explicitAndroidField(t, androidTagOSVersion, explicitAndroidInteger(t, 202402)),
		explicitAndroidField(t, androidTagOSPatchLevel, explicitAndroidInteger(t, 202403)),
	)
	cert := newAndroidPolicyAttestationCert(t, signer, challenge, fields)
	if err := verifyAndroidKeyExtensionWithPolicy(cert, challenge, "", policy); err != nil {
		t.Fatalf("new enough OS levels: %v", err)
	}

	oldVersionFields := testConcat(
		androidPolicyBaseFields(t),
		explicitAndroidField(t, androidTagOSVersion, explicitAndroidInteger(t, 202312)),
		explicitAndroidField(t, androidTagOSPatchLevel, explicitAndroidInteger(t, 202403)),
	)
	oldVersion := newAndroidPolicyAttestationCert(t, signer, challenge, oldVersionFields)
	if err := verifyAndroidKeyExtensionWithPolicy(oldVersion, challenge, "", policy); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("old osVersion error = %v, want ErrInvalidAttestation", err)
	}

	oldPatchFields := testConcat(
		androidPolicyBaseFields(t),
		explicitAndroidField(t, androidTagOSVersion, explicitAndroidInteger(t, 202402)),
		explicitAndroidField(t, androidTagOSPatchLevel, explicitAndroidInteger(t, 202312)),
	)
	oldPatch := newAndroidPolicyAttestationCert(t, signer, challenge, oldPatchFields)
	if err := verifyAndroidKeyExtensionWithPolicy(oldPatch, challenge, "", policy); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("old osPatchLevel error = %v, want ErrInvalidAttestation", err)
	}

	missing := newAndroidPolicyAttestationCert(t, signer, challenge, androidPolicyBaseFields(t))
	if err := verifyAndroidKeyExtensionWithPolicy(missing, challenge, "", policy); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing OS levels error = %v, want ErrInvalidAttestation", err)
	}
}

// TestAndroidKeyPolicyKeyStrength covers key size, EC curve and declared value consistency. |
// TestAndroidKeyPolicyKeyStrength 覆盖密钥位数、EC 曲线与声明值一致性。
func TestAndroidKeyPolicyKeyStrength(t *testing.T) {
	signer := newECSigner(t)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	base := androidPolicyBaseFields(t)

	if err := verifyAndroidKeyExtensionWithPolicy(
		newAndroidPolicyAttestationCert(t, signer, challenge, base), challenge, "",
		AndroidKeyPolicy{MinKeySize: 256},
	); err != nil {
		t.Fatalf("P-256 meets 256-bit minimum: %v", err)
	}
	if err := verifyAndroidKeyExtensionWithPolicy(
		newAndroidPolicyAttestationCert(t, signer, challenge, base), challenge, "",
		AndroidKeyPolicy{MinKeySize: 384},
	); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("P-256 below 384-bit minimum error = %v, want ErrInvalidAttestation", err)
	}

	declaredSize := testConcat(base, explicitAndroidField(t, androidTagKeySize, explicitAndroidInteger(t, 2048)))
	if err := verifyAndroidKeyExtensionWithPolicy(
		newAndroidPolicyAttestationCert(t, signer, challenge, declaredSize), challenge, "",
		AndroidKeyPolicy{},
	); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("declared keySize mismatch error = %v, want ErrInvalidAttestation", err)
	}

	declaredCurve := testConcat(base, explicitAndroidField(t, androidTagECCurve, explicitAndroidInteger(t, 1)))
	if err := verifyAndroidKeyExtensionWithPolicy(
		newAndroidPolicyAttestationCert(t, signer, challenge, declaredCurve), challenge, "",
		AndroidKeyPolicy{AllowedECCurves: []int{256}},
	); err != nil {
		t.Fatalf("declared P-256 curve: %v", err)
	}

	wrongCurve := testConcat(base, explicitAndroidField(t, androidTagECCurve, explicitAndroidInteger(t, 2)))
	if err := verifyAndroidKeyExtensionWithPolicy(
		newAndroidPolicyAttestationCert(t, signer, challenge, wrongCurve), challenge, "",
		AndroidKeyPolicy{},
	); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("declared P-384 on P-256 key error = %v, want ErrInvalidAttestation", err)
	}

	if err := verifyAndroidKeyExtensionWithPolicy(
		newAndroidPolicyAttestationCert(t, signer, challenge, base), challenge, "",
		AndroidKeyPolicy{AllowedECCurves: []int{384}},
	); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("P-256 outside curve allowlist error = %v, want ErrInvalidAttestation", err)
	}
}

// TestAndroidKeyPolicyDigests covers the declared digest algorithm allowlist. |
// TestAndroidKeyPolicyDigests 覆盖已声明摘要算法允许列表。
func TestAndroidKeyPolicyDigests(t *testing.T) {
	signer := newECSigner(t)
	challenge := []byte("0123456789abcdef0123456789abcdef")

	sha256Fields := testConcat(
		androidPolicyBaseFields(t),
		explicitAndroidField(t, androidTagDigest, testDERSet(testDERInteger([]byte{4}))),
	)
	cert := newAndroidPolicyAttestationCert(t, signer, challenge, sha256Fields)
	if err := verifyAndroidKeyExtensionWithPolicy(cert, challenge, "", AndroidKeyPolicy{AllowedDigests: []string{"sha256"}}); err != nil {
		t.Fatalf("allowed sha256 digest: %v", err)
	}
	if err := verifyAndroidKeyExtensionWithPolicy(cert, challenge, "", AndroidKeyPolicy{AllowedDigests: []string{"sha384"}}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("disallowed sha256 digest error = %v, want ErrInvalidAttestation", err)
	}

	noDigest := newAndroidPolicyAttestationCert(t, signer, challenge, androidPolicyBaseFields(t))
	if err := verifyAndroidKeyExtensionWithPolicy(noDigest, challenge, "", AndroidKeyPolicy{AllowedDigests: []string{"sha256"}}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing digest error = %v, want ErrInvalidAttestation", err)
	}
}

// TestAndroidKeyPolicyApplicationDigests covers the package signature digest allowlist. |
// TestAndroidKeyPolicyApplicationDigests 覆盖包签名摘要允许列表。
func TestAndroidKeyPolicyApplicationDigests(t *testing.T) {
	signer := newECSigner(t)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	allowed := hex.EncodeToString(make([]byte, 32))
	fields := testConcat(androidPolicyBaseFields(t), androidPolicyAppIDField(t, "com.example.app"))
	cert := newAndroidPolicyAttestationCert(t, signer, challenge, fields)
	if err := verifyAndroidKeyExtensionWithPolicy(cert, challenge, "com.example.app", AndroidKeyPolicy{
		AllowedApplicationDigests: []string{allowed},
	}); err != nil {
		t.Fatalf("allowed application digest: %v", err)
	}

	other := hex.EncodeToString([]byte{1, 2, 3})
	if err := verifyAndroidKeyExtensionWithPolicy(cert, challenge, "com.example.app", AndroidKeyPolicy{
		AllowedApplicationDigests: []string{other},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("disallowed application digest error = %v, want ErrInvalidAttestation", err)
	}

	noAppID := newAndroidPolicyAttestationCert(t, signer, challenge, androidPolicyBaseFields(t))
	if err := verifyAndroidKeyExtensionWithPolicy(noAppID, challenge, "", AndroidKeyPolicy{
		AllowedApplicationDigests: []string{allowed},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing application digest error = %v, want ErrInvalidAttestation", err)
	}
}

// TestAndroidKeyPolicyInvalidConfiguration covers malformed policy rejection. |
// TestAndroidKeyPolicyInvalidConfiguration 覆盖非法策略拒绝。
func TestAndroidKeyPolicyInvalidConfiguration(t *testing.T) {
	signer := newECSigner(t)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	cert := newAndroidPolicyAttestationCert(t, signer, challenge, androidPolicyBaseFields(t))
	policies := []AndroidKeyPolicy{
		{MinKeySize: -1},
		{MinOSVersion: -1},
		{MinOSPatchLevel: -1},
		{AllowedECCurves: []int{255}},
		{AllowedDigests: []string{"sha3"}},
		{AllowedApplicationDigests: []string{"not base64!"}},
	}
	for _, policy := range policies {
		if err := verifyAndroidKeyExtensionWithPolicy(cert, challenge, "", policy); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("policy %+v error = %v, want ErrInvalidConfig", policy, err)
		}
	}
}

// TestAttestationVerifyAndroidKeyPolicy covers policy wiring through AttestationOptions. |
// TestAttestationVerifyAndroidKeyPolicy 覆盖通过 AttestationOptions 的策略接线。
func TestAttestationVerifyAndroidKeyPolicy(t *testing.T) {
	credentialSigner := newECSigner(t)
	var leaf *x509.Certificate
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		leaf = newAndroidPolicyAttestationCert(t, credentialSigner, clientDataHash, androidPolicyBaseFields(t))
		signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(leaf.Raw))},
		}
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:      testNow,
		AndroidKeyPolicy: AndroidKeyPolicy{MinKeySize: 256, AllowedECCurves: []int{256}},
	}); err != nil {
		t.Fatalf("Verify with matching policy: %v", err)
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:      testNow,
		AndroidKeyPolicy: AndroidKeyPolicy{MinKeySize: 384},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("Verify with rejecting policy error = %v, want ErrInvalidAttestation", err)
	}
}

// TestNewRejectsInvalidAttestationPolicies covers fail-fast Config validation. |
// TestNewRejectsInvalidAttestationPolicies 覆盖 Config 快速失败校验。
func TestNewRejectsInvalidAttestationPolicies(t *testing.T) {
	base := Config{
		RPDisplayName: "Example",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}
	safetyNet := base
	safetyNet.SafetyNetPolicy = SafetyNetPolicy{TimestampTolerance: -time.Second}
	if _, err := New(safetyNet); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid SafetyNetPolicy error = %v, want ErrInvalidConfig", err)
	}
	androidKey := base
	androidKey.AndroidKeyPolicy = AndroidKeyPolicy{MinKeySize: -1}
	if _, err := New(androidKey); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid AndroidKeyPolicy error = %v, want ErrInvalidConfig", err)
	}
	valid := base
	valid.SafetyNetPolicy = SafetyNetPolicy{RequireBasicIntegrity: true}
	valid.AndroidKeyPolicy = AndroidKeyPolicy{MinKeySize: 256}
	if _, err := New(valid); err != nil {
		t.Fatalf("valid policies: %v", err)
	}
}
