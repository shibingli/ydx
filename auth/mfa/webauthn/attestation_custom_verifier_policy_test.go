package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
)

// TestSafetyNetCustomVerifierStillEnforcesPolicy verifies that a custom verifier cannot disable a
// non-zero SafetyNetPolicy. | TestSafetyNetCustomVerifierStillEnforcesPolicy 验证自定义校验器不能关闭
// 非零 SafetyNetPolicy。
func TestSafetyNetCustomVerifierStillEnforcesPolicy(t *testing.T) {
	credentialSigner := newECSigner(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	cert := newSafetyNetCertificate(t, key)
	accepting := SafetyNetVerifierFunc(func(context.Context, []byte, []byte) error { return nil })
	policy := SafetyNetPolicy{RequireBasicIntegrity: true}

	passing, passingHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", nil)
	result, err := passing.Verify(context.Background(), passingHash, AttestationOptions{
		CurrentTime:       testNow,
		SafetyNetVerifier: accepting,
		SafetyNetPolicy:   policy,
		SafetyNetRoots:    certificateRoots(cert),
	})
	if err != nil {
		t.Fatalf("policy-compliant activation with custom verifier: %v", err)
	}
	if !result.TrustVerified || result.Type != AttestationTypeBasic {
		t.Fatalf("result = %#v", result)
	}

	failing, failingHash := buildSafetyNetPolicyObject(t, credentialSigner, cert, key, "1.0", func(payload *testSafetyNetPayload) {
		payload.BasicIntegrity = false
	})
	if _, err := failing.Verify(context.Background(), failingHash, AttestationOptions{
		CurrentTime:       testNow,
		SafetyNetVerifier: accepting,
		SafetyNetPolicy:   policy,
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("custom verifier bypassed basicIntegrity policy: %v", err)
	}

	// The zero policy keeps the baseline behavior for custom verifiers. | 零值策略保持自定义校验器的
	// 基线行为。
	if _, err := failing.Verify(context.Background(), failingHash, AttestationOptions{
		CurrentTime:       testNow,
		SafetyNetVerifier: accepting,
	}); err != nil {
		t.Fatalf("zero policy with custom verifier: %v", err)
	}

	// A non-zero policy also re-runs the mandatory signature check after the custom verifier. |
	// 非零策略还会在自定义校验器之后重新执行强制签名校验。
	unsigned, unsignedHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetJWS(t, cert, nonce[:], testNow.UnixMilli(), true, nil))},
		}
	})
	if _, err := unsigned.Verify(context.Background(), unsignedHash, AttestationOptions{
		CurrentTime:       testNow,
		SafetyNetVerifier: accepting,
		SafetyNetPolicy:   policy,
	}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("custom verifier bypassed mandatory signature check: %v", err)
	}
}

// TestAndroidKeyCustomVerifierStillEnforcesPolicy verifies that a custom verifier cannot disable a
// non-zero AndroidKeyPolicy. | TestAndroidKeyCustomVerifierStillEnforcesPolicy 验证自定义校验器不能关闭
// 非零 AndroidKeyPolicy。
func TestAndroidKeyCustomVerifierStillEnforcesPolicy(t *testing.T) {
	credentialSigner := newECSigner(t)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		leaf := newAndroidPolicyAttestationCert(t, credentialSigner, clientDataHash, androidPolicyBaseFields(t))
		signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(leaf.Raw))},
		}
	})
	accepting := AndroidKeyVerifierFunc(func(context.Context, []*x509.Certificate, AndroidKeyVerifyOptions) (bool, error) {
		return true, nil
	})

	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:        testNow,
		AndroidKeyVerifier: accepting,
		AndroidKeyPolicy:   AndroidKeyPolicy{MinKeySize: 256},
	})
	if err != nil {
		t.Fatalf("policy-compliant android-key with custom verifier: %v", err)
	}
	if !result.TrustVerified || result.Type != AttestationTypeBasic {
		t.Fatalf("result = %#v", result)
	}

	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:        testNow,
		AndroidKeyVerifier: accepting,
		AndroidKeyPolicy:   AndroidKeyPolicy{MinKeySize: 384},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("custom verifier bypassed key size policy: %v", err)
	}

	noExtension := newTestAttestationCert(t, credentialSigner)
	noExtensionObject, noExtensionHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(noExtension.Raw))},
		}
	})
	if _, err := noExtensionObject.Verify(context.Background(), noExtensionHash, AttestationOptions{
		CurrentTime:        testNow,
		AndroidKeyVerifier: accepting,
		AndroidKeyPolicy:   AndroidKeyPolicy{RequireVerifiedBoot: true},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("custom verifier bypassed extension policy: %v", err)
	}
}
