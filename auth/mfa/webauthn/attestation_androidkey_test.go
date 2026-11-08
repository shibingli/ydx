package webauthn

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// explicitAndroidField encodes one EXPLICIT context-specific AuthorizationList field. |
// explicitAndroidField 编码一个 EXPLICIT 上下文特定 AuthorizationList 字段。
func explicitAndroidField(t *testing.T, tag int, inner []byte) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(asn1.RawValue{Class: derClassContext, Tag: tag, IsCompound: true, Bytes: inner})
	if err != nil {
		t.Fatalf("marshal explicit android field %d: %v", tag, err)
	}
	return encoded
}

// explicitAndroidInteger encodes a non-negative INTEGER for an explicit field. | explicitAndroidInteger
// 为显式字段编码非负 INTEGER。
func explicitAndroidInteger(t *testing.T, value int) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal android integer: %v", err)
	}
	return encoded
}

// androidAttestationApplicationIDDER returns the AttestationApplicationId DER for packageName. |
// androidAttestationApplicationIDDER 返回 packageName 的 AttestationApplicationId DER。
func androidAttestationApplicationIDDER(t *testing.T, packageName string) []byte {
	t.Helper()
	packageInfo := testDERSequence(testDEROctetString([]byte(packageName)), testDERElement(0x02, []byte{1}))
	packages := testDERSequence(packageInfo)
	digests := testDERSequence(testDEROctetString(make([]byte, 32)))
	return testDERSequence(packages, digests)
}

// newExplicitAndroidKeyAttestationCert returns an android-key attestation certificate whose
// AuthorizationList uses the standard EXPLICIT encoding of origin and attestationApplicationId. |
// newExplicitAndroidKeyAttestationCert 返回 AuthorizationList 使用标准 EXPLICIT 编码 origin 与
// attestationApplicationId 的 android-key 认证证书。
func newExplicitAndroidKeyAttestationCert(t *testing.T, challenge []byte, packageName string, origin int) *x509.Certificate {
	t.Helper()
	signer := newECSigner(t)
	fields := testConcat(
		explicitAndroidField(t, androidTagPurpose, testDERSet(explicitAndroidInteger(t, kmPurposeSign))),
		explicitAndroidField(t, androidTagOrigin, explicitAndroidInteger(t, origin)),
		explicitAndroidField(t, androidTagAttestationApplicationID,
			testDEROctetString(androidAttestationApplicationIDDER(t, packageName))),
	)
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
		SerialNumber:          big.NewInt(21),
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

// TestVerifyAndroidKeyExtensionExplicitAuthorizationList checks that the standard AOSP EXPLICIT
// encoding of origin and attestationApplicationId is accepted. |
// TestVerifyAndroidKeyExtensionExplicitAuthorizationList 检查标准 AOSP EXPLICIT 编码的 origin 与
// attestationApplicationId 会被接受。
func TestVerifyAndroidKeyExtensionExplicitAuthorizationList(t *testing.T) {
	challenge := []byte("0123456789abcdef0123456789abcdef")
	cert := newExplicitAndroidKeyAttestationCert(t, challenge, "com.example.app", kmOriginGenerated)
	if err := verifyAndroidKeyExtension(cert, challenge, "com.example.app"); err != nil {
		t.Fatalf("verifyAndroidKeyExtension = %v, want nil | 标准显式编码应通过", err)
	}

	requiredPackage := newExplicitAndroidKeyAttestationCert(t, challenge, "com.example.app", kmOriginGenerated)
	if err := verifyAndroidKeyExtension(requiredPackage, challenge, "com.example.other"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("wrong package error = %v, want ErrInvalidAttestation | 包名不匹配未被拒绝", err)
	}

	imported := newExplicitAndroidKeyAttestationCert(t, challenge, "com.example.app", 2)
	if err := verifyAndroidKeyExtension(imported, challenge, "com.example.app"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("imported origin error = %v, want ErrInvalidAttestation | 非生成来源未被拒绝", err)
	}

	if err := verifyAndroidKeyExtension(requiredPackage, []byte("ffffffffffffffffffffffffffffffff"), "com.example.app"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("wrong challenge error = %v, want ErrInvalidAttestation | 挑战不匹配未被拒绝", err)
	}
}
