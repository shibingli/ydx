package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// TestAttestationStatementAccessors covers missing, mistyped, and valid statement members. |
// TestAttestationStatementAccessors 覆盖缺失、类型错误与合法的声明成员。
func TestAttestationStatementAccessors(t *testing.T) {
	stmt := NewMap(
		Pair{Key: NewText("bytes"), Value: NewBytes([]byte{1, 2})},
		Pair{Key: NewText("int"), Value: NewInt(7)},
		Pair{Key: NewText("text"), Value: NewText("value")},
		Pair{Key: NewText("empty"), Value: NewText("")},
		Pair{Key: NewText("bad"), Value: NewBool(true)},
	)
	if _, err := attestationStatementBytes(stmt, "missing"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing bytes error = %v", err)
	}
	if _, err := attestationStatementBytes(stmt, "bad"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("mistyped bytes error = %v", err)
	}
	if value, err := attestationStatementBytes(stmt, "bytes"); err != nil || len(value) != 2 {
		t.Fatalf("bytes = %v, err = %v", value, err)
	}

	if _, err := attestationStatementInt(stmt, "missing"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing int error = %v", err)
	}
	if _, err := attestationStatementInt(stmt, "bad"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("mistyped int error = %v", err)
	}
	if value, err := attestationStatementInt(stmt, "int"); err != nil || value != 7 {
		t.Fatalf("int = %d, err = %v", value, err)
	}

	if _, err := attestationStatementText(stmt, "missing"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing text error = %v", err)
	}
	if _, err := attestationStatementText(stmt, "bad"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("mistyped text error = %v", err)
	}
	if _, err := attestationStatementText(stmt, "empty"); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("empty text error = %v", err)
	}
	if value, err := attestationStatementText(stmt, "text"); err != nil || value != "value" {
		t.Fatalf("text = %q, err = %v", value, err)
	}

	if value, present, err := attestationStatementX5C(NewMap()); err != nil || present || value != nil {
		t.Fatalf("missing x5c = %v, %v, %v", value, present, err)
	}
	if _, _, err := attestationStatementX5C(NewMap(Pair{Key: NewText("x5c"), Value: NewText("bad")})); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("mistyped x5c error = %v", err)
	}
	if _, _, err := attestationStatementX5C(NewMap(Pair{Key: NewText("x5c"), Value: NewArray()})); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("empty x5c error = %v", err)
	}
	tooMany := make([]*Value, 0, maxAttestationCertificates+1)
	for i := 0; i <= maxAttestationCertificates; i++ {
		tooMany = append(tooMany, NewBytes(nil))
	}
	if _, _, err := attestationStatementX5C(NewMap(Pair{Key: NewText("x5c"), Value: NewArray(tooMany...)})); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("oversized x5c error = %v", err)
	}
	x5c := NewArray(NewBytes([]byte{1}))
	if value, present, err := attestationStatementX5C(NewMap(Pair{Key: NewText("x5c"), Value: x5c})); err != nil || !present || value != x5c {
		t.Fatalf("valid x5c = %v, %v, %v", value, present, err)
	}
}

// TestParseX5CErrors covers malformed certificate arrays. | TestParseX5CErrors 覆盖非法证书数组。
func TestParseX5CErrors(t *testing.T) {
	cert := newTestAttestationCert(t, newECSigner(t))
	if _, err := parseX5C(nil); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("nil error = %v", err)
	}
	if _, err := parseX5C(NewText("bad")); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("non-array error = %v", err)
	}
	if _, err := parseX5C(NewArray()); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("empty array error = %v", err)
	}
	tooMany := make([]*Value, 0, maxAttestationCertificates+1)
	for i := 0; i <= maxAttestationCertificates; i++ {
		tooMany = append(tooMany, NewBytes(cert.Raw))
	}
	if _, err := parseX5C(NewArray(tooMany...)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("oversized array error = %v", err)
	}
	if _, err := parseX5C(NewArray(NewText("bad"))); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("non-bytes entry error = %v", err)
	}
	if _, err := parseX5C(NewArray(NewBytes([]byte{1, 2, 3}))); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("non-certificate entry error = %v", err)
	}
	certs, err := parseX5C(NewArray(NewBytes(cert.Raw)))
	if err != nil {
		t.Fatalf("parseX5C: %v", err)
	}
	if len(certs) != 1 || !certs[0].Equal(cert) {
		t.Fatalf("certs = %v", certs)
	}
}

// TestAttestationOptionsCurrentTime covers the zero and explicit verification time. |
// TestAttestationOptionsCurrentTime 覆盖零值与显式校验时间。
func TestAttestationOptionsCurrentTime(t *testing.T) {
	if got := (AttestationOptions{}).currentTime(); got.IsZero() || time.Since(got) > time.Minute {
		t.Fatalf("zero current time = %v", got)
	}
	if got := (AttestationOptions{CurrentTime: testNow}).currentTime(); !got.Equal(testNow) {
		t.Fatalf("explicit current time = %v", got)
	}
}

// newAppleCertWithExtension returns a certificate carrying an arbitrary Apple nonce extension. |
// newAppleCertWithExtension 返回携带任意 Apple nonce 扩展的证书。
func newAppleCertWithExtension(t *testing.T, signer *ecSigner, value []byte, include bool) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(160),
		Subject:               pkix.Name{CommonName: "Apple Extension Test"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if include {
		template.ExtraExtensions = []pkix.Extension{{Id: appleNonceOID, Value: value}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.key.Public(), signer.key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestAttestationAppleExtensionErrors covers missing, malformed, and absent nonce fields. |
// TestAttestationAppleExtensionErrors 覆盖缺失、非法与不存在 nonce 字段。
func TestAttestationAppleExtensionErrors(t *testing.T) {
	credentialSigner := newECSigner(t)
	cases := []struct {
		name    string
		value   []byte
		include bool
	}{
		{name: "missing nonce extension"},
		{name: "malformed nonce extension", value: []byte{0x30, 0x80}, include: true},
		{name: "trailing extension data", value: []byte{0xa1, 0x00, 0x00}, include: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			object, hash := buildTestAttestation(t, credentialSigner, FormatApple, func(t *testing.T, authData, clientDataHash []byte) []Pair {
				cert := newAppleCertWithExtension(t, credentialSigner, test.value, test.include)
				return []Pair{{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))}}
			})
			if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}

	missingX5C, missingHash := buildTestAttestation(t, credentialSigner, FormatApple, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{}
	})
	if _, err := missingX5C.Verify(context.Background(), missingHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing x5c error = %v, want ErrInvalidAttestation", err)
	}
}
