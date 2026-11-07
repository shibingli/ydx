package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"
)

// tpmU16 encodes a big-endian uint16. | tpmU16 编码大端 uint16。
func tpmU16(value uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, value)
	return out
}

// tpmU32 encodes a big-endian uint32. | tpmU32 编码大端 uint32。
func tpmU32(value uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}

// tpmSizedBytes prefixes data with its big-endian uint16 length. | tpmSizedBytes 用大端 uint16 长度前缀 data。
func tpmSizedBytes(data []byte) []byte {
	out := tpmU16(uint16(len(data)))
	return append(out, data...)
}

// tpmECCPubArea encodes a TPMT_PUBLIC for a P-256 credential key. | tpmECCPubArea 为 P-256 凭据密钥编码 TPMT_PUBLIC。
func tpmECCPubArea(t *testing.T, signer *ecSigner) []byte {
	t.Helper()
	out := tpmU16(tpmAlgECC)
	out = append(out, tpmU16(tpmAlgSHA256)...)
	out = append(out, tpmU32(0x00040072)...)
	out = append(out, tpmSizedBytes(nil)...)
	out = append(out, tpmU16(tpmAlgNULL)...)
	out = append(out, tpmU16(tpmAlgNULL)...)
	out = append(out, tpmU16(tpmEccNISTP256)...)
	out = append(out, tpmU16(tpmAlgNULL)...)
	publicKey := signer.publicKeyBytes(t)
	out = append(out, tpmSizedBytes(publicKey[1:33])...)
	out = append(out, tpmSizedBytes(publicKey[33:])...)
	return out
}

// tpmCertInfo encodes a TPMS_ATTEST certifying pubArea. | tpmCertInfo 编码认证 pubArea 的 TPMS_ATTEST。
func tpmCertInfo(t *testing.T, pubArea []byte, extraData []byte) []byte {
	t.Helper()
	name := sha256.Sum256(pubArea)
	attestedName := append(tpmU16(tpmAlgSHA256), name[:]...)
	out := tpmU32(tpmGeneratedMagic)
	out = append(out, tpmU16(tpmStAttestCertify)...)
	out = append(out, tpmSizedBytes(nil)...)
	out = append(out, tpmSizedBytes(extraData)...)
	out = append(out, make([]byte, 17+8)...)
	out = append(out, tpmSizedBytes(attestedName)...)
	out = append(out, tpmSizedBytes(nil)...)
	return out
}

// tpmECDSASignature signs certInfo with signer and encodes a TPMT_SIGNATURE. | tpmECDSASignature 用 signer 签名 certInfo 并编码 TPMT_SIGNATURE。
func tpmECDSASignature(t *testing.T, signer *ecSigner, certInfo []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(certInfo)
	r, s, err := ecdsa.Sign(rand.Reader, signer.key, digest[:])
	if err != nil {
		t.Fatalf("sign TPM certInfo: %v", err)
	}
	out := tpmU16(tpmAlgECDSA)
	out = append(out, tpmU16(tpmAlgSHA256)...)
	out = append(out, tpmSizedBytes(r.Bytes())...)
	out = append(out, tpmSizedBytes(s.Bytes())...)
	return out
}

// marshalDERValue encodes a raw DER value. | marshalDERValue 编码原始 DER 值。
func marshalDERValue(t *testing.T, value asn1.RawValue) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	return encoded
}

// newTPMAttestationCert returns an X.509 v3 AIK certificate with an empty subject. |
// newTPMAttestationCert 返回主题为空的 X.509 v3 AIK 证书。
func newTPMAttestationCert(t *testing.T, signer *ecSigner) *x509.Certificate {
	t.Helper()
	rdns, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: tpmManufacturerOID, Value: "id:FFFFF1D0"}},
		{{Type: tpmModelOID, Value: "id:FFFFF1D0"}},
		{{Type: tpmVersionOID, Value: "id:FFFFF1D0"}},
	})
	if err != nil {
		t.Fatalf("marshal TPM RDN sequence: %v", err)
	}
	directoryName := marshalDERValue(t, asn1.RawValue{Class: derClassContext, Tag: 4, IsCompound: true, Bytes: rdns})
	san := marshalDERValue(t, asn1.RawValue{Class: derClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: directoryName})
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(14),
		Subject:               pkix.Name{},
		NotBefore:             testNow.Add(-2 * time.Hour),
		NotAfter:              testNow.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{tcgKpAIKCertOID},
		ExtraExtensions:       []pkix.Extension{{Id: subjectAltNameOID, Value: san}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.key.Public(), signer.key)
	if err != nil {
		t.Fatalf("create TPM attestation certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse TPM attestation certificate: %v", err)
	}
	return cert
}

func TestAttestationVerifyTPM(t *testing.T) {
	credentialSigner := newECSigner(t)
	aik := newECSigner(t)
	cert := newTPMAttestationCert(t, aik)
	pubArea := tpmECCPubArea(t, credentialSigner)
	object, hash := buildTestAttestation(t, credentialSigner, FormatTPM, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		extraData := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		certInfo := tpmCertInfo(t, pubArea, extraData[:])
		return []Pair{
			{Key: NewText("ver"), Value: NewText("2.0")},
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(tpmECDSASignature(t, aik, certInfo))},
			{Key: NewText("certInfo"), Value: NewBytes(certInfo)},
			{Key: NewText("pubArea"), Value: NewBytes(pubArea)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	})
	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		Roots:       certificateRoots(cert),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Type != AttestationTypeAttCA || result.Format != FormatTPM || !result.TrustVerified {
		t.Fatalf("result = %#v", result)
	}

	wrongExtra, wrongExtraHash := buildTestAttestation(t, credentialSigner, FormatTPM, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		extraData := sha256.Sum256([]byte("unrelated data"))
		info := tpmCertInfo(t, pubArea, extraData[:])
		return []Pair{
			{Key: NewText("ver"), Value: NewText("2.0")},
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(tpmECDSASignature(t, aik, info))},
			{Key: NewText("certInfo"), Value: NewBytes(info)},
			{Key: NewText("pubArea"), Value: NewBytes(pubArea)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	})
	if _, err := wrongExtra.Verify(context.Background(), wrongExtraHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("wrong extraData error = %v, want ErrInvalidAttestation", err)
	}
}

func TestTPMStructureValidation(t *testing.T) {
	credentialSigner := newECSigner(t)
	pubArea := tpmECCPubArea(t, credentialSigner)
	if area, err := parseTPMPublicArea(pubArea); err != nil || area.nameAlg != tpmAlgSHA256 {
		t.Fatalf("parseTPMPublicArea = %#v, %v", area, err)
	}
	if _, err := parseTPMPublicArea(pubArea[:10]); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("truncated pubArea error = %v", err)
	}
	if _, err := parseTPMPublicArea(append(append([]byte(nil), pubArea...), 0)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("trailing pubArea error = %v", err)
	}
	if _, err := parseTPMSAttest(tpmCertInfo(t, pubArea, make([]byte, 32))); err != nil {
		t.Fatalf("parseTPMSAttest: %v", err)
	}
	badMagic := tpmCertInfo(t, pubArea, nil)
	badMagic[0] = 0
	if _, err := parseTPMSAttest(badMagic); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("bad magic error = %v", err)
	}
	signature := tpmECDSASignature(t, newECSigner(t), []byte("certInfo"))
	parsed, err := parseTPMSignature(signature)
	if err != nil || parsed.sigAlg != tpmAlgECDSA || parsed.hashAlg != tpmAlgSHA256 {
		t.Fatalf("parseTPMSignature = %#v, %v", parsed, err)
	}
	if !tpmSignatureMatchesAlgorithm(parsed, AlgES256) {
		t.Fatal("ECDSA SHA-256 signature did not match ES256")
	}
	if tpmSignatureMatchesAlgorithm(parsed, AlgRS256) {
		t.Fatal("ECDSA signature matched RS256")
	}
	if _, err := parseTPMSignature(append(signature, 0)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("trailing signature error = %v", err)
	}
	if _, err := parseTPMSignature(tpmU16(0xffff)); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unknown signature algorithm error = %v", err)
	}
	if _, err := parseTPMPublicArea(append(tpmU16(tpmAlgRSA), tpmU16(tpmAlgSHA256)...)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("truncated RSA pubArea error = %v", err)
	}
}

func TestTPMCertificateValidation(t *testing.T) {
	signer := newECSigner(t)
	cert := newTPMAttestationCert(t, signer)
	if err := verifyTPMCertificate(cert); err != nil {
		t.Fatalf("verifyTPMCertificate: %v", err)
	}
	bad := *cert
	bad.Subject = pkix.Name{CommonName: "not empty"}
	if err := verifyTPMCertificate(&bad); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("non-empty subject error = %v", err)
	}
}
