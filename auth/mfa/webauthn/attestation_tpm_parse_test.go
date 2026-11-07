package webauthn

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
)

// testTPMPrefix encodes the common TPMT_PUBLIC prefix. | testTPMPrefix 编码 TPMT_PUBLIC 的公共前缀。
func testTPMPrefix(keyType, nameAlg uint16) []byte {
	out := tpmU16(keyType)
	out = append(out, tpmU16(nameAlg)...)
	out = append(out, tpmU32(0)...)
	out = append(out, tpmSizedBytes(nil)...)
	return out
}

// testTPMRSAPubArea encodes an RSA TPMT_PUBLIC. | testTPMRSAPubArea 编码 RSA TPMT_PUBLIC。
func testTPMRSAPubArea(symmetric []byte, scheme uint16, exponent uint32, modulus []byte) []byte {
	out := testTPMPrefix(tpmAlgRSA, tpmAlgSHA256)
	out = append(out, symmetric...)
	out = append(out, tpmU16(scheme)...)
	if scheme != tpmAlgNULL {
		out = append(out, tpmU16(tpmAlgSHA256)...)
	}
	out = append(out, tpmU16(2048)...)
	out = append(out, tpmU32(exponent)...)
	out = append(out, tpmSizedBytes(modulus)...)
	return out
}

// testTPMECCPubArea encodes an ECC TPMT_PUBLIC with explicit coordinates. | testTPMECCPubArea 用显式坐标编码 ECC TPMT_PUBLIC。
func testTPMECCPubArea(curve uint16, kdf []byte, x, y []byte) []byte {
	out := testTPMPrefix(tpmAlgECC, tpmAlgSHA256)
	out = append(out, tpmU16(tpmAlgNULL)...)
	out = append(out, tpmU16(tpmAlgNULL)...)
	out = append(out, tpmU16(curve)...)
	out = append(out, kdf...)
	out = append(out, tpmSizedBytes(x)...)
	out = append(out, tpmSizedBytes(y)...)
	return out
}

// testTPMAttest encodes a TPMS_ATTEST with explicit fields. | testTPMAttest 用显式字段编码 TPMS_ATTEST。
func testTPMAttest(magic uint32, attestType uint16, qualified, extra, clock, name, qualifiedName, trailing []byte) []byte {
	out := tpmU32(magic)
	out = append(out, tpmU16(attestType)...)
	out = append(out, tpmSizedBytes(qualified)...)
	out = append(out, tpmSizedBytes(extra)...)
	out = append(out, clock...)
	out = append(out, tpmSizedBytes(name)...)
	out = append(out, tpmSizedBytes(qualifiedName)...)
	return append(out, trailing...)
}

// testTPMSAN builds a subjectAltName extension holding one directory name. | testTPMSAN 构建携带一个目录名的 subjectAltName 扩展。
func testTPMSAN(t *testing.T, sequence pkix.RDNSequence) []byte {
	t.Helper()
	rdns, err := asn1.Marshal(sequence)
	if err != nil {
		t.Fatalf("marshal RDN sequence: %v", err)
	}
	directory := marshalDERValue(t, asn1.RawValue{Class: derClassContext, Tag: 4, IsCompound: true, Bytes: rdns})
	return marshalDERValue(t, asn1.RawValue{Class: derClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: directory})
}

// cloneCertificateWithSAN returns a shallow certificate clone with a replaced SAN value. |
// cloneCertificateWithSAN 返回替换 SAN 值的浅拷贝证书。
func cloneCertificateWithSAN(cert *x509.Certificate, value []byte, present bool) *x509.Certificate {
	clone := *cert
	extensions := make([]pkix.Extension, 0, len(cert.Extensions))
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(subjectAltNameOID) {
			if present {
				extension.Value = value
				extensions = append(extensions, extension)
			}
			continue
		}
		extensions = append(extensions, extension)
	}
	clone.Extensions = extensions
	return &clone
}

// TestParseTPMPublicAreaBranches covers RSA, ECC, and malformed public areas. |
// TestParseTPMPublicAreaBranches 覆盖 RSA、ECC 与非法公钥区域。
func TestParseTPMPublicAreaBranches(t *testing.T) {
	modulus := make([]byte, 256)
	modulus[0] = 0x80
	modulus[255] = 0x01

	rsaArea, err := parseTPMPublicArea(testTPMRSAPubArea(tpmU16(tpmAlgNULL), tpmAlgRSASSA, tpmDefaultExponent, modulus))
	if err != nil {
		t.Fatalf("RSA public area: %v", err)
	}
	if rsaArea.keyType != tpmAlgRSA || rsaArea.nameAlg != tpmAlgSHA256 {
		t.Fatalf("RSA area = %+v", rsaArea)
	}
	defaultExponent, err := parseTPMPublicArea(testTPMRSAPubArea(tpmU16(tpmAlgNULL), tpmAlgNULL, 0, modulus))
	if err != nil {
		t.Fatalf("default exponent area: %v", err)
	}
	key, ok := defaultExponent.publicKey.(*rsa.PublicKey)
	if !ok || key.E != tpmDefaultExponent {
		t.Fatalf("default exponent key = %v", defaultExponent.publicKey)
	}
	symmetric := testConcat(tpmU16(0x0006), tpmU16(128), tpmU16(0x0043))
	if _, err := parseTPMPublicArea(testTPMRSAPubArea(symmetric, tpmAlgRSAPSS, 3, modulus)); err != nil {
		t.Fatalf("symmetric and PSS area: %v", err)
	}

	ecSigner := newECSigner(t)
	publicKey := ecSigner.publicKeyBytes(t)
	validECC := testTPMECCPubArea(tpmEccNISTP256, tpmU16(tpmAlgNULL), publicKey[1:33], publicKey[33:])
	if area, err := parseTPMPublicArea(validECC); err != nil || area.keyType != tpmAlgECC {
		t.Fatalf("ECC public area = %+v, %v", area, err)
	}
	withKDF := testConcat(tpmU16(0x0020), tpmU16(tpmAlgSHA256))
	if _, err := parseTPMPublicArea(testTPMECCPubArea(tpmEccNISTP256, withKDF, publicKey[1:33], publicKey[33:])); err != nil {
		t.Fatalf("ECC KDF public area: %v", err)
	}

	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "unknown name algorithm", raw: testTPMPrefix(tpmAlgRSA, 0x1234), want: ErrUnsupportedAlgorithm},
		{name: "unknown key type", raw: testTPMPrefix(0x9999, tpmAlgSHA256), want: ErrUnsupportedKey},
		{name: "RSA truncated symmetric", raw: testTPMPrefix(tpmAlgRSA, tpmAlgSHA256), want: ErrInvalidAttestation},
		{name: "RSA unknown scheme", raw: testConcat(testTPMPrefix(tpmAlgRSA, tpmAlgSHA256), tpmU16(tpmAlgNULL), tpmU16(0xdead)), want: ErrUnsupportedAlgorithm},
		{name: "RSA truncated scheme hash", raw: testConcat(testTPMPrefix(tpmAlgRSA, tpmAlgSHA256), tpmU16(tpmAlgNULL), tpmU16(tpmAlgRSASSA)), want: ErrInvalidAttestation},
		{name: "RSA empty modulus", raw: testTPMRSAPubArea(tpmU16(tpmAlgNULL), tpmAlgNULL, tpmDefaultExponent, nil), want: ErrInvalidAttestation},
		{name: "RSA small exponent", raw: testTPMRSAPubArea(tpmU16(tpmAlgNULL), tpmAlgNULL, 1, modulus), want: ErrInvalidAttestation},
		{name: "RSA even exponent", raw: testTPMRSAPubArea(tpmU16(tpmAlgNULL), tpmAlgNULL, 4, modulus), want: ErrInvalidAttestation},
		{name: "ECC unknown curve", raw: testTPMECCPubArea(0x9999, tpmU16(tpmAlgNULL), publicKey[1:33], publicKey[33:]), want: ErrUnsupportedKey},
		{name: "ECC unknown KDF", raw: testTPMECCPubArea(tpmEccNISTP256, tpmU16(0xdead), publicKey[1:33], publicKey[33:]), want: ErrUnsupportedAlgorithm},
		{name: "ECC empty point", raw: testTPMECCPubArea(tpmEccNISTP256, tpmU16(tpmAlgNULL), nil, nil), want: ErrInvalidAttestation},
		{name: "ECC invalid point", raw: testTPMECCPubArea(tpmEccNISTP256, tpmU16(tpmAlgNULL), []byte{1}, []byte{1}), want: ErrInvalidAttestation},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseTPMPublicArea(test.raw); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestParseTPMSAttestBranches covers truncation, wrong types, and trailing data. |
// TestParseTPMSAttestBranches 覆盖截断、类型错误与尾随数据。
func TestParseTPMSAttestBranches(t *testing.T) {
	clock := make([]byte, 25)
	valid := testTPMAttest(tpmGeneratedMagic, tpmStAttestCertify, nil, []byte{1, 2}, clock, []byte("name"), nil, nil)
	attest, err := parseTPMSAttest(valid)
	if err != nil {
		t.Fatalf("parseTPMSAttest: %v", err)
	}
	if len(attest.extraData) != 2 || string(attest.name) != "name" {
		t.Fatalf("attest = %+v", attest)
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "truncated magic", raw: valid[:3]},
		{name: "truncated type", raw: valid[:5]},
		{name: "truncated qualified signer length", raw: valid[:6]},
		{name: "truncated qualified signer", raw: testConcat(valid[:6], tpmU16(10))},
		{name: "truncated extra data length", raw: testTPMAttest(tpmGeneratedMagic, tpmStAttestCertify, nil, nil, nil, nil, nil, nil)[:8]},
		{name: "truncated clock", raw: testTPMAttest(tpmGeneratedMagic, tpmStAttestCertify, nil, nil, make([]byte, 10), nil, nil, nil)},
		{name: "truncated name length", raw: testConcat(tpmU32(tpmGeneratedMagic), tpmU16(tpmStAttestCertify), tpmSizedBytes(nil), tpmSizedBytes(nil), clock)},
		{name: "truncated qualified name", raw: testTPMAttest(tpmGeneratedMagic, tpmStAttestCertify, nil, nil, clock, nil, nil, nil)[:len(testTPMAttest(tpmGeneratedMagic, tpmStAttestCertify, nil, nil, clock, nil, nil, nil))-2]},
		{name: "wrong magic", raw: testTPMAttest(0, tpmStAttestCertify, nil, nil, clock, nil, nil, nil)},
		{name: "wrong type", raw: testTPMAttest(tpmGeneratedMagic, 0x8014, nil, nil, clock, nil, nil, nil)},
		{name: "trailing bytes", raw: testTPMAttest(tpmGeneratedMagic, tpmStAttestCertify, nil, nil, clock, nil, nil, []byte{0})},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseTPMSAttest(test.raw); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}
}

// TestParseTPMSignatureBranches covers RSA and ECDSA signature encodings. |
// TestParseTPMSignatureBranches 覆盖 RSA 与 ECDSA 签名编码。
func TestParseTPMSignatureBranches(t *testing.T) {
	rsaSignature := testConcat(tpmU16(tpmAlgRSASSA), tpmU16(tpmAlgSHA256), tpmSizedBytes([]byte{1, 2, 3}))
	parsed, err := parseTPMSignature(rsaSignature)
	if err != nil || parsed.sigAlg != tpmAlgRSASSA || len(parsed.signature) != 3 {
		t.Fatalf("RSA signature = %+v, %v", parsed, err)
	}
	if !tpmSignatureMatchesAlgorithm(parsed, AlgRS256) {
		t.Fatal("RSASSA SHA-256 signature did not match RS256")
	}
	pss := testConcat(tpmU16(tpmAlgRSAPSS), tpmU16(tpmAlgSHA256), tpmSizedBytes([]byte{1}))
	parsedPSS, err := parseTPMSignature(pss)
	if err != nil || !tpmSignatureMatchesAlgorithm(parsedPSS, AlgPS256) {
		t.Fatalf("PSS signature = %+v, %v", parsedPSS, err)
	}
	ecdsa384 := testConcat(tpmU16(tpmAlgECDSA), tpmU16(tpmAlgSHA384), tpmSizedBytes([]byte{1}), tpmSizedBytes([]byte{2}))
	parsedECDSA, err := parseTPMSignature(ecdsa384)
	if err != nil || !tpmSignatureMatchesAlgorithm(parsedECDSA, AlgES384) {
		t.Fatalf("ECDSA signature = %+v, %v", parsedECDSA, err)
	}
	emptyECDSA := testConcat(tpmU16(tpmAlgECDSA), tpmU16(tpmAlgSHA256), tpmSizedBytes(nil), tpmSizedBytes(nil))
	if _, err := parseTPMSignature(emptyECDSA); err != nil {
		t.Fatalf("empty ECDSA signature: %v", err)
	}

	if tpmSignatureMatchesAlgorithm(nil, AlgES256) {
		t.Fatal("nil signature matched an algorithm")
	}
	if tpmSignatureMatchesAlgorithm(parsedECDSA, AlgES256) {
		t.Fatal("SHA-384 signature matched ES256")
	}
	if tpmSignatureMatchesAlgorithm(parsed, AlgEdDSA) {
		t.Fatal("RSA signature matched EdDSA")
	}

	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "RSA truncated hash", raw: tpmU16(tpmAlgRSASSA), want: ErrInvalidAttestation},
		{name: "RSA truncated signature", raw: testConcat(tpmU16(tpmAlgRSASSA), tpmU16(tpmAlgSHA256)), want: ErrInvalidAttestation},
		{name: "RSA trailing", raw: append(append([]byte(nil), rsaSignature...), 0), want: ErrInvalidAttestation},
		{name: "ECDSA truncated hash", raw: tpmU16(tpmAlgECDSA), want: ErrInvalidAttestation},
		{name: "ECDSA truncated R", raw: testConcat(tpmU16(tpmAlgECDSA), tpmU16(tpmAlgSHA256)), want: ErrInvalidAttestation},
		{name: "ECDSA truncated S", raw: testConcat(tpmU16(tpmAlgECDSA), tpmU16(tpmAlgSHA256), tpmSizedBytes([]byte{1})), want: ErrInvalidAttestation},
		{name: "ECDSA trailing", raw: append(append([]byte(nil), ecdsa384...), 0), want: ErrInvalidAttestation},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseTPMSignature(test.raw); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestVerifyTPMCertificateBranches covers every AIK certificate profile rule. |
// TestVerifyTPMCertificateBranches 覆盖 AIK 证书配置的每条规则。
func TestVerifyTPMCertificateBranches(t *testing.T) {
	cert := newTPMAttestationCert(t, newECSigner(t))
	if err := verifyTPMCertificate(cert); err != nil {
		t.Fatalf("verifyTPMCertificate: %v", err)
	}

	notV3 := *cert
	notV3.Version = 2
	if err := verifyTPMCertificate(&notV3); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("version 2 error = %v", err)
	}
	isCA := *cert
	isCA.BasicConstraintsValid = true
	isCA.IsCA = true
	if err := verifyTPMCertificate(&isCA); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("CA certificate error = %v", err)
	}
	noEKU := *cert
	noEKU.UnknownExtKeyUsage = nil
	if err := verifyTPMCertificate(&noEKU); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing EKU error = %v", err)
	}
	if err := verifyTPMCertificate(cloneCertificateWithSAN(cert, nil, false)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing SAN error = %v", err)
	}
	if err := verifyTPMCertificate(cloneCertificateWithSAN(cert, []byte{1}, true)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("malformed SAN error = %v", err)
	}

	missingVersion := testTPMSAN(t, pkix.RDNSequence{
		{{Type: tpmManufacturerOID, Value: "id:FFFFF1D0"}},
		{{Type: tpmModelOID, Value: "id:FFFFF1D0"}},
	})
	if err := verifyTPMCertificate(cloneCertificateWithSAN(cert, missingVersion, true)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing version OID error = %v", err)
	}
	wrongVersion := testTPMSAN(t, pkix.RDNSequence{
		{{Type: tpmManufacturerOID, Value: "id:FFFFF1D0"}},
		{{Type: tpmModelOID, Value: "id:FFFFF1D0"}},
		{{Type: tpmVersionOID, Value: "id:OTHER"}},
	})
	if err := verifyTPMCertificate(cloneCertificateWithSAN(cert, wrongVersion, true)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("wrong version value error = %v", err)
	}
	malformedDirectory := marshalDERValue(t, asn1.RawValue{Class: derClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{0x30, 0x80}})
	if err := verifyTPMCertificate(cloneCertificateWithSAN(cert, malformedDirectory, true)); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("malformed directory name error = %v", err)
	}
}

// TestParseDirectoryNameAttributesBranches covers SAN directory parsing. |
// TestParseDirectoryNameAttributesBranches 覆盖 SAN 目录名解析。
func TestParseDirectoryNameAttributesBranches(t *testing.T) {
	valid := testTPMSAN(t, pkix.RDNSequence{
		{{Type: tpmManufacturerOID, Value: "manufacturer"}},
		{{Type: tpmModelOID, Value: []byte("model")}},
		{{Type: tpmVersionOID, Value: 42}},
	})
	attributes, err := parseDirectoryNameAttributes(valid)
	if err != nil {
		t.Fatalf("parseDirectoryNameAttributes: %v", err)
	}
	if attributes[tpmManufacturerOID.String()] != "manufacturer" || attributes[tpmModelOID.String()] != "model" {
		t.Fatalf("attributes = %v", attributes)
	}
	if _, ok := attributes[tpmVersionOID.String()]; ok {
		t.Fatal("non-string version attribute was recorded")
	}

	nonDirectory := marshalDERValue(t, asn1.RawValue{Class: derClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: testDERElement(0x82, []byte("example.com"))})
	if attributes, err := parseDirectoryNameAttributes(nonDirectory); err != nil || len(attributes) != 0 {
		t.Fatalf("non-directory SAN = %v, %v", attributes, err)
	}
	emptyDirectory := marshalDERValue(t, asn1.RawValue{Class: derClassContext, Tag: 4, IsCompound: true, Bytes: []byte{0x30, 0x80}})
	malformedDirectorySAN := marshalDERValue(t, asn1.RawValue{Class: derClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: emptyDirectory})

	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "invalid ASN.1", raw: []byte{0x30, 0x80}},
		{name: "trailing bytes", raw: append(append([]byte(nil), valid...), 0)},
		{name: "not a sequence", raw: testDERInteger([]byte{1})},
		{name: "malformed directory name", raw: malformedDirectorySAN},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDirectoryNameAttributes(test.raw); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}

	if !containsOID([]asn1.ObjectIdentifier{tcgKpAIKCertOID}, tcgKpAIKCertOID) {
		t.Fatal("containsOID missed a present OID")
	}
	if containsOID(nil, tcgKpAIKCertOID) || containsOID([]asn1.ObjectIdentifier{tpmManufacturerOID}, tcgKpAIKCertOID) {
		t.Fatal("containsOID accepted a missing OID")
	}
}
