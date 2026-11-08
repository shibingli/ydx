package webauthn

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
)

// testRSAKey caches a generated RSA key for structure tests. | testRSAKey 为结构测试缓存生成的 RSA
// 密钥。
var testRSAKey struct {
	once sync.Once
	key  *rsa.PrivateKey
	err  error
}

// testRSAKeyPair returns a shared 2048-bit RSA key. | testRSAKeyPair 返回共享的 2048 位 RSA 密钥。
func testRSAKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAKey.once.Do(func() {
		testRSAKey.key, testRSAKey.err = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testRSAKey.err != nil {
		t.Fatalf("rsa.GenerateKey: %v", testRSAKey.err)
	}
	return testRSAKey.key
}

// testRSAPublic returns a valid restricted-decrypt RSA endorsement public area. |
// testRSAPublic 返回合法的 restricted-decrypt RSA 背书公钥区域。
func testRSAPublic(t *testing.T) TPMTPublic {
	t.Helper()
	key := testRSAKeyPair(t)
	return TPMTPublic{
		Type:             TPMAlgRSA,
		NameAlg:          TPMAlgSHA256,
		ObjectAttributes: TPMAFixedTPM | TPMAFixedParent | TPMASensitiveDataOrigin | TPMAAdminWithPolicy | TPMANoDA | TPMARestricted | TPMADecrypt,
		Symmetric:        TPMSymDefObject{Algorithm: TPMAlgNULL},
		RSAScheme:        TPMTRSAScheme{Scheme: TPMAlgNULL},
		KeyBits:          2048,
		Exponent:         tpmDefaultExponent,
		RSAModulus:       key.N.Bytes(),
	}
}

// testECCPublic returns a valid restricted-decrypt ECC endorsement public area. |
// testECCPublic 返回合法的 restricted-decrypt ECC 背书公钥区域。
func testECCPublic(t *testing.T) (TPMTPublic, *ecdh.PrivateKey) {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey: %v", err)
	}
	point := key.PublicKey().Bytes()
	public := TPMTPublic{
		Type:             TPMAlgECC,
		NameAlg:          TPMAlgSHA256,
		ObjectAttributes: TPMAFixedTPM | TPMAFixedParent | TPMASensitiveDataOrigin | TPMAAdminWithPolicy | TPMANoDA | TPMARestricted | TPMADecrypt,
		Symmetric:        TPMSymDefObject{Algorithm: TPMAlgNULL},
		ECCScheme:        TPMTECCScheme{Scheme: TPMAlgNULL},
		CurveID:          TPMEccNISTP256,
		KDF:              TPMTKDFScheme{Scheme: TPMAlgNULL},
		ECCPoint:         TPMSEccPoint{X: point[1:33], Y: point[33:]},
	}
	return public, key
}

// TestTPMTPublicRSARoundTrip checks RSA public-area marshal and parse symmetry. |
// TestTPMTPublicRSARoundTrip 校验 RSA 公钥区域编码与解析的对称性。
func TestTPMTPublicRSARoundTrip(t *testing.T) {
	public := testRSAPublic(t)
	encoded, err := public.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed, err := ParseTPMTPublic(encoded)
	if err != nil {
		t.Fatalf("ParseTPMTPublic error = %v", err)
	}
	reencoded, err := parsed.Marshal()
	if err != nil {
		t.Fatalf("parsed Marshal error = %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded public area differs:\n got %x\nwant %x", reencoded, encoded)
	}
	key, err := parsed.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey error = %v", err)
	}
	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Fatalf("PublicKey type = %T, want *rsa.PublicKey", key)
	}
	if _, err := ParseTPMTPublic(append(encoded, 0)); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("trailing byte error = %v, want ErrTPMStructure", err)
	}
	if _, err := ParseTPMTPublic(encoded[:len(encoded)-1]); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated public area error = %v, want ErrTPMStructure", err)
	}
}

// TestTPMTPublicECCRoundTrip checks ECC public-area marshal and parse symmetry. |
// TestTPMTPublicECCRoundTrip 校验 ECC 公钥区域编码与解析的对称性。
func TestTPMTPublicECCRoundTrip(t *testing.T) {
	public, _ := testECCPublic(t)
	encoded, err := public.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed, err := ParseTPMTPublic(encoded)
	if err != nil {
		t.Fatalf("ParseTPMTPublic error = %v", err)
	}
	reencoded, err := parsed.Marshal()
	if err != nil {
		t.Fatalf("parsed Marshal error = %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded ECC public area differs:\n got %x\nwant %x", reencoded, encoded)
	}
	other, err := ParseTPMTPublic(append(encoded[:len(encoded)-1], encoded[len(encoded)-1]^0x01))
	if err == nil {
		if _, keyErr := other.PublicKey(); keyErr == nil {
			t.Fatal("off-curve ECC point was accepted")
		}
	}
}

// TestTPMTPublicRejectsInvalidFields checks nested algorithm and key validation. |
// TestTPMTPublicRejectsInvalidFields 校验嵌套算法与密钥校验。
func TestTPMTPublicRejectsInvalidFields(t *testing.T) {
	base := testRSAPublic(t)
	cases := []struct {
		name   string
		modify func(*TPMTPublic)
		want   error
	}{
		{name: "unknown type", modify: func(p *TPMTPublic) { p.Type = 0x9999 }, want: ErrUnsupportedKey},
		{name: "unknown name algorithm", modify: func(p *TPMTPublic) { p.NameAlg = 0x1234 }, want: ErrUnsupportedAlgorithm},
		{name: "null symmetric with keybits", modify: func(p *TPMTPublic) {
			p.Symmetric = TPMSymDefObject{Algorithm: TPMAlgNULL, KeyBits: 128}
		}, want: ErrTPMStructure},
		{name: "zero key bits", modify: func(p *TPMTPublic) { p.KeyBits = 0 }, want: ErrTPMStructure},
		{name: "bad exponent", modify: func(p *TPMTPublic) { p.Exponent = 3 }, want: ErrTPMStructure},
		{name: "empty modulus", modify: func(p *TPMTPublic) { p.RSAModulus = nil }, want: ErrTPMStructure},
		{name: "modulus mismatch", modify: func(p *TPMTPublic) {
			p.RSAModulus = append([]byte(nil), p.RSAModulus...)
			p.RSAModulus[len(p.RSAModulus)-1] ^= 0x01
		}, want: ErrTPMStructure},
	}
	for _, testCase := range cases {
		public := base
		testCase.modify(&public)
		if err := public.Validate(); !errors.Is(err, testCase.want) {
			t.Fatalf("%s Validate error = %v, want %v", testCase.name, err, testCase.want)
		}
	}
}

// TestTPM2BPublicParse checks TPM2B_PUBLIC parsing and Name derivation. | TestTPM2BPublicParse 校验
// TPM2B_PUBLIC 解析与 Name 派生。
func TestTPM2BPublicParse(t *testing.T) {
	public := testRSAPublic(t)
	raw, err := public.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	encoded, err := (TPM2BPublic{Public: public, Raw: raw}).Marshal()
	if err != nil {
		t.Fatalf("TPM2BPublic Marshal error = %v", err)
	}
	parsed, consumed, err := ParseTPM2BPublic(encoded)
	if err != nil {
		t.Fatalf("ParseTPM2BPublic error = %v", err)
	}
	if consumed != len(encoded) {
		t.Fatalf("ParseTPM2BPublic consumed %d of %d", consumed, len(encoded))
	}
	name, err := parsed.Name()
	if err != nil {
		t.Fatalf("Name error = %v", err)
	}
	expected, err := TPMName(raw)
	if err != nil {
		t.Fatalf("TPMName error = %v", err)
	}
	if !bytes.Equal(name, expected) {
		t.Fatalf("Name = %x, want %x", name, expected)
	}
	if _, _, err := ParseTPM2BPublic([]byte{0x00, 0x04, 0x00, 0x23}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated TPM2B_PUBLIC error = %v, want ErrTPMStructure", err)
	}
}

// TestTPMTSensitiveRoundTrip checks TPMT_SENSITIVE marshal and parse. | TestTPMTSensitiveRoundTrip
// 校验 TPMT_SENSITIVE 编码与解析。
func TestTPMTSensitiveRoundTrip(t *testing.T) {
	sensitive := TPMTSensitive{
		Type:      TPMAlgRSA,
		AuthValue: []byte{0x01, 0x02},
		SeedValue: []byte{0x03},
		Sensitive: []byte{0x04, 0x05, 0x06},
	}
	encoded, err := sensitive.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed, err := ParseTPMTSensitive(encoded)
	if err != nil {
		t.Fatalf("ParseTPMTSensitive error = %v", err)
	}
	if parsed.Type != sensitive.Type || !bytes.Equal(parsed.AuthValue, sensitive.AuthValue) ||
		!bytes.Equal(parsed.SeedValue, sensitive.SeedValue) || !bytes.Equal(parsed.Sensitive, sensitive.Sensitive) {
		t.Fatalf("parsed sensitive = %+v", parsed)
	}
	if _, err := ParseTPMTSensitive(encoded[:len(encoded)-1]); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated sensitive error = %v, want ErrTPMStructure", err)
	}
	if _, err := (&TPMTSensitive{Type: TPMAlgRSA}).Marshal(); err == nil {
		t.Fatal("empty RSA sensitive area was accepted")
	}
}

// TestTPMLPCRSelectionRoundTrip checks PCR selection encoding. | TestTPMLPCRSelectionRoundTrip 校验
// PCR 选择编码。
func TestTPMLPCRSelectionRoundTrip(t *testing.T) {
	selection := TPMLPCRSelection{Selections: []TPMSPCRSelection{
		{Hash: TPMAlgSHA256, Select: []byte{0x01, 0x00, 0x00}},
		{Hash: TPMAlgSHA384, Select: []byte{0x02}},
	}}
	encoded, err := selection.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed, consumed, err := ParseTPMLPCRSelection(encoded)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if consumed != len(encoded) || len(parsed.Selections) != 2 ||
		!bytes.Equal(parsed.Selections[0].Select, []byte{0x01, 0x00, 0x00}) ||
		!bytes.Equal(parsed.Selections[1].Select, []byte{0x02}) {
		t.Fatalf("parsed PCR selection = %+v", parsed)
	}
	if _, err := (TPMLPCRSelection{Selections: []TPMSPCRSelection{{Hash: 0x1234}}}).Marshal(); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unknown PCR hash error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestTPMTTicketRoundTrip checks ticket marshal and parse. | TestTPMTTicketRoundTrip 校验票据编码与解析。
func TestTPMTTicketRoundTrip(t *testing.T) {
	ticket := TPMTTicket{Tag: TPMSTHashcheck, Hierarchy: TPMRHOwner, Digest: make([]byte, sha256.Size)}
	encoded, err := ticket.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed, consumed, err := ParseTPMTTicket(encoded)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if consumed != len(encoded) || parsed.Tag != ticket.Tag || parsed.Hierarchy != ticket.Hierarchy {
		t.Fatalf("parsed ticket = %+v", parsed)
	}
	if _, err := (TPMTTicket{Tag: 0x1234}).Marshal(); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("unknown ticket tag error = %v, want ErrTPMStructure", err)
	}
}

// TestTPMSAttestRoundTrip checks certify attestation marshal and parse. | TestTPMSAttestRoundTrip
// 校验证书认证的编码与解析。
func TestTPMSAttestRoundTrip(t *testing.T) {
	name := append([]byte{0x00, 0x0B}, make([]byte, sha256.Size)...)
	attest := TPMSAttest{
		Magic:         TPMGeneratedValue,
		Type:          TPMStAttestCertify,
		ExtraData:     []byte("credential"),
		ClockInfo:     TPMSClockInfo{Clock: 42, ResetCount: 1, RestartCount: 2, Safe: 1},
		Name:          name,
		QualifiedName: name,
	}
	encoded, err := attest.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	parsed, err := ParseTPMSAttest(encoded)
	if err != nil {
		t.Fatalf("ParseTPMSAttest error = %v", err)
	}
	if parsed.ClockInfo != attest.ClockInfo || !bytes.Equal(parsed.ExtraData, attest.ExtraData) ||
		!bytes.Equal(parsed.Name, attest.Name) || !bytes.Equal(parsed.QualifiedName, attest.QualifiedName) {
		t.Fatalf("parsed attest = %+v", parsed)
	}
	bad := attest
	bad.Magic = 0
	if _, err := bad.Marshal(); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("bad magic Marshal error = %v, want ErrTPMStructure", err)
	}
	bad = attest
	bad.Type = 0x8018
	if _, err := bad.Marshal(); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("non-certify Marshal error = %v, want ErrTPMStructure", err)
	}
	if _, err := ParseTPMSAttest(encoded[:len(encoded)-1]); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated attest error = %v, want ErrTPMStructure", err)
	}
}

// TestTPMSymDefObjectEncoding checks the two-byte NULL descriptor. | TestTPMSymDefObjectEncoding 校验
// 两字节 NULL 描述符。
func TestTPMSymDefObjectEncoding(t *testing.T) {
	encoded, err := (TPMSymDefObject{Algorithm: TPMAlgNULL}).Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if !bytes.Equal(encoded, []byte{0x00, 0x10}) {
		t.Fatalf("NULL symmetric = %x, want 0010", encoded)
	}
	if _, err := (TPMSymDefObject{Algorithm: TPMAlgNULL, KeyBits: 128}).Marshal(); err == nil {
		t.Fatal("NULL symmetric with key bits was accepted")
	}
	if _, err := (TPMSymDefObject{Algorithm: TPMAlgAES, KeyBits: 100, Mode: TPMAlgCFB}).Marshal(); err == nil {
		t.Fatal("AES with invalid key size was accepted")
	}
}

// TestTPMHashMapping checks hash identifier mapping. | TestTPMHashMapping 校验哈希标识映射。
func TestTPMHashMapping(t *testing.T) {
	for _, algorithm := range []uint16{TPMAlgSHA256, TPMAlgSHA384, TPMAlgSHA512} {
		hash, ok := TPMHash(algorithm)
		if !ok {
			t.Fatalf("TPMHash(%#04x) not supported", algorithm)
		}
		back, ok := TPMHashAlgorithm(hash)
		if !ok || back != algorithm {
			t.Fatalf("TPMHashAlgorithm(%v) = %#04x, %v", hash, back, ok)
		}
	}
	if _, ok := TPMHash(0x0004); ok {
		t.Fatal("SHA-1 was accepted")
	}
}
