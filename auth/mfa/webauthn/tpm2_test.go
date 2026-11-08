package webauthn

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"testing"
)

// testHex decodes a hexadecimal literal or fails the test. | testHex 解码十六进制字面量或在测试中失败。
func testHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", value, err)
	}
	return decoded
}

// TestKDFaVectors checks KDFa against vectors computed from the TPM 2.0 Part 1 equation. |
// TestKDFaVectors 用根据 TPM 2.0 第一部分公式计算的向量校验 KDFa。
func TestKDFaVectors(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	contextU := []byte("contextU")
	contextV := []byte("contextV")

	got, err := KDFa(crypto.SHA256, key, []byte("STORAGE"), contextU, contextV, 256)
	if err != nil {
		t.Fatalf("KDFa(256) error = %v", err)
	}
	want := testHex(t, "efdaa65b2a9846075704c89a24e2e604abc399a4ab9fb23764ab0d9eeae3de23")
	if !bytes.Equal(got, want) {
		t.Fatalf("KDFa(256) = %x, want %x", got, want)
	}

	got, err = KDFa(crypto.SHA256, key, []byte("STORAGE"), contextU, contextV, 512)
	if err != nil {
		t.Fatalf("KDFa(512) error = %v", err)
	}
	want = testHex(t, "8790de9f471d09e3d050f5811885786bad95d133dc15791530a739f175b8d62a"+
		"a7bc1f4b4baa048979ccc33d55c54c319ee87458e2638079eb78c6cde81589b6")
	if !bytes.Equal(got, want) {
		t.Fatalf("KDFa(512) = %x, want %x", got, want)
	}

	got, err = KDFa(crypto.SHA256, key, []byte("STORAGE"), contextU, contextV, 12)
	if err != nil {
		t.Fatalf("KDFa(12) error = %v", err)
	}
	if !bytes.Equal(got, testHex(t, "57b7")) {
		t.Fatalf("KDFa(12) = %x, want 57b7", got)
	}
}

// TestKDFeVector checks the plain-hash KDFe layout. | TestKDFeVector 校验普通哈希 KDFe 布局。
func TestKDFeVector(t *testing.T) {
	z := make([]byte, 32)
	for index := range z {
		z[index] = byte(index + 32)
	}
	got, err := KDFe(crypto.SHA256, z, []byte("IDENTITY"), []byte("partyU"), []byte("partyV"), 256)
	if err != nil {
		t.Fatalf("KDFe error = %v", err)
	}
	want := testHex(t, "5aece828fff2ab496c3553530226b3e13815d7a3a1b928692acf780144e19291")
	if !bytes.Equal(got, want) {
		t.Fatalf("KDFe = %x, want %x", got, want)
	}
}

// TestKDFRejectsUnsupportedInputs checks output-size, hash and label bounds. |
// TestKDFRejectsUnsupportedInputs 校验输出长度、哈希与标签边界。
func TestKDFRejectsUnsupportedInputs(t *testing.T) {
	if _, err := KDFa(crypto.SHA1, []byte("key"), []byte("label"), nil, nil, 128); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("SHA-1 KDFa error = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := KDFa(crypto.SHA256, nil, []byte("label"), nil, nil, 7); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("7-bit KDFa error = %v, want ErrInvalidConfig", err)
	}
	if _, err := KDFe(crypto.SHA256, nil, bytes.Repeat([]byte("a"), 65), nil, nil, 128); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("65-byte label KDFe error = %v, want ErrInvalidConfig", err)
	}
}

// TestTPM2BRoundTrip checks TPM2B encoding and parsing boundaries. | TestTPM2BRoundTrip 校验 TPM2B
// 编码与解析边界。
func TestTPM2BRoundTrip(t *testing.T) {
	original := TPM2B{Buffer: []byte{0x01, 0x02, 0x03}}
	encoded, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if want := []byte{0x00, 0x03, 0x01, 0x02, 0x03}; !bytes.Equal(encoded, want) {
		t.Fatalf("Marshal = %x, want %x", encoded, want)
	}
	parsed, consumed, err := ParseTPM2B(encoded)
	if err != nil {
		t.Fatalf("ParseTPM2B error = %v", err)
	}
	if consumed != len(encoded) || !bytes.Equal(parsed.Buffer, original.Buffer) {
		t.Fatalf("ParseTPM2B = %x consumed %d", parsed.Buffer, consumed)
	}
	if _, _, err := ParseTPM2B([]byte{0x00, 0x04, 0x01}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated TPM2B error = %v, want ErrTPMStructure", err)
	}
	if _, err := (TPM2B{Buffer: make([]byte, MaxTPM2BUFFERSize+1)}).Marshal(); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("oversized TPM2B error = %v, want ErrTPMStructure", err)
	}
}

// TestTPM2BNameValidation checks Name length and algorithm validation. | TestTPM2BNameValidation 校验
// Name 长度与算法校验。
func TestTPM2BNameValidation(t *testing.T) {
	valid := TPM2BName{Name: append([]byte{0x00, 0x0B}, make([]byte, 32)...)}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid Name error = %v", err)
	}
	if _, err := valid.Marshal(); err != nil {
		t.Fatalf("valid Name Marshal error = %v", err)
	}
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "empty", raw: nil, want: ErrTPMStructure},
		{name: "short digest", raw: append([]byte{0x00, 0x0B}, make([]byte, 31)...), want: ErrTPMStructure},
		{name: "unknown algorithm", raw: append([]byte{0x12, 0x34}, make([]byte, 32)...), want: ErrUnsupportedAlgorithm},
	}
	for _, testCase := range cases {
		if err := (TPM2BName{Name: testCase.raw}).Validate(); !errors.Is(err, testCase.want) {
			t.Fatalf("%s Name error = %v, want %v", testCase.name, err, testCase.want)
		}
	}
}

// TestTPMNameBindsPublicArea checks that the Name covers the exact public area bytes. |
// TestTPMNameBindsPublicArea 校验 Name 覆盖精确公钥区域字节。
func TestTPMNameBindsPublicArea(t *testing.T) {
	public := testRSAPublic(t)
	raw, err := public.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	name, err := TPMName(raw)
	if err != nil {
		t.Fatalf("TPMName error = %v", err)
	}
	if len(name) != 2+32 || name[0] != 0x00 || name[1] != 0x0B {
		t.Fatalf("Name = %x, want SHA-256 algorithm prefix", name)
	}
	altered := append([]byte(nil), raw...)
	altered[len(altered)-2] ^= 0xFF
	otherName, err := TPMName(altered)
	if err != nil {
		t.Fatalf("TPMName(altered) error = %v", err)
	}
	if bytes.Equal(name, otherName) {
		t.Fatal("Name does not bind the public area")
	}
	if _, err := TPMName(raw[:len(raw)-1]); err == nil {
		t.Fatal("TPMName accepted a truncated public area")
	}
}
