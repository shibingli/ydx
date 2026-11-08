package webauthn

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"
)

// testAKName returns a syntactically valid SHA-256 Name for activation tests. |
// testAKName 返回激活测试使用的合法 SHA-256 Name。
func testAKName(t *testing.T, seed byte) TPM2BName {
	t.Helper()
	digest := sha256.Sum256([]byte{seed})
	return TPM2BName{Name: append([]byte{0x00, 0x0B}, digest[:]...)}
}

// TestActivationRSARoundTrip checks deterministic credential protection and recovery. |
// TestActivationRSARoundTrip 校验确定性凭据保护与恢复。
func TestActivationRSARoundTrip(t *testing.T) {
	public := testRSAPublic(t)
	key := testRSAKeyPair(t)
	akName := testAKName(t, 1)
	credential := bytes.Repeat([]byte{0x5A}, sha256.Size)
	seed := bytes.Repeat([]byte{0x42}, sha256.Size)

	result, err := MakeCredentialWithSeed(&public, akName, credential, seed)
	if err != nil {
		t.Fatalf("MakeCredentialWithSeed error = %v", err)
	}
	again, err := MakeCredentialWithSeed(&public, akName, credential, seed)
	if err != nil {
		t.Fatalf("second MakeCredentialWithSeed error = %v", err)
	}
	if !bytes.Equal(result.CredentialBlob.Buffer, again.CredentialBlob.Buffer) {
		t.Fatal("credential blob is not deterministic for a fixed seed")
	}
	if len(result.Secret.Buffer) != 256 {
		t.Fatalf("RSA secret is %d bytes, want 256", len(result.Secret.Buffer))
	}
	recovered, err := ActivateCredential(&public, key, akName, result.CredentialBlob, result.Secret)
	if err != nil {
		t.Fatalf("ActivateCredential error = %v", err)
	}
	if !bytes.Equal(recovered, credential) {
		t.Fatalf("recovered credential = %x, want %x", recovered, credential)
	}
	recoveredAgain, err := ActivateCredential(&public, key, akName, again.CredentialBlob, again.Secret)
	if err != nil {
		t.Fatalf("ActivateCredential(second) error = %v", err)
	}
	if !bytes.Equal(recoveredAgain, credential) {
		t.Fatalf("second recovered credential = %x", recoveredAgain)
	}
}

// TestActivationRSAShortCredential checks a credential shorter than the digest. |
// TestActivationRSAShortCredential 校验短于摘要的凭据。
func TestActivationRSAShortCredential(t *testing.T) {
	public := testRSAPublic(t)
	key := testRSAKeyPair(t)
	akName := testAKName(t, 2)
	credential := []byte("short credential")
	seed := make([]byte, sha256.Size)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	result, err := MakeCredentialWithSeed(&public, akName, credential, seed)
	if err != nil {
		t.Fatalf("MakeCredentialWithSeed error = %v", err)
	}
	recovered, err := ActivateCredential(&public, key, akName, result.CredentialBlob, result.Secret)
	if err != nil {
		t.Fatalf("ActivateCredential error = %v", err)
	}
	if !bytes.Equal(recovered, credential) {
		t.Fatalf("recovered credential = %x, want %x", recovered, credential)
	}
}

// TestActivationECC checks ephemeral ECDH credential activation. | TestActivationECC 校验临时 ECDH
// 凭据激活。
func TestActivationECC(t *testing.T) {
	public, private := testECCPublic(t)
	akName := testAKName(t, 3)
	credential := bytes.Repeat([]byte{0xA5}, sha256.Size)

	result, err := MakeCredential(&public, akName, credential)
	if err != nil {
		t.Fatalf("MakeCredential error = %v", err)
	}
	r := &tpm2Reader{data: result.Secret.Buffer}
	point, err := parseTPMSEccPoint(r)
	if err != nil {
		t.Fatalf("secret is not a TPMS_ECC_POINT: %v", err)
	}
	if !r.done() || len(point.X) != 32 || len(point.Y) != 32 {
		t.Fatalf("secret point = %+v", point)
	}
	recovered, err := ActivateCredential(&public, private, akName, result.CredentialBlob, result.Secret)
	if err != nil {
		t.Fatalf("ActivateCredential error = %v", err)
	}
	if !bytes.Equal(recovered, credential) {
		t.Fatalf("recovered credential = %x, want %x", recovered, credential)
	}

	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh.GenerateKey: %v", err)
	}
	if _, err := ActivateCredential(&public, other, akName, result.CredentialBlob, result.Secret); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("wrong ECC private key error = %v, want ErrEKActivation", err)
	}
	if _, err := MakeCredentialWithSeed(&public, akName, credential, make([]byte, sha256.Size)); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("ECC seed error = %v, want ErrEKActivation", err)
	}
}

// TestActivationRejectsTampering checks integrity failures and malformed blobs. |
// TestActivationRejectsTampering 校验完整性失败与非法 blob。
func TestActivationRejectsTampering(t *testing.T) {
	public := testRSAPublic(t)
	key := testRSAKeyPair(t)
	akName := testAKName(t, 4)
	credential := bytes.Repeat([]byte{0x11}, sha256.Size)
	seed := bytes.Repeat([]byte{0x22}, sha256.Size)
	result, err := MakeCredentialWithSeed(&public, akName, credential, seed)
	if err != nil {
		t.Fatalf("MakeCredentialWithSeed error = %v", err)
	}

	tamperedBlob := TPM2BIDObject{Buffer: append([]byte(nil), result.CredentialBlob.Buffer...)}
	tamperedBlob.Buffer[len(tamperedBlob.Buffer)-1] ^= 0x01
	if _, err := ActivateCredential(&public, key, akName, tamperedBlob, result.Secret); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("tampered blob error = %v, want ErrEKActivation", err)
	}

	tamperedSecret := TPM2BEncryptedSecret{Buffer: append([]byte(nil), result.Secret.Buffer...)}
	tamperedSecret.Buffer[0] ^= 0x01
	if _, err := ActivateCredential(&public, key, akName, result.CredentialBlob, tamperedSecret); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("tampered secret error = %v, want ErrEKActivation", err)
	}

	wrongName := testAKName(t, 99)
	if _, err := ActivateCredential(&public, key, wrongName, result.CredentialBlob, result.Secret); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("wrong AK Name error = %v, want ErrEKActivation", err)
	}

	if _, err := ActivateCredential(&public, key, akName, TPM2BIDObject{Buffer: result.CredentialBlob.Buffer[:10]}, result.Secret); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated blob error = %v, want ErrTPMStructure", err)
	}
	if _, err := ActivateCredential(&public, key, akName, result.CredentialBlob, TPM2BEncryptedSecret{}); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("empty secret error = %v, want ErrEKActivation", err)
	}

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	if _, err := ActivateCredential(&public, otherKey, akName, result.CredentialBlob, result.Secret); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("wrong RSA private key error = %v, want ErrEKActivation", err)
	}
}

// TestMakeCredentialValidatesInputs checks EK attributes, credential size and seeds. |
// TestMakeCredentialValidatesInputs 校验 EK 属性、凭据长度与种子。
func TestMakeCredentialValidatesInputs(t *testing.T) {
	public := testRSAPublic(t)
	akName := testAKName(t, 5)
	credential := make([]byte, sha256.Size)
	seed := make([]byte, sha256.Size)

	if _, err := MakeCredentialWithSeed(&public, akName, append(credential, 0), seed); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("oversized credential error = %v, want ErrEKActivation", err)
	}
	if _, err := MakeCredentialWithSeed(&public, akName, credential, make([]byte, sha256.Size-1)); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("short seed error = %v, want ErrEKActivation", err)
	}
	if _, err := MakeCredentialWithSeed(&public, TPM2BName{}, credential, seed); err == nil {
		t.Fatal("invalid AK Name was accepted")
	}
	unrestricted := public
	unrestricted.ObjectAttributes &^= TPMARestricted
	if _, err := MakeCredentialWithSeed(&unrestricted, akName, credential, seed); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("unrestricted EK error = %v, want ErrEKActivation", err)
	}
	if _, err := MakeCredential(nil, akName, credential); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("nil EK error = %v, want ErrTPMStructure", err)
	}
}

// TestVerifyActivationCertInfo checks certInfo binding. | TestVerifyActivationCertInfo 校验 certInfo
// 绑定。
func TestVerifyActivationCertInfo(t *testing.T) {
	akName := testAKName(t, 6)
	credential := []byte("credential-value")
	attest := TPMSAttest{
		Magic:         TPMGeneratedValue,
		Type:          TPMStAttestCertify,
		ExtraData:     credential,
		ClockInfo:     TPMSClockInfo{Safe: 1},
		Name:          akName.Name,
		QualifiedName: akName.Name,
	}
	encoded, err := attest.Marshal()
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if err := VerifyActivationCertInfo(TPM2BAttest{Buffer: encoded}, credential, akName); err != nil {
		t.Fatalf("VerifyActivationCertInfo error = %v", err)
	}
	if err := VerifyActivationCertInfo(TPM2BAttest{Buffer: encoded}, []byte("other"), akName); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("wrong extraData error = %v, want ErrEKActivation", err)
	}
	if err := VerifyActivationCertInfo(TPM2BAttest{Buffer: encoded}, credential, testAKName(t, 7)); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("wrong Name error = %v, want ErrEKActivation", err)
	}
	if err := VerifyActivationCertInfo(TPM2BAttest{Buffer: encoded[:10]}, credential, akName); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated certInfo error = %v, want ErrTPMStructure", err)
	}
}
