package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// ekActivationFixture holds a simulated TPM and its endorsement-key certificate chain. |
// ekActivationFixture 保存模拟 TPM 及其背书密钥证书链。
type ekActivationFixture struct {
	tpm      *softwareTPM
	ekPublic TPMTPublic
	ekRaw    []byte
	akRaw    []byte
	leaf     *x509.Certificate
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	chain    [][]byte
	roots    *x509.CertPool
	aaguid   [16]byte
}

// newEKActivationFixture builds a simulated TPM and a vendor-signed EK certificate. |
// newEKActivationFixture 构建模拟 TPM 与厂商签发的 EK 证书。
func newEKActivationFixture(t *testing.T, ekType uint16) *ekActivationFixture {
	t.Helper()
	tpm, err := newSoftwareTPM(ekType)
	if err != nil {
		t.Fatalf("newSoftwareTPM: %v", err)
	}
	ekPublic := tpm.EKPublic()
	ekRaw, err := ekPublic.Marshal()
	if err != nil {
		t.Fatalf("marshal EK public area: %v", err)
	}
	akPublic := tpm.AKPublic()
	akRaw, err := akPublic.Marshal()
	if err != nil {
		t.Fatalf("marshal AK public area: %v", err)
	}
	ekKey, err := ekPublic.PublicKey()
	if err != nil {
		t.Fatalf("EK public key: %v", err)
	}
	root, rootKey := newTestRootCA(t, "YDX Test EK Root", 901)
	leaf := newEKTestCertificate(t, ekKey, root, rootKey, testNow.Add(-time.Hour), testNow.Add(time.Hour),
		false, []asn1.ObjectIdentifier{tcgKpEKCertOID}, "id:FFFFF1D0")
	return &ekActivationFixture{
		tpm:      tpm,
		ekPublic: ekPublic,
		ekRaw:    ekRaw,
		akRaw:    akRaw,
		leaf:     leaf,
		root:     root,
		rootKey:  rootKey,
		chain:    [][]byte{leaf.Raw},
		roots:    certificateRoots(root),
		aaguid:   [16]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xb3, 0xb4, 0xc1, 0xc2, 0xc3, 0xc4, 0xd1, 0xd2, 0xd3, 0xd4},
	}
}

// newEKTestCertificate creates an EK leaf certificate for publicKey. | newEKTestCertificate 为 publicKey
// 创建 EK 叶证书。
func newEKTestCertificate(t *testing.T, publicKey any, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time, isCA bool, ekus []asn1.ObjectIdentifier, manufacturer string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(902),
		Subject:               pkix.Name{CommonName: "YDX Test EK"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		UnknownExtKeyUsage:    ekus,
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}
	if manufacturer != "" {
		template.ExtraExtensions = append(template.ExtraExtensions, ekManufacturerSAN(t, manufacturer))
	}
	return newSignedTestCert(t, template, publicKey, parent, parentKey)
}

// ekManufacturerSAN encodes a TCG manufacturer directoryName in subjectAltName. |
// ekManufacturerSAN 在 subjectAltName 中编码 TCG 制造商 directoryName。
func ekManufacturerSAN(t *testing.T, manufacturer string) pkix.Extension {
	t.Helper()
	rdns, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: tpmManufacturerOID, Value: manufacturer}},
	})
	if err != nil {
		t.Fatalf("marshal manufacturer RDN: %v", err)
	}
	directoryName := marshalDERValue(t, asn1.RawValue{Class: derClassContext, Tag: 4, IsCompound: true, Bytes: rdns})
	san := marshalDERValue(t, asn1.RawValue{Class: derClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: directoryName})
	return pkix.Extension{Id: subjectAltNameOID, Value: san}
}

// newTPMEKService builds a Service with an EK activation policy. | newTPMEKService 构建带 EK 激活策略的
// Service。
func (f *ekActivationFixture) newTPMEKService(t *testing.T, activation *TPMEKActivationConfig, mutate func(*Config)) *Service {
	t.Helper()
	return newTestService(t, func(config *Config) {
		if activation == nil {
			activation = &TPMEKActivationConfig{EKRoots: f.roots}
		}
		config.TPMEKActivation = activation
		if mutate != nil {
			mutate(config)
		}
	})
}

// startChallenge begins an activation for the fixture. | startChallenge 为夹具启动激活。
func (f *ekActivationFixture) startChallenge(t *testing.T, service *Service, aaguid [16]byte, userID string) *TPMEKActivationChallenge {
	t.Helper()
	challenge, err := service.BeginTPMEKActivation(context.Background(), &TPMEKActivationRequest{
		EKCertificates: f.chain,
		EKPublic:       f.ekRaw,
		AKPublic:       f.akRaw,
		AAGUID:         aaguid,
		UserID:         userID,
	})
	if err != nil {
		t.Fatalf("BeginTPMEKActivation: %v", err)
	}
	return challenge
}

// activate runs TPM2_ActivateCredential on the simulated TPM and returns the TPM2B_ATTEST. |
// activate 在模拟 TPM 上运行 TPM2_ActivateCredential 并返回 TPM2B_ATTEST。
func (f *ekActivationFixture) activate(t *testing.T, challenge *TPMEKActivationChallenge) []byte {
	t.Helper()
	attest, err := ActivateCredentialCommand(context.Background(), f.tpm, f.tpm.AKHandle(), f.tpm.EKHandle(),
		TPM2BIDObject{Buffer: challenge.CredentialBlob},
		TPM2BEncryptedSecret{Buffer: challenge.EncryptedSecret})
	if err != nil {
		t.Fatalf("ActivateCredentialCommand: %v", err)
	}
	return append([]byte(nil), attest.Buffer...)
}

// statelessVerification builds a complete activation verification value. |
// statelessVerification 构建完整的激活校验值。
func (f *ekActivationFixture) statelessVerification(t *testing.T, credential []byte) *TPMEKActivationVerification {
	t.Helper()
	made, err := MakeCredential(&f.ekPublic, f.tpm.AKName(), credential)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	attest, err := ActivateCredentialCommand(context.Background(), f.tpm, f.tpm.AKHandle(), f.tpm.EKHandle(),
		made.CredentialBlob, made.Secret)
	if err != nil {
		t.Fatalf("ActivateCredentialCommand: %v", err)
	}
	return &TPMEKActivationVerification{
		EKCertificates:  cloneByteSlices(f.chain),
		EKPublic:        append([]byte(nil), f.ekRaw...),
		AKPublic:        append([]byte(nil), f.akRaw...),
		AAGUID:          f.aaguid,
		Credential:      append([]byte(nil), credential...),
		CredentialBlob:  append([]byte(nil), made.CredentialBlob.Buffer...),
		EncryptedSecret: append([]byte(nil), made.Secret.Buffer...),
		CertInfo:        append([]byte(nil), attest.Buffer...),
		Now:             testNow,
	}
}

// TestTPMEKActivationEndToEnd covers RSA and ECC activation through the Service. |
// TestTPMEKActivationEndToEnd 覆盖通过 Service 的 RSA 与 ECC 激活。
func TestTPMEKActivationEndToEnd(t *testing.T) {
	for _, ekType := range []uint16{TPMAlgRSA, TPMAlgECC} {
		name := "rsa"
		if ekType == TPMAlgECC {
			name = "ecc"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newEKActivationFixture(t, ekType)
			service := fixture.newTPMEKService(t, nil, nil)
			challenge := fixture.startChallenge(t, service, fixture.aaguid, "")
			if challenge.ID == "" || len(challenge.CredentialBlob) == 0 || len(challenge.EncryptedSecret) == 0 {
				t.Fatalf("challenge = %#v", challenge)
			}
			if !challenge.ExpiresAt.After(testNow) {
				t.Fatalf("challenge expiry = %s", challenge.ExpiresAt)
			}
			certInfo := fixture.activate(t, challenge)
			result, err := service.FinishTPMEKActivation(context.Background(), challenge.ID, certInfo)
			if err != nil {
				t.Fatalf("FinishTPMEKActivation: %v", err)
			}
			if !result.TrustVerified || result.AAGUID != fixture.aaguid {
				t.Fatalf("result = %#v", result)
			}
			if !constantTimeEqual(result.AKName.Name, fixture.tpm.AKName().Name) {
				t.Fatalf("AK Name = %x, want %x", result.AKName.Name, fixture.tpm.AKName().Name)
			}
			if len(result.EKCertificates) != 1 || !result.EKCertificates[0].Equal(fixture.leaf) {
				t.Fatalf("EK certificates = %#v", result.EKCertificates)
			}
			if _, err := service.FinishTPMEKActivation(context.Background(), challenge.ID, certInfo); !errors.Is(err, ErrEKActivation) {
				t.Fatalf("replayed challenge error = %v, want ErrEKActivation", err)
			}
			standalone, err := VerifyEKActivation(context.Background(), fixture.statelessVerification(t, make([]byte, 32)), &TPMEKActivationConfig{EKRoots: fixture.roots})
			if err != nil {
				t.Fatalf("VerifyEKActivation: %v", err)
			}
			if !standalone.TrustVerified {
				t.Fatal("standalone activation was not trusted")
			}
		})
	}
}

// TestVerifyEKActivationRejectsInvalidEvidence covers tampered credential, key and structure inputs. |
// TestVerifyEKActivationRejectsInvalidEvidence 覆盖被篡改的凭据、密钥与结构输入。
func TestVerifyEKActivationRejectsInvalidEvidence(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	policy := &TPMEKActivationConfig{EKRoots: fixture.roots}
	valid := fixture.statelessVerification(t, make([]byte, 32))
	if _, err := VerifyEKActivation(context.Background(), valid, policy); err != nil {
		t.Fatalf("valid verification: %v", err)
	}
	clone := func() *TPMEKActivationVerification {
		copied := *valid
		copied.EKCertificates = cloneByteSlices(valid.EKCertificates)
		copied.EKPublic = append([]byte(nil), valid.EKPublic...)
		copied.AKPublic = append([]byte(nil), valid.AKPublic...)
		copied.Credential = append([]byte(nil), valid.Credential...)
		copied.CredentialBlob = append([]byte(nil), valid.CredentialBlob...)
		copied.EncryptedSecret = append([]byte(nil), valid.EncryptedSecret...)
		copied.CertInfo = append([]byte(nil), valid.CertInfo...)
		return &copied
	}

	if _, err := VerifyEKActivation(context.Background(), nil, policy); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("nil verification error = %v, want ErrEKActivation", err)
	}

	wrongCredential := clone()
	wrongCredential.Credential = make([]byte, 32)
	wrongCredential.Credential[0] = 0xa5
	if _, err := VerifyEKActivation(context.Background(), wrongCredential, policy); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("wrong credential error = %v, want ErrEKActivation", err)
	}

	oversizedCredential := clone()
	oversizedCredential.Credential = make([]byte, maxTPMEKActivationCredential+1)
	if _, err := VerifyEKActivation(context.Background(), oversizedCredential, policy); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("oversized credential error = %v, want ErrEKActivation", err)
	}

	truncatedBlob := clone()
	truncatedBlob.CredentialBlob = truncatedBlob.CredentialBlob[:len(truncatedBlob.CredentialBlob)-1]
	if _, err := VerifyEKActivation(context.Background(), truncatedBlob, policy); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated blob error = %v, want ErrTPMStructure", err)
	}

	oversizedBlob := clone()
	oversizedBlob.CredentialBlob = append(oversizedBlob.CredentialBlob, 0)
	if _, err := VerifyEKActivation(context.Background(), oversizedBlob, policy); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("oversized blob error = %v, want ErrTPMStructure", err)
	}

	wrongSecret := clone()
	wrongSecret.EncryptedSecret = append(wrongSecret.EncryptedSecret, 0)
	if _, err := VerifyEKActivation(context.Background(), wrongSecret, policy); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("wrong encrypted secret error = %v, want ErrEKActivation", err)
	}

	truncatedCertInfo := clone()
	truncatedCertInfo.CertInfo = truncatedCertInfo.CertInfo[:len(truncatedCertInfo.CertInfo)-1]
	if _, err := VerifyEKActivation(context.Background(), truncatedCertInfo, policy); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("truncated certInfo error = %v, want ErrTPMStructure", err)
	}

	truncatedEK := clone()
	truncatedEK.EKPublic = truncatedEK.EKPublic[:10]
	if _, err := VerifyEKActivation(context.Background(), truncatedEK, policy); err == nil {
		t.Fatal("truncated EK public area was accepted")
	}

	truncatedAK := clone()
	truncatedAK.AKPublic = truncatedAK.AKPublic[:10]
	if _, err := VerifyEKActivation(context.Background(), truncatedAK, policy); err == nil {
		t.Fatal("truncated AK public area was accepted")
	}

	missingAK := clone()
	missingAK.AKPublic = nil
	if _, err := VerifyEKActivation(context.Background(), missingAK, policy); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("missing AK public area error = %v, want ErrTPMStructure", err)
	}

	emptyChain := clone()
	emptyChain.EKCertificates = nil
	if _, err := VerifyEKActivation(context.Background(), emptyChain, policy); !errors.Is(err, ErrEKCertificate) {
		t.Fatalf("empty chain error = %v, want ErrEKCertificate", err)
	}

	tooManyCerts := clone()
	for len(tooManyCerts.EKCertificates) <= maxAttestationCertificates {
		tooManyCerts.EKCertificates = append(tooManyCerts.EKCertificates, fixture.leaf.Raw)
	}
	if _, err := VerifyEKActivation(context.Background(), tooManyCerts, policy); !errors.Is(err, ErrEKCertificate) {
		t.Fatalf("oversized chain error = %v, want ErrEKCertificate", err)
	}

	if _, err := VerifyEKActivation(context.Background(), valid, &TPMEKActivationConfig{EKRoots: fixture.roots, AllowedAAGUIDs: [][16]byte{{0xff}}}); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("AAGUID allowlist error = %v, want ErrEKActivation", err)
	}
}

// TestTPMEKCertificateProfile covers EK certificate profile and trust-chain rejection. |
// TestTPMEKCertificateProfile 覆盖 EK 证书配置与信任链拒绝。
func TestTPMEKCertificateProfile(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	valid := fixture.statelessVerification(t, make([]byte, 32))
	ekKey, err := fixture.ekPublic.PublicKey()
	if err != nil {
		t.Fatalf("EK public key: %v", err)
	}
	ekus := []asn1.ObjectIdentifier{tcgKpEKCertOID}

	cases := []struct {
		name string
		leaf *x509.Certificate
	}{
		{name: "expired", leaf: newEKTestCertificate(t, ekKey, fixture.root, fixture.rootKey, testNow.Add(-2*time.Hour), testNow.Add(-time.Hour), false, ekus, "")},
		{name: "ca", leaf: newEKTestCertificate(t, ekKey, fixture.root, fixture.rootKey, testNow.Add(-time.Hour), testNow.Add(time.Hour), true, ekus, "")},
		{name: "wrong EKU", leaf: newEKTestCertificate(t, ekKey, fixture.root, fixture.rootKey, testNow.Add(-time.Hour), testNow.Add(time.Hour), false, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, "")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			verification := *valid
			verification.EKCertificates = [][]byte{test.leaf.Raw}
			if _, err := VerifyEKActivation(context.Background(), &verification, &TPMEKActivationConfig{EKRoots: fixture.roots}); !errors.Is(err, ErrEKCertificate) {
				t.Fatalf("error = %v, want ErrEKCertificate", err)
			}
		})
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	mismatched := newEKTestCertificate(t, &otherKey.PublicKey, fixture.root, fixture.rootKey, testNow.Add(-time.Hour), testNow.Add(time.Hour), false, ekus, "")
	verification := *valid
	verification.EKCertificates = [][]byte{mismatched.Raw}
	if _, err := VerifyEKActivation(context.Background(), &verification, &TPMEKActivationConfig{EKRoots: fixture.roots}); !errors.Is(err, ErrEKCertificate) {
		t.Fatalf("key mismatch error = %v, want ErrEKCertificate", err)
	}

	otherRoot, _ := newTestRootCA(t, "Unrelated EK Root", 903)
	verification = *valid
	if _, err := VerifyEKActivation(context.Background(), &verification, &TPMEKActivationConfig{EKRoots: certificateRoots(otherRoot)}); !errors.Is(err, ErrEKCertificate) {
		t.Fatalf("wrong root error = %v, want ErrEKCertificate", err)
	}

	result, err := VerifyEKActivation(context.Background(), &verification, &TPMEKActivationConfig{})
	if err != nil {
		t.Fatalf("untrusted activation: %v", err)
	}
	if result.TrustVerified {
		t.Fatal("activation without roots reported a trusted chain")
	}

	if _, err := VerifyEKActivation(context.Background(), &verification, &TPMEKActivationConfig{RequireTrustedEKChain: true}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("required trust without roots error = %v, want ErrInvalidConfig", err)
	}
}

// TestTPMEKActivationConfigValidation covers Service configuration errors. |
// TestTPMEKActivationConfigValidation 覆盖 Service 配置错误。
func TestTPMEKActivationConfigValidation(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	cases := []struct {
		name   string
		config *TPMEKActivationConfig
	}{
		{name: "negative TTL", config: &TPMEKActivationConfig{ChallengeTTL: -time.Second}},
		{name: "negative pending", config: &TPMEKActivationConfig{MaxPendingChallenges: -1}},
		{name: "small RSA", config: &TPMEKActivationConfig{MinEKKeyBits: 1024}},
		{name: "trusted without roots", config: &TPMEKActivationConfig{RequireTrustedEKChain: true}},
		{name: "empty manufacturer", config: &TPMEKActivationConfig{AllowedEKManufacturers: []string{"  "}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(Config{
				RPDisplayName:   "Example RP",
				RPID:            testRPID,
				RPOrigins:       []string{testOrigin},
				Clock:           func() time.Time { return testNow },
				TPMEKActivation: test.config,
			})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	service := newTestService(t, nil)
	if _, err := service.BeginTPMEKActivation(context.Background(), &TPMEKActivationRequest{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unconfigured Begin error = %v, want ErrInvalidConfig", err)
	}
	if _, err := service.FinishTPMEKActivation(context.Background(), "id", nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unconfigured Finish error = %v, want ErrInvalidConfig", err)
	}

	configured := fixture.newTPMEKService(t, &TPMEKActivationConfig{
		EKRoots:        fixture.roots,
		AllowedAAGUIDs: [][16]byte{fixture.aaguid},
	}, nil)
	if _, err := configured.BeginTPMEKActivation(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil request error = %v, want ErrInvalidRequest", err)
	}
	if _, err := configured.BeginTPMEKActivation(context.Background(), &TPMEKActivationRequest{
		EKCertificates: fixture.chain,
		EKPublic:       fixture.ekRaw,
		AKPublic:       fixture.akRaw,
		AAGUID:         [16]byte{0xff},
	}); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("disallowed AAGUID error = %v, want ErrEKActivation", err)
	}
}

// TestTPMEKActivationExpiryAndCapacity covers challenge expiry and bounded eviction. |
// TestTPMEKActivationExpiryAndCapacity 覆盖挑战过期与有界淘汰。
func TestTPMEKActivationExpiryAndCapacity(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgECC)
	current := testNow
	service := newTestService(t, func(config *Config) {
		config.Clock = func() time.Time { return current }
		config.TPMEKActivation = &TPMEKActivationConfig{
			EKRoots:              fixture.roots,
			ChallengeTTL:         time.Minute,
			MaxPendingChallenges: 1,
		}
	})
	first := fixture.startChallenge(t, service, fixture.aaguid, "")
	current = testNow.Add(2 * time.Minute)
	second := fixture.startChallenge(t, service, fixture.aaguid, "")
	if _, err := service.FinishTPMEKActivation(context.Background(), first.ID, fixture.activate(t, first)); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("evicted challenge error = %v, want ErrEKActivation", err)
	}
	current = testNow
	result, err := service.FinishTPMEKActivation(context.Background(), second.ID, fixture.activate(t, second))
	if err != nil {
		t.Fatalf("Finish after eviction: %v", err)
	}
	if result.AAGUID != fixture.aaguid {
		t.Fatalf("result AAGUID = %x", result.AAGUID)
	}

	current = testNow
	expiring := fixture.startChallenge(t, service, fixture.aaguid, "")
	current = testNow.Add(2 * time.Minute)
	if _, err := service.FinishTPMEKActivation(context.Background(), expiring.ID, fixture.activate(t, expiring)); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("expired challenge error = %v, want ErrEKActivation", err)
	}
}

// TestTPMEKActivationCancellation covers context cancellation before challenge issuance and consumption.
// | TestTPMEKActivationCancellation 覆盖挑战签发与消费前的上下文取消。
func TestTPMEKActivationCancellation(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	service := fixture.newTPMEKService(t, nil, nil)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.BeginTPMEKActivation(canceled, &TPMEKActivationRequest{
		EKCertificates: fixture.chain,
		EKPublic:       fixture.ekRaw,
		AKPublic:       fixture.akRaw,
		AAGUID:         fixture.aaguid,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Begin error = %v, want context.Canceled", err)
	}
	challenge := fixture.startChallenge(t, service, fixture.aaguid, "")
	if _, err := service.FinishTPMEKActivation(canceled, challenge.ID, fixture.activate(t, challenge)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Finish error = %v, want context.Canceled", err)
	}
	if _, err := service.FinishTPMEKActivation(context.Background(), challenge.ID, fixture.activate(t, challenge)); err != nil {
		t.Fatalf("Finish after canceled attempt: %v", err)
	}
}

// TestTPMEKActivationCustomVerifier checks custom verifier ordering and failure propagation. |
// TestTPMEKActivationCustomVerifier 校验自定义校验器顺序与失败传播。
func TestTPMEKActivationCustomVerifier(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	sentinel := errors.New("custom EK policy rejected")
	called := false
	service := fixture.newTPMEKService(t, &TPMEKActivationConfig{
		EKRoots: fixture.roots,
		Verifier: TPMEKActivationVerifierFunc(func(context.Context, TPMEKActivationVerification, TPMEKActivationResult) error {
			called = true
			return sentinel
		}),
	}, nil)
	challenge := fixture.startChallenge(t, service, fixture.aaguid, "")
	if _, err := service.FinishTPMEKActivation(context.Background(), challenge.ID, fixture.activate(t, challenge)); !errors.Is(err, sentinel) || !errors.Is(err, ErrEKActivation) {
		t.Fatalf("custom verifier error = %v, want sentinel and ErrEKActivation", err)
	}
	if !called {
		t.Fatal("custom verifier was not called")
	}

	called = false
	strict := fixture.newTPMEKService(t, &TPMEKActivationConfig{
		EKRoots:      fixture.roots,
		MinEKKeyBits: 4096,
		Verifier: TPMEKActivationVerifierFunc(func(context.Context, TPMEKActivationVerification, TPMEKActivationResult) error {
			called = true
			return nil
		}),
	}, nil)
	if _, err := strict.BeginTPMEKActivation(context.Background(), &TPMEKActivationRequest{
		EKCertificates: fixture.chain,
		EKPublic:       fixture.ekRaw,
		AKPublic:       fixture.akRaw,
		AAGUID:         fixture.aaguid,
	}); !errors.Is(err, ErrEKCertificate) {
		t.Fatalf("strict key size error = %v, want ErrEKCertificate", err)
	}
	if called {
		t.Fatal("custom verifier ran before built-in key checks")
	}
}

// tpmRegistrationFixture builds a tpm attestation response for a simulator AK. |
// tpmRegistrationFixture 为模拟 AK 构建 tpm 认证声明响应。
func (f *ekActivationFixture) tpmRegistrationFixture(t *testing.T, credentialSigner *ecSigner) (*registrationFixture, *x509.Certificate) {
	t.Helper()
	akSigner, ok := f.tpm.AKSigner().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("simulator AK signer is not ECDSA")
	}
	aik := &ecSigner{key: akSigner}
	aikCert := newTPMAttestationCert(t, aik)
	pubArea := tpmECCPubArea(t, credentialSigner)
	fixture := &registrationFixture{
		signer: credentialSigner,
		credID: []byte("tpm-credential-id"),
		flags:  FlagUserPresent | FlagAttestedCredentialData,
		format: FormatTPM,
		statement: func(t *testing.T, authData, clientDataHash []byte) []Pair {
			t.Helper()
			extraData := sha256.Sum256(signedAttestationData(authData, clientDataHash))
			certInfo := tpmCertInfo(t, pubArea, extraData[:])
			return []Pair{
				{Key: NewText("ver"), Value: NewText("2.0")},
				{Key: NewText("alg"), Value: NewInt(AlgES256)},
				{Key: NewText("sig"), Value: NewBytes(tpmECDSASignature(t, aik, certInfo))},
				{Key: NewText("certInfo"), Value: NewBytes(certInfo)},
				{Key: NewText("pubArea"), Value: NewBytes(pubArea)},
				{Key: NewText("x5c"), Value: NewArray(NewBytes(aikCert.Raw))},
			}
		},
	}
	return fixture, aikCert
}

// TestTPMEKActivationRegistration covers registration evidence binding and policy. |
// TestTPMEKActivationRegistration 覆盖注册证据绑定与策略。
func TestTPMEKActivationRegistration(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	credentialSigner := newECSigner(t)
	registration, aikCert := fixture.tpmRegistrationFixture(t, credentialSigner)
	user := testUser()
	activationAAGUID := [16]byte{1, 2, 3, 4}

	service := fixture.newTPMEKService(t, &TPMEKActivationConfig{
		EKRoots:                   fixture.roots,
		RequiredForTPMAttestation: true,
	}, func(config *Config) {
		config.AttestationRoots = certificateRoots(aikCert)
	})
	options, ceremony, err := service.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	challenge := fixture.startChallenge(t, service, activationAAGUID, user.ID)
	certInfo := fixture.activate(t, challenge)
	response := registration.creationResponse(t, options)
	response.TPMEKActivation = &TPMEKActivationEvidence{ChallengeID: challenge.ID, CertInfo: b64(certInfo)}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); err != nil {
		t.Fatalf("FinishRegistration with activation: %v", err)
	}

	options, ceremony, err = service.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	registration.credID = []byte("tpm-missing-evidence")
	missing := registration.creationResponse(t, options)
	if _, err := service.FinishRegistration(context.Background(), ceremony, missing); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("missing evidence error = %v, want ErrEKActivation", err)
	}

	options, ceremony, err = service.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	wrongAAGUID := fixture.startChallenge(t, service, [16]byte{9, 9, 9, 9}, user.ID)
	registration.credID = []byte("tpm-aaguid-mismatch")
	response = registration.creationResponse(t, options)
	response.TPMEKActivation = &TPMEKActivationEvidence{ChallengeID: wrongAAGUID.ID, CertInfo: b64(fixture.activate(t, wrongAAGUID))}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("AAGUID mismatch error = %v, want ErrEKActivation", err)
	}

	other := newEKActivationFixture(t, TPMAlgECC)
	combined := x509.NewCertPool()
	combined.AddCert(fixture.root)
	combined.AddCert(other.root)
	service.tpmEKActivation.EKRoots = combined
	options, ceremony, err = service.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	otherChallenge := other.startChallenge(t, service, activationAAGUID, user.ID)
	registration.credID = []byte("tpm-ak-mismatch")
	response = registration.creationResponse(t, options)
	response.TPMEKActivation = &TPMEKActivationEvidence{ChallengeID: otherChallenge.ID, CertInfo: b64(other.activate(t, otherChallenge))}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("AK mismatch error = %v, want ErrEKActivation", err)
	}

	rejecting := fixture.newTPMEKService(t, &TPMEKActivationConfig{
		EKRoots: fixture.roots,
		Verifier: TPMEKActivationVerifierFunc(func(context.Context, TPMEKActivationVerification, TPMEKActivationResult) error {
			return errors.New("registration EK policy rejected")
		}),
	}, func(config *Config) {
		config.AttestationRoots = certificateRoots(aikCert)
	})
	options, ceremony, err = rejecting.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	rejectedChallenge := fixture.startChallenge(t, rejecting, activationAAGUID, user.ID)
	registration.credID = []byte("tpm-custom-verifier")
	response = registration.creationResponse(t, options)
	response.TPMEKActivation = &TPMEKActivationEvidence{ChallengeID: rejectedChallenge.ID, CertInfo: b64(fixture.activate(t, rejectedChallenge))}
	if _, err := rejecting.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("custom verifier bypass error = %v, want ErrEKActivation", err)
	}

	nonTPM := defaultRegistrationFixture(t, credentialSigner)
	options, ceremony, err = service.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	nonTPMChallenge := fixture.startChallenge(t, service, activationAAGUID, user.ID)
	response = nonTPM.creationResponse(t, options)
	response.TPMEKActivation = &TPMEKActivationEvidence{ChallengeID: nonTPMChallenge.ID, CertInfo: b64(fixture.activate(t, nonTPMChallenge))}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("non-tpm evidence error = %v, want ErrEKActivation", err)
	}

	disabled := newTestService(t, nil)
	options, ceremony, err = disabled.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	ignored := registration.creationResponse(t, options)
	ignored.TPMEKActivation = &TPMEKActivationEvidence{ChallengeID: "ignored", CertInfo: "ignored"}
	if _, err := disabled.FinishRegistration(context.Background(), ceremony, ignored); err != nil {
		t.Fatalf("disabled activation altered registration: %v", err)
	}
}

// TestTPMEKActivationUserBinding checks that a challenge bound to another user is rejected. |
// TestTPMEKActivationUserBinding 校验绑定到其他用户的挑战会被拒绝。
func TestTPMEKActivationUserBinding(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	credentialSigner := newECSigner(t)
	registration, aikCert := fixture.tpmRegistrationFixture(t, credentialSigner)
	user := testUser()
	service := fixture.newTPMEKService(t, &TPMEKActivationConfig{EKRoots: fixture.roots}, func(config *Config) {
		config.AttestationRoots = certificateRoots(aikCert)
	})
	options, ceremony, err := service.BeginRegistration(context.Background(), user, RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	challenge := fixture.startChallenge(t, service, [16]byte{1, 2, 3, 4}, "someone-else")
	response := registration.creationResponse(t, options)
	response.TPMEKActivation = &TPMEKActivationEvidence{ChallengeID: challenge.ID, CertInfo: b64(fixture.activate(t, challenge))}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrEKActivation) {
		t.Fatalf("user binding error = %v, want ErrEKActivation", err)
	}
}

// TestTPMEKActivationServiceConcurrency covers concurrent challenge issue and consumption. |
// TestTPMEKActivationServiceConcurrency 覆盖并发挑战签发与消费。
func TestTPMEKActivationServiceConcurrency(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgECC)
	service := fixture.newTPMEKService(t, &TPMEKActivationConfig{
		EKRoots:              fixture.roots,
		MaxPendingChallenges: 16,
	}, nil)
	const workers = 8
	results := make(chan error, workers)
	for range workers {
		go func() {
			challenge, err := service.BeginTPMEKActivation(context.Background(), &TPMEKActivationRequest{
				EKCertificates: cloneByteSlices(fixture.chain),
				EKPublic:       append([]byte(nil), fixture.ekRaw...),
				AKPublic:       append([]byte(nil), fixture.akRaw...),
				AAGUID:         fixture.aaguid,
			})
			if err != nil {
				results <- err
				return
			}
			attest, err := ActivateCredentialCommand(context.Background(), fixture.tpm, fixture.tpm.AKHandle(), fixture.tpm.EKHandle(),
				TPM2BIDObject{Buffer: challenge.CredentialBlob},
				TPM2BEncryptedSecret{Buffer: challenge.EncryptedSecret})
			if err != nil {
				results <- err
				return
			}
			_, err = service.FinishTPMEKActivation(context.Background(), challenge.ID, attest.Buffer)
			results <- err
		}()
	}
	for range workers {
		if err := <-results; err != nil {
			t.Errorf("concurrent activation error = %v", err)
		}
	}
}

// TestTPMEKActivationCertificateManufacturer covers the manufacturer allowlist. |
// TestTPMEKActivationCertificateManufacturer 覆盖制造商允许列表。
func TestTPMEKActivationCertificateManufacturer(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	verification := fixture.statelessVerification(t, make([]byte, 32))
	if _, err := VerifyEKActivation(context.Background(), verification, &TPMEKActivationConfig{
		EKRoots:                fixture.roots,
		AllowedEKManufacturers: []string{"INTEL"},
	}); !errors.Is(err, ErrEKCertificate) {
		t.Fatalf("missing manufacturer error = %v, want ErrEKCertificate", err)
	}
	if _, err := VerifyEKActivation(context.Background(), verification, &TPMEKActivationConfig{
		EKRoots:                fixture.roots,
		AllowedEKManufacturers: []string{" id:fffff1d0 "},
	}); err != nil {
		t.Fatalf("manufacturer allowlist: %v", err)
	}
}

// TestTPMEKActivationIntermediateChain covers a leaf signed by an intermediate CA. |
// TestTPMEKActivationIntermediateChain 覆盖由中间 CA 签发的叶证书。
func TestTPMEKActivationIntermediateChain(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	intermediate, intermediateKey := newTestIntermediate(t, fixture.root, fixture.rootKey, 904, testNow.Add(12*time.Hour))
	ekKey, err := fixture.ekPublic.PublicKey()
	if err != nil {
		t.Fatalf("EK public key: %v", err)
	}
	leaf := newEKTestCertificate(t, ekKey, intermediate, intermediateKey, testNow.Add(-time.Hour), testNow.Add(time.Hour),
		false, []asn1.ObjectIdentifier{tcgKpEKCertOID}, "")
	verification := fixture.statelessVerification(t, make([]byte, 32))
	verification.EKCertificates = [][]byte{leaf.Raw, intermediate.Raw}
	result, err := VerifyEKActivation(context.Background(), verification, &TPMEKActivationConfig{EKRoots: fixture.roots})
	if err != nil {
		t.Fatalf("VerifyEKActivation with intermediate: %v", err)
	}
	if !result.TrustVerified || len(result.EKCertificates) != 2 {
		t.Fatalf("result = %#v", result)
	}
}

// TestTPMEKActivationErrorSentinels checks error classification and platform availability. |
// TestTPMEKActivationErrorSentinels 校验错误分类与平台可用性。
func TestTPMEKActivationErrorSentinels(t *testing.T) {
	fixture := newEKActivationFixture(t, TPMAlgRSA)
	service := fixture.newTPMEKService(t, nil, nil)
	challenge := fixture.startChallenge(t, service, fixture.aaguid, "")
	if _, err := service.FinishTPMEKActivation(context.Background(), "", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty challenge ID error = %v, want ErrInvalidRequest", err)
	}
	if _, err := service.FinishTPMEKActivation(context.Background(), challenge.ID, []byte{1, 2, 3}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("malformed certInfo error = %v, want ErrTPMStructure", err)
	}
	device, err := OpenTPM(TPMOptions{})
	if err != nil {
		if !errors.Is(err, ErrTPMUnavailable) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("OpenTPM error = %v, want ErrTPMUnavailable or ErrUnsupported", err)
		}
		t.Logf("platform TPM unavailable: %v", err)
	} else {
		t.Logf("platform TPM transport opened successfully")
		if err := device.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

// TestTPMEKActivationVerifierFunc covers the function adapter. | TestTPMEKActivationVerifierFunc 覆盖函数
// 适配器。
func TestTPMEKActivationVerifierFunc(t *testing.T) {
	called := false
	verifier := TPMEKActivationVerifierFunc(func(context.Context, TPMEKActivationVerification, TPMEKActivationResult) error {
		called = true
		return nil
	})
	if err := verifier.VerifyTPMEKActivation(context.Background(), TPMEKActivationVerification{}, TPMEKActivationResult{}); err != nil {
		t.Fatalf("VerifyTPMEKActivation: %v", err)
	}
	if !called {
		t.Fatal("adapter did not call the function")
	}
	var _ TPMEKActivationVerifier = verifier
}
