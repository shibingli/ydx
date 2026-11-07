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

	"github.com/shibingli/ydx/base64"
)

// newTestRootCA returns a self-signed CA certificate and its key. | newTestRootCA 返回自签名 CA 证书及其密钥。
func newTestRootCA(t *testing.T, commonName string, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert, key
}

// newSignedTestCert signs template with parent. | newSignedTestCert 用 parent 签发 template。
func newSignedTestCert(t *testing.T, template *x509.Certificate, publicKey any, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// newTestIntermediate returns an intermediate CA signed by root. | newTestIntermediate 返回由 root 签发的中间 CA。
func newTestIntermediate(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, serial int64, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return newSignedTestCert(t, template, &key.PublicKey, root, rootKey), key
}

// newLeafTemplate returns a leaf certificate template. | newLeafTemplate 返回叶证书模板。
func newLeafTemplate(serial int64, notAfter time.Time, extensions []pkix.Extension) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       extensions,
	}
}

// buildSafetyNetES256JWS builds an ES256 compact JWS carrying x5c. | buildSafetyNetES256JWS 构建携带 x5c 的 ES256 紧凑 JWS。
func buildSafetyNetES256JWS(t *testing.T, signer *ecSigner, x5c []*x509.Certificate, nonce []byte, timestampMs int64, cts bool, packageName string) []byte {
	t.Helper()
	header := struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}{Alg: "ES256"}
	for _, cert := range x5c {
		header.X5C = append(header.X5C, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	payload := struct {
		Nonce          string `json:"nonce"`
		TimestampMs    int64  `json:"timestampMs"`
		APKPackageName string `json:"apkPackageName"`
		CTSProfile     bool   `json:"ctsProfileMatch"`
	}{
		Nonce:          base64.StdEncoding.EncodeToString(nonce),
		TimestampMs:    timestampMs,
		APKPackageName: packageName,
		CTSProfile:     cts,
	}
	input := b64(mustMarshal(t, header)) + "." + b64(mustMarshal(t, payload))
	return []byte(input + "." + b64(signer.sign(t, []byte(input))))
}

// safetyNetChainStatement signs a SafetyNet JWS with signer and x5c. | safetyNetChainStatement 用 signer 与 x5c
// 签名 SafetyNet JWS。
func safetyNetChainStatement(signer *ecSigner, x5c []*x509.Certificate, packageName string, timestampMs int64, cts bool) attestationBuilder {
	return func(t *testing.T, authData, clientDataHash []byte) []Pair {
		t.Helper()
		nonce := sha256.Sum256(signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("ver"), Value: NewText("1.0")},
			{Key: NewText("response"), Value: NewBytes(buildSafetyNetES256JWS(t, signer, x5c, nonce[:], timestampMs, cts, packageName))},
		}
	}
}

// TestAttestationSafetyNetTrustRoots covers per-format and generic trust anchors. |
// TestAttestationSafetyNetTrustRoots 覆盖按格式与通用信任锚。
func TestAttestationSafetyNetTrustRoots(t *testing.T) {
	root, rootKey := newTestRootCA(t, "SafetyNet Root", 100)
	intermediate, intermediateKey := newTestIntermediate(t, root, rootKey, 101, testNow.Add(24*time.Hour))
	leafSigner := newECSigner(t)
	leaf := newSignedTestCert(t, newLeafTemplate(102, testNow.Add(24*time.Hour), nil), &leafSigner.key.PublicKey, intermediate, intermediateKey)
	credentialSigner := newECSigner(t)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet,
		safetyNetChainStatement(leafSigner, []*x509.Certificate{leaf, intermediate}, "com.example.app", testNow.UnixMilli(), true))
	goodPool := certificateRoots(root)
	wrongRoot, _ := newTestRootCA(t, "Other Root", 200)
	wrongPool := certificateRoots(wrongRoot)

	t.Run("format roots", func(t *testing.T) {
		result, err := object.Verify(context.Background(), hash, AttestationOptions{
			CurrentTime:    testNow,
			SafetyNetRoots: goodPool,
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !result.TrustVerified || len(result.TrustPath) != 2 {
			t.Fatalf("trust = %v, path = %v", result.TrustVerified, result.TrustPath)
		}
	})
	t.Run("generic roots fallback", func(t *testing.T) {
		result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, Roots: goodPool})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !result.TrustVerified {
			t.Fatal("generic roots were not used")
		}
	})
	t.Run("format roots override generic roots", func(t *testing.T) {
		result, err := object.Verify(context.Background(), hash, AttestationOptions{
			CurrentTime:    testNow,
			Roots:          wrongPool,
			SafetyNetRoots: goodPool,
		})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !result.TrustVerified {
			t.Fatal("format roots did not override generic roots")
		}
	})
	t.Run("format roots do not fall back to generic roots", func(t *testing.T) {
		if _, err := object.Verify(context.Background(), hash, AttestationOptions{
			CurrentTime:    testNow,
			Roots:          goodPool,
			SafetyNetRoots: wrongPool,
		}); !errors.Is(err, ErrUntrustedAttestation) {
			t.Fatalf("error = %v, want ErrUntrustedAttestation", err)
		}
	})
	t.Run("untrusted root", func(t *testing.T) {
		if _, err := object.Verify(context.Background(), hash, AttestationOptions{
			CurrentTime:    testNow,
			SafetyNetRoots: wrongPool,
		}); !errors.Is(err, ErrUntrustedAttestation) {
			t.Fatalf("error = %v, want ErrUntrustedAttestation", err)
		}
	})
	t.Run("no roots reports unverified", func(t *testing.T) {
		result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if result.TrustVerified || len(result.TrustPath) != 2 {
			t.Fatalf("trust = %v, path = %v", result.TrustVerified, result.TrustPath)
		}
	})
	t.Run("expired leaf", func(t *testing.T) {
		expired := newSignedTestCert(t, newLeafTemplate(103, testNow.Add(-time.Minute), nil), &leafSigner.key.PublicKey, intermediate, intermediateKey)
		expiredObject, expiredHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet,
			safetyNetChainStatement(leafSigner, []*x509.Certificate{expired, intermediate}, "com.example.app", testNow.UnixMilli(), true))
		if _, err := expiredObject.Verify(context.Background(), expiredHash, AttestationOptions{CurrentTime: testNow}); !errors.Is(err, ErrUntrustedAttestation) {
			t.Fatalf("expired leaf error = %v, want ErrUntrustedAttestation", err)
		}
	})
	t.Run("expired intermediate", func(t *testing.T) {
		expiredIntermediate, expiredKey := newTestIntermediate(t, root, rootKey, 104, testNow.Add(-time.Minute))
		validLeaf := newSignedTestCert(t, newLeafTemplate(105, testNow.Add(24*time.Hour), nil), &leafSigner.key.PublicKey, expiredIntermediate, expiredKey)
		expiredObject, expiredHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet,
			safetyNetChainStatement(leafSigner, []*x509.Certificate{validLeaf, expiredIntermediate}, "com.example.app", testNow.UnixMilli(), true))
		if _, err := expiredObject.Verify(context.Background(), expiredHash, AttestationOptions{
			CurrentTime:    testNow,
			SafetyNetRoots: goodPool,
		}); !errors.Is(err, ErrUntrustedAttestation) {
			t.Fatalf("expired intermediate error = %v, want ErrUntrustedAttestation", err)
		}
	})
}

// TestAttestationSafetyNetPackageName covers package binding precedence. |
// TestAttestationSafetyNetPackageName 覆盖包名绑定优先级。
func TestAttestationSafetyNetPackageName(t *testing.T) {
	root, rootKey := newTestRootCA(t, "SafetyNet Root", 110)
	leafSigner := newECSigner(t)
	leaf := newSignedTestCert(t, newLeafTemplate(111, testNow.Add(time.Hour), nil), &leafSigner.key.PublicKey, root, rootKey)
	credentialSigner := newECSigner(t)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet,
		safetyNetChainStatement(leafSigner, []*x509.Certificate{leaf}, "com.example.app", testNow.UnixMilli(), true))

	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, AndroidPackageName: "com.example.app"}); err != nil {
		t.Fatalf("matching configured package: %v", err)
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, AndroidPackageName: "com.other.app"}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("configured package mismatch error = %v, want ErrInvalidAttestation", err)
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		ClientData:  &ClientData{AndroidPackageName: "com.example.app"},
	}); err != nil {
		t.Fatalf("matching client data package: %v", err)
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime: testNow,
		ClientData:  &ClientData{AndroidPackageName: "com.other.app"},
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("client data package mismatch error = %v, want ErrInvalidAttestation", err)
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:        testNow,
		AndroidPackageName: "com.example.app",
		ClientData:         &ClientData{AndroidPackageName: "com.other.app"},
	}); err != nil {
		t.Fatalf("configured package did not take precedence: %v", err)
	}

	emptyObject, emptyHash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet,
		safetyNetChainStatement(leafSigner, []*x509.Certificate{leaf}, "", testNow.UnixMilli(), true))
	if _, err := emptyObject.Verify(context.Background(), emptyHash, AttestationOptions{
		CurrentTime:        testNow,
		AndroidPackageName: "com.example.app",
	}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("empty JWS package with configured package error = %v, want ErrInvalidAttestation", err)
	}
}

// TestAttestationSafetyNetCustomVerifierTrust covers custom verifier trust reporting. |
// TestAttestationSafetyNetCustomVerifierTrust 覆盖自定义校验器的信任上报。
func TestAttestationSafetyNetCustomVerifierTrust(t *testing.T) {
	root, rootKey := newTestRootCA(t, "SafetyNet Root", 120)
	leafSigner := newECSigner(t)
	leaf := newSignedTestCert(t, newLeafTemplate(121, testNow.Add(time.Hour), nil), &leafSigner.key.PublicKey, root, rootKey)
	credentialSigner := newECSigner(t)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidSafetyNet,
		safetyNetChainStatement(leafSigner, []*x509.Certificate{leaf, root}, "com.example.app", testNow.UnixMilli(), true))
	accepting := SafetyNetVerifierFunc(func(context.Context, []byte, []byte) error { return nil })
	goodPool := certificateRoots(root)
	wrongRoot, _ := newTestRootCA(t, "Other Root", 122)
	wrongPool := certificateRoots(wrongRoot)

	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:       testNow,
		SafetyNetVerifier: accepting,
	})
	if err != nil {
		t.Fatalf("Verify without roots: %v", err)
	}
	if result.TrustVerified || len(result.TrustPath) != 2 {
		t.Fatalf("trust = %v, path = %v", result.TrustVerified, result.TrustPath)
	}
	result, err = object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:       testNow,
		SafetyNetVerifier: accepting,
		SafetyNetRoots:    goodPool,
	})
	if err != nil {
		t.Fatalf("Verify with roots: %v", err)
	}
	if !result.TrustVerified {
		t.Fatal("custom verifier did not report trust from configured roots")
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:       testNow,
		SafetyNetVerifier: accepting,
		SafetyNetRoots:    wrongPool,
	}); !errors.Is(err, ErrUntrustedAttestation) {
		t.Fatalf("wrong root error = %v, want ErrUntrustedAttestation", err)
	}
	var nonceSeen []byte
	capturing := SafetyNetVerifierFunc(func(_ context.Context, _ []byte, nonce []byte) error {
		nonceSeen = append([]byte(nil), nonce...)
		return nil
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, SafetyNetVerifier: capturing}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(nonceSeen) != sha256.Size {
		t.Fatalf("expected nonce length = %d, want %d", len(nonceSeen), sha256.Size)
	}
}

// testAndroidPackageInfo mirrors the Android PackageInfo structure. | testAndroidPackageInfo 对应 Android PackageInfo 结构。
type testAndroidPackageInfo struct {
	Name    []byte
	Version int
}

// testAndroidApplicationID mirrors AttestationApplicationId. | testAndroidApplicationID 对应 AttestationApplicationId。
type testAndroidApplicationID struct {
	Packages []testAndroidPackageInfo
	Digests  [][]byte
}

// androidApplicationIDField encodes the tag 709 field. | androidApplicationIDField 编码 tag 709 字段。
func androidApplicationIDField(t *testing.T, packageName string) []byte {
	t.Helper()
	inner, err := asn1.Marshal(testAndroidApplicationID{
		Packages: []testAndroidPackageInfo{{Name: []byte(packageName), Version: 1}},
		Digests:  [][]byte{{1, 2, 3}},
	})
	if err != nil {
		t.Fatalf("marshal application ID: %v", err)
	}
	field, err := asn1.Marshal(asn1.RawValue{
		Class:      derClassContext,
		Tag:        androidTagAttestationApplicationID,
		IsCompound: true,
		Bytes:      inner,
	})
	if err != nil {
		t.Fatalf("marshal application ID field: %v", err)
	}
	return field
}

// androidKeyDescriptionValue encodes the Android attestation extension value. |
// androidKeyDescriptionValue 编码 Android 认证扩展值。
func androidKeyDescriptionValue(t *testing.T, challenge []byte, includeApplicationID bool, packageName string) []byte {
	t.Helper()
	software := androidAuthorizationListDER(t, kmPurposeSign, kmOriginGenerated)
	if includeApplicationID {
		software = append(software, androidApplicationIDField(t, packageName)...)
	}
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
			Bytes:      software,
		},
		TEEEnforced: asn1.RawValue{Class: derClassContext, Tag: 1, IsCompound: true},
	}
	value, err := asn1.Marshal(description)
	if err != nil {
		t.Fatalf("marshal android key description: %v", err)
	}
	return value
}

// newAndroidKeyChainLeaf returns a leaf certificate bound to signer, signed by parent. |
// newAndroidKeyChainLeaf 返回绑定 signer、由 parent 签发的叶证书。
func newAndroidKeyChainLeaf(t *testing.T, signer *ecSigner, challenge []byte, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, includeApplicationID bool, packageName string) *x509.Certificate {
	t.Helper()
	extension := pkix.Extension{Id: androidKeyAttestationOID, Value: androidKeyDescriptionValue(t, challenge, includeApplicationID, packageName)}
	return newSignedTestCert(t, newLeafTemplate(130, testNow.Add(time.Hour), []pkix.Extension{extension}), &signer.key.PublicKey, parent, parentKey)
}

// androidKeyChainStatement signs an android-key attestation whose leaf key is the credential key. |
// androidKeyChainStatement 签名叶证书密钥等于凭据密钥的 android-key 认证声明。
func androidKeyChainStatement(signer *ecSigner, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, includeApplicationID bool, packageName string) attestationBuilder {
	return func(t *testing.T, authData, clientDataHash []byte) []Pair {
		t.Helper()
		leaf := newAndroidKeyChainLeaf(t, signer, clientDataHash, parent, parentKey, includeApplicationID, packageName)
		signature := signer.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(leaf.Raw), NewBytes(parent.Raw))},
		}
	}
}

// TestAttestationAndroidKeyTrustRoots covers per-format and generic trust anchors. |
// TestAttestationAndroidKeyTrustRoots 覆盖按格式与通用信任锚。
func TestAttestationAndroidKeyTrustRoots(t *testing.T) {
	root, rootKey := newTestRootCA(t, "Android Key Root", 140)
	intermediate, intermediateKey := newTestIntermediate(t, root, rootKey, 141, testNow.Add(24*time.Hour))
	credentialSigner := newECSigner(t)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidKey,
		androidKeyChainStatement(credentialSigner, intermediate, intermediateKey, true, "com.example.app"))
	goodPool := certificateRoots(root)
	wrongRoot, _ := newTestRootCA(t, "Other Root", 142)
	wrongPool := certificateRoots(wrongRoot)

	result, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, AndroidKeyRoots: goodPool})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.TrustVerified || len(result.TrustPath) != 2 {
		t.Fatalf("trust = %v, path = %v", result.TrustVerified, result.TrustPath)
	}
	result, err = object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, Roots: goodPool})
	if err != nil {
		t.Fatalf("generic roots fallback: %v", err)
	}
	if !result.TrustVerified {
		t.Fatal("generic roots were not used")
	}
	result, err = object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:     testNow,
		Roots:           wrongPool,
		AndroidKeyRoots: goodPool,
	})
	if err != nil {
		t.Fatalf("format roots override: %v", err)
	}
	if !result.TrustVerified {
		t.Fatal("format roots did not override generic roots")
	}
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:     testNow,
		Roots:           goodPool,
		AndroidKeyRoots: wrongPool,
	}); !errors.Is(err, ErrUntrustedAttestation) {
		t.Fatalf("wrong format roots error = %v, want ErrUntrustedAttestation", err)
	}
	result, err = object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow})
	if err != nil {
		t.Fatalf("Verify without roots: %v", err)
	}
	if result.TrustVerified || len(result.TrustPath) != 2 {
		t.Fatalf("trust = %v, path = %v", result.TrustVerified, result.TrustPath)
	}
	t.Run("expired leaf", func(t *testing.T) {
		extension := pkix.Extension{Id: androidKeyAttestationOID, Value: androidKeyDescriptionValue(t, hash[:], true, "com.example.app")}
		leaf := newSignedTestCert(t, newLeafTemplate(143, testNow.Add(-time.Minute), []pkix.Extension{extension}), &credentialSigner.key.PublicKey, intermediate, intermediateKey)
		expiredObject, expiredHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
			signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
			return []Pair{
				{Key: NewText("alg"), Value: NewInt(AlgES256)},
				{Key: NewText("sig"), Value: NewBytes(signature)},
				{Key: NewText("x5c"), Value: NewArray(NewBytes(leaf.Raw), NewBytes(intermediate.Raw))},
			}
		})
		if _, err := expiredObject.Verify(context.Background(), expiredHash, AttestationOptions{
			CurrentTime:     testNow,
			AndroidKeyRoots: goodPool,
		}); !errors.Is(err, ErrUntrustedAttestation) {
			t.Fatalf("expired leaf error = %v, want ErrUntrustedAttestation", err)
		}
	})
	// An expired chain is not rejected when the caller supplies no roots: the package parses but does
	// not establish trust. | 调用方未提供信任锚时过期链不会被拒绝：本包只解析而不建立信任。
	expiredIntermediate, expiredKey := newTestIntermediate(t, root, rootKey, 144, testNow.Add(-time.Minute))
	extension := pkix.Extension{Id: androidKeyAttestationOID, Value: androidKeyDescriptionValue(t, hash[:], true, "com.example.app")}
	validLeaf := newSignedTestCert(t, newLeafTemplate(145, testNow.Add(time.Hour), []pkix.Extension{extension}), &credentialSigner.key.PublicKey, expiredIntermediate, expiredKey)
	intermediateObject, intermediateHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(validLeaf.Raw), NewBytes(expiredIntermediate.Raw))},
		}
	})
	if _, err := intermediateObject.Verify(context.Background(), intermediateHash, AttestationOptions{CurrentTime: testNow}); err != nil {
		t.Fatalf("Verify without roots: %v", err)
	}
	if _, err := intermediateObject.Verify(context.Background(), intermediateHash, AttestationOptions{
		CurrentTime:     testNow,
		AndroidKeyRoots: goodPool,
	}); !errors.Is(err, ErrUntrustedAttestation) {
		t.Fatalf("expired intermediate error = %v, want ErrUntrustedAttestation", err)
	}
}

// TestAttestationAndroidKeyPackageName covers Android Key package binding. |
// TestAttestationAndroidKeyPackageName 覆盖 Android Key 包名绑定。
func TestAttestationAndroidKeyPackageName(t *testing.T) {
	root, rootKey := newTestRootCA(t, "Android Key Root", 150)
	credentialSigner := newECSigner(t)
	withPackage, withHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey,
		androidKeyChainStatement(credentialSigner, root, rootKey, true, "com.example.app"))

	if _, err := withPackage.Verify(context.Background(), withHash, AttestationOptions{CurrentTime: testNow}); err != nil {
		t.Fatalf("Verify without expected package: %v", err)
	}
	if _, err := withPackage.Verify(context.Background(), withHash, AttestationOptions{CurrentTime: testNow, AndroidPackageName: "com.example.app"}); err != nil {
		t.Fatalf("matching configured package: %v", err)
	}
	if _, err := withPackage.Verify(context.Background(), withHash, AttestationOptions{CurrentTime: testNow, AndroidPackageName: "com.other.app"}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("configured package mismatch error = %v, want ErrInvalidAttestation", err)
	}
	if _, err := withPackage.Verify(context.Background(), withHash, AttestationOptions{
		CurrentTime: testNow,
		ClientData:  &ClientData{AndroidPackageName: "com.example.app"},
	}); err != nil {
		t.Fatalf("matching client data package: %v", err)
	}
	if _, err := withPackage.Verify(context.Background(), withHash, AttestationOptions{
		CurrentTime:        testNow,
		AndroidPackageName: "com.example.app",
		ClientData:         &ClientData{AndroidPackageName: "com.other.app"},
	}); err != nil {
		t.Fatalf("configured package did not take precedence: %v", err)
	}

	noPackage, noHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey,
		androidKeyChainStatement(credentialSigner, root, rootKey, false, ""))
	if _, err := noPackage.Verify(context.Background(), noHash, AttestationOptions{CurrentTime: testNow}); err != nil {
		t.Fatalf("Verify without expected package: %v", err)
	}
	if _, err := noPackage.Verify(context.Background(), noHash, AttestationOptions{CurrentTime: testNow, AndroidPackageName: "com.example.app"}); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing application ID error = %v, want ErrInvalidAttestation", err)
	}
}

// TestAttestationAndroidKeyCustomVerifier covers custom verifier behavior. |
// TestAttestationAndroidKeyCustomVerifier 覆盖自定义校验器行为。
func TestAttestationAndroidKeyCustomVerifier(t *testing.T) {
	credentialSigner := newECSigner(t)
	cert := newTestAttestationCert(t, credentialSigner)
	object, hash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		signature := credentialSigner.sign(t, signedAttestationData(authData, clientDataHash))
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes(signature)},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	})
	var seenOptions AndroidKeyVerifyOptions
	var seenCerts []*x509.Certificate
	trusting := AndroidKeyVerifierFunc(func(_ context.Context, certs []*x509.Certificate, opts AndroidKeyVerifyOptions) (bool, error) {
		seenCerts = certs
		seenOptions = opts
		return true, nil
	})
	result, err := object.Verify(context.Background(), hash, AttestationOptions{
		CurrentTime:        testNow,
		AndroidKeyVerifier: trusting,
		AndroidPackageName: "com.example.app",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.TrustVerified || result.Type != AttestationTypeBasic || len(result.TrustPath) != 1 {
		t.Fatalf("result = %#v", result)
	}
	if len(seenCerts) != 1 || !constantTimeEqual(seenOptions.ClientDataHash, hash) {
		t.Fatalf("verifier inputs = %d certs, hash %x", len(seenCerts), seenOptions.ClientDataHash)
	}
	if !constantTimeEqual(seenOptions.AuthData, object.AuthDataRaw) {
		t.Fatal("verifier did not receive the raw auth data")
	}
	if seenOptions.ExpectedPackageName != "com.example.app" {
		t.Fatalf("expected package = %q", seenOptions.ExpectedPackageName)
	}
	distrusting := AndroidKeyVerifierFunc(func(context.Context, []*x509.Certificate, AndroidKeyVerifyOptions) (bool, error) {
		return false, nil
	})
	result, err = object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, AndroidKeyVerifier: distrusting})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.TrustVerified {
		t.Fatal("custom verifier trust result was ignored")
	}
	sentinel := errors.New("custom verifier rejected")
	rejecting := AndroidKeyVerifierFunc(func(context.Context, []*x509.Certificate, AndroidKeyVerifyOptions) (bool, error) {
		return false, sentinel
	})
	if _, err := object.Verify(context.Background(), hash, AttestationOptions{CurrentTime: testNow, AndroidKeyVerifier: rejecting}); !errors.Is(err, sentinel) || !errors.Is(err, ErrUntrustedAttestation) {
		t.Fatalf("rejecting verifier error = %v, want sentinel and ErrUntrustedAttestation", err)
	}

	called := false
	notCalled := AndroidKeyVerifierFunc(func(context.Context, []*x509.Certificate, AndroidKeyVerifyOptions) (bool, error) {
		called = true
		return true, nil
	})
	badObject, badHash := buildTestAttestation(t, credentialSigner, FormatAndroidKey, func(t *testing.T, authData, clientDataHash []byte) []Pair {
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(AlgES256)},
			{Key: NewText("sig"), Value: NewBytes([]byte{1, 2, 3})},
			{Key: NewText("x5c"), Value: NewArray(NewBytes(cert.Raw))},
		}
	})
	if _, err := badObject.Verify(context.Background(), badHash, AttestationOptions{CurrentTime: testNow, AndroidKeyVerifier: notCalled}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("bad signature error = %v, want ErrSignatureInvalid", err)
	}
	if called {
		t.Fatal("custom verifier ran before the attestation signature was verified")
	}
}
