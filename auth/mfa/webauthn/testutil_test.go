package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/json"
)

// Fixed values shared by the tests. | 测试共享的固定值。
const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

var testNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// testSigner signs authenticator data in a test. | testSigner 在测试中签名认证器数据。
type testSigner interface {
	algorithm() int
	coseKey(t *testing.T) *COSEKey
	sign(t *testing.T, message []byte) []byte
}

// ecSigner is a P-256 authenticator key. | ecSigner 是 P-256 认证器密钥。
type ecSigner struct {
	key *ecdsa.PrivateKey
}

func newECSigner(t *testing.T) *ecSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return &ecSigner{key: key}
}

func (s *ecSigner) algorithm() int { return AlgES256 }

// publicKeyBytes returns the uncompressed SEC 1 encoding of the signer's key. |
// publicKeyBytes 返回签名器密钥的未压缩 SEC 1 编码。
func (s *ecSigner) publicKeyBytes(t *testing.T) []byte {
	t.Helper()
	encoded, err := s.key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	if len(encoded) != 65 {
		t.Fatalf("public key length = %d, want 65", len(encoded))
	}
	return encoded
}

func (s *ecSigner) coseKey(t *testing.T) *COSEKey {
	t.Helper()
	encoded := s.publicKeyBytes(t)
	return &COSEKey{
		Kty: KeyTypeEC2,
		Alg: AlgES256,
		Crv: CurveP256,
		X:   append([]byte(nil), encoded[1:33]...),
		Y:   append([]byte(nil), encoded[33:]...),
	}
}

func (s *ecSigner) sign(t *testing.T, message []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatalf("sign ECDSA: %v", err)
	}
	return signature
}

// edSigner is an Ed25519 authenticator key. | edSigner 是 Ed25519 认证器密钥。
type edSigner struct {
	key ed25519.PrivateKey
}

func newEdSigner(t *testing.T) *edSigner {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return &edSigner{key: key}
}

func (s *edSigner) algorithm() int { return AlgEdDSA }

func (s *edSigner) coseKey(t *testing.T) *COSEKey {
	t.Helper()
	return &COSEKey{
		Kty: KeyTypeOKP,
		Alg: AlgEdDSA,
		Crv: CurveEd25519,
		X:   append([]byte(nil), s.key.Public().(ed25519.PublicKey)...),
	}
}

func (s *edSigner) sign(t *testing.T, message []byte) []byte {
	t.Helper()
	return ed25519.Sign(s.key, message)
}

func b64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

func mustEncodeCBOR(t *testing.T, value *Value) []byte {
	t.Helper()
	encoded, err := Encode(value)
	if err != nil {
		t.Fatalf("encode CBOR: %v", err)
	}
	return encoded
}

// newTestService returns a Service with a fixed clock. | newTestService 返回使用固定时钟的 Service。
func newTestService(t *testing.T, mutate func(*Config)) *Service {
	t.Helper()
	clock := func() time.Time { return testNow }
	config := Config{
		RPDisplayName:   "Example RP",
		RPID:            testRPID,
		RPOrigins:       []string{testOrigin},
		Clock:           clock,
		ChallengeStore:  NewMemoryChallengeStoreWithClock(clock),
		CredentialStore: NewMemoryCredentialStore(),
	}
	if mutate != nil {
		mutate(&config)
	}
	service, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return service
}

// buildAuthData assembles WebAuthn authenticator data. | buildAuthData 组装 WebAuthn 认证器数据。
func buildAuthData(t *testing.T, rpID string, flags Flags, signCount uint32, aaguid [16]byte, credentialID []byte, key *COSEKey, extensions *Value) []byte {
	t.Helper()
	hash := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 128)
	out = append(out, hash[:]...)
	out = append(out, byte(flags))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], signCount)
	out = append(out, count[:]...)
	if flags.AttestedCredentialData() {
		out = append(out, aaguid[:]...)
		var idLength [2]byte
		binary.BigEndian.PutUint16(idLength[:], uint16(len(credentialID)))
		out = append(out, idLength[:]...)
		out = append(out, credentialID...)
		out = append(out, mustEncodeCBOR(t, mustCOSEValue(t, key))...)
	}
	if flags.ExtensionsPresent() {
		if extensions == nil {
			t.Fatal("extensions flag set without extension data")
		}
		out = append(out, mustEncodeCBOR(t, extensions)...)
	}
	return out
}

// mustCOSEValue parses the encoded COSE key back into a Value for embedding. | mustCOSEValue 把编码后的 COSE 密钥解析回 Value 以便嵌入。
func mustCOSEValue(t *testing.T, key *COSEKey) *Value {
	t.Helper()
	encoded, err := key.Encode()
	if err != nil {
		t.Fatalf("encode COSE key: %v", err)
	}
	value, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode COSE key: %v", err)
	}
	return value
}

// makeAttestationObject encodes an attestation object. | makeAttestationObject 编码认证声明对象。
func makeAttestationObject(t *testing.T, format string, statement []Pair, authData []byte) []byte {
	t.Helper()
	return mustEncodeCBOR(t, NewMap(
		Pair{Key: NewText("fmt"), Value: NewText(format)},
		Pair{Key: NewText("attStmt"), Value: NewMap(statement...)},
		Pair{Key: NewText("authData"), Value: NewBytes(authData)},
	))
}

// attestationBuilder builds attestation statement pairs from the signed data. | attestationBuilder 从被签名数据构建认证声明键值对。
type attestationBuilder func(t *testing.T, authData, clientDataHash []byte) []Pair

// packedSelfStatement returns a packed self-attestation statement. | packedSelfStatement 返回 packed 自认证声明。
func packedSelfStatement(signer testSigner) attestationBuilder {
	return func(t *testing.T, authData, clientDataHash []byte) []Pair {
		t.Helper()
		signed := signedAttestationData(authData, clientDataHash)
		return []Pair{
			{Key: NewText("alg"), Value: NewInt(int64(signer.algorithm()))},
			{Key: NewText("sig"), Value: NewBytes(signer.sign(t, signed))},
		}
	}
}

// registrationFixture describes one fake registration response. | registrationFixture 描述一个伪造注册响应。
type registrationFixture struct {
	signer    testSigner
	credID    []byte
	flags     Flags
	signCount uint32
	format    string
	statement attestationBuilder
	extension ClientExtensionResults
}

func defaultRegistrationFixture(t *testing.T, signer testSigner) *registrationFixture {
	t.Helper()
	return &registrationFixture{
		signer: signer,
		credID: []byte("test-credential-id"),
		flags:  FlagUserPresent | FlagAttestedCredentialData,
		format: FormatNone,
	}
}

// creationResponse builds the navigator response for fixture. | creationResponse 为 fixture 构建 navigator 响应。
func (f *registrationFixture) creationResponse(t *testing.T, options *CredentialCreationOptions) *CredentialCreationResponse {
	t.Helper()
	authData := buildAuthData(t, testRPID, f.flags, f.signCount, [16]byte{1, 2, 3, 4}, f.credID, f.signer.coseKey(t), nil)
	clientData := &ClientData{
		Type:      ClientDataTypeCreate,
		Challenge: options.PublicKey.Challenge,
		Origin:    testOrigin,
	}
	clientDataJSON := mustMarshal(t, clientData)
	clientDataHash := sha256.Sum256(clientDataJSON)
	var statement []Pair
	if f.statement != nil {
		statement = f.statement(t, authData, clientDataHash[:])
	}
	attestation := makeAttestationObject(t, f.format, statement, authData)
	return &CredentialCreationResponse{
		ID:    b64(f.credID),
		RawID: b64(f.credID),
		Type:  "public-key",
		Response: AuthenticatorAttestationResponse{
			ClientDataJSON:    b64(clientDataJSON),
			AttestationObject: b64(attestation),
			Transports:        []string{"internal"},
		},
		ClientExtensionResults: f.extension,
	}
}

// register runs a full registration for fixture. | register 为 fixture 运行完整注册。
func (f *registrationFixture) register(t *testing.T, service *Service, user *auth.User, opts RegistrationOptions) *Credential {
	t.Helper()
	options, ceremony, err := service.BeginRegistration(context.Background(), user, opts)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	credential, err := service.FinishRegistration(context.Background(), ceremony, f.creationResponse(t, options))
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return credential
}

// assertionFixture describes one fake authentication response. | assertionFixture 描述一个伪造认证响应。
type assertionFixture struct {
	signer     testSigner
	credID     []byte
	flags      Flags
	signCount  uint32
	rpID       string
	origin     string
	userHandle []byte
}

func defaultAssertionFixture(signer testSigner, credID []byte) *assertionFixture {
	return &assertionFixture{
		signer: signer,
		credID: append([]byte(nil), credID...),
		flags:  FlagUserPresent,
		rpID:   testRPID,
		origin: testOrigin,
	}
}

// assertionResponse builds the navigator response for fixture. | assertionResponse 为 fixture 构建 navigator 响应。
func (f *assertionFixture) assertionResponse(t *testing.T, options *CredentialRequestOptions) *CredentialAssertionResponse {
	t.Helper()
	clientData := &ClientData{
		Type:      ClientDataTypeGet,
		Challenge: options.PublicKey.Challenge,
		Origin:    f.origin,
	}
	clientDataJSON := mustMarshal(t, clientData)
	authData := buildAuthData(t, f.rpID, f.flags, f.signCount, [16]byte{}, nil, nil, nil)
	clientDataHash := sha256.Sum256(clientDataJSON)
	signature := f.signer.sign(t, signedAttestationData(authData, clientDataHash[:]))
	response := AuthenticatorAssertionResponse{
		ClientDataJSON:    b64(clientDataJSON),
		AuthenticatorData: b64(authData),
		Signature:         b64(signature),
	}
	if f.userHandle != nil {
		response.UserHandle = b64(f.userHandle)
	}
	return &CredentialAssertionResponse{
		ID:       b64(f.credID),
		RawID:    b64(f.credID),
		Type:     "public-key",
		Response: response,
	}
}

// login runs a full user-bound authentication for fixture. | login 为 fixture 运行完整用户绑定认证。
func (f *assertionFixture) login(t *testing.T, service *Service, user *auth.User) *Credential {
	t.Helper()
	options, ceremony, err := service.BeginLogin(context.Background(), user, LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	credential, err := service.FinishLogin(context.Background(), ceremony, f.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	return credential
}

// newTestAttestationCert returns a self-signed EC attestation certificate. | newTestAttestationCert 返回自签名 EC 认证证书。
func newTestAttestationCert(t *testing.T, signer *ecSigner) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Attestation"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.key.Public(), signer.key)
	if err != nil {
		t.Fatalf("create attestation certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse attestation certificate: %v", err)
	}
	return cert
}

// certificateRoots returns a pool containing cert. | certificateRoots 返回包含 cert 的信任锚池。
func certificateRoots(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
