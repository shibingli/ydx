package kmip

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/shibingli/ydx/auth/token/jose"
)

// mustJWK encodes a JWK or fails the test. | mustJWK 编码 JWK，失败时终止测试。
func mustJWK(t *testing.T, key *jose.Key) []byte {
	t.Helper()
	data, err := key.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	return data
}

// jwkKeyBlock builds a JWK key block. | jwkKeyBlock 构造 JWK 密钥块。
func jwkKeyBlock(t *testing.T, algorithm CryptographicAlgorithm, key *jose.Key) KeyBlock {
	t.Helper()
	return KeyBlock{Format: KeyFormatJWK, Algorithm: algorithm, Value: NewRawKeyValue(mustJWK(t, key))}
}

// registerObject registers one object and returns its identifier. | registerObject 注册一个对象并返回其标识符。
func registerObject(t *testing.T, server *Server, objectType ObjectType, object Object) string {
	t.Helper()
	response, err := DecodeRegisterResponse(runOp(t, server, OpRegister, RegisterRequest{
		ObjectType: objectType,
		Object:     object,
	}))
	if err != nil {
		t.Fatalf("DecodeRegisterResponse: %v", err)
	}
	return response.UniqueIdentifier
}

// getJWK fetches an object as JWK and parses the returned key. | getJWK 以 JWK 获取对象并解析返回的密钥。
func getJWK(t *testing.T, server *Server, uid string) (*jose.Key, KeyBlock) {
	t.Helper()
	response, err := DecodeGetResponse(runOp(t, server, OpGet, GetRequest{UniqueIdentifier: uid, KeyFormatType: KeyFormatJWK}))
	if err != nil {
		t.Fatalf("DecodeGetResponse: %v", err)
	}
	kb, err := response.Object.KeyBlock()
	if err != nil {
		t.Fatalf("KeyBlock: %v", err)
	}
	if kb.Format != KeyFormatJWK {
		t.Fatalf("format = %s, want JWK | 格式 = %s，期望 JWK", kb.Format, kb.Format)
	}
	material, err := kb.Value.Material.AsByteString()
	if err != nil {
		t.Fatalf("MaterialBytes: %v", err)
	}
	key, err := jose.ParseKey(material)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	return key, *kb
}

// objectForType wraps a key block in the matching private or public object. | objectForType 把密钥块包装为匹配的私钥或
// 公钥对象。
func objectForType(objectType ObjectType, kb KeyBlock) Object {
	switch objectType {
	case ObjectTypePublicKey:
		return NewPublicKeyObject(kb)
	case ObjectTypeSymmetricKey:
		return NewSymmetricKeyObject(kb)
	default:
		return NewPrivateKeyObject(kb)
	}
}

// TestJWKRegisterGetKeyTypes covers JWK import, algorithm inference, metadata preservation and private/public
// extraction for every supported key family. | TestJWKRegisterGetKeyTypes 覆盖所有受支持密钥族的 JWK 导入、算法推断、
// 元数据保留以及私钥/公钥提取。
func TestJWKRegisterGetKeyTypes(t *testing.T) {
	server := newTestServer(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rsaJWK, err := jose.FromPrivateKey("rsa-kid", rsaKey)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}
	rsaJWK.Use = "sig"
	rsaJWK.Alg = "RS256"

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecJWK, err := jose.FromPrivateKey("ec-kid", ecKey)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}

	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	edJWK, err := jose.FromPrivateKey("ed-kid", edPrivate)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}

	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	xJWK, err := jose.FromPrivateKey("x-kid", xKey)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}

	symmetricJWK, err := jose.FromHMAC("oct-kid", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("FromHMAC: %v", err)
	}
	symmetricJWK.Alg = "HS256"
	symmetricJWK.Use = "sig"

	for _, testCase := range []struct {
		name       string
		objectType ObjectType
		algorithm  CryptographicAlgorithm
		key        *jose.Key
		wantKty    string
		wantCrv    string
		wantAlg    CryptographicAlgorithm
		wantKid    string
		wantD      bool
	}{
		{"RSA private", ObjectTypePrivateKey, 0, rsaJWK, jose.KeyTypeRSA, "", AlgorithmRSA, "rsa-kid", true},
		{"EC private", ObjectTypePrivateKey, 0, ecJWK, jose.KeyTypeEC, jose.CurveP256, AlgorithmECDSA, "ec-kid", true},
		{"Ed25519 private", ObjectTypePrivateKey, 0, edJWK, jose.KeyTypeOKP, jose.CurveEd25519, AlgorithmEd25519, "ed-kid", true},
		{"X25519 private", ObjectTypePrivateKey, 0, xJWK, jose.KeyTypeOKP, jose.CurveX25519, AlgorithmECDH, "x-kid", true},
		{"oct symmetric", ObjectTypeSymmetricKey, 0, symmetricJWK, jose.KeyTypeOct, "", AlgorithmHMACSHA256, "oct-kid", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			object := objectForType(testCase.objectType, jwkKeyBlock(t, testCase.algorithm, testCase.key))
			uid := registerObject(t, server, testCase.objectType, object)
			got, kb := getJWK(t, server, uid)
			if got.Kty != testCase.wantKty || got.Crv != testCase.wantCrv {
				t.Fatalf("JWK = kty %q crv %q | JWK = kty %q crv %q", got.Kty, got.Crv, got.Kty, got.Crv)
			}
			if got.Kid != testCase.wantKid {
				t.Fatalf("kid = %q, want %q | kid = %q，期望 %q", got.Kid, testCase.wantKid, got.Kid, testCase.wantKid)
			}
			if testCase.algorithm == 0 && kb.Algorithm != testCase.wantAlg {
				t.Fatalf("inferred algorithm = %s, want %s | 推断算法 = %s，期望 %s", kb.Algorithm, testCase.wantAlg, kb.Algorithm, testCase.wantAlg)
			}
			hasPrivate := got.D != ""
			if hasPrivate != testCase.wantD {
				t.Fatalf("private material present = %v, want %v | 私钥材料存在 = %v，期望 %v", hasPrivate, testCase.wantD, hasPrivate, testCase.wantD)
			}
			if testCase.name == "oct symmetric" {
				if got.Alg != "HS256" || got.Use != "sig" {
					t.Fatalf("metadata = alg %q use %q | 元数据 = alg %q use %q", got.Alg, got.Use, got.Alg, got.Use)
				}
				if kb.Length != 256 {
					t.Fatalf("symmetric length = %d | 对称长度 = %d", kb.Length, kb.Length)
				}
			}
		})
	}

	publicJWK, err := jose.FromPublicKey("rsa-public-kid", &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	publicUID := registerObject(t, server, ObjectTypePublicKey, NewPublicKeyObject(jwkKeyBlock(t, AlgorithmRSA, publicJWK)))
	gotPublic, _ := getJWK(t, server, publicUID)
	if gotPublic.D != "" || gotPublic.Kid != "rsa-public-kid" {
		t.Fatalf("public JWK leaked private material or lost kid | 公钥 JWK 泄露私钥材料或丢失 kid")
	}

	edPublicJWK, err := jose.FromPublicKey("ed-public-kid", edPublic)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	edPublicUID := registerObject(t, server, ObjectTypePublicKey, NewPublicKeyObject(jwkKeyBlock(t, AlgorithmEd25519, edPublicJWK)))
	if got, _ := getJWK(t, server, edPublicUID); got.D != "" || got.Crv != jose.CurveEd25519 {
		t.Fatalf("Ed25519 public JWK = %+v | Ed25519 公钥 JWK = %+v", got, got)
	}
}

// TestJWKCreateAndFormatConversion covers Create with JWK as the requested format plus PKCS#8 and raw conversion.
// | TestJWKCreateAndFormatConversion 覆盖以 JWK 作为请求格式的 Create 以及 PKCS#8 与原始格式转换。
func TestJWKCreateAndFormatConversion(t *testing.T) {
	server := newTestServer(t)
	template := TemplateAttribute{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmAES)),
		NewIntegerAttribute(AttributeCryptographicLength, 256),
		NewEnumerationAttribute(AttributeKeyFormatType, uint32(KeyFormatJWK)),
	}}
	created, err := DecodeCreateResponse(runOp(t, server, OpCreate, CreateRequest{
		ObjectType:        ObjectTypeSymmetricKey,
		TemplateAttribute: template,
	}))
	if err != nil {
		t.Fatalf("DecodeCreateResponse: %v", err)
	}
	key, kb := getJWK(t, server, created.UniqueIdentifier)
	if key.Kty != jose.KeyTypeOct || kb.Algorithm != AlgorithmAES || kb.Length != 256 {
		t.Fatalf("created JWK = kty %q algorithm %s length %d | 创建的 JWK = kty %q 算法 %s 长度 %d",
			key.Kty, kb.Algorithm, kb.Length, key.Kty, kb.Algorithm, kb.Length)
	}
	rawResponse, err := DecodeGetResponse(runOp(t, server, OpGet, GetRequest{UniqueIdentifier: created.UniqueIdentifier, KeyFormatType: KeyFormatRaw}))
	if err != nil {
		t.Fatalf("raw Get: %v", err)
	}
	rawBlock, err := rawResponse.Object.KeyBlock()
	if err != nil || rawBlock.Format != KeyFormatRaw {
		t.Fatalf("raw block = %+v, %v | 原始块 = %+v，%v", rawBlock, err, rawBlock, err)
	}

	pairTemplate := TemplateAttribute{Attributes: AttributeList{
		NewEnumerationAttribute(AttributeCryptographicAlgorithm, uint32(AlgorithmRSA)),
		NewIntegerAttribute(AttributeCryptographicLength, 2048),
		NewEnumerationAttribute(AttributeKeyFormatType, uint32(KeyFormatJWK)),
	}}
	pair, err := DecodeCreateKeyPairResponse(runOp(t, server, OpCreateKeyPair, CreateKeyPairRequest{
		CommonTemplateAttribute: &pairTemplate,
	}))
	if err != nil {
		t.Fatalf("DecodeCreateKeyPairResponse: %v", err)
	}
	privateJWK, privateBlock := getJWK(t, server, pair.PrivateKeyUniqueIdentifier)
	publicJWK, publicBlock := getJWK(t, server, pair.PublicKeyUniqueIdentifier)
	if privateJWK.Kty != jose.KeyTypeRSA || privateJWK.D == "" || publicJWK.D != "" {
		t.Fatalf("key pair JWK private/public extraction failed | 密钥对 JWK 私钥/公钥提取失败")
	}
	if privateBlock.Algorithm != AlgorithmRSA || publicBlock.Algorithm != AlgorithmRSA {
		t.Fatalf("key pair algorithms = %s/%s | 密钥对算法 = %s/%s", privateBlock.Algorithm, publicBlock.Algorithm, privateBlock.Algorithm, publicBlock.Algorithm)
	}
	pkcs8, err := DecodeGetResponse(runOp(t, server, OpGet, GetRequest{UniqueIdentifier: pair.PrivateKeyUniqueIdentifier, KeyFormatType: KeyFormatPKCS8}))
	if err != nil {
		t.Fatalf("PKCS#8 Get: %v", err)
	}
	if kb, err := pkcs8.Object.KeyBlock(); err != nil || kb.Format != KeyFormatPKCS8 {
		t.Fatalf("PKCS#8 block = %+v, %v | PKCS#8 块 = %+v，%v", kb, err, kb, err)
	}
}

// TestJWKErrors covers malformed JWK, unknown key types, algorithm mismatches and SM2 rejection. |
// TestJWKErrors 覆盖非法 JWK、未知密钥类型、算法不匹配与 SM2 拒绝。
func TestJWKErrors(t *testing.T) {
	server := newTestServer(t)
	for _, testCase := range []struct {
		name      string
		algorithm CryptographicAlgorithm
		material  []byte
		want      error
	}{
		{"malformed", AlgorithmRSA, []byte("{not-json"), ErrCryptographic},
		{"unknown kty", 0, []byte(`{"kty":"BAD"}`), ErrUnsupported},
		{"empty", AlgorithmRSA, nil, ErrCryptographic},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			item := runOpItem(t, server, OpRegister, RegisterRequest{
				ObjectType: ObjectTypePrivateKey,
				Object:     NewPrivateKeyObject(KeyBlock{Format: KeyFormatJWK, Algorithm: testCase.algorithm, Value: NewRawKeyValue(testCase.material)}),
			})
			if !errors.Is(item.Err(), testCase.want) {
				t.Fatalf("error = %v, want %v | 错误 = %v，期望 %v", item.Err(), testCase.want, item.Err(), testCase.want)
			}
		})
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rsaJWK, err := jose.FromPrivateKey("mismatch", rsaKey)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}
	mismatch := runOpItem(t, server, OpRegister, RegisterRequest{
		ObjectType: ObjectTypePrivateKey,
		Object:     NewPrivateKeyObject(jwkKeyBlock(t, AlgorithmAES, rsaJWK)),
	})
	if !errors.Is(mismatch.Err(), ErrCryptographic) {
		t.Fatalf("algorithm mismatch error = %v | 算法不匹配错误 = %v", mismatch.Err(), mismatch.Err())
	}
	sm2 := runOpItem(t, server, OpRegister, RegisterRequest{
		ObjectType: ObjectTypePrivateKey,
		Object:     NewPrivateKeyObject(jwkKeyBlock(t, AlgorithmSM2, rsaJWK)),
	})
	if !errors.Is(sm2.Err(), ErrUnsupported) {
		t.Fatalf("SM2 JWK error = %v | SM2 JWK 错误 = %v", sm2.Err(), sm2.Err())
	}
	if _, err := parseKeyBlock(KeyBlock{Format: KeyFormatJWK, Value: NewRawKeyValue([]byte("{}"))}); err == nil {
		t.Fatal("parseKeyBlock accepted an empty JWK | parseKeyBlock 接受了空 JWK")
	}
}

// TestJWKConversionFromNativeFormats covers converting PKCS#8, PKIX and raw keys into JWK. |
// TestJWKConversionFromNativeFormats 覆盖把 PKCS#8、PKIX 与原始密钥转换为 JWK。
func TestJWKConversionFromNativeFormats(t *testing.T) {
	server := newTestServer(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	privateKeys := []struct {
		name string
		key  any
		kty  string
	}{
		{"RSA", rsaKey, jose.KeyTypeRSA},
		{"EC", ecKey, jose.KeyTypeEC},
		{"Ed25519", edPrivate, jose.KeyTypeOKP},
		{"X25519", xKey, jose.KeyTypeOKP},
	}
	for _, testCase := range privateKeys {
		t.Run(testCase.name+" private", func(t *testing.T) {
			der, err := x509.MarshalPKCS8PrivateKey(testCase.key)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
			}
			uid := registerObject(t, server, ObjectTypePrivateKey, NewPrivateKeyObject(KeyBlock{
				Format: KeyFormatPKCS8, Value: NewRawKeyValue(der),
			}))
			got, _ := getJWK(t, server, uid)
			if got.Kty != testCase.kty || got.D == "" {
				t.Fatalf("converted private JWK = kty %q d %v | 转换私钥 JWK = kty %q d %v", got.Kty, got.D != "", got.Kty, got.D != "")
			}
		})
	}
	publicKeys := []struct {
		name string
		key  any
		kty  string
	}{
		{"RSA", &rsaKey.PublicKey, jose.KeyTypeRSA},
		{"EC", &ecKey.PublicKey, jose.KeyTypeEC},
		{"Ed25519", edPublic, jose.KeyTypeOKP},
		{"X25519", xKey.PublicKey(), jose.KeyTypeOKP},
	}
	for _, testCase := range publicKeys {
		t.Run(testCase.name+" public", func(t *testing.T) {
			der, err := x509.MarshalPKIXPublicKey(testCase.key)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey: %v", err)
			}
			uid := registerObject(t, server, ObjectTypePublicKey, NewPublicKeyObject(KeyBlock{
				Format: KeyFormatX509, Value: NewRawKeyValue(der),
			}))
			got, _ := getJWK(t, server, uid)
			if got.Kty != testCase.kty || got.D != "" {
				t.Fatalf("converted public JWK = kty %q d %v | 转换公钥 JWK = kty %q d %v", got.Kty, got.D != "", got.Kty, got.D != "")
			}
		})
	}

	uid := registerObject(t, server, ObjectTypeSymmetricKey, NewSymmetricKeyObject(rawKeyBlock(AlgorithmAES, []byte("0123456789abcdef0123456789abcdef"))))
	got, _ := getJWK(t, server, uid)
	if got.Kty != jose.KeyTypeOct || got.K == "" {
		t.Fatalf("converted oct JWK = %+v | 转换 oct JWK = %+v", got, got)
	}
}

// TestJWKAlgorithmMapping covers JWK algorithm inference and compatibility decisions. |
// TestJWKAlgorithmMapping 覆盖 JWK 算法推断与兼容性判定。
func TestJWKAlgorithmMapping(t *testing.T) {
	for _, testCase := range []struct {
		alg  string
		size int
		want CryptographicAlgorithm
	}{
		{"HS256", 32, AlgorithmHMACSHA256},
		{"HS384", 48, AlgorithmHMACSHA384},
		{"HS512", 64, AlgorithmHMACSHA512},
		{"A128GCM", 16, AlgorithmAES},
		{"A192CBC-HS384", 24, AlgorithmAES},
		{"A256KW", 32, AlgorithmAES},
		{"SM4-GCM", 16, AlgorithmSM4},
		{"", 16, AlgorithmAES},
		{"", 24, AlgorithmAES},
		{"", 32, AlgorithmAES},
		{"", 48, AlgorithmHMACSHA384},
		{"", 64, AlgorithmHMACSHA512},
		{"", 20, AlgorithmHMACSHA256},
	} {
		key, err := jose.FromHMAC("", make([]byte, testCase.size))
		if err != nil {
			t.Fatalf("FromHMAC: %v", err)
		}
		key.Alg = testCase.alg
		got, err := inferJWKAlgorithm(key)
		if err != nil || got != testCase.want {
			t.Fatalf("inferJWKAlgorithm(alg=%q size=%d) = %s, %v | 推断 = %s，%v", testCase.alg, testCase.size, got, err, got, err)
		}
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecJWK, err := jose.FromPrivateKey("", ecKey)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}
	for _, alg := range []string{"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"} {
		if !isECDHJWKAlgorithm(alg) {
			t.Fatalf("isECDHJWKAlgorithm(%q) = false | isECDHJWKAlgorithm(%q) = false", alg, alg)
		}
	}
	if isECDHJWKAlgorithm("ES256") {
		t.Fatal("ES256 reported as ECDH | ES256 被判定为 ECDH")
	}
	ecJWK.Alg = "ECDH-ES"
	if got, err := inferJWKAlgorithm(ecJWK); err != nil || got != AlgorithmECDH {
		t.Fatalf("EC ECDH-ES algorithm = %s, %v | EC ECDH-ES 算法 = %s，%v", got, err, got, err)
	}
	ecJWK.Alg = "ES256"
	if got, err := inferJWKAlgorithm(ecJWK); err != nil || got != AlgorithmECDSA {
		t.Fatalf("EC ES256 algorithm = %s, %v | EC ES256 算法 = %s，%v", got, err, got, err)
	}
	if !jwkAlgorithmCompatible(ecJWK, AlgorithmEC, AlgorithmECDSA) || !jwkAlgorithmCompatible(ecJWK, AlgorithmECDH, AlgorithmECDSA) {
		t.Fatal("EC key reported incompatible with EC/ECDH | EC 密钥被判定与 EC/ECDH 不兼容")
	}
	octKey, err := jose.FromHMAC("", make([]byte, 32))
	if err != nil {
		t.Fatalf("FromHMAC: %v", err)
	}
	if !jwkAlgorithmCompatible(octKey, AlgorithmSM4, AlgorithmAES) || jwkAlgorithmCompatible(octKey, AlgorithmRSA, AlgorithmAES) {
		t.Fatal("oct compatibility decision is wrong | oct 兼容性判定错误")
	}
	for _, alg := range []CryptographicAlgorithm{AlgorithmAES, AlgorithmSM4, AlgorithmHMACSHA1, AlgorithmHMACSHA224, AlgorithmHMACSHA256, AlgorithmHMACSHA384, AlgorithmHMACSHA512, AlgorithmHMACMD5} {
		if !isSymmetricAlgorithm(alg) {
			t.Fatalf("isSymmetricAlgorithm(%s) = false | isSymmetricAlgorithm(%s) = false", alg, alg)
		}
	}
	if isSymmetricAlgorithm(AlgorithmRSA) {
		t.Fatal("RSA reported as symmetric | RSA 被判定为对称算法")
	}
}
