package kmip

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"github.com/shibingli/ydx/guomi"
)

// rawKeyBlock builds a Raw key block with the given algorithm and material. | rawKeyBlock 构造指定算法与材料的 Raw 密钥块。
func rawKeyBlock(algorithm CryptographicAlgorithm, material []byte) KeyBlock {
	return KeyBlock{
		Format:    KeyFormatRaw,
		Algorithm: algorithm,
		Length:    len(material) * 8,
		Value:     NewRawKeyValue(material),
	}
}

// mustKeyPair generates a key pair or fails the test. | mustKeyPair 生成密钥对，失败时终止测试。
func mustKeyPair(t *testing.T, algorithm CryptographicAlgorithm, lengthBits int) (KeyBlock, KeyBlock) {
	t.Helper()
	private, public, err := generateKeyPairKeyBlocks(algorithm, lengthBits)
	if err != nil {
		t.Fatalf("generateKeyPairKeyBlocks(%s, %d): %v | 生成密钥对失败：%v", algorithm, lengthBits, err, err)
	}
	return private, public
}

// mustParseKeyBlock parses a key block or fails the test. | mustParseKeyBlock 解析密钥块，失败时终止测试。
func mustParseKeyBlock(t *testing.T, kb KeyBlock) *parsedKey {
	t.Helper()
	parsed, err := parseKeyBlock(kb)
	if err != nil {
		t.Fatalf("parseKeyBlock(%s): %v | 解析密钥块失败：%v", kb.Format, err, err)
	}
	t.Cleanup(parsed.zeroize)
	return parsed
}

// compressECPoint returns a compressed SEC1 encoding of an EC point without using deprecated helpers. |
// compressECPoint 返回 EC 点的压缩 SEC1 编码，不使用已弃用的辅助函数。
func compressECPoint(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	uncompressed, err := pub.Bytes()
	if err != nil || len(uncompressed) == 0 || uncompressed[0] != 4 {
		t.Fatalf("encode uncompressed EC point: %v | 编码未压缩 EC 点失败：%v", err, err)
	}
	size := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+size)
	out[0] = 0x02 | uncompressed[len(uncompressed)-1]&1
	copy(out[1:], uncompressed[1:1+size])
	return out
}

// TestGenerateSymmetricKeyBlock covers symmetric key generation and its length rules. |
// TestGenerateSymmetricKeyBlock 覆盖对称密钥生成及其长度规则。
func TestGenerateSymmetricKeyBlock(t *testing.T) {
	cases := []struct {
		name      string
		algorithm CryptographicAlgorithm
		length    int
		wantLen   int
		wantBits  int
	}{
		{"AES default", AlgorithmAES, 0, 32, 256},
		{"AES 128", AlgorithmAES, 128, 16, 128},
		{"AES 192", AlgorithmAES, 192, 24, 192},
		{"AES 256", AlgorithmAES, 256, 32, 256},
		{"SM4 default", AlgorithmSM4, 0, 16, 128},
		{"SM4 128", AlgorithmSM4, 128, 16, 128},
		{"HMAC-SHA1 default", AlgorithmHMACSHA1, 0, 32, 256},
		{"HMAC-SHA224 512", AlgorithmHMACSHA224, 512, 64, 512},
		{"HMAC-SHA256 64", AlgorithmHMACSHA256, 64, 8, 64},
		{"HMAC-SHA384 4096", AlgorithmHMACSHA384, 4096, 512, 4096},
		{"HMAC-SHA512 1024", AlgorithmHMACSHA512, 1024, 128, 1024},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			kb, err := generateSymmetricKeyBlock(testCase.algorithm, testCase.length)
			if err != nil {
				t.Fatalf("generateSymmetricKeyBlock: %v | 生成对称密钥失败：%v", err, err)
			}
			if kb.Format != KeyFormatRaw || kb.Algorithm != testCase.algorithm || kb.Length != testCase.wantBits {
				t.Fatalf("block = %s/%s/%d | 密钥块 = %s/%s/%d", kb.Format, kb.Algorithm, kb.Length, kb.Format, kb.Algorithm, kb.Length)
			}
			if got := len(kb.Value.Material.Value); got != testCase.wantLen {
				t.Fatalf("material length = %d, want %d | 材料长度 = %d，期望 %d", got, testCase.wantLen, got, testCase.wantLen)
			}
			parsed, err := parseKeyBlock(kb)
			if err != nil {
				t.Fatalf("parse generated key: %v | 解析生成的密钥失败：%v", err, err)
			}
			parsed.zeroize()
		})
	}
	first, _ := generateSymmetricKeyBlock(AlgorithmAES, 256)
	second, _ := generateSymmetricKeyBlock(AlgorithmAES, 256)
	if bytes.Equal(first.Value.Material.Value, second.Value.Material.Value) {
		t.Fatal("two generated keys are identical | 两次生成的密钥相同")
	}

	errorCases := []struct {
		name      string
		algorithm CryptographicAlgorithm
		length    int
		want      error
	}{
		{"AES 100", AlgorithmAES, 100, ErrInvalidRequest},
		{"AES 512", AlgorithmAES, 512, ErrInvalidRequest},
		{"SM4 256", AlgorithmSM4, 256, ErrInvalidRequest},
		{"HMAC 60", AlgorithmHMACSHA256, 60, ErrInvalidRequest},
		{"HMAC 5000", AlgorithmHMACSHA256, 5000, ErrInvalidRequest},
		{"HMAC 100", AlgorithmHMACSHA256, 100, ErrInvalidRequest},
		{"unsupported RSA", AlgorithmRSA, 256, ErrUnsupported},
		{"unsupported HMAC-MD5", AlgorithmHMACMD5, 256, ErrUnsupported},
	}
	for _, testCase := range errorCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := generateSymmetricKeyBlock(testCase.algorithm, testCase.length); !errors.Is(err, testCase.want) {
				t.Fatalf("error = %v, want %v | 错误 = %v，期望 %v", err, testCase.want, err, testCase.want)
			}
		})
	}
}

// TestGenerateKeyPairKeyBlocks covers every supported key pair algorithm. | TestGenerateKeyPairKeyBlocks
// 覆盖所有支持的密钥对算法。
func TestGenerateKeyPairKeyBlocks(t *testing.T) {
	cases := []struct {
		name      string
		algorithm CryptographicAlgorithm
		length    int
		wantAlg   CryptographicAlgorithm
		wantBits  int
	}{
		{"RSA default", AlgorithmRSA, 0, AlgorithmRSA, 2048},
		{"ECDSA default", AlgorithmECDSA, 0, AlgorithmECDSA, 256},
		{"ECDSA P384", AlgorithmECDSA, 384, AlgorithmECDSA, 384},
		{"ECDSA P521", AlgorithmECDSA, 521, AlgorithmECDSA, 521},
		{"EC 256", AlgorithmEC, 256, AlgorithmECDSA, 256},
		{"Ed25519 default", AlgorithmEd25519, 0, AlgorithmEd25519, 256},
		{"Ed25519 256", AlgorithmEd25519, 256, AlgorithmEd25519, 256},
		{"SM2 default", AlgorithmSM2, 0, AlgorithmSM2, 256},
		{"SM2 256", AlgorithmSM2, 256, AlgorithmSM2, 256},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			private, public := mustKeyPair(t, testCase.algorithm, testCase.length)
			if private.Format != KeyFormatPKCS8 && testCase.algorithm != AlgorithmSM2 {
				t.Fatalf("private format = %s, want PKCS#8 | 私钥格式 = %s，期望 PKCS#8", private.Format, private.Format)
			}
			if public.Format != KeyFormatX509 && testCase.algorithm != AlgorithmSM2 {
				t.Fatalf("public format = %s, want X.509 | 公钥格式 = %s，期望 X.509", public.Format, public.Format)
			}
			if private.Algorithm != testCase.wantAlg || private.Length != testCase.wantBits {
				t.Fatalf("private = %s/%d, want %s/%d | 私钥 = %s/%d，期望 %s/%d",
					private.Algorithm, private.Length, testCase.wantAlg, testCase.wantBits,
					private.Algorithm, private.Length, testCase.wantAlg, testCase.wantBits)
			}
			if public.Algorithm != testCase.wantAlg || public.Length != testCase.wantBits {
				t.Fatalf("public = %s/%d, want %s/%d | 公钥 = %s/%d，期望 %s/%d",
					public.Algorithm, public.Length, testCase.wantAlg, testCase.wantBits,
					public.Algorithm, public.Length, testCase.wantAlg, testCase.wantBits)
			}
			privateKey := mustParseKeyBlock(t, private)
			if testCase.algorithm == AlgorithmRSA {
				if privateKey.rsaPrivate == nil {
					t.Fatal("RSA private key not parsed | RSA 私钥未解析")
				}
			} else if testCase.algorithm == AlgorithmEd25519 {
				if privateKey.edPrivate == nil {
					t.Fatal("Ed25519 private key not parsed | Ed25519 私钥未解析")
				}
			} else if testCase.algorithm == AlgorithmSM2 {
				if privateKey.sm2Private == nil {
					t.Fatal("SM2 private key not parsed | SM2 私钥未解析")
				}
			} else if privateKey.ecPrivate == nil {
				t.Fatal("EC private key not parsed | EC 私钥未解析")
			}
			publicKey := mustParseKeyBlock(t, public)
			if publicKey.rsaPublic == nil && publicKey.ecPublic == nil && publicKey.edPublic == nil && publicKey.sm2Public == nil {
				t.Fatal("public key not parsed | 公钥未解析")
			}
		})
	}

	errorCases := []struct {
		name      string
		algorithm CryptographicAlgorithm
		length    int
		want      error
	}{
		{"RSA 1024", AlgorithmRSA, 1024, ErrInvalidRequest},
		{"RSA 9000", AlgorithmRSA, 9000, ErrInvalidRequest},
		{"ECDSA 123", AlgorithmECDSA, 123, ErrUnsupported},
		{"Ed25519 128", AlgorithmEd25519, 128, ErrInvalidRequest},
		{"SM2 128", AlgorithmSM2, 128, ErrInvalidRequest},
		{"unsupported AES", AlgorithmAES, 256, ErrUnsupported},
		{"unsupported Ed448", AlgorithmEd448, 256, ErrUnsupported},
	}
	for _, testCase := range errorCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := generateKeyPairKeyBlocks(testCase.algorithm, testCase.length)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("error = %v, want %v | 错误 = %v，期望 %v", err, testCase.want, err, testCase.want)
			}
		})
	}
}

// TestCurveMappings covers the curve lookup helpers. | TestCurveMappings 覆盖曲线查找辅助函数。
func TestCurveMappings(t *testing.T) {
	for _, testCase := range []struct {
		length int
		bits   int
	}{
		{0, 256}, {256, 256}, {384, 384}, {521, 521},
	} {
		curve, err := curveForLength(testCase.length)
		if err != nil {
			t.Fatalf("curveForLength(%d): %v | 曲线查找失败：%v", testCase.length, err, err)
		}
		if got := curveBits(curve); got != testCase.bits {
			t.Fatalf("curveForLength(%d) bits = %d, want %d | 曲线位长 = %d，期望 %d", testCase.length, got, testCase.bits, got, testCase.bits)
		}
	}
	if _, err := curveForLength(123); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("curveForLength(123) error = %v | 非法曲线长度错误 = %v", err, err)
	}

	mappings := []struct {
		curve RecommendedCurve
		want  elliptic.Curve
	}{
		{CurveP224, elliptic.P224()},
		{CurveP256, elliptic.P256()},
		{CurveP384, elliptic.P384()},
		{CurveP521, elliptic.P521()},
	}
	for _, testCase := range mappings {
		curve, err := curveFor(testCase.curve)
		if err != nil {
			t.Fatalf("curveFor(%v): %v | 推荐曲线查找失败：%v", testCase.curve, err, err)
		}
		if curveBits(curve) != curveBits(testCase.want) {
			t.Fatalf("curveFor(%v) bits = %d | 推荐曲线位长 = %d", testCase.curve, curveBits(curve), curveBits(curve))
		}
		back, err := recommendedCurveFor(curve)
		if err != nil || back != testCase.curve {
			t.Fatalf("recommendedCurveFor(%d) = %v, %v | 反向曲线映射 = %v，%v", curveBits(curve), back, err, back, err)
		}
	}
	if _, err := curveFor(CurveP192); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("curveFor(P192) error = %v | P192 错误 = %v", err, err)
	}
	if _, err := recommendedCurveFor(testCurve{elliptic.P256()}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("recommendedCurveFor(custom) error = %v | 自定义曲线错误 = %v", err, err)
	}
}

// testCurve wraps a curve so that it does not compare equal to a standard curve. |
// testCurve 包装曲线，使其不与标准曲线比较相等。
type testCurve struct{ elliptic.Curve }

// TestParseSymmetricKeyBlocks covers Raw and Transparent Symmetric Key parsing. |
// TestParseSymmetricKeyBlocks 覆盖 Raw 与透明对称密钥解析。
func TestParseSymmetricKeyBlocks(t *testing.T) {
	material := bytes.Repeat([]byte{0x42}, 16)
	parsed := mustParseKeyBlock(t, rawKeyBlock(AlgorithmAES, material))
	if parsed.algorithm != AlgorithmAES || !bytes.Equal(parsed.symmetric, material) {
		t.Fatalf("AES parsed = %s/%x | AES 解析结果 = %s/%x", parsed.algorithm, parsed.symmetric, parsed.algorithm, parsed.symmetric)
	}
	parsed = mustParseKeyBlock(t, rawKeyBlock(AlgorithmHMACSHA512, material))
	if parsed.algorithm != AlgorithmHMACSHA512 || len(parsed.symmetric) != 16 {
		t.Fatalf("HMAC parsed = %s/%d | HMAC 解析结果 = %s/%d", parsed.algorithm, len(parsed.symmetric), parsed.algorithm, len(parsed.symmetric))
	}

	// Unlabelled material is inferred from its length. | 未标注材料按长度推断算法。
	for _, length := range []int{16, 24, 32} {
		parsed = mustParseKeyBlock(t, rawKeyBlock(0, bytes.Repeat([]byte{1}, length)))
		if parsed.algorithm != AlgorithmAES {
			t.Fatalf("inferred algorithm = %s, want AES | 推断算法 = %s，期望 AES", parsed.algorithm, parsed.algorithm)
		}
	}
	if _, err := parseKeyBlock(rawKeyBlock(0, []byte{1, 2, 3})); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("uninferable material error = %v | 无法推断材料错误 = %v", err, err)
	}
	if _, err := parseKeyBlock(rawKeyBlock(AlgorithmChaCha20Poly1305, material)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported algorithm error = %v | 不支持算法错误 = %v", err, err)
	}

	transparent := KeyBlock{
		Format: KeyFormatTransparentSymmetricKey,
		Value:  KeyValue{Material: TransparentSymmetricKey{Key: material}.Item()},
	}
	parsed = mustParseKeyBlock(t, transparent)
	if parsed.algorithm != AlgorithmAES || !bytes.Equal(parsed.symmetric, material) {
		t.Fatalf("transparent default = %s/%x | 透明默认 = %s/%x", parsed.algorithm, parsed.symmetric, parsed.algorithm, parsed.symmetric)
	}
	transparent.Algorithm = AlgorithmSM4
	parsed = mustParseKeyBlock(t, transparent)
	if parsed.algorithm != AlgorithmSM4 {
		t.Fatalf("transparent SM4 algorithm = %s | 透明 SM4 算法 = %s", parsed.algorithm, parsed.algorithm)
	}
	badTransparent := KeyBlock{
		Format: KeyFormatTransparentSymmetricKey,
		Value:  KeyValue{Material: NewByteString(TagKeyMaterial, material)},
	}
	if _, err := parseKeyBlock(badTransparent); !errors.Is(err, ErrMalformed) {
		t.Fatalf("transparent symmetric with raw material error = %v | 透明对称密钥使用原始材料错误 = %v", err, err)
	}
}

// TestParseTransparentAsymmetricKeys covers Transparent RSA and EC key parsing. |
// TestParseTransparentAsymmetricKeys 覆盖透明 RSA 与 EC 密钥解析。
func TestParseTransparentAsymmetricKeys(t *testing.T) {
	rsaPrivate := mustRSAKey(t)
	public := TransparentRSAPublicKey{Modulus: rsaPrivate.N, PublicExponent: big.NewInt(int64(rsaPrivate.E))}
	kb := KeyBlock{Format: KeyFormatTransparentRSAPublicKey, Value: KeyValue{Material: public.Item()}}
	parsed := mustParseKeyBlock(t, kb)
	if parsed.algorithm != AlgorithmRSA || parsed.rsaPublic == nil || parsed.rsaPublic.N.Cmp(rsaPrivate.N) != 0 {
		t.Fatal("transparent RSA public key not parsed | 透明 RSA 公钥未解析")
	}
	private := TransparentRSAPrivateKey{
		Modulus:         rsaPrivate.N,
		PrivateExponent: rsaPrivate.D,
		PublicExponent:  big.NewInt(int64(rsaPrivate.E)),
		P:               rsaPrivate.Primes[0],
		Q:               rsaPrivate.Primes[1],
		PrimeExponentP:  rsaPrivate.Precomputed.Dp,
		PrimeExponentQ:  rsaPrivate.Precomputed.Dq,
		CRTCoefficient:  rsaPrivate.Precomputed.Qinv,
	}
	kb = KeyBlock{Format: KeyFormatTransparentRSAPrivateKey, Value: KeyValue{Material: private.Item()}}
	parsed = mustParseKeyBlock(t, kb)
	if parsed.rsaPrivate == nil || parsed.rsaPrivate.N.Cmp(rsaPrivate.N) != 0 {
		t.Fatal("transparent RSA private key not parsed | 透明 RSA 私钥未解析")
	}
	minimal := TransparentRSAPrivateKey{
		Modulus:         rsaPrivate.N,
		PrivateExponent: rsaPrivate.D,
		PublicExponent:  big.NewInt(int64(rsaPrivate.E)),
	}
	kb = KeyBlock{Format: KeyFormatTransparentRSAPrivateKey, Value: KeyValue{Material: minimal.Item()}}
	parsed = mustParseKeyBlock(t, kb)
	if parsed.rsaPrivate == nil || len(parsed.rsaPrivate.Primes) != 0 {
		t.Fatal("transparent RSA private key without CRT not parsed | 无 CRT 的透明 RSA 私钥未解析")
	}

	huge := new(big.Int).Lsh(big.NewInt(1), 70)
	badPublic := KeyBlock{Format: KeyFormatTransparentRSAPublicKey, Value: KeyValue{
		Material: TransparentRSAPublicKey{Modulus: rsaPrivate.N, PublicExponent: huge}.Item(),
	}}
	if _, err := parseKeyBlock(badPublic); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("oversized RSA public exponent error = %v | 过大 RSA 公开指数字错误 = %v", err, err)
	}
	badPrivate := KeyBlock{Format: KeyFormatTransparentRSAPrivateKey, Value: KeyValue{
		Material: TransparentRSAPrivateKey{
			Modulus:         rsaPrivate.N,
			PrivateExponent: rsaPrivate.D,
			PublicExponent:  huge,
		}.Item(),
	}}
	if _, err := parseKeyBlock(badPrivate); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("oversized RSA private exponent error = %v | 过大 RSA 私密指数字错误 = %v", err, err)
	}
	invalidPrimes := KeyBlock{Format: KeyFormatTransparentRSAPrivateKey, Value: KeyValue{
		Material: TransparentRSAPrivateKey{
			Modulus:         big.NewInt(15),
			PrivateExponent: big.NewInt(3),
			PublicExponent:  big.NewInt(3),
			P:               big.NewInt(3),
			Q:               big.NewInt(7),
		}.Item(),
	}}
	if _, err := parseKeyBlock(invalidPrimes); err == nil {
		t.Fatal("invalid RSA primes accepted | 非法 RSA 素数被接受")
	}

	ecPrivate := mustECDSAKey(t)
	publicBytes, err := ecPrivate.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes: %v", err)
	}
	publicPoint := TransparentECPublicKey{RecommendedCurve: CurveP256, Q: publicBytes}
	kb = KeyBlock{Format: KeyFormatTransparentECPublicKey, Value: KeyValue{Material: publicPoint.Item()}}
	parsed = mustParseKeyBlock(t, kb)
	if parsed.ecPublic == nil {
		t.Fatal("transparent EC public key not parsed | 透明 EC 公钥未解析")
	}
	parsedPublic, err := parsed.ecPublic.Bytes()
	if err != nil || !bytes.Equal(parsedPublic, publicBytes) {
		t.Fatal("transparent EC public key not parsed | 透明 EC 公钥未解析")
	}
	compressed := TransparentECPublicKey{RecommendedCurve: CurveP256, Q: compressECPoint(t, &ecPrivate.PublicKey)}
	kb = KeyBlock{Format: KeyFormatTransparentECPublicKey, Value: KeyValue{Material: compressed.Item()}}
	parsed = mustParseKeyBlock(t, kb)
	if parsed.ecPublic == nil {
		t.Fatal("compressed EC point not parsed | 压缩 EC 点未解析")
	}
	if parsedCompressed, err := parsed.ecPublic.Bytes(); err != nil || !bytes.Equal(parsedCompressed, publicBytes) {
		t.Fatal("compressed EC point not parsed | 压缩 EC 点未解析")
	}
	invalidPoint := TransparentECPublicKey{RecommendedCurve: CurveP256, Q: []byte{4, 1, 2}}
	kb = KeyBlock{Format: KeyFormatTransparentECPublicKey, Value: KeyValue{Material: invalidPoint.Item()}}
	if _, err := parseKeyBlock(kb); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("invalid EC point error = %v | 非法 EC 点错误 = %v", err, err)
	}
	unknownCurve := TransparentECPublicKey{RecommendedCurve: RecommendedCurve(0x99), Q: publicPoint.Q}
	kb = KeyBlock{Format: KeyFormatTransparentECPublicKey, Value: KeyValue{Material: unknownCurve.Item()}}
	if _, err := parseKeyBlock(kb); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown curve error = %v | 未知曲线错误 = %v", err, err)
	}
	rawD, err := ecPrivate.Bytes()
	if err != nil {
		t.Fatalf("encode EC private scalar: %v | 编码 EC 私钥标量失败：%v", err, err)
	}
	ecPrivateKey := TransparentECPrivateKey{RecommendedCurve: CurveP256, D: new(big.Int).SetBytes(rawD)}
	kb = KeyBlock{Format: KeyFormatTransparentECPrivateKey, Value: KeyValue{Material: ecPrivateKey.Item()}}
	parsed = mustParseKeyBlock(t, kb)
	if parsed.ecPrivate == nil {
		t.Fatal("transparent EC private key not parsed | 透明 EC 私钥未解析")
	}
	parsedD, err := parsed.ecPrivate.Bytes()
	if err != nil || !bytes.Equal(parsedD, rawD) {
		t.Fatal("transparent EC private key not parsed | 透明 EC 私钥未解析")
	}
	badCurvePrivate := TransparentECPrivateKey{RecommendedCurve: RecommendedCurve(0x99), D: new(big.Int).SetBytes(rawD)}
	kb = KeyBlock{Format: KeyFormatTransparentECPrivateKey, Value: KeyValue{Material: badCurvePrivate.Item()}}
	if _, err := parseKeyBlock(kb); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("EC private unknown curve error = %v | EC 私钥未知曲线错误 = %v", err, err)
	}

	unsupported := KeyBlock{Format: KeyFormatType(0xFFFF)}
	if err := parseTransparentKeyBlock(unsupported, &parsedKey{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported transparent format error = %v | 不支持透明格式错误 = %v", err, err)
	}
}

// mustRSAKey returns a freshly generated RSA private key. | mustRSAKey 返回新生成的 RSA 私钥。
func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, defaultRSABits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return private
}

// mustECDSAKey returns a freshly generated P-256 private key. | mustECDSAKey 返回新生成的 P-256 私钥。
func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return private
}

// TestParseDERKeyFormats covers PKCS#1, PKCS#8, X.509 and SEC1 parsing. | TestParseDERKeyFormats
// 覆盖 PKCS#1、PKCS#8、X.509 与 SEC1 解析。
func TestParseDERKeyFormats(t *testing.T) {
	rsaPrivate := mustRSAKey(t)
	pkcs1Private := x509.MarshalPKCS1PrivateKey(rsaPrivate)
	pkcs1Public := x509.MarshalPKCS1PublicKey(&rsaPrivate.PublicKey)
	pkcs8Private, err := x509.MarshalPKCS8PrivateKey(rsaPrivate)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkixPublic, err := x509.MarshalPKIXPublicKey(&rsaPrivate.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	cases := []struct {
		name      string
		algorithm CryptographicAlgorithm
		format    KeyFormatType
		material  []byte
		check     func(*parsedKey) bool
	}{
		{"PKCS1 private", AlgorithmRSA, KeyFormatPKCS1, pkcs1Private, func(k *parsedKey) bool { return k.rsaPrivate != nil }},
		{"PKCS1 public", AlgorithmRSA, KeyFormatPKCS1, pkcs1Public, func(k *parsedKey) bool { return k.rsaPublic != nil && k.rsaPrivate == nil }},
		{"PKCS8 private", AlgorithmRSA, KeyFormatPKCS8, pkcs8Private, func(k *parsedKey) bool { return k.rsaPrivate != nil }},
		{"X509 public", AlgorithmRSA, KeyFormatX509, pkixPublic, func(k *parsedKey) bool { return k.rsaPublic != nil }},
		{"unlabelled private", AlgorithmRSA, 0, pkcs1Private, func(k *parsedKey) bool { return k.rsaPrivate != nil }},
		{"unlabelled public", AlgorithmRSA, 0, pkcs1Public, func(k *parsedKey) bool { return k.rsaPublic != nil }},
		{"unlabelled algorithm", 0, KeyFormatPKCS1, pkcs1Private, func(k *parsedKey) bool { return k.algorithm == AlgorithmRSA && k.rsaPrivate != nil }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			kb := KeyBlock{Format: testCase.format, Algorithm: testCase.algorithm, Value: NewRawKeyValue(testCase.material)}
			parsed := mustParseKeyBlock(t, kb)
			if !testCase.check(parsed) {
				t.Fatalf("parsed key = %+v | 解析结果 = %+v", parsed, parsed)
			}
		})
	}
	if _, err := parseKeyBlock(KeyBlock{Format: KeyFormatPKCS8, Algorithm: AlgorithmRSA, Value: NewRawKeyValue([]byte("junk"))}); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("junk PKCS8 error = %v | 垃圾 PKCS8 错误 = %v", err, err)
	}

	ecPrivate := mustECDSAKey(t)
	sec1, err := x509.MarshalECPrivateKey(ecPrivate)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecPrivate)
	if err != nil {
		t.Fatalf("EC MarshalPKCS8PrivateKey: %v", err)
	}
	ecPKIX, err := x509.MarshalPKIXPublicKey(&ecPrivate.PublicKey)
	if err != nil {
		t.Fatalf("EC MarshalPKIXPublicKey: %v", err)
	}
	ecCases := []struct {
		name     string
		format   KeyFormatType
		material []byte
		check    func(*parsedKey) bool
	}{
		{"SEC1", KeyFormatECPrivateKey, sec1, func(k *parsedKey) bool { return k.ecPrivate != nil }},
		{"PKCS8", KeyFormatPKCS8, ecPKCS8, func(k *parsedKey) bool { return k.ecPrivate != nil }},
		{"X509", KeyFormatX509, ecPKIX, func(k *parsedKey) bool { return k.ecPublic != nil && k.ecPrivate == nil }},
		{"unlabelled private", 0, sec1, func(k *parsedKey) bool { return k.ecPrivate != nil }},
		{"unlabelled public", 0, ecPKIX, func(k *parsedKey) bool { return k.ecPublic != nil }},
	}
	for _, testCase := range ecCases {
		t.Run("EC "+testCase.name, func(t *testing.T) {
			kb := KeyBlock{Format: testCase.format, Algorithm: AlgorithmECDSA, Value: NewRawKeyValue(testCase.material)}
			parsed := mustParseKeyBlock(t, kb)
			if !testCase.check(parsed) {
				t.Fatalf("parsed EC key = %+v | EC 解析结果 = %+v", parsed, parsed)
			}
		})
	}
	mismatch := KeyBlock{Format: KeyFormatPKCS8, Algorithm: AlgorithmRSA, Value: NewRawKeyValue(ecPKCS8)}
	if _, err := parseKeyBlock(mismatch); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("RSA parser accepted EC PKCS8: %v | RSA 解析器接受了 EC PKCS8：%v", err, err)
	}
	mismatch = KeyBlock{Format: KeyFormatX509, Algorithm: AlgorithmRSA, Value: NewRawKeyValue(ecPKIX)}
	if _, err := parseKeyBlock(mismatch); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("RSA parser accepted EC X509: %v | RSA 解析器接受了 EC X509：%v", err, err)
	}
	mismatch = KeyBlock{Format: KeyFormatPKCS8, Algorithm: AlgorithmECDSA, Value: NewRawKeyValue(pkcs8Private)}
	if _, err := parseKeyBlock(mismatch); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("EC parser accepted RSA PKCS8: %v | EC 解析器接受了 RSA PKCS8：%v", err, err)
	}
	mismatch = KeyBlock{Format: KeyFormatX509, Algorithm: AlgorithmECDSA, Value: NewRawKeyValue(pkixPublic)}
	if _, err := parseKeyBlock(mismatch); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("EC parser accepted RSA X509: %v | EC 解析器接受了 RSA X509：%v", err, err)
	}
}

// TestParseEd25519AndSM2Keys covers Ed25519 and SM2 key parsing. | TestParseEd25519AndSM2Keys
// 覆盖 Ed25519 与 SM2 密钥解析。
func TestParseEd25519AndSM2Keys(t *testing.T) {
	private, public := mustKeyPair(t, AlgorithmEd25519, 256)
	parsed := mustParseKeyBlock(t, private)
	if parsed.edPrivate == nil {
		t.Fatal("Ed25519 private key not parsed | Ed25519 私钥未解析")
	}
	parsed = mustParseKeyBlock(t, public)
	if parsed.edPublic == nil {
		t.Fatal("Ed25519 public key not parsed | Ed25519 公钥未解析")
	}
	if _, err := parseKeyBlock(KeyBlock{Format: KeyFormatPKCS8, Algorithm: AlgorithmEd25519, Value: NewRawKeyValue([]byte("junk"))}); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("junk Ed25519 error = %v | 垃圾 Ed25519 错误 = %v", err, err)
	}

	rsaPrivate := mustRSAKey(t)
	rsaPKIX, err := x509.MarshalPKIXPublicKey(&rsaPrivate.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	if _, err := parseKeyBlock(KeyBlock{Format: KeyFormatX509, Algorithm: AlgorithmEd25519, Value: NewRawKeyValue(rsaPKIX)}); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("Ed25519 parser accepted RSA key: %v | Ed25519 解析器接受了 RSA 密钥：%v", err, err)
	}

	sm2Private := mustSM2Key(t)
	privatePEM, err := guomi.MarshalPrivateKeyPEM(sm2Private)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	publicPEM, err := guomi.MarshalPublicKeyPEM(sm2Private.Public())
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}
	parsed = mustParseKeyBlock(t, KeyBlock{Format: KeyFormatRaw, Algorithm: AlgorithmSM2, Value: NewRawKeyValue(privatePEM)})
	if parsed.sm2Private == nil || parsed.sm2Public == nil {
		t.Fatal("SM2 private key not parsed | SM2 私钥未解析")
	}
	parsed = mustParseKeyBlock(t, KeyBlock{Format: KeyFormatRaw, Algorithm: AlgorithmSM2, Value: NewRawKeyValue(publicPEM)})
	if parsed.sm2Public == nil || parsed.sm2Private != nil {
		t.Fatal("SM2 public key not parsed | SM2 公钥未解析")
	}
	if _, err := parseKeyBlock(KeyBlock{Format: KeyFormatRaw, Algorithm: AlgorithmSM2, Value: NewRawKeyValue([]byte("junk"))}); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("junk SM2 error = %v | 垃圾 SM2 错误 = %v", err, err)
	}
}

// mustSM2Key returns a freshly generated SM2 private key. | mustSM2Key 返回新生成的 SM2 私钥。
func mustSM2Key(t *testing.T) *guomi.PrivateKey {
	t.Helper()
	private, err := guomi.GenerateKey()
	if err != nil {
		t.Fatalf("guomi.GenerateKey: %v", err)
	}
	return private
}

// TestInferAlgorithm covers algorithm inference for unlabelled material. | TestInferAlgorithm 覆盖未标注材料的算法推断。
func TestInferAlgorithm(t *testing.T) {
	rsaPrivate := mustRSAKey(t)
	ecPrivate := mustECDSAKey(t)
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sm2Private := mustSM2Key(t)
	sm2PrivatePEM, err := guomi.MarshalPrivateKeyPEM(sm2Private)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	sm2PublicPEM, err := guomi.MarshalPublicKeyPEM(sm2Private.Public())
	if err != nil {
		t.Fatalf("MarshalPublicKeyPEM: %v", err)
	}

	marshal := func(value any) []byte {
		t.Helper()
		der, err := x509.MarshalPKCS8PrivateKey(value)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey(%T): %v", value, err)
		}
		return der
	}
	marshalPublic := func(value any) []byte {
		t.Helper()
		der, err := x509.MarshalPKIXPublicKey(value)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey(%T): %v", value, err)
		}
		return der
	}
	sec1, err := x509.MarshalECPrivateKey(ecPrivate)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}

	cases := []struct {
		name     string
		material []byte
		want     CryptographicAlgorithm
	}{
		{"PKCS8 RSA", marshal(rsaPrivate), AlgorithmRSA},
		{"PKCS8 ECDSA", marshal(ecPrivate), AlgorithmECDSA},
		{"PKCS8 Ed25519", marshal(edPrivate), AlgorithmEd25519},
		{"SEC1", sec1, AlgorithmECDSA},
		{"PKCS1 private", x509.MarshalPKCS1PrivateKey(rsaPrivate), AlgorithmRSA},
		{"PKIX RSA", marshalPublic(&rsaPrivate.PublicKey), AlgorithmRSA},
		{"PKIX ECDSA", marshalPublic(&ecPrivate.PublicKey), AlgorithmECDSA},
		{"PKIX Ed25519", marshalPublic(edPublic), AlgorithmEd25519},
		{"PKCS1 public", x509.MarshalPKCS1PublicKey(&rsaPrivate.PublicKey), AlgorithmRSA},
		{"raw 16", bytes.Repeat([]byte{1}, 16), AlgorithmAES},
		{"raw 24", bytes.Repeat([]byte{1}, 24), AlgorithmAES},
		{"raw 32", bytes.Repeat([]byte{1}, 32), AlgorithmAES},
		{"unknown", []byte{1, 2, 3, 4, 5}, 0},
		{"SM2 private PEM", sm2PrivatePEM, AlgorithmSM2},
		{"SM2 public PEM", sm2PublicPEM, AlgorithmSM2},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := inferAlgorithm(testCase.material); got != testCase.want {
				t.Fatalf("inferAlgorithm = %s, want %s | 推断算法 = %s，期望 %s", got, testCase.want, got, testCase.want)
			}
		})
	}
}

// TestKeyMaterialBytes covers raw and structured material extraction. | TestKeyMaterialBytes 覆盖原始与结构化材料提取。
func TestKeyMaterialBytes(t *testing.T) {
	material := []byte{1, 2, 3}
	raw := KeyBlock{Value: NewRawKeyValue(material)}
	got, err := keyMaterialBytes(raw)
	if err != nil || !bytes.Equal(got, material) {
		t.Fatalf("raw material = %x, %v | 原始材料 = %x，%v", got, err, got, err)
	}
	transparent := TransparentSymmetricKey{Key: material}.Item()
	got, err = keyMaterialBytes(KeyBlock{Value: KeyValue{Material: transparent}})
	if err != nil {
		t.Fatalf("structured material: %v | 结构化材料：%v", err, err)
	}
	decoded, err := Decode(got)
	if err != nil || decoded.Tag != TagKeyMaterial {
		t.Fatalf("structured material did not encode the item: tag=%v err=%v | 结构化材料未编码项：tag=%v err=%v", decoded.Tag, err, decoded.Tag, err)
	}
}

// TestConvertKeyBlockFormat covers the key format conversion matrix. | TestConvertKeyBlockFormat
// 覆盖密钥格式转换矩阵。
func TestConvertKeyBlockFormat(t *testing.T) {
	material := bytes.Repeat([]byte{0x11}, 32)
	symmetric := rawKeyBlock(AlgorithmAES, material)
	if same, err := convertKeyBlockFormat(symmetric, 0); err != nil || same.Format != symmetric.Format {
		t.Fatalf("zero format conversion = %s, %v | 零格式转换 = %s，%v", same.Format, err, same.Format, err)
	}
	if same, err := convertKeyBlockFormat(symmetric, KeyFormatRaw); err != nil || same.Format != symmetric.Format {
		t.Fatalf("same format conversion = %s, %v | 同格式转换 = %s，%v", same.Format, err, same.Format, err)
	}
	transparent, err := convertKeyBlockFormat(symmetric, KeyFormatTransparentSymmetricKey)
	if err != nil {
		t.Fatalf("convert to transparent: %v | 转换为透明密钥失败：%v", err, err)
	}
	parsed := mustParseKeyBlock(t, transparent)
	if !bytes.Equal(parsed.symmetric, material) {
		t.Fatal("transparent conversion lost material | 透明转换丢失材料")
	}
	back, err := convertKeyBlockFormat(transparent, KeyFormatRaw)
	if err != nil {
		t.Fatalf("convert back to raw: %v | 转换回原始格式失败：%v", err, err)
	}
	parsed = mustParseKeyBlock(t, back)
	if !bytes.Equal(parsed.symmetric, material) {
		t.Fatal("raw conversion lost material | 原始转换丢失材料")
	}
	for _, format := range []KeyFormatType{KeyFormatPKCS1, KeyFormatPKCS8, KeyFormatX509, KeyFormatECPrivateKey,
		KeyFormatTransparentRSAPublicKey, KeyFormatTransparentRSAPrivateKey,
		KeyFormatTransparentECPublicKey, KeyFormatTransparentECPrivateKey} {
		if _, err := convertKeyBlockFormat(symmetric, format); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("symmetric to %s error = %v | 对称密钥转换为 %s 错误 = %v", format, err, format, err)
		}
	}

	rsaPrivate, rsaPublic := mustKeyPair(t, AlgorithmRSA, 2048)
	pkcs1, err := convertKeyBlockFormat(rsaPrivate, KeyFormatPKCS1)
	if err != nil {
		t.Fatalf("RSA to PKCS1: %v | RSA 转 PKCS1 失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, pkcs1); parsed.rsaPrivate == nil {
		t.Fatal("PKCS1 conversion did not produce a private key | PKCS1 转换未生成私钥")
	}
	transparentRSA, err := convertKeyBlockFormat(rsaPrivate, KeyFormatTransparentRSAPrivateKey)
	if err != nil {
		t.Fatalf("RSA to transparent private: %v | RSA 转透明私钥失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, transparentRSA); parsed.rsaPrivate == nil || len(parsed.rsaPrivate.Primes) != 2 {
		t.Fatal("transparent RSA private conversion is incomplete | 透明 RSA 私钥转换不完整")
	}
	transparentRSAPublic, err := convertKeyBlockFormat(rsaPublic, KeyFormatTransparentRSAPublicKey)
	if err != nil {
		t.Fatalf("RSA public to transparent: %v | RSA 公钥转透明失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, transparentRSAPublic); parsed.rsaPublic == nil {
		t.Fatal("transparent RSA public conversion is incomplete | 透明 RSA 公钥转换不完整")
	}
	x509Public, err := convertKeyBlockFormat(rsaPublic, KeyFormatX509)
	if err != nil {
		t.Fatalf("RSA public to X509: %v | RSA 公钥转 X509 失败：%v", err, err)
	}
	rawPublic, err := convertKeyBlockFormat(x509Public, KeyFormatRaw)
	if err != nil {
		t.Fatalf("X509 to raw: %v | X509 转原始失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, rawPublic); parsed.rsaPublic == nil {
		t.Fatal("raw RSA public conversion is incomplete | 原始 RSA 公钥转换不完整")
	}
	if _, err := convertKeyBlockFormat(x509Public, KeyFormatTransparentRSAPrivateKey); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("public RSA to transparent private error = %v | RSA 公钥转透明私钥错误 = %v", err, err)
	}
	if _, err := convertKeyBlockFormat(x509Public, KeyFormatPKCS8); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("public RSA to PKCS8 error = %v, want ErrUnsupported | RSA 公钥转 PKCS8 错误 = %v，期望 ErrUnsupported", err, err)
	}

	ecPrivate, ecPublic := mustKeyPair(t, AlgorithmECDSA, 256)
	sec1, err := convertKeyBlockFormat(ecPrivate, KeyFormatECPrivateKey)
	if err != nil {
		t.Fatalf("EC to SEC1: %v | EC 转 SEC1 失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, sec1); parsed.ecPrivate == nil {
		t.Fatal("SEC1 conversion is incomplete | SEC1 转换不完整")
	}
	transparentEC, err := convertKeyBlockFormat(ecPrivate, KeyFormatTransparentECPrivateKey)
	if err != nil {
		t.Fatalf("EC to transparent private: %v | EC 转透明私钥失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, transparentEC); parsed.ecPrivate == nil {
		t.Fatal("transparent EC private conversion is incomplete | 透明 EC 私钥转换不完整")
	}
	transparentECPublic, err := convertKeyBlockFormat(ecPublic, KeyFormatTransparentECPublicKey)
	if err != nil {
		t.Fatalf("EC to transparent public: %v | EC 转透明公钥失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, transparentECPublic); parsed.ecPublic == nil {
		t.Fatal("transparent EC public conversion is incomplete | 透明 EC 公钥转换不完整")
	}
	ecX509, err := convertKeyBlockFormat(ecPublic, KeyFormatX509)
	if err != nil {
		t.Fatalf("EC to X509: %v | EC 转 X509 失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, ecX509); parsed.ecPublic == nil {
		t.Fatal("EC X509 conversion is incomplete | EC X509 转换不完整")
	}
	if _, err := convertKeyBlockFormat(ecX509, KeyFormatPKCS8); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("public EC to PKCS8 error = %v | EC 公钥转 PKCS8 错误 = %v", err, err)
	}
	if _, err := convertKeyBlockFormat(ecPrivate, KeyFormatPKCS1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("EC to PKCS1 error = %v | EC 转 PKCS1 错误 = %v", err, err)
	}

	edPrivate, edPublic := mustKeyPair(t, AlgorithmEd25519, 256)
	edRaw, err := convertKeyBlockFormat(edPrivate, KeyFormatRaw)
	if err != nil {
		t.Fatalf("Ed25519 to raw: %v | Ed25519 转原始失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, edRaw); parsed.edPrivate == nil {
		t.Fatal("Ed25519 raw conversion is incomplete | Ed25519 原始转换不完整")
	}
	edX509, err := convertKeyBlockFormat(edPublic, KeyFormatX509)
	if err != nil {
		t.Fatalf("Ed25519 to X509: %v | Ed25519 转 X509 失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, edX509); parsed.edPublic == nil {
		t.Fatal("Ed25519 X509 conversion is incomplete | Ed25519 X509 转换不完整")
	}
	if _, err := convertKeyBlockFormat(edPrivate, KeyFormatTransparentECPublicKey); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Ed25519 to transparent EC error = %v | Ed25519 转透明 EC 错误 = %v", err, err)
	}
	if _, err := convertKeyBlockFormat(edPrivate, KeyFormatPKCS1); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Ed25519 to PKCS1 error = %v | Ed25519 转 PKCS1 错误 = %v", err, err)
	}

	sm2Private, sm2Public := mustKeyPair(t, AlgorithmSM2, 256)
	sm2PKCS8, err := convertKeyBlockFormat(sm2Private, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("SM2 to PKCS8: %v | SM2 转 PKCS8 失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, sm2PKCS8); parsed.sm2Private == nil {
		t.Fatal("SM2 PKCS8 conversion is incomplete | SM2 PKCS8 转换不完整")
	}
	sm2X509, err := convertKeyBlockFormat(sm2Public, KeyFormatX509)
	if err != nil {
		t.Fatalf("SM2 to X509: %v | SM2 转 X509 失败：%v", err, err)
	}
	if parsed := mustParseKeyBlock(t, sm2X509); parsed.sm2Public == nil {
		t.Fatal("SM2 X509 conversion is incomplete | SM2 X509 转换不完整")
	}

	if _, err := convertKeyBlockFormat(symmetric, KeyFormatType(0xFFFF)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown target format error = %v | 未知目标格式错误 = %v", err, err)
	}
	if _, err := convertKeyBlockFormat(rawKeyBlock(AlgorithmAES, []byte("junk")), KeyFormatTransparentSymmetricKey); err != nil {
		t.Fatalf("symmetric raw conversion should not parse material: %v | 对称原始转换不应解析材料：%v", err, err)
	}
	if _, err := convertKeyBlockFormat(rawKeyBlock(AlgorithmRSA, []byte("junk")), KeyFormatPKCS1); !errors.Is(err, ErrCryptographic) {
		t.Fatalf("invalid RSA material error = %v | 非法 RSA 材料错误 = %v", err, err)
	}
}
