package kmip

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// defaultRSABits is the RSA key size used when no length is supplied. | defaultRSABits 是未提供长度时使用的 RSA 密钥位数。
const defaultRSABits = 2048

// parsedKey holds a decoded KMIP key in one of the supported representations. Exactly one key family is populated.
// | parsedKey 保存某一受支持表示的已解码 KMIP 密钥；只会填充一个密钥族。
type parsedKey struct {
	algorithm  CryptographicAlgorithm
	length     int
	symmetric  []byte
	rsaPrivate *rsa.PrivateKey
	rsaPublic  *rsa.PublicKey
	ecPrivate  *ecdsa.PrivateKey
	ecPublic   *ecdsa.PublicKey
	edPrivate  ed25519.PrivateKey
	edPublic   ed25519.PublicKey
	xPrivate   *ecdh.PrivateKey
	xPublic    *ecdh.PublicKey
	sm2Private *guomi.PrivateKey
	sm2Public  *guomi.PublicKey
	jwk        *jose.Key
}

// zeroize clears the symmetric key bytes held by the parsed key. | zeroize 清除已解析密钥持有的对称密钥字节。
func (k *parsedKey) zeroize() {
	if k != nil {
		zeroize(k.symmetric)
	}
}

// generateSymmetricKeyBlock generates a symmetric key block with Raw material. | generateSymmetricKeyBlock 生成材料为 Raw 的对称密钥块。
//
// AES supports 128, 192 and 256 bits, SM4 supports 128 bits, and HMAC-SHA-2 algorithms support 128 to 512 bits.
// | AES 支持 128、192 与 256 位，SM4 支持 128 位，HMAC-SHA-2 算法支持 128 到 512 位。
func generateSymmetricKeyBlock(algorithm CryptographicAlgorithm, lengthBits int) (KeyBlock, error) {
	var length int
	switch algorithm {
	case AlgorithmAES:
		if lengthBits == 0 {
			lengthBits = 256
		}
		switch lengthBits {
		case 128, 192, 256:
			length = lengthBits / 8
		default:
			return KeyBlock{}, errs.Detail(ErrInvalidRequest, "AES key length %d is not 128, 192 or 256 bits | AES 密钥长度 %d 不是 128、192 或 256 位", lengthBits, lengthBits)
		}
	case AlgorithmSM4:
		if lengthBits != 0 && lengthBits != 128 {
			return KeyBlock{}, errs.Detail(ErrInvalidRequest, "SM4 key length %d is not 128 bits | SM4 密钥长度 %d 不是 128 位", lengthBits, lengthBits)
		}
		lengthBits = 128
		length = 16
	case AlgorithmHMACSHA1, AlgorithmHMACSHA224, AlgorithmHMACSHA256, AlgorithmHMACSHA384, AlgorithmHMACSHA512:
		if lengthBits == 0 {
			lengthBits = 256
		}
		if lengthBits < 64 || lengthBits > 4096 || lengthBits%8 != 0 {
			return KeyBlock{}, errs.Detail(ErrInvalidRequest, "HMAC key length %d is not a multiple of 8 between 64 and 4096 bits | HMAC 密钥长度 %d 不是 64 到 4096 之间 8 的倍数", lengthBits, lengthBits)
		}
		length = lengthBits / 8
	default:
		return KeyBlock{}, errs.Detail(ErrUnsupported, "cannot generate symmetric key for algorithm %s | 无法为算法 %s 生成对称密钥", algorithm, algorithm)
	}
	material := make([]byte, length)
	if _, err := rand.Read(material); err != nil {
		return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
	}
	return KeyBlock{
		Format:    KeyFormatRaw,
		Algorithm: algorithm,
		Length:    lengthBits,
		Value:     NewRawKeyValue(material),
	}, nil
}

// generateKeyPairKeyBlocks generates a private/public key pair with PKCS#8 and X.509 material. | generateKeyPairKeyBlocks 生成材料为 PKCS#8 与 X.509 的私钥/公钥对。
//
// RSA keys must be at least 2048 bits. ECDSA/EC lengths select P-256, P-384 or P-521. Ed25519 and SM2 use 256 bits.
// | RSA 密钥至少 2048 位；ECDSA/EC 长度选择 P-256、P-384 或 P-521；Ed25519 与 SM2 使用 256 位。
func generateKeyPairKeyBlocks(algorithm CryptographicAlgorithm, lengthBits int) (KeyBlock, KeyBlock, error) {
	switch algorithm {
	case AlgorithmRSA:
		if lengthBits == 0 {
			lengthBits = defaultRSABits
		}
		if lengthBits < defaultRSABits || lengthBits > 8192 {
			return KeyBlock{}, KeyBlock{}, errs.Detail(ErrInvalidRequest, "RSA key length %d is outside 2048..8192 bits | RSA 密钥长度 %d 超出 2048..8192 位", lengthBits, lengthBits)
		}
		private, err := rsa.GenerateKey(rand.Reader, lengthBits)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		return KeyBlock{
			Format:    KeyFormatPKCS8,
			Algorithm: AlgorithmRSA,
			Length:    lengthBits,
			Value:     NewRawKeyValue(privDER),
		}, KeyBlock{
			Format:    KeyFormatX509,
			Algorithm: AlgorithmRSA,
			Length:    lengthBits,
			Value:     NewRawKeyValue(pubDER),
		}, nil
	case AlgorithmECDSA, AlgorithmEC:
		curve, err := curveForLength(lengthBits)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, err
		}
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		return KeyBlock{
			Format:    KeyFormatPKCS8,
			Algorithm: AlgorithmECDSA,
			Length:    curveBits(curve),
			Value:     NewRawKeyValue(privDER),
		}, KeyBlock{
			Format:    KeyFormatX509,
			Algorithm: AlgorithmECDSA,
			Length:    curveBits(curve),
			Value:     NewRawKeyValue(pubDER),
		}, nil
	case AlgorithmEd25519:
		if lengthBits != 0 && lengthBits != 256 {
			return KeyBlock{}, KeyBlock{}, errs.Detail(ErrInvalidRequest, "Ed25519 key length %d is not 256 bits | Ed25519 密钥长度 %d 不是 256 位", lengthBits, lengthBits)
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		return KeyBlock{
			Format:    KeyFormatPKCS8,
			Algorithm: AlgorithmEd25519,
			Length:    256,
			Value:     NewRawKeyValue(privDER),
		}, KeyBlock{
			Format:    KeyFormatX509,
			Algorithm: AlgorithmEd25519,
			Length:    256,
			Value:     NewRawKeyValue(pubDER),
		}, nil
	case AlgorithmSM2:
		if lengthBits != 0 && lengthBits != 256 {
			return KeyBlock{}, KeyBlock{}, errs.Detail(ErrInvalidRequest, "SM2 key length %d is not 256 bits | SM2 密钥长度 %d 不是 256 位", lengthBits, lengthBits)
		}
		private, err := guomi.GenerateKey()
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		privPEM, err := guomi.MarshalPrivateKeyPEM(private)
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		pubPEM, err := guomi.MarshalPublicKeyPEM(private.Public())
		if err != nil {
			return KeyBlock{}, KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		return KeyBlock{
			Format:    KeyFormatRaw,
			Algorithm: AlgorithmSM2,
			Length:    256,
			Value:     NewRawKeyValue(privPEM),
		}, KeyBlock{
			Format:    KeyFormatRaw,
			Algorithm: AlgorithmSM2,
			Length:    256,
			Value:     NewRawKeyValue(pubPEM),
		}, nil
	default:
		return KeyBlock{}, KeyBlock{}, errs.Detail(ErrUnsupported, "cannot generate key pair for algorithm %s | 无法为算法 %s 生成密钥对", algorithm, algorithm)
	}
}

// curveForLength maps a cryptographic length in bits onto a NIST curve. | curveForLength 把密码长度（位）映射到 NIST 曲线。
func curveForLength(lengthBits int) (elliptic.Curve, error) {
	switch lengthBits {
	case 0, 256:
		return elliptic.P256(), nil
	case 384:
		return elliptic.P384(), nil
	case 521:
		return elliptic.P521(), nil
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported elliptic curve length %d | 不支持的椭圆曲线长度 %d", lengthBits, lengthBits)
	}
}

// curveBits returns the bit size of a curve. | curveBits 返回曲线位长。
func curveBits(curve elliptic.Curve) int {
	return curve.Params().BitSize
}

// curveFor maps a KMIP recommended curve onto a Go curve. | curveFor 把 KMIP 推荐曲线映射到 Go 曲线。
func curveFor(curve RecommendedCurve) (elliptic.Curve, error) {
	switch curve {
	case CurveP256:
		return elliptic.P256(), nil
	case CurveP384:
		return elliptic.P384(), nil
	case CurveP521:
		return elliptic.P521(), nil
	case CurveP224:
		return elliptic.P224(), nil
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported recommended curve 0x%08X | 不支持的推荐曲线 0x%08X", uint32(curve), uint32(curve))
	}
}

// recommendedCurveFor maps a Go curve onto the KMIP recommended curve value. | recommendedCurveFor 把 Go 曲线映射到 KMIP 推荐曲线值。
func recommendedCurveFor(curve elliptic.Curve) (RecommendedCurve, error) {
	switch curve {
	case elliptic.P224():
		return CurveP224, nil
	case elliptic.P256():
		return CurveP256, nil
	case elliptic.P384():
		return CurveP384, nil
	case elliptic.P521():
		return CurveP521, nil
	default:
		return 0, errs.Detail(ErrUnsupported, "unsupported elliptic curve | 不支持的椭圆曲线")
	}
}

// keyMaterialBytes returns the raw bytes stored in a key block. | keyMaterialBytes 返回密钥块中存储的原始字节。
func keyMaterialBytes(kb KeyBlock) ([]byte, error) {
	if kb.Value.Material.Type == TypeByteString {
		return kb.Value.Material.Value, nil
	}
	encoded, err := Encode(kb.Value.Material)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// parseKeyBlock decodes a key block into a parsed key representation. | parseKeyBlock 把密钥块解码为已解析密钥表示。
func parseKeyBlock(kb KeyBlock) (*parsedKey, error) {
	out := &parsedKey{algorithm: kb.Algorithm}
	defer func() { out.length = keyBitLength(out) }()
	if kb.Format == KeyFormatJWK {
		if err := parseJWKKeyBlock(kb, out); err != nil {
			out.zeroize()
			return nil, err
		}
		return out, nil
	}
	switch kb.Format {
	case KeyFormatTransparentSymmetricKey, KeyFormatTransparentRSAPrivateKey, KeyFormatTransparentRSAPublicKey,
		KeyFormatTransparentECPrivateKey, KeyFormatTransparentECPublicKey:
		if err := parseTransparentKeyBlock(kb, out); err != nil {
			out.zeroize()
			return nil, err
		}
		return out, nil
	}
	material, err := keyMaterialBytes(kb)
	if err != nil {
		return nil, errs.Wrap(err, ErrCryptographic)
	}
	algorithm := kb.Algorithm
	if algorithm == 0 {
		switch kb.Format {
		case KeyFormatPKCS1:
			algorithm = AlgorithmRSA
		default:
			algorithm = inferAlgorithm(material)
		}
	}
	out.algorithm = algorithm
	switch algorithm {
	case AlgorithmAES, AlgorithmSM4, AlgorithmHMACSHA1, AlgorithmHMACSHA224,
		AlgorithmHMACSHA256, AlgorithmHMACSHA384, AlgorithmHMACSHA512, AlgorithmHMACMD5:
		out.symmetric = append([]byte(nil), material...)
		return out, nil
	case AlgorithmRSA:
		if err := parseRSAKey(kb.Format, material, out); err != nil {
			return nil, err
		}
		return out, nil
	case AlgorithmECDSA, AlgorithmEC:
		if err := parseECKey(kb.Format, material, out); err != nil {
			return nil, err
		}
		return out, nil
	case AlgorithmECDH:
		if err := parseECDHKey(kb.Format, material, out); err != nil {
			return nil, err
		}
		return out, nil
	case AlgorithmEd25519:
		if err := parseEd25519Key(material, out); err != nil {
			return nil, err
		}
		return out, nil
	case AlgorithmSM2:
		if err := parseSM2Key(material, out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported cryptographic algorithm %s | 不支持的密码算法 %s", algorithm, algorithm)
	}
}

// inferAlgorithm guesses the algorithm of unlabelled DER or PEM key material. | inferAlgorithm 推测未标注 DER 或 PEM 密钥材料的算法。
func inferAlgorithm(material []byte) CryptographicAlgorithm {
	if block, _ := pem.Decode(material); block != nil {
		if _, err := guomi.ParsePrivateKeyPEM(material); err == nil {
			return AlgorithmSM2
		}
		if _, err := guomi.ParsePublicKeyPEM(material); err == nil {
			return AlgorithmSM2
		}
	}
	if key, err := x509.ParsePKCS8PrivateKey(material); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey:
			return AlgorithmRSA
		case *ecdsa.PrivateKey:
			return AlgorithmECDSA
		case ed25519.PrivateKey:
			return AlgorithmEd25519
		case *ecdh.PrivateKey:
			return AlgorithmECDH
		}
		return 0
	}
	if _, err := x509.ParseECPrivateKey(material); err == nil {
		return AlgorithmECDSA
	}
	if _, err := x509.ParsePKCS1PrivateKey(material); err == nil {
		return AlgorithmRSA
	}
	if key, err := x509.ParsePKIXPublicKey(material); err == nil {
		switch key.(type) {
		case *rsa.PublicKey:
			return AlgorithmRSA
		case *ecdsa.PublicKey:
			return AlgorithmECDSA
		case ed25519.PublicKey:
			return AlgorithmEd25519
		case *ecdh.PublicKey:
			return AlgorithmECDH
		}
		return 0
	}
	if _, err := x509.ParsePKCS1PublicKey(material); err == nil {
		return AlgorithmRSA
	}
	if len(material) == 16 || len(material) == 24 || len(material) == 32 {
		return AlgorithmAES
	}
	return 0
}

// parseTransparentKeyBlock decodes a transparent key block. | parseTransparentKeyBlock 解码透明密钥块。
func parseTransparentKeyBlock(kb KeyBlock, out *parsedKey) error {
	item := kb.Value.Material
	switch kb.Format {
	case KeyFormatTransparentSymmetricKey:
		key, err := DecodeTransparentSymmetricKey(item)
		if err != nil {
			return err
		}
		out.algorithm = AlgorithmAES
		if kb.Algorithm != 0 {
			out.algorithm = kb.Algorithm
		}
		out.symmetric = key.Key
		return nil
	case KeyFormatTransparentRSAPublicKey:
		key, err := DecodeTransparentRSAPublicKey(item)
		if err != nil {
			return err
		}
		if !key.PublicExponent.IsInt64() {
			return errs.Detail(ErrCryptographic, "RSA public exponent is too large | RSA 公开指数过大")
		}
		out.algorithm = AlgorithmRSA
		out.rsaPublic = &rsa.PublicKey{N: key.Modulus, E: int(key.PublicExponent.Int64())}
		return nil
	case KeyFormatTransparentRSAPrivateKey:
		key, err := DecodeTransparentRSAPrivateKey(item)
		if err != nil {
			return err
		}
		if !key.PublicExponent.IsInt64() {
			return errs.Detail(ErrCryptographic, "RSA public exponent is too large | RSA 公开指数过大")
		}
		priv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: key.Modulus, E: int(key.PublicExponent.Int64())},
			D:         key.PrivateExponent,
			Primes:    nil,
		}
		if key.P != nil && key.Q != nil {
			priv.Primes = []*big.Int{key.P, key.Q}
			if err := priv.Validate(); err != nil {
				return errs.Wrap(err, ErrCryptographic)
			}
			priv.Precompute()
		}
		out.algorithm = AlgorithmRSA
		out.rsaPrivate = priv
		out.rsaPublic = &priv.PublicKey
		return nil
	case KeyFormatTransparentECPublicKey:
		key, err := DecodeTransparentECPublicKey(item)
		if err != nil {
			return err
		}
		curve, err := curveFor(key.RecommendedCurve)
		if err != nil {
			return err
		}
		// KMIP carries a SEC1 point, normally uncompressed. Compressed points are also legal in KMIP, so fall
		// back to the legacy decoder for them. | KMIP 承载 SEC1 点，通常为未压缩格式；KMIP 也允许压缩点，
		// 因此对压缩点回退到旧解码器。
		publicKey, parseErr := ecdsa.ParseUncompressedPublicKey(curve, key.Q)
		if parseErr != nil {
			x, y := elliptic.UnmarshalCompressed(curve, key.Q) //nolint:staticcheck // KMIP permits compressed SEC1 points.
			if x == nil {
				return errs.Detail(ErrCryptographic, "invalid EC public point | EC 公钥点非法")
			}
			size := (curve.Params().BitSize + 7) / 8
			point := make([]byte, 1+2*size)
			point[0] = 4
			x.FillBytes(point[1 : 1+size])
			y.FillBytes(point[1+size:])
			publicKey, parseErr = ecdsa.ParseUncompressedPublicKey(curve, point)
			if parseErr != nil {
				return errs.Detail(ErrCryptographic, "invalid EC public point | EC 公钥点非法")
			}
		}
		out.algorithm = AlgorithmECDSA
		out.ecPublic = publicKey
		return nil
	case KeyFormatTransparentECPrivateKey:
		key, err := DecodeTransparentECPrivateKey(item)
		if err != nil {
			return err
		}
		curve, err := curveFor(key.RecommendedCurve)
		if err != nil {
			return err
		}
		size := (curve.Params().BitSize + 7) / 8
		if key.D == nil || key.D.Sign() < 0 || key.D.BitLen() > curve.Params().BitSize {
			return errs.Detail(ErrCryptographic, "invalid EC private scalar | EC 私钥标量非法")
		}
		raw := make([]byte, size)
		key.D.FillBytes(raw)
		priv, err := ecdsa.ParseRawPrivateKey(curve, raw)
		if err != nil {
			return errs.WrapDetail(err, ErrCryptographic, "invalid EC private scalar | EC 私钥标量非法")
		}
		out.algorithm = AlgorithmECDSA
		out.ecPrivate = priv
		out.ecPublic = &priv.PublicKey
		return nil
	default:
		return errs.Detail(ErrUnsupported, "unsupported transparent key format %s | 不支持的透明密钥格式 %s", kb.Format, kb.Format)
	}
}

// parseRSAKey decodes RSA material in its declared format. | parseRSAKey 按声明格式解码 RSA 材料。
func parseRSAKey(format KeyFormatType, material []byte, out *parsedKey) error {
	parsePrivate := func(der []byte) error {
		if priv, err := x509.ParsePKCS1PrivateKey(der); err == nil {
			out.rsaPrivate = priv
			out.rsaPublic = &priv.PublicKey
			return nil
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return errs.Wrap(err, ErrCryptographic)
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return errs.Detail(ErrCryptographic, "PKCS#8 material is not an RSA private key | PKCS#8 材料不是 RSA 私钥")
		}
		out.rsaPrivate = priv
		out.rsaPublic = &priv.PublicKey
		return nil
	}
	parsePublic := func(der []byte) error {
		if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
			out.rsaPublic = pub
			return nil
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return errs.Wrap(err, ErrCryptographic)
		}
		pub, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrCryptographic, "X.509 material is not an RSA public key | X.509 材料不是 RSA 公钥")
		}
		out.rsaPublic = pub
		return nil
	}
	switch format {
	case KeyFormatPKCS1:
		if err := parsePrivate(material); err != nil {
			return parsePublic(material)
		}
		return nil
	case KeyFormatPKCS8:
		return parsePrivate(material)
	case KeyFormatX509:
		return parsePublic(material)
	default:
		if err := parsePrivate(material); err == nil {
			return nil
		}
		return parsePublic(material)
	}
}

// parseECKey decodes ECDSA material in its declared format. | parseECKey 按声明格式解码 ECDSA 材料。
func parseECKey(format KeyFormatType, material []byte, out *parsedKey) error {
	parsePrivate := func() error {
		if priv, err := x509.ParseECPrivateKey(material); err == nil {
			out.ecPrivate = priv
			out.ecPublic = &priv.PublicKey
			return nil
		}
		parsed, err := x509.ParsePKCS8PrivateKey(material)
		if err != nil {
			return errs.Wrap(err, ErrCryptographic)
		}
		priv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return errs.Detail(ErrCryptographic, "key material is not an EC private key | 密钥材料不是 EC 私钥")
		}
		out.ecPrivate = priv
		out.ecPublic = &priv.PublicKey
		return nil
	}
	parsePublic := func() error {
		parsed, err := x509.ParsePKIXPublicKey(material)
		if err != nil {
			return errs.Wrap(err, ErrCryptographic)
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return errs.Detail(ErrCryptographic, "key material is not an EC public key | 密钥材料不是 EC 公钥")
		}
		out.ecPublic = pub
		return nil
	}
	switch format {
	case KeyFormatECPrivateKey, KeyFormatPKCS8:
		return parsePrivate()
	case KeyFormatX509:
		return parsePublic()
	default:
		if err := parsePrivate(); err == nil {
			return nil
		}
		return parsePublic()
	}
}

// parseEd25519Key decodes Ed25519 PKCS#8 or X.509 material. | parseEd25519Key 解码 Ed25519 PKCS#8 或 X.509 材料。
func parseEd25519Key(material []byte, out *parsedKey) error {
	if parsed, err := x509.ParsePKCS8PrivateKey(material); err == nil {
		if priv, ok := parsed.(ed25519.PrivateKey); ok {
			out.edPrivate = priv
			out.edPublic = priv.Public().(ed25519.PublicKey)
			return nil
		}
	}
	parsed, err := x509.ParsePKIXPublicKey(material)
	if err != nil {
		return errs.Wrap(err, ErrCryptographic)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errs.Detail(ErrCryptographic, "key material is not an Ed25519 public key | 密钥材料不是 Ed25519 公钥")
	}
	out.edPublic = pub
	return nil
}

// parseECDHKey decodes ECDH key material. X25519 uses PKCS#8 or X.509; NIST-curve ECDH falls back to EC material.
// | parseECDHKey 解码 ECDH 密钥材料。X25519 使用 PKCS#8 或 X.509；NIST 曲线 ECDH 回退到 EC 材料。
func parseECDHKey(format KeyFormatType, material []byte, out *parsedKey) error {
	if parsed, err := x509.ParsePKCS8PrivateKey(material); err == nil {
		if priv, ok := parsed.(*ecdh.PrivateKey); ok {
			out.xPrivate = priv
			out.xPublic = priv.PublicKey()
			return nil
		}
	}
	if parsed, err := x509.ParsePKIXPublicKey(material); err == nil {
		if pub, ok := parsed.(*ecdh.PublicKey); ok {
			out.xPublic = pub
			return nil
		}
	}
	if len(material) == 32 && (format == KeyFormatRaw || format == KeyFormatX509) {
		pub, err := ecdh.X25519().NewPublicKey(material)
		if err != nil {
			return errs.WrapDetail(err, ErrCryptographic, "X25519 public key | X25519 公钥")
		}
		out.xPublic = pub
		return nil
	}
	if err := parseECKey(format, material, out); err != nil {
		return errs.WrapDetail(err, ErrCryptographic, "ECDH key material | ECDH 密钥材料")
	}
	return nil
}

// keyBitLength returns the cryptographic length in bits of the key family held by k. | keyBitLength 返回
// k 所持密钥族的密码长度（位）。
func keyBitLength(k *parsedKey) int {
	switch {
	case k == nil:
		return 0
	case k.symmetric != nil:
		return len(k.symmetric) * 8
	case k.rsaPrivate != nil:
		return k.rsaPrivate.N.BitLen()
	case k.rsaPublic != nil:
		return k.rsaPublic.N.BitLen()
	case k.ecPrivate != nil:
		return curveBits(k.ecPrivate.Curve)
	case k.ecPublic != nil:
		return curveBits(k.ecPublic.Curve)
	case k.edPrivate != nil || k.edPublic != nil:
		return 256
	case k.xPrivate != nil || k.xPublic != nil:
		return 256
	case k.sm2Private != nil || k.sm2Public != nil:
		return 256
	default:
		return 0
	}
}

// parseSM2Key decodes SM2 PEM material. | parseSM2Key 解码 SM2 PEM 材料。
func parseSM2Key(material []byte, out *parsedKey) error {
	if priv, err := guomi.ParsePrivateKeyPEM(material); err == nil {
		out.sm2Private = priv
		out.sm2Public = priv.Public()
		return nil
	}
	if pub, err := guomi.ParsePublicKeyPEM(material); err == nil {
		out.sm2Public = pub
		return nil
	}
	return errs.Detail(ErrCryptographic, "SM2 key material is not valid PEM | SM2 密钥材料不是合法 PEM")
}

// convertKeyBlockFormat converts a key block into the requested KMIP key format. | convertKeyBlockFormat 把密钥块转换为请求的 KMIP 密钥格式。
func convertKeyBlockFormat(kb KeyBlock, format KeyFormatType) (KeyBlock, error) {
	if format == 0 || format == kb.Format {
		return kb, nil
	}
	key, err := parseKeyBlock(kb)
	if err != nil {
		return KeyBlock{}, err
	}
	defer key.zeroize()
	out := KeyBlock{Format: format, Algorithm: kb.Algorithm, Length: kb.Length}
	if out.Algorithm == 0 {
		out.Algorithm = key.algorithm
	}
	setMaterial := func(item Item) {
		out.Value = KeyValue{Material: item}
	}
	switch format {
	case KeyFormatRaw:
		switch {
		case key.symmetric != nil:
			setMaterial(NewByteString(TagKeyMaterial, key.symmetric))
		case key.rsaPrivate != nil:
			der, err := x509.MarshalPKCS8PrivateKey(key.rsaPrivate)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.ecPrivate != nil:
			der, err := x509.MarshalPKCS8PrivateKey(key.ecPrivate)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.edPrivate != nil:
			der, err := x509.MarshalPKCS8PrivateKey(key.edPrivate)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.xPrivate != nil:
			der, err := x509.MarshalPKCS8PrivateKey(key.xPrivate)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.rsaPublic != nil:
			der, err := x509.MarshalPKIXPublicKey(key.rsaPublic)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.ecPublic != nil:
			der, err := x509.MarshalPKIXPublicKey(key.ecPublic)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.edPublic != nil:
			der, err := x509.MarshalPKIXPublicKey(key.edPublic)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.xPublic != nil:
			der, err := x509.MarshalPKIXPublicKey(key.xPublic)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.sm2Private != nil:
			der, err := guomi.MarshalPrivateKeyPEM(key.sm2Private)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		case key.sm2Public != nil:
			der, err := guomi.MarshalPublicKeyPEM(key.sm2Public)
			if err != nil {
				return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
			}
			setMaterial(NewByteString(TagKeyMaterial, der))
		default:
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key cannot be encoded as Raw | 密钥无法编码为 Raw")
		}
		return out, nil
	case KeyFormatTransparentSymmetricKey:
		if key.symmetric == nil {
			return KeyBlock{}, errs.Detail(ErrUnsupported, "only symmetric keys can use Transparent Symmetric Key | 只有对称密钥可使用 Transparent Symmetric Key")
		}
		setMaterial(TransparentSymmetricKey{Key: key.symmetric}.Item())
		return out, nil
	case KeyFormatTransparentRSAPublicKey:
		if key.rsaPublic == nil {
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key is not an RSA public key | 密钥不是 RSA 公钥")
		}
		setMaterial(TransparentRSAPublicKey{Modulus: key.rsaPublic.N, PublicExponent: big.NewInt(int64(key.rsaPublic.E))}.Item())
		return out, nil
	case KeyFormatTransparentRSAPrivateKey:
		if key.rsaPrivate == nil {
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key is not an RSA private key | 密钥不是 RSA 私钥")
		}
		priv := key.rsaPrivate
		transparent := TransparentRSAPrivateKey{
			Modulus:         priv.N,
			PrivateExponent: priv.D,
			PublicExponent:  big.NewInt(int64(priv.E)),
		}
		if len(priv.Primes) >= 2 {
			transparent.P = priv.Primes[0]
			transparent.Q = priv.Primes[1]
		}
		if priv.Precomputed.Dp != nil {
			transparent.PrimeExponentP = priv.Precomputed.Dp
		}
		if priv.Precomputed.Dq != nil {
			transparent.PrimeExponentQ = priv.Precomputed.Dq
		}
		if priv.Precomputed.Qinv != nil {
			transparent.CRTCoefficient = priv.Precomputed.Qinv
		}
		setMaterial(transparent.Item())
		return out, nil
	case KeyFormatTransparentECPublicKey:
		if key.ecPublic == nil {
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key is not an EC public key | 密钥不是 EC 公钥")
		}
		curve, err := recommendedCurveFor(key.ecPublic.Curve)
		if err != nil {
			return KeyBlock{}, err
		}
		point, err := key.ecPublic.Bytes()
		if err != nil {
			return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		setMaterial(TransparentECPublicKey{RecommendedCurve: curve, Q: point}.Item())
		return out, nil
	case KeyFormatTransparentECPrivateKey:
		if key.ecPrivate == nil {
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key is not an EC private key | 密钥不是 EC 私钥")
		}
		curve, err := recommendedCurveFor(key.ecPrivate.Curve)
		if err != nil {
			return KeyBlock{}, err
		}
		raw, err := key.ecPrivate.Bytes()
		if err != nil {
			return KeyBlock{}, errs.WrapDetail(err, ErrCryptographic, "encode EC private scalar | 编码 EC 私钥标量失败")
		}
		setMaterial(TransparentECPrivateKey{RecommendedCurve: curve, D: new(big.Int).SetBytes(raw)}.Item())
		return out, nil
	case KeyFormatPKCS1:
		if key.rsaPrivate != nil {
			setMaterial(NewByteString(TagKeyMaterial, x509.MarshalPKCS1PrivateKey(key.rsaPrivate)))
			return out, nil
		}
		if key.rsaPublic != nil {
			setMaterial(NewByteString(TagKeyMaterial, x509.MarshalPKCS1PublicKey(key.rsaPublic)))
			return out, nil
		}
		return KeyBlock{}, errs.Detail(ErrUnsupported, "only RSA keys can use PKCS#1 | 只有 RSA 密钥可使用 PKCS#1")
	case KeyFormatPKCS8:
		var der []byte
		var err error
		switch {
		case key.rsaPrivate != nil:
			der, err = x509.MarshalPKCS8PrivateKey(key.rsaPrivate)
		case key.ecPrivate != nil:
			der, err = x509.MarshalPKCS8PrivateKey(key.ecPrivate)
		case key.edPrivate != nil:
			der, err = x509.MarshalPKCS8PrivateKey(key.edPrivate)
		case key.xPrivate != nil:
			der, err = x509.MarshalPKCS8PrivateKey(key.xPrivate)
		case key.sm2Private != nil:
			der, err = guomi.MarshalPrivateKeyPEM(key.sm2Private)
		default:
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key is not a supported private key | 密钥不是受支持的私钥")
		}
		if err != nil {
			return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		setMaterial(NewByteString(TagKeyMaterial, der))
		return out, nil
	case KeyFormatX509:
		var der []byte
		var err error
		switch {
		case key.rsaPublic != nil:
			der, err = x509.MarshalPKIXPublicKey(key.rsaPublic)
		case key.ecPublic != nil:
			der, err = x509.MarshalPKIXPublicKey(key.ecPublic)
		case key.edPublic != nil:
			der, err = x509.MarshalPKIXPublicKey(key.edPublic)
		case key.xPublic != nil:
			der, err = x509.MarshalPKIXPublicKey(key.xPublic)
		case key.sm2Public != nil:
			der, err = guomi.MarshalPublicKeyPEM(key.sm2Public)
		default:
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key is not a supported public key | 密钥不是受支持的公钥")
		}
		if err != nil {
			return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		setMaterial(NewByteString(TagKeyMaterial, der))
		return out, nil
	case KeyFormatECPrivateKey:
		if key.ecPrivate == nil {
			return KeyBlock{}, errs.Detail(ErrUnsupported, "key is not an EC private key | 密钥不是 EC 私钥")
		}
		der, err := x509.MarshalECPrivateKey(key.ecPrivate)
		if err != nil {
			return KeyBlock{}, errs.Wrap(err, ErrCryptographic)
		}
		setMaterial(NewByteString(TagKeyMaterial, der))
		return out, nil
	case KeyFormatJWK:
		jwk, err := jwkFromParsedKey(key)
		if err != nil {
			return KeyBlock{}, err
		}
		encoded, err := jwk.MarshalJSON()
		if err != nil {
			return KeyBlock{}, errs.WrapDetail(err, ErrCryptographic, "encode JWK | 编码 JWK 失败")
		}
		setMaterial(NewByteString(TagKeyMaterial, encoded))
		if out.Length == 0 {
			out.Length = key.length
		}
		return out, nil
	default:
		return KeyBlock{}, errs.Detail(ErrUnsupported, "unsupported key format %s | 不支持的密钥格式 %s", format, format)
	}
}
