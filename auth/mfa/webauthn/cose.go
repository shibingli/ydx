package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"math/big"

	"github.com/shibingli/ydx/errs"
)

// COSE key type identifiers (RFC 9052 §7.1). | COSE 密钥类型标识（RFC 9052 §7.1）。
const (
	// KeyTypeOKP is an octet key pair. | KeyTypeOKP 是字节密钥对。
	KeyTypeOKP = 1
	// KeyTypeEC2 is an elliptic curve key with explicit coordinates. | KeyTypeEC2 是带显式坐标的椭圆曲线密钥。
	KeyTypeEC2 = 2
	// KeyTypeRSA is an RSA key. | KeyTypeRSA 是 RSA 密钥。
	KeyTypeRSA = 3
)

// COSE algorithm identifiers used by WebAuthn. | WebAuthn 使用的 COSE 算法标识。
const (
	// AlgES256 is ECDSA with P-256 and SHA-256. | AlgES256 是 P-256 与 SHA-256 的 ECDSA。
	AlgES256 = -7
	// AlgEdDSA is Ed25519. | AlgEdDSA 是 Ed25519。
	AlgEdDSA = -8
	// AlgES384 is ECDSA with P-384 and SHA-384. | AlgES384 是 P-384 与 SHA-384 的 ECDSA。
	AlgES384 = -35
	// AlgES512 is ECDSA with P-521 and SHA-512. | AlgES512 是 P-521 与 SHA-512 的 ECDSA。
	AlgES512 = -36
	// AlgPS256 is RSASSA-PSS with SHA-256. | AlgPS256 是使用 SHA-256 的 RSASSA-PSS。
	AlgPS256 = -37
	// AlgPS384 is RSASSA-PSS with SHA-384. | AlgPS384 是使用 SHA-384 的 RSASSA-PSS。
	AlgPS384 = -38
	// AlgPS512 is RSASSA-PSS with SHA-512. | AlgPS512 是使用 SHA-512 的 RSASSA-PSS。
	AlgPS512 = -39
	// AlgRS256 is RSASSA-PKCS1-v1_5 with SHA-256. | AlgRS256 是使用 SHA-256 的 RSASSA-PKCS1-v1_5。
	AlgRS256 = -257
	// AlgRS384 is RSASSA-PKCS1-v1_5 with SHA-384. | AlgRS384 是使用 SHA-384 的 RSASSA-PKCS1-v1_5。
	AlgRS384 = -258
	// AlgRS512 is RSASSA-PKCS1-v1_5 with SHA-512. | AlgRS512 是使用 SHA-512 的 RSASSA-PKCS1-v1_5。
	AlgRS512 = -259
)

// COSE curve identifiers used by WebAuthn. | WebAuthn 使用的 COSE 曲线标识。
const (
	// CurveP256 is NIST P-256. | CurveP256 是 NIST P-256。
	CurveP256 = 1
	// CurveP384 is NIST P-384. | CurveP384 是 NIST P-384。
	CurveP384 = 2
	// CurveP521 is NIST P-521. | CurveP521 是 NIST P-521。
	CurveP521 = 3
	// CurveEd25519 is Ed25519. | CurveEd25519 是 Ed25519。
	CurveEd25519 = 6
)

// COSEKey is a public WebAuthn credential key in COSE_Key form. | COSEKey 是 COSE_Key 形式的 WebAuthn 公钥凭据。
//
// Only public parameters are accepted; private key material is rejected at parse time. | 只接受公开参数；
// 解析时会拒绝私钥材料。
type COSEKey struct {
	// Kty is the key type, one of KeyTypeOKP, KeyTypeEC2 or KeyTypeRSA. | Kty 是密钥类型，取 KeyTypeOKP、KeyTypeEC2 或 KeyTypeRSA。
	Kty int
	// Kid is the optional key identifier. | Kid 是可选的密钥标识。
	Kid []byte
	// Alg is the COSE signature algorithm. | Alg 是 COSE 签名算法。
	Alg int
	// Crv is the curve identifier for EC2 and OKP keys. | Crv 是 EC2 与 OKP 密钥的曲线标识。
	Crv int
	// X is the EC2 affine x coordinate. | X 是 EC2 仿射 x 坐标。
	X []byte
	// Y is the EC2 affine y coordinate. | Y 是 EC2 仿射 y 坐标。
	Y []byte
	// N is the RSA modulus. | N 是 RSA 模数。
	N []byte
	// E is the RSA public exponent. | E 是 RSA 公开指数。
	E []byte
}

// Algorithm returns the COSE algorithm identifier of the key. | Algorithm 返回密钥的 COSE 算法标识。
func (k *COSEKey) Algorithm() int {
	if k == nil {
		return 0
	}
	return k.Alg
}

// HashForAlgorithm returns the hash function bound to a COSE algorithm. | HashForAlgorithm 返回 COSE 算法绑定的哈希函数。
func HashForAlgorithm(alg int) (crypto.Hash, bool) {
	switch alg {
	case AlgES256, AlgPS256, AlgRS256:
		return crypto.SHA256, true
	case AlgES384, AlgPS384, AlgRS384:
		return crypto.SHA384, true
	case AlgES512, AlgPS512, AlgRS512:
		return crypto.SHA512, true
	case AlgEdDSA:
		return 0, true
	default:
		return 0, false
	}
}

// AlgorithmName returns the conventional name of a COSE signature algorithm. | AlgorithmName 返回 COSE 签名算法的惯用名称。
func AlgorithmName(alg int) string {
	switch alg {
	case AlgES256:
		return "ES256"
	case AlgEdDSA:
		return "EdDSA"
	case AlgES384:
		return "ES384"
	case AlgES512:
		return "ES512"
	case AlgPS256:
		return "PS256"
	case AlgPS384:
		return "PS384"
	case AlgPS512:
		return "PS512"
	case AlgRS256:
		return "RS256"
	case AlgRS384:
		return "RS384"
	case AlgRS512:
		return "RS512"
	default:
		return ""
	}
}

// ParseCOSEKey parses a COSE_Key encoded as CBOR. | ParseCOSEKey 解析 CBOR 编码的 COSE_Key。
func ParseCOSEKey(data []byte) (*COSEKey, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	return ParseCOSEKeyValue(v)
}

// ParseCOSEKeyValue parses an already decoded COSE_Key map. | ParseCOSEKeyValue 解析已解码的 COSE_Key 映射。
func ParseCOSEKeyValue(v *Value) (*COSEKey, error) {
	if v == nil || v.Kind != KindMap {
		return nil, errs.Detail(ErrInvalidCOSEKey, "COSE key is not a map | COSE 公钥不是映射")
	}
	k := &COSEKey{}
	var minus1, minus2, minus3 *Value
	seen := make(map[int64]bool)
	for i := range v.Pairs {
		key, ok := v.Pairs[i].Key.AsInt64()
		if !ok {
			return nil, errs.Detail(ErrInvalidCOSEKey, "COSE key label is not an integer | COSE 公钥标签不是整数")
		}
		if seen[key] {
			return nil, errs.Detail(ErrInvalidCOSEKey, "duplicate COSE key label %d | 重复的 COSE 公钥标签 %d", key, key)
		}
		seen[key] = true
		value := v.Pairs[i].Value
		switch key {
		case 1: // kty
			n, ok := value.AsInt64()
			if !ok {
				return nil, errs.Detail(ErrInvalidCOSEKey, "kty is not an integer | kty 不是整数")
			}
			k.Kty = int(n)
		case 2: // kid
			b, ok := value.AsBytes()
			if !ok {
				return nil, errs.Detail(ErrInvalidCOSEKey, "kid is not a byte string | kid 不是字节串")
			}
			k.Kid = append([]byte(nil), b...)
		case 3: // alg
			n, ok := value.AsInt64()
			if !ok {
				return nil, errs.Detail(ErrInvalidCOSEKey, "alg is not an integer | alg 不是整数")
			}
			k.Alg = int(n)
		case -1:
			minus1 = value
		case -2:
			minus2 = value
		case -3:
			minus3 = value
		case -4, -5, -6, -7, -8, -9, -10, -11, -12, -13:
			return nil, errs.Detail(ErrUnsupportedKey, "private COSE key parameter %d | 私有 COSE 密钥参数 %d", key, key)
		}
	}
	switch k.Kty {
	case KeyTypeEC2, KeyTypeOKP:
		crv, ok := minus1.AsInt64()
		if !ok {
			return nil, errs.Detail(ErrInvalidCOSEKey, "crv is not an integer | crv 不是整数")
		}
		k.Crv = int(crv)
		x, ok := minus2.AsBytes()
		if !ok {
			return nil, errs.Detail(ErrInvalidCOSEKey, "x is not a byte string | x 不是字节串")
		}
		k.X = append([]byte(nil), x...)
		if k.Kty == KeyTypeEC2 {
			y, ok := minus3.AsBytes()
			if !ok {
				return nil, errs.Detail(ErrInvalidCOSEKey, "y is not a byte string | y 不是字节串")
			}
			k.Y = append([]byte(nil), y...)
		} else if minus3 != nil {
			return nil, errs.Detail(ErrInvalidCOSEKey, "OKP key has an unexpected y parameter | OKP 密钥包含意外的 y 参数")
		}
	case KeyTypeRSA:
		n, ok := minus1.AsBytes()
		if !ok {
			return nil, errs.Detail(ErrInvalidCOSEKey, "n is not a byte string | n 不是字节串")
		}
		e, ok := minus2.AsBytes()
		if !ok {
			return nil, errs.Detail(ErrInvalidCOSEKey, "e is not a byte string | e 不是字节串")
		}
		k.N = append([]byte(nil), n...)
		k.E = append([]byte(nil), e...)
		if minus3 != nil {
			return nil, errs.Detail(ErrInvalidCOSEKey, "RSA key has an unexpected label -3 | RSA 密钥包含意外的标签 -3")
		}
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported key type %d | 不支持的密钥类型 %d", k.Kty, k.Kty)
	}
	if err := k.validate(); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *COSEKey) validate() error {
	if k == nil {
		return errs.Detail(ErrInvalidCOSEKey, "nil key | 空密钥")
	}
	switch k.Kty {
	case KeyTypeEC2:
		switch k.Crv {
		case CurveP256:
			if k.X == nil || k.Y == nil || !k.rsaParamsAbsent() {
				// N/E must be empty for EC2 keys. | EC2 密钥的 N/E 必须为空。
				return errs.Detail(ErrInvalidCOSEKey, "EC2 key has inconsistent parameters | EC2 密钥参数不一致")
			}
			if k.Alg != AlgES256 {
				return errs.Detail(ErrAlgorithmMismatch, "P-256 requires ES256, got %d | P-256 需要 ES256，实际为 %d", k.Alg, k.Alg)
			}
			return validateECPoint(k, elliptic.P256(), 32)
		case CurveP384:
			if k.X == nil || k.Y == nil || !k.rsaParamsAbsent() {
				return errs.Detail(ErrInvalidCOSEKey, "EC2 key has inconsistent parameters | EC2 密钥参数不一致")
			}
			if k.Alg != AlgES384 {
				return errs.Detail(ErrAlgorithmMismatch, "P-384 requires ES384, got %d | P-384 需要 ES384，实际为 %d", k.Alg, k.Alg)
			}
			return validateECPoint(k, elliptic.P384(), 48)
		case CurveP521:
			if k.X == nil || k.Y == nil || !k.rsaParamsAbsent() {
				return errs.Detail(ErrInvalidCOSEKey, "EC2 key has inconsistent parameters | EC2 密钥参数不一致")
			}
			if k.Alg != AlgES512 {
				return errs.Detail(ErrAlgorithmMismatch, "P-521 requires ES512, got %d | P-521 需要 ES512，实际为 %d", k.Alg, k.Alg)
			}
			return validateECPoint(k, elliptic.P521(), 66)
		default:
			return errs.Detail(ErrUnsupportedKey, "unsupported EC2 curve %d | 不支持的 EC2 曲线 %d", k.Crv, k.Crv)
		}
	case KeyTypeRSA:
		if k.N == nil || len(k.E) == 0 {
			return errs.Detail(ErrInvalidCOSEKey, "RSA key lacks n or e | RSA 密钥缺少 n 或 e")
		}
		switch k.Alg {
		case AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512:
		default:
			return errs.Detail(ErrUnsupportedAlgorithm, "unsupported RSA algorithm %d | 不支持的 RSA 算法 %d", k.Alg, k.Alg)
		}
		n := new(big.Int).SetBytes(k.N)
		if n.BitLen() < 2048 || n.BitLen() > 8192 {
			return errs.Detail(ErrInvalidCOSEKey, "RSA modulus is %d bits | RSA 模数为 %d 位", n.BitLen(), n.BitLen())
		}
		e := new(big.Int).SetBytes(k.E)
		if e.BitLen() < 2 || e.BitLen() > 32 || e.Bit(0) == 0 {
			return errs.Detail(ErrInvalidCOSEKey, "invalid RSA public exponent | RSA 公开指数非法")
		}
		return nil
	case KeyTypeOKP:
		if k.Crv != CurveEd25519 {
			return errs.Detail(ErrUnsupportedKey, "unsupported OKP curve %d | 不支持的 OKP 曲线 %d", k.Crv, k.Crv)
		}
		if k.Alg != AlgEdDSA {
			return errs.Detail(ErrAlgorithmMismatch, "Ed25519 requires EdDSA, got %d | Ed25519 需要 EdDSA，实际为 %d", k.Alg, k.Alg)
		}
		if len(k.X) != ed25519.PublicKeySize {
			return errs.Detail(ErrInvalidCOSEKey, "Ed25519 key length is %d | Ed25519 密钥长度为 %d", len(k.X), len(k.X))
		}
		return nil
	default:
		return errs.Detail(ErrUnsupportedKey, "unsupported key type %d | 不支持的密钥类型 %d", k.Kty, k.Kty)
	}
}

// rsaParamsAbsent reports whether the RSA parameters are absent. | rsaParamsAbsent 报告 RSA 参数是否缺失。
func (k *COSEKey) rsaParamsAbsent() bool { return len(k.N) == 0 && len(k.E) == 0 }

func validateECPoint(k *COSEKey, curve elliptic.Curve, size int) error {
	if len(k.X) != size || len(k.Y) != size {
		return errs.Detail(ErrInvalidCOSEKey, "coordinate length is %d/%d, want %d | 坐标长度为 %d/%d，期望 %d", len(k.X), len(k.Y), size, len(k.X), len(k.Y), size)
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressedPoint(k.X, k.Y)); err != nil {
		return errs.Detail(ErrInvalidCOSEKey, "EC point is not on the curve | EC 点不在曲线上")
	}
	return nil
}

// uncompressedPoint returns the SEC 1 uncompressed encoding of the COSE coordinates. |
// uncompressedPoint 返回 COSE 坐标的 SEC 1 无压缩编码。
func uncompressedPoint(x, y []byte) []byte {
	point := make([]byte, 1+len(x)+len(y))
	point[0] = 0x04
	copy(point[1:], x)
	copy(point[1+len(x):], y)
	return point
}

// PublicKey returns the crypto.PublicKey represented by the COSE key. | PublicKey 返回 COSE 密钥对应的 crypto.PublicKey。
func (k *COSEKey) PublicKey() (crypto.PublicKey, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	switch k.Kty {
	case KeyTypeEC2:
		var curve elliptic.Curve
		switch k.Crv {
		case CurveP256:
			curve = elliptic.P256()
		case CurveP384:
			curve = elliptic.P384()
		case CurveP521:
			curve = elliptic.P521()
		}
		publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressedPoint(k.X, k.Y))
		if err != nil {
			return nil, errs.Detail(ErrInvalidCOSEKey, "EC point is not on the curve | EC 点不在曲线上")
		}
		return publicKey, nil
	case KeyTypeRSA:
		e := new(big.Int).SetBytes(k.E)
		if !e.IsInt64() || e.Int64() > int64(^uint32(0)>>1) {
			return nil, errs.Detail(ErrInvalidCOSEKey, "RSA exponent does not fit an int | RSA 指数无法放入 int")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(k.N), E: int(e.Int64())}, nil
	case KeyTypeOKP:
		return ed25519.PublicKey(append([]byte(nil), k.X...)), nil
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported key type %d | 不支持的密钥类型 %d", k.Kty, k.Kty)
	}
}

// Encode encodes the COSE key as canonical CBOR. | Encode 把 COSE 公钥编码为规范 CBOR。
func (k *COSEKey) Encode() ([]byte, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	pairs := []Pair{{Key: NewInt(1), Value: NewInt(int64(k.Kty))}}
	if k.Kid != nil {
		pairs = append(pairs, Pair{Key: NewInt(2), Value: NewBytes(k.Kid)})
	}
	pairs = append(pairs, Pair{Key: NewInt(3), Value: NewInt(int64(k.Alg))})
	switch k.Kty {
	case KeyTypeEC2:
		pairs = append(pairs,
			Pair{Key: NewInt(-1), Value: NewInt(int64(k.Crv))},
			Pair{Key: NewInt(-2), Value: NewBytes(k.X)},
			Pair{Key: NewInt(-3), Value: NewBytes(k.Y)},
		)
	case KeyTypeRSA:
		pairs = append(pairs,
			Pair{Key: NewInt(-1), Value: NewBytes(k.N)},
			Pair{Key: NewInt(-2), Value: NewBytes(k.E)},
		)
	case KeyTypeOKP:
		pairs = append(pairs,
			Pair{Key: NewInt(-1), Value: NewInt(int64(k.Crv))},
			Pair{Key: NewInt(-2), Value: NewBytes(k.X)},
		)
	}
	return Encode(NewMap(pairs...))
}

// Verify verifies signature over message with the algorithm alg. | Verify 使用算法 alg 校验 message 上的 signature。
//
// alg must equal the key algorithm; a mismatch returns ErrAlgorithmMismatch. | alg 必须等于密钥算法；
// 不一致时返回 ErrAlgorithmMismatch。
func (k *COSEKey) Verify(alg int, message, signature []byte) error {
	if k == nil {
		return errs.Detail(ErrInvalidCOSEKey, "nil key | 空密钥")
	}
	if alg != k.Alg {
		return errs.Detail(ErrAlgorithmMismatch, "requested %s, key uses %s | 请求 %s，密钥使用 %s",
			AlgorithmName(alg), AlgorithmName(k.Alg), AlgorithmName(alg), AlgorithmName(k.Alg))
	}
	pub, err := k.PublicKey()
	if err != nil {
		return err
	}
	return VerifySignature(alg, pub, message, signature)
}

// VerifySignature verifies signature over message using pub and a COSE algorithm identifier. | VerifySignature 使用 pub 与 COSE 算法标识校验 message 上的 signature。
//
// ECDSA signatures may be ASN.1 DER (the WebAuthn encoding) or the fixed-width r||s form used by
// some authenticators. RSA-PSS uses a salt length equal to the hash length. | ECDSA 签名可以是
// ASN.1 DER（WebAuthn 编码），也可以是部分认证器使用的定宽 r||s 形式。RSA-PSS 使用等于哈希
// 长度的盐长度。
func VerifySignature(alg int, pub crypto.PublicKey, message, signature []byte) error {
	if len(signature) == 0 {
		return errs.Detail(ErrSignatureInvalid, "empty signature | 空签名")
	}
	hash, ok := HashForAlgorithm(alg)
	if !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "algorithm %d | 算法 %d", alg, alg)
	}
	var digest []byte
	switch hash {
	case crypto.SHA256:
		sum := sha256.Sum256(message)
		digest = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(message)
		digest = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(message)
		digest = sum[:]
	case 0:
		digest = message
	}
	switch alg {
	case AlgES256, AlgES384, AlgES512:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errs.Detail(ErrUnsupportedKey, "ECDSA algorithm with a non-ECDSA key | ECDSA 算法搭配非 ECDSA 密钥")
		}
		var want elliptic.Curve
		var size int
		switch alg {
		case AlgES256:
			want, size = elliptic.P256(), 32
		case AlgES384:
			want, size = elliptic.P384(), 48
		default:
			want, size = elliptic.P521(), 66
		}
		if key.Curve != want {
			return errs.Detail(ErrAlgorithmMismatch, "curve does not match %s | 曲线与 %s 不匹配", AlgorithmName(alg), AlgorithmName(alg))
		}
		if ecdsa.VerifyASN1(key, digest, signature) {
			return nil
		}
		if len(signature) == 2*size {
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			if ecdsa.Verify(key, digest, r, s) {
				return nil
			}
		}
		return errs.Detail(ErrSignatureInvalid, "ECDSA verification failed | ECDSA 校验失败")
	case AlgEdDSA:
		key, ok := pub.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return errs.Detail(ErrUnsupportedKey, "EdDSA algorithm with a non-Ed25519 key | EdDSA 算法搭配非 Ed25519 密钥")
		}
		if !ed25519.Verify(key, message, signature) {
			return errs.Detail(ErrSignatureInvalid, "Ed25519 verification failed | Ed25519 校验失败")
		}
		return nil
	case AlgRS256, AlgRS384, AlgRS512:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrUnsupportedKey, "RSA algorithm with a non-RSA key | RSA 算法搭配非 RSA 密钥")
		}
		if err := rsa.VerifyPKCS1v15(key, hash, digest, signature); err != nil {
			return errs.Detail(ErrSignatureInvalid, "RSA PKCS#1 verification failed | RSA PKCS#1 校验失败")
		}
		return nil
	case AlgPS256, AlgPS384, AlgPS512:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrUnsupportedKey, "RSA algorithm with a non-RSA key | RSA 算法搭配非 RSA 密钥")
		}
		err := rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
		if err != nil {
			return errs.Detail(ErrSignatureInvalid, "RSA PSS verification failed | RSA PSS 校验失败")
		}
		return nil
	default:
		return errs.Detail(ErrUnsupportedAlgorithm, "algorithm %d | 算法 %d", alg, alg)
	}
}

// constantTimeEqual compares two byte slices without data-dependent branches. | constantTimeEqual 以无数据相关分支的方式比较两个字节切片。
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
