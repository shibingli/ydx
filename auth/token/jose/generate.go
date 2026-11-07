package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// GenerateKey creates a new random key for alg. | GenerateKey 为 alg 生成新的随机密钥。
//
// Supported algorithms are the JWS families RS256/384/512, PS256/384/512, ES256/384/512,
// EdDSA and HS256/384/512, plus the JWE families RSA-OAEP, RSA-OAEP-256, RSA1_5,
// ECDH-ES and ECDH-ES+A128KW/A192KW/A256KW. For RSA algorithms bits is the modulus size and
// defaults to 2048; values below 2048 are refused. For ECDH-ES algorithms bits selects the NIST
// curve (256, 384 or 521) and defaults to 256. For HMAC algorithms bits is the secret size and
// defaults to the hash output size. | 支持的算法包括 JWS 家族 RS256/384/512、PS256/384/512、
// ES256/384/512、EdDSA 与 HS256/384/512，以及 JWE 家族 RSA-OAEP、RSA-OAEP-256、RSA1_5、
// ECDH-ES 与 ECDH-ES+A128KW/A192KW/A256KW。RSA 算法的 bits 为模数长度，默认 2048，小于 2048
// 会被拒绝。ECDH-ES 算法的 bits 选择 NIST 曲线（256、384 或 521），默认 256。HMAC 算法的 bits
// 为密钥长度，默认为哈希输出长度。
func GenerateKey(alg string, bits int) (*Key, error) {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
		"RSA-OAEP", "RSA-OAEP-256", "RSA1_5":
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, errs.Detail(ErrWeakKey, "RSA key size %[1]d is below 2048 | RSA 密钥长度 %[1]d 小于 2048", bits)
		}
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "generate RSA key | 生成 RSA 密钥")
		}
		k := rsaPrivateToKey(priv)
		k.Alg = alg
		return k.withCache(), nil
	case "ES256", "ES384", "ES512":
		crv, err := ecCurveForAlg(alg)
		if err != nil {
			return nil, err
		}
		priv, err := ecdsa.GenerateKey(crv, rand.Reader)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "generate EC key | 生成 EC 密钥")
		}
		k, err := ecPrivateToKey(priv)
		if err != nil {
			return nil, err
		}
		k.Alg = alg
		return k.withCache(), nil
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "generate Ed25519 key | 生成 Ed25519 密钥")
		}
		k := &Key{
			Kty: KeyTypeOKP,
			Crv: CurveEd25519,
			X:   b64(pub),
			D:   b64(priv.Seed()),
			Alg: alg,
		}
		return k.withCache(), nil
	case "HS256", "HS384", "HS512":
		h, _ := jwsHash(alg)
		if bits == 0 {
			bits = h.Size() * 8
		}
		if bits < h.Size()*8 {
			return nil, errs.Detail(ErrWeakKey, "alg=%[1]s needs at least %[2]d bits | 算法 %[1]s 至少需要 %[2]d 位", alg, h.Size()*8)
		}
		secret := make([]byte, (bits+7)/8)
		if _, err := rand.Read(secret); err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "generate HMAC key | 生成 HMAC 密钥")
		}
		return (&Key{Kty: KeyTypeOct, K: b64(secret), Alg: alg}).withCache(), nil
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		crv, err := ecdhCurveForBits(bits)
		if err != nil {
			return nil, err
		}
		priv, err := ecdsa.GenerateKey(crv, rand.Reader)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "generate ECDH key | 生成 ECDH 密钥")
		}
		k, err := ecPrivateToKey(priv)
		if err != nil {
			return nil, err
		}
		k.Alg = alg
		k.Use = "enc"
		return k.withCache(), nil
	default:
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
}

// FromPrivateKey converts a standard-library private key into a JWK with the given kid. | FromPrivateKey
// 把标准库私钥转换为带指定 kid 的 JWK。
//
// Accepted types are *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey
// (X25519 only) and []byte or string for a symmetric "oct" key. The algorithm is left unset so the
// key can be reused for every compatible algorithm. | 接受 *rsa.PrivateKey、*ecdsa.PrivateKey、
// ed25519.PrivateKey、*ecdh.PrivateKey（仅 X25519）以及 []byte 或 string 对称 "oct" 密钥。
// 算法保持未设置，使密钥可用于所有兼容算法。
func FromPrivateKey(kid string, priv any) (*Key, error) {
	var k *Key
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		if err := key.Validate(); err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "RSA private key | RSA 私钥")
		}
		k = rsaPrivateToKey(key)
	case *ecdsa.PrivateKey:
		if key == nil {
			return nil, ErrInvalidKey
		}
		// Bytes validates the scalar and the public point through the standard library instead of
		// inspecting the deprecated D, X and Y fields directly. | Bytes 通过标准库校验标量与公钥点，
		// 无需直接读取已弃用的 D、X、Y 字段。
		if _, err := key.Bytes(); err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "EC private key | EC 私钥")
		}
		if _, err := key.PublicKey.Bytes(); err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "EC public key | EC 公钥")
		}
		converted, err := ecPrivateToKey(key)
		if err != nil {
			return nil, err
		}
		k = converted
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, errs.Detail(ErrInvalidKey, "Ed25519 private key is %[1]d bytes | Ed25519 私钥为 %[1]d 字节", len(key))
		}
		k = &Key{Kty: KeyTypeOKP, Crv: CurveEd25519, X: b64(key.Public().(ed25519.PublicKey)), D: b64(key.Seed())}
	case *ecdh.PrivateKey:
		if key == nil {
			return nil, ErrInvalidKey
		}
		if !isX25519Curve(key.Curve()) {
			return nil, errs.Detail(ErrInvalidKey, "only X25519 ECDH keys are supported | 仅支持 X25519 ECDH 密钥")
		}
		k = &Key{Kty: KeyTypeOKP, Crv: CurveX25519, X: b64(key.PublicKey().Bytes()), D: b64(key.Bytes())}
	case []byte:
		if len(key) == 0 {
			return nil, errs.Detail(ErrInvalidKey, "empty symmetric key | 对称密钥为空")
		}
		k = &Key{Kty: KeyTypeOct, K: b64(key)}
	case string:
		if key == "" {
			return nil, errs.Detail(ErrInvalidKey, "empty symmetric key | 对称密钥为空")
		}
		k = &Key{Kty: KeyTypeOct, K: b64([]byte(key))}
	default:
		return nil, errs.Detail(ErrInvalidKey, "unsupported private key type %[1]T | 不支持的私钥类型 %[1]T", priv)
	}
	k.Kid = kid
	return k.withCache(), nil
}

// FromPublicKey converts a standard-library public key into a JWK with the given kid. | FromPublicKey
// 把标准库公钥转换为带指定 kid 的 JWK。
//
// Accepted types are *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey
// (X25519 only) and []byte or string for a symmetric "oct" key. | 接受 *rsa.PublicKey、
// *ecdsa.PublicKey、ed25519.PublicKey、*ecdh.PublicKey（仅 X25519）以及 []byte 或 string 对称
// "oct" 密钥。
func FromPublicKey(kid string, pub any) (*Key, error) {
	var k *Key
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.E <= 0 {
			return nil, ErrInvalidKey
		}
		k = &Key{Kty: KeyTypeRSA, N: b64(key.N.Bytes()), E: b64(new(big.Int).SetInt64(int64(key.E)).Bytes())}
	case *ecdsa.PublicKey:
		if key == nil {
			return nil, ErrInvalidKey
		}
		crv, ok := ecCurveName(key.Curve)
		if !ok {
			return nil, errs.Detail(ErrInvalidKey, "unsupported EC curve | 不支持的 EC 曲线")
		}
		// Bytes returns the SEC 1 uncompressed point and validates the key, so the deprecated X and
		// Y fields never have to be read. | Bytes 返回 SEC 1 未压缩点并完成密钥校验，因此无需读取
		// 已弃用的 X 与 Y 字段。
		raw, err := key.Bytes()
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidKey, "EC public key | EC 公钥")
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		if len(raw) != 1+2*size {
			return nil, errs.Detail(ErrInvalidKey, "EC public key has %[1]d bytes | EC 公钥为 %[1]d 字节", len(raw))
		}
		k = &Key{
			Kty: KeyTypeEC,
			Crv: crv,
			X:   b64(raw[1 : 1+size]),
			Y:   b64(raw[1+size:]),
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, errs.Detail(ErrInvalidKey, "Ed25519 public key is %[1]d bytes | Ed25519 公钥为 %[1]d 字节", len(key))
		}
		k = &Key{Kty: KeyTypeOKP, Crv: CurveEd25519, X: b64(key)}
	case *ecdh.PublicKey:
		if key == nil || !isX25519Curve(key.Curve()) {
			return nil, errs.Detail(ErrInvalidKey, "only X25519 ECDH keys are supported | 仅支持 X25519 ECDH 密钥")
		}
		k = &Key{Kty: KeyTypeOKP, Crv: CurveX25519, X: b64(key.Bytes())}
	case []byte:
		if len(key) == 0 {
			return nil, errs.Detail(ErrInvalidKey, "empty symmetric key | 对称密钥为空")
		}
		k = &Key{Kty: KeyTypeOct, K: b64(key)}
	case string:
		if key == "" {
			return nil, errs.Detail(ErrInvalidKey, "empty symmetric key | 对称密钥为空")
		}
		k = &Key{Kty: KeyTypeOct, K: b64([]byte(key))}
	default:
		return nil, errs.Detail(ErrInvalidKey, "unsupported public key type %[1]T | 不支持的公钥类型 %[1]T", pub)
	}
	k.Kid = kid
	return k.withCache(), nil
}

// FromHMAC creates a symmetric "oct" JWK from a shared secret. | FromHMAC 用共享密钥创建对称
// "oct" JWK。
func FromHMAC(kid string, secret []byte) (*Key, error) {
	if len(secret) == 0 {
		return nil, errs.Detail(ErrInvalidKey, "empty HMAC secret | HMAC 密钥为空")
	}
	return (&Key{Kty: KeyTypeOct, Kid: kid, K: b64(secret)}).withCache(), nil
}

// rsaPrivateToKey converts an RSA private key into a JWK. | rsaPrivateToKey 把 RSA 私钥转换为 JWK。
func rsaPrivateToKey(priv *rsa.PrivateKey) *Key {
	priv.Precompute()
	k := &Key{
		Kty: KeyTypeRSA,
		N:   b64(priv.N.Bytes()),
		E:   b64(new(big.Int).SetInt64(int64(priv.E)).Bytes()),
	}
	if len(priv.Primes) < 2 || priv.D == nil {
		return k
	}
	p, q := priv.Primes[0], priv.Primes[1]
	k.D = b64(priv.D.Bytes())
	k.P = b64(p.Bytes())
	k.Q = b64(q.Bytes())
	if priv.Precomputed.Dp != nil {
		k.DP = b64(priv.Precomputed.Dp.Bytes())
	}
	if priv.Precomputed.Dq != nil {
		k.DQ = b64(priv.Precomputed.Dq.Bytes())
	}
	if priv.Precomputed.Qinv != nil {
		k.QI = b64(priv.Precomputed.Qinv.Bytes())
	}
	acc := new(big.Int).Mul(p, q)
	for i := 2; i < len(priv.Primes); i++ {
		r := priv.Primes[i]
		exp := new(big.Int).Sub(r, big.NewInt(1))
		dp := new(big.Int).Mod(priv.D, exp)
		t := new(big.Int).ModInverse(acc, r)
		if t == nil {
			continue
		}
		k.Oth = append(k.Oth, OtherPrime{R: b64(r.Bytes()), D: b64(dp.Bytes()), T: b64(t.Bytes())})
		acc.Mul(acc, r)
	}
	return k
}

// ecPrivateToKey converts an ECDSA private key into a JWK. | ecPrivateToKey 把 ECDSA 私钥转换为
// JWK。
//
// The standard-library Bytes methods produce the fixed-width scalar and the SEC 1 uncompressed point,
// which are exactly the JWK d, x and y members, without reading the deprecated D, X and Y fields. |
// 标准库的 Bytes 方法产出定宽标量与 SEC 1 未压缩点，正好对应 JWK 的 d、x 与 y 成员，无需读取已弃用
// 的 D、X 与 Y 字段。
func ecPrivateToKey(priv *ecdsa.PrivateKey) (*Key, error) {
	crv, ok := ecCurveName(priv.Curve)
	if !ok {
		return nil, errs.Detail(ErrInvalidKey, "unsupported EC curve | 不支持的 EC 曲线")
	}
	scalar, err := priv.Bytes()
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "EC private key | EC 私钥")
	}
	// PrivateKey.Bytes embeds PublicKey, but calling it on the embedded value can be ambiguous in
	// readability; take the address explicitly. | PrivateKey.Bytes 内嵌自 PublicKey，显式取地址调用
	// 以免混淆。
	public, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidKey, "EC public key | EC 公钥")
	}
	size := (priv.Curve.Params().BitSize + 7) / 8
	if len(scalar) != size || len(public) != 1+2*size {
		return nil, errs.Detail(ErrInvalidKey, "EC key has an unexpected length | EC 密钥长度异常")
	}
	return &Key{
		Kty: KeyTypeEC,
		Crv: crv,
		X:   b64(public[1 : 1+size]),
		Y:   b64(public[1+size:]),
		D:   b64(scalar),
	}, nil
}

// b64 returns the unpadded base64url encoding of src. | b64 返回 src 的无填充 base64url 编码。
func b64(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

// ecCurveForAlg returns the NIST curve required by an ECDSA algorithm. | ecCurveForAlg 返回 ECDSA
// 算法要求的 NIST 曲线。
func ecCurveForAlg(alg string) (elliptic.Curve, error) {
	switch alg {
	case "ES256":
		return elliptic.P256(), nil
	case "ES384":
		return elliptic.P384(), nil
	case "ES512":
		return elliptic.P521(), nil
	}
	return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
}

// ecdhCurveForBits maps a key size in bits to a NIST curve for ECDH-ES. | ecdhCurveForBits 把位数
// 映射为 ECDH-ES 使用的 NIST 曲线。
func ecdhCurveForBits(bits int) (elliptic.Curve, error) {
	switch bits {
	case 0, 256:
		return elliptic.P256(), nil
	case 384:
		return elliptic.P384(), nil
	case 521:
		return elliptic.P521(), nil
	default:
		return nil, errs.Detail(ErrInvalidConfig, "unsupported ECDH key size %[1]d | 不支持的 ECDH 密钥长度 %[1]d", bits)
	}
}

// isX25519Curve reports whether c is the X25519 ECDH curve. | isX25519Curve 报告 c 是否为 X25519
// ECDH 曲线。
func isX25519Curve(c ecdh.Curve) bool {
	return c != nil && c == ecdh.X25519()
}
