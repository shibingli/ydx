package kmip

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/errs"
)

// parseJWKKeyBlock decodes a JSON Web Key key block. The JWK must carry material compatible with the key block's
// Cryptographic Algorithm when that field is present; otherwise the algorithm is inferred from the key type and,
// for "oct" keys, from kty, alg and key size. | parseJWKKeyBlock 解码 JSON Web Key 密钥块。密钥块带有密码算法时，
// JWK 材料必须与其兼容；否则根据密钥类型推断算法，对 "oct" 密钥则依据 kty、alg 与密钥长度推断。
func parseJWKKeyBlock(kb KeyBlock, out *parsedKey) error {
	if kb.Algorithm == AlgorithmSM2 {
		return errs.Detail(ErrUnsupported, "SM2 keys cannot be represented as JWK | SM2 密钥无法表示为 JWK")
	}
	material, err := keyMaterialBytes(kb)
	if err != nil {
		return errs.WrapDetail(err, ErrCryptographic, "read JWK key material | 读取 JWK 密钥材料失败")
	}
	key, err := jose.ParseKey(material)
	if err != nil {
		return errs.WrapDetail(err, ErrCryptographic, "parse JWK | 解析 JWK 失败")
	}
	switch key.Kty {
	case jose.KeyTypeRSA, jose.KeyTypeEC, jose.KeyTypeOKP, jose.KeyTypeOct:
	default:
		return errs.Detail(ErrUnsupported, "unsupported JWK kty %q | 不支持的 JWK kty %q", key.Kty, key.Kty)
	}
	if key.Kty == jose.KeyTypeOKP && key.Crv != jose.CurveEd25519 && key.Crv != jose.CurveX25519 {
		return errs.Detail(ErrUnsupported, "unsupported JWK OKP curve %q | 不支持的 JWK OKP 曲线 %q", key.Crv, key.Crv)
	}
	if err := key.Validate(); err != nil {
		return errs.WrapDetail(err, ErrCryptographic, "validate JWK | 校验 JWK 失败")
	}
	inferred, err := inferJWKAlgorithm(key)
	if err != nil {
		return err
	}
	algorithm := kb.Algorithm
	if algorithm == 0 {
		algorithm = inferred
	} else if !jwkAlgorithmCompatible(key, algorithm, inferred) {
		return errs.Detail(ErrCryptographic, "JWK key type is not compatible with algorithm %s | JWK 密钥类型与算法 %s 不兼容", algorithm, algorithm)
	}
	if algorithm == 0 {
		return errs.Detail(ErrCryptographic, "cannot infer a cryptographic algorithm from the JWK | 无法从 JWK 推断密码算法")
	}
	out.algorithm = algorithm
	if err := populateJWKKey(key, out); err != nil {
		return err
	}
	out.jwk = key
	return nil
}

// inferJWKAlgorithm returns the KMIP algorithm represented by a validated JWK. | inferJWKAlgorithm 返回已校验 JWK
// 表示的 KMIP 算法。
func inferJWKAlgorithm(key *jose.Key) (CryptographicAlgorithm, error) {
	if key == nil {
		return 0, errs.Detail(ErrCryptographic, "empty JWK | JWK 为空")
	}
	switch key.Kty {
	case jose.KeyTypeRSA:
		return AlgorithmRSA, nil
	case jose.KeyTypeEC:
		if isECDHJWKAlgorithm(key.Alg) {
			return AlgorithmECDH, nil
		}
		return AlgorithmECDSA, nil
	case jose.KeyTypeOKP:
		switch key.Crv {
		case jose.CurveEd25519:
			return AlgorithmEd25519, nil
		case jose.CurveX25519:
			return AlgorithmECDH, nil
		default:
			return 0, errs.Detail(ErrUnsupported, "unsupported JWK OKP curve %q | 不支持的 JWK OKP 曲线 %q", key.Crv, key.Crv)
		}
	case jose.KeyTypeOct:
		if algorithm := jwkSymmetricAlgorithm(key.Alg); algorithm != 0 {
			return algorithm, nil
		}
		switch keySizeOctets(key) {
		case 16, 24, 32:
			return AlgorithmAES, nil
		case 48:
			return AlgorithmHMACSHA384, nil
		case 64:
			return AlgorithmHMACSHA512, nil
		default:
			return AlgorithmHMACSHA256, nil
		}
	default:
		return 0, errs.Detail(ErrUnsupported, "unsupported JWK kty %q | 不支持的 JWK kty %q", key.Kty, key.Kty)
	}
}

// isECDHJWKAlgorithm reports whether a JWK alg value identifies an ECDH key agreement algorithm. | isECDHJWKAlgorithm
// 报告 JWK alg 取值是否标识 ECDH 密钥协商算法。
func isECDHJWKAlgorithm(alg string) bool {
	switch alg {
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		return true
	default:
		return false
	}
}

// jwkSymmetricAlgorithm maps a JWK alg value onto the KMIP symmetric algorithm it implies. Zero means that alg does
// not identify a symmetric algorithm. | jwkSymmetricAlgorithm 把 JWK alg 取值映射到其蕴含的 KMIP 对称算法。零表示
// alg 未标识对称算法。
func jwkSymmetricAlgorithm(alg string) CryptographicAlgorithm {
	switch alg {
	case "HS256":
		return AlgorithmHMACSHA256
	case "HS384":
		return AlgorithmHMACSHA384
	case "HS512":
		return AlgorithmHMACSHA512
	case "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
		"A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW":
		return AlgorithmAES
	case "SM4-GCM", "SM4-CBC":
		return AlgorithmSM4
	default:
		return 0
	}
}

// keySizeOctets returns the length of an "oct" key in octets. A malformed value returns zero; validation reports the
// malformed member separately. | keySizeOctets 返回 "oct" 密钥的字节长度。非法值返回零；校验会另行报告非法成员。
func keySizeOctets(key *jose.Key) int {
	secret, err := key.PrivateKey()
	if err != nil {
		return 0
	}
	raw, ok := secret.([]byte)
	if !ok {
		return 0
	}
	defer zeroize(raw)
	return len(raw)
}

// jwkAlgorithmCompatible reports whether key can carry algorithm. Symmetric key bytes are algorithm-agnostic, so any
// supported symmetric algorithm is accepted for "oct". NIST EC keys are interchangeable between ECDSA, generic EC and
// ECDH, while X25519 is ECDH-only. | jwkAlgorithmCompatible 报告 key 能否承载 algorithm。对称密钥字节与算法无关，
// 因此 "oct" 接受任何受支持的对称算法。NIST EC 密钥可在 ECDSA、通用 EC 与 ECDH 之间互换，而 X25519 仅用于 ECDH。
func jwkAlgorithmCompatible(key *jose.Key, algorithm, inferred CryptographicAlgorithm) bool {
	if algorithm == inferred {
		return true
	}
	switch key.Kty {
	case jose.KeyTypeOct:
		return isSymmetricAlgorithm(algorithm)
	case jose.KeyTypeEC:
		return algorithm == AlgorithmECDSA || algorithm == AlgorithmEC || algorithm == AlgorithmECDH
	case jose.KeyTypeOKP:
		if key.Crv == jose.CurveX25519 {
			return algorithm == AlgorithmECDH
		}
		return algorithm == AlgorithmEd25519
	default:
		return false
	}
}

// isSymmetricAlgorithm reports whether algorithm uses a symmetric key. | isSymmetricAlgorithm 报告 algorithm 是否
// 使用对称密钥。
func isSymmetricAlgorithm(algorithm CryptographicAlgorithm) bool {
	switch algorithm {
	case AlgorithmAES, AlgorithmSM4, AlgorithmHMACSHA1, AlgorithmHMACSHA224,
		AlgorithmHMACSHA256, AlgorithmHMACSHA384, AlgorithmHMACSHA512, AlgorithmHMACMD5:
		return true
	default:
		return false
	}
}

// populateJWKKey fills the standard-library key family of out from a validated JWK, preserving whether the JWK
// carried private material. | populateJWKKey 从已校验 JWK 填充 out 的标准库密钥族，并保留 JWK 是否携带私钥材料。
func populateJWKKey(key *jose.Key, out *parsedKey) error {
	switch key.Kty {
	case jose.KeyTypeOct:
		value, err := key.PrivateKey()
		if err != nil {
			return errs.WrapDetail(err, ErrCryptographic, "decode oct JWK | 解码 oct JWK 失败")
		}
		secret, ok := value.([]byte)
		if !ok || len(secret) == 0 {
			return errs.Detail(ErrCryptographic, "oct JWK has no key value | oct JWK 没有密钥值")
		}
		out.symmetric = append([]byte(nil), secret...)
		zeroize(secret)
		return nil
	case jose.KeyTypeRSA:
		if key.D != "" {
			value, err := key.PrivateKey()
			if err != nil {
				return errs.WrapDetail(err, ErrCryptographic, "decode RSA private JWK | 解码 RSA 私钥 JWK 失败")
			}
			priv, ok := value.(*rsa.PrivateKey)
			if !ok {
				return errs.Detail(ErrCryptographic, "RSA JWK did not produce an RSA private key | RSA JWK 未产生 RSA 私钥")
			}
			out.rsaPrivate = priv
			out.rsaPublic = &priv.PublicKey
			return nil
		}
		value, err := key.PublicKey()
		if err != nil {
			return errs.WrapDetail(err, ErrCryptographic, "decode RSA public JWK | 解码 RSA 公钥 JWK 失败")
		}
		pub, ok := value.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrCryptographic, "RSA JWK did not produce an RSA public key | RSA JWK 未产生 RSA 公钥")
		}
		out.rsaPublic = pub
		return nil
	case jose.KeyTypeEC:
		if key.D != "" {
			value, err := key.PrivateKey()
			if err != nil {
				return errs.WrapDetail(err, ErrCryptographic, "decode EC private JWK | 解码 EC 私钥 JWK 失败")
			}
			priv, ok := value.(*ecdsa.PrivateKey)
			if !ok {
				return errs.Detail(ErrCryptographic, "EC JWK did not produce an EC private key | EC JWK 未产生 EC 私钥")
			}
			out.ecPrivate = priv
			out.ecPublic = &priv.PublicKey
			return nil
		}
		value, err := key.PublicKey()
		if err != nil {
			return errs.WrapDetail(err, ErrCryptographic, "decode EC public JWK | 解码 EC 公钥 JWK 失败")
		}
		pub, ok := value.(*ecdsa.PublicKey)
		if !ok {
			return errs.Detail(ErrCryptographic, "EC JWK did not produce an EC public key | EC JWK 未产生 EC 公钥")
		}
		out.ecPublic = pub
		return nil
	case jose.KeyTypeOKP:
		switch key.Crv {
		case jose.CurveEd25519:
			if key.D != "" {
				value, err := key.PrivateKey()
				if err != nil {
					return errs.WrapDetail(err, ErrCryptographic, "decode Ed25519 private JWK | 解码 Ed25519 私钥 JWK 失败")
				}
				priv, ok := value.(ed25519.PrivateKey)
				if !ok {
					return errs.Detail(ErrCryptographic, "Ed25519 JWK did not produce a private key | Ed25519 JWK 未产生私钥")
				}
				out.edPrivate = append(ed25519.PrivateKey(nil), priv...)
				out.edPublic = append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
				return nil
			}
			value, err := key.PublicKey()
			if err != nil {
				return errs.WrapDetail(err, ErrCryptographic, "decode Ed25519 public JWK | 解码 Ed25519 公钥 JWK 失败")
			}
			pub, ok := value.(ed25519.PublicKey)
			if !ok {
				return errs.Detail(ErrCryptographic, "Ed25519 JWK did not produce a public key | Ed25519 JWK 未产生公钥")
			}
			out.edPublic = append(ed25519.PublicKey(nil), pub...)
			return nil
		case jose.CurveX25519:
			if key.D != "" {
				value, err := key.PrivateKey()
				if err != nil {
					return errs.WrapDetail(err, ErrCryptographic, "decode X25519 private JWK | 解码 X25519 私钥 JWK 失败")
				}
				priv, ok := value.(*ecdh.PrivateKey)
				if !ok {
					return errs.Detail(ErrCryptographic, "X25519 JWK did not produce a private key | X25519 JWK 未产生私钥")
				}
				out.xPrivate = priv
				out.xPublic = priv.PublicKey()
				return nil
			}
			value, err := key.PublicKey()
			if err != nil {
				return errs.WrapDetail(err, ErrCryptographic, "decode X25519 public JWK | 解码 X25519 公钥 JWK 失败")
			}
			pub, ok := value.(*ecdh.PublicKey)
			if !ok {
				return errs.Detail(ErrCryptographic, "X25519 JWK did not produce a public key | X25519 JWK 未产生公钥")
			}
			out.xPublic = pub
			return nil
		default:
			return errs.Detail(ErrUnsupported, "unsupported JWK OKP curve %q | 不支持的 JWK OKP 曲线 %q", key.Crv, key.Crv)
		}
	default:
		return errs.Detail(ErrUnsupported, "unsupported JWK kty %q | 不支持的 JWK kty %q", key.Kty, key.Kty)
	}
}

// jwkFromParsedKey converts a parsed key into a JWK, preserving parsed JWK metadata when the key originated as a JWK.
// | jwkFromParsedKey 把已解析密钥转换为 JWK；密钥源自 JWK 时保留其元数据。
func jwkFromParsedKey(key *parsedKey) (*jose.Key, error) {
	if key == nil {
		return nil, errs.Detail(ErrCryptographic, "empty parsed key | 已解析密钥为空")
	}
	if key.jwk != nil {
		return key.jwk.Clone(), nil
	}
	var jwk *jose.Key
	var err error
	switch {
	case key.symmetric != nil:
		jwk, err = jose.FromHMAC("", key.symmetric)
	case key.rsaPrivate != nil:
		jwk, err = jose.FromPrivateKey("", key.rsaPrivate)
	case key.rsaPublic != nil:
		jwk, err = jose.FromPublicKey("", key.rsaPublic)
	case key.ecPrivate != nil:
		jwk, err = jose.FromPrivateKey("", key.ecPrivate)
	case key.ecPublic != nil:
		jwk, err = jose.FromPublicKey("", key.ecPublic)
	case key.edPrivate != nil:
		jwk, err = jose.FromPrivateKey("", key.edPrivate)
	case key.edPublic != nil:
		jwk, err = jose.FromPublicKey("", key.edPublic)
	case key.xPrivate != nil:
		jwk, err = jose.FromPrivateKey("", key.xPrivate)
	case key.xPublic != nil:
		jwk, err = jose.FromPublicKey("", key.xPublic)
	case key.sm2Private != nil || key.sm2Public != nil:
		return nil, errs.Detail(ErrUnsupported, "SM2 keys cannot be represented as JWK | SM2 密钥无法表示为 JWK")
	default:
		return nil, errs.Detail(ErrUnsupported, "key cannot be encoded as JWK | 密钥无法编码为 JWK")
	}
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCryptographic, "encode JWK | 编码 JWK 失败")
	}
	return jwk, nil
}
