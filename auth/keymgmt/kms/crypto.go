package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"sort"

	_ "crypto/sha512" // register SHA-384 and SHA-512 with crypto.Hash | 向 crypto.Hash 注册 SHA-384 与 SHA-512

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// signOptions holds the normalized signature parameters. | signOptions 保存规范化后的签名参数。
type signOptions struct {
	// digest reports that the caller supplied a precomputed digest. | digest 表示调用方提供了预计算摘要。
	digest bool
	// hash is the digest algorithm; SHA-256 when unset. | hash 是摘要算法；未设置时为 SHA-256。
	hash crypto.Hash
	// pss selects RSA-PSS instead of PKCS#1 v1.5. | pss 选择 RSA-PSS 而非 PKCS#1 v1.5。
	pss bool
}

// SignOption customizes Sign and Verify. | SignOption 定制 Sign 与 Verify。
type SignOption func(*signOptions)

// WithDigest declares that data is already a digest of the message. | WithDigest 声明 data 已是消息摘要。
func WithDigest() SignOption {
	return func(o *signOptions) { o.digest = true }
}

// WithHash selects the digest algorithm for Sign and Verify. | WithHash 选择 Sign 与 Verify 的摘要算法。
//
// Supported values are crypto.SHA256 (default), crypto.SHA384 and crypto.SHA512. | 支持 crypto.SHA256
// （默认）、crypto.SHA384 与 crypto.SHA512。
func WithHash(hash crypto.Hash) SignOption {
	return func(o *signOptions) { o.hash = hash }
}

// WithPSS selects RSA-PSS padding; it has no effect on non-RSA keys. | WithPSS 选择 RSA-PSS 填充；对非 RSA 密钥无影响。
func WithPSS() SignOption {
	return func(o *signOptions) { o.pss = true }
}

// normalizeSignOptions applies defaults and validates the options. | normalizeSignOptions 应用默认值并校验选项。
func normalizeSignOptions(opts []SignOption) (signOptions, error) {
	var out signOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&out)
		}
	}
	if out.hash == 0 {
		out.hash = crypto.SHA256
	}
	switch out.hash {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
	default:
		return out, errs.Detail(ErrNotSupported, "digest hash %[1]v | 摘要算法 %[1]v", out.hash)
	}
	if !out.hash.Available() {
		return out, errs.Detail(ErrNotSupported, "digest hash %[1]v is not linked | 未链接摘要算法 %[1]v", out.hash)
	}
	return out, nil
}

// digestBytes hashes data with hash. | digestBytes 用 hash 计算 data 的摘要。
func digestBytes(hash crypto.Hash, data []byte) []byte {
	hasher := hash.New()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

// GenerateRandom returns n cryptographically secure random bytes. | GenerateRandom 返回 n 字节密码学安全随机数。
//
// n must be between 1 and 1 MiB. The operation is audited. | n 必须介于 1 与 1 MiB 之间。该操作会写入审计。
func (s *Service) GenerateRandom(ctx context.Context, n int) ([]byte, error) {
	const maxRandom = 1 << 20
	if n <= 0 || n > maxRandom {
		err := errs.Detail(ErrInvalidRequest, "random length %[1]d outside 1..%[2]d | 随机长度 %[1]d 超出 1..%[2]d", n, maxRandom)
		s.fail(ctx, OperationRandom, "", 0, err)
		return nil, err
	}
	out, err := randomBytes(n)
	if err != nil {
		s.fail(ctx, OperationRandom, "", 0, err)
		return nil, err
	}
	s.succeed(ctx, OperationRandom, "", 0, map[string]string{"bytes": strconvUint32(uint32(n))})
	return out, nil
}

// generateMaterial creates a fresh key pair or symmetric key for keyType and bits. | generateMaterial
// 为 keyType 与 bits 生成新的密钥对或对称密钥。
//
// It returns the private (or symmetric) material, the public material (empty for symmetric keys),
// the algorithm label, the normalized bit size and an error. | 它返回私钥（或对称）材料、公钥材料
// （对称密钥为空）、算法标签、规范化位长与错误。
func generateMaterial(keyType KeyType, bits int) (private, public []byte, algorithm string, normalizedBits int, err error) {
	switch keyType {
	case KeyTypeAES:
		if bits == 0 {
			bits = 256
		}
		if bits != 128 && bits != 192 && bits != 256 {
			return nil, nil, "", 0, errs.Detail(ErrInvalidKeySize, "AES bits %[1]d (want 128, 192 or 256) | AES 位数 %[1]d（应为 128、192 或 256）", bits)
		}
		private, err = randomBytes(bits / 8)
		if err != nil {
			return nil, nil, "", 0, err
		}
		return private, nil, aesAlgorithm(bits, "GCM"), bits, nil
	case KeyTypeChaCha20:
		if bits != 0 && bits != 256 {
			return nil, nil, "", 0, errs.Detail(ErrInvalidKeySize, "ChaCha20 bits %[1]d (want 256) | ChaCha20 位数 %[1]d（应为 256）", bits)
		}
		private, err = randomBytes(32)
		if err != nil {
			return nil, nil, "", 0, err
		}
		return private, nil, "ChaCha20-Poly1305", 256, nil
	case KeyTypeSM4:
		if bits != 0 && bits != 128 {
			return nil, nil, "", 0, errs.Detail(ErrInvalidKeySize, "SM4 bits %[1]d (want 128) | SM4 位数 %[1]d（应为 128）", bits)
		}
		private, err = randomBytes(16)
		if err != nil {
			return nil, nil, "", 0, err
		}
		return private, nil, "SM4-GCM", 128, nil
	case KeyTypeRSA:
		if bits == 0 {
			bits = 2048
		}
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, nil, "", 0, errs.Detail(ErrInvalidKeySize, "RSA bits %[1]d (want 2048, 3072 or 4096) | RSA 位数 %[1]d（应为 2048、3072 或 4096）", bits)
		}
		key, genErr := rsa.GenerateKey(rand.Reader, bits)
		if genErr != nil {
			return nil, nil, "", 0, errs.Wrap(genErr, ErrRandomSource)
		}
		privDER, derErr := x509.MarshalPKCS8PrivateKey(key)
		if derErr != nil {
			return nil, nil, "", 0, errs.WrapDetail(derErr, ErrInvalidMaterial, "encode RSA private key | 编码 RSA 私钥")
		}
		pubDER, derErr := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if derErr != nil {
			zeroBytes(privDER)
			return nil, nil, "", 0, errs.WrapDetail(derErr, ErrInvalidMaterial, "encode RSA public key | 编码 RSA 公钥")
		}
		return privDER, pubDER, "RSA", bits, nil
	case KeyTypeECDSA:
		if bits == 0 {
			bits = 256
		}
		curve, curveErr := ecdsaCurve(bits)
		if curveErr != nil {
			return nil, nil, "", 0, curveErr
		}
		key, genErr := ecdsa.GenerateKey(curve, rand.Reader)
		if genErr != nil {
			return nil, nil, "", 0, errs.Wrap(genErr, ErrRandomSource)
		}
		privDER, derErr := x509.MarshalPKCS8PrivateKey(key)
		if derErr != nil {
			return nil, nil, "", 0, errs.WrapDetail(derErr, ErrInvalidMaterial, "encode ECDSA private key | 编码 ECDSA 私钥")
		}
		pubDER, derErr := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if derErr != nil {
			zeroBytes(privDER)
			return nil, nil, "", 0, errs.WrapDetail(derErr, ErrInvalidMaterial, "encode ECDSA public key | 编码 ECDSA 公钥")
		}
		return privDER, pubDER, "ECDSA-P" + strconvUint32(uint32(bits)), bits, nil
	case KeyTypeEd25519:
		if bits != 0 && bits != 256 {
			return nil, nil, "", 0, errs.Detail(ErrInvalidKeySize, "Ed25519 bits %[1]d (want 256) | Ed25519 位数 %[1]d（应为 256）", bits)
		}
		pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, nil, "", 0, errs.Wrap(genErr, ErrRandomSource)
		}
		privDER, derErr := x509.MarshalPKCS8PrivateKey(priv)
		if derErr != nil {
			return nil, nil, "", 0, errs.WrapDetail(derErr, ErrInvalidMaterial, "encode Ed25519 private key | 编码 Ed25519 私钥")
		}
		pubDER, derErr := x509.MarshalPKIXPublicKey(pub)
		if derErr != nil {
			zeroBytes(privDER)
			return nil, nil, "", 0, errs.WrapDetail(derErr, ErrInvalidMaterial, "encode Ed25519 public key | 编码 Ed25519 公钥")
		}
		return privDER, pubDER, "Ed25519", 256, nil
	case KeyTypeSM2:
		if bits != 0 && bits != 256 {
			return nil, nil, "", 0, errs.Detail(ErrInvalidKeySize, "SM2 bits %[1]d (want 256) | SM2 位数 %[1]d（应为 256）", bits)
		}
		key, genErr := guomi.GenerateKey()
		if genErr != nil {
			return nil, nil, "", 0, errs.Wrap(genErr, ErrRandomSource)
		}
		privPEM, pemErr := guomi.MarshalPrivateKeyPEM(key)
		if pemErr != nil {
			return nil, nil, "", 0, errs.WrapDetail(pemErr, ErrInvalidMaterial, "encode SM2 private key | 编码 SM2 私钥")
		}
		pubPEM, pemErr := guomi.MarshalPublicKeyPEM(key.Public())
		if pemErr != nil {
			zeroBytes(privPEM)
			return nil, nil, "", 0, errs.WrapDetail(pemErr, ErrInvalidMaterial, "encode SM2 public key | 编码 SM2 公钥")
		}
		return privPEM, pubPEM, "SM2", 256, nil
	default:
		return nil, nil, "", 0, errs.Detail(ErrInvalidKeyType, "type %[1]q | 类型 %[1]q", keyType)
	}
}

// ecdsaCurve maps a bit size to a NIST curve. | ecdsaCurve 把位长映射为 NIST 曲线。
func ecdsaCurve(bits int) (elliptic.Curve, error) {
	switch bits {
	case 256:
		return elliptic.P256(), nil
	case 384:
		return elliptic.P384(), nil
	case 521:
		return elliptic.P521(), nil
	default:
		return nil, errs.Detail(ErrInvalidKeySize, "ECDSA bits %[1]d (want 256, 384 or 521) | ECDSA 位数 %[1]d（应为 256、384 或 521）", bits)
	}
}

// aesAlgorithm labels an AES mode for bits. | aesAlgorithm 为 bits 标注 AES 模式。
func aesAlgorithm(bits int, mode string) string {
	return "AES-" + strconvUint32(uint32(bits)) + "-" + mode
}

// ValidateMaterial checks that private material matches keyType and bits and derives public material
// when it is missing. | ValidateMaterial 校验私钥材料与 keyType、bits 是否匹配，并在缺失时推导公钥材料。
//
// It is used by ImportKey and by the internal consistency checks. | 它用于 ImportKey 与内部一致性检查。
func ValidateMaterial(keyType KeyType, bits int, private, public []byte) ([]byte, []byte, int, error) {
	switch keyType {
	case KeyTypeAES, KeyTypeChaCha20, KeyTypeSM4:
		want := 0
		switch keyType {
		case KeyTypeAES:
			want = bits / 8
			if bits == 0 {
				want = 32
				bits = 256
			}
			if want != 16 && want != 24 && want != 32 {
				return nil, nil, 0, errs.Detail(ErrInvalidKeySize, "AES bits %[1]d | AES 位数 %[1]d", bits)
			}
		case KeyTypeChaCha20:
			want = 32
			bits = 256
		case KeyTypeSM4:
			want = 16
			bits = 128
		}
		if len(private) != want {
			return nil, nil, 0, errs.Detail(ErrInvalidMaterial, "type %[1]s needs %[2]d-byte material, got %[3]d | 类型 %[1]s 需要 %[2]d 字节材料，实际 %[3]d", keyType, want, len(private))
		}
		return append([]byte(nil), private...), append([]byte(nil), public...), bits, nil
	default:
		if len(private) == 0 && len(public) == 0 {
			return nil, nil, 0, errs.Detail(ErrInvalidMaterial, "empty asymmetric key material | 非对称密钥材料为空")
		}
		if len(private) > 0 {
			priv, err := parsePrivateKey(keyType, private)
			if err != nil {
				return nil, nil, 0, err
			}
			derived, err := publicFromPrivate(keyType, priv)
			if err != nil {
				return nil, nil, 0, err
			}
			if len(public) == 0 {
				public = derived
			} else if !publicMaterialMatches(keyType, public, derived) {
				return nil, nil, 0, errs.Detail(ErrInvalidMaterial, "public material does not match the private key | 公钥材料与私钥不匹配")
			}
		}
		pub, err := parsePublicKey(keyType, public)
		if err != nil {
			return nil, nil, 0, err
		}
		bits = bitsForPublic(keyType, pub)
		if bits == 0 {
			return nil, nil, 0, errs.Detail(ErrInvalidMaterial, "cannot determine key size | 无法确定密钥长度")
		}
		return append([]byte(nil), private...), append([]byte(nil), public...), bits, nil
	}
}

// parsePrivateKey parses private material for keyType. | parsePrivateKey 为 keyType 解析私钥材料。
func parsePrivateKey(keyType KeyType, material []byte) (any, error) {
	switch keyType {
	case KeyTypeSM2:
		key, err := guomi.ParsePrivateKeyPEM(material)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "parse SM2 private key | 解析 SM2 私钥")
		}
		return key, nil
	case KeyTypeRSA, KeyTypeECDSA, KeyTypeEd25519:
		key, err := x509.ParsePKCS8PrivateKey(material)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "parse PKCS#8 private key | 解析 PKCS#8 私钥")
		}
		if err := checkPrivateType(keyType, key); err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, errs.Detail(ErrInvalidKeyType, "type %[1]q has no private key encoding | 类型 %[1]q 没有私钥编码", keyType)
	}
}

// checkPrivateType verifies that key is the expected standard-library type. | checkPrivateType 校验 key 是否为预期的标准库类型。
func checkPrivateType(keyType KeyType, key any) error {
	switch keyType {
	case KeyTypeRSA:
		if _, ok := key.(*rsa.PrivateKey); ok {
			return nil
		}
	case KeyTypeECDSA:
		if _, ok := key.(*ecdsa.PrivateKey); ok {
			return nil
		}
	case KeyTypeEd25519:
		if _, ok := key.(ed25519.PrivateKey); ok {
			return nil
		}
	}
	return errs.Detail(ErrInvalidMaterial, "material does not match type %[1]s | 材料与类型 %[1]s 不匹配", keyType)
}

// parsePublicKey parses public material for keyType. | parsePublicKey 为 keyType 解析公钥材料。
func parsePublicKey(keyType KeyType, material []byte) (any, error) {
	if len(material) == 0 {
		return nil, errs.Detail(ErrInvalidMaterial, "empty public material | 公钥材料为空")
	}
	switch keyType {
	case KeyTypeSM2:
		key, err := guomi.ParsePublicKeyPEM(material)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "parse SM2 public key | 解析 SM2 公钥")
		}
		return key, nil
	case KeyTypeRSA, KeyTypeECDSA, KeyTypeEd25519:
		key, err := x509.ParsePKIXPublicKey(material)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidMaterial, "parse PKIX public key | 解析 PKIX 公钥")
		}
		switch keyType {
		case KeyTypeRSA:
			if _, ok := key.(*rsa.PublicKey); ok {
				return key, nil
			}
		case KeyTypeECDSA:
			if _, ok := key.(*ecdsa.PublicKey); ok {
				return key, nil
			}
		case KeyTypeEd25519:
			if _, ok := key.(ed25519.PublicKey); ok {
				return key, nil
			}
		}
		return nil, errs.Detail(ErrInvalidMaterial, "public material does not match type %[1]s | 公钥材料与类型 %[1]s 不匹配", keyType)
	default:
		return nil, errs.Detail(ErrInvalidKeyType, "type %[1]q has no public encoding | 类型 %[1]q 没有公钥编码", keyType)
	}
}

// publicFromPrivate derives the public material from a parsed private key. | publicFromPrivate 从解析后的私钥推导公钥材料。
func publicFromPrivate(keyType KeyType, key any) ([]byte, error) {
	switch private := key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&private.PublicKey)
	case *ecdsa.PrivateKey:
		return x509.MarshalPKIXPublicKey(&private.PublicKey)
	case ed25519.PrivateKey:
		return x509.MarshalPKIXPublicKey(private.Public())
	case *guomi.PrivateKey:
		return guomi.MarshalPublicKeyPEM(private.Public())
	default:
		return nil, errs.Detail(ErrInvalidKeyType, "type %[1]q | 类型 %[1]q", keyType)
	}
}

// publicMaterialMatches reports whether two encodings contain the same public key. | publicMaterialMatches
// 报告两个编码是否包含同一公钥。
func publicMaterialMatches(keyType KeyType, supplied, derived []byte) bool {
	suppliedKey, err := parsePublicKey(keyType, supplied)
	if err != nil {
		return false
	}
	derivedKey, err := parsePublicKey(keyType, derived)
	if err != nil {
		return false
	}
	switch left := suppliedKey.(type) {
	case *rsa.PublicKey:
		right, ok := derivedKey.(*rsa.PublicKey)
		return ok && left.N != nil && right.N != nil && left.N.Cmp(right.N) == 0 && left.E == right.E
	case *ecdsa.PublicKey:
		right, ok := derivedKey.(*ecdsa.PublicKey)
		if !ok || left == nil || right == nil || left.Curve == nil || right.Curve == nil {
			return false
		}
		return left.Equal(right)
	case ed25519.PublicKey:
		right, ok := derivedKey.(ed25519.PublicKey)
		return ok && bytes.Equal(left, right)
	case *guomi.PublicKey:
		right, ok := derivedKey.(*guomi.PublicKey)
		return ok && left.Hex() != "" && left.Hex() == right.Hex()
	}
	return false
}

// bitsForPublic reports the effective size of a parsed public key. | bitsForPublic 报告解析后公钥的有效位长。
func bitsForPublic(keyType KeyType, key any) int {
	switch public := key.(type) {
	case *rsa.PublicKey:
		if public.N != nil {
			return public.N.BitLen()
		}
	case *ecdsa.PublicKey:
		if public.Curve != nil {
			return public.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		return 256
	case *guomi.PublicKey:
		return 256
	}
	switch keyType {
	case KeyTypeRSA:
		return 2048
	case KeyTypeECDSA:
		return 256
	case KeyTypeEd25519, KeyTypeSM2:
		return 256
	default:
		return 0
	}
}

// defaultUsageMask returns the usages enabled for a key type when the caller does not specify them. | defaultUsageMask
// 返回调用方未指定用途时该密钥类型的默认用途。
func defaultUsageMask(keyType KeyType) UsageMask {
	switch keyType {
	case KeyTypeAES, KeyTypeChaCha20, KeyTypeSM4:
		return MaskEncrypt | MaskDecrypt | MaskWrapKey | MaskUnwrapKey | MaskDeriveKey | MaskGenerateDataKey
	case KeyTypeRSA, KeyTypeECDSA, KeyTypeEd25519, KeyTypeSM2:
		return MaskSign | MaskVerify
	default:
		return 0
	}
}

// filterUsages validates usages against keyType and returns the mask. | filterUsages 校验用途与
// keyType 是否匹配并返回掩码。
func filterUsages(keyType KeyType, usages []KeyUsage) (UsageMask, error) {
	if len(usages) == 0 {
		return defaultUsageMask(keyType), nil
	}
	allowed := defaultUsageMask(keyType)
	var mask UsageMask
	for _, usage := range usages {
		entry := UsageMaskOf(usage)
		if entry == 0 {
			return 0, errs.Detail(ErrInvalidRequest, "unknown usage %[1]q | 未知用途 %[1]q", usage)
		}
		if entry&allowed == 0 {
			return 0, errs.Detail(ErrUsageNotAllowed, "type %[1]s does not support usage %[2]q | 类型 %[1]s 不支持用途 %[2]q", keyType, usage)
		}
		mask |= entry
	}
	return mask, nil
}

// Sign creates a signature over data with the current version of key id. | Sign 使用 id 的当前版本
// 对 data 生成签名。
//
// RSA uses PKCS#1 v1.5 by default and PSS with WithPSS. ECDSA emits ASN.1 DER. Ed25519 and SM2 sign
// the message directly and reject WithDigest. The operation is audited. | RSA 默认使用 PKCS#1 v1.5，
// 配合 WithPSS 使用 PSS。ECDSA 输出 ASN.1 DER。Ed25519 与 SM2 直接对消息签名并拒绝 WithDigest。
// 该操作会写入审计。
func (s *Service) Sign(ctx context.Context, id string, data []byte, opts ...SignOption) ([]byte, error) {
	options, err := normalizeSignOptions(opts)
	if err != nil {
		s.fail(ctx, OperationSign, id, 0, err)
		return nil, err
	}
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationSign, id, 0, err)
		return nil, err
	}
	defer key.eraseMaterial()
	version := key.Version
	if err := authorizeUse(key, key.VersionAt(version), UsageSign); err != nil {
		s.fail(ctx, OperationSign, key.ID, version, err)
		return nil, err
	}
	material := materialForVersion(key, version)
	if len(material) == 0 {
		err := errs.Detail(ErrInvalidMaterial, "current version has no private material | 当前版本没有私钥材料")
		s.fail(ctx, OperationSign, key.ID, version, err)
		return nil, err
	}
	signature, err := signWithMaterial(key.Type, material, data, options)
	if err != nil {
		s.fail(ctx, OperationSign, key.ID, version, err)
		return nil, err
	}
	s.succeed(ctx, OperationSign, key.ID, version, map[string]string{"type": string(key.Type), "algorithm": key.Algorithm})
	return signature, nil
}

// signWithMaterial signs data with raw material. | signWithMaterial 用原始材料对 data 签名。
func signWithMaterial(keyType KeyType, material, data []byte, options signOptions) ([]byte, error) {
	copyMaterial := append([]byte(nil), material...)
	defer zeroBytes(copyMaterial)
	if keyType == KeyTypeSM2 {
		if options.digest {
			return nil, errs.Detail(ErrNotSupported, "SM2 signs messages, not precomputed digests | SM2 对消息签名，不支持预计算摘要")
		}
		key, err := parsePrivateKey(keyType, copyMaterial)
		if err != nil {
			return nil, err
		}
		return guomi.Sign(key.(*guomi.PrivateKey), data)
	}
	if keyType == KeyTypeEd25519 {
		if options.digest {
			return nil, errs.Detail(ErrNotSupported, "Ed25519 signs messages, not precomputed digests | Ed25519 对消息签名，不支持预计算摘要")
		}
		key, err := parsePrivateKey(keyType, copyMaterial)
		if err != nil {
			return nil, err
		}
		return ed25519.Sign(key.(ed25519.PrivateKey), data), nil
	}
	digest := data
	if !options.digest {
		digest = digestBytes(options.hash, data)
	}
	key, err := parsePrivateKey(keyType, copyMaterial)
	if err != nil {
		return nil, err
	}
	switch private := key.(type) {
	case *rsa.PrivateKey:
		if options.pss {
			signature, err := rsa.SignPSS(rand.Reader, private, options.hash, digest, nil)
			if err != nil {
				return nil, errs.WrapDetail(err, ErrAuthentication, "RSA-PSS signing failed | RSA-PSS 签名失败")
			}
			return signature, nil
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, private, options.hash, digest)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrAuthentication, "RSA PKCS#1 v1.5 signing failed | RSA PKCS#1 v1.5 签名失败")
		}
		return signature, nil
	case *ecdsa.PrivateKey:
		signature, err := ecdsa.SignASN1(rand.Reader, private, digest)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrAuthentication, "ECDSA signing failed | ECDSA 签名失败")
		}
		return signature, nil
	default:
		return nil, errs.Detail(ErrInvalidKeyType, "type %[1]q cannot sign | 类型 %[1]q 无法签名", keyType)
	}
}

// Verify checks a signature over data with any retained version of key id. | Verify 使用 id 的任意
// 保留版本校验 data 上的签名。
//
// Verification is attempted from the newest version to the oldest, so signatures created before a
// rotation remain valid. A structurally invalid or non-matching signature returns (false, nil); a
// missing key or unsupported key type returns an error. The operation is audited. | 校验按从最新到
// 最旧的版本尝试，因此轮换前创建的签名仍然有效。结构非法或不匹配的签名返回 (false, nil)；密钥
// 缺失或类型不支持返回错误。该操作会写入审计。
func (s *Service) Verify(ctx context.Context, id string, data, signature []byte, opts ...SignOption) (bool, error) {
	options, err := normalizeSignOptions(opts)
	if err != nil {
		s.fail(ctx, OperationVerify, id, 0, err)
		return false, err
	}
	key, err := s.loadResolvedKey(ctx, id)
	if err != nil {
		s.fail(ctx, OperationVerify, id, 0, err)
		return false, err
	}
	defer key.eraseMaterial()
	if err := authorizeUse(key, nil, UsageVerify); err != nil {
		s.fail(ctx, OperationVerify, key.ID, key.Version, err)
		return false, err
	}
	versions := append([]*KeyVersion(nil), key.Versions...)
	sort.Slice(versions, func(i, j int) bool { return versions[i].Version > versions[j].Version })
	attempted := false
	for _, version := range versions {
		if version == nil || version.usableFor(UsageVerify) != nil {
			continue
		}
		public := version.PublicMaterial
		if len(public) == 0 && version.Version == key.Version {
			public = key.PublicMaterial
		}
		if len(public) == 0 {
			continue
		}
		attempted = true
		ok, err := verifyWithMaterial(key.Type, public, data, signature, options)
		if err != nil {
			s.fail(ctx, OperationVerify, key.ID, version.Version, err)
			return false, err
		}
		if ok {
			s.succeed(ctx, OperationVerify, key.ID, version.Version, map[string]string{"type": string(key.Type), "algorithm": key.Algorithm, "valid": "true"})
			return true, nil
		}
	}
	if !attempted {
		err := errs.Detail(ErrInvalidMaterial, "no verifiable public material | 没有可验签的公钥材料")
		s.fail(ctx, OperationVerify, key.ID, key.Version, err)
		return false, err
	}
	s.succeed(ctx, OperationVerify, key.ID, key.Version, map[string]string{"type": string(key.Type), "algorithm": key.Algorithm, "valid": "false"})
	return false, nil
}

// verifyWithMaterial verifies signature with raw public material. | verifyWithMaterial 用原始公钥材料校验签名。
func verifyWithMaterial(keyType KeyType, material, data, signature []byte, options signOptions) (bool, error) {
	if keyType == KeyTypeSM2 {
		key, err := parsePublicKey(keyType, material)
		if err != nil {
			return false, err
		}
		return guomi.Verify(key.(*guomi.PublicKey), data, signature)
	}
	if keyType == KeyTypeEd25519 {
		key, err := parsePublicKey(keyType, material)
		if err != nil {
			return false, err
		}
		if options.digest {
			return false, errs.Detail(ErrNotSupported, "Ed25519 verifies messages, not precomputed digests | Ed25519 对消息验签，不支持预计算摘要")
		}
		return ed25519.Verify(key.(ed25519.PublicKey), data, signature), nil
	}
	digest := data
	if !options.digest {
		digest = digestBytes(options.hash, data)
	}
	key, err := parsePublicKey(keyType, material)
	if err != nil {
		return false, err
	}
	switch public := key.(type) {
	case *rsa.PublicKey:
		var verifyErr error
		if options.pss {
			verifyErr = rsa.VerifyPSS(public, options.hash, digest, signature, nil)
		} else {
			verifyErr = rsa.VerifyPKCS1v15(public, options.hash, digest, signature)
		}
		if verifyErr != nil {
			return false, nil
		}
		return true, nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(public, digest, signature), nil
	default:
		return false, errs.Detail(ErrInvalidKeyType, "type %[1]q cannot verify | 类型 %[1]q 无法验签", keyType)
	}
}

// authorizeUse checks the key state and an optional version state for usage. | authorizeUse 检查密钥
// 状态与可选的版本状态是否允许 usage。
func authorizeUse(key *Key, version *KeyVersion, usage KeyUsage) error {
	if err := key.usableFor(usage); err != nil {
		return err
	}
	if version != nil {
		if err := version.usableFor(usage); err != nil {
			return err
		}
	}
	return nil
}

// loadResolvedKey resolves an identifier or alias and unwraps its material. | loadResolvedKey 解析标识
// 或别名并解包其材料。
func (s *Service) loadResolvedKey(ctx context.Context, aliasOrID string) (*Key, error) {
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	key, err := resolveStoredKey(ctx, s.store, aliasOrID)
	if err != nil {
		return nil, err
	}
	return s.loadKey(ctx, key)
}
