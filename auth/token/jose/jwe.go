package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"strings"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// The JWE key-management algorithm names defined by RFC 7518. | RFC 7518 定义的 JWE 密钥管理
// 算法名。
const (
	// AlgRSAOAEP is RSAES-OAEP with SHA-1 and MGF1-SHA-1. | AlgRSAOAEP 是使用 SHA-1 与 MGF1-SHA-1 的 RSAES-OAEP。
	AlgRSAOAEP = "RSA-OAEP"
	// AlgRSAOAEP256 is RSAES-OAEP with SHA-256 and MGF1-SHA-256. | AlgRSAOAEP256 是使用 SHA-256 与 MGF1-SHA-256 的 RSAES-OAEP。
	AlgRSAOAEP256 = "RSA-OAEP-256"
	// AlgRSA15 is RSAES-PKCS1-v1_5; it is refused unless the caller opts in. | AlgRSA15 是 RSAES-PKCS1-v1_5；除非调用方显式开启，否则拒绝。
	AlgRSA15 = "RSA1_5"
	// AlgA128KW, AlgA192KW and AlgA256KW are AES Key Wrap with the named key size. | AlgA128KW、AlgA192KW 与 AlgA256KW 是使用指定密钥长度的 AES 密钥包装。
	AlgA128KW = "A128KW"
	AlgA192KW = "A192KW"
	AlgA256KW = "A256KW"
	// AlgDir is direct use of the shared symmetric key as the CEK. | AlgDir 直接把共享对称密钥用作 CEK。
	AlgDir = "dir"
	// AlgECDHES is ECDH-ES direct key agreement. | AlgECDHES 是 ECDH-ES 直接密钥协商。
	AlgECDHES = "ECDH-ES"
	// AlgECDHESA128KW, AlgECDHESA192KW and AlgECDHESA256KW are ECDH-ES with AES key wrapping. | AlgECDHESA128KW、AlgECDHESA192KW 与 AlgECDHESA256KW 是带 AES 密钥包装的 ECDH-ES。
	AlgECDHESA128KW = "ECDH-ES+A128KW"
	AlgECDHESA192KW = "ECDH-ES+A192KW"
	AlgECDHESA256KW = "ECDH-ES+A256KW"
)

// The JWE content-encryption algorithm names defined by RFC 7518. | RFC 7518 定义的 JWE 内容
// 加密算法名。
const (
	// EncA128CBCHS256 is AES-128-CBC with HMAC-SHA-256. | EncA128CBCHS256 是 AES-128-CBC 与 HMAC-SHA-256。
	EncA128CBCHS256 = "A128CBC-HS256"
	// EncA192CBCHS384 is AES-192-CBC with HMAC-SHA-384. | EncA192CBCHS384 是 AES-192-CBC 与 HMAC-SHA-384。
	EncA192CBCHS384 = "A192CBC-HS384"
	// EncA256CBCHS512 is AES-256-CBC with HMAC-SHA-512. | EncA256CBCHS512 是 AES-256-CBC 与 HMAC-SHA-512。
	EncA256CBCHS512 = "A256CBC-HS512"
	// EncA128GCM is AES-128-GCM. | EncA128GCM 是 AES-128-GCM。
	EncA128GCM = "A128GCM"
	// EncA192GCM is AES-192-GCM. | EncA192GCM 是 AES-192-GCM。
	EncA192GCM = "A192GCM"
	// EncA256GCM is AES-256-GCM. | EncA256GCM 是 AES-256-GCM。
	EncA256GCM = "A256GCM"
)

// ZipDEF is the only compression algorithm defined for JWE. | ZipDEF 是 JWE 定义的唯一压缩算法。
const ZipDEF = "DEF"

// jweHeader is the protected header of a compact JWE. | jweHeader 是紧凑 JWE 的受保护头部。
type jweHeader struct {
	Alg string `json:"alg"`
	Enc string `json:"enc"`
	Zip string `json:"zip,omitempty"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
	Cty string `json:"cty,omitempty"`
	EPK *Key   `json:"epk,omitempty"`
	APU string `json:"apu,omitempty"`
	APV string `json:"apv,omitempty"`
}

// EncryptOptions configures Encrypt. | EncryptOptions 配置 Encrypt。
type EncryptOptions struct {
	// Alg selects the key-management algorithm; when empty key.Alg is used. | Alg 选择密钥管理算法；为空时使用 key.Alg。
	Alg string
	// Enc selects the content-encryption algorithm and is required. | Enc 选择内容加密算法且为必需。
	Enc string
	// Zip is "" or "DEF". | Zip 取值为 "" 或 "DEF"。
	Zip string
	// Kid overrides the key identifier; when empty key.Kid is used. | Kid 覆盖密钥标识；为空时使用 key.Kid。
	Kid string
	// Typ sets the "typ" protected header parameter. | Typ 设置 "typ" 受保护头部参数。
	Typ string
	// Cty sets the "cty" protected header parameter. | Cty 设置 "cty" 受保护头部参数。
	Cty string
	// APU is the agreement PartyUInfo value; it is base64url encoded in the header. | APU 是协商 PartyUInfo 值；在头部中以 base64url 编码。
	APU []byte
	// APV is the agreement PartyVInfo value; it is base64url encoded in the header. | APV 是协商 PartyVInfo 值；在头部中以 base64url 编码。
	APV []byte
	// AllowRSA1_5 explicitly enables the deprecated RSA1_5 algorithm. It exists only for legacy
	// interoperability; prefer RSA-OAEP or RSA-OAEP-256. | AllowRSA1_5 显式启用已弃用的 RSA1_5
	// 算法。它仅用于兼容旧系统；应优先使用 RSA-OAEP 或 RSA-OAEP-256。
	AllowRSA1_5 bool
}

// DecryptOptions configures Decrypt. | DecryptOptions 配置 Decrypt。
type DecryptOptions struct {
	// AllowRSA1_5 explicitly accepts the deprecated RSA1_5 algorithm. | AllowRSA1_5 显式接受已弃用的 RSA1_5 算法。
	AllowRSA1_5 bool
	// MaxDecompressedSize caps DEF output; zero uses DefaultJWEMaxDecompressedSize. | MaxDecompressedSize 限制 DEF 输出；零值使用 DefaultJWEMaxDecompressedSize。
	MaxDecompressedSize int64
}

// Encrypt builds a compact JWE over plaintext with key. | Encrypt 使用 key 对 plaintext 生成紧凑 JWE。
//
// The protected header is the only header; there is no unprotected or per-recipient header to
// disagree with it. The header always carries alg and enc, while kid, typ, cty, zip, apu, apv
// and epk are added when applicable. RSA1_5 is refused unless opts.AllowRSA1_5 is set. | 受保护
// 头部是唯一头部，不存在可能与它矛盾的非保护头部或每接收方头部。头部始终包含 alg 与 enc，
// kid、typ、cty、zip、apu、apv 与 epk 在适用时加入。除非设置 opts.AllowRSA1_5，否则拒绝 RSA1_5。
func Encrypt(plaintext []byte, key *Key, opts EncryptOptions) (string, error) {
	if key == nil {
		return "", ErrInvalidKey
	}
	alg := opts.Alg
	if alg == "" {
		alg = key.Alg
	}
	if alg == "" {
		return "", errs.Detail(ErrAlgNotAllowed, "no alg specified | 未指定 alg")
	}
	if !supportedJWEAlg(alg) {
		return "", errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	enc := opts.Enc
	if !supportedEnc(enc) {
		return "", errs.Detail(ErrUnsupportedEnc, "enc=%[1]q | enc=%[1]q", enc)
	}
	zip := opts.Zip
	if zip != "" && zip != ZipDEF {
		return "", errs.Detail(ErrInvalidConfig, "zip=%[1]q | zip=%[1]q", zip)
	}
	if key.Alg != "" && key.Alg != alg {
		return "", errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, alg)
	}
	if err := checkKeyAlg(key, alg); err != nil {
		return "", err
	}
	if alg == AlgRSA15 && !opts.AllowRSA1_5 {
		return "", errs.Detail(ErrAlgNotAllowed, "RSA1_5 requires explicit opt-in | RSA1_5 需要显式开启")
	}
	kid := opts.Kid
	if kid == "" {
		kid = key.Kid
	}
	h := &jweHeader{Alg: alg, Enc: enc, Zip: zip, Kid: kid, Typ: opts.Typ, Cty: opts.Cty}
	if len(opts.APU) > 0 {
		h.APU = base64.RawURLEncoding.EncodeToString(opts.APU)
	}
	if len(opts.APV) > 0 {
		h.APV = base64.RawURLEncoding.EncodeToString(opts.APV)
	}
	cek, encryptedKey, err := encryptCEK(alg, key, enc, h, opts)
	if err != nil {
		return "", err
	}
	headerBytes, err := json.Marshal(h)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidHeader, "encode JWE header | 编码 JWE 头部")
	}
	protected := EncodeSegment(headerBytes)
	aad := []byte(protected)
	data := plaintext
	if zip == ZipDEF {
		data, err = deflate(plaintext)
		if err != nil {
			return "", err
		}
	}
	iv, ciphertext, tag, err := sealContent(enc, cek, aad, data)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, len(protected)+len(encryptedKey)+len(iv)+len(ciphertext)+len(tag)+4)
	out = append(out, protected...)
	out = append(out, '.')
	out = appendSegment(out, encryptedKey)
	out = append(out, '.')
	out = appendSegment(out, iv)
	out = append(out, '.')
	out = appendSegment(out, ciphertext)
	out = append(out, '.')
	out = appendSegment(out, tag)
	return string(out), nil
}

// Decrypt decrypts a compact JWE with key. | Decrypt 使用 key 解密紧凑 JWE。
//
// Decryption authenticates before releasing plaintext; CBC tags are compared in constant time
// before any padding is examined, and GCM authentication happens inside the AEAD. Duplicate
// header members, critical extensions, unknown alg/enc/zip values, ambiguous empty or non-empty
// encrypted-key segments and RSA1_5 without opt-in are all refused. RSA1_5 is deprecated by RFC 7518
// because RSA PKCS#1 v1.5 decryption is vulnerable to Bleichenbacher-style oracles; it is accepted
// only through DecryptOptions.AllowRSA1_5, and every RSA key-transport failure is reported with the
// same error and message so that padding and CEK-length failures cannot be distinguished. Callers
// that do not need legacy interoperability should leave it disabled. | 解密在释放明文前完成认证；
// CBC 标签在任何填充检查之前以常量时间比较，GCM 认证在 AEAD 内部完成。重复头部成员、关键扩展、
// 未知 alg/enc/zip、与算法矛盾的加密密钥段（应空不空或应非空却空）以及未显式开启的 RSA1_5
// 都会被拒绝。RFC 7518 因 RSA PKCS#1 v1.5 解密易受 Bleichenbacher 类预言机攻击而弃用 RSA1_5；
// 本实现仅在 DecryptOptions.AllowRSA1_5 显式开启时接受，并让所有 RSA 密钥传输失败返回相同的错误
// 与文案，使填充失败与 CEK 长度失败不可区分。无需兼容旧系统的调用方应保持关闭。
func Decrypt(token string, key *Key, opts DecryptOptions) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, errs.Detail(ErrMalformed, "JWE must have five segments | JWE 必须包含五段")
	}
	if parts[0] == "" {
		return nil, errs.Detail(ErrMalformed, "empty protected header | 受保护头部为空")
	}
	headerBytes, err := DecodeSegment(parts[0])
	if err != nil {
		return nil, err
	}
	h, err := parseJWEHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	if !supportedJWEAlg(h.Alg) {
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", h.Alg)
	}
	if !supportedEnc(h.Enc) {
		return nil, errs.Detail(ErrUnsupportedEnc, "enc=%[1]q | enc=%[1]q", h.Enc)
	}
	if h.Zip != "" && h.Zip != ZipDEF {
		return nil, errs.Detail(ErrInvalidHeader, "zip=%[1]q | zip=%[1]q", h.Zip)
	}
	if h.Alg == AlgRSA15 && !opts.AllowRSA1_5 {
		return nil, errs.Detail(ErrAlgNotAllowed, "RSA1_5 requires explicit opt-in | RSA1_5 需要显式开启")
	}
	if key.Alg != "" && key.Alg != h.Alg {
		return nil, errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, h.Alg)
	}
	if err := checkKeyAlg(key, h.Alg); err != nil {
		return nil, err
	}
	encryptedKey, err := DecodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	iv, err := DecodeSegment(parts[2])
	if err != nil {
		return nil, err
	}
	ciphertext, err := DecodeSegment(parts[3])
	if err != nil {
		return nil, err
	}
	tag, err := DecodeSegment(parts[4])
	if err != nil {
		return nil, err
	}
	cek, err := decryptCEK(h, key, encryptedKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := openContent(h.Enc, cek, []byte(parts[0]), iv, ciphertext, tag)
	if err != nil {
		return nil, err
	}
	if h.Zip == ZipDEF {
		plaintext, err = inflate(plaintext, opts.MaxDecompressedSize)
		if err != nil {
			return nil, err
		}
	}
	return plaintext, nil
}

// supportedJWEAlg reports whether alg is a supported key-management algorithm. | supportedJWEAlg
// 报告 alg 是否为受支持的密钥管理算法。
func supportedJWEAlg(alg string) bool {
	switch alg {
	case AlgRSAOAEP, AlgRSAOAEP256, AlgRSA15,
		AlgA128KW, AlgA192KW, AlgA256KW,
		AlgDir, AlgECDHES, AlgECDHESA128KW, AlgECDHESA192KW, AlgECDHESA256KW:
		return true
	}
	return false
}

// parseJWEHeader decodes a protected JWE header and refuses critical extensions. | parseJWEHeader
// 解码受保护的 JWE 头部并拒绝关键扩展。
func parseJWEHeader(raw []byte) (jweHeader, error) {
	m, err := headerJSON(raw)
	if err != nil {
		return jweHeader{}, err
	}
	if v, present := m["crit"]; present {
		crit, ok := stringSlice(v)
		if !ok || len(crit) > 0 {
			return jweHeader{}, errs.Detail(ErrUnsupportedCrit, "crit is not supported | 不支持 crit")
		}
	}
	var h jweHeader
	if err := unmarshal(raw, &h); err != nil {
		return jweHeader{}, errs.WrapDetail(err, ErrInvalidHeader, "decode JWE header | 解码 JWE 头部")
	}
	if h.Alg == "" || h.Enc == "" {
		return jweHeader{}, errs.Detail(ErrInvalidHeader, "header must carry alg and enc | 头部必须包含 alg 与 enc")
	}
	if h.EPK != nil {
		if !strings.HasPrefix(h.Alg, AlgECDHES) {
			return jweHeader{}, errs.Detail(ErrInvalidHeader, "epk without ECDH-ES | 非 ECDH-ES 却包含 epk")
		}
		if h.EPK.D != "" || h.EPK.K != "" {
			return jweHeader{}, errs.Detail(ErrInvalidHeader, "epk must contain public material only | epk 只能包含公开材料")
		}
	}
	return h, nil
}

// encryptCEK performs key management and returns the CEK plus the encrypted key segment. | encryptCEK
// 执行密钥管理并返回 CEK 与加密密钥段。
func encryptCEK(alg string, key *Key, enc string, h *jweHeader, opts EncryptOptions) (cek, encryptedKey []byte, err error) {
	p, _ := encParamsFor(enc)
	switch alg {
	case AlgRSAOAEP, AlgRSAOAEP256, AlgRSA15:
		cek, err = randomBytes(p.cekLen)
		if err != nil {
			return nil, nil, err
		}
		raw, err := key.PublicKey()
		if err != nil {
			return nil, nil, err
		}
		pub, ok := raw.(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 {
			return nil, nil, errs.Detail(ErrWeakKey, "RSA key transport needs a 2048-bit key | RSA 密钥传输需要 2048 位密钥")
		}
		switch alg {
		case AlgRSAOAEP:
			encryptedKey, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, cek, nil)
		case AlgRSAOAEP256:
			encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
		default:
			encryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, pub, cek)
		}
		if err != nil {
			return nil, nil, errs.WrapDetail(err, ErrInvalidKey, "RSA key encryption | RSA 密钥加密")
		}
	case AlgA128KW, AlgA192KW, AlgA256KW:
		kek, err := key.octets()
		if err != nil {
			return nil, nil, err
		}
		cek, err = randomBytes(p.cekLen)
		if err != nil {
			return nil, nil, err
		}
		encryptedKey, err = aesKeyWrap(kek, cek)
		if err != nil {
			return nil, nil, err
		}
	case AlgDir:
		cek, err = key.octets()
		if err != nil {
			return nil, nil, err
		}
		if len(cek) != p.cekLen {
			return nil, nil, errs.Detail(ErrWeakKey, "dir with enc=%[1]s needs a %[2]d-byte key | dir 配 enc=%[1]s 需要 %[2]d 字节密钥", enc, p.cekLen)
		}
	case AlgECDHES:
		var shared []byte
		shared, h.EPK, err = ecdhSharedForEncrypt(key)
		if err != nil {
			return nil, nil, err
		}
		cek, err = concatKDF(shared, []byte(enc), opts.APU, opts.APV, p.cekLen)
		if err != nil {
			return nil, nil, err
		}
	case AlgECDHESA128KW, AlgECDHESA192KW, AlgECDHESA256KW:
		var shared []byte
		shared, h.EPK, err = ecdhSharedForEncrypt(key)
		if err != nil {
			return nil, nil, err
		}
		kekLen := map[string]int{AlgECDHESA128KW: 16, AlgECDHESA192KW: 24, AlgECDHESA256KW: 32}[alg]
		kek, err := concatKDF(shared, []byte(alg), opts.APU, opts.APV, kekLen)
		if err != nil {
			return nil, nil, err
		}
		cek, err = randomBytes(p.cekLen)
		if err != nil {
			return nil, nil, err
		}
		encryptedKey, err = aesKeyWrap(kek, cek)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	return cek, encryptedKey, nil
}

// decryptCEK performs key management and returns the CEK. | decryptCEK 执行密钥管理并返回 CEK。
func decryptCEK(h jweHeader, key *Key, encryptedKey []byte) ([]byte, error) {
	p, _ := encParamsFor(h.Enc)
	apu, err := decodeOptionalB64(h.APU)
	if err != nil {
		return nil, err
	}
	apv, err := decodeOptionalB64(h.APV)
	if err != nil {
		return nil, err
	}
	switch h.Alg {
	case AlgRSAOAEP, AlgRSAOAEP256, AlgRSA15:
		if len(encryptedKey) == 0 {
			return nil, errs.Detail(ErrDecryptionFailed, "missing encrypted key | 缺少加密密钥")
		}
		raw, err := key.PrivateKey()
		if err != nil {
			return nil, err
		}
		priv, ok := raw.(*rsa.PrivateKey)
		if !ok || priv.N.BitLen() < 2048 {
			return nil, errs.Detail(ErrWeakKey, "RSA key transport needs a 2048-bit key | RSA 密钥传输需要 2048 位密钥")
		}
		var cek []byte
		switch h.Alg {
		case AlgRSAOAEP:
			cek, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, encryptedKey, nil)
		case AlgRSAOAEP256:
			cek, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
		default:
			cek, err = rsa.DecryptPKCS1v15(rand.Reader, priv, encryptedKey)
		}
		// All RSA key-transport failures collapse into one error and one message. RSA1_5 is a
		// Bleichenbacher oracle if a caller can distinguish a padding failure from a CEK length
		// failure, so the detail must not vary across those cases. | 所有 RSA 密钥传输失败都归并为
		// 同一错误与同一文案。若调用方能区分填充失败与 CEK 长度失败，RSA1_5 就会成为
		// Bleichenbacher 预言机，因此这些情况的细节必须一致。
		if err != nil || len(cek) != p.cekLen {
			return nil, errs.Detail(ErrDecryptionFailed, "RSA key decryption failed | RSA 密钥解密失败")
		}
		return cek, nil
	case AlgA128KW, AlgA192KW, AlgA256KW:
		if len(encryptedKey) == 0 {
			return nil, errs.Detail(ErrDecryptionFailed, "missing encrypted key | 缺少加密密钥")
		}
		kek, err := key.octets()
		if err != nil {
			return nil, err
		}
		cek, err := aesKeyUnwrap(kek, encryptedKey)
		if err != nil {
			return nil, err
		}
		if len(cek) != p.cekLen {
			return nil, errs.Detail(ErrDecryptionFailed, "CEK length mismatch | CEK 长度不匹配")
		}
		return cek, nil
	case AlgDir:
		if len(encryptedKey) != 0 {
			return nil, errs.Detail(ErrDecryptionFailed, "dir must have an empty encrypted key | dir 的加密密钥段必须为空")
		}
		cek, err := key.octets()
		if err != nil {
			return nil, err
		}
		if len(cek) != p.cekLen {
			return nil, errs.Detail(ErrWeakKey, "dir with enc=%[1]s needs a %[2]d-byte key | dir 配 enc=%[1]s 需要 %[2]d 字节密钥", h.Enc, p.cekLen)
		}
		return cek, nil
	case AlgECDHES:
		if len(encryptedKey) != 0 {
			return nil, errs.Detail(ErrDecryptionFailed, "ECDH-ES must have an empty encrypted key | ECDH-ES 的加密密钥段必须为空")
		}
		shared, err := ecdhSharedForDecrypt(key, h.EPK)
		if err != nil {
			return nil, err
		}
		cek, err := concatKDF(shared, []byte(h.Enc), apu, apv, p.cekLen)
		if err != nil {
			return nil, err
		}
		return cek, nil
	case AlgECDHESA128KW, AlgECDHESA192KW, AlgECDHESA256KW:
		if len(encryptedKey) == 0 {
			return nil, errs.Detail(ErrDecryptionFailed, "missing encrypted key | 缺少加密密钥")
		}
		shared, err := ecdhSharedForDecrypt(key, h.EPK)
		if err != nil {
			return nil, err
		}
		kekLen := map[string]int{AlgECDHESA128KW: 16, AlgECDHESA192KW: 24, AlgECDHESA256KW: 32}[h.Alg]
		kek, err := concatKDF(shared, []byte(h.Alg), apu, apv, kekLen)
		if err != nil {
			return nil, err
		}
		cek, err := aesKeyUnwrap(kek, encryptedKey)
		if err != nil {
			return nil, err
		}
		if len(cek) != p.cekLen {
			return nil, errs.Detail(ErrDecryptionFailed, "CEK length mismatch | CEK 长度不匹配")
		}
		return cek, nil
	default:
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", h.Alg)
	}
}

// decodeOptionalB64 decodes an optional base64url header value. | decodeOptionalB64 解码可选的
// base64url 头部取值。
func decodeOptionalB64(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	out, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidHeader, "apu/apv | apu/apv")
	}
	return out, nil
}
