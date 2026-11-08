package jose

import (
	"context"
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
	// Alg is the key-management algorithm. | Alg 是密钥管理算法。
	Alg string `json:"alg"`
	// Enc is the content-encryption algorithm. | Enc 是内容加密算法。
	Enc string `json:"enc"`
	// Zip is the compression algorithm, empty or "DEF". | Zip 是压缩算法，取值为空或 "DEF"。
	Zip string `json:"zip,omitempty"`
	// Kid identifies the key used for key management. | Kid 标识密钥管理使用的密钥。
	Kid string `json:"kid,omitempty"`
	// Typ is the media type of the complete JWE. | Typ 是完整 JWE 的媒体类型。
	Typ string `json:"typ,omitempty"`
	// Cty is the media type of the encrypted plaintext. | Cty 是加密明文的媒体类型。
	Cty string `json:"cty,omitempty"`
	// EPK is the ephemeral public key used by ECDH-ES. | EPK 是 ECDH-ES 使用的临时公钥。
	EPK *Key `json:"epk,omitempty"`
	// APU is the base64url-encoded agreement PartyUInfo value. | APU 是 base64url 编码的协商 PartyUInfo 值。
	APU string `json:"apu,omitempty"`
	// APV is the base64url-encoded agreement PartyVInfo value. | APV 是 base64url 编码的协商 PartyVInfo 值。
	APV string `json:"apv,omitempty"`
}

// Recipient is one recipient of a JWE JSON serialization. | Recipient 是 JWE JSON 序列化的一个
// 接收方。
type Recipient struct {
	// Key is the recipient key and is required. | Key 是接收方密钥且为必需。
	Key *Key
	// Alg selects the key-management algorithm; when empty Key.Alg is used, then EncryptOptions.Alg. |
	// Alg 选择密钥管理算法；为空时使用 Key.Alg，再退到 EncryptOptions.Alg。
	Alg string
	// Kid overrides the key identifier; when empty Key.Kid is used. | Kid 覆盖密钥标识；为空时使用
	// Key.Kid。
	Kid string
	// Header holds extra per-recipient unprotected header parameters. The managed names alg, enc,
	// zip, epk, apu, apv, crit and kid are refused. | Header 保存额外的每接收方非保护头部参数。
	// 受管理名 alg、enc、zip、epk、apu、apv、crit 与 kid 会被拒绝。
	Header map[string]any
}

// EncryptOptions configures Encrypt. | EncryptOptions 配置 Encrypt。
type EncryptOptions struct {
	// Alg selects the key-management algorithm; when empty key.Alg is used. With Recipients it is the
	// fallback for recipients whose Alg and Key.Alg are both empty. | Alg 选择密钥管理算法；为空时
	// 使用 key.Alg。设置 Recipients 时，它作为 Alg 与 Key.Alg 都为空的接收方的回退值。
	Alg string
	// Enc selects the content-encryption algorithm and is required. | Enc 选择内容加密算法且为必需。
	Enc string
	// Zip is "" or "DEF". | Zip 取值为 "" 或 "DEF"。
	Zip string
	// Kid overrides the key identifier; when empty key.Kid is used. It must be empty with Recipients,
	// which carry their own Kid. | Kid 覆盖密钥标识；为空时使用 key.Kid。设置 Recipients 时必须为
	// 空，因为接收方各自携带 Kid。
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
	// Serialization selects the output form: compact (the default), flattened JSON or general JSON.
	// JSON-only options — Recipients, Unprotected and AAD — require an explicit JSON serialization
	// and are refused with the compact form. | Serialization 选择输出形式：紧凑（默认）、扁平 JSON
	// 或通用 JSON。仅限 JSON 的选项 —— Recipients、Unprotected 与 AAD —— 要求显式 JSON 序列化，
	// 与紧凑形式一起使用会被拒绝。
	Serialization Serialization
	// Recipients supplies one or more recipient keys for a JWE JSON serialization. When non-empty,
	// key must be nil, Serialization must be Flattened or General, and flattened accepts exactly one
	// recipient. dir and ECDH-ES direct agreement accept only a single recipient because they derive
	// the CEK instead of wrapping a shared one. | Recipients 为 JWE JSON 序列化提供一个或多个接收方
	// 密钥。非空时 key 必须为 nil，Serialization 必须为 Flattened 或 General，且扁平形式只接受一个
	// 接收方。dir 与 ECDH-ES 直接协商只接受单个接收方，因为它们派生 CEK 而不是包装共享 CEK。
	Recipients []Recipient
	// Unprotected holds shared unprotected header parameters for a JSON serialization. A name that
	// is also protected is refused, as is crit, so the header can never be ambiguous. | Unprotected
	// 保存 JSON 序列化共享的非保护头部参数。与受保护头部重名的参数以及 crit 都会被拒绝，因此头部
	// 不可能产生歧义。
	Unprotected map[string]any
	// AAD supplies additional authenticated data for a JSON serialization. A nil value omits the
	// "aad" member; a non-nil value, including an empty slice, emits it and binds it to the content
	// authentication tag. The compact serialization has no place for it and refuses it. | AAD 为 JSON
	// 序列化提供附加认证数据。nil 值省略 "aad" 成员；非 nil 值（包括空切片）会写出该成员并绑定到
	// 内容认证标签。紧凑序列化没有承载位置，因此会拒绝它。
	AAD []byte
}

// DecryptOptions configures Decrypt. | DecryptOptions 配置 Decrypt。
type DecryptOptions struct {
	// AllowRSA1_5 explicitly accepts the deprecated RSA1_5 algorithm. | AllowRSA1_5 显式接受已弃用的 RSA1_5 算法。
	AllowRSA1_5 bool
	// MaxDecompressedSize caps DEF output; zero uses DefaultJWEMaxDecompressedSize. | MaxDecompressedSize 限制 DEF 输出；零值使用 DefaultJWEMaxDecompressedSize。
	MaxDecompressedSize int64
	// MaxTokenSize caps the token length in bytes before any decoding; zero or a negative value
	// uses DefaultMaxTokenSize. Raise it when ciphertexts legitimately exceed the default, and keep
	// the HTTP layer's request body limit in sync. | MaxTokenSize 在解码前限制 token 字节长度；
	// 零值或负值使用 DefaultMaxTokenSize。密文确实超过默认值时请调高，并同步调整 HTTP 层的请求体
	// 上限。
	MaxTokenSize int
}

// Encrypt builds a JWE over plaintext with key. | Encrypt 使用 key 对 plaintext 生成 JWE。
//
// Serialization selects compact (the default), flattened JSON or general JSON. The compact form has
// a single protected header; the JSON forms add optional shared unprotected headers, per-recipient
// headers and an AAD member, and support multiple recipients through Recipients. The header always
// carries enc, while alg, kid, typ, cty, zip, apu, apv and epk are added when applicable. RSA1_5 is
// refused unless opts.AllowRSA1_5 is set. | Serialization 选择紧凑（默认）、扁平 JSON 或通用 JSON。
// 紧凑形式只有一个受保护头部；JSON 形式增加可选的共享非保护头部、每接收方头部与 AAD 成员，并通过
// Recipients 支持多个接收方。头部始终包含 enc，alg、kid、typ、cty、zip、apu、apv 与 epk 在适用时
// 加入。除非设置 opts.AllowRSA1_5，否则拒绝 RSA1_5。
func Encrypt(plaintext []byte, key *Key, opts EncryptOptions) (string, error) {
	switch opts.Serialization {
	case SerializationCompact:
		if key == nil {
			return "", ErrInvalidKey
		}
		if len(opts.Recipients) > 0 || opts.Unprotected != nil || opts.AAD != nil {
			return "", errs.Detail(ErrInvalidConfig, "Recipients, Unprotected and AAD require a JSON serialization | Recipients、Unprotected 与 AAD 需要 JSON 序列化")
		}
		return encryptCompact(plaintext, key, opts)
	case SerializationFlattened, SerializationGeneral:
		return encryptJSON(plaintext, key, opts)
	default:
		return "", errs.Detail(ErrInvalidConfig, "unknown serialization %[1]q | 未知序列化 %[1]q", string(opts.Serialization))
	}
}

// encryptCompact builds a compact JWE. | encryptCompact 构建紧凑 JWE。
func encryptCompact(plaintext []byte, key *Key, opts EncryptOptions) (string, error) {
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
	if err := checkKeyUse(key, "encrypt"); err != nil {
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
	cek, encryptedKey, epk, err := encryptCEK(alg, key, enc, nil, opts.APU, opts.APV)
	if err != nil {
		return "", err
	}
	h.EPK = epk
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

// Decrypt decrypts a JWE with key. | Decrypt 使用 key 解密 JWE。
//
// The input may be a compact JWE or a flattened/general JWE JSON serialization; a value whose first
// non-space byte is '{' is parsed as JSON, while every other value is compact. For a JSON
// serialization with several recipients, the recipients whose kid matches key.Kid are tried first
// and the first recipient that authenticates wins. | 输入可以是紧凑 JWE 或扁平/通用 JWE JSON
// 序列化；首个非空白字节为 '{' 的取值按 JSON 解析，其它取值按紧凑解析。对于包含多个接收方的 JSON
// 序列化，kid 与 key.Kid 匹配的接收方先尝试，第一个通过认证的接收方胜出。
//
// The input length is checked before any decoding: the limit is DecryptOptions.MaxTokenSize, or
// DefaultMaxTokenSize when it is zero or negative, and an over-limit token is rejected with
// ErrTokenTooLarge. Decryption authenticates before releasing plaintext; CBC tags are compared in
// constant time before any padding is examined, and GCM authentication happens inside the AEAD.
// Duplicate header members, critical extensions, unknown alg/enc/zip values, ambiguous empty or
// non-empty encrypted-key segments, duplicate parameters across protected, unprotected and
// per-recipient headers, and RSA1_5 without opt-in are all refused. RSA1_5 is deprecated by RFC 7518
// because RSA PKCS#1 v1.5 decryption is vulnerable to Bleichenbacher-style oracles; it is accepted
// only through DecryptOptions.AllowRSA1_5, and every RSA key-transport failure is reported with the
// same error and message so that padding and CEK-length failures cannot be distinguished. Callers
// that do not need legacy interoperability should leave it disabled. | 任何解码之前先检查输入长度：
// 上限为 DecryptOptions.MaxTokenSize，零值或负值时使用 DefaultMaxTokenSize，超限返回
// ErrTokenTooLarge。解密在释放明文前完成认证；CBC 标签在任何填充检查之前以常量时间比较，GCM
// 认证在 AEAD 内部完成。重复头部成员、关键扩展、未知 alg/enc/zip、与算法矛盾的加密密钥段（应空
// 不空或应非空却空）、受保护/非保护/每接收方头部之间的重复参数以及未显式开启的 RSA1_5 都会被拒绝。
// RFC 7518 因 RSA PKCS#1 v1.5 解密易受 Bleichenbacher 类预言机攻击而弃用 RSA1_5；本实现仅在
// DecryptOptions.AllowRSA1_5 显式开启时接受，并让所有 RSA 密钥传输失败返回相同的错误与文案，使
// 填充失败与 CEK 长度失败不可区分。无需兼容旧系统的调用方应保持关闭。
func Decrypt(token string, key *Key, opts DecryptOptions) ([]byte, error) {
	if key == nil {
		return nil, ErrInvalidKey
	}
	if err := checkTokenSize(token, opts.MaxTokenSize); err != nil {
		return nil, err
	}
	if isJSONJWE(token) {
		doc, err := parseJWEJSON(token)
		if err != nil {
			return nil, err
		}
		return decryptJWEJSONWithKey(doc, key, opts)
	}
	parts, h, _, err := parseCompactJWE(token, opts)
	if err != nil {
		return nil, err
	}
	return decryptCompactJWE(parts, h, key, opts)
}

// DecryptWithResolver decrypts a JWE with keys chosen by resolver. | DecryptWithResolver 使用
// resolver 选择的密钥解密 JWE。
//
// Compact, flattened JSON and general JSON are accepted. For every JSON recipient the merged
// protected, shared unprotected and per-recipient headers are offered to the resolver, and the first
// recipient whose key authenticates the content wins; when none does, the first error is returned.
// RSA1_5 still requires DecryptOptions.AllowRSA1_5. | 接受紧凑、扁平 JSON 与通用 JSON。对于每个
// JSON 接收方，合并后的受保护、共享非保护与每接收方头部会交给 resolver；第一个用其密钥通过内容
// 认证的接收方胜出；全部失败时返回第一个错误。RSA1_5 仍要求 DecryptOptions.AllowRSA1_5。
func DecryptWithResolver(token string, resolver KeyResolver, opts DecryptOptions) ([]byte, error) {
	if resolver == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil key resolver | 密钥解析器为 nil")
	}
	if err := checkTokenSize(token, opts.MaxTokenSize); err != nil {
		return nil, err
	}
	if isJSONJWE(token) {
		doc, err := parseJWEJSON(token)
		if err != nil {
			return nil, err
		}
		return decryptJWEJSONWithResolver(doc, resolver, opts)
	}
	parts, h, rawHeader, err := parseCompactJWE(token, opts)
	if err != nil {
		return nil, err
	}
	key, err := resolver.ResolveKey(context.Background(), rawHeader)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, errs.Detail(ErrKeyNotFound, "resolver returned nil key | 解析器返回 nil 密钥")
	}
	return decryptCompactJWE(parts, h, key, opts)
}

// isJSONJWE reports whether token starts, after whitespace, with '{'. | isJSONJWE 报告 token 在
// 空白之后是否以 '{' 开头。
func isJSONJWE(token string) bool {
	i := 0
	for i < len(token) {
		switch token[i] {
		case ' ', '\t', '\r', '\n':
			i++
			continue
		}
		break
	}
	return i < len(token) && token[i] == '{'
}

// parseCompactJWE validates the compact structure and protected header before key selection. |
// parseCompactJWE 在选择密钥之前校验紧凑结构与受保护头部。
func parseCompactJWE(token string, opts DecryptOptions) ([]string, jweHeader, Header, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, jweHeader{}, nil, errs.Detail(ErrMalformed, "JWE must have five segments | JWE 必须包含五段")
	}
	if parts[0] == "" {
		return nil, jweHeader{}, nil, errs.Detail(ErrMalformed, "empty protected header | 受保护头部为空")
	}
	headerBytes, err := DecodeSegment(parts[0])
	if err != nil {
		return nil, jweHeader{}, nil, err
	}
	h, rawHeader, err := parseJWEHeaderMap(headerBytes)
	if err != nil {
		return nil, jweHeader{}, nil, err
	}
	if !supportedJWEAlg(h.Alg) {
		return nil, jweHeader{}, nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", h.Alg)
	}
	if !supportedEnc(h.Enc) {
		return nil, jweHeader{}, nil, errs.Detail(ErrUnsupportedEnc, "enc=%[1]q | enc=%[1]q", h.Enc)
	}
	if h.Zip != "" && h.Zip != ZipDEF {
		return nil, jweHeader{}, nil, errs.Detail(ErrInvalidHeader, "zip=%[1]q | zip=%[1]q", h.Zip)
	}
	if h.Alg == AlgRSA15 && !opts.AllowRSA1_5 {
		return nil, jweHeader{}, nil, errs.Detail(ErrAlgNotAllowed, "RSA1_5 requires explicit opt-in | RSA1_5 需要显式开启")
	}
	return parts, h, rawHeader, nil
}

// decryptCompactJWE decrypts the five compact segments with key. | decryptCompactJWE 使用 key 解密
// 五个紧凑段。
func decryptCompactJWE(parts []string, h jweHeader, key *Key, opts DecryptOptions) ([]byte, error) {
	if key.Alg != "" && key.Alg != h.Alg {
		return nil, errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, h.Alg)
	}
	if err := checkKeyAlg(key, h.Alg); err != nil {
		return nil, err
	}
	if err := checkKeyUse(key, "decrypt"); err != nil {
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
	h, _, err := parseJWEHeaderMap(raw)
	return h, err
}

// parseJWEHeaderMap decodes a protected JWE header and returns both the typed header and its raw
// parameter map for a KeyResolver. | parseJWEHeaderMap 解码受保护的 JWE 头部，并同时返回类型化
// 头部与供 KeyResolver 使用的原始参数映射。
func parseJWEHeaderMap(raw []byte) (jweHeader, Header, error) {
	m, err := headerJSON(raw)
	if err != nil {
		return jweHeader{}, nil, err
	}
	if err := validateJWEProtectedCrit(m); err != nil {
		return jweHeader{}, nil, err
	}
	h, err := jweHeaderFromMap(m)
	if err != nil {
		return jweHeader{}, nil, err
	}
	return h, Header(m), nil
}

// validateJWEProtectedCrit refuses any non-empty crit because no JWE extension is understood. |
// validateJWEProtectedCrit 拒绝任何非空 crit，因为本实现不理解任何 JWE 扩展。
func validateJWEProtectedCrit(m map[string]any) error {
	if v, present := m["crit"]; present {
		crit, ok := stringSlice(v)
		if !ok || len(crit) > 0 {
			return errs.Detail(ErrUnsupportedCrit, "crit is not supported | 不支持 crit")
		}
	}
	return nil
}

// jweHeaderFromMap decodes a merged JWE header parameter map. | jweHeaderFromMap 解码合并后的 JWE
// 头部参数映射。
func jweHeaderFromMap(m map[string]any) (jweHeader, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return jweHeader{}, errs.WrapDetail(err, ErrInvalidHeader, "encode merged JWE header | 编码合并后的 JWE 头部")
	}
	var h jweHeader
	if err := unmarshal(raw, &h); err != nil {
		return jweHeader{}, errs.WrapDetail(err, ErrInvalidHeader, "decode JWE header | 解码 JWE 头部")
	}
	return validateJWEHeader(h)
}

// validateJWEHeader checks the decoded alg, enc and ECDH parameters of a JWE header. |
// validateJWEHeader 检查解码后的 JWE 头部 alg、enc 与 ECDH 参数。
func validateJWEHeader(h jweHeader) (jweHeader, error) {
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

// encryptCEK performs key management and returns the CEK, the encrypted key segment and, for
// ECDH-ES, the ephemeral public key. | encryptCEK 执行密钥管理并返回 CEK、加密密钥段，以及 ECDH-ES
// 的临时公钥。
//
// When cek is nil a fresh CEK is generated for every algorithm that wraps a CEK. A non-nil cek lets
// a multi-recipient JWE share one CEK across RSA, AES Key Wrap and ECDH-ES+KW recipients; dir and
// ECDH-ES derive the CEK instead and therefore require cek to be nil. | cek 为 nil 时，每个包装 CEK
// 的算法都会生成新的 CEK。非 nil 的 cek 让多接收方 JWE 在 RSA、AES Key Wrap 与 ECDH-ES+KW 接收方
// 之间共享同一个 CEK；dir 与 ECDH-ES 派生 CEK，因此要求 cek 为 nil。
func encryptCEK(alg string, key *Key, enc string, cek, apu, apv []byte) (outCEK, encryptedKey []byte, epk *Key, err error) {
	p, _ := encParamsFor(enc)
	switch alg {
	case AlgRSAOAEP, AlgRSAOAEP256, AlgRSA15:
		outCEK, err = sharedOrNewCEK(cek, p.cekLen, enc)
		if err != nil {
			return nil, nil, nil, err
		}
		raw, err := key.PublicKey()
		if err != nil {
			return nil, nil, nil, err
		}
		pub, ok := raw.(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < 2048 {
			return nil, nil, nil, errs.Detail(ErrWeakKey, "RSA key transport needs a 2048-bit key | RSA 密钥传输需要 2048 位密钥")
		}
		switch alg {
		case AlgRSAOAEP:
			encryptedKey, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, outCEK, nil)
		case AlgRSAOAEP256:
			encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, outCEK, nil)
		default:
			encryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, pub, outCEK)
		}
		if err != nil {
			return nil, nil, nil, errs.WrapDetail(err, ErrInvalidKey, "RSA key encryption | RSA 密钥加密")
		}
	case AlgA128KW, AlgA192KW, AlgA256KW:
		kek, err := key.octets()
		if err != nil {
			return nil, nil, nil, err
		}
		outCEK, err = sharedOrNewCEK(cek, p.cekLen, enc)
		if err != nil {
			return nil, nil, nil, err
		}
		encryptedKey, err = aesKeyWrap(kek, outCEK)
		if err != nil {
			return nil, nil, nil, err
		}
	case AlgDir:
		if cek != nil {
			return nil, nil, nil, errs.Detail(ErrInvalidConfig, "dir derives the CEK and cannot share one | dir 派生 CEK，无法共享")
		}
		outCEK, err = key.octets()
		if err != nil {
			return nil, nil, nil, err
		}
		if len(outCEK) != p.cekLen {
			return nil, nil, nil, errs.Detail(ErrWeakKey, "dir with enc=%[1]s needs a %[2]d-byte key | dir 配 enc=%[1]s 需要 %[2]d 字节密钥", enc, p.cekLen)
		}
	case AlgECDHES:
		if cek != nil {
			return nil, nil, nil, errs.Detail(ErrInvalidConfig, "ECDH-ES derives the CEK and cannot share one | ECDH-ES 派生 CEK，无法共享")
		}
		var shared []byte
		shared, epk, err = ecdhSharedForEncrypt(key)
		if err != nil {
			return nil, nil, nil, err
		}
		outCEK, err = concatKDF(shared, []byte(enc), apu, apv, p.cekLen)
		if err != nil {
			return nil, nil, nil, err
		}
	case AlgECDHESA128KW, AlgECDHESA192KW, AlgECDHESA256KW:
		var shared []byte
		shared, epk, err = ecdhSharedForEncrypt(key)
		if err != nil {
			return nil, nil, nil, err
		}
		kekLen := map[string]int{AlgECDHESA128KW: 16, AlgECDHESA192KW: 24, AlgECDHESA256KW: 32}[alg]
		kek, err := concatKDF(shared, []byte(alg), apu, apv, kekLen)
		if err != nil {
			return nil, nil, nil, err
		}
		outCEK, err = sharedOrNewCEK(cek, p.cekLen, enc)
		if err != nil {
			return nil, nil, nil, err
		}
		encryptedKey, err = aesKeyWrap(kek, outCEK)
		if err != nil {
			return nil, nil, nil, err
		}
	default:
		return nil, nil, nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	return outCEK, encryptedKey, epk, nil
}

// sharedOrNewCEK returns cek when it has the expected length, or generates a fresh CEK. | sharedOrNewCEK
// 在 cek 长度符合预期时返回它，否则生成新的 CEK。
func sharedOrNewCEK(cek []byte, n int, enc string) ([]byte, error) {
	if cek == nil {
		return randomBytes(n)
	}
	if len(cek) != n {
		return nil, errs.Detail(ErrInvalidConfig, "shared CEK has %[1]d bytes, enc=%[2]s needs %[3]d | 共享 CEK 为 %[1]d 字节，enc=%[2]s 需要 %[3]d 字节", len(cek), enc, n)
	}
	return cek, nil
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
	out, err := strictRawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidHeader, "apu/apv | apu/apv")
	}
	return out, nil
}
