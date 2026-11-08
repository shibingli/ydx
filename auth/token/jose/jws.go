package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"sort"
	"strings"
	"time"

	ydjwt "github.com/shibingli/ydx/auth/token/jwt"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// JWSHeader is the protected header of a JWS. | JWSHeader 是 JWS 的受保护头部。
type JWSHeader struct {
	// Alg is the "alg" parameter and is mandatory; "none" is never accepted. | Alg 是 "alg" 参数且为必需；"none" 永不被接受。
	Alg string
	// Kid is the optional "kid" parameter selecting the signing key. | Kid 是可选的 "kid" 参数，用于选择签名密钥。
	Kid string
	// Typ is the optional "typ" parameter, for example "JWT". | Typ 是可选的 "typ" 参数，例如 "JWT"。
	Typ string
	// Cty is the optional "cty" parameter describing the payload content type. | Cty 是可选的 "cty" 参数，描述载荷内容类型。
	Cty string
	// Crit lists critical extensions. Only "b64" from RFC 7797 is understood; any other entry is
	// refused. | Crit 列出关键扩展。仅理解 RFC 7797 的 "b64"；其它条目一律拒绝。
	Crit []string
	// B64 is the RFC 7797 "b64" parameter: nil when absent, true when the payload is base64url
	// encoded (the default), and false when the payload is unencoded. A false value requires "b64"
	// to appear in Crit. | B64 是 RFC 7797 的 "b64" 参数：缺失时为 nil，true 表示载荷经 base64url
	// 编码（默认），false 表示载荷未编码。取值为 false 时要求 Crit 中包含 "b64"。
	B64 *bool
	// Extra holds additional non-reserved header parameters. | Extra 保存额外的非保留头部参数。
	Extra map[string]any
}

// Verified is the result of a successful JWS verification. | Verified 是 JWS 校验成功的结果。
type Verified struct {
	// Header is the parsed protected header. | Header 是解析后的受保护头部。
	Header JWSHeader
	// RawHeader is the full parameter map, including application-defined values. | RawHeader 是完整参数映射，包含应用自定义取值。
	RawHeader Header
	// Payload is the decoded payload bytes, exactly as signed. | Payload 是解码后的载荷字节，与签名覆盖的内容完全一致。
	Payload []byte
	// Claims is Payload when it is a well-formed JSON object, otherwise nil. | Claims 在 Payload 为结构良好的 JSON 对象时等于 Payload，否则为 nil。
	Claims []byte
	// Signature is the decoded signature bytes. | Signature 是解码后的签名字节。
	Signature []byte
}

// IsJSON reports whether the payload is a well-formed JSON object. | IsJSON 报告载荷是否为结构
// 良好的 JSON 对象。
func (v *Verified) IsJSON() bool { return v != nil && v.Claims != nil }

// Serialization selects the JWS serialization used by Sign and Verify. | Serialization 选择 Sign
// 与 Verify 使用的 JWS 序列化形式。
type Serialization string

// The supported JWS serializations. | 受支持的 JWS 序列化形式。
const (
	// SerializationCompact is the RFC 7515 §7.1 compact serialization and the zero value. Sign
	// emits the compact form; Verify with this zero value accepts a compact token and also
	// auto-detects a JSON serialization, because a compact token can never start with '{'. |
	// SerializationCompact 是 RFC 7515 §7.1 的紧凑序列化，也是零值。Sign 输出紧凑形式；Verify
	// 使用该零值时接受紧凑 token，并自动识别 JSON 序列化，因为紧凑 token 绝不会以 '{' 开头。
	SerializationCompact Serialization = ""
	// SerializationFlattened is the RFC 7515 §7.2.2 flattened JSON serialization. | SerializationFlattened
	// 是 RFC 7515 §7.2.2 的扁平 JSON 序列化。
	SerializationFlattened Serialization = "flattened"
	// SerializationGeneral is the RFC 7515 §7.2.1 general JSON serialization. | SerializationGeneral
	// 是 RFC 7515 §7.2.1 的通用 JSON 序列化。
	SerializationGeneral Serialization = "general"
)

// KeyResolver resolves the verification key for a JOSE header. | KeyResolver 为 JOSE 头部解析校验密钥。
type KeyResolver interface {
	// ResolveKey returns the key named by the header, or an error. | ResolveKey 返回头部指定的密钥或错误。
	ResolveKey(ctx context.Context, header Header) (*Key, error)
}

// KeyResolverFunc adapts a function to KeyResolver. | KeyResolverFunc 把函数适配为 KeyResolver。
type KeyResolverFunc func(ctx context.Context, header Header) (*Key, error)

// ResolveKey calls f(ctx, header). | ResolveKey 调用 f(ctx, header)。
func (f KeyResolverFunc) ResolveKey(ctx context.Context, header Header) (*Key, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil key resolver | 密钥解析器为 nil")
	}
	return f(ctx, header)
}

// KeySetResolver returns a resolver that selects keys from set by kid. | KeySetResolver 返回按 kid
// 从 set 选择密钥的解析器。
func KeySetResolver(set *KeySet) KeyResolver {
	return KeyResolverFunc(func(_ context.Context, header Header) (*Key, error) {
		return set.Lookup(header.String("kid"))
	})
}

// CacheResolver returns a resolver that selects keys from cache by kid. | CacheResolver 返回按 kid
// 从 cache 选择密钥的解析器。
func CacheResolver(cache *Cache) KeyResolver {
	return KeyResolverFunc(func(_ context.Context, header Header) (*Key, error) {
		if cache == nil {
			return nil, errs.Detail(ErrKeyNotFound, "nil key cache | 密钥缓存为 nil")
		}
		return cache.Get(header.String("kid"))
	})
}

// Resolver returns a resolver backed by the set. | Resolver 返回由该集合支持的解析器。
func (s *KeySet) Resolver() KeyResolver { return KeySetResolver(s) }

// Resolver returns a resolver backed by the cache. | Resolver 返回由该缓存支持的解析器。
func (c *Cache) Resolver() KeyResolver { return CacheResolver(c) }

// SignOptions configures Sign. | SignOptions 配置 Sign。
type SignOptions struct {
	// Alg overrides the algorithm; when empty key.Alg is used and must be set. | Alg 覆盖算法；为空时使用 key.Alg，且必须已设置。
	Alg string
	// Kid overrides the key identifier; when empty key.Kid is used. | Kid 覆盖密钥标识；为空时使用 key.Kid。
	Kid string
	// Typ sets the "typ" header parameter. | Typ 设置 "typ" 头部参数。
	Typ string
	// Cty sets the "cty" header parameter. | Cty 设置 "cty" 头部参数。
	Cty string
	// Crit lists critical extensions. Only "b64" from RFC 7797 is understood; any other entry is
	// refused with ErrUnsupportedCrit. A "b64" entry without an explicit UnencodedPayload selects
	// b64=true, and UnencodedPayload adds the entry automatically. | Crit 列出关键扩展。仅理解
	// RFC 7797 的 "b64"；其它条目一律以 ErrUnsupportedCrit 拒绝。未显式设置 UnencodedPayload 时，
	// "b64" 条目会选择 b64=true；UnencodedPayload 会自动加入该条目。
	Crit []string
	// Extra holds additional header parameters; reserved names are refused. | Extra 保存额外头部参数；保留名会被拒绝。
	Extra map[string]any
	// Serialization selects the output form: compact (the default), flattened JSON or general JSON. | Serialization
	// 选择输出形式：紧凑（默认）、扁平 JSON 或通用 JSON。
	Serialization Serialization
	// Detached omits the payload from the serialization for RFC 7515 Appendix F detached content.
	// The signature still covers the payload, and the caller must present it to VerifyDetached.
	// Detached works with both b64=true and RFC 7797 b64=false; an unencoded detached payload may
	// contain any byte, including '.'. | Detached 按 RFC 7515 附录 F 从序列化中移除载荷。签名仍覆盖
	// 载荷，调用方必须把它交给 VerifyDetached。Detached 同时适用于 b64=true 与 RFC 7797 b64=false；
	// 未编码的分离载荷可以包含任意字节，包括 '.'。
	Detached bool
	// UnencodedPayload selects the RFC 7797 b64=false form and adds "b64" to Crit. A compact
	// attached payload must not contain '.', because the compact serialization would become
	// ambiguous; a JSON attached payload must be valid UTF-8 so it can be carried as a JSON string.
	// Detached payloads have no such restriction. | UnencodedPayload 选择 RFC 7797 的 b64=false 形式，
	// 并把 "b64" 加入 Crit。紧凑的非分离载荷不得包含 '.'，否则紧凑序列化会产生歧义；JSON 非分离载荷
	// 必须是合法 UTF-8，才能作为 JSON 字符串承载。分离载荷没有这些限制。
	UnencodedPayload bool
	// LowS normalizes ES256, ES384 and ES512 signatures to the canonical low-S form. It has no
	// effect on other algorithms. | LowS 把 ES256、ES384 与 ES512 签名规范化为规范的 low-S 形式。
	// 其它算法不受影响。
	LowS bool
}

// Sign builds a JWS over payload with key, using the serialization selected by
// SignOptions.Serialization (compact by default). | Sign 使用 key 对 payload 生成 JWS，序列化形式由
// SignOptions.Serialization 选择（默认为紧凑）。
//
// The payload may be arbitrary bytes; a JSON object is signed through the ydx/auth/token/jwt fast path
// when the header is a plain JWT header, and every other payload is signed directly by the crypto
// primitives. The header always carries alg and never carries alg=none. | 载荷可以是任意字节；
// 当头部是普通 JWT 头部时，JSON 对象经 ydx/auth/token/jwt 快路径签名，其它载荷则由加密原语直接签名。
// 头部始终包含 alg，且绝不会包含 alg=none。
//
// The key must match the algorithm: an "oct" key for HSxxx, RSA for RSxxx/PSxxx, EC on the
// matching curve for ESxxx, and OKP Ed25519 for EdDSA; any other family is refused with
// ErrKeyTypeMismatch. | 密钥必须与算法匹配：HSxxx 使用 "oct" 密钥，RSxxx/PSxxx 使用 RSA，
// ESxxx 使用对应曲线的 EC，EdDSA 使用 OKP Ed25519；其它密钥族一律以 ErrKeyTypeMismatch 拒绝。
func Sign(payload []byte, key *Key, opts SignOptions) (string, error) {
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
	if alg == "none" || !supportedJWSAlg(alg) {
		return "", errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	if key.Alg != "" && key.Alg != alg {
		return "", errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, alg)
	}
	if err := checkKeyAlg(key, alg); err != nil {
		return "", err
	}
	if err := checkKeyUse(key, "sign"); err != nil {
		return "", err
	}
	kid := opts.Kid
	if kid == "" {
		kid = key.Kid
	}
	header := JWSHeader{
		Alg:   alg,
		Kid:   kid,
		Typ:   opts.Typ,
		Cty:   opts.Cty,
		Crit:  opts.Crit,
		Extra: opts.Extra,
	}
	if opts.UnencodedPayload {
		b64 := false
		header.B64 = &b64
	}
	switch opts.Serialization {
	case SerializationCompact:
		if opts.Detached {
			return signDetachedCompact(payload, key, header, opts.LowS)
		}
	case SerializationFlattened, SerializationGeneral:
		return signJSON(payload, key, header, opts)
	default:
		return "", errs.Detail(ErrInvalidConfig, "unknown serialization %[1]q | 未知序列化 %[1]q", string(opts.Serialization))
	}
	// A plain JWT JSON payload goes through the existing ydx/auth/token/jwt signer, which is the same
	// implementation the rest of ydx uses; every other case is signed here so arbitrary bytes
	// remain possible. The JWT signer emits neither crit nor b64, so any RFC 7797 option takes the
	// direct path. | 普通 JWT JSON 载荷走现有 ydx/auth/token/jwt 签名器，即 ydx 其余部分使用的
	// 同一实现；其它情况在此签名，以便任意字节都能使用。JWT 签名器不输出 crit 或 b64，因此任何
	// RFC 7797 选项都走直接路径。
	if header.Typ == "JWT" && header.Cty == "" && len(header.Extra) == 0 && header.B64 == nil &&
		len(header.Crit) == 0 && isJSONObject(payload) {
		jkey, err := key.PrivateKey()
		if err != nil {
			return "", err
		}
		return ydjwt.SignJSON(payload, jkey, ydjwt.Alg(alg), ydjwt.SignOptions{Kid: kid, LowS: opts.LowS})
	}
	return signDirect(payload, key, header, opts.LowS)
}

// signDirect builds a compact JWS without the JWT-specific JSON requirement. | signDirect 构建不
// 受 JWT JSON 要求限制的紧凑 JWS。
func signDirect(payload []byte, key *Key, header JWSHeader, lowS bool) (string, error) {
	headerBytes, err := encodeJWSHeader(header)
	if err != nil {
		return "", err
	}
	unencoded := unencodedPayload(header)
	if unencoded && bytes.IndexByte(payload, '.') >= 0 {
		return "", errs.Detail(ErrInvalidConfig, "unencoded compact payload must not contain '.' | 未编码的紧凑载荷不得包含 '.'")
	}
	input := make([]byte, 0, len(headerBytes)+len(payload)+len(payload)/3+len(headerBytes)/3+2)
	input = appendJWSInput(input, headerBytes, payload, unencoded)
	sig, err := signJWSWithLowS(header.Alg, key, input, lowS)
	if err != nil {
		return "", err
	}
	input = append(input, '.')
	input = appendSegment(input, sig)
	return string(input), nil
}

// signDetachedCompact builds a compact JWS with the payload segment omitted (RFC 7515 Appendix F). |
// signDetachedCompact 构建省略载荷段的紧凑 JWS（RFC 7515 附录 F）。
func signDetachedCompact(payload []byte, key *Key, header JWSHeader, lowS bool) (string, error) {
	headerBytes, err := encodeJWSHeader(header)
	if err != nil {
		return "", err
	}
	unencoded := unencodedPayload(header)
	input := make([]byte, 0, len(headerBytes)+len(payload)+len(payload)/3+len(headerBytes)/3+2)
	input = appendJWSInput(input, headerBytes, payload, unencoded)
	sig, err := signJWSWithLowS(header.Alg, key, input, lowS)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, len(headerBytes)+len(sig)*2+2)
	out = appendSegment(out, headerBytes)
	out = append(out, '.', '.')
	out = appendSegment(out, sig)
	return string(out), nil
}

// VerifyOptions configures Verify. | VerifyOptions 配置 Verify。
type VerifyOptions struct {
	// ValidAlgs restricts accepted algorithms; nil means every supported algorithm. | ValidAlgs 限定可接受的算法；nil 表示全部受支持的算法。
	//
	// Setting it is strongly recommended: an allow list is the first line of defence against
	// algorithm confusion. | 强烈建议设置：白名单是抵御算法混淆的第一道防线。
	ValidAlgs []string
	// Typ, when non-empty, must match the typ header case-insensitively. | Typ 非空时必须与 typ 头部大小写不敏感地匹配。
	Typ string
	// Leeway is the clock tolerance applied to exp, nbf and iat by ValidateClaims. | Leeway 是
	// ValidateClaims 对 exp、nbf 与 iat 施加的时钟容差。
	Leeway time.Duration
	// Now overrides the clock used by ValidateClaims. | Now 替换 ValidateClaims 使用的时钟。
	Now func() time.Time
	// ValidateClaims enables ydx/auth/token/jwt registered-claim validation, including exp, nbf, iat,
	// iss and aud. Without it, a valid signature is the only requirement. | ValidateClaims 启用
	// ydx/auth/token/jwt 登记声明校验，包括 exp、nbf、iat、iss 与 aud。未启用时唯一要求是签名有效。
	ValidateClaims bool
	// RequireExp rejects a token without exp when ValidateClaims is set. | RequireExp 在启用
	// ValidateClaims 时拒绝缺少 exp 的令牌。
	RequireExp bool
	// Issuer, when non-empty and ValidateClaims is set, must equal the iss claim. | Issuer 非空且
	// 启用 ValidateClaims 时必须等于 iss 声明。
	Issuer string
	// Issuers, when non-empty and ValidateClaims is set, must contain the iss claim; the token
	// passes when iss equals any non-empty entry. It is combined with Issuer. | Issuers 非空且启用
	// ValidateClaims 时必须包含 iss 声明；iss 等于任意非空条目即通过。它与 Issuer 合并。
	Issuers []string
	// Audience, when non-empty and ValidateClaims is set, must be contained in aud. | Audience
	// 非空且启用 ValidateClaims 时必须包含于 aud。
	Audience string
	// Audiences, when non-empty and ValidateClaims is set, requires at least one non-empty entry
	// to be contained in the token aud. It is combined with Audience. | Audiences 非空且启用
	// ValidateClaims 时，要求其中至少一个非空条目包含于 token 的 aud。它与 Audience 合并。
	Audiences []string
	// ValidateIssuedAt, when ValidateClaims is set, rejects an iat later than Now plus Leeway. |
	// ValidateIssuedAt 在启用 ValidateClaims 时拒绝晚于 Now 加 Leeway 的 iat。
	ValidateIssuedAt bool
	// RequireIssuedAt, when ValidateClaims is set, requires a valid iat and implies
	// ValidateIssuedAt. | RequireIssuedAt 在启用 ValidateClaims 时要求合法的 iat，并隐含
	// ValidateIssuedAt。
	RequireIssuedAt bool
	// RequireLowS rejects non-canonical high-S ECDSA signatures on ES256, ES384 and ES512. |
	// RequireLowS 拒绝 ES256、ES384 与 ES512 的非规范高 S ECDSA 签名。
	RequireLowS bool
	// Serialization selects the accepted input form. The zero value accepts a compact token and
	// also auto-detects a JSON serialization from its leading '{'; setting SerializationFlattened
	// or SerializationGeneral pins that JSON form and rejects the other. | Serialization 选择接受
	// 的输入形式。零值接受紧凑 token，并根据开头的 '{' 自动识别 JSON 序列化；设置
	// SerializationFlattened 或 SerializationGeneral 会固定该 JSON 形式并拒绝另一种。
	Serialization Serialization
	// MaxTokenSize caps the token length in bytes before any decoding; zero or a negative value
	// uses DefaultMaxTokenSize. Raise it when payloads legitimately exceed the default, and keep
	// the HTTP layer's request body limit in sync. | MaxTokenSize 在解码前限制 token 字节长度；
	// 零值或负值使用 DefaultMaxTokenSize。载荷确实超过默认值时请调高，并同步调整 HTTP 层的请求体
	// 上限。
	MaxTokenSize int
}

// Verify verifies a compact JWS using resolver and the background context. | Verify 使用 resolver
// 与后台上下文校验紧凑 JWS。
//
// Compact is the default input form. A value whose first non-space byte is '{' is treated as a JWS
// JSON serialization (flattened or general), so existing compact tokens are unaffected. Set
// VerifyOptions.Serialization to pin a form explicitly. | 默认输入形式为紧凑。首个非空白字节为 '{'
// 的取值按 JWS JSON 序列化（扁平或通用）处理，因此既有紧凑 token 不受影响。可用
// VerifyOptions.Serialization 显式固定形式。
func Verify(token string, resolver KeyResolver, opts VerifyOptions) (*Verified, error) {
	return VerifyContext(context.Background(), token, resolver, opts)
}

// VerifyDetached verifies a JWS whose payload was detached per RFC 7515 Appendix F. | VerifyDetached
// 校验按 RFC 7515 附录 F 分离载荷的 JWS。
//
// The token may be a compact "header..signature" value or a flattened/general JSON document without
// a payload member, and must not carry a payload itself. payload supplies the signed bytes; both
// b64=true and RFC 7797 b64=false are supported, so payload is always covered by the signature. |
// token 可以是 "header..signature" 紧凑值，或缺少 payload 成员的扁平/通用 JSON 文档，且自身不得
// 携带载荷。payload 提供被签名的字节；同时支持 b64=true 与 RFC 7797 b64=false，因此 payload
// 始终被签名覆盖。
func VerifyDetached(token string, payload []byte, resolver KeyResolver, opts VerifyOptions) (*Verified, error) {
	return VerifyDetachedContext(context.Background(), token, payload, resolver, opts)
}

// VerifyDetachedContext verifies a detached-payload JWS using ctx. | VerifyDetachedContext 使用
// ctx 校验分离载荷的 JWS。
func VerifyDetachedContext(ctx context.Context, token string, payload []byte, resolver KeyResolver, opts VerifyOptions) (*Verified, error) {
	return verifyContext(ctx, token, payload, resolver, opts, true)
}

// VerifyContext verifies a JWS using resolver and ctx. | VerifyContext 使用 resolver 与 ctx 校验 JWS。
//
// The input length is checked before any decoding: the limit is VerifyOptions.MaxTokenSize, or
// DefaultMaxTokenSize when it is zero or negative, and an over-limit token is rejected with
// ErrTokenTooLarge. The header is then decoded and its alg is checked against the allow list and key
// family before the signature is validated; only then is the payload exposed. RFC 7797 b64=false is
// understood when "b64" appears in crit; every other critical extension, duplicate header members,
// alg=none and algorithm confusion are rejected. A general JSON
// serialization succeeds when any one of its signatures verifies; the first failure is returned when
// none does. When ValidateClaims is set, a JSON-object payload is additionally validated by
// ydx/auth/token/jwt, whose sentinels remain visible through errors.Is. | 任何解码之前先检查输入长度：
// 上限为 VerifyOptions.MaxTokenSize，零值或负值时使用 DefaultMaxTokenSize，超限返回 ErrTokenTooLarge。
// 随后解码头部，并在校验签名之前检查 alg 是否在白名单内且与密钥族匹配；之后才暴露载荷。当 "b64"
// 出现在 crit 中时理解 RFC 7797 的 b64=false；其它关键扩展、重复头部成员、alg=none 与算法混淆都会
// 被拒绝。通用 JSON 序列化在任意一个签名通过时即成功；全部失败时
// 返回第一个错误。启用 ValidateClaims 时，JSON 对象载荷还会经 ydx/auth/token/jwt 校验，其哨兵仍可通过
// errors.Is 观察到。
func VerifyContext(ctx context.Context, token string, resolver KeyResolver, opts VerifyOptions) (*Verified, error) {
	return verifyContext(ctx, token, nil, resolver, opts, false)
}

// verifyContext dispatches the compact and JSON serializations. | verifyContext 分派紧凑与 JSON 序列化。
func verifyContext(ctx context.Context, token string, detachedPayload []byte, resolver KeyResolver, opts VerifyOptions, detached bool) (*Verified, error) {
	if resolver == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil key resolver | 密钥解析器为 nil")
	}
	if err := checkTokenSize(token, opts.MaxTokenSize); err != nil {
		return nil, err
	}
	jsonForm, err := detectJSONSerialization(token, opts.Serialization)
	if err != nil {
		return nil, err
	}
	if jsonForm {
		return verifyJSONContext(ctx, token, detachedPayload, resolver, opts, detached)
	}
	return verifyCompactContext(ctx, token, detachedPayload, resolver, opts, detached)
}

// detectJSONSerialization reports whether token must be parsed as a JWS JSON serialization. |
// detectJSONSerialization 报告 token 是否必须按 JWS JSON 序列化解析。
//
// The zero option auto-detects: compact segments are base64url and therefore never start with '{',
// while a JSON serialization always does after optional whitespace. | 零值选项自动识别：紧凑段是
// base64url，绝不会以 '{' 开头，而 JSON 序列化在可选空白之后总是以 '{' 开头。
func detectJSONSerialization(token string, sel Serialization) (bool, error) {
	switch sel {
	case SerializationFlattened, SerializationGeneral:
		return true, nil
	case SerializationCompact:
		i := 0
		for i < len(token) {
			switch token[i] {
			case ' ', '\t', '\r', '\n':
				i++
				continue
			}
			break
		}
		return i < len(token) && token[i] == '{', nil
	}
	return false, errs.Detail(ErrInvalidConfig, "unknown serialization %[1]q | 未知序列化 %[1]q", string(sel))
}

// verifyCompactContext verifies a compact JWS. | verifyCompactContext 校验紧凑 JWS。
func verifyCompactContext(ctx context.Context, token string, detachedPayload []byte, resolver KeyResolver, opts VerifyOptions, detached bool) (*Verified, error) {
	first := strings.IndexByte(token, '.')
	if first <= 0 {
		return nil, errs.Detail(ErrMalformed, "missing header or payload separator | 缺少头部或载荷分隔符")
	}
	rest := token[first+1:]
	second := strings.IndexByte(rest, '.')
	if second < 0 {
		return nil, errs.Detail(ErrMalformed, "missing signature separator | 缺少签名分隔符")
	}
	if strings.IndexByte(rest[second+1:], '.') >= 0 {
		return nil, errs.Detail(ErrMalformed, "too many segments | 段数过多")
	}
	payloadSeg, sigSeg := rest[:second], rest[second+1:]
	if detached && payloadSeg != "" {
		return nil, errs.Detail(ErrMalformed, "detached token carries a payload segment | 分离载荷 token 带有载荷段")
	}
	return verifyVerified(ctx, token[:first], nil, payloadSeg, sigSeg, detachedPayload, resolver, opts, detached)
}

// verifyJSONContext verifies a flattened or general JSON serialization. | verifyJSONContext 校验
// 扁平或通用 JSON 序列化。
func verifyJSONContext(ctx context.Context, token string, detachedPayload []byte, resolver KeyResolver, opts VerifyOptions, detached bool) (*Verified, error) {
	doc, err := parseJWSJSON(token)
	if err != nil {
		return nil, err
	}
	if opts.Serialization == SerializationFlattened && doc.general {
		return nil, errs.Detail(ErrMalformed, "general JSON serialization is not allowed | 不允许通用 JSON 序列化")
	}
	if opts.Serialization == SerializationGeneral && !doc.general {
		return nil, errs.Detail(ErrMalformed, "flattened JSON serialization is not allowed | 不允许扁平 JSON 序列化")
	}
	if detached {
		if doc.hasPayload {
			return nil, errs.Detail(ErrMalformed, "detached verification requires a token without payload | 分离载荷校验要求 token 不含 payload")
		}
	} else if !doc.hasPayload {
		return nil, errs.Detail(ErrMalformed, "token has no payload; use VerifyDetached | token 缺少 payload，请使用 VerifyDetached")
	}
	var firstErr error
	for _, cand := range doc.signatures {
		verified, err := verifyVerified(ctx, cand.protected, cand.header, doc.payload, cand.signature, detachedPayload, resolver, opts, detached)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return verified, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errs.Detail(ErrMalformed, "no signature to verify | 没有可校验的签名")
}

// verifyVerified verifies one signature and optionally validates its claims. | verifyVerified
// 校验单个签名，并可选地校验其声明。
func verifyVerified(ctx context.Context, protectedSeg string, unprotected Header, payloadSeg, sigSeg string, detachedPayload []byte, resolver KeyResolver, opts VerifyOptions, detached bool) (*Verified, error) {
	header, rawHeader, key, payload, sig, err := verifyJWSSignature(ctx, protectedSeg, unprotected, payloadSeg, sigSeg, detachedPayload, resolver, opts, detached)
	if err != nil {
		return nil, err
	}
	verified := &Verified{
		Header:    header,
		RawHeader: rawHeader,
		Payload:   payload,
		Signature: sig,
	}
	if isJSONObject(payload) {
		verified.Claims = payload
	}
	if opts.ValidateClaims {
		if verified.Claims == nil {
			return nil, errs.Detail(ErrClaimsInvalid, "payload is not a JSON object | 载荷不是 JSON 对象")
		}
		if unencodedPayload(header) {
			if err := validateClaimsUnencoded(payload, opts); err != nil {
				return nil, err
			}
		} else {
			checkPayloadSeg := payloadSeg
			if detached {
				checkPayloadSeg = EncodeSegment(payload)
			}
			compact := protectedSeg + "." + checkPayloadSeg + "." + sigSeg
			if err := validateClaims(compact, key, header.Alg, opts); err != nil {
				return nil, err
			}
		}
	}
	return verified, nil
}

// verifyJWSSignature verifies a single JWS signature. | verifyJWSSignature 校验单个 JWS 签名。
//
// protectedSeg is the base64url protected header, unprotected is an optional decoded unprotected
// header, and payloadSeg is the exact payload segment from the serialization. When detached is set,
// payloadSeg is ignored and detachedPayload supplies the signed bytes. | protectedSeg 是 base64url
// 受保护头部，unprotected 是可选的已解码非保护头部，payloadSeg 是序列化中原样的载荷段。detached
// 为真时忽略 payloadSeg，由 detachedPayload 提供被签名的字节。
func verifyJWSSignature(ctx context.Context, protectedSeg string, unprotected Header, payloadSeg, sigSeg string, detachedPayload []byte, resolver KeyResolver, opts VerifyOptions, detached bool) (JWSHeader, Header, *Key, []byte, []byte, error) {
	fail := func(err error) (JWSHeader, Header, *Key, []byte, []byte, error) {
		return JWSHeader{}, nil, nil, nil, nil, err
	}
	if sigSeg == "" {
		return fail(errs.Detail(ErrMalformed, "empty signature segment | 签名段为空"))
	}
	if protectedSeg == "" {
		return fail(errs.Detail(ErrInvalidHeader, "missing protected header | 缺少受保护头部"))
	}
	raw, err := DecodeSegment(protectedSeg)
	if err != nil {
		return fail(err)
	}
	header, rawHeader, err := parseJWSHeader(raw)
	if err != nil {
		return fail(err)
	}
	if unprotected != nil {
		for name := range unprotected {
			if _, dup := rawHeader[name]; dup {
				return fail(errs.Detail(ErrInvalidHeader, "duplicate %[1]s header | %[1]s 头部重复", name))
			}
			switch name {
			case "crit":
				return fail(errs.Detail(ErrUnsupportedCrit, "crit extension is not supported | 不支持 crit 扩展"))
			case "b64":
				return fail(errs.Detail(ErrInvalidHeader, "b64 extension is not supported | 不支持 b64 扩展"))
			}
		}
		for name, v := range unprotected {
			rawHeader[name] = v
		}
	}
	if header.Alg == "none" || !supportedJWSAlg(header.Alg) {
		return fail(errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", header.Alg))
	}
	if !algAllowed(opts.ValidAlgs, header.Alg) {
		return fail(errs.Detail(ErrAlgNotAllowed, "alg=%[1]q is outside the allow list | alg=%[1]q 不在白名单内", header.Alg))
	}
	if opts.Typ != "" && !strings.EqualFold(header.Typ, opts.Typ) {
		return fail(errs.Detail(ErrInvalidHeader, "typ=%[1]q, want %[2]q | typ=%[1]q，期望 %[2]q", header.Typ, opts.Typ))
	}

	key, err := resolver.ResolveKey(ctx, rawHeader)
	if err != nil {
		return fail(err)
	}
	if key == nil {
		return fail(errs.Detail(ErrKeyNotFound, "resolver returned nil key | 解析器返回 nil 密钥"))
	}
	if key.Alg != "" && key.Alg != header.Alg {
		return fail(errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, header.Alg))
	}
	if err := checkKeyAlg(key, header.Alg); err != nil {
		return fail(err)
	}
	if err := checkKeyUse(key, "verify"); err != nil {
		return fail(err)
	}

	sig, err := DecodeSegment(sigSeg)
	if err != nil {
		return fail(err)
	}
	unencoded := unencodedPayload(header)
	var payload []byte
	switch {
	case detached:
		payload = detachedPayload
	case unencoded:
		// RFC 7797 b64=false carries the payload verbatim, so the segment is not base64url and
		// must not be decoded. | RFC 7797 的 b64=false 原样承载载荷，因此该段不是 base64url，不得解码。
		payload = []byte(payloadSeg)
	default:
		payload, err = DecodeSegment(payloadSeg)
		if err != nil {
			return fail(err)
		}
	}
	input := make([]byte, 0, len(protectedSeg)+1+len(payloadSeg))
	input = append(input, protectedSeg...)
	input = append(input, '.')
	if unencoded {
		input = append(input, payload...)
	} else if detached {
		input = appendSegment(input, payload)
	} else {
		input = append(input, payloadSeg...)
	}
	if err := verifyJWSWithLowS(header.Alg, key, input, sig, opts.RequireLowS); err != nil {
		return fail(err)
	}
	return header, rawHeader, key, payload, sig, nil
}

// validateClaims runs ydx/auth/token/jwt registered-claim validation on a token whose signature has
// already been checked. | validateClaims 对签名已校验的令牌运行 ydx/auth/token/jwt 登记声明校验。
func validateClaims(token string, key *Key, alg string, opts VerifyOptions) error {
	pub, err := key.PublicKey()
	if err != nil {
		return err
	}
	keyFn := func(ydjwt.Header) (any, error) { return pub, nil }
	_, err = ydjwt.Parse(token, keyFn, ydjwt.ParseOptions{
		ValidAlgs:        []ydjwt.Alg{ydjwt.Alg(alg)},
		Leeway:           opts.Leeway,
		Now:              opts.Now,
		RequireExp:       opts.RequireExp,
		Issuer:           opts.Issuer,
		Issuers:          opts.Issuers,
		Audience:         opts.Audience,
		Audiences:        opts.Audiences,
		ValidateIssuedAt: opts.ValidateIssuedAt,
		RequireIssuedAt:  opts.RequireIssuedAt,
		RequireLowS:      opts.RequireLowS,
	})
	if err != nil {
		return errs.Wrap(err, ErrClaimsInvalid)
	}
	return nil
}

// validateClaimsUnencoded runs the same registered-claim validation for an RFC 7797 b64=false
// payload. The payload bytes are not a compact JWS segment, so they are wrapped in a synthetic
// compact HS256 token with an ephemeral secret and parsed with exactly the same ParseOptions; the
// random secret never leaves this function. | validateClaimsUnencoded 对 RFC 7797 b64=false 载荷
// 运行相同的登记声明校验。载荷字节不是紧凑 JWS 段，因此用临时密钥把它们包装成合成的紧凑 HS256
// 令牌，并以完全相同的 ParseOptions 解析；随机密钥不会离开本函数。
func validateClaimsUnencoded(payload []byte, opts VerifyOptions) error {
	secret, err := randomBytes(32)
	if err != nil {
		return err
	}
	token, err := ydjwt.SignJSON(payload, secret, ydjwt.HS256, ydjwt.SignOptions{})
	if err != nil {
		return errs.Wrap(err, ErrClaimsInvalid)
	}
	keyFn := func(ydjwt.Header) (any, error) { return secret, nil }
	_, err = ydjwt.Parse(token, keyFn, ydjwt.ParseOptions{
		ValidAlgs:        []ydjwt.Alg{ydjwt.HS256},
		Leeway:           opts.Leeway,
		Now:              opts.Now,
		RequireExp:       opts.RequireExp,
		Issuer:           opts.Issuer,
		Issuers:          opts.Issuers,
		Audience:         opts.Audience,
		Audiences:        opts.Audiences,
		ValidateIssuedAt: opts.ValidateIssuedAt,
		RequireIssuedAt:  opts.RequireIssuedAt,
		RequireLowS:      opts.RequireLowS,
	})
	if err != nil {
		return errs.Wrap(err, ErrClaimsInvalid)
	}
	return nil
}

// parseJWSHeader decodes and validates a protected JWS header. | parseJWSHeader 解码并校验受保护
// 的 JWS 头部。
func parseJWSHeader(raw []byte) (JWSHeader, Header, error) {
	m, err := headerJSON(raw)
	if err != nil {
		return JWSHeader{}, nil, err
	}
	alg, ok := m["alg"].(string)
	if !ok || alg == "" {
		return JWSHeader{}, nil, errs.Detail(ErrAlgNotAllowed, "header has no string alg | 头部缺少字符串 alg")
	}
	var h JWSHeader
	h.Alg = alg
	for _, f := range [...]struct {
		name string
		dst  *string
	}{
		{"kid", &h.Kid},
		{"typ", &h.Typ},
		{"cty", &h.Cty},
	} {
		if v, present := m[f.name]; present {
			s, ok := v.(string)
			if !ok {
				return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "%[1]s is not a string | %[1]s 不是字符串", f.name)
			}
			*f.dst = s
		}
	}
	hasB64 := false
	b64 := false
	if v, present := m["b64"]; present {
		bv, ok := v.(bool)
		if !ok {
			return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "b64 is not a boolean | b64 不是布尔值")
		}
		b64, hasB64 = bv, true
		h.B64 = &b64
	}
	hasCritB64 := false
	if v, present := m["crit"]; present {
		crit, ok := stringSlice(v)
		if !ok {
			return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "crit is not a string array | crit 不是字符串数组")
		}
		seen := make(map[string]struct{}, len(crit))
		for _, name := range crit {
			if _, dup := seen[name]; dup {
				return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "duplicate crit entry %[1]q | crit 条目 %[1]q 重复", name)
			}
			if name != "b64" {
				return JWSHeader{}, nil, errs.Detail(ErrUnsupportedCrit, "crit=%[1]v | crit=%[1]v", crit)
			}
			seen[name] = struct{}{}
			hasCritB64 = true
		}
		h.Crit = crit
	}
	if hasB64 && !b64 && !hasCritB64 {
		return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "b64=false requires crit=[\"b64\"] | b64=false 要求 crit=[\"b64\"]")
	}
	if hasCritB64 && !hasB64 {
		return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "crit names b64 but b64 is absent | crit 指明 b64 但 b64 缺失")
	}
	for name, v := range m {
		switch name {
		case "alg", "kid", "typ", "cty", "crit", "b64":
			continue
		}
		if h.Extra == nil {
			h.Extra = make(map[string]any, len(m))
		}
		h.Extra[name] = v
	}
	return h, Header(m), nil
}

// stringSlice converts a decoded JSON array of strings. | stringSlice 转换解码后的字符串 JSON 数组。
func stringSlice(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		if ss, ok := v.([]string); ok {
			return ss, true
		}
		return nil, false
	}
	out := make([]string, len(arr))
	for i, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// encodeJWSHeader serializes a protected header with deterministic member order. | encodeJWSHeader
// 以确定的成员顺序序列化受保护头部。
//
// The RFC 7797 b64 parameter is emitted after kid and before crit, which reproduces the protected
// header of the RFC 7797 example byte for byte. The "b64" member is added automatically for
// UnencodedPayload-style input, and crit is expanded with "b64" when b64=false. | RFC 7797 的 b64
// 参数位于 kid 之后、crit 之前，从而逐字节复现 RFC 7797 示例的受保护头部。UnencodedPayload 风格的
// 输入会自动加入 "b64" 成员，b64=false 时 crit 会自动补充 "b64"。
func encodeJWSHeader(h JWSHeader) ([]byte, error) {
	h, err := normalizeSigningJWSHeader(h)
	if err != nil {
		return nil, err
	}
	return appendJWSHeader(nil, h)
}

// normalizeSigningJWSHeader validates crit and b64 for signing and fills in their defaults. |
// normalizeSigningJWSHeader 为签名校验 crit 与 b64 并填入默认值。
//
// Only the RFC 7797 "b64" extension is understood. Duplicate crit entries are refused; b64=false
// gains a "b64" crit entry; a "b64" crit entry without an explicit b64 parameter selects b64=true. |
// 仅理解 RFC 7797 的 "b64" 扩展。重复的 crit 条目会被拒绝；b64=false 会获得 "b64" crit 条目；
// 只有 "b64" crit 条目而未显式给出 b64 参数时选择 b64=true。
func normalizeSigningJWSHeader(h JWSHeader) (JWSHeader, error) {
	if h.Alg == "" || h.Alg == "none" || !supportedJWSAlg(h.Alg) {
		return JWSHeader{}, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", h.Alg)
	}
	crit := make([]string, 0, len(h.Crit)+1)
	seen := make(map[string]struct{}, len(h.Crit))
	for _, name := range h.Crit {
		if _, dup := seen[name]; dup {
			return JWSHeader{}, errs.Detail(ErrInvalidHeader, "duplicate crit entry %[1]q | crit 条目 %[1]q 重复", name)
		}
		if name != "b64" {
			return JWSHeader{}, errs.Detail(ErrUnsupportedCrit, "crit=%[1]v | crit=%[1]v", h.Crit)
		}
		seen[name] = struct{}{}
		crit = append(crit, name)
	}
	if h.B64 == nil {
		if _, ok := seen["b64"]; ok {
			v := true
			h.B64 = &v
		}
	}
	if h.B64 != nil && !*h.B64 {
		if _, ok := seen["b64"]; !ok {
			crit = append(crit, "b64")
		}
	}
	h.Crit = crit
	return h, nil
}

// appendJWSHeader appends an already normalized protected header. | appendJWSHeader 追加已规范化的
// 受保护头部。
func appendJWSHeader(out []byte, h JWSHeader) ([]byte, error) {
	reserved := map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}, "b64": {}}
	extraKeys := make([]string, 0, len(h.Extra))
	for name := range h.Extra {
		if _, bad := reserved[name]; bad {
			return nil, errs.Detail(ErrInvalidHeader, "reserved header %[1]q | 保留头部 %[1]q", name)
		}
		extraKeys = append(extraKeys, name)
	}
	sort.Strings(extraKeys)

	out = append(out, `{"alg":`...)
	out = appendJSONString(out, h.Alg)
	if h.Typ != "" {
		out = append(out, `,"typ":`...)
		out = appendJSONString(out, h.Typ)
	}
	if h.Cty != "" {
		out = append(out, `,"cty":`...)
		out = appendJSONString(out, h.Cty)
	}
	if h.Kid != "" {
		out = append(out, `,"kid":`...)
		out = appendJSONString(out, h.Kid)
	}
	if h.B64 != nil {
		out = append(out, `,"b64":`...)
		if *h.B64 {
			out = append(out, "true"...)
		} else {
			out = append(out, "false"...)
		}
	}
	if len(h.Crit) > 0 {
		out = append(out, `,"crit":[`...)
		for i, name := range h.Crit {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendJSONString(out, name)
		}
		out = append(out, ']')
	}
	for _, name := range extraKeys {
		value, err := jsonValue(h.Extra[name])
		if err != nil {
			return nil, err
		}
		out = append(out, ',')
		out = appendJSONString(out, name)
		out = append(out, ':')
		out = append(out, value...)
	}
	return append(out, '}'), nil
}

// unencodedPayload reports whether the protected header selects RFC 7797 b64=false. | unencodedPayload
// 报告受保护头部是否选择 RFC 7797 的 b64=false。
func unencodedPayload(h JWSHeader) bool {
	return h.B64 != nil && !*h.B64
}

// appendJWSInput appends the JWS signing input: the encoded protected header, '.', and either the
// base64url payload or the raw unencoded payload. | appendJWSInput 追加 JWS 签名输入：编码后的受保护
// 头部、'.'，以及 base64url 载荷或未编码的原始载荷。
func appendJWSInput(dst, headerBytes, payload []byte, unencoded bool) []byte {
	dst = appendSegment(dst, headerBytes)
	dst = append(dst, '.')
	if unencoded {
		return append(dst, payload...)
	}
	return appendSegment(dst, payload)
}

// jsonValue encodes one header value with ydx/json. | jsonValue 使用 ydx/json 编码一个头部值。
func jsonValue(v any) ([]byte, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidHeader, "header value | 头部取值")
	}
	return out, nil
}

// supportedJWSAlg reports whether alg is a JWS algorithm implemented by this package. | supportedJWSAlg
// 报告 alg 是否为本包实现的 JWS 算法。
func supportedJWSAlg(alg string) bool {
	switch alg {
	case "HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512",
		"EdDSA":
		return true
	}
	return false
}

// algAllowed reports whether alg passes the allow list; an empty list allows everything. | algAllowed
// 报告 alg 是否通过白名单；空列表允许全部。
func algAllowed(valid []string, alg string) bool {
	if len(valid) == 0 {
		return true
	}
	for _, v := range valid {
		if v == alg {
			return true
		}
	}
	return false
}

// jwsHash returns the hash identity of a JWS algorithm. | jwsHash 返回 JWS 算法的哈希标识。
func jwsHash(alg string) (crypto.Hash, bool) {
	switch alg {
	case "HS256", "RS256", "PS256", "ES256":
		return crypto.SHA256, true
	case "HS384", "RS384", "PS384", "ES384":
		return crypto.SHA384, true
	case "HS512", "RS512", "PS512", "ES512":
		return crypto.SHA512, true
	}
	return 0, false
}

// digest returns the hash digest of data. | digest 返回 data 的哈希摘要。
func digest(h crypto.Hash, data []byte) []byte {
	d := h.New()
	_, _ = d.Write(data)
	return d.Sum(nil)
}

// signJWS signs input with key for alg. | signJWS 使用 key 按 alg 对 input 签名。
func signJWS(alg string, key *Key, input []byte) ([]byte, error) {
	return signJWSWithLowS(alg, key, input, false)
}

// signJWSWithLowS signs input for alg and optionally normalizes an ECDSA signature to low-S. |
// signJWSWithLowS 按 alg 对 input 签名，并可选地把 ECDSA 签名规范化为 low-S。
func signJWSWithLowS(alg string, key *Key, input []byte, lowS bool) ([]byte, error) {
	switch alg {
	case "EdDSA":
		raw, err := key.PrivateKey()
		if err != nil {
			return nil, err
		}
		priv, ok := raw.(ed25519.PrivateKey)
		if !ok || len(priv) != ed25519.PrivateKeySize {
			return nil, errs.Detail(ErrKeyTypeMismatch, "EdDSA needs an Ed25519 private key | EdDSA 需要 Ed25519 私钥")
		}
		return ed25519.Sign(priv, input), nil
	}
	h, ok := jwsHash(alg)
	if !ok {
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	switch alg {
	case "HS256", "HS384", "HS512":
		secret, err := key.octets()
		if err != nil {
			return nil, err
		}
		if len(secret) < h.Size() {
			return nil, errs.Detail(ErrWeakKey, "alg=%[1]s needs at least %[2]d key bytes | 算法 %[1]s 至少需要 %[2]d 字节密钥", alg, h.Size())
		}
		mac := hmac.New(h.New, secret)
		_, _ = mac.Write(input)
		return mac.Sum(nil), nil
	case "RS256", "RS384", "RS512":
		raw, err := key.PrivateKey()
		if err != nil {
			return nil, err
		}
		priv, ok := raw.(*rsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyTypeMismatch, "RSxxx needs an RSA private key | RSxxx 需要 RSA 私钥")
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, h, digest(h, input))
		if err != nil {
			return nil, errs.WrapDetail(err, ErrSignatureInvalid, "RSA signing | RSA 签名")
		}
		return sig, nil
	case "PS256", "PS384", "PS512":
		raw, err := key.PrivateKey()
		if err != nil {
			return nil, err
		}
		priv, ok := raw.(*rsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyTypeMismatch, "PSxxx needs an RSA private key | PSxxx 需要 RSA 私钥")
		}
		sig, err := rsa.SignPSS(rand.Reader, priv, h, digest(h, input), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
		if err != nil {
			return nil, errs.WrapDetail(err, ErrSignatureInvalid, "RSA-PSS signing | RSA-PSS 签名")
		}
		return sig, nil
	case "ES256", "ES384", "ES512":
		raw, err := key.PrivateKey()
		if err != nil {
			return nil, err
		}
		priv, ok := raw.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyTypeMismatch, "ESxxx needs an ECDSA private key | ESxxx 需要 ECDSA 私钥")
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest(h, input))
		if err != nil {
			return nil, errs.WrapDetail(err, ErrSignatureInvalid, "ECDSA signing | ECDSA 签名")
		}
		if lowS {
			s = toLowS(priv.Curve, s)
		}
		width := curveWidth(alg)
		out := make([]byte, 2*width)
		r.FillBytes(out[:width])
		s.FillBytes(out[width:])
		return out, nil
	}
	return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
}

// verifyJWS checks the signature of input. | verifyJWS 校验 input 的签名。
func verifyJWS(alg string, key *Key, input, sig []byte) error {
	return verifyJWSWithLowS(alg, key, input, sig, false)
}

// verifyJWSWithLowS checks the signature of input and optionally requires a canonical low-S ECDSA
// signature. | verifyJWSWithLowS 校验 input 的签名，并可选地要求规范的 low-S ECDSA 签名。
func verifyJWSWithLowS(alg string, key *Key, input, sig []byte, requireLowS bool) error {
	fail := func() error {
		return errs.Detail(ErrSignatureInvalid, "alg=%[1]q | 算法=%[1]q", alg)
	}
	switch alg {
	case "EdDSA":
		pub, err := key.PublicKey()
		if err != nil {
			return err
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok || len(edPub) != ed25519.PublicKeySize {
			return errs.Detail(ErrKeyTypeMismatch, "EdDSA needs an Ed25519 public key | EdDSA 需要 Ed25519 公钥")
		}
		if !ed25519.Verify(edPub, input, sig) {
			return fail()
		}
		return nil
	}
	h, ok := jwsHash(alg)
	if !ok {
		return errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	switch alg {
	case "HS256", "HS384", "HS512":
		secret, err := key.octets()
		if err != nil {
			return err
		}
		if len(secret) < h.Size() {
			return errs.Detail(ErrWeakKey, "alg=%[1]s needs at least %[2]d key bytes | 算法 %[1]s 至少需要 %[2]d 字节密钥", alg, h.Size())
		}
		mac := hmac.New(h.New, secret)
		_, _ = mac.Write(input)
		if !hmac.Equal(mac.Sum(nil), sig) {
			return fail()
		}
		return nil
	case "RS256", "RS384", "RS512":
		pub, err := key.PublicKey()
		if err != nil {
			return err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyTypeMismatch, "RSxxx needs an RSA public key | RSxxx 需要 RSA 公钥")
		}
		if rsa.VerifyPKCS1v15(rsaPub, h, digest(h, input), sig) != nil {
			return fail()
		}
		return nil
	case "PS256", "PS384", "PS512":
		pub, err := key.PublicKey()
		if err != nil {
			return err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyTypeMismatch, "PSxxx needs an RSA public key | PSxxx 需要 RSA 公钥")
		}
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		if rsa.VerifyPSS(rsaPub, h, digest(h, input), sig, opts) != nil {
			return fail()
		}
		return nil
	case "ES256", "ES384", "ES512":
		pub, err := key.PublicKey()
		if err != nil {
			return err
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyTypeMismatch, "ESxxx needs an ECDSA public key | ESxxx 需要 ECDSA 公钥")
		}
		width := curveWidth(alg)
		if len(sig) != 2*width {
			return fail()
		}
		if requireLowS && !isLowS(ecPub.Curve, sig[width:]) {
			return fail()
		}
		// JWS carries the fixed-width r||s form while the standard library verifies DER, so the
		// signature is converted on the stack instead of through math/big. | JWS 使用定宽 r||s 形式，
		// 而标准库校验 DER，因此在栈上完成转换而不再经过 math/big。
		if !ecdsa.VerifyASN1(ecPub, digest(h, input), esSignatureDER(sig, width)) {
			return fail()
		}
		return nil
	}
	return errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
}

// toLowS returns the canonical low-S form of an ECDSA signature scalar, replacing s with N-s when s
// lies in the upper half of the group order. | toLowS 返回 ECDSA 签名标量的规范 low-S 形式；s 位于
// 群阶上半区时用 N-s 替换。
func toLowS(curve elliptic.Curve, s *big.Int) *big.Int {
	n := curve.Params().N
	half := new(big.Int).Rsh(n, 1)
	if s.Cmp(half) > 0 {
		return new(big.Int).Sub(n, s)
	}
	return s
}

// isLowS reports whether the big-endian scalar s is in the canonical low-S range 1 <= s <= N/2. |
// isLowS 报告大端标量 s 是否位于规范 low-S 范围 1 <= s <= N/2 内。
func isLowS(curve elliptic.Curve, s []byte) bool {
	v := new(big.Int).SetBytes(s)
	if v.Sign() <= 0 {
		return false
	}
	half := new(big.Int).Rsh(curve.Params().N, 1)
	return v.Cmp(half) <= 0
}

// curveWidth returns the byte width of one ECDSA signature half. | curveWidth 返回 ECDSA 签名半值
// 的字节宽度。
func curveWidth(alg string) int {
	switch alg {
	case "ES256":
		return 32
	case "ES384":
		return 48
	case "ES512":
		return 66
	}
	return 0
}

// esSignatureDER converts the fixed-width r||s form of a JWS ECDSA signature into ASN.1 DER. |
// esSignatureDER 把 JWS 的定宽 r||s 形式 ECDSA 签名转换为 ASN.1 DER。
//
// Both buffers are sized for the largest supported curve (P-521: two 67-byte integers including the
// sign pad, plus tags and lengths), so the conversion does not grow an allocation. | 两个缓冲区都按
// 最大支持曲线定容（P-521：两个含符号填充的 67 字节整数，再加标签与长度），因此转换无需扩容分配。
func esSignatureDER(sig []byte, width int) []byte {
	var body [144]byte
	b := body[:0]
	b = appendDERInteger(b, sig[:width])
	b = appendDERInteger(b, sig[width:])
	var out [147]byte
	if len(b) < 128 {
		out[0] = 0x30
		out[1] = byte(len(b))
		copy(out[2:], b)
		return out[:2+len(b)]
	}
	out[0] = 0x30
	out[1] = 0x81
	out[2] = byte(len(b))
	copy(out[3:], b)
	return out[:3+len(b)]
}

// appendDERInteger appends a minimally encoded ASN.1 INTEGER holding the unsigned big-endian value.
// | appendDERInteger 追加一个保存无符号大端值的最小 ASN.1 INTEGER 编码。
func appendDERInteger(dst, value []byte) []byte {
	for len(value) > 1 && value[0] == 0 {
		value = value[1:]
	}
	if len(value) == 0 {
		value = []byte{0}
	}
	if value[0]&0x80 != 0 {
		dst = append(dst, 0x02, byte(len(value)+1), 0x00)
		return append(dst, value...)
	}
	dst = append(dst, 0x02, byte(len(value)))
	return append(dst, value...)
}
