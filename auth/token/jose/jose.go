// Package jose implements the JSON Object Signing and Encryption toolkit used by the OAuth 2.0
// and OpenID Connect servers: JWK and JWKS handling, compact and JSON-serialized JWS and JWE,
// and the HTTP helpers needed to publish and consume a key set. JWS supports the compact,
// flattened JSON and general JSON serializations, multiple signatures, detached payloads (RFC
// 7515 Appendix F) and unencoded payloads (RFC 7797); JWE supports the compact, flattened JSON
// and general JSON serializations, extra authenticated data, compression and multiple
// recipients. | Package jose 实现 OAuth 2.0 与 OpenID Connect 服务端使用的 JSON 对象签名与
// 加密工具集：JWK 与 JWKS 处理、紧凑与 JSON 序列化的 JWS 与 JWE，以及发布与读取密钥集所需的
// HTTP 辅助能力。JWS 支持紧凑、扁平 JSON 与通用 JSON 序列化、多签名、分离载荷（RFC 7515
// 附录 F）与未编码载荷（RFC 7797）；JWE 支持紧凑、扁平 JSON 与通用 JSON 序列化、附加认证
// 数据、压缩与多接收方。
//
// The package keeps the wire formats independent from ydx/router so that oidc, oauth2 and
// external resource servers can share one implementation. Handlers are plain http.Handler
// values and can be mounted on ydx/router with router.HandleRaw or used directly with
// net/http. | 本包使线格式独立于 ydx/router，因此 oidc、oauth2 与外部资源服务器可以共享同一套
// 实现。处理器是普通的 http.Handler，可通过 router.HandleRaw 挂载到 ydx/router，也可直接用于
// net/http。
//
// Security posture | 安全定位：
//
//   - "alg":"none" is never accepted by any entry point. | 任何入口都不接受 "alg":"none"。
//   - A key whose family does not match the header algorithm is refused, which closes
//     algorithm-confusion attacks in both directions. | 密钥族与头部算法不符时一律拒绝，从而
//     双向封堵算法混淆攻击。
//   - Critical header extensions are rejected except for RFC 7797 "b64" on JWS, the only
//     extension this implementation understands; JWE understands none. | 关键头部扩展一律拒绝，
//     JWS 仅理解 RFC 7797 的 "b64"，JWE 不理解任何扩展。
//   - Token headers with duplicate member names are refused before decoding, so two parsers can
//     never disagree about which value is authoritative. | 成员名重复的令牌头部在解码前即被拒绝，
//     因此任何两个解析器都不可能对哪个取值生效产生分歧。
//   - KeySet.Handler omits symmetric "oct" keys, because publishing "k" would disclose the secret;
//     enabling IncludeSymmetricKeys is reserved for trusted internal distribution. |
//     KeySet.Handler 会省略对称 "oct" 密钥，因为发布 "k" 会泄露密钥；IncludeSymmetricKeys 仅供
//     可信内部发布使用。
//   - Verify and Decrypt reject inputs above DefaultMaxTokenSize before decoding, so a hostile
//     caller cannot force unbounded allocation; large payloads raise MaxTokenSize explicitly. |
//     Verify 与 Decrypt 在解码前拒绝超过 DefaultMaxTokenSize 的输入，恶意调用方无法强制无界分配；
//     大载荷场景需显式调高 MaxTokenSize。
//
// # Example | 示例
//
//	key, _ := jose.GenerateKey("ES256", 0)
//	token, _ := jose.Sign([]byte(`{"sub":"alice"}`), key, jose.SignOptions{Typ: "JWT"})
//	resolver := jose.KeySetResolver(&jose.KeySet{Keys: []*jose.Key{key.Public()}})
//	verified, _ := jose.Verify(token, resolver, jose.VerifyOptions{ValidAlgs: []string{"ES256"}})
//	// verified.Claims holds the raw JSON payload. | verified.Claims 保存原始 JSON 载荷。
package jose

import (
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// The declared sentinels of this package. | 本包的哨兵错误声明。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers
// can classify failures with errors.Is instead of matching message text. | 所有失败路径都直接返回
// 其中之一，或经由 errs.Detail / errs.Wrap 包装，因此调用方可用 errors.Is 分类失败，而无需
// 匹配文案。
var (
	// ErrInvalidKey reports a JWK with missing, malformed or contradictory members. | ErrInvalidKey 表示 JWK 成员缺失、格式非法或互相矛盾。
	ErrInvalidKey = errs.New("jose: invalid key | jose：密钥非法")
	// ErrNotPrivateKey reports an operation that needs private key material on a public-only key. | ErrNotPrivateKey 表示在仅含公钥的密钥上执行需要私钥的操作。
	ErrNotPrivateKey = errs.New("jose: key has no private material | jose：密钥不含私钥材料")
	// ErrKeyNotFound reports a key set lookup that matched no key. | ErrKeyNotFound 表示密钥集查找未命中任何密钥。
	ErrKeyNotFound = errs.New("jose: key not found | jose：密钥不存在")
	// ErrDuplicateKey reports a key set with two keys carrying the same non-empty kid. | ErrDuplicateKey 表示密钥集中存在两个 kid 相同且非空的密钥。
	ErrDuplicateKey = errs.New("jose: duplicate key identifier | jose：密钥标识重复")
	// ErrMalformed reports a token that is not a well-formed compact JWS, compact JWE or JWS or
	// JWE JSON serialization. | ErrMalformed 表示令牌不是结构良好的紧凑 JWS、紧凑 JWE 或
	// JWS/JWE JSON 序列化。
	ErrMalformed = errs.New("jose: malformed token | jose：令牌格式非法")
	// ErrSignatureInvalid reports a signature that did not verify. | ErrSignatureInvalid 表示签名校验未通过。
	ErrSignatureInvalid = errs.New("jose: invalid signature | jose：签名校验失败")
	// ErrAlgNotAllowed reports an alg header that is unsupported, unknown or outside the allow list. | ErrAlgNotAllowed 表示 alg 头部不受支持、未知或不在白名单内。
	ErrAlgNotAllowed = errs.New("jose: algorithm not allowed | jose：算法不被允许")
	// ErrKeyTypeMismatch reports a key family that does not match the algorithm. | ErrKeyTypeMismatch 表示密钥族与算法不匹配。
	ErrKeyTypeMismatch = errs.New("jose: key type does not match algorithm | jose：密钥类型与算法不匹配")
	// ErrWeakKey reports an HMAC secret shorter than the algorithm hash output, a symmetric key of
	// the wrong size, or an RSA key whose modulus is smaller than 2048 bits. | ErrWeakKey 表示
	// HMAC 密钥短于算法哈希输出、对称密钥长度不符，或 RSA 密钥模数小于 2048 位。
	ErrWeakKey = errs.New("jose: key is too weak | jose：密钥过弱")
	// ErrUnsupportedCrit reports a critical extension this implementation does not understand.
	// JWS understands "b64"; JWE understands none. | ErrUnsupportedCrit 表示本实现不理解的
	// 关键扩展。JWS 理解 "b64"，JWE 不理解任何扩展。
	ErrUnsupportedCrit = errs.New("jose: unsupported critical header | jose：不支持的关键头部")
	// ErrInvalidHeader reports a structurally invalid or ambiguous JOSE header. | ErrInvalidHeader 表示 JOSE 头部结构非法或存在歧义。
	ErrInvalidHeader = errs.New("jose: invalid header | jose：头部非法")
	// ErrDecryptionFailed reports a JWE that could not be authenticated or decrypted. | ErrDecryptionFailed 表示 JWE 无法通过认证或解密。
	ErrDecryptionFailed = errs.New("jose: decryption failed | jose：解密失败")
	// ErrUnsupportedEnc reports an unsupported JWE enc value. | ErrUnsupportedEnc 表示不受支持的 JWE enc 取值。
	ErrUnsupportedEnc = errs.New("jose: encryption algorithm not supported | jose：加密算法不受支持")
	// ErrInvalidConfig reports a missing or contradictory option or HTTP endpoint. | ErrInvalidConfig 表示选项或 HTTP 端点缺失或互相矛盾。
	ErrInvalidConfig = errs.New("jose: invalid configuration | jose：配置非法")
	// ErrResponseTooLarge reports an HTTP body that exceeded the configured limit. | ErrResponseTooLarge 表示 HTTP 正文超过配置上限。
	ErrResponseTooLarge = errs.New("jose: response body exceeds limit | jose：响应体超过限制")
	// ErrFetchFailed reports a failed JWKS HTTP exchange. | ErrFetchFailed 表示 JWKS HTTP 交互失败。
	ErrFetchFailed = errs.New("jose: key set fetch failed | jose：密钥集获取失败")
	// ErrClaimsInvalid reports a payload that failed the optional JWT claim validation. | ErrClaimsInvalid 表示载荷未通过可选的 JWT 声明校验。
	ErrClaimsInvalid = errs.New("jose: invalid claims | jose：声明无效")
	// ErrDecompressionLimit reports a DEF-compressed JWE whose plaintext exceeded the limit. | ErrDecompressionLimit 表示 DEF 压缩 JWE 的解压后明文超过上限。
	ErrDecompressionLimit = errs.New("jose: decompressed size exceeds limit | jose：解压后大小超过上限")
	// ErrTokenTooLarge reports a JWS or JWE whose input length exceeds the configured limit. |
	// ErrTokenTooLarge 表示 JWS 或 JWE 的输入长度超过配置上限。
	ErrTokenTooLarge = errs.New("jose: token exceeds size limit | jose：令牌超过大小上限")
)

// maxHeaderBytes bounds a decoded JOSE header; any legitimate header is far smaller. | maxHeaderBytes
// 限制解码后的 JOSE 头部大小；任何合法头部都远小于该值。
const maxHeaderBytes = 64 << 10

// DefaultMaxTokenSize is the default input limit in bytes for Verify and Decrypt. It accepts
// ordinary JWT and JWE tokens while bounding the memory a hostile caller can make the process
// allocate; raise VerifyOptions.MaxTokenSize or DecryptOptions.MaxTokenSize for large payloads. |
// DefaultMaxTokenSize 是 Verify 与 Decrypt 的默认输入上限（字节）。它能容纳常见的 JWT 与 JWE，
// 同时限制恶意调用方让进程分配的内存；大载荷场景请调高 VerifyOptions.MaxTokenSize 或
// DecryptOptions.MaxTokenSize。
const DefaultMaxTokenSize = 1 << 20

// tokenSizeLimit resolves a configured input limit; non-positive values select the default. |
// tokenSizeLimit 解析配置的输入上限；非正值选择默认上限。
func tokenSizeLimit(configured int) int {
	if configured <= 0 {
		return DefaultMaxTokenSize
	}
	return configured
}

// checkTokenSize rejects a token longer than the resolved input limit. | checkTokenSize 拒绝超过
// 解析后输入上限的令牌。
func checkTokenSize(token string, configured int) error {
	limit := tokenSizeLimit(configured)
	if len(token) > limit {
		return errs.Detail(ErrTokenTooLarge, "token is %[1]d bytes, limit is %[2]d | 令牌为 %[1]d 字节，上限为 %[2]d 字节", len(token), limit)
	}
	return nil
}

// strictRawURLEncoding is the canonical unpadded base64url codec. RFC 7515 §2 requires the pad bits
// to be zero; the tolerant default would accept several spellings of the same segment bytes. |
// strictRawURLEncoding 是规范的无填充 base64url 编解码器。RFC 7515 §2 要求填充位为零；宽容的默认
// 解码会接受同一段字节的多种拼写。
var strictRawURLEncoding = base64.RawURLEncoding.Strict()

// EncodeSegment encodes src with unpadded base64url, the JOSE segment encoding. | EncodeSegment
// 使用 JOSE 段编码，即无填充 base64url，对 src 进行编码。
func EncodeSegment(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
}

// DecodeSegment decodes an unpadded base64url JOSE segment. | DecodeSegment 解码无填充 base64url
// 的 JOSE 段。
//
// Padding characters and non-zero trailing pad bits are rejected: RFC 7515 mandates the canonical
// unpadded encoding, and accepting aliases would give one token several encodings. | 填充字符与
// 非零尾部填充位都会被拒绝：RFC 7515 规定使用规范的无填充编码，接受别名会使同一 token 出现多种
// 编码。
func DecodeSegment(seg string) ([]byte, error) {
	out, err := strictRawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrMalformed, "segment is not base64url | 段不是 base64url")
	}
	return out, nil
}

// appendSegment appends the unpadded base64url encoding of src to dst. | appendSegment 把 src 的
// 无填充 base64url 编码追加到 dst。
func appendSegment(dst, src []byte) []byte {
	return base64.RawURLEncoding.AppendEncode(dst, src)
}

// unmarshal decodes JSON through ydx/json. | unmarshal 通过 ydx/json 解码 JSON。
//
// The copy that older code made for inputs whose last eight bytes contain a quote has been
// removed: ydx/json v0.1.17 fixed the parseCleanString arena-offset bug that copy worked around,
// and this module pins v0.1.18. | 旧代码会在最后八字节含双引号时复制输入并追加空格，这一复制已被
// 移除：ydx/json v0.1.17 修复了该复制所规避的 parseCleanString arena 偏移缺陷，本模块锁定
// v0.1.18。
func unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// Header is a decoded JOSE header as a generic parameter map. | Header 是以通用参数映射表示的
// 解码后 JOSE 头部。
//
// It is handed to KeyResolver so a resolver can inspect any header parameter, including
// application-defined ones, before choosing a key. | 它会被交给 KeyResolver，使解析器在选择密钥
// 之前可以检查任意头部参数，包括应用自定义参数。
type Header map[string]any

// String returns the string value of the named parameter, or "" when it is absent or not a
// string. | String 返回指定参数的字符串值；参数缺失或不是字符串时返回 ""。
func (h Header) String(name string) string {
	v, _ := h[name].(string)
	return v
}

// Has reports whether the named parameter is present. | Has 报告指定参数是否存在。
func (h Header) Has(name string) bool {
	_, ok := h[name]
	return ok
}

// appendJSONString appends s as a JSON string literal, escaping control characters and quotes and
// replacing invalid UTF-8 bytes with U+FFFD, matching encoding/json's replacement rule. | appendJSONString
// 把 s 作为 JSON 字符串字面量追加，转义控制字符与引号，并把非法 UTF-8 字节替换为 U+FFFD，
// 与 encoding/json 的替换规则一致。
func appendJSONString(dst []byte, s string) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			switch c {
			case '"', '\\':
				dst = append(dst, '\\', c)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				if c < 0x20 {
					dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0x0f])
				} else {
					dst = append(dst, c)
				}
			}
			i++
			continue
		}
		r, size := decodeRune(s[i:])
		if r == '�' && size == 1 {
			dst = append(dst, "�"...)
			i++
			continue
		}
		dst = append(dst, s[i:i+size]...)
		i += size
	}
	return append(dst, '"')
}

// decodeRune decodes one UTF-8 rune from s. | decodeRune 从 s 解码一个 UTF-8 字符。
func decodeRune(s string) (rune, int) {
	if len(s) == 0 {
		return 0, 0
	}
	b := s[0]
	switch {
	case b < 0x80:
		return rune(b), 1
	case b < 0xC0:
		return '�', 1
	case b < 0xE0:
		if len(s) < 2 || s[1]&0xC0 != 0x80 {
			return '�', 1
		}
		return rune(b&0x1F)<<6 | rune(s[1]&0x3F), 2
	case b < 0xF0:
		if len(s) < 3 || s[1]&0xC0 != 0x80 || s[2]&0xC0 != 0x80 {
			return '�', 1
		}
		r := rune(b&0x0F)<<12 | rune(s[1]&0x3F)<<6 | rune(s[2]&0x3F)
		if r < 0x800 {
			return '�', 1
		}
		return r, 3
	default:
		if len(s) < 4 || s[1]&0xC0 != 0x80 || s[2]&0xC0 != 0x80 || s[3]&0xC0 != 0x80 {
			return '�', 1
		}
		r := rune(b&0x07)<<18 | rune(s[1]&0x3F)<<12 | rune(s[2]&0x3F)<<6 | rune(s[3]&0x3F)
		if r < 0x10000 || r > 0x10FFFF {
			return '�', 1
		}
		return r, 4
	}
}

// isJSONObject reports whether raw is a single well-formed JSON object. | isJSONObject 报告 raw
// 是否为单个结构良好的 JSON 对象。
func isJSONObject(raw []byte) bool {
	i := 0
	for i < len(raw) {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			i++
			continue
		}
		break
	}
	if i >= len(raw) || raw[i] != '{' {
		return false
	}
	return json.Valid(raw)
}

// headerJSON validates raw as a JSON object without duplicate member names at any nesting level
// and returns its decoded form. | headerJSON 校验 raw 是否为任意层级都不含重复成员名的 JSON
// 对象，并返回其解码结果。
func headerJSON(raw []byte) (map[string]any, error) {
	if len(raw) > maxHeaderBytes {
		return nil, errs.Detail(ErrInvalidHeader, "header exceeds %[1]d bytes | 头部超过 %[1]d 字节", maxHeaderBytes)
	}
	if m, ok := stringHeaderJSON(raw); ok {
		return m, nil
	}
	if !isJSONObject(raw) {
		return nil, errs.Detail(ErrInvalidHeader, "header is not a JSON object | 头部不是 JSON 对象")
	}
	if hasDuplicateKeys(raw) {
		return nil, errs.Detail(ErrInvalidHeader, "header has duplicate members | 头部存在重复成员")
	}
	var m map[string]any
	if err := unmarshal(raw, &m); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidHeader, "header decode | 头部解码")
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// stringHeaderJSON parses the common header shape — a flat JSON object whose member values are all
// escape-free printable ASCII strings — without reflection or a generic JSON decode. | stringHeaderJSON
// 解析常见的头部形态 —— 成员值全部是无转义可打印 ASCII 字符串的扁平 JSON 对象 —— 无需反射或通用
// JSON 解码。
//
// ok is false when raw is not exactly that shape, including duplicate members, non-ASCII bytes,
// escapes and non-string values; the caller then falls back to the strict generic decoder, which
// performs the full validation and reports the error. | raw 不完全符合该形态时（包括重复成员、非
// ASCII 字节、转义与非字符串值）ok 为 false，调用方随后回退到执行完整校验并报告错误的严格通用解码器。
func stringHeaderJSON(raw []byte) (map[string]any, bool) {
	i := skipSpace(raw, 0)
	if i >= len(raw) || raw[i] != '{' {
		return nil, false
	}
	i++
	m := make(map[string]any, 8)
	i = skipSpace(raw, i)
	if i < len(raw) && raw[i] == '}' {
		i++
		if skipSpace(raw, i) != len(raw) {
			return nil, false
		}
		return m, true
	}
	for {
		i = skipSpace(raw, i)
		if i >= len(raw) || raw[i] != '"' {
			return nil, false
		}
		keyStart := i + 1
		keyEnd, ok := scanCleanASCIIString(raw, i)
		if !ok {
			return nil, false
		}
		key := string(raw[keyStart : keyEnd-1])
		i = skipSpace(raw, keyEnd)
		if i >= len(raw) || raw[i] != ':' {
			return nil, false
		}
		i = skipSpace(raw, i+1)
		if i >= len(raw) || raw[i] != '"' {
			return nil, false
		}
		valStart := i + 1
		valEnd, ok := scanCleanASCIIString(raw, i)
		if !ok {
			return nil, false
		}
		if _, dup := m[key]; dup {
			return nil, false
		}
		m[key] = string(raw[valStart : valEnd-1])
		i = skipSpace(raw, valEnd)
		if i >= len(raw) {
			return nil, false
		}
		if raw[i] == '}' {
			i++
			break
		}
		if raw[i] != ',' {
			return nil, false
		}
		i++
	}
	if skipSpace(raw, i) != len(raw) {
		return nil, false
	}
	return m, true
}

// scanCleanASCIIString returns the index just past the closing quote of an escape-free printable
// ASCII string starting at i. | scanCleanASCIIString 返回 i 处起始的无转义可打印 ASCII 字符串闭合
// 引号之后的下标。
func scanCleanASCIIString(raw []byte, i int) (int, bool) {
	if i >= len(raw) || raw[i] != '"' {
		return 0, false
	}
	for i++; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '"':
			return i + 1, true
		case c < 0x20 || c == '\\' || c >= 0x80:
			return 0, false
		}
	}
	return 0, false
}

// hasDuplicateKeys reports whether any JSON object nested in raw repeats a member name. | hasDuplicateKeys
// 报告 raw 中任意 JSON 对象是否重复出现成员名。
func hasDuplicateKeys(raw []byte) bool {
	i := skipSpace(raw, 0)
	_, ok, dup := scanJSONValue(raw, i, 0)
	return ok && dup
}

// skipSpace returns the index of the first non-whitespace byte at or after i. | skipSpace 返回 i
// 之后第一个非空白字节的下标。
func skipSpace(raw []byte, i int) int {
	for i < len(raw) {
		switch raw[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

// scanJSONValue scans one JSON value starting at i. | scanJSONValue 从 i 开始扫描一个 JSON 值。
//
// It returns the index just past the value, whether scanning succeeded, and whether a duplicate
// object member was seen. Nesting deeper than 64 levels is rejected so a hostile header cannot
// drive unbounded recursion. | 它返回值的结束下标、扫描是否成功，以及是否见到重复的对象成员。
// 超过 64 层的嵌套会被拒绝，使恶意头部无法驱动无界递归。
func scanJSONValue(raw []byte, i, depth int) (next int, ok, dup bool) {
	if depth > 64 {
		return 0, false, false
	}
	i = skipSpace(raw, i)
	if i >= len(raw) {
		return 0, false, false
	}
	switch raw[i] {
	case '{':
		return scanJSONObject(raw, i+1, depth+1)
	case '[':
		return scanJSONArray(raw, i+1, depth+1)
	case '"':
		end, sok := scanJSONString(raw, i)
		return end, sok, false
	case 't', 'f', 'n':
		for _, lit := range []string{"true", "false", "null"} {
			if len(raw)-i >= len(lit) && string(raw[i:i+len(lit)]) == lit {
				return i + len(lit), true, false
			}
		}
		return 0, false, false
	default:
		return scanJSONNumber(raw, i)
	}
}

// scanJSONObject scans the body of an object after its opening brace. | scanJSONObject 扫描对象
// 开括号之后的主体。
func scanJSONObject(raw []byte, i, depth int) (next int, ok, dup bool) {
	seen := make(map[string]struct{})
	for {
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return 0, false, false
		}
		if raw[i] == '}' {
			return i + 1, true, false
		}
		if raw[i] != '"' {
			return 0, false, false
		}
		keyEnd, sok := scanJSONString(raw, i)
		if !sok {
			return 0, false, false
		}
		var key string
		if err := unmarshal(raw[i:keyEnd], &key); err != nil {
			return 0, false, false
		}
		if _, exists := seen[key]; exists {
			dup = true
		}
		seen[key] = struct{}{}
		i = skipSpace(raw, keyEnd)
		if i >= len(raw) || raw[i] != ':' {
			return 0, false, false
		}
		var vdup bool
		i, ok, vdup = scanJSONValue(raw, i+1, depth)
		if !ok {
			return 0, false, false
		}
		dup = dup || vdup
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return 0, false, false
		}
		switch raw[i] {
		case ',':
			i++
		case '}':
			return i + 1, true, dup
		default:
			return 0, false, false
		}
	}
}

// scanJSONArray scans the body of an array after its opening bracket. | scanJSONArray 扫描数组
// 开括号之后的主体。
func scanJSONArray(raw []byte, i, depth int) (next int, ok, dup bool) {
	for {
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return 0, false, false
		}
		if raw[i] == ']' {
			return i + 1, true, false
		}
		var vdup bool
		i, ok, vdup = scanJSONValue(raw, i, depth)
		if !ok {
			return 0, false, false
		}
		dup = dup || vdup
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return 0, false, false
		}
		switch raw[i] {
		case ',':
			i++
		case ']':
			return i + 1, true, dup
		default:
			return 0, false, false
		}
	}
}

// scanJSONString returns the index just past the closing quote of the string at i. | scanJSONString
// 返回 i 处字符串闭合引号之后的下标。
func scanJSONString(raw []byte, i int) (int, bool) {
	if i >= len(raw) || raw[i] != '"' {
		return 0, false
	}
	for i++; i < len(raw); i++ {
		switch raw[i] {
		case '\\':
			i++
		case '"':
			return i + 1, true
		}
	}
	return 0, false
}

// scanJSONNumber returns the index just past the number at i. | scanJSONNumber 返回 i 处数字之后
// 的下标。
func scanJSONNumber(raw []byte, i int) (int, bool, bool) {
	start := i
	for i < len(raw) {
		switch raw[i] {
		case '-', '+', '.', 'e', 'E', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			i++
		default:
			return i, i > start, false
		}
	}
	return i, i > start, false
}
