package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"sort"
	"sync"
	"unicode/utf8"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// This file holds the signing and verification core. | 本文件是签发与校验的核心。
//
// Two rules shape it. First, the signature is always computed on the raw signing input, i.e. the exact
// "header.payload" ASCII bytes of the compact serialization, never on a re-encoded or re-serialized form.
// Second, every intermediate buffer comes from a sync.Pool, so a steady-state Parse or Sign performs no
// buffer allocation at all. | 两条规则贯穿全文：其一，签名始终在原始 signing input 上计算，
// 即紧凑序列化中 "header.payload" 的原始 ASCII 字节，绝不基于重新编码或重新序列化的形式；
// 其二，所有中间缓冲都来自 sync.Pool，因此稳态下 Parse 与 Sign 不产生任何缓冲分配。

// scratch holds the reusable buffers of one Parse or Sign call. | scratch 保存一次 Parse 或 Sign 调用中的可复用缓冲。
//
// A scratch never outlives the call that borrowed it, and never leaks into a Token, so returning it to the
// pool cannot hand out bytes that a caller still references. | scratch 的生命周期不超过借用它的那次调用，
// 也绝不会泄漏进 Token，因此归还池中不会把调用方仍在引用的字节再次分发出去。
type scratch struct {
	header  []byte // decoded JOSE header | 解码后的 JOSE 头部
	payload []byte // decoded payload | 解码后的载荷
	sig     []byte // decoded signature | 解码后的签名
	input   []byte // signing input: the bytes the signature covers | 签名输入：签名所覆盖的字节
	mac     []byte // hash and MAC output space | 哈希与 MAC 的输出空间
}

// scratchPool recycles *scratch values; pooling the pointer instead of the slices keeps the pool free of
// interface-boxing allocations. | scratchPool 回收 *scratch；池化指针而非切片，可避免接口装箱带来的分配。
var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

// getScratch borrows a scratch and resets its slice lengths. | getScratch 借出一个 scratch 并把切片长度归零。
func getScratch() *scratch {
	s := scratchPool.Get().(*scratch)
	s.header, s.payload, s.sig, s.input, s.mac =
		s.header[:0], s.payload[:0], s.sig[:0], s.input[:0], s.mac[:0]
	return s
}

// putScratch returns a scratch to the pool, dropping oversized buffers under the same
// retention limit Token.Release uses so one huge token cannot pin memory in the pool.
// | putScratch 把 scratch 归还池中；与 Token.Release 使用同一保留上限丢弃超大缓冲，
// 使单个巨型 token 无法把内存长期钉在池里。
func putScratch(s *scratch) {
	if cap(s.header) > tokenDataRetainLimit || cap(s.payload) > tokenDataRetainLimit ||
		cap(s.sig) > tokenDataRetainLimit || cap(s.input) > tokenDataRetainLimit ||
		cap(s.mac) > tokenDataRetainLimit {
		return
	}
	scratchPool.Put(s)
}

// strictRawURLEncoding is the canonical unpadded base64url codec. RFC 7515 §2 requires the pad bits
// to be zero; the tolerant default would accept several spellings of the same segment bytes. |
// strictRawURLEncoding 是规范的无填充 base64url 编解码器。RFC 7515 §2 要求填充位为零；宽容的默认
// 解码会接受同一段字节的多种拼写。
var strictRawURLEncoding = base64.RawURLEncoding.Strict()

// decodeSegment base64url-decodes seg into dst without allocating an intermediate
// text buffer: AppendDecodeString reads the string directly. | decodeSegment 把 seg
// 以 base64url 解码到 dst，且不分配中间文本缓冲：AppendDecodeString 直接读取字符串。
func decodeSegment(s *scratch, dst *[]byte, seg string) bool {
	out, err := strictRawURLEncoding.AppendDecodeString((*dst)[:0], seg)
	if err != nil {
		return false
	}
	*dst = out
	return true
}

// headerFields holds the raw values located in the JOSE header. | headerFields 保存从 JOSE 头部中定位到的原始取值。
type headerFields struct {
	extra                  map[string]string
	alg                    Alg
	algRaw, kidRaw, typRaw []byte
	haveAlg                bool
}

// scanHeader scans the decoded JOSE header for alg, typ and kid. | scanHeader 从解码后的 JOSE 头部中扫描 alg、typ 与 kid。
//
// The typ and kid values are returned as raw slices so the caller can copy them into token-owned
// storage instead of allocating a string here. Every other string-valued parameter lands in extra;
// extra stays nil when there is none. The reserved parameters can never be smuggled into extra, so a
// caller that reads it cannot be fooled by a duplicate of a reserved name. | typ 与 kid 以原始切片
// 返回，调用方可以把它们复制进 token 自有存储，而不必在此分配字符串。其余取值为字符串的参数进入
// extra；没有时 extra 保持 nil。保留参数绝不会被塞进 extra，因此读取 extra 的调用方不会被保留名
// 的重复项误导。
func scanHeader(raw []byte, f *headerFields) error {
	var s scanner
	if !s.init(raw) {
		return errs.Detail(ErrMalformed, "header is not a JSON object | 头部不是 JSON 对象")
	}
	// RFC 7515 §4 requires JOSE header member names to be unique. Duplicate members are rejected
	// instead of resolved last-wins, because two parsers on the same token could otherwise disagree
	// about alg or kid. | RFC 7515 §4 要求 JOSE 头部成员名唯一。重复成员一律拒绝，而不是后者覆盖
	// 前者，否则同一 token 在两个解析器中可能得到不同的 alg 或 kid。
	seen := 0
	for s.next() {
		switch headerParam(s.key) {
		case headerParamAlg:
			if seen&1 != 0 {
				return errs.Detail(ErrMalformed, "duplicate alg header | alg 头部重复")
			}
			seen |= 1
			f.algRaw, f.haveAlg = s.val, true
		case headerParamTyp:
			if seen&2 != 0 {
				return errs.Detail(ErrMalformed, "duplicate typ header | typ 头部重复")
			}
			seen |= 2
			f.typRaw = s.val
		case headerParamKid:
			if seen&4 != 0 {
				return errs.Detail(ErrMalformed, "duplicate kid header | kid 头部重复")
			}
			seen |= 4
			f.kidRaw = s.val
		default:
			// RFC 7515 §4.1.11 requires a recipient that does not understand a "crit" extension to
			// reject the token. This implementation supports none, so any crit header fails closed.
			// | RFC 7515 §4.1.11 要求接收方不理解 "crit" 扩展时必须拒绝令牌。本实现不支持任何扩展，
			// 因此任何 crit 头部都失败关闭。
			// Compare the decoded name, not the raw bytes: a member name that JSON-decodes to "crit"
			// (for example an ASCII letter spelled with a Unicode escape) is the crit parameter under
			// RFC 7515 §4, and a byte comparison would let that spelling bypass the fail-closed check. |
			// 比较解码后的名字而不是原始字节：JSON 解码后等于 "crit" 的成员名（例如用 Unicode 转义
			// 拼出的 ASCII 字母）就是 RFC 7515 §4 的 crit 参数，逐字节比较会让这种拼写绕过失败关闭检查。
			if keyMatches(s.key, "crit") {
				return errs.Detail(ErrMalformed, "unsupported crit header | 不支持 crit 头部")
			}
			// RFC 7797 unencoded payloads are not implemented. Accepting b64=false would change the
			// signing input without implementing its rules, so the parameter is refused outright. |
			// 本实现不支持 RFC 7797 的无编码载荷。接受 b64=false 会在未实现其规则的情况下改变签名
			// 输入，因此该参数一律拒绝。
			if keyMatches(s.key, "b64") {
				return errs.Detail(ErrMalformed, "unsupported b64 header | 不支持 b64 头部")
			}
			if v, ok := jsonStringValue(s.val); ok {
				key := jsonKeyString(s.key)
				if f.extra == nil {
					f.extra = make(map[string]string, 4)
				} else if _, exists := f.extra[key]; exists {
					return errs.Detail(ErrMalformed, "duplicate %[1]s header | %[1]s 头部重复", key)
				}
				f.extra[key] = v
			}
		}
	}
	if s.err {
		return errs.Detail(ErrMalformed, "header is not well-formed JSON | 头部不是结构良好的 JSON")
	}
	if !f.haveAlg {
		return errs.Detail(ErrAlgNotAllowed, "header has no alg | 头部缺少 alg")
	}
	alg, ok := algFromRaw(f.algRaw)
	if !ok {
		return errs.Detail(ErrAlgNotAllowed, "alg=%[1]q is unsupported | alg=%[1]q 不受支持", string(f.algRaw))
	}
	f.alg = alg
	return nil
}

// algFromRaw maps the raw alg value to a supported algorithm without allocating a string. | algFromRaw 把原始 alg 值映射为受支持的算法，且不产生字符串分配。
func algFromRaw(raw []byte) (Alg, bool) {
	body, ok := jsonStringBody(raw)
	if !ok {
		return "", false
	}
	for _, a := range allAlgs {
		// The body is compared byte by byte, so no string has to be materialized for the comparison. | 逐字节比较，
		// 因此比较过程无需生成字符串。
		if rawEqualString(body, string(a)) {
			return a, true
		}
	}
	return "", false
}

// allAlgs lists every supported algorithm in a fixed order. | allAlgs 以固定顺序列出全部受支持的算法。
var allAlgs = []Alg{HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

// SignOptions carries the non-claim part of a token. | SignOptions 承载 token 中与声明无关的部分。
type SignOptions struct {
	// Header adds extra header parameters. | Header 附加额外的头部参数。
	//
	// The reserved names alg, typ and kid are ignored, so this map can never override them. The crit
	// and b64 extension names are refused with ErrInvalidHeader because this implementation supports
	// neither, and signing them would only produce a token that Parse rejects. | 保留名 alg、typ 与
	// kid 会被忽略，因此该 map 无法覆盖它们。crit 与 b64 扩展名会以 ErrInvalidHeader 拒绝，因为本
	// 实现两者都不支持，签发它们只会产出 Parse 拒绝的 token。
	Header map[string]string
	// Kid sets the "kid" header parameter; empty means the parameter is omitted. | Kid 设置 "kid" 头部参数；为空表示省略该参数。
	Kid string
	// LowS normalizes ES256, ES384 and ES512 signatures to the canonical low-S form, whose s
	// half is at most half the curve order. It has no effect on other algorithms. | LowS 把
	// ES256、ES384 与 ES512 签名规范化为规范的 low-S 形式，即 s 半值不超过曲线阶的一半。其它
	// 算法不受影响。
	LowS bool
}

// Sign builds a compact JWS from claims and key. | Sign 用 claims 与 key 生成紧凑 JWS。
//
// Claims may be any value json.Marshal accepts; a struct is faster than a
// map[string]any because it avoids map reflection. For an already encoded JSON
// object use SignJSON, which skips serialization entirely. | claims 可以是
// json.Marshal 接受的任意值；结构体比 map[string]any 更快，因为它避免 map 反射。
// 已经编码好的 JSON 对象请用 SignJSON，它完全跳过序列化。
//
// The key must match the algorithm: []byte or string for HSxxx, *rsa.PrivateKey for RSxxx and PSxxx,
// *ecdsa.PrivateKey for ESxxx, and ed25519.PrivateKey for EdDSA; a key from another family is refused with
// ErrSignatureInvalid. | 密钥必须与算法匹配：HSxxx 用 []byte 或 string，RSxxx 与 PSxxx 用 *rsa.PrivateKey，
// ESxxx 用 *ecdsa.PrivateKey，EdDSA 用 ed25519.PrivateKey；密钥族不符时以 ErrSignatureInvalid 拒绝。
//
// The header always carries alg and typ; the payload is json.Marshal of claims, and the signature covers the
// raw "header.payload" bytes produced here. | 头部始终包含 alg 与 typ；载荷由 json.Marshal 序列化 claims，
// 签名覆盖此处产出的原始 "header.payload" 字节。
func Sign(claims any, key any, alg Alg, o SignOptions) (string, error) {
	if !supported(alg) {
		return "", errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", string(alg))
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidClaims, "claims | 声明")
	}
	return signPayload(payload, key, alg, o)
}

// SignJSON signs an already encoded JSON object. | SignJSON 对已经编码好的 JSON 对象签名。
//
// The payload must be a single well-formed JSON object; it is validated
// structurally before signing, so a caller cannot accidentally mint a token
// whose bytes are not a JWT payload. The signature covers exactly payload, the
// bytes passed here, with no re-encoding. | 载荷必须是单个结构良好的 JSON 对象；签名前
// 会做结构校验，因此调用方不可能误签出不是 JWT 载荷的字节。签名精确覆盖传入的 payload，
// 不做任何重新编码。
func SignJSON(payload []byte, key any, alg Alg, o SignOptions) (string, error) {
	if !supported(alg) {
		return "", errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", string(alg))
	}
	if !validJSONObject(payload) {
		return "", errs.Detail(ErrInvalidClaims, "payload is not a JSON object | 载荷不是 JSON 对象")
	}
	return signPayload(payload, key, alg, o)
}

// signPayload encodes the header and signs header.payload. | signPayload 编码头部并签名 header.payload。
func signPayload(payload []byte, key any, alg Alg, o SignOptions) (string, error) {
	s := getScratch()
	defer putScratch(s)

	// Encode both segments into pooled buffers and keep the signing input in one contiguous slice. | 把两段编码进池化缓冲，并让签名输入保持为一段连续内存。
	var err error
	s.header, err = appendHeader(s.header[:0], alg, o)
	if err != nil {
		return "", err
	}
	s.input = base64.RawURLEncoding.AppendEncode(s.input[:0], s.header)
	s.input = append(s.input, '.')
	s.input = base64.RawURLEncoding.AppendEncode(s.input, payload)
	sig, err := signRaw(alg, key, s.input, s, o.LowS)
	if err != nil {
		return "", err
	}

	// The signature is appended straight after the signing input, so the compact token occupies one buffer. | 签名直接追加在签名输入之后，因此紧凑 token 只占一个缓冲。
	s.input = append(s.input, '.')
	s.input = base64.RawURLEncoding.AppendEncode(s.input, sig)
	return string(s.input), nil
}

// appendHeader serializes the protected header into dst without a map or reflection. | appendHeader
// 把受保护头部序列化进 dst，不构造 map，也不使用反射。
//
// The reserved names alg, typ and kid are controlled by SignOptions and can never be smuggled in
// through Header. The unsupported crit and b64 extensions are refused so Sign cannot mint a token
// that Parse would reject. Keys are sorted so that identical options produce identical header
// bytes. | 保留名 alg、typ 与 kid 由 SignOptions 控制，绝不可能经由 Header 混入。尚未支持的
// crit 与 b64 扩展会被拒绝，使 Sign 无法签发 Parse 会拒绝的 token。键会排序，因此相同选项产生
// 相同的头部字节。
func appendHeader(dst []byte, alg Alg, o SignOptions) ([]byte, error) {
	dst = append(dst, `{"alg":"`...)
	dst = append(dst, alg...)
	dst = append(dst, `","typ":"JWT"`...)
	if o.Kid != "" {
		dst = append(dst, `,"kid":`...)
		dst = appendJSONStringLiteral(dst, o.Kid)
	}
	if len(o.Header) > 0 {
		keys := make([]string, 0, len(o.Header))
		for k := range o.Header {
			switch k {
			case "alg", "typ", "kid":
				continue
			case "crit", "b64":
				return dst, errs.Detail(ErrInvalidHeader, "unsupported %[1]s header | 不支持 %[1]s 头部", k)
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dst = append(dst, ',')
			dst = appendJSONStringLiteral(dst, k)
			dst = append(dst, ':')
			dst = appendJSONStringLiteral(dst, o.Header[k])
		}
	}
	return append(dst, '}'), nil
}

// appendJSONStringLiteral appends s as a JSON string literal, escaping control characters and quotes and
// replacing invalid UTF-8 bytes with U+FFFD, matching encoding/json's replacement rule. | appendJSONString
// 把 s 作为 JSON 字符串字面量追加，转义控制字符与引号，并把非法 UTF-8 字节替换为 U+FFFD，
// 与 encoding/json 的替换规则一致。
func appendJSONStringLiteral(dst []byte, s string) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
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
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, `�`...)
			i++
			continue
		}
		dst = append(dst, s[i:i+size]...)
		i += size
	}
	return append(dst, '"')
}

// hmacSecret accepts the symmetric key forms and rejects every other type. | hmacSecret 接受对称密钥的形式，并拒绝其它所有类型。
//
// Rejecting non-symmetric types here is what defeats algorithm confusion: an RSA or ECDSA public key can
// never be reinterpreted as an HMAC secret. | 在此拒绝非对称类型正是击破算法混淆的关键：RSA 或 ECDSA 公钥永远不会被当作 HMAC 密钥使用。
//
// The key must be at least as long as the algorithm's hash output, as RFC 7518 §3.2 requires: an empty
// or short secret (for example an unset environment variable) is universally guessable and turns a
// signing key into a forgery oracle. | 密钥至少要与算法的哈希输出等长，这是 RFC 7518 §3.2 的要求：
// 空密钥或短密钥（例如未设置的环境变量）可被普遍猜出，会把签名密钥变成伪造预言机。
func hmacSecret(alg Alg, key any) ([]byte, bool) {
	var secret []byte
	switch k := key.(type) {
	case []byte:
		secret = k
	case string:
		secret = []byte(k)
	default:
		return nil, false
	}
	h, ok := algHash(alg)
	if !ok || len(secret) < h.Size() {
		return nil, false
	}
	return secret, true
}

// algHash returns the standard-library hash identity of an algorithm. | algHash 返回算法对应的标准库哈希标识。
func algHash(alg Alg) (crypto.Hash, bool) {
	switch alg {
	case HS256, RS256, PS256, ES256:
		return crypto.SHA256, true
	case HS384, RS384, PS384, ES384:
		return crypto.SHA384, true
	case HS512, RS512, PS512, ES512:
		return crypto.SHA512, true
	}
	return 0, false
}

// algCurve returns the NIST curve an ECDSA algorithm requires. | algCurve 返回 ECDSA 算法要求的 NIST 曲线。
func algCurve(alg Alg) elliptic.Curve {
	switch alg {
	case ES256:
		return elliptic.P256()
	case ES384:
		return elliptic.P384()
	case ES512:
		return elliptic.P521()
	}
	return nil
}

// signRaw signs input with key for alg. | signRaw 用 key 按 alg 对 input 签名。
//
// lowS selects the canonical low-S form for the ECDSA algorithms. | lowS 为 ECDSA 算法选择
// 规范的 low-S 形式。
func signRaw(alg Alg, key any, input []byte, s *scratch, lowS bool) ([]byte, error) {
	switch alg {
	case EdDSA:
		k, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, keyTypeError(alg)
		}
		// ed25519.Sign panics on a wrong-length key, and a library must never panic on caller-supplied
		// key material. | 密钥长度不符时 ed25519.Sign 会 panic，而库绝不能因调用方提供的密钥材料 panic。
		if len(k) != ed25519.PrivateKeySize {
			return nil, errs.Detail(ErrSignatureInvalid, "ed25519 private key is %[1]d bytes, want %[2]d | ed25519 私钥为 %[1]d 字节，期望 %[2]d 字节", len(k), ed25519.PrivateKeySize)
		}
		return ed25519.Sign(k, input), nil
	}

	h, ok := algHash(alg)
	if !ok {
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", string(alg))
	}

	switch alg {
	case HS256, HS384, HS512:
		secret, ok := hmacSecret(alg, key)
		if !ok {
			switch key.(type) {
			case []byte, string:
				return nil, errs.Detail(ErrWeakKey, "alg=%[1]s needs at least %[2]d key bytes | 算法 %[1]s 至少需要 %[2]d 字节密钥", string(alg), h.Size())
			}
			return nil, keyTypeError(alg)
		}
		s.mac = algMACPool(alg).sum(secret, input, s.mac[:0])
		return s.mac, nil
	case RS256, RS384, RS512:
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, keyTypeError(alg)
		}
		if k.N == nil || k.N.BitLen() < 2048 {
			return nil, errs.Detail(ErrWeakKey, "alg=%[1]s needs a 2048-bit RSA key | 算法 %[1]s 需要 2048 位 RSA 密钥", string(alg))
		}
		digest := algHashPool(alg).sum(input, s.mac[:0])
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, h, digest)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrSignatureInvalid, "RSA signing | RSA 签名")
		}
		return sig, nil
	case PS256, PS384, PS512:
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, keyTypeError(alg)
		}
		if k.N == nil || k.N.BitLen() < 2048 {
			return nil, errs.Detail(ErrWeakKey, "alg=%[1]s needs a 2048-bit RSA key | 算法 %[1]s 需要 2048 位 RSA 密钥", string(alg))
		}
		digest := algHashPool(alg).sum(input, s.mac[:0])
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		sig, err := rsa.SignPSS(rand.Reader, k, h, digest, opts)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrSignatureInvalid, "RSA-PSS signing | RSA-PSS 签名")
		}
		return sig, nil
	case ES256, ES384, ES512:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || !curveMatches(k.Curve, algCurve(alg)) {
			return nil, keyTypeError(alg)
		}
		digest := algHashPool(alg).sum(input, s.mac[:0])
		r, sv, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrSignatureInvalid, "ECDSA signing | ECDSA 签名")
		}
		if lowS {
			sv = toLowS(k.Curve, sv)
		}
		return appendFixedWidth(nil, r, sv, curveWidth(alg)), nil
	}
	return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", string(alg))
}

// verify checks the signature of a compact token. | verify 校验紧凑 token 的签名。
//
// input is the raw "header.payload" signing input and sig is the decoded signature. requireLowS
// additionally rejects a non-canonical high-S ECDSA signature. | input 是原始的
// "header.payload" 签名输入，sig 是解码后的签名。requireLowS 还会拒绝非规范的高 S ECDSA 签名。
//
// A key from the wrong family is reported as ErrSignatureInvalid, never as an internal panic or a confusing
// success; that single rule closes algorithm confusion in both directions. A private key of the matching
// family is accepted and only its public half is used, so one key value can serve both Sign and Parse. |
// 密钥族不符一律报告 ErrSignatureInvalid，既不 panic 也不会误判成功；这一条规则同时封堵了两个方向的
// 算法混淆。匹配族的私钥也可以传入，且只会使用其公钥部分，因此同一个密钥取值可同时服务 Sign 与 Parse。
func verify(alg Alg, key any, input, sig []byte, s *scratch, requireLowS bool) bool {
	switch alg {
	case EdDSA:
		k, ok := ed25519VerifyKey(key)
		if !ok {
			return false
		}
		return ed25519.Verify(k, input, sig)
	}

	h, ok := algHash(alg)
	if !ok {
		return false
	}

	switch alg {
	case HS256, HS384, HS512:
		secret, ok := hmacSecret(alg, key)
		if !ok {
			return false
		}
		s.mac = algMACPool(alg).sum(secret, input, s.mac[:0])
		return hmac.Equal(s.mac, sig)
	case RS256, RS384, RS512:
		k, ok := rsaVerifyKey(key)
		if !ok {
			return false
		}
		digest := algHashPool(alg).sum(input, s.mac[:0])
		return rsa.VerifyPKCS1v15(k, h, digest, sig) == nil
	case PS256, PS384, PS512:
		k, ok := rsaVerifyKey(key)
		if !ok {
			return false
		}
		digest := algHashPool(alg).sum(input, s.mac[:0])
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		return rsa.VerifyPSS(k, h, digest, sig, opts) == nil
	case ES256, ES384, ES512:
		k, ok := ecdsaVerifyKey(key)
		if !ok || !curveMatches(k.Curve, algCurve(alg)) {
			return false
		}
		width := curveWidth(alg)
		if len(sig) != 2*width {
			return false
		}
		if requireLowS && !isLowS(k.Curve, sig[width:]) {
			return false
		}
		digest := algHashPool(alg).sum(input, s.mac[:0])
		// Build the DER signature on the stack and verify it directly. The legacy ecdsa.Verify
		// entry point would parse the two fixed-width halves into big.Ints only to re-encode them
		// as DER and call VerifyASN1, so this path removes both conversions and their allocations
		// while keeping exactly the same scalar validation performed by the standard library. |
		// 在栈上构造 DER 签名并直接校验。旧的 ecdsa.Verify 入口会先把两段定宽值解析为 big.Int，
		// 再重新编码为 DER 并调用 VerifyASN1；本路径省去两次转换及其分配，同时保留标准库执行的
		// 完全相同的标量校验。
		der := derSignature(sig[:width], sig[width:])
		return ecdsa.VerifyASN1(k, digest, der)
	}
	return false
}

// derSignature encodes two fixed-width ECDSA integers as one DER SEQUENCE. | derSignature 把两个
// 定宽 ECDSA 整数编码为一个 DER SEQUENCE。
//
// The returned slice aliases a stack buffer owned by the caller's frame; it is valid until
// derSignature returns to a caller that did not let it escape. The maximum size is a P-521
// signature: 136 content bytes plus a two-byte long-form sequence header, hence 139 bytes. | 返回的
// 切片指向调用方栈帧中的缓冲区；只要调用方不让它逃逸，在 derSignature 返回后仍然有效。最大为
// P-521 签名：136 字节内容加上两字节长形式序列头，共 139 字节。
func derSignature(r, s []byte) []byte {
	var body [136]byte
	b := body[:0]
	b = appendDERInteger(b, r)
	b = appendDERInteger(b, s)
	var out [139]byte
	switch {
	case len(b) < 128:
		out[0] = 0x30
		out[1] = byte(len(b))
		copy(out[2:], b)
		return out[:2+len(b)]
	default:
		out[0] = 0x30
		out[1] = 0x81
		out[2] = byte(len(b))
		copy(out[3:], b)
		return out[:3+len(b)]
	}
}

// appendDERInteger appends one minimally encoded DER INTEGER for a fixed-width unsigned value. |
// appendDERInteger 为一个定宽无符号值追加最小编码的 DER INTEGER。
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

// curveMatches reports whether c is the required curve. | curveMatches 报告 c 是否为要求的曲线。
//
// The comparison uses the curve name rather than the bit size: secp256k1 and brainpoolP256r1 are both
// 256-bit curves, but RFC 7518 mandates NIST P-256 for ES256, and a same-width foreign curve must not
// silently take its place. | 比较使用曲线名而不是位宽：secp256k1 与 brainpoolP256r1 都是 256 位曲线，
// 但 RFC 7518 规定 ES256 使用 NIST P-256，同宽的外来曲线不得悄悄顶替。
func curveMatches(c, want elliptic.Curve) bool {
	if c == nil || want == nil {
		return false
	}
	return c.Params().Name == want.Params().Name && c.Params().BitSize == want.Params().BitSize
}

// curveWidth returns the byte width of one ECDSA signature half for alg. | curveWidth 返回 alg 对应的 ECDSA 签名半值字节宽度。
func curveWidth(alg Alg) int {
	if c := algCurve(alg); c != nil {
		return (c.Params().BitSize + 7) / 8
	}
	return 0
}

// appendFixedWidth appends r and s as two fixed-width big-endian integers, the JWS ECDSA signature form. | appendFixedWidth 把 r 与 s 按定宽大端整数追加，即 JWS 的 ECDSA 签名形式。
//
// JWS requires this fixed-width form rather than the DER encoding produced by ecdsa.SignASN1, which is why the
// sign side does not use SignASN1. | JWS 要求定宽形式，而非 ecdsa.SignASN1 产出的 DER 编码，
// 因此签发侧不使用 SignASN1。
func appendFixedWidth(dst []byte, r, s *big.Int, width int) []byte {
	base := len(dst)
	dst = append(dst, make([]byte, 2*width)...)
	r.FillBytes(dst[base : base+width])
	s.FillBytes(dst[base+width:])
	return dst
}

// toLowS returns s or its curve-order complement, whichever is not greater than half the order. | toLowS
// 返回 s 或其曲线阶补值中不大于阶一半的那个。
//
// ECDSA admits both s and N-s; pinning the low half removes signature malleability. The caller only
// invokes this when SignOptions.LowS is set, so the default signing path is unchanged. | ECDSA 同时接受
// s 与 N-s；固定取低半值可消除签名可塑性。调用方仅在设置 SignOptions.LowS 时使用，默认签发路径不变。
func toLowS(curve elliptic.Curve, s *big.Int) *big.Int {
	if curve == nil || s == nil {
		return s
	}
	n := curve.Params().N
	if n == nil {
		return s
	}
	half := new(big.Int).Rsh(n, 1)
	if s.Cmp(half) > 0 {
		return new(big.Int).Sub(n, s)
	}
	return s
}

// isLowS reports whether the fixed-width s half is in the canonical low-S range (1 <= s <= N/2). | isLowS
// 报告定宽 s 半值是否位于规范的 low-S 范围（1 <= s <= N/2）。
func isLowS(curve elliptic.Curve, s []byte) bool {
	if curve == nil || len(s) == 0 {
		return false
	}
	n := curve.Params().N
	if n == nil {
		return false
	}
	v := new(big.Int).SetBytes(s)
	if v.Sign() <= 0 {
		return false
	}
	half := new(big.Int).Rsh(n, 1)
	return v.Cmp(half) <= 0
}

// rsaVerifyKey extracts the public half of an RSA verification key. | rsaVerifyKey 提取 RSA 验签
// 密钥的公钥部分。
//
// A private key is accepted for interoperability with callers that reuse one key value for Sign and
// Parse, as golang-jwt does. Verification only reads the public members, so accepting a private key
// cannot weaken the signature check. | 接受私钥是为了与把同一个密钥取值同时用于 Sign 与 Parse 的
// 调用方互操作（golang-jwt 亦如此）。验签只读取公开成员，因此接受私钥不会削弱签名校验。
func rsaVerifyKey(key any) (*rsa.PublicKey, bool) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.E <= 0 || k.N.BitLen() < 2048 {
			return nil, false
		}
		return k, true
	case *rsa.PrivateKey:
		if k == nil || k.N == nil || k.E <= 0 || k.N.BitLen() < 2048 {
			return nil, false
		}
		return &k.PublicKey, true
	}
	return nil, false
}

// ecdsaVerifyKey extracts the public half of an ECDSA verification key. | ecdsaVerifyKey 提取
// ECDSA 验签密钥的公钥部分。
//
// As with rsaVerifyKey, a private key is accepted so one key value can serve Sign and Parse; only
// the embedded public key reaches ecdsa.VerifyASN1. | 与 rsaVerifyKey 相同，接受私钥使同一个密钥取值
// 可同时服务 Sign 与 Parse；只有内嵌公钥会传给 ecdsa.VerifyASN1。
func ecdsaVerifyKey(key any) (*ecdsa.PublicKey, bool) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, false
		}
		return k, true
	case *ecdsa.PrivateKey:
		if k == nil {
			return nil, false
		}
		return &k.PublicKey, true
	}
	return nil, false
}

// ed25519VerifyKey extracts the public half of an Ed25519 verification key. | ed25519VerifyKey
// 提取 Ed25519 验签密钥的公钥部分。
//
// Length is checked before calling Public on a private key, because ed25519.PrivateKey.Public
// slices the key and would panic on a short value. | 调用私钥的 Public 之前先检查长度，因为
// ed25519.PrivateKey.Public 会切片该密钥，长度不足时会 panic。
func ed25519VerifyKey(key any) (ed25519.PublicKey, bool) {
	switch k := key.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, false
		}
		return k, true
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, false
		}
		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return nil, false
		}
		return pub, true
	}
	return nil, false
}

// keyTypeError reports a key whose family does not match the algorithm. | keyTypeError 报告密钥族与算法不匹配。
func keyTypeError(alg Alg) error {
	return errs.Detail(ErrSignatureInvalid, "key type does not match alg=%[1]q | 密钥类型与 alg=%[1]q 不匹配", string(alg))
}
