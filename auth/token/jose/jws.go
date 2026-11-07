package jose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
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
	// Crit lists critical extensions; this implementation understands none, so signing with a
	// non-empty Crit is refused. | Crit 列出关键扩展；本实现不支持任何扩展，因此 Crit 非空时拒绝签名。
	Crit []string
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
	// Crit is refused when non-empty because no extension is understood. | Crit 非空时会被拒绝，因为本实现不支持任何扩展。
	Crit []string
	// Extra holds additional header parameters; reserved names are refused. | Extra 保存额外头部参数；保留名会被拒绝。
	Extra map[string]any
}

// Sign builds a compact JWS over payload with key. | Sign 使用 key 对 payload 生成紧凑 JWS。
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
	if len(header.Crit) > 0 {
		return "", errs.Detail(ErrUnsupportedCrit, "crit=%[1]v | crit=%[1]v", header.Crit)
	}
	// A plain JWT JSON payload goes through the existing ydx/auth/token/jwt signer, which is the same
	// implementation the rest of ydx uses; every other case is signed here so arbitrary bytes
	// remain possible. | 普通 JWT JSON 载荷走现有 ydx/auth/token/jwt 签名器，即 ydx 其余部分使用的
	// 同一实现；其它情况在此签名，以便任意字节都能使用。
	if header.Typ == "JWT" && header.Cty == "" && len(header.Extra) == 0 && isJSONObject(payload) {
		jkey, err := key.PrivateKey()
		if err != nil {
			return "", err
		}
		return ydjwt.SignJSON(payload, jkey, ydjwt.Alg(alg), ydjwt.SignOptions{Kid: kid})
	}
	return signDirect(payload, key, header)
}

// signDirect builds a compact JWS without the JWT-specific JSON requirement. | signDirect 构建不
// 受 JWT JSON 要求限制的紧凑 JWS。
func signDirect(payload []byte, key *Key, header JWSHeader) (string, error) {
	headerBytes, err := encodeJWSHeader(header)
	if err != nil {
		return "", err
	}
	input := make([]byte, 0, len(headerBytes)+len(payload)+len(payload)/3+len(headerBytes)/3+2)
	input = appendSegment(input, headerBytes)
	input = append(input, '.')
	input = appendSegment(input, payload)
	sig, err := signJWS(header.Alg, key, input)
	if err != nil {
		return "", err
	}
	input = append(input, '.')
	input = appendSegment(input, sig)
	return string(input), nil
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
	// Leeway is the clock tolerance applied to exp and nbf by ValidateClaims. | Leeway 是 ValidateClaims 对 exp 与 nbf 施加的时钟容差。
	Leeway time.Duration
	// Now overrides the clock used by ValidateClaims. | Now 替换 ValidateClaims 使用的时钟。
	Now func() time.Time
	// ValidateClaims enables ydx/auth/token/jwt registered-claim validation, including exp, nbf, iss
	// and aud. Without it, a valid signature is the only requirement. | ValidateClaims 启用
	// ydx/auth/token/jwt 登记声明校验，包括 exp、nbf、iss 与 aud。未启用时唯一要求是签名有效。
	ValidateClaims bool
	// RequireExp rejects a token without exp when ValidateClaims is set. | RequireExp 在启用
	// ValidateClaims 时拒绝缺少 exp 的令牌。
	RequireExp bool
	// Issuer, when non-empty and ValidateClaims is set, must equal the iss claim. | Issuer 非空且
	// 启用 ValidateClaims 时必须等于 iss 声明。
	Issuer string
	// Audience, when non-empty and ValidateClaims is set, must be contained in aud. | Audience
	// 非空且启用 ValidateClaims 时必须包含于 aud。
	Audience string
}

// Verify verifies a compact JWS using resolver and the background context. | Verify 使用 resolver
// 与后台上下文校验紧凑 JWS。
func Verify(token string, resolver KeyResolver, opts VerifyOptions) (*Verified, error) {
	return VerifyContext(context.Background(), token, resolver, opts)
}

// VerifyContext verifies a compact JWS using resolver and ctx. | VerifyContext 使用 resolver 与
// ctx 校验紧凑 JWS。
//
// The header is decoded first and its alg is checked against the allow list and key family before
// the signature is validated; only then is the payload exposed. Critical extensions, duplicate
// header members, alg=none and algorithm confusion are rejected. When ValidateClaims is set, a
// JSON-object payload is additionally validated by ydx/auth/token/jwt, whose sentinels remain visible
// through errors.Is. | 首先解码头部，并在校验签名之前检查 alg 是否在白名单内且与密钥族匹配；
// 之后才暴露载荷。关键扩展、重复头部成员、alg=none 与算法混淆都会被拒绝。启用 ValidateClaims
// 时，JSON 对象载荷还会经 ydx/auth/token/jwt 校验，其哨兵仍可通过 errors.Is 观察到。
func VerifyContext(ctx context.Context, token string, resolver KeyResolver, opts VerifyOptions) (*Verified, error) {
	if resolver == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil key resolver | 密钥解析器为 nil")
	}
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
	sigSeg := rest[second+1:]
	payloadSeg := rest[:second]
	if sigSeg == "" {
		return nil, errs.Detail(ErrMalformed, "empty signature segment | 签名段为空")
	}

	raw, err := DecodeSegment(token[:first])
	if err != nil {
		return nil, err
	}
	header, rawHeader, err := parseJWSHeader(raw)
	if err != nil {
		return nil, err
	}
	if header.Alg == "none" || !supportedJWSAlg(header.Alg) {
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", header.Alg)
	}
	if !algAllowed(opts.ValidAlgs, header.Alg) {
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q is outside the allow list | alg=%[1]q 不在白名单内", header.Alg)
	}
	if opts.Typ != "" && !strings.EqualFold(header.Typ, opts.Typ) {
		return nil, errs.Detail(ErrInvalidHeader, "typ=%[1]q, want %[2]q | typ=%[1]q，期望 %[2]q", header.Typ, opts.Typ)
	}

	key, err := resolver.ResolveKey(ctx, rawHeader)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, errs.Detail(ErrKeyNotFound, "resolver returned nil key | 解析器返回 nil 密钥")
	}
	if key.Alg != "" && key.Alg != header.Alg {
		return nil, errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", key.Alg, header.Alg)
	}
	if err := checkKeyAlg(key, header.Alg); err != nil {
		return nil, err
	}

	sig, err := DecodeSegment(sigSeg)
	if err != nil {
		return nil, err
	}
	payload, err := DecodeSegment(payloadSeg)
	if err != nil {
		return nil, err
	}
	input := []byte(token[:first+1+second])
	if err := verifyJWS(header.Alg, key, input, sig); err != nil {
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
		if err := validateClaims(token, key, header.Alg, opts); err != nil {
			return nil, err
		}
	}
	return verified, nil
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
		ValidAlgs:  []ydjwt.Alg{ydjwt.Alg(alg)},
		Leeway:     opts.Leeway,
		Now:        opts.Now,
		RequireExp: opts.RequireExp,
		Issuer:     opts.Issuer,
		Audience:   opts.Audience,
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
	if v, present := m["crit"]; present {
		crit, ok := stringSlice(v)
		if !ok {
			return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "crit is not a string array | crit 不是字符串数组")
		}
		if len(crit) > 0 {
			return JWSHeader{}, nil, errs.Detail(ErrUnsupportedCrit, "crit=%[1]v | crit=%[1]v", crit)
		}
		h.Crit = crit
	}
	if _, present := m["b64"]; present {
		// RFC 7797 unencoded payloads are not implemented; ignoring the parameter would change
		// the meaning of the signature input, so it is refused outright. | RFC 7797 的未编码载荷
		// 未实现；忽略该参数会改变签名输入的含义，因此直接拒绝。
		return JWSHeader{}, nil, errs.Detail(ErrInvalidHeader, "b64 extension is not supported | 不支持 b64 扩展")
	}
	for name, v := range m {
		switch name {
		case "alg", "kid", "typ", "cty", "crit":
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
func encodeJWSHeader(h JWSHeader) ([]byte, error) {
	if h.Alg == "" || h.Alg == "none" || !supportedJWSAlg(h.Alg) {
		return nil, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", h.Alg)
	}
	if len(h.Crit) > 0 {
		return nil, errs.Detail(ErrUnsupportedCrit, "crit=%[1]v | crit=%[1]v", h.Crit)
	}
	reserved := map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}, "b64": {}}
	extraKeys := make([]string, 0, len(h.Extra))
	for name := range h.Extra {
		if _, bad := reserved[name]; bad {
			return nil, errs.Detail(ErrInvalidHeader, "reserved header %[1]q | 保留头部 %[1]q", name)
		}
		extraKeys = append(extraKeys, name)
	}
	sort.Strings(extraKeys)

	out := make([]byte, 0, 64+len(extraKeys)*16)
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
