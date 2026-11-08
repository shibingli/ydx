package jose

import (
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// maxJWSSigners bounds the signatures of one JWS JSON serialization. | maxJWSSigners 限制一个 JWS
// JSON 序列化的签名数量。
const maxJWSSigners = 64

// Signer describes one signature produced by SignMulti. | Signer 描述 SignMulti 生成的一个签名。
type Signer struct {
	// Key is the signing key and is required. | Key 是签名密钥且为必需。
	Key *Key
	// Header is the protected header; Alg is required unless Key.Alg supplies it. Crit and B64 are
	// interpreted exactly as by Sign, including RFC 7797. | Header 是受保护头部；Alg 必需，除非
	// Key.Alg 提供它。Crit 与 B64 的解释与 Sign 完全相同，包括 RFC 7797。
	Header JWSHeader
	// Unprotected holds unprotected header parameters. The names alg, crit and b64 are always
	// refused, and a name already present in the protected header is refused so the two headers can
	// never disagree. | Unprotected 保存非保护头部参数。alg、crit 与 b64 一律拒绝；受保护头部已有的
	// 名称也会被拒绝，使两个头部不可能互相矛盾。
	Unprotected map[string]any
	// LowS normalizes ES256, ES384 and ES512 signatures to the canonical low-S form. | LowS 把
	// ES256、ES384 与 ES512 签名规范化为规范的 low-S 形式。
	LowS bool
}

// MultiSignOptions configures SignMulti. | MultiSignOptions 配置 SignMulti。
type MultiSignOptions struct {
	// Detached omits the shared payload member for RFC 7515 Appendix F detached content; the caller
	// must present the payload to VerifyDetached. | Detached 按 RFC 7515 附录 F 省略共享的 payload
	// 成员；调用方必须把载荷交给 VerifyDetached。
	Detached bool
	// Serialization selects flattened or general JSON. Compact is the zero value and cannot carry a
	// JSON signature, so the zero value selects flattened for one signer and general for more than
	// one; compact output is never produced. | Serialization 选择扁平或通用 JSON。紧凑形式是零值且
	// 无法承载 JSON 签名，因此零值在单签名时选择扁平、多签名时选择通用；绝不会输出紧凑形式。
	Serialization Serialization
}

// preparedJWSSignature is one validated signature ready to be emitted. | preparedJWSSignature 是准备
// 输出的一个已校验签名。
type preparedJWSSignature struct {
	// key is the signing key. | key 是签名密钥。
	key *Key
	// header is the normalized protected header. | header 是规范化后的受保护头部。
	header JWSHeader
	// protected is the base64url protected header. | protected 是 base64url 受保护头部。
	protected string
	// unprotected is the optional unprotected header. | unprotected 是可选的、非保护的头部。
	unprotected Header
	// lowS requests canonical low-S ECDSA signatures. | lowS 请求规范的 low-S ECDSA 签名。
	lowS bool
}

// SignMulti builds a flattened or general JWS JSON serialization carrying one or more signatures. |
// SignMulti 构建携带一个或多个签名的扁平或通用 JWS JSON 序列化。
//
// Every signer signs the same payload. Each protected header stays independent, and an optional
// per-signature unprotected header can carry non-integrity-protected parameters. RFC 7797 b64=false
// is supported, but all signers must agree on the b64 mode because the payload member is shared.
// Output is deterministic: members are emitted in a fixed order and unprotected maps are encoded
// with sorted keys. | 每个签名方对同一载荷签名。各受保护头部互相独立，可选的每签名非保护头部可承载
// 不受完整性保护的参数。支持 RFC 7797 的 b64=false，但由于 payload 成员共享，所有签名方必须就 b64
// 模式达成一致。输出是确定的：成员按固定顺序写出，非保护映射按键排序编码。
func SignMulti(payload []byte, signers []Signer, opts MultiSignOptions) (string, error) {
	if len(signers) == 0 {
		return "", errs.Detail(ErrInvalidConfig, "no signers | 没有签名方")
	}
	if len(signers) > maxJWSSigners {
		return "", errs.Detail(ErrInvalidConfig, "too many signers: %[1]d | 签名方过多：%[1]d", len(signers))
	}
	general := false
	switch opts.Serialization {
	case SerializationFlattened:
		if len(signers) > 1 {
			return "", errs.Detail(ErrInvalidConfig, "flattened carries exactly one signature | 扁平形式仅承载一个签名")
		}
	case SerializationGeneral:
		general = true
	case SerializationCompact:
		// SerializationCompact is the zero value; it cannot describe a JSON signature and therefore
		// selects flattened for one signer and general for more than one. | SerializationCompact 是
		// 零值；它无法描述 JSON 签名，因此在单签名时选择扁平、多签名时选择通用。
		general = len(signers) > 1
	default:
		return "", errs.Detail(ErrInvalidConfig, "unknown serialization %[1]q | 未知序列化 %[1]q", string(opts.Serialization))
	}

	prepared := make([]preparedJWSSignature, len(signers))
	var unencoded *bool
	for i := range signers {
		p, err := prepareJWSSigner(signers[i])
		if err != nil {
			return "", err
		}
		mode := unencodedPayload(p.header)
		if unencoded == nil {
			unencoded = &mode
		} else if *unencoded != mode {
			return "", errs.Detail(ErrInvalidConfig, "all signers must share the b64 mode | 所有签名方必须采用相同的 b64 模式")
		}
		prepared[i] = p
	}

	payloadSeg := ""
	if *unencoded {
		if !opts.Detached && !utf8.Valid(payload) {
			return "", errs.Detail(ErrInvalidConfig, "unencoded JSON payload must be valid UTF-8 | 未编码的 JSON 载荷必须是合法 UTF-8")
		}
		payloadSeg = string(payload)
	} else {
		payloadSeg = EncodeSegment(payload)
	}

	out := make([]byte, 0, len(payloadSeg)+len(signers)*96+64)
	out = append(out, '{')
	if !opts.Detached {
		out = append(out, `"payload":`...)
		out = appendJSONString(out, payloadSeg)
		out = append(out, ',')
	}
	if general {
		out = append(out, `"signatures":[`...)
		for i := range prepared {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, '{')
			var err error
			out, err = appendJWSSignatureMembers(out, prepared[i], payload, payloadSeg, *unencoded)
			if err != nil {
				return "", err
			}
			out = append(out, '}')
		}
		out = append(out, ']', '}')
		return string(out), nil
	}
	var err error
	out, err = appendJWSSignatureMembers(out, prepared[0], payload, payloadSeg, *unencoded)
	if err != nil {
		return "", err
	}
	out = append(out, '}')
	return string(out), nil
}

// prepareJWSSigner validates one signer and normalizes its protected header. | prepareJWSSigner 校验
// 一个签名方并规范化其受保护头部。
func prepareJWSSigner(s Signer) (preparedJWSSignature, error) {
	if s.Key == nil {
		return preparedJWSSignature{}, ErrInvalidKey
	}
	alg := s.Header.Alg
	if alg == "" {
		alg = s.Key.Alg
	}
	if alg == "" {
		return preparedJWSSignature{}, errs.Detail(ErrAlgNotAllowed, "no alg specified | 未指定 alg")
	}
	if alg == "none" || !supportedJWSAlg(alg) {
		return preparedJWSSignature{}, errs.Detail(ErrAlgNotAllowed, "alg=%[1]q | 算法=%[1]q", alg)
	}
	if s.Key.Alg != "" && s.Key.Alg != alg {
		return preparedJWSSignature{}, errs.Detail(ErrAlgNotAllowed, "key alg=%[1]q does not allow %[2]q | 密钥 alg=%[1]q 不允许 %[2]q", s.Key.Alg, alg)
	}
	if err := checkKeyAlg(s.Key, alg); err != nil {
		return preparedJWSSignature{}, err
	}
	if err := checkKeyUse(s.Key, "sign"); err != nil {
		return preparedJWSSignature{}, err
	}
	h := s.Header
	h.Alg = alg
	if h.Kid == "" {
		h.Kid = s.Key.Kid
	}
	h, err := normalizeSigningJWSHeader(h)
	if err != nil {
		return preparedJWSSignature{}, err
	}
	if err := validateJWSUnprotected(h, s.Unprotected); err != nil {
		return preparedJWSSignature{}, err
	}
	headerBytes, err := appendJWSHeader(nil, h)
	if err != nil {
		return preparedJWSSignature{}, err
	}
	return preparedJWSSignature{
		key:         s.Key,
		header:      h,
		protected:   EncodeSegment(headerBytes),
		unprotected: s.Unprotected,
		lowS:        s.LowS,
	}, nil
}

// validateJWSUnprotected refuses unprotected parameters that the protected header already carries
// or that must stay integrity protected. | validateJWSUnprotected 拒绝受保护头部已携带的，以及必须
// 保持完整性保护的非保护参数。
func validateJWSUnprotected(h JWSHeader, unprotected Header) error {
	if len(unprotected) == 0 {
		return nil
	}
	protected := make(map[string]struct{}, 6+len(h.Extra))
	protected["alg"] = struct{}{}
	if h.Kid != "" {
		protected["kid"] = struct{}{}
	}
	if h.Typ != "" {
		protected["typ"] = struct{}{}
	}
	if h.Cty != "" {
		protected["cty"] = struct{}{}
	}
	if h.B64 != nil {
		protected["b64"] = struct{}{}
	}
	if len(h.Crit) > 0 {
		protected["crit"] = struct{}{}
	}
	for name := range h.Extra {
		protected[name] = struct{}{}
	}
	for name := range unprotected {
		switch name {
		case "alg", "crit", "b64":
			return errs.Detail(ErrInvalidHeader, "header %[1]q must be protected | 头部 %[1]q 必须受保护", name)
		}
		if _, dup := protected[name]; dup {
			return errs.Detail(ErrInvalidHeader, "duplicate %[1]s header | %[1]s 头部重复", name)
		}
	}
	return nil
}

// appendJWSSignatureMembers appends protected, header and signature members without the enclosing
// braces. | appendJWSSignatureMembers 追加 protected、header 与 signature 成员，不含外层花括号。
func appendJWSSignatureMembers(out []byte, p preparedJWSSignature, payload []byte, payloadSeg string, unencoded bool) ([]byte, error) {
	input := make([]byte, 0, len(p.protected)+1+len(payloadSeg))
	input = append(input, p.protected...)
	input = append(input, '.')
	if unencoded {
		input = append(input, payload...)
	} else {
		input = append(input, payloadSeg...)
	}
	sig, err := signJWSWithLowS(p.header.Alg, p.key, input, p.lowS)
	if err != nil {
		return nil, err
	}
	out = append(out, `"protected":`...)
	out = appendJSONString(out, p.protected)
	if len(p.unprotected) > 0 {
		value, err := json.Marshal(p.unprotected)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidHeader, "unprotected header | 非保护头部")
		}
		out = append(out, `,"header":`...)
		out = append(out, value...)
	}
	out = append(out, `,"signature":`...)
	out = appendJSONString(out, EncodeSegment(sig))
	return out, nil
}

// jwsJSONSignature is one signature entry of a JWS JSON serialization. | jwsJSONSignature 是 JWS
// JSON 序列化中的一个签名条目。
type jwsJSONSignature struct {
	// protected is the base64url protected header as it appeared on the wire. | protected 是线格式中
	// 原样的 base64url 受保护头部。
	protected string
	// header is the decoded unprotected header, or nil when the member is absent. | header 是解码后的
	// 非保护头部；成员缺失时为 nil。
	header Header
	// signature is the base64url signature as it appeared on the wire. | signature 是线格式中原样的
	// base64url 签名。
	signature string
}

// jwsJSONDoc is a parsed flattened or general JWS JSON serialization. | jwsJSONDoc 是解析后的扁平
// 或通用 JWS JSON 序列化。
type jwsJSONDoc struct {
	// payload is the base64url payload member, empty when absent or detached. | payload 是 base64url
	// 载荷成员；缺失或分离载荷时为空。
	payload string
	// hasPayload reports whether the payload member was present. | hasPayload 报告 payload 成员是否
	// 存在。
	hasPayload bool
	// general reports whether the document used the general (signatures array) form. | general 报告
	// 文档是否使用通用（signatures 数组）形式。
	general bool
	// signatures holds one entry for flattened form and one or more for general form. | signatures
	// 在扁平形式下保存一个条目，在通用形式下保存一个或多个条目。
	signatures []jwsJSONSignature
}

// signJSON builds a flattened or general JWS JSON serialization with one signature. | signJSON 构建
// 带一个签名的扁平或通用 JWS JSON 序列化。
//
// It delegates to SignMulti so the single-signature and multi-signature forms share every header,
// RFC 7797 and serialization rule. When Detached is set the payload member is omitted from the
// serialization while the signature still covers the payload. | 它委托给 SignMulti，使单签名与多签名
// 形式共享全部头部、RFC 7797 与序列化规则。设置 Detached 时，序列化省略 payload 成员，但签名仍
// 覆盖载荷。
func signJSON(payload []byte, key *Key, header JWSHeader, opts SignOptions) (string, error) {
	return SignMulti(payload, []Signer{{Key: key, Header: header, LowS: opts.LowS}}, MultiSignOptions{
		Detached:      opts.Detached,
		Serialization: opts.Serialization,
	})
}

// parseJWSJSON parses a flattened or general JWS JSON serialization. | parseJWSJSON 解析扁平或通用
// JWS JSON 序列化。
//
// It is strict: the document must be one JSON object, duplicate member names at any nesting level
// are refused, general and flattened members may not be mixed, and a general signatures array must
// be non-empty. Unknown extension members are ignored, as RFC 7515 permits. | 解析是严格的：文档必须
// 是单个 JSON 对象，任意层级的重复成员名都会被拒绝，通用与扁平成员不得混用，通用 signatures 数组
// 不得为空。未知扩展成员按 RFC 7515 允许的方式忽略。
func parseJWSJSON(raw string) (jwsJSONDoc, error) {
	b := []byte(raw)
	if !isJSONObject(b) {
		return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON is not a JSON object | JWS JSON 不是 JSON 对象")
	}
	if hasDuplicateKeys(b) {
		return jwsJSONDoc{}, errs.Detail(ErrInvalidHeader, "JWS JSON has duplicate members | JWS JSON 存在重复成员")
	}
	var (
		doc                        jwsJSONDoc
		protected, signature       string
		header                     Header
		hasProtected, hasSignature bool
		hasHeader, hasSignatures   bool
	)
	i := skipSpace(b, 0)
	i++ // consume '{'
	for {
		i = skipSpace(b, i)
		if i >= len(b) {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON is truncated | JWS JSON 被截断")
		}
		if b[i] == '}' {
			i++
			break
		}
		if b[i] != '"' {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON member name is not a string | JWS JSON 成员名不是字符串")
		}
		keyEnd, ok := scanJSONString(b, i)
		if !ok {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON member name is unterminated | JWS JSON 成员名未闭合")
		}
		var key string
		if err := unmarshal(b[i:keyEnd], &key); err != nil {
			return jwsJSONDoc{}, errs.WrapDetail(err, ErrMalformed, "JWS JSON member name decode | JWS JSON 成员名解码")
		}
		i = skipSpace(b, keyEnd)
		if i >= len(b) || b[i] != ':' {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON member has no value | JWS JSON 成员缺少取值")
		}
		i = skipSpace(b, i+1)
		valueStart := i
		valueEnd, ok, _ := scanJSONValue(b, i, 0)
		if !ok {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON member value is invalid | JWS JSON 成员取值非法")
		}
		value := b[valueStart:valueEnd]
		switch key {
		case "payload":
			s, err := decodeJSONStringValue(value)
			if err != nil {
				return jwsJSONDoc{}, err
			}
			doc.payload, doc.hasPayload = s, true
		case "protected":
			s, err := decodeJSONStringValue(value)
			if err != nil {
				return jwsJSONDoc{}, err
			}
			protected, hasProtected = s, true
		case "signature":
			s, err := decodeJSONStringValue(value)
			if err != nil {
				return jwsJSONDoc{}, err
			}
			signature, hasSignature = s, true
		case "header":
			h, err := parseJWSUnprotectedHeader(value)
			if err != nil {
				return jwsJSONDoc{}, err
			}
			header, hasHeader = h, true
		case "signatures":
			sigs, err := parseJWSSignatures(value)
			if err != nil {
				return jwsJSONDoc{}, err
			}
			doc.signatures, hasSignatures = sigs, true
		}
		i = skipSpace(b, valueEnd)
		if i >= len(b) {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON is truncated | JWS JSON 被截断")
		}
		switch b[i] {
		case ',':
			i++
		case '}':
			i++
		default:
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON member separator is invalid | JWS JSON 成员分隔符非法")
		}
		if b[i-1] == '}' {
			break
		}
	}
	if skipSpace(b, i) != len(b) {
		return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON has trailing data | JWS JSON 存在尾随数据")
	}
	if hasSignatures {
		if hasProtected || hasHeader || hasSignature {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON mixes general and flattened members | JWS JSON 混用通用与扁平成员")
		}
		doc.general = true
		if len(doc.signatures) == 0 {
			return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON has an empty signatures array | JWS JSON 的 signatures 数组为空")
		}
		return doc, nil
	}
	if !hasSignature {
		return jwsJSONDoc{}, errs.Detail(ErrMalformed, "JWS JSON has no signature | JWS JSON 缺少 signature")
	}
	doc.signatures = []jwsJSONSignature{{protected: protected, header: header, signature: signature}}
	return doc, nil
}

// parseJWSSignatures parses the general-form signatures array. | parseJWSSignatures 解析通用形式的
// signatures 数组。
func parseJWSSignatures(arr []byte) ([]jwsJSONSignature, error) {
	i := skipSpace(arr, 0)
	if i >= len(arr) || arr[i] != '[' {
		return nil, errs.Detail(ErrMalformed, "JWS JSON signatures is not an array | JWS JSON 的 signatures 不是数组")
	}
	i++
	var out []jwsJSONSignature
	for {
		i = skipSpace(arr, i)
		if i >= len(arr) {
			return nil, errs.Detail(ErrMalformed, "JWS JSON signatures array is truncated | JWS JSON 的 signatures 数组被截断")
		}
		if arr[i] == ']' {
			i++
			break
		}
		if arr[i] != '{' {
			return nil, errs.Detail(ErrMalformed, "JWS JSON signature entry is not an object | JWS JSON 签名条目不是对象")
		}
		end, ok, _ := scanJSONValue(arr, i, 0)
		if !ok {
			return nil, errs.Detail(ErrMalformed, "JWS JSON signature entry is invalid | JWS JSON 签名条目非法")
		}
		sig, err := parseJWSSignatureEntry(arr[i:end])
		if err != nil {
			return nil, err
		}
		out = append(out, sig)
		i = skipSpace(arr, end)
		if i >= len(arr) {
			return nil, errs.Detail(ErrMalformed, "JWS JSON signatures array is truncated | JWS JSON 的 signatures 数组被截断")
		}
		switch arr[i] {
		case ',':
			i++
		case ']':
			i++
		default:
			return nil, errs.Detail(ErrMalformed, "JWS JSON signatures separator is invalid | JWS JSON 的 signatures 分隔符非法")
		}
		if arr[i-1] == ']' {
			break
		}
	}
	if skipSpace(arr, i) != len(arr) {
		return nil, errs.Detail(ErrMalformed, "JWS JSON signatures has trailing data | JWS JSON 的 signatures 存在尾随数据")
	}
	return out, nil
}

// parseJWSSignatureEntry parses one general-form signature entry. | parseJWSSignatureEntry 解析一个
// 通用形式的签名条目。
func parseJWSSignatureEntry(obj []byte) (jwsJSONSignature, error) {
	var sig jwsJSONSignature
	hasSignature := false
	i := skipSpace(obj, 0)
	i++ // consume '{'
	for {
		i = skipSpace(obj, i)
		if i >= len(obj) {
			return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature entry is truncated | JWS JSON 签名条目被截断")
		}
		if obj[i] == '}' {
			i++
			break
		}
		if obj[i] != '"' {
			return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature member name is not a string | JWS JSON 签名成员名不是字符串")
		}
		keyEnd, ok := scanJSONString(obj, i)
		if !ok {
			return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature member name is unterminated | JWS JSON 签名成员名未闭合")
		}
		var key string
		if err := unmarshal(obj[i:keyEnd], &key); err != nil {
			return jwsJSONSignature{}, errs.WrapDetail(err, ErrMalformed, "JWS JSON signature member name decode | JWS JSON 签名成员名解码")
		}
		i = skipSpace(obj, keyEnd)
		if i >= len(obj) || obj[i] != ':' {
			return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature member has no value | JWS JSON 签名成员缺少取值")
		}
		i = skipSpace(obj, i+1)
		valueStart := i
		valueEnd, ok, _ := scanJSONValue(obj, i, 0)
		if !ok {
			return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature member value is invalid | JWS JSON 签名成员取值非法")
		}
		value := obj[valueStart:valueEnd]
		switch key {
		case "protected":
			s, err := decodeJSONStringValue(value)
			if err != nil {
				return jwsJSONSignature{}, err
			}
			sig.protected = s
		case "signature":
			s, err := decodeJSONStringValue(value)
			if err != nil {
				return jwsJSONSignature{}, err
			}
			sig.signature, hasSignature = s, true
		case "header":
			h, err := parseJWSUnprotectedHeader(value)
			if err != nil {
				return jwsJSONSignature{}, err
			}
			sig.header = h
		}
		i = skipSpace(obj, valueEnd)
		if i >= len(obj) {
			return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature entry is truncated | JWS JSON 签名条目被截断")
		}
		switch obj[i] {
		case ',':
			i++
		case '}':
			i++
		default:
			return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature member separator is invalid | JWS JSON 签名成员分隔符非法")
		}
		if obj[i-1] == '}' {
			break
		}
	}
	if skipSpace(obj, i) != len(obj) {
		return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature entry has trailing data | JWS JSON 签名条目存在尾随数据")
	}
	if !hasSignature {
		return jwsJSONSignature{}, errs.Detail(ErrMalformed, "JWS JSON signature entry has no signature | JWS JSON 签名条目缺少 signature")
	}
	return sig, nil
}

// parseJWSUnprotectedHeader decodes the optional unprotected header object. | parseJWSUnprotectedHeader
// 解码可选的、非保护的头部对象。
func parseJWSUnprotectedHeader(value []byte) (Header, error) {
	if len(value) == 0 || value[0] != '{' {
		return nil, errs.Detail(ErrInvalidHeader, "unprotected header is not an object | 非保护头部不是对象")
	}
	m, err := headerJSON(value)
	if err != nil {
		return nil, err
	}
	return Header(m), nil
}

// decodeJSONStringValue decodes one JSON string member value. | decodeJSONStringValue 解码一个 JSON
// 字符串成员取值。
func decodeJSONStringValue(v []byte) (string, error) {
	if len(v) == 0 || v[0] != '"' {
		return "", errs.Detail(ErrMalformed, "JWS JSON member is not a string | JWS JSON 成员不是字符串")
	}
	var s string
	if err := unmarshal(v, &s); err != nil {
		return "", errs.WrapDetail(err, ErrMalformed, "JWS JSON string decode | JWS JSON 字符串解码")
	}
	return s, nil
}
