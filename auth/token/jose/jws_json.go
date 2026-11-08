package jose

import (
	"github.com/shibingli/ydx/errs"
)

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

// signJSON builds a flattened or general JWS JSON serialization. | signJSON 构建扁平或通用 JWS JSON
// 序列化。
//
// All header parameters are emitted in the protected header, the signature entry is singular, and
// members are written in a fixed order so the output is deterministic. When Detached is set the
// payload member is omitted from the serialization while the signature still covers the base64url
// payload segment. | 所有头部参数都写入受保护头部，签名条目只有一个，成员按固定顺序写出，因此输出
// 是确定的。设置 Detached 时，序列化省略 payload 成员，但签名仍覆盖 base64url 载荷段。
func signJSON(payload []byte, key *Key, header JWSHeader, opts SignOptions) (string, error) {
	headerBytes, err := encodeJWSHeader(header)
	if err != nil {
		return "", err
	}
	protected := EncodeSegment(headerBytes)
	payloadSeg := EncodeSegment(payload)
	input := make([]byte, 0, len(protected)+1+len(payloadSeg))
	input = append(input, protected...)
	input = append(input, '.')
	input = append(input, payloadSeg...)
	sig, err := signJWSWithLowS(header.Alg, key, input, opts.LowS)
	if err != nil {
		return "", err
	}
	sigSeg := EncodeSegment(sig)

	out := make([]byte, 0, len(protected)+len(payloadSeg)+len(sigSeg)+64)
	out = append(out, '{')
	if !opts.Detached {
		out = append(out, `"payload":`...)
		out = appendJSONString(out, payloadSeg)
		out = append(out, ',')
	}
	if opts.Serialization == SerializationGeneral {
		out = append(out, `"signatures":[{"protected":`...)
		out = appendJSONString(out, protected)
		out = append(out, `,"signature":`...)
		out = appendJSONString(out, sigSeg)
		out = append(out, `}]}`...)
		return string(out), nil
	}
	out = append(out, `"protected":`...)
	out = appendJSONString(out, protected)
	out = append(out, `,"signature":`...)
	out = appendJSONString(out, sigSeg)
	out = append(out, '}')
	return string(out), nil
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
