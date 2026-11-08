package ntlm

import (
	"bytes"

	"github.com/shibingli/ydx/errs"
)

// DER tags and object identifiers used by the minimal SPNEGO framing. | 最小
// SPNEGO 分帧使用的 DER 标签与对象标识符。
var (
	spnegoMechOID = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmMechOID   = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

// NegState is the SPNEGO negotiation state carried by a NegTokenResp. | NegState
// 是 NegTokenResp 携带的 SPNEGO 协商状态。
type NegState uint8

// SPNEGO negotiation states from RFC 4178. | RFC 4178 的 SPNEGO 协商状态。
const (
	// NegStateAcceptCompleted means the acceptor completed the negotiation. |
	// NegStateAcceptCompleted 表示接受方完成协商。
	NegStateAcceptCompleted NegState = 0
	// NegStateAcceptIncomplete means more tokens are required. | NegStateAcceptIncomplete
	// 表示还需要更多令牌。
	NegStateAcceptIncomplete NegState = 1
	// NegStateReject means the negotiation failed. | NegStateReject 表示协商失败。
	NegStateReject NegState = 2
	// NegStateRequestMIC requests a mechListMIC. | NegStateRequestMIC 请求 mechListMIC。
	NegStateRequestMIC NegState = 3
)

// String returns a stable name for the negotiation state. | String 返回协商状态的稳定名称。
func (s NegState) String() string {
	switch s {
	case NegStateAcceptCompleted:
		return "accept-completed"
	case NegStateAcceptIncomplete:
		return "accept-incomplete"
	case NegStateReject:
		return "reject"
	case NegStateRequestMIC:
		return "request-mic"
	default:
		return "unknown"
	}
}

// SPNEGOToken is a parsed SPNEGO NegTokenInit or NegTokenResp, possibly wrapped
// in the GSS-API InitialContextToken header. | SPNEGOToken 是解析后的 SPNEGO
// NegTokenInit 或 NegTokenResp，可能带有 GSS-API InitialContextToken 外层包装。
type SPNEGOToken struct {
	// SupportedMech is the DER OID value of the supportedMech field. | SupportedMech 是
	// supportedMech 字段的 DER OID 值。
	SupportedMech []byte
	// ResponseToken is the responseToken field of a NegTokenResp. | ResponseToken 是
	// NegTokenResp 的 responseToken 字段。
	ResponseToken []byte
	// MechToken is the mechToken field of a NegTokenInit. | MechToken 是 NegTokenInit 的
	// mechToken 字段。
	MechToken []byte
	// MechListMIC is the optional mechListMIC field. | MechListMIC 是可选 mechListMIC 字段。
	MechListMIC []byte
	// MechTypes lists the DER OID values advertised by a NegTokenInit or by the
	// MS-SPNG mechTypes extension of a NegTokenResp. | MechTypes 列出 NegTokenInit
	// 或 NegTokenResp 的 MS-SPNG mechTypes 扩展所声明的 DER OID 值。
	MechTypes [][]byte
	// MechTypesDER is the canonical DER SEQUENCE OF OID over which mechListMIC is
	// computed. | MechTypesDER 是计算 mechListMIC 所用的规范 DER SEQUENCE OF OID。
	MechTypesDER []byte
	// NegState is the negotiation state when HasNegState is true. | 当 HasNegState
	// 为 true 时，NegState 是协商状态。
	NegState NegState
	// HasNegState reports whether a negState field was present. | HasNegState 报告是否存在
	// negState 字段。
	HasNegState bool
	// HasMechListMIC reports whether a mechListMIC field was present, including
	// an empty but present OCTET STRING. | HasMechListMIC 报告是否存在 mechListMIC
	// 字段，包括存在但为空的 OCTET STRING。
	HasMechListMIC bool
}

// Token returns ResponseToken when it is non-empty, otherwise MechToken. | Token
// 在 ResponseToken 非空时返回它，否则返回 MechToken。
func (t *SPNEGOToken) Token() []byte {
	if len(t.ResponseToken) > 0 {
		return t.ResponseToken
	}
	return t.MechToken
}

// SupportsNTLM reports whether the token advertises the NTLMSSP mechanism. A
// token that advertises no mechanism list is treated as permissive because the
// LDAP SASL mechanism already selected NTLM. | SupportsNTLM 报告令牌是否声明 NTLMSSP
// 机制。未声明机制列表的令牌被视为宽松允许，因为 LDAP SASL 机制已选择 NTLM。
func (t *SPNEGOToken) SupportsNTLM() bool {
	if len(t.SupportedMech) > 0 {
		return bytes.Equal(t.SupportedMech, ntlmMechOID)
	}
	if len(t.MechTypes) == 0 {
		return true
	}
	for _, mechanism := range t.MechTypes {
		if bytes.Equal(mechanism, ntlmMechOID) {
			return true
		}
	}
	return false
}

// tokenMechTypes returns the DER OID values carried by a token, decoding
// MechTypesDER when MechTypes is empty. | tokenMechTypes 返回令牌携带的 DER OID 值；
// 当 MechTypes 为空时解码 MechTypesDER。
func tokenMechTypes(token *SPNEGOToken) ([][]byte, error) {
	if len(token.MechTypes) > 0 {
		return token.MechTypes, nil
	}
	if len(token.MechTypesDER) == 0 {
		return nil, errs.Detail(ErrSPNEGO, "token has no mechTypes | 令牌没有 mechTypes")
	}
	tag, value, rest, err := readDER(token.MechTypesDER)
	if err != nil {
		return nil, err
	}
	if tag != 0x30 || len(rest) != 0 {
		return nil, errs.Detail(ErrSPNEGO, "mechTypes is not a single SEQUENCE | mechTypes 不是单个 SEQUENCE")
	}
	return parseMechTypes(value)
}

// EncodeSPNEGOToken encodes a SPNEGO token. When initChoice is true it emits a
// NegTokenInit wrapped in a GSS-API InitialContextToken; otherwise it emits a
// bare NegTokenResp. NegTokenInit requires MechTypes; NegTokenResp encodes
// MechTypes as the MS-SPNG mechTypes [4] extension when present. NegState,
// SupportedMech, MechToken or ResponseToken, and MechListMIC are emitted when
// their fields are present. All DER lengths are canonical. | EncodeSPNEGOToken
// 编码 SPNEGO 令牌。initChoice 为 true 时输出包装在 GSS-API InitialContextToken 中的
// NegTokenInit；否则输出裸 NegTokenResp。NegTokenInit 必须提供 MechTypes；
// NegTokenResp 在存在 MechTypes 时以 MS-SPNG 的 mechTypes [4] 扩展编码。NegState、
// SupportedMech、MechToken 或 ResponseToken、MechListMIC 在字段存在时输出。所有 DER
// 长度均为规范形式。
func EncodeSPNEGOToken(token *SPNEGOToken, initChoice bool) ([]byte, error) {
	if token == nil {
		return nil, errs.Detail(ErrSPNEGO, "token is nil | 令牌为空")
	}
	if token.HasNegState && token.NegState > NegStateRequestMIC {
		return nil, errs.Detail(ErrSPNEGO, "negState value %d is invalid | negState 值 %d 非法", token.NegState, token.NegState)
	}
	builder := &derBuilder{}
	if initChoice {
		mechanisms, err := tokenMechTypes(token)
		if err != nil {
			return nil, err
		}
		mechList, err := EncodeMechTypeList(mechanisms)
		if err != nil {
			return nil, err
		}
		fields := [][]byte{builder.seq(0xA0, mechList)}
		if token.MechToken != nil {
			fields = append(fields, builder.seq(0xA2, builder.tlv(0x04, token.MechToken)))
		}
		if token.HasMechListMIC || token.MechListMIC != nil {
			fields = append(fields, builder.seq(0xA3, builder.tlv(0x04, token.MechListMIC)))
		}
		negTokenInit := builder.seq(0x30, fields...)
		choice := builder.seq(0xA0, negTokenInit)
		spnegoOID := builder.tlv(0x06, spnegoMechOID)
		initial := builder.seq(0x60, spnegoOID, choice)
		if builder.err != nil {
			return nil, builder.err
		}
		return initial, nil
	}
	fields := make([][]byte, 0, 5)
	if token.HasNegState {
		fields = append(fields, builder.seq(0xA0, builder.tlv(0x0A, []byte{byte(token.NegState)})))
	}
	if len(token.SupportedMech) > 0 {
		fields = append(fields, builder.seq(0xA1, builder.tlv(0x06, token.SupportedMech)))
	}
	if token.ResponseToken != nil {
		fields = append(fields, builder.seq(0xA2, builder.tlv(0x04, token.ResponseToken)))
	}
	if token.HasMechListMIC || token.MechListMIC != nil {
		fields = append(fields, builder.seq(0xA3, builder.tlv(0x04, token.MechListMIC)))
	}
	if len(token.MechTypes) > 0 || len(token.MechTypesDER) > 0 {
		mechanisms, err := tokenMechTypes(token)
		if err != nil {
			return nil, err
		}
		mechList, err := EncodeMechTypeList(mechanisms)
		if err != nil {
			return nil, err
		}
		fields = append(fields, builder.seq(0xA4, mechList))
	}
	negotiation := builder.seq(0x30, fields...)
	response := builder.seq(0xA1, negotiation)
	if builder.err != nil {
		return nil, builder.err
	}
	return response, nil
}

// EncodeSPNEGONegotiateInit wraps a Type 1 NEGOTIATE_MESSAGE in a GSS-API
// InitialContextToken carrying a NegTokenInit that advertises only NTLMSSP. This
// is the initial response Active Directory expects for SASL GSS-SPNEGO. |
// EncodeSPNEGONegotiateInit 把 Type 1 NEGOTIATE_MESSAGE 包装为携带 NegTokenInit 的
// GSS-API InitialContextToken，仅声明 NTLMSSP。这是 Active Directory 对 SASL
// GSS-SPNEGO 期望的初始响应。
func EncodeSPNEGONegotiateInit(mechToken []byte) ([]byte, error) {
	return EncodeSPNEGOToken(&SPNEGOToken{
		MechTypes: [][]byte{ntlmMechOID},
		MechToken: mechToken,
	}, true)
}

// EncodeSPNEGOResponse wraps a Type 3 AUTHENTICATE_MESSAGE in a bare
// NegTokenResp. The client omits negState, as RFC 4178 reserves
// accept-completed for the acceptor. | EncodeSPNEGOResponse 把 Type 3
// AUTHENTICATE_MESSAGE 包装为裸 NegTokenResp。客户端省略 negState，因为 RFC 4178 将
// accept-completed 保留给接受方。
func EncodeSPNEGOResponse(mechToken []byte) ([]byte, error) {
	return EncodeSPNEGOToken(&SPNEGOToken{ResponseToken: mechToken}, false)
}

// EncodeSPNEGOResponseWithMIC wraps a Type 3 AUTHENTICATE_MESSAGE and an
// optional mechListMIC in a bare NegTokenResp. A nil mechListMIC omits the field.
// | EncodeSPNEGOResponseWithMIC 把 Type 3 AUTHENTICATE_MESSAGE 与可选 mechListMIC
// 包装为裸 NegTokenResp。nil mechListMIC 省略该字段。
func EncodeSPNEGOResponseWithMIC(mechToken, mechListMIC []byte) ([]byte, error) {
	return EncodeSPNEGOToken(&SPNEGOToken{
		ResponseToken:  mechToken,
		MechListMIC:    mechListMIC,
		HasMechListMIC: mechListMIC != nil,
	}, false)
}

// ParseSPNEGOToken parses a SPNEGO token in any of the forms Active Directory
// uses over SASL: a GSS-API InitialContextToken wrapping NegTokenInit or
// NegTokenResp, a bare NegTokenInit/NegTokenResp choice, or a bare SEQUENCE.
// Lengths and structure are fully bounds-checked. | ParseSPNEGOToken 解析 Active
// Directory 在 SASL 上使用的任一 SPNEGO 令牌形式：包装 NegTokenInit 或 NegTokenResp 的
// GSS-API InitialContextToken、裸 NegTokenInit/NegTokenResp 选择，或裸 SEQUENCE。长度
// 与结构均进行完整边界检查。
func ParseSPNEGOToken(data []byte) (*SPNEGOToken, error) {
	if len(data) == 0 {
		return nil, errs.Detail(ErrSPNEGO, "token is empty | 令牌为空")
	}
	tag, value, rest, err := readDER(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errs.Detail(ErrSPNEGO, "bytes follow the SPNEGO token | SPNEGO 令牌之后仍有字节")
	}
	switch tag {
	case 0x60:
		oidTag, oid, inner, err := readDER(value)
		if err != nil {
			return nil, err
		}
		if oidTag != 0x06 {
			return nil, errs.Detail(ErrSPNEGO, "initial context token does not start with an OID | 初始上下文令牌未以 OID 开始")
		}
		if !bytes.Equal(oid, spnegoMechOID) {
			return nil, errs.Detail(ErrSPNEGO, "initial context token is not SPNEGO | 初始上下文令牌不是 SPNEGO")
		}
		if len(inner) == 0 {
			return nil, errs.Detail(ErrSPNEGO, "initial context token has no negotiation token | 初始上下文令牌没有协商令牌")
		}
		token, consumed, err := parseNegToken(inner)
		if err != nil {
			return nil, err
		}
		if consumed != len(inner) {
			return nil, errs.Detail(ErrSPNEGO, "bytes follow the negotiation token | 协商令牌之后仍有字节")
		}
		return token, nil
	case 0xA0, 0xA1, 0x30:
		token, consumed, err := parseNegToken(data)
		if err != nil {
			return nil, err
		}
		if consumed != len(data) {
			return nil, errs.Detail(ErrSPNEGO, "bytes follow the negotiation token | 协商令牌之后仍有字节")
		}
		return token, nil
	default:
		return nil, errs.Detail(ErrSPNEGO, "unexpected SPNEGO tag 0x%02x | 意外的 SPNEGO 标签 0x%02x", tag, tag)
	}
}

// parseNegToken parses a NegTokenInit/NegTokenResp choice or bare sequence and
// returns the number of bytes consumed. | parseNegToken 解析 NegTokenInit/NegTokenResp
// 选择或裸序列并返回消耗的字节数。
func parseNegToken(data []byte) (*SPNEGOToken, int, error) {
	tag, value, rest, err := readDER(data)
	if err != nil {
		return nil, 0, err
	}
	consumed := len(data) - len(rest)
	switch tag {
	case 0xA0, 0xA1:
		innerTag, innerValue, innerRest, err := readDER(value)
		if err != nil {
			return nil, 0, err
		}
		if len(innerRest) != 0 {
			return nil, 0, errs.Detail(ErrSPNEGO, "bytes follow the negotiation SEQUENCE | 协商 SEQUENCE 之后仍有字节")
		}
		if innerTag != 0x30 {
			return nil, 0, errs.Detail(ErrSPNEGO, "negotiation token is not a SEQUENCE | 协商令牌不是 SEQUENCE")
		}
		token, err := parseNegFields(innerValue, tag == 0xA0)
		if err != nil {
			return nil, 0, err
		}
		return token, consumed, nil
	case 0x30:
		token, err := parseNegFields(value, false)
		if err != nil {
			return nil, 0, err
		}
		return token, consumed, nil
	default:
		return nil, 0, errs.Detail(ErrSPNEGO, "unexpected negotiation tag 0x%02x | 意外的协商标签 0x%02x", tag, tag)
	}
}

// parseNegFields parses the fields of a NegTokenInit or NegTokenResp. When
// initChoice is true the token is known to be a NegTokenInit; a bare SEQUENCE is
// disambiguated by the inner tag of each context-specific field. | parseNegFields
// 解析 NegTokenInit 或 NegTokenResp 的字段。initChoice 为 true 时令牌已知为
// NegTokenInit；裸 SEQUENCE 通过每个上下文相关字段的内部标签区分。
func parseNegFields(content []byte, initChoice bool) (*SPNEGOToken, error) {
	token := &SPNEGOToken{}
	initSyntax := initChoice
	seen := make(map[byte]struct{}, 5)
	for len(content) > 0 {
		tag, value, rest, err := readDER(content)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[tag]; duplicate {
			return nil, errs.Detail(ErrSPNEGO, "duplicate SPNEGO field 0x%02x | 重复的 SPNEGO 字段 0x%02x", tag, tag)
		}
		seen[tag] = struct{}{}
		switch tag {
		case 0xA0:
			innerTag, innerValue, err := parseTaggedValue(value)
			if err != nil {
				return nil, err
			}
			if initSyntax || innerTag == 0x30 {
				if innerTag != 0x30 {
					return nil, errs.Detail(ErrSPNEGO, "mechTypes is not a SEQUENCE | mechTypes 不是 SEQUENCE")
				}
				mechanisms, err := parseMechTypes(innerValue)
				if err != nil {
					return nil, err
				}
				token.MechTypes = mechanisms
				token.MechTypesDER = append([]byte(nil), value...)
				initSyntax = true
			} else {
				if innerTag != 0x0A {
					return nil, errs.Detail(ErrSPNEGO, "negState is not an ENUMERATED | negState 不是 ENUMERATED")
				}
				state, err := parseNegState(innerValue)
				if err != nil {
					return nil, err
				}
				token.NegState = state
				token.HasNegState = true
			}
		case 0xA1:
			innerTag, innerValue, err := parseTaggedValue(value)
			if err != nil {
				return nil, err
			}
			if initSyntax || innerTag == 0x03 {
				if innerTag != 0x03 {
					return nil, errs.Detail(ErrSPNEGO, "reqFlags is not a BIT STRING | reqFlags 不是 BIT STRING")
				}
			} else {
				if innerTag != 0x06 {
					return nil, errs.Detail(ErrSPNEGO, "supportedMech is not an OID | supportedMech 不是 OID")
				}
				if len(innerValue) == 0 {
					return nil, errs.Detail(ErrSPNEGO, "supportedMech OID is empty | supportedMech OID 为空")
				}
				token.SupportedMech = append([]byte(nil), innerValue...)
			}
		case 0xA2:
			innerTag, innerValue, err := parseTaggedValue(value)
			if err != nil {
				return nil, err
			}
			if innerTag != 0x04 {
				return nil, errs.Detail(ErrSPNEGO, "mechanism token is not an OCTET STRING | 机制令牌不是 OCTET STRING")
			}
			copied := append([]byte(nil), innerValue...)
			if initSyntax {
				token.MechToken = copied
			} else {
				token.ResponseToken = copied
			}
		case 0xA3:
			innerTag, innerValue, err := parseTaggedValue(value)
			if err != nil {
				return nil, err
			}
			if innerTag != 0x04 {
				return nil, errs.Detail(ErrSPNEGO, "mechListMIC is not an OCTET STRING | mechListMIC 不是 OCTET STRING")
			}
			if token.HasMechListMIC {
				return nil, errs.Detail(ErrSPNEGO, "duplicate mechListMIC | 重复的 mechListMIC")
			}
			token.MechListMIC = append([]byte(nil), innerValue...)
			token.HasMechListMIC = true
		case 0xA4:
			innerTag, innerValue, err := parseTaggedValue(value)
			if err != nil {
				return nil, err
			}
			if initSyntax {
				// NegTokenInit2 carries mechListMIC in field [4]; field [3] is
				// negHints and is not part of the NTLM exchange. | NegTokenInit2
				// 在字段 [4] 中携带 mechListMIC；字段 [3] 是 negHints，不属于 NTLM
				// 交换。
				if innerTag != 0x04 {
					return nil, errs.Detail(ErrSPNEGO, "mechListMIC is not an OCTET STRING | mechListMIC 不是 OCTET STRING")
				}
				if token.HasMechListMIC {
					return nil, errs.Detail(ErrSPNEGO, "duplicate mechListMIC | 重复的 mechListMIC")
				}
				token.MechListMIC = append([]byte(nil), innerValue...)
				token.HasMechListMIC = true
			} else {
				// The MS-SPNG negTokenResp extension advertises mechTypes in
				// field [4]. | MS-SPNG negTokenResp 扩展在字段 [4] 中声明 mechTypes。
				if innerTag != 0x30 {
					return nil, errs.Detail(ErrSPNEGO, "mechTypes is not a SEQUENCE | mechTypes 不是 SEQUENCE")
				}
				mechanisms, err := parseMechTypes(innerValue)
				if err != nil {
					return nil, err
				}
				token.MechTypes = mechanisms
				token.MechTypesDER = append([]byte(nil), value...)
			}
		default:
			return nil, errs.Detail(ErrSPNEGO, "unexpected SPNEGO field 0x%02x | 意外的 SPNEGO 字段 0x%02x", tag, tag)
		}
		content = rest
	}
	if initChoice && len(token.MechTypes) == 0 {
		return nil, errs.Detail(ErrSPNEGO, "NegTokenInit has no mechTypes | NegTokenInit 没有 mechTypes")
	}
	return token, nil
}

// parseTaggedValue unwraps a context-specific field holding exactly one DER
// value. | parseTaggedValue 解包恰好包含一个 DER 值的上下文相关字段。
func parseTaggedValue(value []byte) (byte, []byte, error) {
	tag, inner, rest, err := readDER(value)
	if err != nil {
		return 0, nil, err
	}
	if len(rest) != 0 {
		return 0, nil, errs.Detail(ErrSPNEGO, "context field holds more than one value | 上下文字段包含多个值")
	}
	return tag, inner, nil
}

// parseMechTypes parses a SEQUENCE OF OID value list. | parseMechTypes 解析 SEQUENCE
// OF OID 值列表。
func parseMechTypes(value []byte) ([][]byte, error) {
	mechanisms := make([][]byte, 0, 4)
	for len(value) > 0 {
		tag, oid, rest, err := readDER(value)
		if err != nil {
			return nil, err
		}
		if tag != 0x06 || len(oid) == 0 {
			return nil, errs.Detail(ErrSPNEGO, "mechTypes entry is not an OID | mechTypes 条目不是 OID")
		}
		mechanisms = append(mechanisms, append([]byte(nil), oid...))
		value = rest
	}
	if len(mechanisms) == 0 {
		return nil, errs.Detail(ErrSPNEGO, "mechTypes is empty | mechTypes 为空")
	}
	return mechanisms, nil
}

// parseNegState parses the ENUMERATED body of a negState field. | parseNegState
// 解析 negState 字段的 ENUMERATED 内容。
func parseNegState(value []byte) (NegState, error) {
	if len(value) != 1 {
		return 0, errs.Detail(ErrSPNEGO, "negState has length %d, want 1 | negState 长度为 %d，期望 1", len(value), len(value))
	}
	state := NegState(value[0])
	if state > NegStateRequestMIC {
		return 0, errs.Detail(ErrSPNEGO, "negState value %d is invalid | negState 值 %d 非法", value[0], value[0])
	}
	return state, nil
}

// derBuilder accumulates DER encoding errors so nested construction stays
// linear. | derBuilder 累积 DER 编码错误，使嵌套构造保持线性。
type derBuilder struct {
	err error
}

// tlv appends a DER tag-length-value. | tlv 追加一个 DER 标签-长度-值。
func (b *derBuilder) tlv(tag byte, value []byte) []byte {
	if b.err != nil {
		return nil
	}
	encoded, err := derTLV(tag, value)
	if err != nil {
		b.err = err
		return nil
	}
	return encoded
}

// seq appends a DER constructed value whose content is the concatenation of
// children. | seq 追加一个 DER 构造值，其内容为 children 的连接。
func (b *derBuilder) seq(tag byte, children ...[]byte) []byte {
	if b.err != nil {
		return nil
	}
	size := 0
	for _, child := range children {
		size += len(child)
	}
	content := make([]byte, 0, size)
	for _, child := range children {
		content = append(content, child...)
	}
	return b.tlv(tag, content)
}

// derTLV encodes one DER tag-length-value. | derTLV 编码一个 DER 标签-长度-值。
func derTLV(tag byte, value []byte) ([]byte, error) {
	length, err := derLength(len(value))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(length)+len(value))
	out = append(out, tag)
	out = append(out, length...)
	out = append(out, value...)
	return out, nil
}

// derLength encodes a DER length in minimal form. | derLength 以最小形式编码 DER 长度。
func derLength(n int) ([]byte, error) {
	if n < 0 || uint64(n) > 0xffffffff {
		return nil, errs.Detail(ErrSPNEGO, "DER length %d is out of range | DER 长度 %d 超出范围", n, n)
	}
	if n < 0x80 {
		return []byte{byte(n)}, nil
	}
	count := 0
	for value := n; value > 0; value >>= 8 {
		count++
	}
	out := make([]byte, 1+count)
	out[0] = 0x80 | byte(count)
	for index := 0; index < count; index++ {
		out[1+index] = byte(n >> (8 * (count - 1 - index)))
	}
	return out, nil
}

// readDER reads one DER tag-length-value with strict bounds and minimal-length
// checks. | readDER 读取一个 DER 标签-长度-值，并进行严格边界与最小长度检查。
func readDER(data []byte) (tag byte, value, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "DER value is truncated | DER 值被截断")
	}
	tag = data[0]
	if tag&0x1f == 0x1f {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "high-tag-number form is unsupported | 不支持高标签号形式")
	}
	first := data[1]
	if first < 0x80 {
		length := int(first)
		if length > len(data)-2 {
			return 0, nil, nil, errs.Detail(ErrSPNEGO, "DER length %d exceeds input | DER 长度 %d 超出输入", length, length)
		}
		return tag, data[2 : 2+length], data[2+length:], nil
	}
	count := int(first & 0x7f)
	if count == 0 {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "indefinite DER length is unsupported | 不支持不定长 DER 长度")
	}
	if count > 4 {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "DER length uses %d bytes | DER 长度使用 %d 字节", count, count)
	}
	if len(data) < 2+count {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "DER length is truncated | DER 长度被截断")
	}
	if data[2] == 0 {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "DER length is not minimal | DER 长度不是最小形式")
	}
	var length uint64
	for index := 0; index < count; index++ {
		length = length<<8 | uint64(data[2+index])
	}
	if length < 0x80 {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "DER length is not minimal | DER 长度不是最小形式")
	}
	body := data[2+count:]
	if length > uint64(len(body)) {
		return 0, nil, nil, errs.Detail(ErrSPNEGO, "DER length %d exceeds input | DER 长度 %d 超出输入", length, length)
	}
	return tag, body[:int(length)], body[int(length):], nil
}
