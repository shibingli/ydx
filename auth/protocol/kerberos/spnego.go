package kerberos

import (
	"github.com/shibingli/ydx/errs"
)

// negState is an RFC 4178 NegTokenResp negotiation state. | negState 是 RFC 4178
// NegTokenResp 协商状态。
type negState int32

// The RFC 4178 negotiation states. | RFC 4178 协商状态。
const (
	negStateAcceptCompleted  negState = 0
	negStateAcceptIncomplete negState = 1
	negStateReject           negState = 2
	negStateRequestMIC       negState = 3
)

// negTokenInit is an RFC 4178 NegTokenInit. | negTokenInit 是 RFC 4178 NegTokenInit。
type negTokenInit struct {
	mechTypes   [][]uint32
	mechListDER []byte
	mechToken   []byte
	mechListMIC []byte
}

// negTokenResp is an RFC 4178 NegTokenResp. | negTokenResp 是 RFC 4178 NegTokenResp。
type negTokenResp struct {
	state         *negState
	supportedMech []uint32
	responseToken []byte
	mechListMIC   []byte
}

// appendMechTypeList encodes a MechTypeList SEQUENCE. | appendMechTypeList 编码
// MechTypeList SEQUENCE。
func appendMechTypeList(dst []byte, mechanisms [][]uint32) []byte {
	parts := make([][]byte, 0, len(mechanisms))
	for _, mechanism := range mechanisms {
		parts = append(parts, derAppendOID(nil, mechanism))
	}
	return derAppendSequence(dst, parts...)
}

// appendNegTokenInit encodes a NegTokenInit with its [0] choice tag. | appendNegTokenInit
// 编码带 [0] 选择标签的 NegTokenInit。
func appendNegTokenInit(token negTokenInit) []byte {
	mechList := appendMechTypeList(nil, token.mechTypes)
	parts := [][]byte{
		derAppendContext(nil, 0, mechList),
	}
	if len(token.mechToken) > 0 {
		parts = append(parts, derAppendContext(nil, 2, derAppendOctetString(nil, token.mechToken)))
	}
	if len(token.mechListMIC) > 0 {
		parts = append(parts, derAppendContext(nil, 3, derAppendOctetString(nil, token.mechListMIC)))
	}
	return derAppendContext(nil, 0, derAppendSequence(nil, parts...))
}

// parseNegTokenInit decodes a NegTokenInit. | parseNegTokenInit 解码 NegTokenInit。
func parseNegTokenInit(data []byte) (negTokenInit, error) {
	var token negTokenInit
	body, err := contextSequenceContent(data, 0)
	if err != nil {
		return token, err
	}
	seen := [4]bool{}
	r := newDERReader(body)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return token, err
		}
		if tag < 0xA0 || tag > 0xA3 {
			return token, errs.Detail(ErrSPNEGO, "unexpected NegTokenInit field 0x%02x | 意外的 NegTokenInit 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return token, errs.Detail(ErrSPNEGO, "duplicate NegTokenInit field 0x%02x | 重复的 NegTokenInit 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			list, err := contextContent(value, derTagSequence)
			if err != nil {
				return token, err
			}
			mechanisms, err := parseMechTypeList(list)
			if err != nil {
				return token, err
			}
			token.mechTypes = mechanisms
			token.mechListDER = derAppendTLV(nil, derTagSequence, list)
		case 0xA1:
			// reqFlags is legacy and unauthenticated; RFC 4178 requires peers to
			// ignore it. | reqFlags 属于遗留字段且未受认证；RFC 4178 要求对端忽略它。
			if _, err := contextContent(value, derTagBitString); err != nil {
				return token, err
			}
		case 0xA2:
			token.mechToken, err = readContextOctets(value)
			if err != nil {
				return token, err
			}
		case 0xA3:
			token.mechListMIC, err = readContextOctets(value)
			if err != nil {
				return token, err
			}
		}
	}
	if !seen[0] || len(token.mechTypes) == 0 {
		return token, errs.Detail(ErrSPNEGO, "NegTokenInit has no mechanism list | NegTokenInit 没有机制列表")
	}
	return token, nil
}

// parseMechTypeList decodes the content of a MechTypeList SEQUENCE. | parseMechTypeList
// 解码 MechTypeList SEQUENCE 的内容。
func parseMechTypeList(content []byte) ([][]uint32, error) {
	var mechanisms [][]uint32
	r := newDERReader(content)
	for r.remaining() > 0 {
		value, err := r.expect(derTagOID)
		if err != nil {
			return nil, err
		}
		arcs, err := parseOIDContent(value)
		if err != nil {
			return nil, err
		}
		mechanisms = append(mechanisms, arcs)
	}
	if len(mechanisms) == 0 {
		return nil, errs.Detail(ErrSPNEGO, "empty mechanism list | 机制列表为空")
	}
	return mechanisms, nil
}

// appendNegTokenResp encodes a NegTokenResp with its [1] choice tag. | appendNegTokenResp
// 编码带 [1] 选择标签的 NegTokenResp。
func appendNegTokenResp(token negTokenResp) []byte {
	var parts [][]byte
	if token.state != nil {
		parts = append(parts, derAppendContext(nil, 0, derAppendEnumerated(nil, int(*token.state))))
	}
	if len(token.supportedMech) > 0 {
		parts = append(parts, derAppendContext(nil, 1, derAppendOID(nil, token.supportedMech)))
	}
	if len(token.responseToken) > 0 {
		parts = append(parts, derAppendContext(nil, 2, derAppendOctetString(nil, token.responseToken)))
	}
	if len(token.mechListMIC) > 0 {
		parts = append(parts, derAppendContext(nil, 3, derAppendOctetString(nil, token.mechListMIC)))
	}
	return derAppendContext(nil, 1, derAppendSequence(nil, parts...))
}

// parseNegTokenResp decodes a NegTokenResp. | parseNegTokenResp 解码 NegTokenResp。
func parseNegTokenResp(data []byte) (negTokenResp, error) {
	var token negTokenResp
	body, err := contextSequenceContent(data, 1)
	if err != nil {
		return token, err
	}
	var seen [4]bool
	r := newDERReader(body)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return token, err
		}
		if tag < 0xA0 || tag > 0xA3 {
			return token, errs.Detail(ErrSPNEGO, "unexpected NegTokenResp field 0x%02x | 意外的 NegTokenResp 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return token, errs.Detail(ErrSPNEGO, "duplicate NegTokenResp field 0x%02x | 重复的 NegTokenResp 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			enumerated, err := contextContent(value, derTagEnumerated)
			if err != nil {
				return token, err
			}
			number, err := readInt32(enumerated)
			if err != nil {
				return token, err
			}
			state := negState(number)
			if state < negStateAcceptCompleted || state > negStateRequestMIC {
				return token, errs.Detail(ErrSPNEGO, "invalid negState %d | 非法 negState %d", number, number)
			}
			token.state = &state
		case 0xA1:
			oid, err := contextContent(value, derTagOID)
			if err != nil {
				return token, err
			}
			token.supportedMech, err = parseOIDContent(oid)
			if err != nil {
				return token, err
			}
		case 0xA2:
			token.responseToken, err = readContextOctets(value)
			if err != nil {
				return token, err
			}
		case 0xA3:
			token.mechListMIC, err = readContextOctets(value)
			if err != nil {
				return token, err
			}
		}
	}
	return token, nil
}

// contextSequenceContent extracts a SEQUENCE content field wrapped in an
// explicit context tag. | contextSequenceContent 从显式上下文标签中提取 SEQUENCE 内容。
func contextSequenceContent(data []byte, number int) ([]byte, error) {
	content, err := contextContent(data, byte(derTagContextBase+number))
	if err != nil {
		return nil, err
	}
	return sequenceContent(content)
}

// isSPNEGOToken reports whether data carries a SPNEGO negotiation token. | isSPNEGOToken
// 报告 data 是否携带 SPNEGO 协商令牌。
func isSPNEGOToken(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0] == 0xA0 || data[0] == 0xA1
}
