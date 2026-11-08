package kerberos

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// KDCReqBody is the RFC 4120 KDC-REQ-BODY shared by AS-REQ and TGS-REQ. | KDCReqBody
// 是 AS-REQ 与 TGS-REQ 共用的 RFC 4120 KDC-REQ-BODY。
type KDCReqBody struct {
	// KDCReqOptions are the requested KDC options. | KDCReqOptions 是请求的 KDC 选项。
	KDCReqOptions KDCOptions
	// CName is the optional client principal. | CName 是可选客户端主体。
	CName *PrincipalName
	// Realm is the request realm. | Realm 是请求 realm。
	Realm string
	// SName is the optional server principal. | SName 是可选服务端主体。
	SName *PrincipalName
	// From is the optional requested start time. | From 是可选请求起始时间。
	From *KerberosTime
	// Till is the requested expiry time. | Till 是请求过期时间。
	Till KerberosTime
	// RTime is the optional requested renewal time. | RTime 是可选请求续期时间。
	RTime *KerberosTime
	// Nonce is the request nonce. | Nonce 是请求 nonce。
	Nonce uint32
	// ETypes lists the acceptable encryption types. | ETypes 列出可接受的加密类型。
	ETypes []int32
	// Addresses is the optional requested address list. | Addresses 是可选请求地址列表。
	Addresses []HostAddress
	// EncAuthorizationData is the optional encrypted authorization data. | EncAuthorizationData
	// 是可选加密授权数据。
	EncAuthorizationData *EncryptedData
	// AdditionalTickets is the optional additional ticket list. | AdditionalTickets 是
	// 可选附加票据列表。
	AdditionalTickets []Ticket
}

// ASReq is an RFC 4120 AS-REQ. | ASReq 是 RFC 4120 AS-REQ。
type ASReq struct {
	// PAData carries pre-authentication data. | PAData 携带预认证数据。
	PAData []PAData
	// Body is the KDC request body. | Body 是 KDC 请求主体。
	Body KDCReqBody
}

// ASRep is an RFC 4120 AS-REP. | ASRep 是 RFC 4120 AS-REP。
type ASRep struct {
	// PAData carries pre-authentication data. | PAData 携带预认证数据。
	PAData []PAData
	// CRealm is the client realm. | CRealm 是客户端 realm。
	CRealm string
	// CName is the client principal. | CName 是客户端主体。
	CName PrincipalName
	// Ticket is the ticket-granting ticket. | Ticket 是票据授予票据。
	Ticket Ticket
	// EncPart is the encrypted EncASRepPart. | EncPart 是加密的 EncASRepPart。
	EncPart EncryptedData
}

// TGSReq is an RFC 4120 TGS-REQ. | TGSReq 是 RFC 4120 TGS-REQ。
type TGSReq struct {
	// PAData carries pre-authentication data. | PAData 携带预认证数据。
	PAData []PAData
	// Body is the KDC request body. | Body 是 KDC 请求主体。
	Body KDCReqBody
}

// TGSRep is an RFC 4120 TGS-REP. | TGSRep 是 RFC 4120 TGS-REP。
type TGSRep struct {
	// PAData carries pre-authentication data. | PAData 携带预认证数据。
	PAData []PAData
	// CRealm is the client realm. | CRealm 是客户端 realm。
	CRealm string
	// CName is the client principal. | CName 是客户端主体。
	CName PrincipalName
	// Ticket is the service ticket. | Ticket 是服务票据。
	Ticket Ticket
	// EncPart is the encrypted EncTGSRepPart. | EncPart 是加密的 EncTGSRepPart。
	EncPart EncryptedData
}

// APReq is an RFC 4120 AP-REQ. | APReq 是 RFC 4120 AP-REQ。
type APReq struct {
	// PVNO is the protocol version. | PVNO 是协议版本。
	PVNO int32
	// MsgType is the message type. | MsgType 是消息类型。
	MsgType int32
	// APOptions are the requested AP options. | APOptions 是请求的 AP 选项。
	APOptions APOptions
	// Ticket is the service ticket. | Ticket 是服务票据。
	Ticket Ticket
	// Authenticator is the encrypted Authenticator. | Authenticator 是加密的 Authenticator。
	Authenticator EncryptedData
}

// APRep is an RFC 4120 AP-REP. | APRep 是 RFC 4120 AP-REP。
type APRep struct {
	// PVNO is the protocol version. | PVNO 是协议版本。
	PVNO int32
	// MsgType is the message type. | MsgType 是消息类型。
	MsgType int32
	// EncPart is the encrypted EncAPRepPart. | EncPart 是加密的 EncAPRepPart。
	EncPart EncryptedData
}

// KRBError is an RFC 4120 KRB-ERROR. It implements error so callers can use
// errors.Is against the package sentinels. | KRBError 是 RFC 4120 KRB-ERROR。
// 它实现 error，调用方可以对包哨兵使用 errors.Is。
type KRBError struct {
	// PVNO is the protocol version. | PVNO 是协议版本。
	PVNO int32
	// MsgType is the message type. | MsgType 是消息类型。
	MsgType int32
	// CTime is the optional client time. | CTime 是可选客户端时间。
	CTime *KerberosTime
	// CUSec is the optional client microsecond field. | CUSec 是可选客户端微秒字段。
	CUSec *int32
	// STime is the server time. | STime 是服务端时间。
	STime KerberosTime
	// SUSec is the server microsecond field. | SUSec 是服务端微秒字段。
	SUSec int32
	// ErrorCode is the RFC 4120 error code. | ErrorCode 是 RFC 4120 错误码。
	ErrorCode int32
	// CRealm is the optional client realm. | CRealm 是可选客户端 realm。
	CRealm string
	// CName is the optional client principal. | CName 是可选客户端主体。
	CName *PrincipalName
	// Realm is the realm of the server named in SName. | Realm 是 SName 中服务端所属 realm。
	Realm string
	// SName is the server principal. | SName 是服务端主体。
	SName PrincipalName
	// EText is the optional diagnostic text. | EText 是可选诊断文本。
	EText string
	// EData is the optional error data, for example METHOD-DATA. | EData 是可选错误数据，
	// 例如 METHOD-DATA。
	EData []byte
}

// Error renders the Kerberos error code and diagnostic text. | Error 渲染 Kerberos 错误码与
// 诊断文本。
func (e KRBError) Error() string {
	name := ErrorCodeName(e.ErrorCode)
	if name == "" {
		name = "UNKNOWN"
	}
	var b strings.Builder
	b.WriteString("kerberos: KDC error ")
	b.WriteString(name)
	b.WriteString(" (")
	b.WriteString(strconv.FormatInt(int64(e.ErrorCode), 10))
	b.WriteString(")")
	if e.EText != "" {
		b.WriteString(": ")
		b.WriteString(e.EText)
	}
	b.WriteString(" | kerberos：KDC 错误 ")
	b.WriteString(name)
	b.WriteString("（")
	b.WriteString(strconv.FormatInt(int64(e.ErrorCode), 10))
	b.WriteString("）")
	if e.EText != "" {
		b.WriteString("：")
		b.WriteString(e.EText)
	}
	return b.String()
}

// Unwrap returns the sentinel that classifies the RFC 4120 error code. | Unwrap
// 返回分类该 RFC 4120 错误码的哨兵。
func (e KRBError) Unwrap() error { return sentinelForCode(e.ErrorCode) }

// Err returns the KRBError as a wrapped sentinel carrying the KDC diagnostics. | Err
// 把 KRBError 转换为携带 KDC 诊断信息的包装哨兵。
func (e KRBError) Err() error {
	sentinel := sentinelForCode(e.ErrorCode)
	return errs.WrapDetail(e, sentinel, "KDC error %s (%d) | KDC 错误 %s（%d）",
		ErrorCodeName(e.ErrorCode), e.ErrorCode, ErrorCodeName(e.ErrorCode), e.ErrorCode)
}

// Marshal encodes the AS-REQ. | Marshal 编码 AS-REQ。
func (r ASReq) Marshal() ([]byte, error) {
	return marshalKDCReq(MessageTypeASReq, r.PAData, r.Body)
}

// ParseASReq decodes an AS-REQ. | ParseASReq 解码 AS-REQ。
func ParseASReq(data []byte) (ASReq, error) {
	padata, body, err := parseKDCReq(data, MessageTypeASReq)
	if err != nil {
		return ASReq{}, err
	}
	return ASReq{PAData: padata, Body: body}, nil
}

// Marshal encodes the AS-REP. | Marshal 编码 AS-REP。
func (r ASRep) Marshal() ([]byte, error) {
	return marshalKDCRep(MessageTypeASRep, r.PAData, r.CRealm, r.CName, r.Ticket, r.EncPart)
}

// ParseASRep decodes an AS-REP. | ParseASRep 解码 AS-REP。
func ParseASRep(data []byte) (ASRep, error) {
	padata, crealm, cname, ticket, encPart, err := parseKDCRep(data, MessageTypeASRep)
	if err != nil {
		return ASRep{}, err
	}
	return ASRep{PAData: padata, CRealm: crealm, CName: cname, Ticket: ticket, EncPart: encPart}, nil
}

// Marshal encodes the TGS-REQ. | Marshal 编码 TGS-REQ。
func (r TGSReq) Marshal() ([]byte, error) {
	return marshalKDCReq(MessageTypeTGSReq, r.PAData, r.Body)
}

// ParseTGSReq decodes a TGS-REQ. | ParseTGSReq 解码 TGS-REQ。
func ParseTGSReq(data []byte) (TGSReq, error) {
	padata, body, err := parseKDCReq(data, MessageTypeTGSReq)
	if err != nil {
		return TGSReq{}, err
	}
	return TGSReq{PAData: padata, Body: body}, nil
}

// Marshal encodes the TGS-REP. | Marshal 编码 TGS-REP。
func (r TGSRep) Marshal() ([]byte, error) {
	return marshalKDCRep(MessageTypeTGSRep, r.PAData, r.CRealm, r.CName, r.Ticket, r.EncPart)
}

// ParseTGSRep decodes a TGS-REP. | ParseTGSRep 解码 TGS-REP。
func ParseTGSRep(data []byte) (TGSRep, error) {
	padata, crealm, cname, ticket, encPart, err := parseKDCRep(data, MessageTypeTGSRep)
	if err != nil {
		return TGSRep{}, err
	}
	return TGSRep{PAData: padata, CRealm: crealm, CName: cname, Ticket: ticket, EncPart: encPart}, nil
}

// Marshal encodes the AP-REQ. | Marshal 编码 AP-REQ。
func (r APReq) Marshal() ([]byte, error) {
	if r.Ticket.TktVNO == 0 || r.Ticket.Realm == "" {
		return nil, errs.Detail(ErrInvalidMessage, "AP-REQ has no usable ticket | AP-REQ 没有可用票据")
	}
	if len(r.Authenticator.Cipher) == 0 {
		return nil, errs.Detail(ErrInvalidMessage, "AP-REQ has no authenticator | AP-REQ 没有认证器")
	}
	pvno := r.PVNO
	if pvno == 0 {
		pvno = PVNO
	}
	msgType := r.MsgType
	if msgType == 0 {
		msgType = MessageTypeAPReq
	}
	body := derAppendSequence(nil,
		appendIntContext(nil, 0, pvno),
		appendIntContext(nil, 1, msgType),
		appendFlagsContext(nil, 2, uint32(r.APOptions)),
		derAppendContext(nil, 3, appendTicket(nil, r.Ticket)),
		derAppendContext(nil, 4, appendEncryptedData(nil, r.Authenticator)),
	)
	return derAppendApplication(nil, 14, body), nil
}

// ParseAPReq decodes an AP-REQ. | ParseAPReq 解码 AP-REQ。
func ParseAPReq(data []byte) (APReq, error) {
	content, err := applicationContent(data, 14)
	if err != nil {
		return APReq{}, err
	}
	var req APReq
	seen := [5]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return APReq{}, err
		}
		if tag < 0xA0 || tag > 0xA4 {
			return APReq{}, errs.Detail(ErrInvalidMessage, "unexpected AP-REQ field 0x%02x | 意外的 AP-REQ 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return APReq{}, errs.Detail(ErrInvalidMessage, "duplicate AP-REQ field 0x%02x | 重复的 AP-REQ 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return APReq{}, err
			}
			req.PVNO = number
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return APReq{}, err
			}
			req.MsgType = number
		case 0xA2:
			flags, err := readContextKerberosFlags(value)
			if err != nil {
				return APReq{}, err
			}
			req.APOptions = APOptions(flags)
		case 0xA3:
			req.Ticket, err = parseTicket(value)
			if err != nil {
				return APReq{}, err
			}
		case 0xA4:
			req.Authenticator, err = parseEncryptedData(value)
			if err != nil {
				return APReq{}, err
			}
		}
	}
	for _, index := range []int{0, 1, 3, 4} {
		if !seen[index] {
			return APReq{}, errs.Detail(ErrInvalidMessage, "AP-REQ is missing field %d | AP-REQ 缺少字段 %d", index, index)
		}
	}
	if req.PVNO != PVNO {
		return APReq{}, errs.Detail(ErrInvalidMessage, "AP-REQ protocol version %d | AP-REQ 协议版本 %d", req.PVNO, req.PVNO)
	}
	if req.MsgType != MessageTypeAPReq {
		return APReq{}, errs.Detail(ErrInvalidMessage, "AP-REQ message type %d | AP-REQ 消息类型 %d", req.MsgType, req.MsgType)
	}
	return req, nil
}

// Marshal encodes the AP-REP. | Marshal 编码 AP-REP。
func (r APRep) Marshal() ([]byte, error) {
	if len(r.EncPart.Cipher) == 0 {
		return nil, errs.Detail(ErrInvalidMessage, "AP-REP has no encrypted part | AP-REP 没有加密部分")
	}
	pvno := r.PVNO
	if pvno == 0 {
		pvno = PVNO
	}
	msgType := r.MsgType
	if msgType == 0 {
		msgType = MessageTypeAPRep
	}
	body := derAppendSequence(nil,
		appendIntContext(nil, 0, pvno),
		appendIntContext(nil, 1, msgType),
		derAppendContext(nil, 2, appendEncryptedData(nil, r.EncPart)),
	)
	return derAppendApplication(nil, 15, body), nil
}

// ParseAPRep decodes an AP-REP. | ParseAPRep 解码 AP-REP。
func ParseAPRep(data []byte) (APRep, error) {
	content, err := applicationContent(data, 15)
	if err != nil {
		return APRep{}, err
	}
	var rep APRep
	seen := [3]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return APRep{}, err
		}
		if tag < 0xA0 || tag > 0xA2 {
			return APRep{}, errs.Detail(ErrInvalidMessage, "unexpected AP-REP field 0x%02x | 意外的 AP-REP 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return APRep{}, errs.Detail(ErrInvalidMessage, "duplicate AP-REP field 0x%02x | 重复的 AP-REP 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return APRep{}, err
			}
			rep.PVNO = number
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return APRep{}, err
			}
			rep.MsgType = number
		case 0xA2:
			rep.EncPart, err = parseEncryptedData(value)
			if err != nil {
				return APRep{}, err
			}
		}
	}
	if !seen[0] || !seen[1] || !seen[2] {
		return APRep{}, errs.Detail(ErrInvalidMessage, "AP-REP is missing required fields | AP-REP 缺少必需字段")
	}
	if rep.PVNO != PVNO {
		return APRep{}, errs.Detail(ErrInvalidMessage, "AP-REP protocol version %d | AP-REP 协议版本 %d", rep.PVNO, rep.PVNO)
	}
	if rep.MsgType != MessageTypeAPRep {
		return APRep{}, errs.Detail(ErrInvalidMessage, "AP-REP message type %d | AP-REP 消息类型 %d", rep.MsgType, rep.MsgType)
	}
	return rep, nil
}

// Marshal encodes the KRB-ERROR. | Marshal 编码 KRB-ERROR。
func (e KRBError) Marshal() ([]byte, error) {
	pvno := e.PVNO
	if pvno == 0 {
		pvno = PVNO
	}
	msgType := e.MsgType
	if msgType == 0 {
		msgType = MessageTypeKRBError
	}
	parts := [][]byte{
		appendIntContext(nil, 0, pvno),
		appendIntContext(nil, 1, msgType),
	}
	if e.CTime != nil {
		parts = append(parts, appendTimeContext(nil, 2, e.CTime.Time))
	}
	if e.CUSec != nil {
		parts = append(parts, appendIntContext(nil, 3, *e.CUSec))
	}
	parts = append(parts,
		appendTimeContext(nil, 4, e.STime.Time),
		appendIntContext(nil, 5, e.SUSec),
		appendIntContext(nil, 6, e.ErrorCode),
	)
	if e.CRealm != "" {
		parts = append(parts, appendStringContext(nil, 7, e.CRealm))
	}
	if e.CName != nil {
		parts = append(parts, derAppendContext(nil, 8, appendPrincipalName(nil, *e.CName)))
	}
	parts = append(parts,
		appendStringContext(nil, 9, e.Realm),
		derAppendContext(nil, 10, appendPrincipalName(nil, e.SName)),
	)
	if e.EText != "" {
		parts = append(parts, appendStringContext(nil, 11, e.EText))
	}
	if e.EData != nil {
		parts = append(parts, appendOctetsContext(nil, 12, e.EData))
	}
	body := derAppendSequence(nil, parts...)
	return derAppendApplication(nil, 30, body), nil
}

// ParseKRBError decodes a KRB-ERROR. | ParseKRBError 解码 KRB-ERROR。
func ParseKRBError(data []byte) (KRBError, error) {
	content, err := applicationContent(data, 30)
	if err != nil {
		return KRBError{}, err
	}
	var krbErr KRBError
	seen := [13]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return KRBError{}, err
		}
		if tag < 0xA0 || tag > 0xAC {
			return KRBError{}, errs.Detail(ErrInvalidMessage, "unexpected KRB-ERROR field 0x%02x | 意外的 KRB-ERROR 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return KRBError{}, errs.Detail(ErrInvalidMessage, "duplicate KRB-ERROR field 0x%02x | 重复的 KRB-ERROR 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return KRBError{}, err
			}
			krbErr.PVNO = number
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return KRBError{}, err
			}
			krbErr.MsgType = number
		case 0xA2:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return KRBError{}, err
			}
			ctime := NewKerberosTime(parsed)
			krbErr.CTime = &ctime
		case 0xA3:
			number, err := readContextInt32(value)
			if err != nil {
				return KRBError{}, err
			}
			krbErr.CUSec = &number
		case 0xA4:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return KRBError{}, err
			}
			krbErr.STime = NewKerberosTime(parsed)
		case 0xA5:
			number, err := readContextInt32(value)
			if err != nil {
				return KRBError{}, err
			}
			krbErr.SUSec = number
		case 0xA6:
			number, err := readContextInt32(value)
			if err != nil {
				return KRBError{}, err
			}
			krbErr.ErrorCode = number
		case 0xA7:
			krbErr.CRealm, err = readContextString(value)
			if err != nil {
				return KRBError{}, err
			}
		case 0xA8:
			cname, err := parsePrincipalName(value)
			if err != nil {
				return KRBError{}, err
			}
			krbErr.CName = &cname
		case 0xA9:
			krbErr.Realm, err = readContextString(value)
			if err != nil {
				return KRBError{}, err
			}
		case 0xAA:
			krbErr.SName, err = parsePrincipalName(value)
			if err != nil {
				return KRBError{}, err
			}
		case 0xAB:
			krbErr.EText, err = readContextString(value)
			if err != nil {
				return KRBError{}, err
			}
		case 0xAC:
			krbErr.EData, err = readContextOctets(value)
			if err != nil {
				return KRBError{}, err
			}
		}
	}
	for _, index := range []int{0, 1, 4, 5, 6} {
		if !seen[index] {
			return KRBError{}, errs.Detail(ErrInvalidMessage, "KRB-ERROR is missing field %d | KRB-ERROR 缺少字段 %d", index, index)
		}
	}
	if krbErr.PVNO != PVNO {
		return KRBError{}, errs.Detail(ErrInvalidMessage, "KRB-ERROR protocol version %d | KRB-ERROR 协议版本 %d", krbErr.PVNO, krbErr.PVNO)
	}
	if krbErr.MsgType != MessageTypeKRBError {
		return KRBError{}, errs.Detail(ErrInvalidMessage, "KRB-ERROR message type %d | KRB-ERROR 消息类型 %d", krbErr.MsgType, krbErr.MsgType)
	}
	return krbErr, nil
}

// encodePADataSequence encodes a SEQUENCE OF PA-DATA. | encodePADataSequence 编码
// SEQUENCE OF PA-DATA。
func encodePADataSequence(data []PAData) []byte {
	parts := make([][]byte, 0, len(data))
	for _, item := range data {
		parts = append(parts, appendPAData(nil, item))
	}
	return derAppendSequence(nil, parts...)
}

// parsePADataSequence decodes a SEQUENCE OF PA-DATA. | parsePADataSequence 解码
// SEQUENCE OF PA-DATA。
func parsePADataSequence(content []byte) ([]PAData, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return nil, err
	}
	r := newDERReader(body)
	var data []PAData
	for r.remaining() > 0 {
		entry, err := r.expect(derTagSequence)
		if err != nil {
			return nil, err
		}
		item, err := parsePAData(entry)
		if err != nil {
			return nil, err
		}
		data = append(data, item)
	}
	return data, nil
}

// encodeInt32Sequence encodes a SEQUENCE OF INTEGER. | encodeInt32Sequence 编码
// SEQUENCE OF INTEGER。
func encodeInt32Sequence(values []int32) []byte {
	parts := make([][]byte, 0, len(values))
	for _, value := range values {
		parts = append(parts, derAppendInteger(nil, value))
	}
	return derAppendSequence(nil, parts...)
}

// parseInt32Sequence decodes a SEQUENCE OF INTEGER. | parseInt32Sequence 解码
// SEQUENCE OF INTEGER。
func parseInt32Sequence(content []byte) ([]int32, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return nil, err
	}
	r := newDERReader(body)
	var values []int32
	for r.remaining() > 0 {
		entry, err := r.expect(derTagInteger)
		if err != nil {
			return nil, err
		}
		value, err := readInt32(entry)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

// encodeTicketSequence encodes a SEQUENCE OF Ticket. | encodeTicketSequence 编码
// SEQUENCE OF Ticket。
func encodeTicketSequence(tickets []Ticket) []byte {
	parts := make([][]byte, 0, len(tickets))
	for _, ticket := range tickets {
		parts = append(parts, appendTicket(nil, ticket))
	}
	return derAppendSequence(nil, parts...)
}

// parseTicketSequence decodes a SEQUENCE OF Ticket. | parseTicketSequence 解码
// SEQUENCE OF Ticket。
func parseTicketSequence(content []byte) ([]Ticket, error) {
	body, err := sequenceContent(content)
	if err != nil {
		return nil, err
	}
	r := newDERReader(body)
	var tickets []Ticket
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return nil, err
		}
		if tag != 0x61 {
			return nil, errs.Detail(ErrInvalidMessage, "unexpected ticket tag 0x%02x | 意外的票据标签 0x%02x", tag, tag)
		}
		ticketData := derAppendTLV(nil, tag, value)
		ticket, err := parseTicket(ticketData)
		if err != nil {
			return nil, err
		}
		tickets = append(tickets, ticket)
	}
	return tickets, nil
}

// appendKDCReqBody encodes a KDC-REQ-BODY. | appendKDCReqBody 编码 KDC-REQ-BODY。
func appendKDCReqBody(body KDCReqBody) []byte {
	parts := [][]byte{
		appendFlagsContext(nil, 0, uint32(body.KDCReqOptions)),
	}
	if body.CName != nil {
		parts = append(parts, derAppendContext(nil, 1, appendPrincipalName(nil, *body.CName)))
	}
	parts = append(parts, appendStringContext(nil, 2, body.Realm))
	if body.SName != nil {
		parts = append(parts, derAppendContext(nil, 3, appendPrincipalName(nil, *body.SName)))
	}
	if body.From != nil {
		parts = append(parts, appendTimeContext(nil, 4, body.From.Time))
	}
	parts = append(parts, appendTimeContext(nil, 5, body.Till.Time))
	if body.RTime != nil {
		parts = append(parts, appendTimeContext(nil, 6, body.RTime.Time))
	}
	parts = append(parts,
		appendUintContext(nil, 7, body.Nonce),
		derAppendContext(nil, 8, encodeInt32Sequence(body.ETypes)),
	)
	if body.Addresses != nil {
		parts = append(parts, derAppendContext(nil, 9, appendHostAddresses(nil, body.Addresses)))
	}
	if body.EncAuthorizationData != nil {
		parts = append(parts, derAppendContext(nil, 10, appendEncryptedData(nil, *body.EncAuthorizationData)))
	}
	if body.AdditionalTickets != nil {
		parts = append(parts, derAppendContext(nil, 11, encodeTicketSequence(body.AdditionalTickets)))
	}
	return derAppendSequence(nil, parts...)
}

// validateKDCReqBody checks the mandatory fields of a KDC-REQ-BODY. | validateKDCReqBody
// 检查 KDC-REQ-BODY 的必需字段。
func validateKDCReqBody(body KDCReqBody) error {
	if body.Realm == "" {
		return errs.Detail(ErrInvalidMessage, "KDC request has no realm | KDC 请求没有 realm")
	}
	if body.Till.IsZero() {
		return errs.Detail(ErrInvalidMessage, "KDC request has no expiry time | KDC 请求没有过期时间")
	}
	if len(body.ETypes) == 0 {
		return errs.Detail(ErrInvalidMessage, "KDC request has no encryption types | KDC 请求没有加密类型")
	}
	return nil
}

// marshalKDCReq encodes an AS-REQ or TGS-REQ. | marshalKDCReq 编码 AS-REQ 或 TGS-REQ。
func marshalKDCReq(msgType int, padata []PAData, body KDCReqBody) ([]byte, error) {
	if err := validateKDCReqBody(body); err != nil {
		return nil, err
	}
	parts := [][]byte{
		appendIntContext(nil, 1, PVNO),
		appendIntContext(nil, 2, int32(msgType)),
	}
	if len(padata) > 0 {
		parts = append(parts, derAppendContext(nil, 3, encodePADataSequence(padata)))
	}
	parts = append(parts, derAppendContext(nil, 4, appendKDCReqBody(body)))
	application := 10
	if msgType == MessageTypeTGSReq {
		application = 12
	}
	return derAppendApplication(nil, application, derAppendSequence(nil, parts...)), nil
}

// parseKDCReq decodes an AS-REQ or TGS-REQ. | parseKDCReq 解码 AS-REQ 或 TGS-REQ。
func parseKDCReq(data []byte, wantType int) ([]PAData, KDCReqBody, error) {
	application := 10
	if wantType == MessageTypeTGSReq {
		application = 12
	}
	content, err := applicationContent(data, application)
	if err != nil {
		return nil, KDCReqBody{}, err
	}
	var (
		padata  []PAData
		body    KDCReqBody
		msgType int32
		pvno    int32
		seen    [5]bool
	)
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return nil, KDCReqBody{}, err
		}
		if tag < 0xA1 || tag > 0xA4 {
			return nil, KDCReqBody{}, errs.Detail(ErrInvalidMessage, "unexpected KDC-REQ field 0x%02x | 意外的 KDC-REQ 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return nil, KDCReqBody{}, errs.Detail(ErrInvalidMessage, "duplicate KDC-REQ field 0x%02x | 重复的 KDC-REQ 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return nil, KDCReqBody{}, err
			}
			pvno = number
		case 0xA2:
			number, err := readContextInt32(value)
			if err != nil {
				return nil, KDCReqBody{}, err
			}
			msgType = number
		case 0xA3:
			padata, err = parsePADataSequence(value)
			if err != nil {
				return nil, KDCReqBody{}, err
			}
		case 0xA4:
			body, err = parseKDCReqBody(value)
			if err != nil {
				return nil, KDCReqBody{}, err
			}
		}
	}
	if !seen[1] || !seen[2] || !seen[4] {
		return nil, KDCReqBody{}, errs.Detail(ErrInvalidMessage, "KDC-REQ is missing required fields | KDC-REQ 缺少必需字段")
	}
	if pvno != PVNO {
		return nil, KDCReqBody{}, errs.Detail(ErrInvalidMessage, "KDC-REQ protocol version %d | KDC-REQ 协议版本 %d", pvno, pvno)
	}
	if msgType != int32(wantType) {
		return nil, KDCReqBody{}, errs.Detail(ErrInvalidMessage, "KDC-REQ message type %d, want %d | KDC-REQ 消息类型 %d，期望 %d",
			msgType, wantType, msgType, wantType)
	}
	return padata, body, nil
}

// parseKDCReqBody decodes a KDC-REQ-BODY. | parseKDCReqBody 解码 KDC-REQ-BODY。
func parseKDCReqBody(data []byte) (KDCReqBody, error) {
	content, err := sequenceContent(data)
	if err != nil {
		return KDCReqBody{}, err
	}
	var body KDCReqBody
	seen := [12]bool{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return KDCReqBody{}, err
		}
		if tag < 0xA0 || tag > 0xAB {
			return KDCReqBody{}, errs.Detail(ErrInvalidMessage, "unexpected KDC-REQ-BODY field 0x%02x | 意外的 KDC-REQ-BODY 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return KDCReqBody{}, errs.Detail(ErrInvalidMessage, "duplicate KDC-REQ-BODY field 0x%02x | 重复的 KDC-REQ-BODY 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			flags, err := readContextKerberosFlags(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			body.KDCReqOptions = KDCOptions(flags)
		case 0xA1:
			cname, err := parsePrincipalName(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			body.CName = &cname
		case 0xA2:
			body.Realm, err = readContextString(value)
			if err != nil {
				return KDCReqBody{}, err
			}
		case 0xA3:
			sname, err := parsePrincipalName(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			body.SName = &sname
		case 0xA4:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			from := NewKerberosTime(parsed)
			body.From = &from
		case 0xA5:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			body.Till = NewKerberosTime(parsed)
		case 0xA6:
			parsed, err := readContextGeneralizedTime(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			rtime := NewKerberosTime(parsed)
			body.RTime = &rtime
		case 0xA7:
			number, err := readContextUint32(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			body.Nonce = number
		case 0xA8:
			body.ETypes, err = parseInt32Sequence(value)
			if err != nil {
				return KDCReqBody{}, err
			}
		case 0xA9:
			body.Addresses, err = parseHostAddresses(value)
			if err != nil {
				return KDCReqBody{}, err
			}
		case 0xAA:
			enc, err := parseEncryptedData(value)
			if err != nil {
				return KDCReqBody{}, err
			}
			body.EncAuthorizationData = &enc
		case 0xAB:
			body.AdditionalTickets, err = parseTicketSequence(value)
			if err != nil {
				return KDCReqBody{}, err
			}
		}
	}
	for _, index := range []int{0, 2, 5, 7, 8} {
		if !seen[index] {
			return KDCReqBody{}, errs.Detail(ErrInvalidMessage, "KDC-REQ-BODY is missing field %d | KDC-REQ-BODY 缺少字段 %d", index, index)
		}
	}
	return body, nil
}

// marshalKDCRep encodes an AS-REP or TGS-REP. | marshalKDCRep 编码 AS-REP 或 TGS-REP。
func marshalKDCRep(msgType int, padata []PAData, crealm string, cname PrincipalName, ticket Ticket, encPart EncryptedData) ([]byte, error) {
	if crealm == "" || ticket.Realm == "" || ticket.TktVNO == 0 {
		return nil, errs.Detail(ErrInvalidMessage, "KDC-REP has an incomplete ticket or client realm | KDC-REP 的票据或客户端 realm 不完整")
	}
	if len(encPart.Cipher) == 0 {
		return nil, errs.Detail(ErrInvalidMessage, "KDC-REP has no encrypted part | KDC-REP 没有加密部分")
	}
	parts := [][]byte{
		appendIntContext(nil, 0, PVNO),
		appendIntContext(nil, 1, int32(msgType)),
	}
	if len(padata) > 0 {
		parts = append(parts, derAppendContext(nil, 2, encodePADataSequence(padata)))
	}
	parts = append(parts,
		appendStringContext(nil, 3, crealm),
		derAppendContext(nil, 4, appendPrincipalName(nil, cname)),
		derAppendContext(nil, 5, appendTicket(nil, ticket)),
		derAppendContext(nil, 6, appendEncryptedData(nil, encPart)),
	)
	application := 11
	if msgType == MessageTypeTGSRep {
		application = 13
	}
	return derAppendApplication(nil, application, derAppendSequence(nil, parts...)), nil
}

// parseKDCRep decodes an AS-REP or TGS-REP. | parseKDCRep 解码 AS-REP 或 TGS-REP。
func parseKDCRep(data []byte, wantType int) ([]PAData, string, PrincipalName, Ticket, EncryptedData, error) {
	application := 11
	if wantType == MessageTypeTGSRep {
		application = 13
	}
	content, err := applicationContent(data, application)
	if err != nil {
		return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
	}
	var (
		padata  []PAData
		crealm  string
		cname   PrincipalName
		ticket  Ticket
		encPart EncryptedData
		msgType int32
		pvno    int32
		seen    [7]bool
	)
	r := newDERReader(content)
	for r.remaining() > 0 {
		tag, value, err := r.next()
		if err != nil {
			return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
		}
		if tag < 0xA0 || tag > 0xA6 {
			return nil, "", PrincipalName{}, Ticket{}, EncryptedData{},
				errs.Detail(ErrInvalidMessage, "unexpected KDC-REP field 0x%02x | 意外的 KDC-REP 字段 0x%02x", tag, tag)
		}
		index := int(tag - 0xA0)
		if seen[index] {
			return nil, "", PrincipalName{}, Ticket{}, EncryptedData{},
				errs.Detail(ErrInvalidMessage, "duplicate KDC-REP field 0x%02x | 重复的 KDC-REP 字段 0x%02x", tag, tag)
		}
		seen[index] = true
		switch tag {
		case 0xA0:
			number, err := readContextInt32(value)
			if err != nil {
				return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
			}
			pvno = number
		case 0xA1:
			number, err := readContextInt32(value)
			if err != nil {
				return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
			}
			msgType = number
		case 0xA2:
			padata, err = parsePADataSequence(value)
			if err != nil {
				return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
			}
		case 0xA3:
			crealm, err = readContextString(value)
			if err != nil {
				return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
			}
		case 0xA4:
			cname, err = parsePrincipalName(value)
			if err != nil {
				return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
			}
		case 0xA5:
			ticket, err = parseTicket(value)
			if err != nil {
				return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
			}
		case 0xA6:
			encPart, err = parseEncryptedData(value)
			if err != nil {
				return nil, "", PrincipalName{}, Ticket{}, EncryptedData{}, err
			}
		}
	}
	for _, index := range []int{0, 1, 3, 4, 5, 6} {
		if !seen[index] {
			return nil, "", PrincipalName{}, Ticket{}, EncryptedData{},
				errs.Detail(ErrInvalidMessage, "KDC-REP is missing field %d | KDC-REP 缺少字段 %d", index, index)
		}
	}
	if pvno != PVNO {
		return nil, "", PrincipalName{}, Ticket{}, EncryptedData{},
			errs.Detail(ErrInvalidMessage, "KDC-REP protocol version %d | KDC-REP 协议版本 %d", pvno, pvno)
	}
	if msgType != int32(wantType) {
		return nil, "", PrincipalName{}, Ticket{}, EncryptedData{},
			errs.Detail(ErrInvalidMessage, "KDC-REP message type %d, want %d | KDC-REP 消息类型 %d，期望 %d",
				msgType, wantType, msgType, wantType)
	}
	return padata, crealm, cname, ticket, encPart, nil
}
