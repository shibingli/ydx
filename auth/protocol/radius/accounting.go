package radius

import (
	"context"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
)

// maxUint32Value is the largest 32-bit attribute value. | maxUint32Value 是最大的 32 位属性值。
const maxUint32Value = ^uint32(0)

// AccountingRequest describes one Accounting-Request (RFC 2866). | AccountingRequest 描述一次
// Accounting-Request（RFC 2866）。
//
// Start, Stop and Interim-Update requests require SessionID and carry the octet, packet and
// session-time counters. Accounting-On and Accounting-Off requests omit the counters. |
// Start、Stop 与 Interim-Update 请求要求 SessionID，并携带八位组、报文与会话时间计数。
// Accounting-On 与 Accounting-Off 请求省略这些计数。
type AccountingRequest struct {
	// EventTimestamp is Event-Timestamp; the current time is used when zero. | EventTimestamp 是
	// Event-Timestamp；为零时使用当前时间。
	EventTimestamp time.Time
	// SessionID is the Acct-Session-Id value; required for session statuses. | SessionID 是
	// Acct-Session-Id 值；会话状态必填。
	SessionID string
	// UserName is the User-Name value. | UserName 是 User-Name 值。
	UserName string
	// NASIdentifier overrides the client NAS-Identifier. | NASIdentifier 覆盖客户端的 NAS-Identifier。
	NASIdentifier string
	// CallingStationID is the Calling-Station-Id value. | CallingStationID 是 Calling-Station-Id 值。
	CallingStationID string
	// CalledStationID is the Called-Station-Id value. | CalledStationID 是 Called-Station-Id 值。
	CalledStationID string
	// NASIPAddress overrides the client NAS-IP-Address. | NASIPAddress 覆盖客户端的 NAS-IP-Address。
	NASIPAddress net.IP
	// Class is the Class value echoed from the Access-Accept. | Class 是从 Access-Accept 回显的 Class 值。
	Class []byte
	// Attributes carries additional attributes. | Attributes 携带附加属性。
	Attributes Attributes
	// StatusType is the Acct-Status-Type value and is required. | StatusType 是 Acct-Status-Type 值，必填。
	StatusType AcctStatusType
	// NASPort is the NAS-Port value; zero omits it. | NASPort 是 NAS-Port 值；零值省略该属性。
	NASPort uint32
	// NASPortType is the NAS-Port-Type value; zero omits it. | NASPortType 是 NAS-Port-Type 值；
	// 零值省略该属性。
	NASPortType NASPortType
	// Authentic is the Acct-Authentic value; zero omits it. | Authentic 是 Acct-Authentic 值；零值省略该属性。
	Authentic AcctAuthentic
	// DelayTime is the initial Acct-Delay-Time in seconds. Elapsed retransmission time is added to
	// each attempt. | DelayTime 是初始 Acct-Delay-Time 秒数。每次尝试会加上经过的重传时间。
	DelayTime uint32
	// InputOctets is Acct-Input-Octets. | InputOctets 是 Acct-Input-Octets。
	InputOctets uint32
	// OutputOctets is Acct-Output-Octets. | OutputOctets 是 Acct-Output-Octets。
	OutputOctets uint32
	// InputPackets is Acct-Input-Packets. | InputPackets 是 Acct-Input-Packets。
	InputPackets uint32
	// OutputPackets is Acct-Output-Packets. | OutputPackets 是 Acct-Output-Packets。
	OutputPackets uint32
	// SessionTime is Acct-Session-Time in seconds. | SessionTime 是 Acct-Session-Time 秒数。
	SessionTime uint32
	// TerminateCause is Acct-Terminate-Cause; zero omits it. | TerminateCause 是
	// Acct-Terminate-Cause；零值省略该属性。
	TerminateCause AcctTerminateCause
}

// AccountingResponse is the decoded answer to an Accounting-Request. | AccountingResponse 是
// Accounting-Request 的解码应答。
type AccountingResponse struct {
	// ReplyMessage is the first Reply-Message. | ReplyMessage 是首个 Reply-Message。
	ReplyMessage string
	// Attributes holds every response attribute in wire order. | Attributes 按线序保存全部响应属性。
	Attributes Attributes
	// Authenticator is the verified Response Authenticator. | Authenticator 是已校验的 Response Authenticator。
	Authenticator [16]byte
	// Code is the response code, normally Accounting-Response. | Code 是响应码，通常为 Accounting-Response。
	Code Code
	// Identifier is the response packet identifier. | Identifier 是响应报文标识符。
	Identifier uint8
}

// AccountRequest sends an Accounting-Request and verifies the response. | AccountRequest 发送
// Accounting-Request 并校验响应。
//
// The Request Authenticator is computed as specified by RFC 2866 and the response must carry a
// matching Response Authenticator. UDP responses that are malformed, carry another identifier, or
// fail Response Authenticator verification are silently discarded and reading continues until a
// valid response or the attempt deadline, as RFC 2866 section 4 requires; stream transports fail
// the attempt so the connection can be closed. Every attempt uses a fresh Identifier and an updated
// Acct-Delay-Time. | Request Authenticator 按 RFC 2866 计算，响应必须携带匹配的 Response
// Authenticator。按 RFC 2866 第 4 节要求，UDP 响应中结构畸形、标识符不同或认证符不匹配者被静默
// 丢弃，读取继续直到收到合法响应或本次尝试超时；流传输则让本次尝试失败以便关闭连接。每次尝试使用
// 新的 Identifier 和更新后的 Acct-Delay-Time。
func (c *Client) AccountRequest(ctx context.Context, request *AccountingRequest) (*AccountingResponse, error) {
	prepared, eventTimestamp, err := prepareAccountingRequest(request)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	packet, raw, requestAuthenticator, err := c.exchange(ctx, CodeAccountingRequest, false, func(int) ([]byte, [16]byte, error) {
		return c.buildAccountingRequest(prepared, start, eventTimestamp)
	})
	if err != nil {
		return nil, err
	}
	secret, err := c.secretSnapshot()
	if err != nil {
		return nil, err
	}
	present, valid, err := verifyMessageAuthenticatorRaw(raw, secret, requestAuthenticator)
	zeroBytes(secret)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	if present && !valid {
		return nil, errs.Detail(ErrMessageAuthenticator, "accounting response Message-Authenticator mismatch")
	}
	response := &AccountingResponse{
		Code:          packet.Code,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		Attributes:    packet.Attributes,
	}
	if message, ok := packet.Attributes.Get(AttrReplyMessage); ok {
		response.ReplyMessage = message.String()
	}
	return response, nil
}

// prepareAccountingRequest validates and copies an Accounting-Request. | prepareAccountingRequest
// 校验并复制 Accounting-Request。
func prepareAccountingRequest(request *AccountingRequest) (*AccountingRequest, time.Time, error) {
	if request == nil {
		return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "accounting request is nil")
	}
	switch request.StatusType {
	case AcctStatusStart, AcctStatusStop, AcctStatusInterimUpdate:
		if request.SessionID == "" {
			return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "session ID is required for status type %d", uint32(request.StatusType))
		}
	case AcctStatusAccountingOn, AcctStatusAccountingOff:
	default:
		return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "unsupported accounting status type %d", uint32(request.StatusType))
	}
	if request.NASIPAddress != nil && request.NASIPAddress.To4() == nil {
		return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "NAS IP address %s is not IPv4", request.NASIPAddress)
	}
	eventTimestamp := request.EventTimestamp
	if eventTimestamp.IsZero() {
		eventTimestamp = time.Now()
	}
	eventTimestamp = eventTimestamp.UTC()
	unix := eventTimestamp.Unix()
	if unix < 0 || unix > int64(maxUint32Value) {
		return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "event timestamp %d is outside the 32-bit Unix range", unix)
	}
	prepared := *request
	prepared.Attributes = request.Attributes.Clone()
	return &prepared, eventTimestamp, nil
}

// buildAccountingRequest encodes one Accounting-Request transmission attempt. | buildAccountingRequest
// 编码一次 Accounting-Request 传输尝试。
func (c *Client) buildAccountingRequest(request *AccountingRequest, start, eventTimestamp time.Time) ([]byte, [16]byte, error) {
	secret, err := c.secretSnapshot()
	if err != nil {
		return nil, [16]byte{}, err
	}
	defer zeroBytes(secret)
	packet := &Packet{
		Code:       CodeAccountingRequest,
		Identifier: c.nextIdentifier(),
	}
	attributes := &packet.Attributes
	attributes.AddUint32(AttrAcctStatusType, uint32(request.StatusType))
	attributes.AddUint32(AttrAcctDelayTime, accountingDelay(request.DelayTime, start))
	if request.SessionID != "" {
		attributes.AddString(AttrAcctSessionID, request.SessionID)
	}
	if request.UserName != "" {
		attributes.AddString(AttrUserName, request.UserName)
	}
	if request.Authentic != 0 {
		attributes.AddUint32(AttrAcctAuthentic, uint32(request.Authentic))
	}
	c.appendNASAttributes(attributes, request.NASIPAddress, request.NASIdentifier, request.NASPort, request.NASPortType)
	if accountingSessionStatus(request.StatusType) {
		attributes.AddUint32(AttrAcctInputOctets, request.InputOctets)
		attributes.AddUint32(AttrAcctOutputOctets, request.OutputOctets)
		attributes.AddUint32(AttrAcctInputPackets, request.InputPackets)
		attributes.AddUint32(AttrAcctOutputPackets, request.OutputPackets)
		attributes.AddUint32(AttrAcctSessionTime, request.SessionTime)
	}
	if request.TerminateCause != 0 {
		attributes.AddUint32(AttrAcctTerminateCause, uint32(request.TerminateCause))
	}
	attributes.AddUint32(AttrEventTimestamp, uint32(eventTimestamp.Unix()))
	if request.CallingStationID != "" {
		attributes.AddString(AttrCallingStationID, request.CallingStationID)
	}
	if request.CalledStationID != "" {
		attributes.AddString(AttrCalledStationID, request.CalledStationID)
	}
	if len(request.Class) != 0 {
		attributes.Add(AttrClass, request.Class)
	}
	for _, attribute := range request.Attributes {
		if accountingManagedAttribute(attribute) {
			continue
		}
		*attributes = append(*attributes, attribute)
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		return nil, [16]byte{}, errs.Wrap(err, ErrInvalidRequest)
	}
	authenticator, err := accountingRequestAuthenticator(raw, secret)
	if err != nil {
		return nil, [16]byte{}, errs.Wrap(err, ErrInvalidRequest)
	}
	copy(raw[4:HeaderLength], authenticator[:])
	return raw, authenticator, nil
}

// accountingDelay returns the Acct-Delay-Time including elapsed retransmission time. | accountingDelay
// 返回包含已过重传时间的 Acct-Delay-Time。
func accountingDelay(initial uint32, start time.Time) uint32 {
	elapsed := time.Since(start)
	if elapsed <= 0 {
		return initial
	}
	seconds := uint64(elapsed / time.Second)
	if seconds == 0 {
		return initial
	}
	total := uint64(initial) + seconds
	if total > uint64(maxUint32Value) {
		return maxUint32Value
	}
	return uint32(total)
}

// accountingSessionStatus reports whether the status carries session counters. | accountingSessionStatus
// 报告状态是否携带会话计数。
func accountingSessionStatus(status AcctStatusType) bool {
	return status == AcctStatusStart || status == AcctStatusStop || status == AcctStatusInterimUpdate
}

// accountingManagedAttribute reports whether an extra attribute is generated by the client. |
// accountingManagedAttribute 报告附加属性是否由客户端生成。
func accountingManagedAttribute(attribute Attribute) bool {
	switch attribute.Type {
	case AttrAcctStatusType, AttrAcctDelayTime, AttrAcctSessionID, AttrAcctAuthentic,
		AttrAcctInputOctets, AttrAcctOutputOctets, AttrAcctInputPackets, AttrAcctOutputPackets,
		AttrAcctSessionTime, AttrAcctTerminateCause, AttrEventTimestamp, AttrMessageAuthenticator:
		return true
	default:
		return false
	}
}
