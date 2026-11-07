package radius

import (
	"context"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DynamicAuthorizationRequest describes one RFC 5176 Change-of-Authorization (code 43) or
// Disconnect (code 40) request. | DynamicAuthorizationRequest 描述一次 RFC 5176 授权变更
// （类型 43）或断开（类型 40）请求。
//
// Session identification follows RFC 5176 section 2.1: either SessionID identifies the session,
// or UserName is combined with a NAS identity taken from NASIPAddress, NASIdentifier or the client
// defaults. Attributes carries the authorization changes of a CoA-Request or additional session
// identifiers of a Disconnect-Request. | 会话标识遵循 RFC 5176 第 2.1 节：或由 SessionID 标识会话，
// 或由 UserName 配合取自 NASIPAddress、NASIdentifier 或客户端默认值的 NAS 标识。Attributes 携带
// CoA-Request 的授权变更，或 Disconnect-Request 的附加会话标识。
type DynamicAuthorizationRequest struct {
	// SessionID is Acct-Session-Id. Required unless UserName identifies the session. | SessionID
	// 是 Acct-Session-Id。除非由 UserName 标识会话，否则必填。
	SessionID string
	// UserName is User-Name. A User-Name-only request also needs NASIPAddress, NASIdentifier or
	// the corresponding client default. | UserName 是 User-Name。仅携带 User-Name 的请求还需要
	// NASIPAddress、NASIdentifier 或相应的客户端默认值。
	UserName string
	// NASIPAddress overrides the client NAS-IP-Address and must be IPv4. | NASIPAddress 覆盖客户端
	// NAS-IP-Address，必须是 IPv4。
	NASIPAddress net.IP
	// NASIdentifier overrides the client NAS-Identifier. | NASIdentifier 覆盖客户端 NAS-Identifier。
	NASIdentifier string
	// NASPort is the NAS-Port value; zero omits it. | NASPort 是 NAS-Port 值；零值省略该属性。
	NASPort uint32
	// EventTimestamp is Event-Timestamp; the current time is used when zero. RFC 5176 section 3.6
	// recommends including it and keeping it unchanged on retransmission. | EventTimestamp 是
	// Event-Timestamp；为零时使用当前时间。RFC 5176 第 3.6 节建议携带该属性，并在重传时保持不变。
	EventTimestamp time.Time
	// IncludeMessageAuthenticator adds and signs a Message-Authenticator. When set, the ACK or NAK
	// must also carry a valid Message-Authenticator (RFC 5176 section 3.4). | IncludeMessageAuthenticator
	// 添加并签名 Message-Authenticator。设置后，ACK 或 NAK 也必须携带合法的 Message-Authenticator
	// （RFC 5176 第 3.4 节）。
	IncludeMessageAuthenticator bool
	// Attributes carries additional attributes. Client-managed attributes (User-Name,
	// Acct-Session-Id, NAS-IP-Address, NAS-Identifier, NAS-Port, Event-Timestamp and
	// Message-Authenticator) are supplied through the fields above and ignored here; Error-Cause is
	// rejected because it is only valid in ACK and NAK responses. | Attributes 携带附加属性。客户端
	// 管理的属性（User-Name、Acct-Session-Id、NAS-IP-Address、NAS-Identifier、NAS-Port、
	// Event-Timestamp 与 Message-Authenticator）由上述字段提供并在此忽略；Error-Cause 会被拒绝，
	// 因为它只允许出现在 ACK 与 NAK 响应中。
	Attributes Attributes
}

// CoARequest is the Change-of-Authorization Request (RFC 5176 code 43) accepted by Client.SendCoA.
// | CoARequest 是 Client.SendCoA 接受的授权变更请求（RFC 5176 类型 43）。
type CoARequest = DynamicAuthorizationRequest

// DisconnectRequest is the Disconnect-Request (RFC 5176 code 40) accepted by
// Client.SendDisconnect. | DisconnectRequest 是 Client.SendDisconnect 接受的断开请求
// （RFC 5176 类型 40）。
type DisconnectRequest = DynamicAuthorizationRequest

// DynamicAuthorizationResponse is the decoded ACK or NAK answering a CoA-Request or
// Disconnect-Request. | DynamicAuthorizationResponse 是应答 CoA-Request 或 Disconnect-Request 的
// 已解码 ACK 或 NAK。
type DynamicAuthorizationResponse struct {
	// Code is CodeCoAACK, CodeCoANAK, CodeDisconnectACK or CodeDisconnectNAK. | Code 是
	// CodeCoAACK、CodeCoANAK、CodeDisconnectACK 或 CodeDisconnectNAK。
	Code Code
	// Identifier is the response packet identifier. | Identifier 是响应报文标识符。
	Identifier uint8
	// Authenticator is the verified Response Authenticator. | Authenticator 是已校验的 Response Authenticator。
	Authenticator [16]byte
	// Attributes holds every response attribute in wire order. | Attributes 按线序保存全部响应属性。
	Attributes Attributes
	// ErrorCause is the decoded Error-Cause value; it is zero when HasErrorCause is false. |
	// ErrorCause 是已解码的 Error-Cause 值；HasErrorCause 为 false 时为零。
	ErrorCause ErrorCause
	// HasErrorCause reports whether the response carried Error-Cause. | HasErrorCause 报告响应是否
	// 携带 Error-Cause。
	HasErrorCause bool
	// ReplyMessage is the first Reply-Message. | ReplyMessage 是首个 Reply-Message。
	ReplyMessage string
}

// CoAResponse is the ACK or NAK answering a CoA-Request. | CoAResponse 是应答 CoA-Request 的 ACK 或 NAK。
type CoAResponse = DynamicAuthorizationResponse

// DisconnectResponse is the ACK or NAK answering a Disconnect-Request. | DisconnectResponse 是应答
// Disconnect-Request 的 ACK 或 NAK。
type DisconnectResponse = DynamicAuthorizationResponse

// Acknowledged reports whether the response is a CoA-ACK or Disconnect-ACK. | Acknowledged 报告响应
// 是否为 CoA-ACK 或 Disconnect-ACK。
func (r *DynamicAuthorizationResponse) Acknowledged() bool {
	return r != nil && (r.Code == CodeCoAACK || r.Code == CodeDisconnectACK)
}

// Rejected reports whether the response is a CoA-NAK or Disconnect-NAK. | Rejected 报告响应是否为
// CoA-NAK 或 Disconnect-NAK。
func (r *DynamicAuthorizationResponse) Rejected() bool {
	return r != nil && (r.Code == CodeCoANAK || r.Code == CodeDisconnectNAK)
}

// SendCoA sends a Change-of-Authorization Request (RFC 5176 code 43) and verifies the ACK or NAK.
// | SendCoA 发送授权变更请求（RFC 5176 类型 43）并校验 ACK 或 NAK。
//
// The Request Authenticator uses the RFC 2866 calculation required by RFC 5176 section 2.3.
// Timeouts are retransmitted with exponential backoff until Retries is exhausted or the context
// ends. Every retransmission resends byte-identical content, including the Identifier, Request
// Authenticator and Event-Timestamp, so the NAS can detect duplicates as RFC 5176 section 3.6
// recommends; each SendCoA call uses a fresh Identifier. A CoA-NAK returns a non-nil response and
// an error wrapping ErrCoANAK that reports Error-Cause. Malformed or unauthenticated responses,
// Message-Authenticator failures and unexpected response codes are not retried. | Request
// Authenticator 使用 RFC 5176 第 2.3 节要求的 RFC 2866 算法。超时按指数退避重传，直到 Retries
// 用尽或上下文结束。每次重传发送完全相同的字节，包括 Identifier、Request Authenticator 与
// Event-Timestamp，以便 NAS 按 RFC 5176 第 3.6 节建议进行重复检测；每次 SendCoA 调用使用新的
// Identifier。CoA-NAK 会返回非空响应与包装 ErrCoANAK 并报告 Error-Cause 的错误。畸形或未通过
// 认证的响应、Message-Authenticator 失败以及意外响应类型不会重试。
func (c *Client) SendCoA(ctx context.Context, request *CoARequest) (*CoAResponse, error) {
	return c.sendDynamicAuthorization(ctx, CodeCoARequest, request, ErrCoANAK)
}

// SendDisconnect sends a Disconnect-Request (RFC 5176 code 40) and verifies the ACK or NAK. | SendDisconnect
// 发送断开请求（RFC 5176 类型 40）并校验 ACK 或 NAK。
//
// The retransmission and verification rules are the same as SendCoA. A Disconnect-NAK returns a
// non-nil response and an error wrapping ErrDisconnectNAK that reports Error-Cause. | 重传与校验
// 规则与 SendCoA 相同。Disconnect-NAK 会返回非空响应与包装 ErrDisconnectNAK 并报告 Error-Cause
// 的错误。
func (c *Client) SendDisconnect(ctx context.Context, request *DisconnectRequest) (*DisconnectResponse, error) {
	return c.sendDynamicAuthorization(ctx, CodeDisconnectRequest, request, ErrDisconnectNAK)
}

// sendDynamicAuthorization performs one CoA or Disconnect exchange. | sendDynamicAuthorization 执行
// 一次 CoA 或断开交互。
func (c *Client) sendDynamicAuthorization(ctx context.Context, requestCode Code, request *DynamicAuthorizationRequest, nakError error) (*DynamicAuthorizationResponse, error) {
	prepared, eventTimestamp, err := c.prepareDynamicAuthorizationRequest(request)
	if err != nil {
		return nil, err
	}
	raw, requestAuthenticator, err := c.buildDynamicAuthorizationRequest(requestCode, prepared, eventTimestamp)
	if err != nil {
		return nil, err
	}
	// RFC 5176 section 3.6: retransmissions keep the Identifier and Event-Timestamp so the
	// server can detect duplicates; the Request Authenticator therefore also stays unchanged. |
	// RFC 5176 第 3.6 节：重传保持 Identifier 与 Event-Timestamp，便于服务器检测重复，因此
	// Request Authenticator 也保持不变。
	packet, received, verifiedAuthenticator, err := c.exchange(ctx, requestCode, func(int) ([]byte, [16]byte, error) {
		return raw, requestAuthenticator, nil
	})
	if err != nil {
		return nil, err
	}
	secret, err := c.secretSnapshot()
	if err != nil {
		return nil, err
	}
	present, valid, err := verifyMessageAuthenticatorRaw(received, secret, verifiedAuthenticator)
	zeroBytes(secret)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidResponse)
	}
	if present && !valid {
		return nil, errs.Detail(ErrMessageAuthenticator, "dynamic authorization response Message-Authenticator mismatch")
	}
	if prepared.IncludeMessageAuthenticator && !present {
		return nil, errs.Detail(ErrMessageAuthenticator, "dynamic authorization response lacks the required Message-Authenticator")
	}
	response := decodeDynamicAuthorizationResponse(packet)
	if response.Rejected() {
		if response.HasErrorCause {
			return response, errs.Detail(nakError, "code %d Error-Cause %d (%s)", uint8(response.Code), uint32(response.ErrorCause), response.ErrorCause.String())
		}
		return response, errs.Detail(nakError, "code %d without Error-Cause", uint8(response.Code))
	}
	return response, nil
}

// prepareDynamicAuthorizationRequest validates and copies a CoA or Disconnect request. | prepareDynamicAuthorizationRequest
// 校验并复制 CoA 或断开请求。
func (c *Client) prepareDynamicAuthorizationRequest(request *DynamicAuthorizationRequest) (*DynamicAuthorizationRequest, time.Time, error) {
	if request == nil {
		return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "dynamic authorization request is nil")
	}
	if request.SessionID == "" && request.UserName == "" {
		return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "Acct-Session-Id or User-Name is required")
	}
	nasIP := request.NASIPAddress
	if nasIP == nil {
		nasIP = c.cfg.NASIPAddress
	}
	nasIdentifier := request.NASIdentifier
	if nasIdentifier == "" {
		nasIdentifier = c.cfg.NASIdentifier
	}
	if request.SessionID == "" && nasIP == nil && nasIdentifier == "" {
		return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "User-Name sessions require NAS-IP-Address or NAS-Identifier")
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
	for _, attribute := range prepared.Attributes {
		if attribute.Type == AttrErrorCause {
			return nil, time.Time{}, errs.Detail(ErrInvalidRequest, "Error-Cause is only valid in ACK and NAK responses")
		}
	}
	return &prepared, eventTimestamp, nil
}

// buildDynamicAuthorizationRequest encodes one CoA or Disconnect request. | buildDynamicAuthorizationRequest
// 编码一次 CoA 或断开请求。
func (c *Client) buildDynamicAuthorizationRequest(requestCode Code, request *DynamicAuthorizationRequest, eventTimestamp time.Time) ([]byte, [16]byte, error) {
	secret, err := c.secretSnapshot()
	if err != nil {
		return nil, [16]byte{}, err
	}
	defer zeroBytes(secret)
	packet := &Packet{
		Code:       requestCode,
		Identifier: c.nextIdentifier(),
	}
	attributes := &packet.Attributes
	if request.SessionID != "" {
		attributes.AddString(AttrAcctSessionID, request.SessionID)
	}
	if request.UserName != "" {
		attributes.AddString(AttrUserName, request.UserName)
	}
	c.appendNASAttributes(attributes, request.NASIPAddress, request.NASIdentifier, request.NASPort, 0)
	attributes.AddUint32(AttrEventTimestamp, uint32(eventTimestamp.Unix()))
	for _, attribute := range request.Attributes {
		if dynamicManagedAttribute(attribute) {
			continue
		}
		*attributes = append(*attributes, attribute)
	}
	if request.IncludeMessageAuthenticator {
		attributes.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		return nil, [16]byte{}, errs.Wrap(err, ErrInvalidRequest)
	}
	authenticator, err := signDynamicRequest(raw, secret, request.IncludeMessageAuthenticator)
	if err != nil {
		return nil, [16]byte{}, errs.Wrap(err, ErrInvalidRequest)
	}
	return raw, authenticator, nil
}

// dynamicManagedAttribute reports whether an extra attribute is generated by the client. | dynamicManagedAttribute
// 报告附加属性是否由客户端生成。
func dynamicManagedAttribute(attribute Attribute) bool {
	switch attribute.Type {
	case AttrUserName, AttrAcctSessionID, AttrNASIPAddress, AttrNASIdentifier, AttrNASPort,
		AttrEventTimestamp, AttrMessageAuthenticator, AttrErrorCause:
		return true
	default:
		return false
	}
}

// decodeDynamicAuthorizationResponse extracts typed fields from an ACK or NAK packet. | decodeDynamicAuthorizationResponse
// 从 ACK 或 NAK 报文提取类型化字段。
func decodeDynamicAuthorizationResponse(packet *Packet) *DynamicAuthorizationResponse {
	response := &DynamicAuthorizationResponse{
		Code:          packet.Code,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		Attributes:    packet.Attributes,
	}
	if attribute, ok := packet.Attributes.Get(AttrErrorCause); ok {
		if cause, ok := attribute.Uint32(); ok {
			response.ErrorCause = ErrorCause(cause)
			response.HasErrorCause = true
		}
	}
	if message, ok := packet.Attributes.Get(AttrReplyMessage); ok {
		response.ReplyMessage = message.String()
	}
	return response
}
