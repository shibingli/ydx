package radius

import (
	"context"
	"crypto/rand"
	"net"

	"github.com/shibingli/ydx/errs"
)

// AccessRequest describes one Access-Request. | AccessRequest 描述一次 Access-Request。
//
// The convenience fields generate standard attributes; Attributes carries additional attributes
// such as Proxy-State or vendor attributes. Credential attributes generated from Method are
// filtered from Attributes to avoid sending conflicting values. | 便捷字段生成标准属性；
// Attributes 携带附加属性，例如 Proxy-State 或厂商属性。由 Method 生成的凭据属性会从
// Attributes 中过滤，以避免发送冲突值。
type AccessRequest struct {
	// UserName is the login name (User-Name). | UserName 是登录名（User-Name）。
	UserName string
	// Password is the plaintext password for PAP, or the CHAP secret. It is never logged. | Password
	// 是 PAP 的明文口令，或 CHAP 密钥。它绝不会被记录到日志。
	Password string
	// Method selects the authentication mechanism. | Method 选择认证机制。
	Method AuthMethod
	// CHAPChallenge is an explicit CHAP-Challenge; the Request Authenticator is used when empty. |
	// CHAPChallenge 是显式 CHAP 挑战；为空时使用 Request Authenticator。
	CHAPChallenge []byte
	// CHAPIdentifier is the CHAP identifier; the packet Identifier is used when zero. | CHAPIdentifier
	// 是 CHAP 标识；为零时使用报文 Identifier。
	CHAPIdentifier uint8
	// MSCHAPv2 carries MS-CHAPv2 credentials when Method is AuthMSCHAPv2. | MSCHAPv2 在 Method 为
	// AuthMSCHAPv2 时携带 MS-CHAPv2 凭据。
	MSCHAPv2 *MSCHAPv2Credentials
	// EAPMessages carries one or more EAP packets when Method is AuthEAP. | EAPMessages 在 Method
	// 为 AuthEAP 时携带一个或多个 EAP 报文。
	EAPMessages [][]byte
	// IncludeMessageAuthenticator adds and signs a Message-Authenticator. It is always added when
	// an EAP-Message is present, and whenever the request carries one the response must carry a
	// valid Message-Authenticator (RFC 3579 section 3.2). | IncludeMessageAuthenticator 添加并
	// 签名 Message-Authenticator。存在 EAP-Message 时始终添加，且只要请求携带它，响应就必须
	// 携带合法的 Message-Authenticator（RFC 3579 第 3.2 节）。
	IncludeMessageAuthenticator bool
	// State echoes Access-Challenge state from a previous response. | State 回显先前响应的
	// Access-Challenge 状态。
	State []byte
	// NASIPAddress overrides the client NAS-IP-Address. | NASIPAddress 覆盖客户端的 NAS-IP-Address。
	NASIPAddress net.IP
	// NASIdentifier overrides the client NAS-Identifier. | NASIdentifier 覆盖客户端的 NAS-Identifier。
	NASIdentifier string
	// NASPort is the NAS-Port value; zero omits it. | NASPort 是 NAS-Port 值；零值省略该属性。
	NASPort uint32
	// NASPortType is the NAS-Port-Type value; zero omits it. Add AttrNASPortType explicitly to send
	// the Async value zero. | NASPortType 是 NAS-Port-Type 值；零值省略该属性。要发送 Async 值零，
	// 请显式添加 AttrNASPortType。
	NASPortType NASPortType
	// ServiceType is the Service-Type value; zero omits it. | ServiceType 是 Service-Type 值；零值省略该属性。
	ServiceType ServiceType
	// FramedProtocol is the Framed-Protocol value; zero omits it. | FramedProtocol 是
	// Framed-Protocol 值；零值省略该属性。
	FramedProtocol FramedProtocol
	// CallingStationID is the Calling-Station-Id value. | CallingStationID 是 Calling-Station-Id 值。
	CallingStationID string
	// CalledStationID is the Called-Station-Id value. | CalledStationID 是 Called-Station-Id 值。
	CalledStationID string
	// Attributes carries additional attributes. | Attributes 携带附加属性。
	Attributes Attributes
}

// MSCHAPv2Credentials holds MS-CHAPv2 authentication material. | MSCHAPv2Credentials 保存
// MS-CHAPv2 认证材料。
type MSCHAPv2Credentials struct {
	// UserName is the MS-CHAPv2 user name; AccessRequest.UserName is used when empty. | UserName 是
	// MS-CHAPv2 用户名；为空时使用 AccessRequest.UserName。
	UserName string
	// Password is the plaintext password. It is never logged. | Password 是明文口令。它绝不会被记录到日志。
	Password string
	// Challenge is the 16-octet MS-CHAP-Challenge from the server. | Challenge 是服务器发来的 16 字节
	// MS-CHAP-Challenge。
	Challenge []byte
	// PeerChallenge is the 16-octet peer challenge; a random value is generated when empty. |
	// PeerChallenge 是 16 字节对端挑战；为空时生成随机值。
	PeerChallenge []byte
	// Ident is the MS-CHAPv2 identifier; the packet Identifier is used when zero. | Ident 是
	// MS-CHAPv2 标识；为零时使用报文 Identifier。
	Ident uint8
	// Response is a precomputed 50-octet MS-CHAP2-Response value. Challenge is still sent as
	// MS-CHAP-Challenge, while Password and PeerChallenge are not used. | Response 是预计算的
	// 50 字节 MS-CHAP2-Response 值。仍会将 Challenge 作为 MS-CHAP-Challenge 发送，但不使用
	// Password 与 PeerChallenge。
	Response []byte
}

// AccessResponse is the decoded answer to an Access-Request. | AccessResponse 是 Access-Request
// 的解码应答。
type AccessResponse struct {
	// Code is the response code. | Code 是响应码。
	Code Code
	// Identifier is the response packet identifier. | Identifier 是响应报文标识符。
	Identifier uint8
	// Authenticator is the verified Response Authenticator. | Authenticator 是已校验的 Response Authenticator。
	Authenticator [16]byte
	// Attributes holds every response attribute in wire order. | Attributes 按线序保存全部响应属性。
	Attributes Attributes
	// ReplyMessage is the first Reply-Message. | ReplyMessage 是首个 Reply-Message。
	ReplyMessage string
	// ReplyMessages holds every Reply-Message. | ReplyMessages 保存全部 Reply-Message。
	ReplyMessages []string
	// State is the first State value. | State 是首个 State 值。
	State []byte
	// Class is the first Class value. | Class 是首个 Class 值。
	Class []byte
	// SessionTimeout is the Session-Timeout value in seconds. | SessionTimeout 是 Session-Timeout 秒数。
	SessionTimeout uint32
	// IdleTimeout is the Idle-Timeout value in seconds. | IdleTimeout 是 Idle-Timeout 秒数。
	IdleTimeout uint32
	// FilterID is the Filter-Id value. | FilterID 是 Filter-Id 值。
	FilterID string
	// FramedIPAddress is the Framed-IP-Address value. | FramedIPAddress 是 Framed-IP-Address 值。
	FramedIPAddress net.IP
	// TunnelTypes holds every Tunnel-Type value. | TunnelTypes 保存全部 Tunnel-Type 值。
	TunnelTypes []TunnelType
	// TunnelMediumTypes holds every Tunnel-Medium-Type value. | TunnelMediumTypes 保存全部
	// Tunnel-Medium-Type 值。
	TunnelMediumTypes []TunnelMediumType
	// TunnelPrivateGroupIDs holds every Tunnel-Private-Group-Id value. | TunnelPrivateGroupIDs 保存
	// 全部 Tunnel-Private-Group-Id 值。
	TunnelPrivateGroupIDs []string
	// EAPMessages holds every EAP-Message value. | EAPMessages 保存全部 EAP-Message 值。
	EAPMessages [][]byte
	// MSCHAPv2Challenge is the MS-CHAP-Challenge vendor value. | MSCHAPv2Challenge 是
	// MS-CHAP-Challenge 厂商值。
	MSCHAPv2Challenge []byte
	// MSCHAPv2Success is the MS-CHAP2-Success vendor value. | MSCHAPv2Success 是 MS-CHAP2-Success
	// 厂商值。
	MSCHAPv2Success []byte
	// MSCHAPv2Error is the MS-CHAP-Error vendor value. | MSCHAPv2Error 是 MS-CHAP-Error 厂商值。
	MSCHAPv2Error string
}

// Accepted reports whether the response is Access-Accept. | Accepted 报告响应是否为 Access-Accept。
func (r *AccessResponse) Accepted() bool {
	return r != nil && r.Code == CodeAccessAccept
}

// Rejected reports whether the response is Access-Reject. | Rejected 报告响应是否为 Access-Reject。
func (r *AccessResponse) Rejected() bool {
	return r != nil && r.Code == CodeAccessReject
}

// Challenged reports whether the response is Access-Challenge. | Challenged 报告响应是否为 Access-Challenge。
func (r *AccessResponse) Challenged() bool {
	return r != nil && r.Code == CodeAccessChallenge
}

// AccessRequest sends an Access-Request and verifies the response. | AccessRequest 发送
// Access-Request 并校验响应。
//
// PAP, CHAP, MS-CHAPv2 and EAP are supported. Every transmission attempt uses a fresh Identifier
// and Request Authenticator; timeouts are retried with exponential backoff until Retries is
// exhausted or the context ends. UDP responses whose Response Authenticator does not match are
// silently discarded and the attempt keeps waiting for a valid response, as RFC 2865 sections 4.2
// and 4.4 require; stream transports fail the attempt so the connection can be closed. Malformed
// responses and credential failures are not retried. | 支持 PAP、CHAP、MS-CHAPv2 与 EAP。每次传输
// 尝试使用新的 Identifier 与 Request Authenticator；超时按指数退避重试，直到 Retries 用尽或上下文
// 结束。UDP 响应中 Response Authenticator 不匹配者按 RFC 2865 第 4.2 与 4.4 节要求被静默丢弃，
// 本次尝试继续等待合法响应；流传输则让本次尝试失败以便关闭连接。畸形响应与凭据失败不重试。
func (c *Client) AccessRequest(ctx context.Context, request *AccessRequest) (*AccessResponse, error) {
	prepared, err := prepareAccessRequest(request)
	if err != nil {
		return nil, err
	}
	packet, raw, requestAuthenticator, err := c.exchange(ctx, CodeAccessRequest, func(int) ([]byte, [16]byte, error) {
		return c.buildAccessRequest(prepared)
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
		return nil, errs.Detail(ErrMessageAuthenticator, "response Message-Authenticator mismatch")
	}
	if !present && accessIncludesMessageAuthenticator(prepared) {
		return nil, errs.Detail(ErrMessageAuthenticator, "response lacks the required Message-Authenticator")
	}
	return decodeAccessResponse(packet), nil
}

// AuthenticateMSCHAPv2 performs the MS-CHAPv2 probe and challenge exchange. | AuthenticateMSCHAPv2
// 执行 MS-CHAPv2 探测与挑战交互。
//
// The first Access-Request carries no credential so that the server returns an Access-Challenge
// with MS-CHAP-Challenge. The second request carries the computed MS-CHAP2-Response and echoes any
// State. base supplies optional NAS and extra attributes and may be nil. | 首个 Access-Request 不携带
// 凭据，以便服务器返回带 MS-CHAP-Challenge 的 Access-Challenge。第二个请求携带计算出的
// MS-CHAP2-Response 并回显任何 State。base 提供可选的 NAS 与附加属性，可为 nil。
func (c *Client) AuthenticateMSCHAPv2(ctx context.Context, userName, password string, base *AccessRequest) (*AccessResponse, error) {
	if userName == "" {
		return nil, errs.Detail(ErrInvalidRequest, "user name is required")
	}
	probe := AccessRequest{}
	if base != nil {
		probe = *base
		probe.Attributes = base.Attributes.Clone()
	}
	probe.UserName = userName
	probe.Method = AuthNone
	probe.Password = ""
	probe.CHAPChallenge = nil
	probe.CHAPIdentifier = 0
	probe.MSCHAPv2 = nil
	probe.EAPMessages = nil
	probe.IncludeMessageAuthenticator = false
	first, err := c.AccessRequest(ctx, &probe)
	if err != nil {
		return nil, err
	}
	if !first.Challenged() {
		return first, nil
	}
	challenge := append([]byte(nil), first.MSCHAPv2Challenge...)
	if len(challenge) != 16 {
		return nil, errs.Detail(ErrInvalidResponse, "Access-Challenge MS-CHAP-Challenge length %d must be 16", len(challenge))
	}
	peerChallenge := make([]byte, 16)
	if _, err := rand.Read(peerChallenge); err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	response := probe
	response.Method = AuthMSCHAPv2
	response.State = first.State
	response.MSCHAPv2 = &MSCHAPv2Credentials{
		UserName:      userName,
		Password:      password,
		Challenge:     challenge,
		PeerChallenge: peerChallenge,
	}
	return c.AccessRequest(ctx, &response)
}

// prepareAccessRequest validates and copies an Access-Request. | prepareAccessRequest 校验并复制
// Access-Request。
func prepareAccessRequest(request *AccessRequest) (*AccessRequest, error) {
	if request == nil {
		return nil, errs.Detail(ErrInvalidRequest, "access request is nil")
	}
	prepared := *request
	prepared.Attributes = request.Attributes.Clone()
	switch prepared.Method {
	case AuthPAP, AuthCHAP:
		if prepared.UserName == "" {
			return nil, errs.Detail(ErrInvalidRequest, "user name is required for method %d", uint8(prepared.Method))
		}
	case AuthMSCHAPv2:
		if prepared.MSCHAPv2 == nil {
			return nil, errs.Detail(ErrInvalidRequest, "MS-CHAPv2 credentials are required")
		}
		credentials := *prepared.MSCHAPv2
		if credentials.UserName == "" {
			credentials.UserName = prepared.UserName
		}
		if credentials.UserName == "" {
			return nil, errs.Detail(ErrInvalidRequest, "MS-CHAPv2 user name is required")
		}
		if len(credentials.Challenge) != 16 {
			return nil, errs.Detail(ErrInvalidRequest, "MS-CHAPv2 challenge length %d must be 16", len(credentials.Challenge))
		}
		if len(credentials.Response) != 0 {
			if len(credentials.Response) != msCHAPv2ResponseLength {
				return nil, errs.Detail(ErrInvalidRequest, "MS-CHAP2-Response length %d must be %d", len(credentials.Response), msCHAPv2ResponseLength)
			}
		} else {
			if len(credentials.PeerChallenge) == 0 {
				peerChallenge := make([]byte, 16)
				if _, err := rand.Read(peerChallenge); err != nil {
					return nil, errs.Wrap(err, ErrInternal)
				}
				credentials.PeerChallenge = peerChallenge
			}
			if len(credentials.PeerChallenge) != 16 {
				return nil, errs.Detail(ErrInvalidRequest, "MS-CHAPv2 peer challenge length %d must be 16", len(credentials.PeerChallenge))
			}
		}
		prepared.MSCHAPv2 = &credentials
	case AuthEAP:
		if len(prepared.EAPMessages) == 0 {
			return nil, errs.Detail(ErrInvalidRequest, "at least one EAP message is required")
		}
		for _, message := range prepared.EAPMessages {
			if len(message) == 0 {
				return nil, errs.Detail(ErrInvalidRequest, "EAP messages must not be empty")
			}
			if len(message) > MaxAttributeValueLength {
				return nil, errs.Detail(ErrInvalidRequest, "EAP message length %d exceeds %d", len(message), MaxAttributeValueLength)
			}
		}
	case AuthNone:
	default:
		return nil, errs.Detail(ErrInvalidRequest, "unsupported authentication method %d", uint8(prepared.Method))
	}
	if prepared.Method == AuthMSCHAPv2 && prepared.UserName == "" {
		prepared.UserName = prepared.MSCHAPv2.UserName
	}
	if prepared.Method != AuthEAP && prepared.Method != AuthNone {
		for _, attribute := range prepared.Attributes {
			if attribute.Type == AttrEAPMessage {
				return nil, errs.Detail(ErrInvalidRequest, "EAP-Message cannot be combined with method %d", uint8(prepared.Method))
			}
		}
	}
	if prepared.NASIPAddress != nil && prepared.NASIPAddress.To4() == nil {
		return nil, errs.Detail(ErrInvalidRequest, "NAS IP address %s is not IPv4", prepared.NASIPAddress)
	}
	return &prepared, nil
}

// buildAccessRequest encodes one Access-Request transmission attempt. | buildAccessRequest 编码一次
// Access-Request 传输尝试。
func (c *Client) buildAccessRequest(request *AccessRequest) ([]byte, [16]byte, error) {
	var requestAuthenticator [16]byte
	if _, err := rand.Read(requestAuthenticator[:]); err != nil {
		return nil, requestAuthenticator, errs.Wrap(err, ErrInternal)
	}
	packet := &Packet{
		Code:          CodeAccessRequest,
		Identifier:    c.nextIdentifier(),
		Authenticator: requestAuthenticator,
	}
	secret, err := c.secretSnapshot()
	if err != nil {
		return nil, requestAuthenticator, err
	}
	defer zeroBytes(secret)
	if err := c.appendAccessAttributes(packet, request, requestAuthenticator, secret); err != nil {
		return nil, requestAuthenticator, err
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		return nil, requestAuthenticator, errs.Wrap(err, ErrInvalidRequest)
	}
	if accessIncludesMessageAuthenticator(request) {
		if err := signMessageAuthenticator(raw, secret, requestAuthenticator); err != nil {
			return nil, requestAuthenticator, errs.Wrap(err, ErrInvalidRequest)
		}
	}
	return raw, requestAuthenticator, nil
}

// appendAccessAttributes appends the Access-Request attributes. | appendAccessAttributes 追加
// Access-Request 属性。
func (c *Client) appendAccessAttributes(packet *Packet, request *AccessRequest, requestAuthenticator [16]byte, secret []byte) error {
	attributes := &packet.Attributes
	userName := request.UserName
	if request.Method == AuthMSCHAPv2 && request.MSCHAPv2.UserName != "" {
		userName = request.MSCHAPv2.UserName
	}
	if userName != "" {
		attributes.AddString(AttrUserName, userName)
	}
	c.appendNASAttributes(attributes, request.NASIPAddress, request.NASIdentifier, request.NASPort, request.NASPortType)
	if request.ServiceType != 0 {
		attributes.AddUint32(AttrServiceType, uint32(request.ServiceType))
	}
	if request.FramedProtocol != 0 {
		attributes.AddUint32(AttrFramedProtocol, uint32(request.FramedProtocol))
	}
	if request.CallingStationID != "" {
		attributes.AddString(AttrCallingStationID, request.CallingStationID)
	}
	if request.CalledStationID != "" {
		attributes.AddString(AttrCalledStationID, request.CalledStationID)
	}
	if len(request.State) != 0 {
		attributes.Add(AttrState, request.State)
	}
	switch request.Method {
	case AuthPAP:
		password := []byte(request.Password)
		encrypted, err := EncryptUserPassword(secret, requestAuthenticator[:], password)
		zeroBytes(password)
		if err != nil {
			return errs.Wrap(err, ErrInvalidRequest)
		}
		attributes.Add(AttrUserPassword, encrypted)
		zeroBytes(encrypted)
	case AuthCHAP:
		challenge := request.CHAPChallenge
		if len(challenge) == 0 {
			challenge = requestAuthenticator[:]
		} else {
			attributes.Add(AttrCHAPChallenge, challenge)
		}
		ident := request.CHAPIdentifier
		if ident == 0 {
			ident = packet.Identifier
		}
		password := []byte(request.Password)
		response := CHAPResponse(ident, password, challenge)
		zeroBytes(password)
		value := make([]byte, 1+len(response))
		value[0] = ident
		copy(value[1:], response[:])
		attributes.Add(AttrCHAPPassword, value)
		zeroBytes(value)
	case AuthMSCHAPv2:
		credentials := request.MSCHAPv2
		var response []byte
		if len(credentials.Response) != 0 {
			response = credentials.Response
		} else {
			ident := credentials.Ident
			if ident == 0 {
				ident = packet.Identifier
			}
			computed, err := MSCHAPv2Response(credentials.UserName, credentials.Password, credentials.Challenge, credentials.PeerChallenge, ident)
			if err != nil {
				return errs.Wrap(err, ErrInvalidRequest)
			}
			defer zeroBytes(computed)
			response = computed
		}
		if len(credentials.Challenge) != 0 {
			attributes.AddVendor(VendorMicrosoft, VendorMSCHAPChallenge, credentials.Challenge)
		}
		attributes.AddVendor(VendorMicrosoft, VendorMSCHAP2Response, response)
	case AuthEAP:
		for _, message := range request.EAPMessages {
			attributes.Add(AttrEAPMessage, message)
		}
	case AuthNone:
	}
	for _, attribute := range request.Attributes {
		if accessManagedAttribute(request.Method, attribute) {
			continue
		}
		*attributes = append(*attributes, attribute)
	}
	if accessIncludesMessageAuthenticator(request) {
		attributes.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	return nil
}

// accessManagedAttribute reports whether an extra attribute conflicts with a generated credential. |
// accessManagedAttribute 报告附加属性是否与生成的凭据冲突。
func accessManagedAttribute(method AuthMethod, attribute Attribute) bool {
	if attribute.Type == AttrMessageAuthenticator {
		return true
	}
	switch method {
	case AuthPAP:
		return attribute.Type == AttrUserPassword
	case AuthCHAP:
		return attribute.Type == AttrCHAPPassword
	case AuthMSCHAPv2:
		return attribute.Type == AttrVendorSpecific && attribute.VendorID == VendorMicrosoft &&
			(attribute.VendorType == VendorMSCHAPChallenge || attribute.VendorType == VendorMSCHAP2Response)
	case AuthEAP:
		return attribute.Type == AttrEAPMessage
	default:
		return false
	}
}

// accessIncludesEAP reports whether the request carries an EAP-Message. | accessIncludesEAP 报告
// 请求是否携带 EAP-Message。
func accessIncludesEAP(request *AccessRequest) bool {
	if request.Method == AuthEAP {
		return true
	}
	for _, attribute := range request.Attributes {
		if attribute.Type == AttrEAPMessage {
			return true
		}
	}
	return false
}

// accessIncludesMessageAuthenticator reports whether the request carries a Message-Authenticator.
// RFC 3579 section 3.2 requires one whenever an EAP-Message is present. | accessIncludesMessageAuthenticator
// 报告请求是否携带 Message-Authenticator。RFC 3579 第 3.2 节要求存在 EAP-Message 时必须携带。
func accessIncludesMessageAuthenticator(request *AccessRequest) bool {
	return request.IncludeMessageAuthenticator || accessIncludesEAP(request)
}

// decodeAccessResponse extracts typed fields from an Access response packet. | decodeAccessResponse
// 从 Access 响应报文提取类型化字段。
func decodeAccessResponse(packet *Packet) *AccessResponse {
	response := &AccessResponse{
		Code:          packet.Code,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		Attributes:    packet.Attributes,
	}
	for _, attribute := range packet.Attributes {
		switch attribute.Type {
		case AttrReplyMessage:
			response.ReplyMessages = append(response.ReplyMessages, attribute.String())
		case AttrState:
			if response.State == nil {
				response.State = append([]byte(nil), attribute.Value...)
			}
		case AttrClass:
			if response.Class == nil {
				response.Class = append([]byte(nil), attribute.Value...)
			}
		case AttrSessionTimeout:
			if value, ok := attribute.Uint32(); ok {
				response.SessionTimeout = value
			}
		case AttrIdleTimeout:
			if value, ok := attribute.Uint32(); ok {
				response.IdleTimeout = value
			}
		case AttrFilterID:
			if response.FilterID == "" {
				response.FilterID = attribute.String()
			}
		case AttrFramedIPAddress:
			if response.FramedIPAddress == nil {
				if ip, ok := attribute.IPv4(); ok {
					response.FramedIPAddress = ip
				}
			}
		case AttrTunnelType:
			if _, value, ok := attribute.TaggedUint32(); ok {
				response.TunnelTypes = append(response.TunnelTypes, TunnelType(value))
			}
		case AttrTunnelMediumType:
			if _, value, ok := attribute.TaggedUint32(); ok {
				response.TunnelMediumTypes = append(response.TunnelMediumTypes, TunnelMediumType(value))
			}
		case AttrTunnelPrivateGroupID:
			_, value := attribute.TaggedString()
			response.TunnelPrivateGroupIDs = append(response.TunnelPrivateGroupIDs, value)
		case AttrEAPMessage:
			response.EAPMessages = append(response.EAPMessages, append([]byte(nil), attribute.Value...))
		case AttrVendorSpecific:
			if attribute.VendorID != VendorMicrosoft {
				continue
			}
			switch attribute.VendorType {
			case VendorMSCHAPChallenge:
				if response.MSCHAPv2Challenge == nil {
					response.MSCHAPv2Challenge = append([]byte(nil), attribute.Value...)
				}
			case VendorMSCHAP2Success:
				if response.MSCHAPv2Success == nil {
					response.MSCHAPv2Success = append([]byte(nil), attribute.Value...)
				}
			case VendorMSCHAPError:
				if response.MSCHAPv2Error == "" {
					response.MSCHAPv2Error = attribute.String()
				}
			}
		}
	}
	if len(response.ReplyMessages) != 0 {
		response.ReplyMessage = response.ReplyMessages[0]
	}
	return response
}

// appendNASAttributes appends NAS identification attributes. | appendNASAttributes 追加 NAS 标识属性。
func (c *Client) appendNASAttributes(attributes *Attributes, nasIP net.IP, nasIdentifier string, nasPort uint32, nasPortType NASPortType) {
	ip := nasIP
	if ip == nil {
		ip = c.cfg.NASIPAddress
	}
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			attributes.Add(AttrNASIPAddress, v4)
		}
	}
	identifier := nasIdentifier
	if identifier == "" {
		identifier = c.cfg.NASIdentifier
	}
	if identifier != "" {
		attributes.AddString(AttrNASIdentifier, identifier)
	}
	if nasPort != 0 {
		attributes.AddUint32(AttrNASPort, nasPort)
	}
	if nasPortType != 0 {
		attributes.AddUint32(AttrNASPortType, uint32(nasPortType))
	}
}
