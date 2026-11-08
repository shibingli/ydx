package radius

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// AccountingHandler records one authenticated Accounting-Request. | AccountingHandler 记录一次已认证的
// Accounting-Request。
//
// The handler receives a context bounded by AccountingServerConfig.Timeout, derived from the server
// context. It must return promptly or honor cancellation. Returning an error or a nil result sends no
// Accounting-Response, so the NAS retransmits the record; the error is logged and never exposed to
// the client. A non-nil result sends Accounting-Response with the optional reply attributes.
// Handlers must be safe for concurrent use when the server is shared. | 处理器接收由服务器上下文派生、
// 受 AccountingServerConfig.Timeout 约束的上下文。它必须及时返回或响应取消。返回错误或 nil 结果
// 不会发送 Accounting-Response，NAS 会重传记费记录；错误会写入日志，绝不会暴露给客户端。非 nil
// 结果会发送带可选回复属性的 Accounting-Response。服务器被共享时，处理器必须可并发使用。
type AccountingHandler interface {
	// HandleAccounting records request and returns the reply attributes. | HandleAccounting 记录
	// request 并返回回复属性。
	HandleAccounting(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error)
}

// AccountingHandlerFunc adapts a function to AccountingHandler. | AccountingHandlerFunc 将函数适配为
// AccountingHandler。
type AccountingHandlerFunc func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error)

// HandleAccounting calls f. A nil f returns ErrInvalidRequest instead of panicking. | HandleAccounting
// 调用 f。f 为 nil 时返回 ErrInvalidRequest 而不是 panic。
func (f AccountingHandlerFunc) HandleAccounting(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidRequest, "accounting handler function is nil")
	}
	return f(ctx, request)
}

// AccountingServerRequest is one authenticated Accounting-Request received by an AccountingServer. |
// AccountingServerRequest 是 AccountingServer 收到的一次已认证 Accounting-Request。
//
// The server verifies the RFC 2866 Request Authenticator before decoding. Start, Stop and
// Interim-Update require Acct-Session-Id, and every request requires NAS-IP-Address or
// NAS-Identifier, as RFC 2866 section 4.1 specifies. Attributes preserves every attribute in wire
// order. | 服务器在解码前校验 RFC 2866 Request Authenticator。按 RFC 2866 第 4.1 节要求，Start、Stop
// 与 Interim-Update 要求 Acct-Session-Id，每个请求都要求 NAS-IP-Address 或 NAS-Identifier。
// Attributes 按线序保留全部属性。
type AccountingServerRequest struct {
	// EventTimestamp is Event-Timestamp; it is only meaningful when HasEventTimestamp is true. |
	// EventTimestamp 是 Event-Timestamp；仅在 HasEventTimestamp 为 true 时有意义。
	EventTimestamp time.Time
	// RemoteAddr is the datagram source or stream peer address. | RemoteAddr 是数据报源地址或流对端地址。
	RemoteAddr net.Addr
	// SessionID is Acct-Session-Id; required for Start, Stop and Interim-Update. | SessionID 是
	// Acct-Session-Id；Start、Stop 与 Interim-Update 必填。
	SessionID string
	// UserName is User-Name, empty when absent. | UserName 是 User-Name，缺失时为空。
	UserName string
	// NASIdentifier is NAS-Identifier, empty when absent. | NASIdentifier 是 NAS-Identifier，缺失时为空。
	NASIdentifier string
	// MultiSessionID is Acct-Multi-Session-Id, empty when absent. | MultiSessionID 是
	// Acct-Multi-Session-Id，缺失时为空。
	MultiSessionID string
	// CallingStationID is Calling-Station-Id, empty when absent. | CallingStationID 是
	// Calling-Station-Id，缺失时为空。
	CallingStationID string
	// CalledStationID is Called-Station-Id, empty when absent. | CalledStationID 是
	// Called-Station-Id，缺失时为空。
	CalledStationID string
	// NASIPAddress is NAS-IP-Address, nil when absent. | NASIPAddress 是 NAS-IP-Address，缺失时为 nil。
	NASIPAddress net.IP
	// Class is the first Class value, nil when absent. | Class 是首个 Class 值，缺失时为 nil。
	Class []byte
	// Attributes holds every request attribute in wire order, including vendor attributes. |
	// Attributes 按线序保存全部请求属性，包括厂商属性。
	Attributes Attributes
	// StatusType is the required Acct-Status-Type: Start, Stop, Interim-Update, Accounting-On or
	// Accounting-Off. | StatusType 是必填的 Acct-Status-Type：Start、Stop、Interim-Update、
	// Accounting-On 或 Accounting-Off。
	StatusType AcctStatusType
	// NASPort is NAS-Port, zero when absent. | NASPort 是 NAS-Port，缺失时为零。
	NASPort uint32
	// NASPortType is NAS-Port-Type, zero when absent. | NASPortType 是 NAS-Port-Type，缺失时为零。
	NASPortType NASPortType
	// Authentic is Acct-Authentic, zero when absent. | Authentic 是 Acct-Authentic，缺失时为零。
	Authentic AcctAuthentic
	// DelayTime is Acct-Delay-Time in seconds, zero when absent. | DelayTime 是 Acct-Delay-Time 秒数，
	// 缺失时为零。
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
	// TerminateCause is Acct-Terminate-Cause, zero when absent. | TerminateCause 是
	// Acct-Terminate-Cause，缺失时为零。
	TerminateCause AcctTerminateCause
	// Authenticator is the verified Request Authenticator. | Authenticator 是已校验的 Request Authenticator。
	Authenticator [16]byte
	// HasEventTimestamp reports whether Event-Timestamp was present. | HasEventTimestamp 报告是否携带
	// Event-Timestamp。
	HasEventTimestamp bool
	// Identifier is the request identifier, reused by the response. | Identifier 是请求标识符，由响应复用。
	Identifier uint8
}

// AccountingServerResult is the handler result for one Accounting-Request. | AccountingServerResult
// 是处理器对一次 Accounting-Request 的结果。
//
// A non-nil result acknowledges the record with Accounting-Response. Proxy-State is echoed from the
// request automatically and is ignored inside Attributes. ReplyMessage is a convenience for a single
// Reply-Message and is emitted before Attributes. | 非 nil 结果会以 Accounting-Response 确认记录。
// Proxy-State 会自动从请求回显，Attributes 中的该属性会被忽略。ReplyMessage 是单个 Reply-Message 的
// 便捷字段，并在 Attributes 之前编码。
type AccountingServerResult struct {
	// ReplyMessage is the optional Reply-Message text; empty omits the attribute. | ReplyMessage 是
	// 可选 Reply-Message 文本；空值省略该属性。
	ReplyMessage string
	// Attributes carries additional response attributes in wire order. | Attributes 按线序携带附加
	// 响应属性。
	Attributes Attributes
}

// AccountingServerConfig configures an AccountingServer. | AccountingServerConfig 配置 AccountingServer。
type AccountingServerConfig struct {
	// ClientLookup optionally resolves a per-client shared secret before verification. When set it
	// takes precedence over Secret. | ClientLookup 可选地在校验前解析每客户端共享密钥。设置后优先于
	// Secret。
	ClientLookup ServerClientLookup
	// Handler is required and records every authenticated request. | Handler 必填，记录每个已认证请求。
	Handler AccountingHandler
	// TLSConfig configures the server certificate and policy for network "tls". It is required for
	// TLS and cloned by the constructor. | TLSConfig 为 "tls" 网络配置服务器证书与策略。TLS 必填，
	// 并由构造函数克隆。
	TLSConfig *tls.Config
	// Logger receives dropped-request and handler diagnostics; nil selects log.Default(). It never
	// receives the shared secret or request contents. | Logger 接收丢包与处理器诊断；nil 选择
	// log.Default()。它绝不会收到共享密钥或请求内容。
	Logger *log.Logger
	// Network selects the transport: "udp" (the default), "udp4", "udp6", "tcp", "tcp4", "tcp6",
	// "tls", "tls4" or "tls6". TCP and TLS serve length-delimited RFC 6613/RFC 6614 streams. |
	// Network 选择传输："udp"（默认）、"udp4"、"udp6"、"tcp"、"tcp4"、"tcp6"、"tls"、"tls4" 或
	// "tls6"。TCP 与 TLS 服务按长度分帧的 RFC 6613/RFC 6614 流。
	Network string
	// Address is the listen "host:port"; empty selects DefaultAccountingServerAddress for UDP and
	// DefaultServerTLSAddress for TCP and TLS. | Address 是监听 "host:port"；UDP 空值选择
	// DefaultAccountingServerAddress，TCP 与 TLS 空值选择 DefaultServerTLSAddress。
	Address string
	// Secret is the shared secret used to verify Request Authenticators and sign responses. It is
	// ignored when ClientLookup is set. The server copies it and zeroes its copy in Close. | Secret
	// 是用于校验 Request Authenticator 与签名响应的共享密钥。设置 ClientLookup 时忽略该字段。服务器
	// 会复制它并在 Close 时清零副本。
	Secret []byte
	// Timeout bounds one handler invocation and, on stream transports, one response write; zero
	// selects DefaultTimeout. It does not bound the lifetime of Serve. | Timeout 约束一次处理器调用
	// 以及流传输的一次响应写入；零值选择 DefaultTimeout。它不约束 Serve 的生命周期。
	Timeout time.Duration
	// MaxPacketSize is the largest accepted datagram or stream frame; zero selects MaxPacketLength.
	// Values below HeaderLength or above MaxPacketLength are rejected and larger requests are
	// dropped without a response. | MaxPacketSize 是接受的最大数据报或流帧；零值选择
	// MaxPacketLength。低于 HeaderLength 或高于 MaxPacketLength 的值会被拒绝，更大的请求会被静默
	// 丢弃而不响应。
	MaxPacketSize int
	// MaxConcurrent is the maximum number of requests handled at once; zero selects
	// DefaultMaxConcurrentRequests. UDP requests and stream connections beyond the limit are
	// dropped. Negative values are rejected. | MaxConcurrent 是同时处理的最大请求数；零值选择
	// DefaultMaxConcurrentRequests。超出上限的 UDP 请求与流连接会被丢弃。负值会被拒绝。
	MaxConcurrent int
}

// AccountingServer is a reusable Accounting-Request recorder over UDP, TCP or TLS. | AccountingServer
// 是基于 UDP、TCP 或 TLS 的可复用 Accounting-Request 记录器。
//
// The server validates packet structure, resolves the client secret, verifies the RFC 2866 Request
// Authenticator, checks the required attributes, invokes the AccountingHandler and returns a signed
// Accounting-Response. Proxy-State is echoed unchanged. RFC 2869 does not define a Message-
// Authenticator calculation for Accounting-Request, so the server does not validate one, and it does
// not suppress duplicate records: retransmissions are delivered to the handler. Requests are handled
// concurrently up to MaxConcurrent. An AccountingServer is safe for concurrent use, and Close may run
// while Serve is active. | 服务器校验报文结构、解析客户端密钥、校验 RFC 2866 Request Authenticator、
// 检查必选属性、调用 AccountingHandler，并返回已签名的 Accounting-Response。Proxy-State 原样回显。
// RFC 2869 未定义 Accounting-Request 的 Message-Authenticator 算法，因此服务器不校验该属性，也不
// 抑制重复记录：重传会交给处理器。请求最多按 MaxConcurrent 并发处理。AccountingServer 可并发使用，
// Close 可在 Serve 活动期间调用。
type AccountingServer struct {
	handler   AccountingHandler
	secrets   *serverSecretResolver
	logger    *log.Logger
	transport *serverTransport
}

// NewAccountingServer validates config and returns a server. The server does not bind until Listen
// or ListenAndServe is called. | NewAccountingServer 校验 config 并返回服务器。服务器在调用 Listen
// 或 ListenAndServe 之前不会绑定套接字。
func NewAccountingServer(config AccountingServerConfig) (*AccountingServer, error) {
	settings, err := normalizeServerSettings(
		config.Network,
		config.Address,
		DefaultAccountingServerAddress,
		config.MaxPacketSize,
		config.MaxConcurrent,
		config.Timeout,
		config.TLSConfig,
	)
	if err != nil {
		return nil, err
	}
	if config.Handler == nil {
		return nil, errs.Detail(ErrInvalidConfig, "accounting handler is required")
	}
	if config.ClientLookup == nil && len(config.Secret) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret or client lookup is required")
	}
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}
	server := &AccountingServer{
		handler: config.Handler,
		secrets: newServerSecretResolver(config.Secret, config.ClientLookup),
		logger:  logger,
	}
	server.transport = newServerTransport(serverTransportConfig{
		settings: settings,
		label:    "accounting",
		logger:   logger,
		handle:   server.handleRequest,
	})
	return server, nil
}

// Listen binds the configured address and returns it. Calling Listen again returns the existing
// address. | Listen 绑定配置的地址并返回它。再次调用 Listen 返回现有地址。
func (s *AccountingServer) Listen() (net.Addr, error) {
	return s.transport.Listen()
}

// Addr returns the bound address, or nil before Listen. | Addr 返回已绑定的地址，Listen 之前为 nil。
func (s *AccountingServer) Addr() net.Addr {
	return s.transport.Addr()
}

// ListenAndServe binds the configured address and serves until ctx is done or Close is called. It
// returns nil after context cancellation and ErrServerClosed after Close. | ListenAndServe 绑定配置的
// 地址并服务，直到 ctx 结束或调用 Close。上下文取消后返回 nil，Close 之后返回 ErrServerClosed。
func (s *AccountingServer) ListenAndServe(ctx context.Context) error {
	if _, err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Serve serves the bound address until ctx is done or Close is called. Listen must be called first;
// Serve takes ownership of the bound socket or listener and closes it when it returns. It returns
// nil after context cancellation, ErrServerClosed after Close, ErrInvalidConfig when the server is
// not listening or is already serving, and an error wrapping ErrNetwork for a transport failure. |
// Serve 服务已绑定的地址，直到 ctx 结束或调用 Close。必须先调用 Listen；Serve 接管已绑定的套接字或
// 监听器并在返回时关闭它。上下文取消后返回 nil，Close 之后返回 ErrServerClosed，服务器未监听或已在
// 服务时返回 ErrInvalidConfig，传输故障返回包装 ErrNetwork 的错误。
func (s *AccountingServer) Serve(ctx context.Context) error {
	return s.transport.Serve(ctx)
}

// Close zeroizes the static shared secret, closes the socket or listener and every stream connection,
// and rejects further Listen and Serve calls. Close is idempotent and safe for concurrent use. |
// Close 清零静态共享密钥、关闭套接字或监听器以及全部流连接，并拒绝后续 Listen 与 Serve 调用。Close
// 幂等且可并发使用。
func (s *AccountingServer) Close() error {
	err := s.transport.Close()
	s.secrets.close()
	return err
}

// handleRequest authenticates and answers one Accounting-Request. The keep result reports whether the
// stream connection may remain open; UDP ignores it. | handleRequest 认证并应答一次 Accounting-Request。
// keep 结果报告流连接是否可以保持打开；UDP 忽略它。
func (s *AccountingServer) handleRequest(ctx context.Context, raw []byte, remote net.Addr) ([]byte, bool) {
	packet, err := ParsePacket(raw)
	if err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	if packet.Code != CodeAccountingRequest {
		s.logDrop(remote, errs.Detail(ErrUnexpectedCode, "accounting server received code %d", uint8(packet.Code)))
		return nil, false
	}
	secret, err := s.secrets.resolve(ctx, remote, packet.Attributes)
	if err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	defer zeroBytes(secret)
	if err := verifyAccountingRequestAuthenticator(raw, secret); err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	request, err := decodeAccountingServerRequest(packet, remote)
	if err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	result, err := s.handler.HandleAccounting(ctx, request)
	if err != nil {
		s.logger.Warn("radius: accounting handler failed | radius：计费处理器失败",
			log.Str("peer", peerString(remote)), log.Err(err))
		return nil, true
	}
	if result == nil {
		s.logger.Warn("radius: accounting handler returned a nil result | radius：计费处理器返回 nil 结果",
			log.Str("peer", peerString(remote)))
		return nil, true
	}
	response, err := buildAccountingResponse(packet, result, secret)
	if err != nil {
		s.logger.Warn("radius: invalid accounting response | radius：计费响应非法",
			log.Str("peer", peerString(remote)), log.Err(err))
		response, err = buildAccountingResponse(packet, &AccountingServerResult{}, secret)
		if err != nil {
			s.logger.Error("radius: cannot encode accounting response | radius：无法编码计费响应",
				log.Str("peer", peerString(remote)), log.Err(err))
			return nil, true
		}
	}
	return response, true
}

// decodeAccountingServerRequest validates required attributes and extracts typed fields. |
// decodeAccountingServerRequest 校验必选属性并提取类型化字段。
func decodeAccountingServerRequest(packet *Packet, remote net.Addr) (*AccountingServerRequest, error) {
	statusAttribute, ok := packet.Attributes.Get(AttrAcctStatusType)
	if !ok {
		return nil, errs.Detail(ErrInvalidRequest, "accounting request lacks Acct-Status-Type")
	}
	status, ok := statusAttribute.Uint32()
	if !ok {
		return nil, errs.Detail(ErrInvalidAttribute, "Acct-Status-Type is not a 32-bit value")
	}
	switch AcctStatusType(status) {
	case AcctStatusStart, AcctStatusStop, AcctStatusInterimUpdate, AcctStatusAccountingOn, AcctStatusAccountingOff:
	default:
		return nil, errs.Detail(ErrInvalidRequest, "unsupported accounting status type %d", status)
	}
	if accountingSessionStatus(AcctStatusType(status)) {
		if _, ok := packet.Attributes.Get(AttrAcctSessionID); !ok {
			return nil, errs.Detail(ErrInvalidRequest, "Acct-Session-Id is required for status type %d", status)
		}
	}
	if _, ok := packet.Attributes.Get(AttrNASIPAddress); !ok {
		if _, ok := packet.Attributes.Get(AttrNASIdentifier); !ok {
			return nil, errs.Detail(ErrInvalidRequest, "NAS-IP-Address or NAS-Identifier is required")
		}
	}
	request := &AccountingServerRequest{
		StatusType:    AcctStatusType(status),
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		RemoteAddr:    remote,
		Attributes:    packet.Attributes.Clone(),
	}
	if attribute, ok := request.Attributes.Get(AttrAcctSessionID); ok {
		request.SessionID = attribute.String()
	}
	if attribute, ok := request.Attributes.Get(AttrUserName); ok {
		request.UserName = attribute.String()
	}
	if attribute, ok := request.Attributes.Get(AttrNASIPAddress); ok {
		if ip, ok := attribute.IPv4(); ok {
			request.NASIPAddress = ip
		}
	}
	if attribute, ok := request.Attributes.Get(AttrNASIdentifier); ok {
		request.NASIdentifier = attribute.String()
	}
	if value, ok := request.Attributes.Uint32(AttrNASPort); ok {
		request.NASPort = value
	}
	if value, ok := request.Attributes.Uint32(AttrNASPortType); ok {
		request.NASPortType = NASPortType(value)
	}
	if value, ok := request.Attributes.Uint32(AttrAcctAuthentic); ok {
		request.Authentic = AcctAuthentic(value)
	}
	if value, ok := request.Attributes.Uint32(AttrAcctDelayTime); ok {
		request.DelayTime = value
	}
	if value, ok := request.Attributes.Uint32(AttrAcctInputOctets); ok {
		request.InputOctets = value
	}
	if value, ok := request.Attributes.Uint32(AttrAcctOutputOctets); ok {
		request.OutputOctets = value
	}
	if value, ok := request.Attributes.Uint32(AttrAcctInputPackets); ok {
		request.InputPackets = value
	}
	if value, ok := request.Attributes.Uint32(AttrAcctOutputPackets); ok {
		request.OutputPackets = value
	}
	if value, ok := request.Attributes.Uint32(AttrAcctSessionTime); ok {
		request.SessionTime = value
	}
	if value, ok := request.Attributes.Uint32(AttrAcctTerminateCause); ok {
		request.TerminateCause = AcctTerminateCause(value)
	}
	if attribute, ok := request.Attributes.Get(AttrAcctMultiSessionID); ok {
		request.MultiSessionID = attribute.String()
	}
	if attribute, ok := request.Attributes.Get(AttrCallingStationID); ok {
		request.CallingStationID = attribute.String()
	}
	if attribute, ok := request.Attributes.Get(AttrCalledStationID); ok {
		request.CalledStationID = attribute.String()
	}
	if attribute, ok := request.Attributes.Get(AttrEventTimestamp); ok {
		if value, ok := attribute.Uint32(); ok {
			request.EventTimestamp = time.Unix(int64(value), 0).UTC()
			request.HasEventTimestamp = true
		}
	}
	if attribute, ok := request.Attributes.Get(AttrClass); ok {
		request.Class = append([]byte(nil), attribute.Value...)
	}
	return request, nil
}

// buildAccountingResponse encodes and signs an Accounting-Response. | buildAccountingResponse 编码并
// 签名 Accounting-Response。
func buildAccountingResponse(packet *Packet, result *AccountingServerResult, secret []byte) ([]byte, error) {
	if result == nil {
		result = &AccountingServerResult{}
	}
	raw, err := MarshalPacket(&Packet{
		Code:          CodeAccountingResponse,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		Attributes:    accountingResponseAttributes(packet, result),
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	if err := applyResponseAuthenticator(raw, secret); err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	return raw, nil
}

// accountingResponseAttributes assembles the Accounting-Response attribute list. |
// accountingResponseAttributes 组装 Accounting-Response 属性列表。
func accountingResponseAttributes(packet *Packet, result *AccountingServerResult) Attributes {
	var attributes Attributes
	for _, proxyState := range packet.Attributes.GetAll(AttrProxyState) {
		attributes = append(attributes, Attributes{proxyState}.Clone()...)
	}
	if result.ReplyMessage != "" {
		attributes.AddString(AttrReplyMessage, result.ReplyMessage)
	}
	for _, attribute := range result.Attributes {
		switch attribute.Type {
		case AttrProxyState, AttrMessageAuthenticator:
			continue
		}
		attributes = append(attributes, Attributes{attribute}.Clone()...)
	}
	return attributes
}

// logDrop reports a discarded request at debug level. | logDrop 以调试级别报告被丢弃的请求。
func (s *AccountingServer) logDrop(remote net.Addr, err error) {
	s.logger.Debug("radius: dropped accounting request | radius：已丢弃计费请求",
		log.Str("peer", peerString(remote)), log.Err(err))
}
