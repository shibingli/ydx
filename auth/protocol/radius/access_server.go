package radius

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// AccessAuthenticator decides the Access-Accept or Access-Reject for an authenticated Access-Request.
// | AccessAuthenticator 为已认证的 Access-Request 决定 Access-Accept 或 Access-Reject。
//
// The handler receives a context bounded by AccessServerConfig.Timeout, derived from the server
// context. It must return promptly or honor cancellation. Returning an error or a nil result
// produces an Access-Reject without exposing the error text to the client. To control the reply
// message and attributes of a rejection, return a non-nil result with Accept=false. Handlers must be
// safe for concurrent use when the server is shared. | 处理器接收由服务器上下文派生、受
// AccessServerConfig.Timeout 约束的上下文。它必须及时返回或响应取消。返回错误或 nil 结果会生成
// Access-Reject，且不会向客户端暴露错误文本。要控制拒绝时的回复消息与属性，应返回 Accept=false
// 的非 nil 结果。服务器被共享时，处理器必须可并发使用。
type AccessAuthenticator interface {
	// AuthenticateAccess returns the decision for request. | AuthenticateAccess 返回针对 request 的决定。
	AuthenticateAccess(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error)
}

// AccessAuthenticatorFunc adapts a function to AccessAuthenticator. | AccessAuthenticatorFunc 将函数
// 适配为 AccessAuthenticator。
type AccessAuthenticatorFunc func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error)

// AuthenticateAccess calls f. A nil f returns ErrInvalidRequest instead of panicking. |
// AuthenticateAccess 调用 f。f 为 nil 时返回 ErrInvalidRequest 而不是 panic。
func (f AccessAuthenticatorFunc) AuthenticateAccess(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidRequest, "access authenticator function is nil")
	}
	return f(ctx, request)
}

// AccessServerRequest is one authenticated Access-Request received by an AccessServer. |
// AccessServerRequest 是 AccessServer 收到的一次已认证 Access-Request。
//
// The server verifies the Message-Authenticator when present and decrypts a PAP User-Password with
// the shared secret and Request Authenticator before invoking the authenticator. The Request
// Authenticator of an Access-Request is random (RFC 2865 section 3), so an unauthenticated request
// cannot be rejected cryptographically; use AccessServerConfig.RequireMessageAuthenticator to accept
// only requests that carry a valid Message-Authenticator. Attributes preserves every attribute in
// wire order. Password is an ephemeral plaintext copy that the server zeroes after the handler
// returns; it is never logged. | 服务器在存在 Message-Authenticator 时校验它，并在调用认证器前用共享
// 密钥与 Request Authenticator 解密 PAP User-Password。Access-Request 的 Request Authenticator 是
// 随机值（RFC 2865 第 3 节），因此无法从密码学上拒绝未认证请求；可使用
// AccessServerConfig.RequireMessageAuthenticator 只接受携带合法 Message-Authenticator 的请求。
// Attributes 按线序保留全部属性。Password 是临时明文副本，服务器在处理器返回后清零；它绝不会被
// 记录到日志。
type AccessServerRequest struct {
	// RemoteAddr is the datagram source or stream peer address. | RemoteAddr 是数据报源地址或流对端地址。
	RemoteAddr net.Addr
	// UserName is the required User-Name value. | UserName 是必填的 User-Name 值。
	UserName string
	// Password is the decrypted PAP password, or nil for other credential methods. | Password 是
	// 已解密的 PAP 口令；其它凭据方式为 nil。
	Password []byte
	// CHAPChallenge is the explicit CHAP-Challenge, or the Request Authenticator when the attribute
	// was absent (RFC 2865 section 2.2). | CHAPChallenge 是显式 CHAP-Challenge；属性缺失时为
	// Request Authenticator（RFC 2865 第 2.2 节）。
	CHAPChallenge []byte
	// Attributes holds every request attribute in wire order, including User-Password, Proxy-State,
	// EAP-Message and vendor attributes. | Attributes 按线序保存全部请求属性，包括 User-Password、
	// Proxy-State、EAP-Message 与厂商属性。
	Attributes Attributes
	// CHAPResponse is the 16-octet CHAP response when CredentialMethod is AuthCHAP. | CHAPResponse
	// 在 CredentialMethod 为 AuthCHAP 时是 16 字节 CHAP 响应。
	CHAPResponse [16]byte
	// Authenticator is the request's random Request Authenticator. | Authenticator 是请求的随机
	// Request Authenticator。
	Authenticator [16]byte
	// CredentialMethod reports which credential attribute the request carried: AuthPAP, AuthCHAP or
	// AuthNone. AuthMSCHAPv2 and AuthEAP are not decoded by the server. | CredentialMethod 报告请求
	// 携带的凭据属性：AuthPAP、AuthCHAP 或 AuthNone。服务器不解码 AuthMSCHAPv2 与 AuthEAP。
	CredentialMethod AuthMethod
	// CHAPIdentifier is the CHAP identifier octet when CredentialMethod is AuthCHAP. | CHAPIdentifier
	// 在 CredentialMethod 为 AuthCHAP 时是 CHAP 标识字节。
	CHAPIdentifier uint8
	// Identifier is the request identifier, reused by the response. | Identifier 是请求标识符，由响应复用。
	Identifier uint8
	// HasMessageAuthenticator reports whether the request carried a valid Message-Authenticator. |
	// HasMessageAuthenticator 报告请求是否携带合法的 Message-Authenticator。
	HasMessageAuthenticator bool
}

// VerifyPAP reports whether the PAP password matches plaintext in constant time. It returns false
// when the request did not use PAP. The caller's slice is not modified. | VerifyPAP 以常量时间报告
// PAP 口令是否与 plaintext 匹配。请求未使用 PAP 时返回 false。调用方的切片不会被修改。
func (r *AccessServerRequest) VerifyPAP(plaintext []byte) bool {
	return r != nil && r.CredentialMethod == AuthPAP && constantTimeEqual(r.Password, plaintext)
}

// VerifyCHAP reports whether password reproduces the CHAP response in constant time. It returns
// false when the request did not use CHAP. | VerifyCHAP 以常量时间报告 password 能否重现 CHAP 响应。
// 请求未使用 CHAP 时返回 false。
func (r *AccessServerRequest) VerifyCHAP(password []byte) bool {
	if r == nil || r.CredentialMethod != AuthCHAP {
		return false
	}
	return VerifyCHAPResponse(r.CHAPIdentifier, password, r.CHAPChallenge, r.CHAPResponse[:])
}

// AccessServerResult is the handler decision for one Access-Request. | AccessServerResult 是处理器对
// 一次 Access-Request 的决定。
//
// The zero value rejects the request with Access-Reject. Accept selects Access-Accept. Proxy-State is
// echoed from the request automatically, and Message-Authenticator is generated by the server when
// the request carried one; both are ignored inside Attributes. ReplyMessage is a convenience for a
// single Reply-Message and is emitted before Attributes. | 零值以 Access-Reject 拒绝请求。Accept 选择
// Access-Accept。Proxy-State 会自动从请求回显，请求携带 Message-Authenticator 时服务器会自动生成
// 响应值；Attributes 中的这两类属性会被忽略。ReplyMessage 是单个 Reply-Message 的便捷字段，并在
// Attributes 之前编码。
type AccessServerResult struct {
	// ReplyMessage is the optional Reply-Message text; empty omits the attribute. | ReplyMessage 是
	// 可选 Reply-Message 文本；空值省略该属性。
	ReplyMessage string
	// Attributes carries additional response attributes such as Session-Timeout, Filter-Id,
	// Framed-IP-Address or Class. | Attributes 携带附加响应属性，例如 Session-Timeout、Filter-Id、
	// Framed-IP-Address 或 Class。
	Attributes Attributes
	// Accept selects Access-Accept instead of Access-Reject. | Accept 选择 Access-Accept 而非 Access-Reject。
	Accept bool
}

// AccessServerConfig configures an AccessServer. | AccessServerConfig 配置 AccessServer。
type AccessServerConfig struct {
	// ClientLookup optionally resolves a per-client shared secret before verification. When set it
	// takes precedence over Secret, which allows one server to serve several NAS clients. | ClientLookup
	// 可选地在校验前解析每客户端共享密钥。设置后优先于 Secret，使一个服务器可服务多个 NAS 客户端。
	ClientLookup ServerClientLookup
	// Authenticator is required and decides every authenticated request. | Authenticator 必填，为
	// 每个已认证请求作出决定。
	Authenticator AccessAuthenticator
	// TLSConfig configures the server certificate and policy for network "tls". It is required for
	// TLS and cloned by the constructor. | TLSConfig 为 "tls" 网络配置服务器证书与策略。TLS 必填，
	// 并由构造函数克隆。
	TLSConfig *tls.Config
	// Logger receives dropped-request and handler diagnostics; nil selects log.Default(). It never
	// receives the shared secret, a user password or request contents. | Logger 接收丢包与处理器诊断；
	// nil 选择 log.Default()。它绝不会收到共享密钥、用户口令或请求内容。
	Logger *log.Logger
	// Network selects the transport: "udp" (the default), "udp4", "udp6", "tcp", "tcp4", "tcp6",
	// "tls", "tls4" or "tls6". TCP and TLS serve length-delimited RFC 6613/RFC 6614 streams. |
	// Network 选择传输："udp"（默认）、"udp4"、"udp6"、"tcp"、"tcp4"、"tcp6"、"tls"、"tls4" 或
	// "tls6"。TCP 与 TLS 服务按长度分帧的 RFC 6613/RFC 6614 流。
	Network string
	// Address is the listen "host:port"; empty selects DefaultAccessServerAddress for UDP and
	// DefaultServerTLSAddress for TCP and TLS. | Address 是监听 "host:port"；UDP 空值选择
	// DefaultAccessServerAddress，TCP 与 TLS 空值选择 DefaultServerTLSAddress。
	Address string
	// Secret is the shared secret used to verify Message-Authenticator values, decrypt
	// User-Password and sign responses. It is ignored when ClientLookup is set. The server copies it
	// and zeroes its copy in Close. | Secret 是用于校验 Message-Authenticator、解密 User-Password 与
	// 签名响应的共享密钥。设置 ClientLookup 时忽略该字段。服务器会复制它并在 Close 时清零副本。
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
	// RequireMessageAuthenticator drops requests that do not carry a valid Message-Authenticator.
	// Requests with an invalid value are always dropped. | RequireMessageAuthenticator 丢弃不携带
	// 合法 Message-Authenticator 的请求。值非法的请求始终被丢弃。
	RequireMessageAuthenticator bool
}

// AccessServer is a reusable Access-Request responder over UDP, TCP or TLS. | AccessServer 是基于
// UDP、TCP 或 TLS 的可复用 Access-Request 响应器。
//
// The server validates packet structure, resolves the client secret, verifies a present
// Message-Authenticator, decrypts PAP User-Password or extracts CHAP material, invokes the
// AccessAuthenticator and returns a signed Access-Accept or Access-Reject. Proxy-State is echoed
// unchanged and a valid Message-Authenticator is added to the response whenever the request carried
// one (RFC 3579 section 3.2). It does not implement an EAP state machine or generate
// Access-Challenge; EAP-Message attributes are passed through to the handler, and handlers can only
// accept or reject. Requests are handled concurrently up to MaxConcurrent. An AccessServer is safe
// for concurrent use, and Close may run while Serve is active. | 服务器校验报文结构、解析客户端密钥、
// 校验存在的 Message-Authenticator、解密 PAP User-Password 或提取 CHAP 材料、调用
// AccessAuthenticator，并返回已签名的 Access-Accept 或 Access-Reject。Proxy-State 原样回显；只要请求
// 携带 Message-Authenticator，响应就会添加合法值（RFC 3579 第 3.2 节）。它不实现 EAP 状态机，也不
// 生成 Access-Challenge；EAP-Message 属性透传给处理器，处理器只能接受或拒绝。请求最多按
// MaxConcurrent 并发处理。AccessServer 可并发使用，Close 可在 Serve 活动期间调用。
type AccessServer struct {
	authenticator AccessAuthenticator
	secrets       *serverSecretResolver
	logger        *log.Logger
	transport     *serverTransport
	requireMA     bool
}

// NewAccessServer validates config and returns a server. The server does not bind until Listen or
// ListenAndServe is called. | NewAccessServer 校验 config 并返回服务器。服务器在调用 Listen 或
// ListenAndServe 之前不会绑定套接字。
func NewAccessServer(config AccessServerConfig) (*AccessServer, error) {
	settings, err := normalizeServerSettings(
		config.Network,
		config.Address,
		DefaultAccessServerAddress,
		config.MaxPacketSize,
		config.MaxConcurrent,
		config.Timeout,
		config.TLSConfig,
	)
	if err != nil {
		return nil, err
	}
	if config.Authenticator == nil {
		return nil, errs.Detail(ErrInvalidConfig, "access authenticator is required")
	}
	if config.ClientLookup == nil && len(config.Secret) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret or client lookup is required")
	}
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}
	server := &AccessServer{
		authenticator: config.Authenticator,
		secrets:       newServerSecretResolver(config.Secret, config.ClientLookup),
		requireMA:     config.RequireMessageAuthenticator,
		logger:        logger,
	}
	server.transport = newServerTransport(serverTransportConfig{
		settings: settings,
		label:    "access",
		logger:   logger,
		handle:   server.handleRequest,
	})
	return server, nil
}

// Listen binds the configured address and returns it. Calling Listen again returns the existing
// address. | Listen 绑定配置的地址并返回它。再次调用 Listen 返回现有地址。
func (s *AccessServer) Listen() (net.Addr, error) {
	return s.transport.Listen()
}

// Addr returns the bound address, or nil before Listen. | Addr 返回已绑定的地址，Listen 之前为 nil。
func (s *AccessServer) Addr() net.Addr {
	return s.transport.Addr()
}

// ListenAndServe binds the configured address and serves until ctx is done or Close is called. It
// returns nil after context cancellation and ErrServerClosed after Close. | ListenAndServe 绑定配置的
// 地址并服务，直到 ctx 结束或调用 Close。上下文取消后返回 nil，Close 之后返回 ErrServerClosed。
func (s *AccessServer) ListenAndServe(ctx context.Context) error {
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
func (s *AccessServer) Serve(ctx context.Context) error {
	return s.transport.Serve(ctx)
}

// Close zeroizes the static shared secret, closes the socket or listener and every stream connection,
// and rejects further Listen and Serve calls. Close is idempotent and safe for concurrent use. |
// Close 清零静态共享密钥、关闭套接字或监听器以及全部流连接，并拒绝后续 Listen 与 Serve 调用。Close
// 幂等且可并发使用。
func (s *AccessServer) Close() error {
	err := s.transport.Close()
	s.secrets.close()
	return err
}

// handleRequest authenticates and answers one request. The keep result reports whether the stream
// connection may remain open; UDP ignores it. | handleRequest 认证并应答一次请求。keep 结果报告流连接
// 是否可以保持打开；UDP 忽略它。
func (s *AccessServer) handleRequest(ctx context.Context, raw []byte, remote net.Addr) ([]byte, bool) {
	packet, err := ParsePacket(raw)
	if err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	if packet.Code != CodeAccessRequest {
		s.logDrop(remote, errs.Detail(ErrUnexpectedCode, "access server received code %d", uint8(packet.Code)))
		return nil, false
	}
	secret, err := s.secrets.resolve(ctx, remote, packet.Attributes)
	if err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	defer zeroBytes(secret)
	present, valid, err := verifyMessageAuthenticatorRaw(raw, secret, packet.Authenticator)
	if err != nil {
		s.logDrop(remote, errs.Wrap(err, ErrInvalidResponse))
		return nil, false
	}
	if present && !valid {
		s.logDrop(remote, errs.Detail(ErrMessageAuthenticator, "request Message-Authenticator mismatch"))
		return nil, false
	}
	if !present && (s.requireMA || len(packet.Attributes.GetAll(AttrEAPMessage)) > 0) {
		s.logDrop(remote, errs.Detail(ErrMessageAuthenticator, "request lacks a required Message-Authenticator"))
		return nil, false
	}
	request, rejectMessage, err := decodeAccessServerRequest(packet, remote, secret)
	if err != nil {
		// The secret is valid, so refusing with Access-Reject lets the client stop retransmitting
		// instead of timing out. | 密钥有效，因此用 Access-Reject 拒绝可让客户端停止重传而不是超时。
		s.logDrop(remote, err)
		response, buildErr := buildAccessResponse(packet, &AccessServerResult{ReplyMessage: rejectMessage}, secret, present)
		if buildErr != nil {
			s.logger.Error("radius: cannot encode access rejection | radius：无法编码 Access 拒绝响应",
				log.Str("peer", peerString(remote)), log.Err(buildErr))
			return nil, true
		}
		return response, true
	}
	result, err := s.authenticator.AuthenticateAccess(ctx, request)
	zeroBytes(request.Password)
	if err != nil {
		s.logger.Warn("radius: access authenticator failed | radius：Access 认证器失败",
			log.Str("peer", peerString(remote)), log.Err(err))
		result = &AccessServerResult{}
	}
	if result == nil {
		s.logger.Warn("radius: access authenticator returned a nil result | radius：Access 认证器返回 nil 结果",
			log.Str("peer", peerString(remote)))
		result = &AccessServerResult{}
	}
	response, err := buildAccessResponse(packet, result, secret, present)
	if err != nil {
		s.logger.Warn("radius: invalid access response | radius：Access 响应非法",
			log.Str("peer", peerString(remote)), log.Err(err))
		response, err = buildAccessResponse(packet, &AccessServerResult{}, secret, present)
		if err != nil {
			s.logger.Error("radius: cannot encode access response | radius：无法编码 Access 响应",
				log.Str("peer", peerString(remote)), log.Err(err))
			return nil, true
		}
	}
	return response, true
}

// decodeAccessServerRequest validates credentials and extracts typed fields. | decodeAccessServerRequest
// 校验凭据并提取类型化字段。
func decodeAccessServerRequest(packet *Packet, remote net.Addr, secret []byte) (*AccessServerRequest, string, error) {
	userName, ok := packet.Attributes.Get(AttrUserName)
	if !ok {
		return nil, "missing User-Name", errs.Detail(ErrInvalidRequest, "access request lacks User-Name")
	}
	passwords := packet.Attributes.GetAll(AttrUserPassword)
	chapPasswords := packet.Attributes.GetAll(AttrCHAPPassword)
	if len(passwords) > 1 || len(chapPasswords) > 1 {
		return nil, "duplicate credential attributes", errs.Detail(ErrInvalidRequest, "access request carries duplicate credential attributes")
	}
	if len(passwords) == 1 && len(chapPasswords) == 1 {
		return nil, "conflicting credential attributes", errs.Detail(ErrInvalidRequest, "access request carries both User-Password and CHAP-Password")
	}
	request := &AccessServerRequest{
		UserName:                userName.String(),
		CredentialMethod:        AuthNone,
		Identifier:              packet.Identifier,
		Authenticator:           packet.Authenticator,
		RemoteAddr:              remote,
		Attributes:              packet.Attributes.Clone(),
		HasMessageAuthenticator: false,
	}
	if _, ok := packet.Attributes.Get(AttrMessageAuthenticator); ok {
		request.HasMessageAuthenticator = true
	}
	if len(passwords) == 1 {
		password, err := DecryptUserPassword(secret, packet.Authenticator[:], passwords[0].Value)
		if err != nil {
			return nil, "invalid User-Password", errs.Wrap(err, ErrInvalidRequest)
		}
		request.Password = password
		request.CredentialMethod = AuthPAP
	}
	if len(chapPasswords) == 1 {
		value := chapPasswords[0].Value
		request.CredentialMethod = AuthCHAP
		request.CHAPIdentifier = value[0]
		copy(request.CHAPResponse[:], value[1:])
		challenge := append([]byte(nil), packet.Authenticator[:]...)
		if attribute, ok := packet.Attributes.Get(AttrCHAPChallenge); ok {
			challenge = append([]byte(nil), attribute.Value...)
		}
		request.CHAPChallenge = challenge
	}
	return request, "", nil
}

// buildAccessResponse encodes and signs an Access-Accept or Access-Reject. | buildAccessResponse 编码
// 并签名 Access-Accept 或 Access-Reject。
func buildAccessResponse(packet *Packet, result *AccessServerResult, secret []byte, includeMessageAuthenticator bool) ([]byte, error) {
	if result == nil {
		result = &AccessServerResult{}
	}
	code := CodeAccessReject
	if result.Accept {
		code = CodeAccessAccept
	}
	raw, err := MarshalPacket(&Packet{
		Code:          code,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		Attributes:    accessResponseAttributes(packet, result, includeMessageAuthenticator),
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	if includeMessageAuthenticator {
		if err := signMessageAuthenticator(raw, secret, packet.Authenticator); err != nil {
			return nil, errs.Wrap(err, ErrInternal)
		}
	}
	if err := applyResponseAuthenticator(raw, secret); err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	return raw, nil
}

// accessResponseAttributes assembles the response attribute list. | accessResponseAttributes 组装响应
// 属性列表。
func accessResponseAttributes(packet *Packet, result *AccessServerResult, includeMessageAuthenticator bool) Attributes {
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
	if includeMessageAuthenticator {
		attributes.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	return attributes
}

// logDrop reports a discarded request at debug level. | logDrop 以调试级别报告被丢弃的请求。
func (s *AccessServer) logDrop(remote net.Addr, err error) {
	peer := ""
	if remote != nil {
		peer = peerString(remote)
	}
	s.logger.Debug("radius: dropped access request | radius：已丢弃 Access 请求",
		log.Str("peer", peer), log.Err(err))
}
