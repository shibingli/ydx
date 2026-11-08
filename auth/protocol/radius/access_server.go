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
	// EAPPacket is the parsed EAP packet when the request carried one. | EAPPacket 是请求携带的已解析
	// EAP 报文。
	EAPPacket *EAPPacket
	// EAPMessages is the concatenated EAP-Message payload. | EAPMessages 是拼接后的 EAP-Message 负载。
	EAPMessages []byte
	// EAPIdentity is the identity carried by an EAP-Response/Identity, or empty. | EAPIdentity 是
	// EAP-Response/Identity 携带的身份，缺失时为空。
	EAPIdentity string
	// State is the first RADIUS State value echoed from a previous Access-Challenge. | State 是从先前
	// Access-Challenge 回显的首个 RADIUS State 值。
	State []byte
	// MSCHAPv2Challenge is the MS-CHAP-Challenge vendor value, or nil. | MSCHAPv2Challenge 是
	// MS-CHAP-Challenge 厂商值，缺失时为 nil。
	MSCHAPv2Challenge []byte
	// MSCHAPv2Response is the 50-octet MS-CHAP2-Response vendor value, or nil. | MSCHAPv2Response 是
	// 50 字节 MS-CHAP2-Response 厂商值，缺失时为 nil。
	MSCHAPv2Response []byte
	// MSCHAPv2Result is the verified MS-CHAPv2 result when AccessServerConfig.MSCHAPv2 verified the
	// credentials before invoking the authenticator. | MSCHAPv2Result 是 AccessServerConfig.MSCHAPv2
	// 在调用认证器前校验凭据所得的 MS-CHAPv2 结果。
	MSCHAPv2Result *MSCHAPv2ServerResult
	// CHAPResponse is the 16-octet CHAP response when CredentialMethod is AuthCHAP. | CHAPResponse
	// 在 CredentialMethod 为 AuthCHAP 时是 16 字节 CHAP 响应。
	CHAPResponse [16]byte
	// Authenticator is the request's random Request Authenticator. | Authenticator 是请求的随机
	// Request Authenticator。
	Authenticator [16]byte
	// CredentialMethod reports which credential attribute the request carried: AuthPAP, AuthCHAP,
	// AuthMSCHAPv2, AuthEAP or AuthNone. | CredentialMethod 报告请求携带的凭据属性：AuthPAP、
	// AuthCHAP、AuthMSCHAPv2、AuthEAP 或 AuthNone。
	CredentialMethod AuthMethod
	// CHAPIdentifier is the CHAP identifier octet when CredentialMethod is AuthCHAP. | CHAPIdentifier
	// 在 CredentialMethod 为 AuthCHAP 时是 CHAP 标识字节。
	CHAPIdentifier uint8
	// MSCHAPv2Ident is the MS-CHAPv2 ident octet when MSCHAPv2Response is present. | MSCHAPv2Ident
	// 在 MSCHAPv2Response 存在时是 MS-CHAPv2 标识字节。
	MSCHAPv2Ident uint8
	// Identifier is the request identifier, reused by the response. | Identifier 是请求标识符，由响应复用。
	Identifier uint8
	// HasMessageAuthenticator reports whether the request carried a valid Message-Authenticator. |
	// HasMessageAuthenticator 报告请求是否携带合法的 Message-Authenticator。
	HasMessageAuthenticator bool
	// MSCHAPv2Verified reports whether AccessServerConfig.MSCHAPv2 validated the credentials. |
	// MSCHAPv2Verified 报告 AccessServerConfig.MSCHAPv2 是否已校验凭据。
	MSCHAPv2Verified bool
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

// VerifyMSCHAPv2 verifies the request's MS-CHAP2-Response against password and the request's
// MS-CHAP-Challenge. It returns false when the request lacks MS-CHAPv2 material. | VerifyMSCHAPv2
// 依据 password 与请求的 MS-CHAP-Challenge 校验 MS-CHAP2-Response。请求缺少 MS-CHAPv2 材料时返回
// false。
func (r *AccessServerRequest) VerifyMSCHAPv2(password string) (bool, error) {
	if r == nil || len(r.MSCHAPv2Challenge) != 16 || len(r.MSCHAPv2Response) != msCHAPv2ResponseLength {
		return false, nil
	}
	return VerifyMSCHAPv2Response(r.UserName, password, r.MSCHAPv2Challenge, r.MSCHAPv2Response)
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
	// Identity is the authenticated identity, for example a certificate subject or EAP identity;
	// empty omits it from the response and it is never sent on the wire automatically. | Identity 是
	// 已认证身份，例如证书主题或 EAP 身份；为空时不在响应中体现，且不会自动发送到线路。
	Identity string
	// Attributes carries additional response attributes such as Session-Timeout, Filter-Id,
	// Framed-IP-Address or Class. | Attributes 携带附加响应属性，例如 Session-Timeout、Filter-Id、
	// Framed-IP-Address 或 Class。
	Attributes Attributes
	// MPPESendKey is a plain 16-octet server-to-peer MS-MPPE-Send-Key. The AccessServer encrypts it
	// with RFC 2548 key hiding before transmission. | MPPESendKey 是 16 字节明文服务器到对端
	// MS-MPPE-Send-Key。AccessServer 在发送前按 RFC 2548 隐藏它。
	MPPESendKey []byte
	// MPPERecvKey is a plain 16-octet peer-to-server MS-MPPE-Recv-Key. The AccessServer encrypts it
	// with RFC 2548 key hiding before transmission. | MPPERecvKey 是 16 字节明文对端到服务器
	// MS-MPPE-Recv-Key。AccessServer 在发送前按 RFC 2548 隐藏它。
	MPPERecvKey []byte
	// State is the RADIUS State value placed in an Access-Challenge. It is ignored outside a
	// challenge. | State 是放入 Access-Challenge 的 RADIUS State 值，非挑战响应中忽略。
	State []byte
	// Accept selects Access-Accept instead of Access-Reject. | Accept 选择 Access-Accept 而非 Access-Reject。
	Accept bool
	// Challenge selects Access-Challenge instead of Access-Accept or Access-Reject. Accept and
	// Challenge are mutually exclusive; Challenge takes precedence. | Challenge 选择 Access-Challenge
	// 而非 Access-Accept 或 Access-Reject。Accept 与 Challenge 互斥，Challenge 优先。
	Challenge bool
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
	// MSCHAPv2 optionally enables server-issued MS-CHAPv2 challenges and automatic verification.
	// When set, an Access-Request without credentials receives an Access-Challenge carrying
	// MS-CHAP-Challenge and State, and a subsequent valid MS-CHAP2-Response is verified before the
	// Authenticator decides authorization. Invalid credentials are rejected with MS-CHAP-Error. |
	// MSCHAPv2 可选启用服务器签发的 MS-CHAPv2 挑战与自动校验。设置后，无凭据的 Access-Request 会收到
	// 携带 MS-CHAP-Challenge 与 State 的 Access-Challenge；后续合法的 MS-CHAP2-Response 会在认证器
	// 决定授权前完成校验。非法凭据以 MS-CHAP-Error 拒绝。
	MSCHAPv2 *MSCHAPv2Server
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
// AccessAuthenticator and returns a signed Access-Accept, Access-Reject or Access-Challenge.
// Proxy-State is echoed unchanged and a valid Message-Authenticator is added to the response
// whenever the request carried one (RFC 3579 section 3.2). When AccessServerConfig.MSCHAPv2 is
// set, the server issues stateful MS-CHAPv2 challenges itself: a request without credentials
// receives an Access-Challenge carrying MS-CHAP-Challenge and State, and a later valid
// MS-CHAP2-Response is verified before the authenticator observes MSCHAPv2Verified. EAP state and
// EAP Access-Challenge sequencing are supplied by EAPServer, which implements AccessAuthenticator
// and is installed as the authenticator in that case. Requests are handled concurrently up to
// MaxConcurrent. An AccessServer is safe for concurrent use, and Close may run while Serve is
// active. | 服务器校验报文结构、解析客户端密钥、校验存在的 Message-Authenticator、解密 PAP
// User-Password 或提取 CHAP 材料、调用 AccessAuthenticator，并返回已签名的 Access-Accept、
// Access-Reject 或 Access-Challenge。Proxy-State 原样回显；只要请求携带 Message-Authenticator，
// 响应就会添加合法值（RFC 3579 第 3.2 节）。设置 AccessServerConfig.MSCHAPv2 后，服务器自行签发
// 有状态 MS-CHAPv2 挑战：无凭据请求收到携带 MS-CHAP-Challenge 与 State 的 Access-Challenge，
// 后续合法 MS-CHAP2-Response 会在认证器看到 MSCHAPv2Verified 之前完成校验。EAP 状态与 EAP
// Access-Challenge 序列由 EAPServer 提供；此时将实现 AccessAuthenticator 的 EAPServer 安装为
// 认证器。请求最多按 MaxConcurrent 并发处理。AccessServer 可并发使用，Close 可在 Serve 活动期间
// 调用。
type AccessServer struct {
	authenticator AccessAuthenticator
	mschapv2      *MSCHAPv2Server
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
		mschapv2:      config.MSCHAPv2,
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
	if s.mschapv2 != nil {
		if response, handled, keep := s.handleMSCHAPv2(ctx, packet, request, secret, present); handled {
			zeroBytes(request.Password)
			return response, keep
		}
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
	if request.MSCHAPv2Result != nil && request.MSCHAPv2Result.Succeeded() {
		if len(result.MPPESendKey) == 0 {
			result.MPPESendKey = append([]byte(nil), request.MSCHAPv2Result.MPPESendKey...)
		}
		if len(result.MPPERecvKey) == 0 {
			result.MPPERecvKey = append([]byte(nil), request.MSCHAPv2Result.MPPERecvKey...)
		}
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

// handleMSCHAPv2 implements challenge issuance and credential verification when AccessServerConfig
// enables MS-CHAPv2. handled reports that the request was fully answered. | handleMSCHAPv2 在
// AccessServerConfig 启用 MS-CHAPv2 时实现挑战签发与凭据校验。handled 报告请求是否已被完整应答。
func (s *AccessServer) handleMSCHAPv2(ctx context.Context, packet *Packet, request *AccessServerRequest, secret []byte, present bool) (response []byte, handled, keep bool) {
	if request.CredentialMethod == AuthNone && request.EAPPacket == nil && len(request.MSCHAPv2Response) == 0 {
		challenge, err := s.mschapv2.IssueChallenge(ctx, request.UserName)
		if err != nil {
			s.logger.Warn("radius: cannot issue MS-CHAPv2 challenge | radius：无法签发 MS-CHAPv2 挑战",
				log.Str("peer", peerString(request.RemoteAddr)), log.Err(err))
			return nil, false, true
		}
		result := &AccessServerResult{
			Challenge: true,
			State:     challenge.State,
			Attributes: Attributes{
				NewVendorAttribute(VendorMicrosoft, VendorMSCHAPChallenge, challenge.Challenge),
			},
		}
		raw, err := buildAccessResponse(packet, result, secret, present)
		if err != nil {
			s.logger.Error("radius: cannot encode MS-CHAPv2 challenge | radius：无法编码 MS-CHAPv2 挑战",
				log.Str("peer", peerString(request.RemoteAddr)), log.Err(err))
			return nil, false, true
		}
		return raw, true, true
	}
	if len(request.MSCHAPv2Response) == 0 {
		return nil, false, true
	}
	var (
		verification *MSCHAPv2ServerResult
		err          error
	)
	if len(request.State) != 0 {
		verification, err = s.mschapv2.VerifyResponse(ctx, request.UserName, request.State, request.MSCHAPv2Challenge, request.MSCHAPv2Response)
	} else {
		challenge := request.MSCHAPv2Challenge
		if len(challenge) == 0 {
			challenge = request.Authenticator[:]
		}
		var password []byte
		password, err = lookupEAPPassword(ctx, s.mschapv2.lookup, request.UserName)
		if err == nil {
			verification, err = VerifyMSCHAPv2Server(request.UserName, string(password), challenge, request.MSCHAPv2Response)
			zeroBytes(password)
		}
	}
	if err != nil {
		s.logger.Warn("radius: MS-CHAPv2 verification failed | radius：MS-CHAPv2 校验失败",
			log.Str("peer", peerString(request.RemoteAddr)), log.Err(err))
		reason := MSCHAPv2FailureMalformed
		if isUnknownUser(err) {
			reason = MSCHAPv2FailureUnknownUser
		}
		return s.rejectMSCHAPv2(packet, request, reason, secret, present)
	}
	if verification == nil || !verification.Succeeded() {
		reason := MSCHAPv2FailureAuthentication
		if verification != nil {
			reason = verification.Failure
		}
		return s.rejectMSCHAPv2(packet, request, reason, secret, present)
	}
	request.MSCHAPv2Result = verification
	request.MSCHAPv2Verified = true
	request.CredentialMethod = AuthMSCHAPv2
	return nil, false, true
}

// rejectMSCHAPv2 builds an Access-Reject carrying MS-CHAP-Error. | rejectMSCHAPv2 构建携带
// MS-CHAP-Error 的 Access-Reject。
func (s *AccessServer) rejectMSCHAPv2(packet *Packet, request *AccessServerRequest, reason MSCHAPv2FailureReason, secret []byte, present bool) ([]byte, bool, bool) {
	challenge := request.MSCHAPv2Challenge
	if len(challenge) != 16 {
		challenge = make([]byte, 16)
	}
	errorValue, err := MSCHAPError(reason, challenge, reason.String())
	if err != nil {
		errorValue = "E=691 R=0 C=00000000000000000000000000000000 V=3 M=authentication failure"
	}
	raw, buildErr := buildAccessResponse(packet, &AccessServerResult{
		ReplyMessage: reason.String(),
		Attributes: Attributes{
			NewVendorAttribute(VendorMicrosoft, VendorMSCHAPError, []byte(errorValue)),
		},
	}, secret, present)
	if buildErr != nil {
		s.logger.Error("radius: cannot encode MS-CHAPv2 rejection | radius：无法编码 MS-CHAPv2 拒绝",
			log.Str("peer", peerString(request.RemoteAddr)), log.Err(buildErr))
		return nil, true, true
	}
	return raw, true, true
}

// decodeAccessServerRequest validates credentials and extracts typed fields. | decodeAccessServerRequest
// 校验凭据并提取类型化字段。
func decodeAccessServerRequest(packet *Packet, remote net.Addr, secret []byte) (*AccessServerRequest, string, error) {
	eapValues := packet.Attributes.GetAll(AttrEAPMessage)
	userNameAttribute, hasUserName := packet.Attributes.Get(AttrUserName)
	if !hasUserName && len(eapValues) == 0 {
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
	if len(eapValues) > 0 && (len(passwords) > 0 || len(chapPasswords) > 0) {
		return nil, "conflicting credential attributes", errs.Detail(ErrInvalidRequest, "access request combines EAP-Message with User-Password or CHAP-Password")
	}
	request := &AccessServerRequest{
		CredentialMethod:        AuthNone,
		Identifier:              packet.Identifier,
		Authenticator:           packet.Authenticator,
		RemoteAddr:              remote,
		Attributes:              packet.Attributes.Clone(),
		HasMessageAuthenticator: false,
	}
	if hasUserName {
		request.UserName = userNameAttribute.String()
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
	mschapChallenge := packet.Attributes.VendorAll(VendorMicrosoft, VendorMSCHAPChallenge)
	mschapResponses := packet.Attributes.VendorAll(VendorMicrosoft, VendorMSCHAP2Response)
	if len(mschapChallenge) > 1 || len(mschapResponses) > 1 {
		return nil, "duplicate MS-CHAPv2 attributes", errs.Detail(ErrInvalidRequest, "access request carries duplicate MS-CHAPv2 attributes")
	}
	if len(mschapChallenge) == 1 {
		request.MSCHAPv2Challenge = append([]byte(nil), mschapChallenge[0].Value...)
	}
	if len(mschapResponses) == 1 {
		if len(mschapResponses[0].Value) != msCHAPv2ResponseLength {
			return nil, "invalid MS-CHAP2-Response", errs.Detail(ErrInvalidAttribute, "MS-CHAP2-Response length %d must be %d", len(mschapResponses[0].Value), msCHAPv2ResponseLength)
		}
		request.MSCHAPv2Response = append([]byte(nil), mschapResponses[0].Value...)
		request.MSCHAPv2Ident = request.MSCHAPv2Response[0]
		if request.CredentialMethod == AuthNone {
			request.CredentialMethod = AuthMSCHAPv2
		}
	}
	if attribute, ok := packet.Attributes.Get(AttrState); ok {
		request.State = append([]byte(nil), attribute.Value...)
	}
	if len(eapValues) > 0 {
		message, err := ReassembleEAPMessages(packet.Attributes)
		if err != nil {
			return nil, "invalid EAP-Message", err
		}
		eapPacket, err := ParseEAPPacket(message)
		if err != nil {
			return nil, "invalid EAP packet", err
		}
		request.EAPMessages = message
		request.EAPPacket = eapPacket
		if eapPacket.Code == EAPCodeResponse && eapPacket.Type == EAPTypeIdentity {
			if identity, identityErr := EAPResponseIdentity(eapPacket); identityErr == nil {
				request.EAPIdentity = identity
				if request.UserName == "" {
					request.UserName = identity
				}
			}
		}
		if request.CredentialMethod == AuthNone {
			request.CredentialMethod = AuthEAP
		}
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
	switch {
	case result.Challenge:
		code = CodeAccessChallenge
	case result.Accept:
		code = CodeAccessAccept
	}
	attributes := accessResponseAttributes(packet, result, includeMessageAuthenticator)
	if code == CodeAccessAccept {
		if len(result.MPPESendKey) != 0 {
			encrypted, err := EncryptMSMPPEKey(secret, packet.Authenticator[:], result.MPPESendKey)
			if err != nil {
				return nil, errs.Wrap(err, ErrInternal)
			}
			attributes = append(attributes, NewVendorAttribute(VendorMicrosoft, VendorMSMPPESendKey, encrypted))
		}
		if len(result.MPPERecvKey) != 0 {
			encrypted, err := EncryptMSMPPEKey(secret, packet.Authenticator[:], result.MPPERecvKey)
			if err != nil {
				return nil, errs.Wrap(err, ErrInternal)
			}
			attributes = append(attributes, NewVendorAttribute(VendorMicrosoft, VendorMSMPPERecvKey, encrypted))
		}
	}
	if includeMessageAuthenticator {
		attributes.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	raw, err := MarshalPacket(&Packet{
		Code:          code,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		Attributes:    attributes,
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
	if result.Challenge && len(result.State) != 0 {
		attributes.Add(AttrState, result.State)
	}
	for _, attribute := range result.Attributes {
		switch attribute.Type {
		case AttrProxyState, AttrMessageAuthenticator:
			continue
		case AttrState:
			if result.Challenge && len(result.State) != 0 {
				continue
			}
		}
		attributes = append(attributes, Attributes{attribute}.Clone()...)
	}
	_ = includeMessageAuthenticator
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
