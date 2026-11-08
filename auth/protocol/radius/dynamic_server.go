package radius

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// DefaultDynamicServerAddress is the RFC 5176 dynamic authorization UDP port. | DefaultDynamicServerAddress
// 是 RFC 5176 动态授权的 UDP 端口。
const DefaultDynamicServerAddress = ":3799"

// DynamicAuthorizationPacket is one authenticated CoA-Request or Disconnect-Request received by a
// DynamicServer. | DynamicAuthorizationPacket 是 DynamicServer 收到的一个已认证 CoA-Request 或
// Disconnect-Request。
//
// The server verifies the Request Authenticator and, when present, the Message-Authenticator before
// decoding the packet and invoking the handler. Attributes preserves every attribute in wire order,
// including Proxy-State and vendor attributes. | 服务器在解码报文并调用处理器之前校验 Request
// Authenticator，并在存在时校验 Message-Authenticator。Attributes 按线序保留全部属性，包括
// Proxy-State 与厂商属性。
type DynamicAuthorizationPacket struct {
	// EventTimestamp is Event-Timestamp; it is only meaningful when HasEventTimestamp is true. |
	// EventTimestamp 是 Event-Timestamp；仅在 HasEventTimestamp 为 true 时有意义。
	EventTimestamp time.Time
	// RemoteAddr is the source address of the datagram. | RemoteAddr 是数据报的源地址。
	RemoteAddr net.Addr
	// SessionID is Acct-Session-Id, empty when absent. | SessionID 是 Acct-Session-Id，缺失时为空。
	SessionID string
	// UserName is User-Name, empty when absent. | UserName 是 User-Name，缺失时为空。
	UserName string
	// NASIdentifier is NAS-Identifier, empty when absent. | NASIdentifier 是 NAS-Identifier，缺失时为空。
	NASIdentifier string
	// Attributes holds every request attribute in wire order. | Attributes 按线序保存全部请求属性。
	Attributes Attributes
	// NASIPAddress is NAS-IP-Address, nil when absent. | NASIPAddress 是 NAS-IP-Address，缺失时为 nil。
	NASIPAddress net.IP
	// NASPort is NAS-Port, zero when absent. | NASPort 是 NAS-Port，缺失时为零。
	NASPort uint32
	// Authenticator is the verified Request Authenticator. | Authenticator 是已校验的 Request
	// Authenticator。
	Authenticator [16]byte
	// Code is CodeCoARequest or CodeDisconnectRequest. | Code 是 CodeCoARequest 或
	// CodeDisconnectRequest。
	Code Code
	// Identifier is the request identifier, reused by the ACK or NAK. | Identifier 是请求标识符，由
	// ACK 或 NAK 复用。
	Identifier uint8
	// HasEventTimestamp reports whether Event-Timestamp was present. | HasEventTimestamp 报告是否携带
	// Event-Timestamp。
	HasEventTimestamp bool
	// HasMessageAuthenticator reports whether the request carried a verified Message-Authenticator.
	// | HasMessageAuthenticator 报告请求是否携带已校验的 Message-Authenticator。
	HasMessageAuthenticator bool
}

// DynamicAuthorizationResult is the handler decision for one dynamic authorization request. |
// DynamicAuthorizationResult 是处理器对一个动态授权请求的决定。
//
// The zero value rejects the request with a NAK, which keeps an incompletely initialized result from
// silently acknowledging a change. A successful decision sets Accept. Error-Cause values 200-299 are
// only valid in an ACK (ErrorCauseResidualSessionContextRemoved only in a Disconnect-ACK) and values
// 400-599 only in a NAK, as required by RFC 5176 section 3.5; an invalid combination is replaced by a
// NAK carrying ErrorCauseResourcesUnavailable. ErrorCause, ReplyMessage and Message-Authenticator
// inside Attributes are ignored: the first two belong in the typed fields and the server signs the
// Message-Authenticator itself. | 零值以 NAK 拒绝请求，避免未完整初始化的结果静默确认变更。成功决定
// 设置 Accept。按 RFC 5176 第 3.5 节，Error-Cause 200-299 仅允许出现在 ACK（且
// ErrorCauseResidualSessionContextRemoved 仅允许 Disconnect-ACK），400-599 仅允许出现在 NAK；非法
// 组合会被替换为携带 ErrorCauseResourcesUnavailable 的 NAK。Attributes 中的 Error-Cause、
// Reply-Message 与 Message-Authenticator 会被忽略：前两者应使用类型化字段，后者由服务器自行签名。
type DynamicAuthorizationResult struct {
	// ReplyMessage is the optional Reply-Message text; empty omits the attribute. | ReplyMessage 是
	// 可选 Reply-Message 文本；空值省略该属性。
	ReplyMessage string
	// Attributes carries additional response attributes in wire order. | Attributes 按线序携带附加
	// 响应属性。
	Attributes Attributes
	// ErrorCause is the optional Error-Cause value; zero omits the attribute. | ErrorCause 是可选
	// Error-Cause 值；零值省略该属性。
	ErrorCause ErrorCause
	// Accept acknowledges the request with an ACK. | Accept 以 ACK 确认请求。
	Accept bool
}

// DynamicRequestHandler decides the ACK or NAK for an authenticated CoA-Request or
// Disconnect-Request. | DynamicRequestHandler 为已认证的 CoA-Request 或 Disconnect-Request 决定 ACK
// 或 NAK。
//
// The handler receives a context bounded by DynamicServerConfig.Timeout, derived from the server
// context, so it must return promptly or honor cancellation. Returning an error, or a nil result,
// produces a NAK carrying ErrorCauseResourcesUnavailable without exposing the error text to the
// client. To reject with a specific cause or reply message, return a non-nil result with
// Accept=false instead of an error. Handlers must be safe for concurrent use when the same server is
// embedded in a larger application. | 处理器接收由服务器上下文派生、受 DynamicServerConfig.Timeout
// 约束的上下文，因此必须及时返回或响应取消。返回错误或 nil 结果会生成携带
// ErrorCauseResourcesUnavailable 的 NAK，且不会向客户端暴露错误文本。要以特定原因或回复消息拒绝，
// 应返回 Accept=false 的非 nil 结果而不是错误。当同一服务器嵌入更大应用时，处理器必须可并发使用。
type DynamicRequestHandler interface {
	// HandleDynamicAuthorization returns the decision for request. | HandleDynamicAuthorization
	// 返回针对 request 的决定。
	HandleDynamicAuthorization(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error)
}

// DynamicRequestHandlerFunc adapts a function to DynamicRequestHandler. | DynamicRequestHandlerFunc
// 将函数适配为 DynamicRequestHandler。
type DynamicRequestHandlerFunc func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error)

// HandleDynamicAuthorization calls f. A nil f returns ErrInvalidRequest instead of panicking. |
// HandleDynamicAuthorization 调用 f。f 为 nil 时返回 ErrInvalidRequest 而不是 panic。
func (f DynamicRequestHandlerFunc) HandleDynamicAuthorization(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidRequest, "dynamic authorization handler function is nil")
	}
	return f(ctx, request)
}

// DynamicServerConfig configures a DynamicServer. | DynamicServerConfig 配置 DynamicServer。
type DynamicServerConfig struct {
	// Handler is required and decides every authenticated request. | Handler 必填，为每个已认证
	// 请求作出决定。
	Handler DynamicRequestHandler
	// DuplicateCache optionally supplies an external duplicate cache, for example one shared by
	// several servers or seeded with a test clock. Nil creates an owned cache. | DuplicateCache 可选
	// 提供外部重复缓存，例如由多个服务器共享或注入测试时钟。nil 创建自有缓存。
	DuplicateCache *DynamicDuplicateCache
	// Logger receives dropped-packet and handler diagnostics; nil selects log.Default(). It never
	// receives the shared secret or request contents. | Logger 接收丢包与处理器诊断；nil 选择
	// log.Default()。它绝不会收到共享密钥或请求内容。
	Logger *log.Logger
	// Network is the UDP network: "udp" (the default), "udp4" or "udp6". | Network 是 UDP 网络：
	// "udp"（默认）、"udp4" 或 "udp6"。
	Network string
	// Address is the listen address; empty selects DefaultDynamicServerAddress (":3799"). |
	// Address 是监听地址；空值选择 DefaultDynamicServerAddress（":3799"）。
	Address string
	// Secret is the shared secret used to authenticate requests and sign responses. The server
	// copies it and zeroes its copy in Close; the caller remains responsible for its own slice. |
	// Secret 是用于认证请求与签名响应的共享密钥。服务器会复制它并在 Close 时清零副本；调用方仍需
	// 自行清零自己的切片。
	Secret []byte
	// Timeout bounds one handler invocation and the following response write; zero selects
	// DefaultTimeout. It does not bound the lifetime of Serve. | Timeout 约束一次处理器调用与随后的
	// 响应写入；零值选择 DefaultTimeout。它不约束 Serve 的生命周期。
	Timeout time.Duration
	// MaxPacketSize is the largest accepted datagram; zero selects MaxPacketLength. Values below
	// HeaderLength or above MaxPacketLength are rejected. Larger datagrams are dropped. |
	// MaxPacketSize 是接受的最大数据报；零值选择 MaxPacketLength。低于 HeaderLength 或高于
	// MaxPacketLength 的值会被拒绝。更大的数据报会被丢弃。
	MaxPacketSize int
	// DuplicateTTL is the duplicate-detection window; zero selects DefaultDynamicDuplicateTTL and
	// negative values are rejected. It is ignored when DuplicateCache is set. | DuplicateTTL 是重复
	// 检测窗口；零值选择 DefaultDynamicDuplicateTTL，负值会被拒绝。设置 DuplicateCache 时忽略该
	// 字段。
	DuplicateTTL time.Duration
	// DuplicateCapacity is the maximum number of cached responses; zero selects
	// DefaultDynamicDuplicateCapacity and negative values are rejected. It is ignored when
	// DuplicateCache is set. | DuplicateCapacity 是缓存响应的最大条数；零值选择
	// DefaultDynamicDuplicateCapacity，负值会被拒绝。设置 DuplicateCache 时忽略该字段。
	DuplicateCapacity int
	// RequireMessageAuthenticator drops requests that do not carry a Message-Authenticator. Invalid
	// values are always dropped, as RFC 5176 section 3.4 requires, whether or not this is set. |
	// RequireMessageAuthenticator 丢弃不携带 Message-Authenticator 的请求。无论是否设置该字段，
	// 非法值始终按 RFC 5176 第 3.4 节要求丢弃。
	RequireMessageAuthenticator bool
}

// DynamicServer is an RFC 5176 NAS-side dynamic authorization responder over UDP. | DynamicServer
// 是基于 UDP 的 RFC 5176 NAS 侧动态授权响应器。
//
// The server accepts CoA-Request and Disconnect-Request packets on one UDP socket, verifies the
// Request Authenticator and any Message-Authenticator, replays a cached response for a retransmitted
// request, invokes the handler once, and returns a properly signed ACK or NAK. Proxy-State from the
// request is echoed unchanged, as RFC 5176 section 3.3 requires. Requests are handled sequentially so
// memory use stays bounded; a handler must therefore return promptly. Relay and proxy behavior is not
// implemented. A DynamicServer is safe for concurrent use, and Close may run while Serve is active. |
// 服务器在一个 UDP 套接字上接受 CoA-Request 与 Disconnect-Request，校验 Request Authenticator 与
// 任何 Message-Authenticator，对重传请求重放缓存响应，只调用一次处理器，并返回正确签名的 ACK 或
// NAK。按 RFC 5176 第 3.3 节要求，请求中的 Proxy-State 会原样回显。请求按顺序处理以保持内存占用
// 有界，因此处理器必须及时返回。不实现中继与代理行为。DynamicServer 可并发使用，Close 可在
// Serve 活动期间调用。
type DynamicServer struct {
	cfg     DynamicServerConfig
	handler DynamicRequestHandler
	conn    net.PacketConn
	addr    net.Addr
	cache   *DynamicDuplicateCache
	logger  *log.Logger

	secret []byte

	mu      sync.RWMutex
	closed  bool
	serving bool
}

// NewDynamicServer validates config and returns a server. The server does not bind until Listen,
// ListenAndServe or Serve is called. | NewDynamicServer 校验 config 并返回服务器。服务器在调用
// Listen、ListenAndServe 或 Serve 之前不会绑定套接字。
func NewDynamicServer(config DynamicServerConfig) (*DynamicServer, error) {
	normalized, err := normalizeDynamicServerConfig(config)
	if err != nil {
		return nil, err
	}
	cache := normalized.DuplicateCache
	if cache == nil {
		cache, err = NewDynamicDuplicateCache(DynamicDuplicateCacheConfig{
			Capacity: normalized.DuplicateCapacity,
			TTL:      normalized.DuplicateTTL,
		})
		if err != nil {
			return nil, err
		}
	}
	secret := append([]byte(nil), normalized.Secret...)
	normalized.Secret = nil
	return &DynamicServer{
		cfg:     normalized,
		handler: normalized.Handler,
		cache:   cache,
		logger:  normalized.Logger,
		secret:  secret,
	}, nil
}

// normalizeDynamicServerConfig validates and fills config defaults. | normalizeDynamicServerConfig
// 校验并填充 config 的默认值。
func normalizeDynamicServerConfig(config DynamicServerConfig) (DynamicServerConfig, error) {
	network, err := normalizeDynamicNetwork(config.Network)
	if err != nil {
		return DynamicServerConfig{}, err
	}
	config.Network = network
	if strings.TrimSpace(config.Address) == "" {
		config.Address = DefaultDynamicServerAddress
	}
	if _, _, err := net.SplitHostPort(config.Address); err != nil {
		return DynamicServerConfig{}, errs.WrapDetail(err, ErrInvalidConfig, "listen address %q is invalid", config.Address)
	}
	if len(config.Secret) == 0 {
		return DynamicServerConfig{}, errs.Detail(ErrInvalidConfig, "shared secret is required")
	}
	if config.Handler == nil {
		return DynamicServerConfig{}, errs.Detail(ErrInvalidConfig, "dynamic authorization handler is required")
	}
	if config.Timeout < 0 {
		return DynamicServerConfig{}, errs.Detail(ErrInvalidConfig, "timeout must not be negative")
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}
	if config.MaxPacketSize == 0 {
		config.MaxPacketSize = MaxPacketLength
	}
	if config.MaxPacketSize < HeaderLength || config.MaxPacketSize > MaxPacketLength {
		return DynamicServerConfig{}, errs.Detail(ErrInvalidConfig, "max packet size %d must be in [%d,%d]", config.MaxPacketSize, HeaderLength, MaxPacketLength)
	}
	if config.Logger == nil {
		config.Logger = log.Default()
	}
	return config, nil
}

// normalizeDynamicNetwork validates and canonicalizes a UDP network name. | normalizeDynamicNetwork
// 校验并规范化 UDP 网络名称。
func normalizeDynamicNetwork(network string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(network))
	switch name {
	case "":
		return NetworkUDP, nil
	case "udp", "udp4", "udp6":
		return name, nil
	default:
		return "", errs.Detail(ErrInvalidConfig, "unsupported dynamic authorization network %q", network)
	}
}

// Listen binds the configured UDP address and returns it. Calling Listen again returns the existing
// address. | Listen 绑定配置的 UDP 地址并返回它。再次调用 Listen 返回现有地址。
func (s *DynamicServer) Listen() (net.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrServerClosed
	}
	if s.conn != nil {
		return s.conn.LocalAddr(), nil
	}
	conn, err := net.ListenPacket(s.cfg.Network, s.cfg.Address)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrNetwork, "listen on %s", s.cfg.Address)
	}
	s.conn = conn
	s.addr = conn.LocalAddr()
	return s.addr, nil
}

// Addr returns the bound address, or nil before Listen. The address remains available after Serve
// returns. | Addr 返回已绑定的地址，Listen 之前为 nil。Serve 返回后地址仍可获取。
func (s *DynamicServer) Addr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return s.addr
}

// ListenAndServe binds the configured address and serves until ctx is done or Close is called. It
// returns nil after context cancellation and ErrServerClosed after Close. | ListenAndServe 绑定配置
// 的地址并服务，直到 ctx 结束或调用 Close。上下文取消后返回 nil，Close 之后返回 ErrServerClosed。
func (s *DynamicServer) ListenAndServe(ctx context.Context) error {
	if _, err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Serve serves the bound UDP socket until ctx is done or Close is called. Listen must be called
// first; Serve takes ownership of the bound socket and closes it when it returns. It returns nil
// after context cancellation, ErrServerClosed after Close, ErrInvalidConfig when the server is not
// listening or is already serving, and an error wrapping ErrNetwork for a socket failure. | Serve
// 服务已绑定的 UDP 套接字，直到 ctx 结束或调用 Close。必须先调用 Listen；Serve 接管已绑定的
// 套接字并在返回时关闭它。上下文取消后返回 nil，Close 之后返回 ErrServerClosed，服务器未监听或
// 已在服务时返回 ErrInvalidConfig，套接字故障返回包装 ErrNetwork 的错误。
func (s *DynamicServer) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	if s.conn == nil {
		s.mu.Unlock()
		return errs.Detail(ErrInvalidConfig, "dynamic authorization server is not listening")
	}
	if s.serving {
		s.mu.Unlock()
		return errs.Detail(ErrInvalidConfig, "dynamic authorization server is already serving")
	}
	conn := s.conn
	s.serving = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.serving = false
		if s.conn == conn {
			s.conn = nil
		}
		s.mu.Unlock()
		_ = conn.Close()
	}()
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	buffer := make([]byte, s.cfg.MaxPacketSize+1)
	for {
		n, source, err := conn.ReadFrom(buffer)
		if err != nil {
			if s.isClosed() {
				return ErrServerClosed
			}
			if ctx.Err() != nil {
				return nil
			}
			// Windows reports a datagram that does not fit the receive buffer as an error instead of
			// silently truncating it, returning n equal to the full buffer. The datagram is dropped and
			// the server keeps serving. | 在 Windows 上，超出接收缓冲区的数据报会以错误报告而不是被静默
			// 截断，此时 n 等于整个缓冲区长度。该数据报会被丢弃，服务器继续服务。
			if n > 0 && n == len(buffer) {
				s.logDrop(source, errs.Detail(ErrInvalidPacket, "datagram exceeds %d bytes", s.cfg.MaxPacketSize))
				continue
			}
			// A UDP socket can report an ICMP-induced reset from a previous response to an already
			// closed peer. That is transient, so keep serving instead of stopping the NAS. | UDP
			// 套接字可能因先前向已关闭对端发送响应而被 ICMP 重置。这是暂时性的，应继续服务而不是
			// 停止 NAS。
			if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
				s.logger.Debug("radius: transient dynamic authorization socket error | radius：动态授权套接字暂时性错误",
					log.Err(err))
				continue
			}
			return errs.Wrap(err, ErrNetwork)
		}
		if n > s.cfg.MaxPacketSize {
			s.logDrop(source, errs.Detail(ErrInvalidPacket, "datagram length %d exceeds %d", n, s.cfg.MaxPacketSize))
			continue
		}
		raw := append([]byte(nil), buffer[:n]...)
		s.handleDatagram(ctx, conn, raw, source)
	}
}

// Close zeroizes the server's shared secret copy, closes the socket and rejects further Listen and
// Serve calls. Close is idempotent and safe for concurrent use. | Close 清零服务器的共享密钥副本、
// 关闭套接字并拒绝后续 Listen 与 Serve 调用。Close 幂等且可并发使用。
func (s *DynamicServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	zeroBytes(s.secret)
	s.secret = nil
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	return nil
}

// isClosed reports whether Close has run. | isClosed 报告是否已执行 Close。
func (s *DynamicServer) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// secretSnapshot returns a zeroable copy of the shared secret. | secretSnapshot 返回可清零的共享密钥副本。
func (s *DynamicServer) secretSnapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrServerClosed
	}
	out := make([]byte, len(s.secret))
	copy(out, s.secret)
	return out, nil
}

// handleDatagram validates and answers one datagram. | handleDatagram 校验并应答一个数据报。
func (s *DynamicServer) handleDatagram(ctx context.Context, conn net.PacketConn, raw []byte, source net.Addr) {
	packet, err := ParsePacket(raw)
	if err != nil {
		s.logDrop(source, err)
		return
	}
	if packet.Code != CodeCoARequest && packet.Code != CodeDisconnectRequest {
		s.logDrop(source, errs.Detail(ErrUnexpectedCode, "dynamic server received code %d", uint8(packet.Code)))
		return
	}
	secret, err := s.secretSnapshot()
	if err != nil {
		return
	}
	defer zeroBytes(secret)
	if err := verifyAccountingRequestAuthenticator(raw, secret); err != nil {
		s.logDrop(source, err)
		return
	}
	present, valid, err := verifyMessageAuthenticatorRaw(raw, secret, [16]byte{})
	if err != nil {
		s.logDrop(source, err)
		return
	}
	if present && !valid {
		s.logDrop(source, ErrMessageAuthenticator)
		return
	}
	if !present && s.cfg.RequireMessageAuthenticator {
		s.logDrop(source, errs.Detail(ErrMessageAuthenticator, "request lacks the required Message-Authenticator"))
		return
	}

	key := DynamicDuplicateKey{
		Source:        source.String(),
		Code:          packet.Code,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
	}
	if cached, ok := s.cache.Get(key); ok {
		s.logger.Debug("radius: replayed duplicate dynamic authorization response | radius：已重放重复的动态授权响应",
			log.Str("peer", source.String()))
		s.writeResponse(conn, source, cached)
		return
	}

	request := decodeDynamicAuthorizationPacket(packet, source)
	result, err := s.invokeHandler(ctx, request)
	if err != nil {
		s.logger.Warn("radius: dynamic authorization handler failed | radius：动态授权处理器失败",
			log.Str("peer", source.String()), log.Err(err))
		result = &DynamicAuthorizationResult{ErrorCause: ErrorCauseResourcesUnavailable}
	}
	response, err := s.buildResponse(request, result, present, secret)
	if err != nil {
		s.logger.Warn("radius: invalid dynamic authorization response | radius：动态授权响应非法",
			log.Str("peer", source.String()), log.Err(err))
		result = &DynamicAuthorizationResult{ErrorCause: ErrorCauseResourcesUnavailable}
		response, err = s.buildResponse(request, result, present, secret)
		if err != nil {
			s.logger.Error("radius: cannot encode dynamic authorization response | radius：无法编码动态授权响应",
				log.Str("peer", source.String()), log.Err(err))
			return
		}
	}
	s.cache.Put(key, response)
	s.writeResponse(conn, source, response)
}

// invokeHandler runs the handler under the configured per-request timeout. | invokeHandler 在配置的
// 单请求超时下运行处理器。
func (s *DynamicServer) invokeHandler(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
	if s.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}
	result, err := s.handler.HandleDynamicAuthorization(ctx, request)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errs.Detail(ErrInternal, "dynamic authorization handler returned a nil result")
	}
	return result, nil
}

// buildResponse encodes and signs the ACK or NAK for request. | buildResponse 编码并签名针对 request
// 的 ACK 或 NAK。
func (s *DynamicServer) buildResponse(request *DynamicAuthorizationPacket, result *DynamicAuthorizationResult, includeMessageAuthenticator bool, secret []byte) ([]byte, error) {
	if err := validateDynamicAuthorizationResult(request.Code, result); err != nil {
		return nil, err
	}
	code, err := dynamicAuthorizationResponseCode(request.Code, result.Accept)
	if err != nil {
		return nil, err
	}
	raw, err := MarshalPacket(&Packet{
		Code:          code,
		Identifier:    request.Identifier,
		Authenticator: request.Authenticator,
		Attributes:    dynamicResponseAttributes(request, result, includeMessageAuthenticator),
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	if includeMessageAuthenticator {
		if err := signMessageAuthenticator(raw, secret, request.Authenticator); err != nil {
			return nil, errs.Wrap(err, ErrInternal)
		}
	}
	if err := applyResponseAuthenticator(raw, secret); err != nil {
		return nil, errs.Wrap(err, ErrInternal)
	}
	return raw, nil
}

// dynamicResponseAttributes assembles the response attribute list. | dynamicResponseAttributes 组装
// 响应属性列表。
func dynamicResponseAttributes(request *DynamicAuthorizationPacket, result *DynamicAuthorizationResult, includeMessageAuthenticator bool) Attributes {
	var attributes Attributes
	for _, proxyState := range request.Attributes.GetAll(AttrProxyState) {
		attributes = append(attributes, Attributes{proxyState}.Clone()...)
	}
	if result.ErrorCause != 0 {
		attributes.AddUint32(AttrErrorCause, uint32(result.ErrorCause))
	}
	if result.ReplyMessage != "" {
		attributes.AddString(AttrReplyMessage, result.ReplyMessage)
	}
	for _, attribute := range result.Attributes {
		switch attribute.Type {
		case AttrErrorCause, AttrReplyMessage, AttrMessageAuthenticator:
			continue
		}
		attributes = append(attributes, Attributes{attribute}.Clone()...)
	}
	if includeMessageAuthenticator {
		attributes.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	return attributes
}

// validateDynamicAuthorizationResult enforces RFC 5176 Error-Cause ranges. | validateDynamicAuthorizationResult
// 强制执行 RFC 5176 的 Error-Cause 取值范围。
func validateDynamicAuthorizationResult(requestCode Code, result *DynamicAuthorizationResult) error {
	if result == nil {
		return errs.Detail(ErrInvalidRequest, "dynamic authorization result is nil")
	}
	if result.ErrorCause == 0 {
		return nil
	}
	if result.Accept {
		if result.ErrorCause < 200 || result.ErrorCause > 299 {
			return errs.Detail(ErrInvalidRequest, "Error-Cause %d is not valid in an ACK", uint32(result.ErrorCause))
		}
		if result.ErrorCause == ErrorCauseResidualSessionContextRemoved && requestCode != CodeDisconnectRequest {
			return errs.Detail(ErrInvalidRequest, "Error-Cause %d is only valid in a Disconnect-ACK", uint32(result.ErrorCause))
		}
		return nil
	}
	if result.ErrorCause < 400 || result.ErrorCause > 599 {
		return errs.Detail(ErrInvalidRequest, "Error-Cause %d is not valid in a NAK", uint32(result.ErrorCause))
	}
	return nil
}

// dynamicAuthorizationResponseCode maps a request code and decision to the response code. |
// dynamicAuthorizationResponseCode 将请求类型与决定映射为响应类型。
func dynamicAuthorizationResponseCode(requestCode Code, accept bool) (Code, error) {
	switch requestCode {
	case CodeCoARequest:
		if accept {
			return CodeCoAACK, nil
		}
		return CodeCoANAK, nil
	case CodeDisconnectRequest:
		if accept {
			return CodeDisconnectACK, nil
		}
		return CodeDisconnectNAK, nil
	default:
		return 0, errs.Detail(ErrUnexpectedCode, "code %d is not a dynamic authorization request", uint8(requestCode))
	}
}

// decodeDynamicAuthorizationPacket extracts typed fields from an authenticated request. |
// decodeDynamicAuthorizationPacket 从已认证请求提取类型化字段。
func decodeDynamicAuthorizationPacket(packet *Packet, source net.Addr) *DynamicAuthorizationPacket {
	request := &DynamicAuthorizationPacket{
		Code:          packet.Code,
		Identifier:    packet.Identifier,
		Authenticator: packet.Authenticator,
		RemoteAddr:    source,
		Attributes:    packet.Attributes.Clone(),
	}
	if attribute, ok := packet.Attributes.Get(AttrAcctSessionID); ok {
		request.SessionID = attribute.String()
	}
	if attribute, ok := packet.Attributes.Get(AttrUserName); ok {
		request.UserName = attribute.String()
	}
	if attribute, ok := packet.Attributes.Get(AttrNASIPAddress); ok {
		if ip, ok := attribute.IPv4(); ok {
			request.NASIPAddress = ip
		}
	}
	if attribute, ok := packet.Attributes.Get(AttrNASIdentifier); ok {
		request.NASIdentifier = attribute.String()
	}
	if value, ok := packet.Attributes.Uint32(AttrNASPort); ok {
		request.NASPort = value
	}
	if value, ok := packet.Attributes.Uint32(AttrEventTimestamp); ok {
		request.EventTimestamp = time.Unix(int64(value), 0).UTC()
		request.HasEventTimestamp = true
	}
	_, request.HasMessageAuthenticator = packet.Attributes.Get(AttrMessageAuthenticator)
	return request
}

// writeResponse sends one datagram under the configured timeout. | writeResponse 在配置的超时下发送
// 一个数据报。
func (s *DynamicServer) writeResponse(conn net.PacketConn, source net.Addr, response []byte) {
	if s.cfg.Timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout))
	}
	if _, err := conn.WriteTo(response, source); err != nil && !s.isClosed() {
		s.logger.Debug("radius: failed to write dynamic authorization response | radius：写入动态授权响应失败",
			log.Str("peer", source.String()), log.Err(err))
	}
}

// logDrop reports a discarded datagram at debug level. | logDrop 以调试级别报告被丢弃的数据报。
func (s *DynamicServer) logDrop(source net.Addr, err error) {
	peer := ""
	if source != nil {
		peer = source.String()
	}
	s.logger.Debug("radius: dropped dynamic authorization packet | radius：已丢弃动态授权报文",
		log.Str("peer", peer), log.Err(err))
}
