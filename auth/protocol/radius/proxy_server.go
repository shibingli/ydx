package radius

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// ProxyServerConfig configures a ProxyServer. | ProxyServerConfig 配置 ProxyServer。
type ProxyServerConfig struct {
	// ClientLookup optionally resolves the downstream client secret before verification. When set
	// it takes precedence over Secret. | ClientLookup 可选地在下游校验前解析客户端共享密钥。设置后
	// 优先于 Secret。
	ClientLookup ServerClientLookup
	// Relay is required and performs authentication, translation and upstream failover. The caller
	// owns the Relay and must close it separately; ProxyServer.Close does not close it. | Relay 必填，
	// 执行认证、转换与上游故障转移。Relay 由调用方拥有并需单独关闭；ProxyServer.Close 不会关闭它。
	Relay *Relay
	// TLSConfig configures the server certificate and policy for network "tls". It is required for
	// TLS and cloned by the constructor. | TLSConfig 为 "tls" 网络配置服务器证书与策略。TLS 必填，
	// 并由构造函数克隆。
	TLSConfig *tls.Config
	// Logger receives dropped-request diagnostics; nil selects log.Default(). It never receives the
	// shared secret, a user password or request contents. | Logger 接收丢包诊断；nil 选择
	// log.Default()。它绝不会收到共享密钥、用户口令或请求内容。
	Logger *log.Logger
	// Network selects the downstream transport: "udp" (the default), "udp4", "udp6", "tcp",
	// "tcp4", "tcp6", "tls", "tls4" or "tls6". | Network 选择下游传输："udp"（默认）、"udp4"、
	// "udp6"、"tcp"、"tcp4"、"tcp6"、"tls"、"tls4" 或 "tls6"。
	Network string
	// Address is the downstream listen "host:port"; empty selects DefaultAccessServerAddress for
	// UDP and DefaultServerTLSAddress for TCP and TLS. One listener accepts both Access-Request and
	// Accounting-Request codes, so deployments that need both standard UDP ports start two servers
	// sharing one Relay. | Address 是下游监听 "host:port"；UDP 空值选择 DefaultAccessServerAddress，
	// TCP 与 TLS 空值选择 DefaultServerTLSAddress。单个监听器同时接受 Access-Request 与
	// Accounting-Request，因此需要两个标准 UDP 端口的部署应启动共享同一 Relay 的两个服务器。
	Address string
	// Secret is the downstream shared secret used to authenticate requests and sign responses. It
	// is ignored when ClientLookup is set. The server copies it and zeroes its copy in Close. |
	// Secret 是用于认证请求与签名响应的下游共享密钥。设置 ClientLookup 时忽略该字段。服务器会复制它
	// 并在 Close 时清零副本。
	Secret []byte
	// Timeout bounds one forwarded request and, on stream transports, one response write; zero
	// selects DefaultTimeout. It does not bound the lifetime of Serve. | Timeout 约束一次转发请求
	// 以及流传输的一次响应写入；零值选择 DefaultTimeout。它不约束 Serve 的生命周期。
	Timeout time.Duration
	// MaxPacketSize is the largest accepted datagram or stream frame; zero selects MaxPacketLength.
	// Values below HeaderLength or above MaxPacketLength are rejected and larger requests are
	// dropped without a response. | MaxPacketSize 是接受的最大数据报或流帧；零值选择
	// MaxPacketLength。低于 HeaderLength 或高于 MaxPacketLength 的值会被拒绝，更大的请求会被静默
	// 丢弃而不响应。
	MaxPacketSize int
	// MaxConcurrent is the maximum number of requests handled at once; zero selects
	// DefaultMaxConcurrentRequests. Negative values are rejected. | MaxConcurrent 是同时处理的最大
	// 请求数；零值选择 DefaultMaxConcurrentRequests。负值会被拒绝。
	MaxConcurrent int
	// RequireMessageAuthenticator drops Access-Requests without a valid Message-Authenticator.
	// Requests with an invalid value are always dropped. | RequireMessageAuthenticator 丢弃不携带
	// 合法 Message-Authenticator 的 Access-Request。值非法的请求始终被丢弃。
	RequireMessageAuthenticator bool
}

// ProxyServer is a RADIUS relay front end over UDP, TCP or TLS. | ProxyServer 是基于 UDP、TCP 或
// TLS 的 RADIUS 中继前端。
//
// It parses and authenticates each downstream request, verifies Accounting-Request authenticators
// and any present Message-Authenticator, then delegates translation, loop detection and upstream
// failover to its Relay. Authenticated requests whose upstreams all fail receive no response so the
// NAS retransmits; malformed or unauthenticated requests are dropped and close stream connections.
// A ProxyServer is safe for concurrent use, and Close may run while Serve is active. | 它解析并认证
// 每个下游请求，校验 Accounting-Request 认证符与存在的 Message-Authenticator，然后把转换、循环检测
// 与上游故障转移交给 Relay。已认证请求在所有上游失败时不返回响应，让 NAS 重传；畸形或未认证请求被
// 丢弃并关闭流连接。ProxyServer 可并发使用，Close 可在 Serve 活动期间调用。
type ProxyServer struct {
	relay     *Relay
	secrets   *serverSecretResolver
	logger    *log.Logger
	transport *serverTransport
	requireMA bool
}

// NewProxyServer validates config and returns a proxy server. The server does not bind until
// Listen or ListenAndServe is called. | NewProxyServer 校验 config 并返回代理服务器。服务器在调用
// Listen 或 ListenAndServe 之前不会绑定套接字。
func NewProxyServer(config ProxyServerConfig) (*ProxyServer, error) {
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
	if config.Relay == nil {
		return nil, errs.Detail(ErrInvalidConfig, "relay is required")
	}
	if config.ClientLookup == nil && len(config.Secret) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret or client lookup is required")
	}
	logger := config.Logger
	if logger == nil {
		logger = log.Default()
	}
	server := &ProxyServer{
		relay:     config.Relay,
		secrets:   newServerSecretResolver(config.Secret, config.ClientLookup),
		logger:    logger,
		requireMA: config.RequireMessageAuthenticator,
	}
	server.transport = newServerTransport(serverTransportConfig{
		settings: settings,
		label:    "proxy",
		logger:   logger,
		handle:   server.handleRequest,
	})
	return server, nil
}

// Listen binds the configured address and returns it. Calling Listen again returns the existing
// address. | Listen 绑定配置的地址并返回它。再次调用 Listen 返回现有地址。
func (s *ProxyServer) Listen() (net.Addr, error) {
	return s.transport.Listen()
}

// Addr returns the bound address, or nil before Listen. | Addr 返回已绑定的地址，Listen 之前为 nil。
func (s *ProxyServer) Addr() net.Addr {
	return s.transport.Addr()
}

// ListenAndServe binds the configured address and serves until ctx is done or Close is called. It
// returns nil after context cancellation and ErrServerClosed after Close. | ListenAndServe 绑定配置的
// 地址并服务，直到 ctx 结束或调用 Close。上下文取消后返回 nil，Close 之后返回 ErrServerClosed。
func (s *ProxyServer) ListenAndServe(ctx context.Context) error {
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
func (s *ProxyServer) Serve(ctx context.Context) error {
	return s.transport.Serve(ctx)
}

// Close zeroizes the downstream static secret and closes the socket or listener and every stream
// connection. It does not close the Relay, which may be shared with other proxy servers. Close is
// idempotent and safe for concurrent use. | Close 清零下游静态密钥并关闭套接字或监听器以及全部流
// 连接。它不会关闭可能与其他代理服务器共享的 Relay。Close 幂等且可并发使用。
func (s *ProxyServer) Close() error {
	err := s.transport.Close()
	s.secrets.close()
	return err
}

// handleRequest authenticates and forwards one request. The keep result reports whether a stream
// connection may remain open; UDP ignores it. | handleRequest 认证并转发一次请求。keep 结果报告流
// 连接是否可以保持打开；UDP 忽略它。
func (s *ProxyServer) handleRequest(ctx context.Context, raw []byte, remote net.Addr) ([]byte, bool) {
	packet, err := ParsePacket(raw)
	if err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	switch packet.Code {
	case CodeAccessRequest, CodeAccountingRequest:
	default:
		s.logDrop(remote, errs.Detail(ErrUnexpectedCode, "proxy server received code %d", uint8(packet.Code)))
		return nil, false
	}
	secret, err := s.secrets.resolve(ctx, remote, packet.Attributes)
	if err != nil {
		s.logDrop(remote, err)
		return nil, false
	}
	defer zeroBytes(secret)
	if packet.Code == CodeAccountingRequest {
		if err := verifyAccountingRequestAuthenticator(raw, secret); err != nil {
			s.logDrop(remote, err)
			return nil, false
		}
	}
	present, valid, err := verifyInboundMessageAuthenticator(packet.Code, raw, secret, packet.Authenticator)
	if err != nil {
		s.logDrop(remote, errs.Wrap(err, ErrInvalidResponse))
		return nil, false
	}
	if present && !valid {
		s.logDrop(remote, errs.Detail(ErrMessageAuthenticator, "request Message-Authenticator mismatch"))
		return nil, false
	}
	if !present && (s.requireMA || (packet.Code == CodeAccessRequest && len(packet.Attributes.GetAll(AttrEAPMessage)) > 0)) {
		s.logDrop(remote, errs.Detail(ErrMessageAuthenticator, "request lacks a required Message-Authenticator"))
		return nil, false
	}
	var result *RelayResult
	if packet.Code == CodeAccountingRequest {
		result, err = s.relay.ForwardAccounting(ctx, raw, secret)
	} else {
		result, err = s.relay.ForwardAccess(ctx, raw, secret)
	}
	if err != nil {
		s.logDrop(remote, err)
		return nil, true
	}
	return result.Raw, true
}

// logDrop reports a discarded request at debug level. | logDrop 以调试级别报告被丢弃的请求。
func (s *ProxyServer) logDrop(remote net.Addr, err error) {
	s.logger.Debug("radius: dropped proxy request | radius：已丢弃代理请求",
		log.Str("peer", peerString(remote)), log.Err(err))
}
