package radius

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// Default server addresses and limits. | 默认服务器地址与限制。
const (
	// DefaultAccessServerAddress is the RFC 2865 Access-Request UDP port. | DefaultAccessServerAddress
	// 是 RFC 2865 Access-Request 的 UDP 端口。
	DefaultAccessServerAddress = ":1812"
	// DefaultAccountingServerAddress is the RFC 2866 Accounting-Request UDP port. |
	// DefaultAccountingServerAddress 是 RFC 2866 Accounting-Request 的 UDP 端口。
	DefaultAccountingServerAddress = ":1813"
	// DefaultServerTLSAddress is the RFC 6614 RADIUS over TLS port used by stream servers when no
	// address is configured. RFC 6613 TCP also defaults to this port. | DefaultServerTLSAddress 是
	// 未配置地址时流服务器使用的 RFC 6614 RADIUS over TLS 端口。RFC 6613 TCP 也默认使用该端口。
	DefaultServerTLSAddress = ":2083"
	// DefaultMaxConcurrentRequests is the default number of requests an AccessServer or
	// AccountingServer handles concurrently. | DefaultMaxConcurrentRequests 是 AccessServer 或
	// AccountingServer 默认并发处理的请求数。
	DefaultMaxConcurrentRequests = 128
)

// ServerClient is the shared secret a server resolved for one RADIUS client. | ServerClient 是服务器
// 为某个 RADIUS 客户端解析出的共享密钥。
//
// Secret is copied before use and the copy is zeroed after the request, so a lookup may reuse a
// buffer. Name is only used in diagnostics and never appears on the wire. | Secret 会在使用前被复制，
// 并在请求结束后清零，因此查找逻辑可以复用缓冲区。Name 仅用于诊断，绝不会出现在线路上。
type ServerClient struct {
	// Name identifies the client in diagnostics. | Name 在诊断中标识客户端。
	Name string
	// Secret is the shared secret; it must not be empty. | Secret 是共享密钥；不得为空。
	Secret []byte
}

// ServerClientLookup resolves the RADIUS client and shared secret for an incoming request. |
// ServerClientLookup 为收到的请求解析 RADIUS 客户端与共享密钥。
//
// The server calls LookupServerClient before verifying the request authenticator. remote is the
// datagram source or the peer address of a stream connection, and attributes preserves the request
// attributes in wire order, which allows selecting a client by NAS-Identifier or NAS-IP-Address.
// Returning an error or a nil client drops the request. Lookups must be safe for concurrent use and
// should honor ctx cancellation. | 服务器在校验请求认证符之前调用 LookupServerClient。remote 是数据报
// 源地址或流连接的对端地址，attributes 按线序保留请求属性，可用于按 NAS-Identifier 或
// NAS-IP-Address 选择客户端。返回错误或 nil 客户端会丢弃请求。查找必须可并发使用，并应响应 ctx 取消。
type ServerClientLookup interface {
	// LookupServerClient returns the client for one request. | LookupServerClient 返回一次请求对应的客户端。
	LookupServerClient(ctx context.Context, remote net.Addr, attributes Attributes) (*ServerClient, error)
}

// ServerClientLookupFunc adapts a function to ServerClientLookup. | ServerClientLookupFunc 将函数
// 适配为 ServerClientLookup。
type ServerClientLookupFunc func(ctx context.Context, remote net.Addr, attributes Attributes) (*ServerClient, error)

// LookupServerClient calls f. A nil f returns ErrInvalidConfig instead of panicking. |
// LookupServerClient 调用 f。f 为 nil 时返回 ErrInvalidConfig 而不是 panic。
func (f ServerClientLookupFunc) LookupServerClient(ctx context.Context, remote net.Addr, attributes Attributes) (*ServerClient, error) {
	if f == nil {
		return nil, errs.Detail(ErrInvalidConfig, "server client lookup function is nil")
	}
	return f(ctx, remote, attributes)
}

// serverSecretResolver resolves and owns the shared secrets used by an AccessServer or
// AccountingServer. | serverSecretResolver 解析并持有 AccessServer 或 AccountingServer 使用的共享密钥。
type serverSecretResolver struct {
	lookup ServerClientLookup
	secret []byte
	mu     sync.RWMutex
	closed bool
}

// newServerSecretResolver copies a static secret. When lookup is non-nil the static secret is
// ignored, because every request resolves its own client secret. | newServerSecretResolver 复制静态
// 密钥。lookup 非 nil 时忽略静态密钥，因为每个请求都会解析自己的客户端密钥。
func newServerSecretResolver(secret []byte, lookup ServerClientLookup) *serverSecretResolver {
	resolver := &serverSecretResolver{lookup: lookup}
	if lookup == nil {
		resolver.secret = append([]byte(nil), secret...)
	}
	return resolver
}

// resolve returns a zeroable copy of the secret for one request. | resolve 返回一次请求可清零的密钥副本。
func (r *serverSecretResolver) resolve(ctx context.Context, remote net.Addr, attributes Attributes) ([]byte, error) {
	r.mu.RLock()
	closed := r.closed
	r.mu.RUnlock()
	if closed {
		return nil, ErrServerClosed
	}
	if r.lookup != nil {
		client, err := r.lookup.LookupServerClient(ctx, remote, attributes)
		if err != nil {
			return nil, err
		}
		if client == nil {
			return nil, errs.Detail(ErrInvalidConfig, "server client lookup returned no client")
		}
		if len(client.Secret) == 0 {
			return nil, errs.Detail(ErrInvalidConfig, "server client lookup returned an empty secret")
		}
		return append([]byte(nil), client.Secret...), nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, ErrServerClosed
	}
	if len(r.secret) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret is not configured")
	}
	return append([]byte(nil), r.secret...), nil
}

// close zeroizes the static secret and rejects further lookups. Per-request lookup secrets are
// owned by the request and are zeroed by the server. | close 清零静态密钥并拒绝后续查找。按请求解析
// 的查找密钥归请求所有，由服务器清零。
func (r *serverSecretResolver) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	zeroBytes(r.secret)
	r.secret = nil
}

// serverSettings is the validated common transport configuration of an AccessServer or
// AccountingServer. | serverSettings 是 AccessServer 或 AccountingServer 已校验的公共传输配置。
type serverSettings struct {
	tlsConfig     *tls.Config
	network       string
	address       string
	maxPacketSize int
	maxConcurrent int
	timeout       time.Duration
	stream        bool
	useTLS        bool
}

// normalizeServerSettings validates common server configuration and fills defaults. | normalizeServerSettings
// 校验服务器公共配置并填充默认值。
func normalizeServerSettings(network, address, udpDefault string, maxPacketSize, maxConcurrent int, timeout time.Duration, tlsConfig *tls.Config) (serverSettings, error) {
	canonical, err := normalizeNetwork(network)
	if err != nil {
		return serverSettings{}, err
	}
	stream := strings.HasPrefix(canonical, NetworkTCP) || strings.HasPrefix(canonical, NetworkTLS)
	useTLS := strings.HasPrefix(canonical, NetworkTLS)
	if strings.TrimSpace(address) == "" {
		if stream {
			address = DefaultServerTLSAddress
		} else {
			address = udpDefault
		}
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return serverSettings{}, errs.WrapDetail(err, ErrInvalidConfig, "listen address %q is invalid", address)
	}
	if maxPacketSize == 0 {
		maxPacketSize = MaxPacketLength
	}
	if maxPacketSize < HeaderLength || maxPacketSize > MaxPacketLength {
		return serverSettings{}, errs.Detail(ErrInvalidConfig, "max packet size %d must be in [%d,%d]", maxPacketSize, HeaderLength, MaxPacketLength)
	}
	if maxConcurrent < 0 {
		return serverSettings{}, errs.Detail(ErrInvalidConfig, "max concurrent requests must not be negative")
	}
	if maxConcurrent == 0 {
		maxConcurrent = DefaultMaxConcurrentRequests
	}
	if timeout < 0 {
		return serverSettings{}, errs.Detail(ErrInvalidConfig, "timeout must not be negative")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if useTLS && tlsConfig == nil {
		return serverSettings{}, errs.Detail(ErrInvalidConfig, "TLS configuration is required for network %q", canonical)
	}
	if tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
	}
	return serverSettings{
		network:       canonical,
		address:       address,
		stream:        stream,
		useTLS:        useTLS,
		maxPacketSize: maxPacketSize,
		maxConcurrent: maxConcurrent,
		timeout:       timeout,
		tlsConfig:     tlsConfig,
	}, nil
}

// serverTransportConfig configures the shared UDP or stream transport of a server. |
// serverTransportConfig 配置服务器的共享 UDP 或流传输。
type serverTransportConfig struct {
	settings serverSettings
	logger   *log.Logger
	handle   func(ctx context.Context, raw []byte, remote net.Addr) (response []byte, keep bool)
	label    string
}

// serverTransport serves one UDP socket or one TCP/TLS listener for an AccessServer or
// AccountingServer. | serverTransport 为 AccessServer 或 AccountingServer 服务一个 UDP 套接字或一个
// TCP/TLS 监听器。
type serverTransport struct {
	cfg serverTransportConfig

	packet   net.PacketConn
	listener net.Listener
	addr     net.Addr
	cancel   context.CancelFunc
	conns    map[net.Conn]struct{}

	handlers sync.WaitGroup

	mu      sync.Mutex
	closed  bool
	serving bool
}

// newServerTransport returns a transport that binds only when Listen is called. |
// newServerTransport 返回仅在调用 Listen 时绑定套接字的传输。
func newServerTransport(config serverTransportConfig) *serverTransport {
	return &serverTransport{cfg: config}
}

// Listen binds the configured address and returns it. Calling Listen again returns the existing
// address. | Listen 绑定配置的地址并返回它。再次调用 Listen 返回现有地址。
func (t *serverTransport) Listen() (net.Addr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, ErrServerClosed
	}
	if t.packet != nil {
		return t.packet.LocalAddr(), nil
	}
	if t.listener != nil {
		return t.listener.Addr(), nil
	}
	if t.cfg.settings.stream {
		listenNetwork := t.cfg.settings.network
		if t.cfg.settings.useTLS {
			listenNetwork = "tcp" + strings.TrimPrefix(listenNetwork, NetworkTLS)
		}
		listener, err := net.Listen(listenNetwork, t.cfg.settings.address)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrNetwork, "listen on %s", t.cfg.settings.address)
		}
		if t.cfg.settings.useTLS {
			listener = tls.NewListener(listener, t.cfg.settings.tlsConfig.Clone())
		}
		t.listener = listener
		t.addr = listener.Addr()
		return t.addr, nil
	}
	conn, err := net.ListenPacket(t.cfg.settings.network, t.cfg.settings.address)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrNetwork, "listen on %s", t.cfg.settings.address)
	}
	t.packet = conn
	t.addr = conn.LocalAddr()
	return t.addr, nil
}

// Addr returns the bound address, or nil before Listen. The address remains available after Serve
// returns. | Addr 返回已绑定的地址，Listen 之前为 nil。Serve 返回后地址仍可获取。
func (t *serverTransport) Addr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.packet != nil {
		return t.packet.LocalAddr()
	}
	if t.listener != nil {
		return t.listener.Addr()
	}
	return t.addr
}

// Serve serves the bound socket or listener until ctx is done or Close is called. Listen must be
// called first. It returns nil after context cancellation, ErrServerClosed after Close,
// ErrInvalidConfig when the server is not listening or is already serving, and an error wrapping
// ErrNetwork for a listener or socket failure. | Serve 服务已绑定的套接字或监听器，直到 ctx 结束或
// 调用 Close。必须先调用 Listen。上下文取消后返回 nil，Close 之后返回 ErrServerClosed，服务器未监听
// 或已在服务时返回 ErrInvalidConfig，监听器或套接字故障返回包装 ErrNetwork 的错误。
func (t *serverTransport) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrServerClosed
	}
	packet := t.packet
	listener := t.listener
	if packet == nil && listener == nil {
		t.mu.Unlock()
		return errs.Detail(ErrInvalidConfig, "%s server is not listening", t.cfg.label)
	}
	if t.serving {
		t.mu.Unlock()
		return errs.Detail(ErrInvalidConfig, "%s server is already serving", t.cfg.label)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	t.serving = true
	t.cancel = cancel
	t.mu.Unlock()

	defer func() {
		cancel()
		t.mu.Lock()
		t.serving = false
		t.cancel = nil
		if t.packet == packet {
			t.packet = nil
		}
		if t.listener == listener {
			t.listener = nil
		}
		t.mu.Unlock()
		if packet != nil {
			_ = packet.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		t.closeConnections()
		t.handlers.Wait()
	}()
	stop := context.AfterFunc(serveCtx, func() {
		if packet != nil {
			_ = packet.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		t.closeConnections()
	})
	defer stop()

	if packet != nil {
		return t.serveUDP(serveCtx, packet)
	}
	return t.serveStream(serveCtx, listener)
}

// Close closes the socket or listener and every accepted stream connection, and rejects further
// Listen and Serve calls. Close is idempotent and safe for concurrent use. The owning server zeroizes
// its shared keystore separately. | Close 关闭套接字或监听器以及全部已接受的流连接，并拒绝后续 Listen
// 与 Serve 调用。Close 幂等且可并发使用。所属服务器会另行清零共享密钥存储。
func (t *serverTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	cancel := t.cancel
	packet := t.packet
	listener := t.listener
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if packet != nil {
		_ = packet.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	t.closeConnections()
	return nil
}

// isClosed reports whether Close has run. | isClosed 报告是否已执行 Close。
func (t *serverTransport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// requestContext derives the per-request context and always returns a cancel function. |
// requestContext 派生单请求上下文，并且总是返回取消函数。
func (t *serverTransport) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if t.cfg.settings.timeout > 0 {
		return context.WithTimeout(ctx, t.cfg.settings.timeout)
	}
	return context.WithCancel(ctx)
}

// serveUDP reads and dispatches datagrams until the socket closes. | serveUDP 读取并分派数据报，直到
// 套接字关闭。
func (t *serverTransport) serveUDP(ctx context.Context, conn net.PacketConn) error {
	buffer := make([]byte, t.cfg.settings.maxPacketSize+1)
	semaphore := make(chan struct{}, t.cfg.settings.maxConcurrent)
	for {
		n, source, err := conn.ReadFrom(buffer)
		if err != nil {
			if t.isClosed() {
				return ErrServerClosed
			}
			if ctx.Err() != nil {
				return nil
			}
			// Windows reports an oversized datagram as an error while returning a full buffer. |
			// Windows 会把超大数据报报告为错误并返回填满的缓冲区。
			if n > 0 && n >= len(buffer) {
				t.logDrop(source, errs.Detail(ErrInvalidPacket, "datagram exceeds %d bytes", t.cfg.settings.maxPacketSize))
				continue
			}
			// An ICMP error from a previous response must not stop the server. | 先前响应引发的
			// ICMP 错误不得停止服务器。
			if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
				t.cfg.logger.Debug("radius: transient server socket error | radius：服务器套接字暂时性错误",
					log.Err(err))
				continue
			}
			return errs.Wrap(err, ErrNetwork)
		}
		if n > t.cfg.settings.maxPacketSize {
			t.logDrop(source, errs.Detail(ErrInvalidPacket, "datagram length %d exceeds %d", n, t.cfg.settings.maxPacketSize))
			continue
		}
		select {
		case semaphore <- struct{}{}:
		default:
			t.logDrop(source, errs.Detail(ErrInvalidPacket, "concurrency limit of %d reached", t.cfg.settings.maxConcurrent))
			continue
		}
		raw := append([]byte(nil), buffer[:n]...)
		t.handlers.Add(1)
		go func(raw []byte, source net.Addr) {
			defer t.handlers.Done()
			defer func() { <-semaphore }()
			requestCtx, cancel := t.requestContext(ctx)
			response, _ := t.cfg.handle(requestCtx, raw, source)
			cancel()
			if response != nil {
				t.writeDatagram(conn, source, response)
			}
		}(raw, source)
	}
}

// serveStream accepts connections until the listener closes. Each connection is handled by one
// goroutine that processes length-delimited requests sequentially, so responses stay in request
// order on that connection. | serveStream 接受连接，直到监听器关闭。每个连接由一个协程顺序处理按长度
// 分帧的请求，因此该连接上的响应保持请求顺序。
func (t *serverTransport) serveStream(ctx context.Context, listener net.Listener) error {
	semaphore := make(chan struct{}, t.cfg.settings.maxConcurrent)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if t.isClosed() {
				return ErrServerClosed
			}
			if ctx.Err() != nil {
				return nil
			}
			return errs.Wrap(err, ErrNetwork)
		}
		select {
		case semaphore <- struct{}{}:
		default:
			t.logDrop(conn.RemoteAddr(), errs.Detail(ErrInvalidPacket, "concurrency limit of %d reached", t.cfg.settings.maxConcurrent))
			_ = conn.Close()
			continue
		}
		t.trackConn(conn)
		t.handlers.Add(1)
		go func(conn net.Conn) {
			defer t.handlers.Done()
			defer func() { <-semaphore }()
			defer t.untrackConn(conn)
			defer func() { _ = conn.Close() }()
			t.serveStreamConn(ctx, conn)
		}(conn)
	}
}

// serveStreamConn reads and answers length-delimited requests on one stream connection. A handler
// that returns keep=false closes the connection, following RFC 6613 section 2.6.4 for unauthenticated
// or malformed packets. | serveStreamConn 在一个流连接上读取并应答按长度分帧的请求。处理器返回
// keep=false 时关闭连接，遵循 RFC 6613 第 2.6.4 节对未认证或畸形报文的处理。
func (t *serverTransport) serveStreamConn(ctx context.Context, conn net.Conn) {
	for {
		raw, err := readServerFrame(conn, t.cfg.settings.maxPacketSize)
		if err != nil {
			if !errors.Is(err, io.EOF) && !t.isClosed() {
				t.logDrop(conn.RemoteAddr(), err)
			}
			return
		}
		requestCtx, cancel := t.requestContext(ctx)
		response, keep := t.cfg.handle(requestCtx, raw, conn.RemoteAddr())
		cancel()
		if !keep {
			return
		}
		if response == nil {
			continue
		}
		if t.cfg.settings.timeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(t.cfg.settings.timeout))
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

// readServerFrame reads one length-delimited RADIUS request from a stream. | readServerFrame 从流中
// 读取一个按长度分帧的 RADIUS 请求。
func readServerFrame(conn net.Conn, maxPacketSize int) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < HeaderLength || length > maxPacketSize {
		return nil, errs.Detail(ErrInvalidPacket, "declared length %d is invalid", length)
	}
	raw := make([]byte, length)
	copy(raw, header)
	if _, err := io.ReadFull(conn, raw[4:]); err != nil {
		return nil, err
	}
	return raw, nil
}

// writeDatagram sends one response datagram under the configured timeout. | writeDatagram 在配置的
// 超时下发送一个响应数据报。
func (t *serverTransport) writeDatagram(conn net.PacketConn, source net.Addr, response []byte) {
	if t.cfg.settings.timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(t.cfg.settings.timeout))
	}
	if _, err := conn.WriteTo(response, source); err != nil && !t.isClosed() {
		t.cfg.logger.Debug("radius: failed to write server response | radius：写入服务器响应失败",
			log.Str("peer", source.String()), log.Err(err))
	}
}

// trackConn records an accepted stream connection for Close. | trackConn 记录已接受的流连接以供 Close 关闭。
func (t *serverTransport) trackConn(conn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conns == nil {
		t.conns = make(map[net.Conn]struct{})
	}
	t.conns[conn] = struct{}{}
}

// untrackConn forgets a closed stream connection. | untrackConn 移除已关闭的流连接。
func (t *serverTransport) untrackConn(conn net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, conn)
}

// closeConnections closes every accepted stream connection. | closeConnections 关闭全部已接受的流连接。
func (t *serverTransport) closeConnections() {
	t.mu.Lock()
	conns := make([]net.Conn, 0, len(t.conns))
	for conn := range t.conns {
		conns = append(conns, conn)
	}
	t.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// logDrop reports a discarded request at debug level. | logDrop 以调试级别报告被丢弃的请求。
func (t *serverTransport) logDrop(source net.Addr, err error) {
	t.cfg.logger.Debug("radius: dropped server packet | radius：已丢弃服务器报文",
		log.Str("server", t.cfg.label), log.Str("peer", peerString(source)), log.Err(err))
}

// peerString renders a remote address for diagnostics. | peerString 为诊断呈现远端地址。
func peerString(remote net.Addr) string {
	if remote == nil {
		return ""
	}
	return remote.String()
}
