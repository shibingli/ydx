package kmip

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ClientConfig configures a Client. | ClientConfig 配置 Client。
//
// A production client requires TLS; AllowPlaintext exists only for tests and local in-process
// deployments. | 生产客户端必须使用 TLS；AllowPlaintext 仅用于测试与本地进程内部署。
type ClientConfig struct {
	// Address is the server address in host:port form. | Address 是 host:port 形式的服务器地址。
	Address string
	// TLSConfig enables TLS when non-nil. ServerName should normally be set. | TLSConfig 非空时启用 TLS；
	// 通常应设置 ServerName。
	TLSConfig *tls.Config
	// AllowPlaintext permits a TCP connection without TLS. Tests may set it; production deployments
	// should not. | AllowPlaintext 允许不带 TLS 的 TCP 连接；测试可设置，生产部署不应设置。
	AllowPlaintext bool
	// DialTimeout bounds the TCP connect and TLS handshake; zero uses the context deadline or blocks. |
	// DialTimeout 限制 TCP 连接与 TLS 握手；为零时使用上下文截止时间或一直等待。
	DialTimeout time.Duration
	// ReadTimeout bounds one response read; zero uses the context deadline or blocks. | ReadTimeout
	// 限制一次响应读取；为零时使用上下文截止时间或一直等待。
	ReadTimeout time.Duration
	// WriteTimeout bounds one request write; zero uses the context deadline or blocks. | WriteTimeout
	// 限制一次请求写入；为零时使用上下文截止时间或一直等待。
	WriteTimeout time.Duration
	// MaxResponseSize limits a response; zero uses DefaultMaxMessageSize. | MaxResponseSize 限制响应
	// 长度；为零时使用 DefaultMaxMessageSize。
	MaxResponseSize int
	// Limits optionally overrides the TTLV resource limits. | Limits 可选覆盖 TTLV 资源限制。
	Limits Limits
	// ProtocolVersion is the requested protocol version; zero uses DefaultProtocolVersion. |
	// ProtocolVersion 是请求的协议版本；为零时使用 DefaultProtocolVersion。
	ProtocolVersion ProtocolVersion
	// Authentication optionally carries client credentials. | Authentication 可选携带客户端凭据。
	Authentication *Authentication
	// BatchErrorContinuationOption is sent in every request header; zero uses the server default. |
	// BatchErrorContinuationOption 随每个请求头发送；为零时使用服务器默认行为。
	BatchErrorContinuationOption BatchErrorContinuationOption
}

// Client is a KMIP client. It serializes requests on one connection, so a single Client is safe for
// concurrent use.
//
// A Client reconnects lazily: after a transport failure it closes the broken connection and the next
// request dials a fresh one. The request that observed the failure is never replayed, because it may
// already have been written to the server; only the caller can decide whether retrying is safe. A
// transport error therefore means "outcome unknown" for mutating requests. Close is permanent. | Client
// 是 KMIP 客户端。它在单条连接上串行发送请求，因此单个 Client 可安全并发使用。
//
// Client 采用惰性重连：传输失败后关闭损坏的连接，下一个请求重新拨号。观察到失败的请求绝不会被重放，
// 因为它可能已经写入服务器；只有调用方能判断重试是否安全。因此对变更类请求而言，传输错误表示“结果未知”。
// Close 是永久性的。
type Client struct {
	cfg      ClientConfig
	limits   Limits
	connMu   sync.Mutex
	conn     net.Conn
	mu       sync.Mutex
	closed   bool
	closing  atomic.Bool
	closeCtx context.Context
	closeFn  context.CancelFunc
}

// DialContext connects to the KMIP server described by cfg. | DialContext 连接 cfg 描述的 KMIP 服务器。
//
// The returned Client owns the connection; callers must close it. A non-zero ProtocolVersion must be
// KMIP 1.4 or 2.0; other versions return ErrUnsupported. | 返回的 Client 拥有该连接，调用方必须关闭它。
// 非零 ProtocolVersion 必须是 KMIP 1.4 或 2.0；其它版本返回 ErrUnsupported。
func DialContext(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.Address == "" {
		return nil, errs.Detail(ErrInvalidRequest, "client address is empty | 客户端地址为空")
	}
	if cfg.TLSConfig == nil && !cfg.AllowPlaintext {
		return nil, errs.Detail(ErrTLSRequired, "client requires TLS unless AllowPlaintext is set | 除非设置 AllowPlaintext，否则客户端必须使用 TLS")
	}
	if cfg.MaxResponseSize <= 0 {
		cfg.MaxResponseSize = DefaultMaxMessageSize
	}
	if !cfg.ProtocolVersion.Valid() {
		cfg.ProtocolVersion = DefaultProtocolVersion
	}
	if !cfg.ProtocolVersion.Supported() {
		return nil, errs.Detail(ErrUnsupported,
			"protocol version %s is not supported; use KMIP 1.4 or 2.0 | 协议版本 %s 不受支持；请使用 KMIP 1.4 或 2.0",
			cfg.ProtocolVersion, cfg.ProtocolVersion)
	}
	conn, err := dialConn(ctx, cfg)
	if err != nil {
		return nil, err
	}
	closeCtx, closeFn := context.WithCancel(context.Background())
	return &Client{cfg: cfg, limits: cfg.Limits.normalized(), conn: conn, closeCtx: closeCtx, closeFn: closeFn}, nil
}

// dialConn establishes the TCP connection and optional TLS handshake described by cfg. | dialConn 建立 cfg
// 描述的 TCP 连接与可选 TLS 握手。
func dialConn(ctx context.Context, cfg ClientConfig) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, errs.WrapDetail(err, ErrTransport, "dial %s | 拨号 %s 失败", cfg.Address, cfg.Address)
	}
	if cfg.TLSConfig != nil {
		tlsConn := tls.Client(conn, cfg.TLSConfig)
		handshakeCtx := ctx
		if cfg.DialTimeout > 0 {
			var cancel context.CancelFunc
			handshakeCtx, cancel = context.WithTimeout(ctx, cfg.DialTimeout)
			defer cancel()
		}
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			_ = conn.Close()
			if ctxErr := handshakeCtx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, errs.WrapDetail(err, ErrAuthenticationFailed, "TLS handshake with %s | 与 %s 的 TLS 握手失败", cfg.Address, cfg.Address)
		}
		conn = tlsConn
	}
	return conn, nil
}

// connectLocked dials a replacement connection. The caller must hold c.mu. | connectLocked 拨号替换连接；
// 调用方必须持有 c.mu。
func (c *Client) connectLocked(ctx context.Context) error {
	if c.closing.Load() {
		return errs.Detail(ErrClosed, "client is closing | 客户端正在关闭")
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.closeCtx, cancel)
	defer stop()
	conn, err := dialConn(dialCtx, c.cfg)
	if err != nil {
		if c.closing.Load() {
			return errs.Detail(ErrClosed, "client is closing | 客户端正在关闭")
		}
		return err
	}
	if c.closing.Load() {
		_ = conn.Close()
		return errs.Detail(ErrClosed, "client is closing | 客户端正在关闭")
	}
	c.setConn(conn)
	return nil
}

// currentConn returns the active connection, if any. | currentConn 返回当前活动连接（如有）。
func (c *Client) currentConn() net.Conn {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.conn
}

// setConn installs conn as the active connection. | setConn 把 conn 设为活动连接。
func (c *Client) setConn(conn net.Conn) {
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
}

// takeConn removes and returns the active connection. | takeConn 移除并返回活动连接。
func (c *Client) takeConn() net.Conn {
	c.connMu.Lock()
	conn := c.conn
	c.conn = nil
	c.connMu.Unlock()
	return conn
}

// discardConn closes conn and clears it when it is still the active connection. | discardConn 关闭 conn，
// 并在它仍是活动连接时清除它。
func (c *Client) discardConn(conn net.Conn) {
	if conn == nil {
		return
	}
	c.connMu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.connMu.Unlock()
	_ = conn.Close()
}

// Close closes the client connection. It is idempotent. A pending request is interrupted instead of
// blocking Close indefinitely. After Close, the client never reconnects. | Close 关闭客户端连接，可重复调用。
// 进行中的请求会被中断，避免 Close 无限阻塞。Close 之后客户端不再重连。
func (c *Client) Close() error {
	c.closing.Store(true)
	if c.closeFn != nil {
		c.closeFn()
	}
	if conn := c.currentConn(); conn != nil {
		// Wake an in-flight request blocked in connection I/O; net.Conn permits concurrent deadline
		// updates. | 唤醒阻塞在连接 I/O 上的请求；net.Conn 允许并发更新截止时间。
		_ = conn.SetDeadline(time.Now())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	conn := c.takeConn()
	if conn == nil {
		return nil
	}
	if err := conn.Close(); err != nil {
		return errs.Wrap(err, ErrClosed)
	}
	return nil
}

// Do sends one batch of requests and returns the response. Requests on one Client are serialized.
// A non-success batch item is returned in the response; callers should check ResponseBatchItem.Err.
//
// The first request after a transport failure dials a new connection. A request is never retried:
// when write, read or decode fails after the connection was used, Do invalidates the connection and
// returns the error. Mutating requests should therefore be retried only when the caller can tolerate
// a duplicate, for example by supplying a caller-chosen Unique Identifier. | Do 发送一批请求并返回响应。
// 同一 Client 上的请求串行执行。非成功的批处理项会原样返回，调用方应检查 ResponseBatchItem.Err。
//
// 传输失败后的第一个请求会重新拨号。请求绝不重试：连接使用后若写入、读取或解码失败，Do 会使连接失效
// 并返回错误。因此变更类请求只应在调用方能容忍重复时重试，例如提供调用方选定的唯一标识符。
func (c *Client) Do(ctx context.Context, items ...RequestBatchItem) (ResponseMessage, error) {
	if len(items) == 0 {
		return ResponseMessage{}, errs.Detail(ErrInvalidRequest, "no batch items | 没有批处理项")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.closing.Load() {
		return ResponseMessage{}, errs.Detail(ErrClosed, "client is closed | 客户端已关闭")
	}
	if err := ctx.Err(); err != nil {
		return ResponseMessage{}, err
	}
	conn := c.currentConn()
	if conn == nil {
		if err := c.connectLocked(ctx); err != nil {
			return ResponseMessage{}, err
		}
		conn = c.currentConn()
	}
	request := RequestMessage{
		Header: RequestHeader{
			ProtocolVersion:              c.cfg.ProtocolVersion,
			MaximumResponseSize:          c.cfg.MaxResponseSize,
			Authentication:               c.cfg.Authentication,
			BatchErrorContinuationOption: c.cfg.BatchErrorContinuationOption,
		},
		BatchItems: items,
	}
	encoded, err := EncodeRequestWithLimits(request, c.limits)
	if err != nil {
		return ResponseMessage{}, err
	}
	defer zeroize(encoded)
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stop()
	if err := c.setDeadline(conn, ctx, c.cfg.WriteTimeout); err != nil {
		c.discardConn(conn)
		return ResponseMessage{}, err
	}
	if err := writeAll(conn, encoded); err != nil {
		c.discardConn(conn)
		if c.closing.Load() {
			return ResponseMessage{}, errs.Detail(ErrClosed, "client closed during request | 请求期间客户端关闭")
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ResponseMessage{}, ctxErr
		}
		return ResponseMessage{}, errs.WrapDetail(err, ErrTransport, "write request | 写入请求失败")
	}
	if err := c.setDeadline(conn, ctx, c.cfg.ReadTimeout); err != nil {
		c.discardConn(conn)
		return ResponseMessage{}, err
	}
	raw, err := readResponse(conn, c.cfg.MaxResponseSize)
	if err != nil {
		c.discardConn(conn)
		if c.closing.Load() {
			return ResponseMessage{}, errs.Detail(ErrClosed, "client closed during request | 请求期间客户端关闭")
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ResponseMessage{}, ctxErr
		}
		return ResponseMessage{}, err
	}
	// Decoded value slices alias raw, so raw must stay live as long as the response is in use. The
	// response carries the server's payload; callers zeroize key material through the object helpers. |
	// 解码后的值切片与 raw 共享底层数组，因此 raw 必须与响应同生命周期。响应携带服务器负载；
	// 调用方通过对象辅助方法清零密钥材料。
	response, err := DecodeResponseWithLimits(raw, c.limits)
	if err != nil {
		// A broken response leaves the stream position unknown. | 损坏的响应使流位置不可知。
		c.discardConn(conn)
		return ResponseMessage{}, err
	}
	return response, nil
}

// setDeadline applies the earlier of the context deadline and timeout to conn. | setDeadline 把上下文截止
// 时间与 timeout 中较早的一个应用到 conn。
func (c *Client) setDeadline(conn net.Conn, ctx context.Context, timeout time.Duration) error {
	if c.closing.Load() {
		_ = conn.SetDeadline(time.Now())
		return errs.Detail(ErrClosed, "client is closing | 客户端正在关闭")
	}
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return errs.WrapDetail(err, ErrTransport, "set connection deadline | 设置连接截止时间失败")
	}
	return nil
}

// readResponse reads one length-delimited TTLV response message. | readResponse 读取一条带长度定界的
// TTLV 响应消息。
func readResponse(r io.Reader, maxSize int) ([]byte, error) {
	var header [ttlvHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, errs.Wrap(err, ErrTransport)
	}
	tag := Tag(uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2]))
	if tag != TagResponseMessage {
		return nil, errs.Detail(ErrMalformed, "unexpected response tag 0x%06X | 响应标签 0x%06X 非预期", uint32(tag), uint32(tag))
	}
	typ := Type(header[3])
	if typ != TypeStructure {
		return nil, errs.Detail(ErrMalformed, "response is not a structure | 响应不是结构")
	}
	// A TTLV header stores the value length, not the total item length. For a Response Message the
	// value is the encoded children, so the total is the header plus the value length. | TTLV 头保存的是
	// 值长度而不是项总长度。Response Message 的值是编码后的子项，因此总长度为头加上值长度。
	valueLength := uint64(binary.BigEndian.Uint32(header[4:]))
	total := valueLength + ttlvHeaderSize
	if total > uint64(maxSize) {
		return nil, errs.Detail(ErrResponseTooLarge, "response length %d exceeds limit %d | 响应长度 %d 超过限制 %d", total, maxSize, total, maxSize)
	}
	raw := make([]byte, int(total))
	copy(raw, header[:])
	if _, err := io.ReadFull(r, raw[ttlvHeaderSize:]); err != nil {
		return nil, errs.Wrap(err, ErrTransport)
	}
	return raw, nil
}
