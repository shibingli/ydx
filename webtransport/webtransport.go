package webtransport

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	wtgo "github.com/quic-go/webtransport-go"

	"github.com/shibingli/ydx/errs"
)

// Errors returned by this package. | 本包返回的哨兵错误。
var (
	// ErrTLSRequired reports a server without a TLS configuration; WebTransport
	// only runs over QUIC, which always uses TLS. | ErrTLSRequired 表示服务端缺少
	// TLS 配置；WebTransport 只运行在始终使用 TLS 的 QUIC 上。
	ErrTLSRequired = errs.New("webtransport: TLS configuration is required | webtransport：必须提供 TLS 配置")

	// ErrNilH3 reports a missing *http3.Server. | ErrNilH3 表示缺少 *http3.Server。
	ErrNilH3 = errs.New("webtransport: nil *http3.Server | webtransport：*http3.Server 为 nil")

	// ErrHandshake reports a failed WebTransport session upgrade. | ErrHandshake
	// 表示 WebTransport 会话升级失败。
	ErrHandshake = errs.New("webtransport: session upgrade failed | webtransport：会话升级失败")

	// ErrScheme reports a dial URL that is not https. | ErrScheme 表示拨号 URL 不是 https。
	ErrScheme = errs.New("webtransport: URL scheme must be https | webtransport：URL 协议必须是 https")

	// ErrMessageTooLarge reports a frame whose payload exceeds the configured
	// limit. | ErrMessageTooLarge 表示帧载荷超过配置上限。
	ErrMessageTooLarge = errs.New("webtransport: message exceeds the configured limit | webtransport：消息超过配置上限")

	// ErrEmptyMessage reports a zero-length frame, which can only mean the stream
	// lost framing. | ErrEmptyMessage 表示零长度帧，只可能意味着流已失去帧边界。
	ErrEmptyMessage = errs.New("webtransport: empty message | webtransport：空消息")

	// ErrClosed reports work on a closed channel or session. | ErrClosed 表示在已关闭的
	// 通道或会话上操作。
	ErrClosed = errs.New("webtransport: channel or session is closed | webtransport：通道或会话已关闭")
)

// DefaultMaxMessageSize bounds one framed message when Options.MaxMessageSize is
// not set. | DefaultMaxMessageSize 是 Options.MaxMessageSize 未设置时单条消息的上限。
const DefaultMaxMessageSize = 1 << 20

// Options configures a Server. | Options 配置 Server。
type Options struct {
	// TLSConfig is the certificate configuration of the QUIC listener; it must
	// carry the "h3" ALPN, which http3.ConfigureTLSConfig adds when absent. |
	// TLSConfig 是 QUIC 监听的证书配置；必须带 "h3" ALPN，缺失时由
	// http3.ConfigureTLSConfig 补齐。
	TLSConfig *tls.Config
	// CheckOrigin validates the Origin header of an upgrade request. A nil value
	// uses the WebTransport library's same-origin policy. | CheckOrigin 校验升级请求的
	// Origin 头；nil 时使用 WebTransport 库的同源策略。
	CheckOrigin func(*http.Request) bool
	// ApplicationProtocols lists the application protocols offered to clients. |
	// ApplicationProtocols 列出向客户端提议的应用协议。
	ApplicationProtocols []string
	// MaxMessageSize bounds one framed message; values <= 0 take
	// DefaultMaxMessageSize. | MaxMessageSize 限制单条消息；<=0 时取
	// DefaultMaxMessageSize。
	MaxMessageSize int
	// Tracker, when non-nil, registers every session established by Upgrade so a
	// shutdown can close them all at once. | Tracker 非 nil 时登记 Upgrade 建立的每个
	// 会话，使退出流程能一次关闭全部会话。
	Tracker Tracker
	// QUICConfig is the QUIC configuration of the listener; nil takes the
	// library defaults (datagrams and stream-reset partial delivery are enabled
	// by the WebTransport layer regardless). | QUICConfig 是监听的 QUIC 配置；nil 取
	// 库默认值（无论何种取值，WebTransport 层都会启用数据报与流重置部分交付）。
	QUICConfig *quic.Config
}

// Server owns a WebTransport server bound to one HTTP/3 server. | Server 持有绑定到
// 一个 HTTP/3 服务器的 WebTransport 服务端。
type Server struct {
	h3      *http3.Server
	wt      *wtgo.Server
	tracker Tracker
	max     int
}

// New builds a Server with its own HTTP/3 server. | New 用自带的 HTTP/3 服务器构建 Server。
//
// The caller serves it with Serve; the embedded HTTP/3 server is available from
// H3 so the caller can install the request handler. | 调用方通过 Serve 提供服务；
// 内嵌的 HTTP/3 服务器可经 H3 取得，以便安装请求处理器。
func New(o Options) (*Server, error) {
	if o.TLSConfig == nil {
		return nil, ErrTLSRequired
	}
	h3 := &http3.Server{
		TLSConfig:  http3.ConfigureTLSConfig(o.TLSConfig),
		QUICConfig: o.QUICConfig,
	}
	return NewWithH3(h3, o)
}

// NewWithH3 builds a Server over an existing HTTP/3 server, which is how the
// framework shares one UDP listener between HTTP/3 requests and WebTransport
// sessions. | NewWithH3 在既有 HTTP/3 服务器之上构建 Server，框架借此让同一个 UDP
// 监听同时服务 HTTP/3 请求与 WebTransport 会话。
//
// The HTTP/3 server's handler must be installed by the caller before serving. |
// HTTP/3 服务器的处理器必须由调用方在提供服务前安装。
func NewWithH3(h3 *http3.Server, o Options) (*Server, error) {
	if h3 == nil {
		return nil, ErrNilH3
	}
	// A shared HTTP/3 server may have been built without an ALPN set; QUIC needs
	// "h3" before it can negotiate anything. The clone keeps the caller's config
	// untouched. | 共享的 HTTP/3 服务器可能尚未设置 ALPN；QUIC 必须先有 "h3" 才能协商。
	// 克隆保证调用方的配置不被改写。
	if h3.TLSConfig != nil && len(h3.TLSConfig.NextProtos) == 0 {
		h3.TLSConfig = http3.ConfigureTLSConfig(h3.TLSConfig)
	}
	// ConfigureHTTP3Server adds the WebTransport settings, turns on datagrams and
	// records the connection context the library needs for sessions. | ConfigureHTTP3Server
	// 追加 WebTransport 设置、开启数据报，并记录库在会话中需要的连接上下文。
	wtgo.ConfigureHTTP3Server(h3)
	wt := &wtgo.Server{
		H3:                   h3,
		CheckOrigin:          o.CheckOrigin,
		ApplicationProtocols: o.ApplicationProtocols,
	}
	max := o.MaxMessageSize
	if max <= 0 {
		max = DefaultMaxMessageSize
	}
	return &Server{h3: h3, wt: wt, tracker: o.Tracker, max: max}, nil
}

// H3 returns the embedded HTTP/3 server. | H3 返回内嵌的 HTTP/3 服务器。
func (s *Server) H3() *http3.Server { return s.h3 }

// Serve serves the QUIC listener until the server is closed. | Serve 服务 QUIC 监听直到
// 服务器关闭。
func (s *Server) Serve(conn net.PacketConn) error {
	if conn == nil {
		return errs.Detail(ErrNilH3, "nil packet connection | 数据包连接为 nil")
	}
	return s.wt.Serve(conn)
}

// Upgrade turns a WebTransport extended CONNECT request into a Session. | Upgrade
// 把 WebTransport extended CONNECT 请求升级为 Session。
//
// The handler must stay alive until the session ends: returning closes the
// CONNECT stream and with it the session. | 处理器必须阻塞到会话结束：返回即关闭
// CONNECT 流，会话随之结束。
func (s *Server) Upgrade(w http.ResponseWriter, r *http.Request) (*Session, error) {
	raw, err := s.wt.Upgrade(w, r)
	if err != nil {
		// Every rejection happens before the 200 response is written, so answering
		// here keeps a rejected peer from mistaking an empty 200 for a session. |
		// 所有拒绝都发生在写出 200 之前，因此在这里应答可以避免被拒的对端把空的 200
		// 误认为会话已建立。
		http.Error(w, "WebTransport session upgrade rejected | WebTransport 会话升级被拒绝", http.StatusBadRequest)
		return nil, errs.WrapDetail(err, ErrHandshake, "upgrade failed | 升级失败")
	}
	return s.wrap(raw), nil
}

// wrap builds the framework Session and registers it with the tracker. | wrap 构造框架
// Session 并登记到 Tracker。
func (s *Server) wrap(raw *wtgo.Session) *Session {
	sess := &Session{sess: raw, max: s.max}
	if s.tracker != nil {
		sess.setUntrack(s.tracker.Track(sess))
	}
	return sess
}

// Close terminates every tracked session and closes the embedded HTTP/3 server. |
// Close 终止全部已登记会话并关闭内嵌的 HTTP/3 服务器。
//
// It is idempotent. | 该方法是幂等的。
func (s *Server) Close() error {
	if s.tracker != nil {
		s.tracker.CloseAll(0, "server shutdown | 服务器关闭")
	}
	return s.wt.Close()
}
