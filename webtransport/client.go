package webtransport

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"

	"github.com/quic-go/quic-go"
	wtgo "github.com/quic-go/webtransport-go"

	"github.com/shibingli/ydx/errs"
)

// DialOptions configures Dial. | DialOptions 配置 Dial。
type DialOptions struct {
	// TLSClientConfig is the TLS configuration of the QUIC client; it must carry
	// the "h3" ALPN, which Dial adds when absent. | TLSClientConfig 是 QUIC 客户端的
	// TLS 配置；必须带 "h3" ALPN，缺失时由 Dial 补齐。
	TLSClientConfig *tls.Config
	// ApplicationProtocols lists the application protocols offered to the server. |
	// ApplicationProtocols 列出向服务端提议的应用协议。
	ApplicationProtocols []string
	// Header carries additional request headers of the CONNECT request. | Header
	// 携带 CONNECT 请求的额外头部。
	Header http.Header
	// QUICConfig is the QUIC configuration; nil takes the library defaults. |
	// QUICConfig 是 QUIC 配置；nil 取库默认值。
	QUICConfig *quic.Config
	// MaxMessageSize bounds one framed message; values <= 0 take
	// DefaultMaxMessageSize. | MaxMessageSize 限制单条消息；<=0 时取
	// DefaultMaxMessageSize。
	MaxMessageSize int
}

// Dial establishes one WebTransport session. | Dial 建立一个 WebTransport 会话。
//
// The URL must use https; a session owns its QUIC connection and closing it
// closes that connection. | URL 必须使用 https；会话拥有自己的 QUIC 连接，关闭会话
// 即关闭该连接。
func Dial(ctx context.Context, rawURL string, o DialOptions) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrScheme, "url %q | 地址 %q", rawURL, rawURL)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, errs.Detail(ErrScheme, "scheme %q | 协议 %q", u.Scheme, u.Scheme)
	}

	clientTLS := o.TLSClientConfig
	if clientTLS == nil {
		clientTLS = &tls.Config{}
	} else {
		clientTLS = clientTLS.Clone()
	}
	if len(clientTLS.NextProtos) == 0 {
		clientTLS.NextProtos = []string{"h3"}
	}

	transport := &wtgo.Transport{
		TLSClientConfig:      clientTLS,
		ApplicationProtocols: o.ApplicationProtocols,
		QUICConfig:           o.QUICConfig,
	}
	_, raw, err := transport.Dial(ctx, rawURL, o.Header)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrHandshake, "dial %q | 拨号 %q", rawURL, rawURL)
	}
	max := o.MaxMessageSize
	if max <= 0 {
		max = DefaultMaxMessageSize
	}
	return &Session{sess: raw, max: max}, nil
}
