package client

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// engine is the policy RoundTripper behind a Client. | engine 是 Client 背后的策略 RoundTripper。
type engine struct {
	base http.RoundTripper
	opts options
}

// newEngine builds the engine and a default transport when none was supplied. | newEngine 构建引擎，并在未提供 Transport 时创建默认传输。
func newEngine(o options) *engine {
	base := o.Transport
	if base == nil {
		base = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
	}
	return &engine{base: base, opts: o}
}

// RoundTrip forwards the request through the configured transport. | RoundTrip 通过配置的传输转发请求。
func (e *engine) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, ErrInvalidConfig
	}
	return e.base.RoundTrip(req)
}

// closeIdleConnections releases idle connections held by the base transport. | closeIdleConnections 释放底层传输持有的空闲连接。
func (e *engine) closeIdleConnections() {
	if closer, ok := e.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// cancelBody cancels a request-scoped context when the body is exhausted or closed. | cancelBody 在正文读完或关闭时取消请求级 context。
type cancelBody struct {
	body interface {
		Read([]byte) (int, error)
		Close() error
	}
	cancel context.CancelFunc
	once   sync.Once
}

// Read reads from the wrapped body and cancels on EOF or error. | Read 从包装的正文读取，并在 EOF 或错误时取消。
func (b *cancelBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil {
		b.stop()
	}
	return n, err
}

// Close closes the wrapped body and cancels the request context. | Close 关闭包装的正文并取消请求 context。
func (b *cancelBody) Close() error {
	b.stop()
	return b.body.Close()
}

// stop cancels the context exactly once. | stop 只取消一次 context。
func (b *cancelBody) stop() {
	b.once.Do(b.cancel)
}
