package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/shibingli/ydx/buffpool"
	"github.com/shibingli/ydx/errs"
)

// forwardNoRetryKey marks a forwarded request that keeps its body streaming. | forwardNoRetryKey 标记保持正文流式的转发请求。
type forwardNoRetryKey struct{}

// forwardPreserveHostKey carries the PreserveHost decision into the engine. | forwardPreserveHostKey 把 PreserveHost 决策传入引擎。
type forwardPreserveHostKey struct{}

// forwardNoDefaultRetry reports whether the default retry policy must be disabled. | forwardNoDefaultRetry 报告是否必须禁用默认重试。
func forwardNoDefaultRetry(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(forwardNoRetryKey{}).(bool)
	return value
}

// forwardPreserveHost reports whether the forwarded Host header is kept. | forwardPreserveHost 报告转发请求是否保留 Host 头。
func forwardPreserveHost(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(forwardPreserveHostKey{}).(bool)
	return value
}

// defaultForwardOptions returns the reverse-proxy defaults. | defaultForwardOptions 返回反向代理默认值。
func defaultForwardOptions() ForwardOptions {
	return ForwardOptions{
		PreserveHost:    true,
		AddForwardedFor: true,
		MaxBodyBytes:    8 << 20,
	}
}

// buildForwardOptions applies functional options. | buildForwardOptions 应用函数式选项。
func buildForwardOptions(opts ...ForwardOption) (ForwardOptions, error) {
	cfg := defaultForwardOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return ForwardOptions{}, err
		}
	}
	return cfg, nil
}

// WithForwardAddForwardedFor toggles X-Forwarded-* headers. | WithForwardAddForwardedFor 开关 X-Forwarded-* 头。
func WithForwardAddForwardedFor(ok bool) ForwardOption {
	return func(o *ForwardOptions) error {
		o.AddForwardedFor = ok
		return nil
	}
}

// WithForwardFlushInterval sets the normal-response flush interval. | WithForwardFlushInterval 设置普通响应刷新间隔。
func WithForwardFlushInterval(d time.Duration) ForwardOption {
	return func(o *ForwardOptions) error {
		o.FlushInterval = d
		return nil
	}
}

// WithForwardMaxBodyBytes caps buffered forwarding bodies. | WithForwardMaxBodyBytes 限制转发的缓冲正文。
func WithForwardMaxBodyBytes(n int64) ForwardOption {
	return func(o *ForwardOptions) error {
		if n <= 0 {
			return errs.Detail(ErrInvalidConfig, "max body bytes must be positive | 最大正文字节数必须为正")
		}
		o.MaxBodyBytes = n
		return nil
	}
}

// WithForwardStripHeaders removes extra inbound headers. | WithForwardStripHeaders 移除额外入站头。
func WithForwardStripHeaders(names ...string) ForwardOption {
	return func(o *ForwardOptions) error {
		o.StripHeaders = append(o.StripHeaders, names...)
		return nil
	}
}

// WithForwardBodyTimeout bounds a non-SSE upstream body copy. | WithForwardBodyTimeout 限制非 SSE 上游正文复制。
func WithForwardBodyTimeout(d time.Duration) ForwardOption {
	return func(o *ForwardOptions) error {
		o.BodyTimeout = d
		return nil
	}
}

// Forward forwards one inbound request and returns the upstream response. It does
// not follow redirects or apply the cookie jar. | Forward 转发一个入站请求并返回上游响应；不跟随
// 重定向，也不应用 Cookie 罐。
func (c *Client) Forward(ctx context.Context, r *http.Request, opts ...ForwardOption) (*http.Response, error) {
	cfg, err := buildForwardOptions(opts...)
	if err != nil {
		return nil, err
	}
	return c.forwardRequest(ctx, r, cfg)
}

// forwardRequest clones and sanitizes the inbound request before the engine. | forwardRequest 在进入引擎前克隆并净化入站请求。
func (c *Client) forwardRequest(ctx context.Context, r *http.Request, cfg ForwardOptions) (*http.Response, error) {
	if c == nil || c.closed.Load() {
		return nil, ErrClosed
	}
	if r == nil || r.URL == nil {
		return nil, ErrInvalidRequest
	}
	if r.Method == http.MethodConnect || r.Header.Get("Upgrade") != "" {
		return nil, ErrUpgradeUnsupported
	}
	if ctx == nil {
		ctx = context.Background()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	path := r.URL.Path
	rawPath := r.URL.RawPath
	query := r.URL.RawQuery
	if r.URL.IsAbs() {
		scheme = r.URL.Scheme
		host = r.URL.Host
	}
	if host == "" {
		return nil, errs.Detail(ErrNoHosts, "forward request has no target host | 转发请求没有目标 Host")
	}
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.URL = &url.URL{Scheme: scheme, Host: host, Path: path, RawPath: rawPath, RawQuery: query}
	out.Header = r.Header.Clone()
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	skip := hopByHopSet(out.Header)
	for key := range skip {
		out.Header.Del(key)
	}
	for _, name := range cfg.StripHeaders {
		out.Header.Del(name)
	}
	if cfg.PreserveHost {
		out.Host = r.Host
		if out.Host == "" {
			out.Host = host
		}
	} else {
		out.Host = ""
	}
	if cfg.AddForwardedFor {
		addForwardedHeaders(out, r, scheme)
	}
	out = out.WithContext(context.WithValue(out.Context(), forwardNoRetryKey{}, true))
	out = out.WithContext(context.WithValue(out.Context(), forwardPreserveHostKey{}, cfg.PreserveHost))
	return c.engine.RoundTrip(out)
}

// addForwardedHeaders appends X-Forwarded-For/Proto/Host. | addForwardedHeaders 追加 X-Forwarded-For/Proto/Host。
func addForwardedHeaders(out, in *http.Request, scheme string) {
	clientIP := in.RemoteAddr
	if host, _, err := net.SplitHostPort(in.RemoteAddr); err == nil {
		clientIP = host
	}
	if clientIP != "" {
		if prior := out.Header.Get("X-Forwarded-For"); prior != "" {
			out.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			out.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	if out.Header.Get("X-Forwarded-Proto") == "" {
		out.Header.Set("X-Forwarded-Proto", scheme)
	}
	if out.Header.Get("X-Forwarded-Host") == "" && in.Host != "" {
		out.Header.Set("X-Forwarded-Host", in.Host)
	}
}

// Handler returns a reverse-proxy http.Handler using the client engine. | Handler 返回使用客户端引擎的反向代理 http.Handler。
func (c *Client) Handler(opts ...ForwardOption) http.Handler {
	cfg, cfgErr := buildForwardOptions(opts...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfgErr != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		resp, err := c.forwardRequest(r.Context(), r, cfg)
		if err != nil {
			writeForwardError(w, err)
			return
		}
		c.writeForwardResponse(w, r, resp, cfg)
	})
}

// writeForwardResponse copies the upstream response to the downstream writer. | writeForwardResponse 把上游响应复制到下游。
func (c *Client) writeForwardResponse(w http.ResponseWriter, r *http.Request, resp *http.Response, cfg ForwardOptions) {
	if resp == nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	if isEventStream(resp.Header) {
		_ = c.copySSE(r.Context(), w, resp, r, cfg)
		return
	}
	defer resp.Body.Close()
	skip := hopByHopSet(resp.Header)
	header := w.Header()
	for key, values := range resp.Header {
		canonical := http.CanonicalHeaderKey(key)
		if skip[canonical] {
			continue
		}
		for _, value := range values {
			header.Add(key, value)
		}
	}
	for key := range resp.Trailer {
		header.Add("Trailer", key)
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body == nil {
		return
	}
	var timer *time.Timer
	if cfg.BodyTimeout > 0 {
		timer = time.AfterFunc(cfg.BodyTimeout, func() { _ = resp.Body.Close() })
		defer timer.Stop()
	}
	var dst io.Writer = w
	if cfg.FlushInterval > 0 {
		dst = &forwardFlushWriter{writer: w, interval: cfg.FlushInterval, last: time.Now()}
	}
	buffer := buffpool.Get(32 << 10)
	buffer = buffer[:cap(buffer)]
	defer buffpool.Put(buffer)
	_, _ = io.CopyBuffer(dst, resp.Body, buffer)
	for key, values := range resp.Trailer {
		header[key] = values
	}
}

// forwardFlushWriter flushes at most once per interval. | forwardFlushWriter 每个间隔至多刷新一次。
type forwardFlushWriter struct {
	writer   http.ResponseWriter
	interval time.Duration
	last     time.Time
}

// Write writes and periodically flushes. | Write 写入并周期性刷新。
func (f *forwardFlushWriter) Write(p []byte) (int, error) {
	n, err := f.writer.Write(p)
	if err == nil && time.Since(f.last) >= f.interval {
		_ = flushResponseWriter(f.writer)
		f.last = time.Now()
	}
	return n, err
}

// writeForwardError maps engine errors to downstream status codes. | writeForwardError 把引擎错误映射为下游状态码。
func writeForwardError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case errors.Is(err, ErrBlocked):
		status = http.StatusForbidden
	case errors.Is(err, ErrClosed):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ErrUpgradeUnsupported):
		status = http.StatusNotImplemented
	}
	http.Error(w, http.StatusText(status), status)
}
