package client

import (
	"context"
	"net/http"

	"github.com/shibingli/ydx/errs"
)

// ConnMode selects short or long connection behavior. | ConnMode 选择短连接或长连接行为。
type ConnMode string

const (
	// ConnAuto uses the default long-lived transport. | ConnAuto 使用默认长连接传输。
	ConnAuto ConnMode = "auto"
	// ConnLong keeps connections alive and pooled. | ConnLong 保持连接存活并复用。
	ConnLong ConnMode = "long"
	// ConnShort sends Connection: close and does not reuse the connection. | ConnShort 发送 Connection: close 且不复用连接。
	ConnShort ConnMode = "short"
)

// connModeKey carries the resolved connection mode to cloneAttempt. | connModeKey 把解析后的连接模式传给 cloneAttempt。
type connModeKey struct{}

// WithConnectionMode sets the default connection mode. | WithConnectionMode 设置默认连接模式。
func WithConnectionMode(mode ConnMode) Option {
	return func(o *options) error {
		if !validConnMode(mode) {
			return errs.Detail(ErrInvalidConfig, "unknown connection mode %q | 未知连接模式 %q", mode, mode)
		}
		o.ConnMode = mode
		return nil
	}
}

// WithH2C enables cleartext HTTP/2 for http:// URLs. It disables HTTP/1.1 cleartext. | WithH2C 为 http:// URL 启用明文 HTTP/2，并禁用明文 HTTP/1.1。
func WithH2C(enabled bool) Option {
	return func(o *options) error {
		o.H2C = enabled
		return nil
	}
}

// validConnMode reports whether mode is supported. | validConnMode 报告模式是否受支持。
func validConnMode(mode ConnMode) bool {
	switch mode {
	case "", ConnAuto, ConnLong, ConnShort:
		return true
	default:
		return false
	}
}

// connModeFrom returns the connection mode stored in ctx. | connModeFrom 返回 ctx 中存储的连接模式。
func connModeFrom(ctx context.Context) ConnMode {
	if ctx == nil {
		return ConnLong
	}
	mode, _ := ctx.Value(connModeKey{}).(ConnMode)
	if mode == "" {
		return ConnLong
	}
	return mode
}

// connectionMode resolves the rule or client connection mode. | connectionMode 解析规则或客户端连接模式。
func (e *engine) connectionMode(rule *Rule) ConnMode {
	if rule != nil && rule.Connection != "" {
		return rule.Connection
	}
	if e.opts.ConnMode != "" {
		return e.opts.ConnMode
	}
	return ConnLong
}

// Warmup opens n connections per default host with HEAD requests. | Warmup 用 HEAD 请求为每个默认 Host 预热 n 个连接。
func (c *Client) Warmup(ctx context.Context, n int) error {
	if c == nil || c.closed.Load() {
		return ErrClosed
	}
	if n <= 0 {
		return nil
	}
	hosts := c.engine.hosts.Load()
	if hosts == nil || hosts.Len() == 0 {
		return ErrNoHosts
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, entry := range hosts.entries {
		target := *entry.host.URL
		if target.Path == "" {
			target.Path = "/"
		}
		transport, err := c.engine.transportFor(entry.host)
		if err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
			if err != nil {
				return err
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				return err
			}
			drainAndClose(resp.Body, 64<<10)
		}
	}
	return nil
}
