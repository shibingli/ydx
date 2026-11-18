package client

import (
	"context"
	"net/http"
	"sync/atomic"
)

// Client is a policy-driven HTTP client compatible with http.Client.Do. | Client 是兼容 http.Client.Do 的策略化 HTTP 客户端。
type Client struct {
	hc     *http.Client
	engine *engine
	opts   options
	closed atomic.Bool
}

// New creates a Client from functional options. | New 根据函数式选项创建 Client。
func New(opts ...Option) (*Client, error) {
	cfg := defaultOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	rules, err := CompileRules(cfg.Rules...)
	if err != nil {
		return nil, err
	}
	eng := newEngine(cfg)
	eng.rules.Store(rules)
	hc := &http.Client{
		Transport:     eng,
		Jar:           cfg.Jar,
		CheckRedirect: cfg.CheckRedirect,
	}
	return &Client{hc: hc, engine: eng, opts: cfg}, nil
}

// Do sends req and returns the response, following standard http.Client semantics. | Do 发送 req 并返回响应，遵循标准 http.Client 语义。
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c == nil || c.closed.Load() {
		return nil, ErrClosed
	}
	if req == nil || req.URL == nil {
		return nil, ErrInvalidConfig
	}
	if !req.URL.IsAbs() {
		return nil, ErrRelativeURL
	}
	if c.opts.Timeout <= 0 {
		return c.hc.Do(req)
	}
	ctx, cancel := context.WithTimeout(req.Context(), c.opts.Timeout)
	resp, err := c.hc.Do(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{body: resp.Body, cancel: cancel}
	return resp, nil
}

// HTTPClient exposes the embedded standard client for interoperability. | HTTPClient 暴露内嵌的标准客户端以便互操作。
func (c *Client) HTTPClient() *http.Client {
	if c == nil {
		return nil
	}
	return c.hc
}

// Transport returns the policy RoundTripper, suitable for a standard http.Client. | Transport 返回策略 RoundTripper，可交给标准 http.Client。
func (c *Client) Transport() http.RoundTripper {
	if c == nil {
		return nil
	}
	return c.engine
}

// Close releases idle connections and rejects new requests. | Close 释放空闲连接并拒绝新请求。
func (c *Client) Close() error {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.engine.closeIdleConnections()
	return nil
}
