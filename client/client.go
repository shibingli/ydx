package client

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Client is a policy-driven HTTP client compatible with http.Client.Do. | Client 是兼容 http.Client.Do 的策略化 HTTP 客户端。
type Client struct {
	rootCtx    context.Context
	hc         *http.Client
	engine     *engine
	rootCancel context.CancelFunc
	asyncSem   chan struct{}
	opts       options
	asyncWG    sync.WaitGroup
	asyncMu    sync.Mutex
	closed     atomic.Bool
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
	eng, err := newEngine(cfg)
	if err != nil {
		return nil, err
	}
	ua, err := prepareUA(cfg.UserAgent)
	if err != nil {
		return nil, err
	}
	eng.ua = ua
	eng.hooks = cfg.Hooks
	eng.rules.Store(rules)
	eng.registerRuleHosts(rules)
	hs := cfg.HostSet
	if hs == nil && len(cfg.Hosts) > 0 {
		hs, err = NewHostSet(cfg.Hosts...)
		if err != nil {
			return nil, err
		}
	}
	if hs != nil {
		eng.hosts.Store(hs)
		hs.startHealth(context.Background(), eng.healthTransport, cfg.Logger)
	}
	eng.bare.Store(isBareEngine(cfg, rules, hs))
	if cfg.Jar == nil && !cfg.DisableCookieJar {
		cfg.Jar = newLazyJar()
	}
	hc := &http.Client{
		Transport:     eng,
		Jar:           cfg.Jar,
		CheckRedirect: cfg.CheckRedirect,
	}
	rootCtx, rootCancel := context.WithCancel(context.Background())
	maxAsync := cfg.MaxAsync
	if maxAsync <= 0 {
		maxAsync = 1024
	}
	return &Client{
		hc:         hc,
		engine:     eng,
		opts:       cfg,
		rootCtx:    rootCtx,
		rootCancel: rootCancel,
		asyncSem:   make(chan struct{}, maxAsync),
	}, nil
}

// Do sends req and returns the response, following standard http.Client semantics. | Do 发送 req 并返回响应，遵循标准 http.Client 语义。
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c == nil || c.engine == nil || c.hc == nil {
		return nil, ErrInvalidConfig
	}
	if c.closed.Load() {
		return nil, ErrClosed
	}
	if req == nil || req.URL == nil {
		return nil, ErrInvalidConfig
	}
	if !req.URL.IsAbs() {
		return nil, ErrRelativeURL
	}
	if req.Header == nil {
		req = req.Clone(req.Context())
		req.Header = make(http.Header)
	}
	if c.opts.Timeout <= 0 {
		return c.hc.Do(req)
	}
	ctx, cancel := context.WithTimeout(req.Context(), c.opts.Timeout)
	resp, err := c.hc.Do(req.WithContext(ctx))
	if err != nil {
		cancel()
		if resp != nil {
			return resp, err
		}
		return nil, err
	}
	resp.Body = &cancelBody{body: resp.Body, cancel: cancel}
	return resp, nil
}

// HTTPClient exposes the embedded standard client for interoperability. | HTTPClient 暴露内嵌的标准客户端以便互操作。
func (c *Client) HTTPClient() *http.Client {
	if c == nil || c.hc == nil {
		return nil
	}
	return c.hc
}

// Transport returns the policy RoundTripper, suitable for a standard http.Client. | Transport 返回策略 RoundTripper，可交给标准 http.Client。
func (c *Client) Transport() http.RoundTripper {
	if c == nil || c.engine == nil {
		return nil
	}
	return c.engine
}

// Close releases resources and waits up to five seconds for async requests. | Close 释放资源并最多等待异步请求五秒。
func (c *Client) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CloseContext(ctx)
}

// CloseContext releases resources and waits for async requests within ctx. | CloseContext 释放资源并在 ctx 内等待异步请求。
func (c *Client) CloseContext(ctx context.Context) error {
	if c == nil || c.engine == nil || !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.rootCancel()
	c.engine.closed.Store(true)
	c.asyncMu.Lock()
	c.asyncMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if hs := c.engine.hosts.Load(); hs != nil {
		_ = hs.CloseContext(ctx)
	}
	_ = c.engine.mirrors.CloseContext(ctx)
	c.engine.closeRuleHosts(ctx)
	c.engine.closeTLSIdle()
	c.engine.cacheMu.Lock()
	store := c.engine.cacheStore
	owned := c.engine.ownsCache
	c.engine.cacheStore = nil
	c.engine.cacheMu.Unlock()
	if store != nil && owned {
		_ = store.Close()
	}
	c.engine.closeIdleConnections()
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		c.asyncWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
