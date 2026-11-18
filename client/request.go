package client

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// headerPair is one request header without a map allocation. | headerPair 是一个无需 map 分配的请求头。
type headerPair struct {
	key   string
	value string
}

// requestConfig accumulates per-request options. | requestConfig 累加逐请求选项。
type requestConfig struct {
	query   url.Values
	headers []headerPair
	timeout time.Duration
}

// RequestOption mutates one request's configuration. | RequestOption 修改单个请求的配置。
type RequestOption func(*requestConfig) error

// WithRequestTimeout bounds one request including its response body. | WithRequestTimeout 限制单个请求（含响应正文）的总时长。
func WithRequestTimeout(d time.Duration) RequestOption {
	return func(c *requestConfig) error {
		if d < 0 {
			return errs.Detail(ErrInvalidConfig, "negative request timeout | 请求超时为负")
		}
		c.timeout = d
		return nil
	}
}

// WithRequestHeader adds one request header. | WithRequestHeader 添加一个请求头。
func WithRequestHeader(key, value string) RequestOption {
	return func(c *requestConfig) error {
		if key == "" {
			return errs.Detail(ErrInvalidConfig, "empty request header name | 空请求头名")
		}
		c.headers = append(c.headers, headerPair{key: key, value: value})
		return nil
	}
}

// WithRequestQuery adds one query parameter. | WithRequestQuery 添加一个查询参数。
func WithRequestQuery(key, value string) RequestOption {
	return func(c *requestConfig) error {
		if c.query == nil {
			c.query = make(url.Values, 4)
		}
		c.query.Add(key, value)
		return nil
	}
}

// Send builds and executes one request. | Send 构建并执行单个请求。
func (c *Client) Send(ctx context.Context, method, rawURL string, body any, opts ...RequestOption) (*Response, error) {
	if c == nil || c.engine == nil {
		return nil, ErrInvalidConfig
	}
	if len(opts) == 0 {
		return c.send(ctx, method, rawURL, body, requestConfig{})
	}
	cfg := requestConfig{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	return c.send(ctx, method, rawURL, body, cfg)
}

// send executes one request with an already-resolved option set. | send 使用已解析选项执行单个请求。
func (c *Client) send(ctx context.Context, method, rawURL string, body any, cfg requestConfig) (*Response, error) {
	rc, getBody, contentType, length, err := prepareBodyInfo(body)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	relative := !strings.Contains(rawURL, "://")
	state := &responseState{Context: ctx, useDefaultHosts: relative}
	state.response.Meta.Hops = state.response.Meta.hopInline[:0]
	if strings.Contains(rawURL, "://") && !strings.ContainsAny(rawURL, "?#@%") {
		state.response.Meta.urlHint = rawURL
	}
	ctx = state
	target := rawURL
	if !strings.Contains(rawURL, "://") {
		resolved, err := c.resolveRequestURL(rawURL)
		if err != nil {
			if rc != nil {
				_ = rc.Close()
			}
			return nil, err
		}
		target = resolved
	}
	if state.response.Meta.urlHint == "" && strings.Contains(target, "://") && !strings.ContainsAny(target, "?#@%") {
		state.response.Meta.urlHint = target
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rc)
	if err != nil {
		if rc != nil {
			_ = rc.Close()
		}
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	if relative {
		state.defaultHost = req.URL.Host
	}
	if rc != nil && length >= 0 {
		if length == 0 {
			_ = rc.Close()
			req.Body = http.NoBody
			req.ContentLength = 0
		} else {
			req.ContentLength = length
		}
	}
	if getBody != nil {
		req.GetBody = getBody
	}
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, header := range cfg.headers {
		if http.CanonicalHeaderKey(header.key) == "Host" {
			req.Host = header.value
			state.explicitHost = true
			continue
		}
		if http.CanonicalHeaderKey(header.key) == "Content-Type" {
			req.Header.Set(header.key, header.value)
			continue
		}
		req.Header.Add(header.key, header.value)
	}
	if len(cfg.query) > 0 {
		query := req.URL.Query()
		for key, values := range cfg.query {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		req.URL.RawQuery = query.Encode()
	}
	if cfg.timeout <= 0 {
		return c.finishState(req, state)
	}
	deadlineCtx, cancel := context.WithTimeout(req.Context(), cfg.timeout)
	resp, err := c.Do(req.WithContext(deadlineCtx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{body: resp.Body, cancel: cancel}
	c.engine.fireComplete(req.Context(), &state.response.Meta)
	state.response.Response = resp
	return &state.response, nil
}

// DoWithMeta executes req and returns the client metadata alongside the response. | DoWithMeta 执行 req 并返回客户端元数据。
func (c *Client) DoWithMeta(req *http.Request) (*Response, error) {
	if req == nil || req.URL == nil {
		return nil, ErrInvalidRequest
	}
	state := &responseState{Context: req.Context()}
	state.response.Meta.Hops = state.response.Meta.hopInline[:0]
	req = req.WithContext(state)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	c.engine.fireComplete(req.Context(), &state.response.Meta)
	state.response.Response = resp
	return &state.response, nil
}

// resolveRequestURL resolves a convenience-method URL against BaseURL or the
// first default host. | resolveRequestURL 用 BaseURL 或第一个默认 Host 解析便捷方法的 URL。
func (c *Client) resolveRequestURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidRequest)
	}
	if parsed.IsAbs() {
		return raw, nil
	}
	base := c.opts.BaseURL
	if base == nil {
		if hs := c.engine.hosts.Load(); hs != nil {
			base = hs.firstBaseURL()
		}
	}
	if base == nil {
		return "", ErrRelativeURL
	}
	return base.ResolveReference(parsed).String(), nil
}

// explicitHostKey marks a request whose Host header was explicitly set. | explicitHostKey 标记显式设置 Host 头的请求。
type explicitHostKey struct{}

// explicitHostFrom reports whether the caller explicitly set the Host header. | explicitHostFrom 报告调用方是否显式设置 Host 头。
func explicitHostFrom(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(explicitHostKey{}).(bool)
	return value
}

// defaultHostKey carries the host resolved from a relative convenience URL. | defaultHostKey 携带相对便捷 URL 解析出的 Host。
type defaultHostKey struct{}

// defaultHostFrom returns the expected default host for a relative send. | defaultHostFrom 返回相对请求预期的默认 Host。
func defaultHostFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	host, _ := ctx.Value(defaultHostKey{}).(string)
	return host
}

// finish executes a request and wraps the response with meta. | finish 执行请求并用 meta 包装响应。
// responseState combines Meta and Response in one allocation. | responseState 用一次分配组合 Meta 与 Response。
type responseState struct {
	context.Context
	response        Response
	defaultHost     string
	useDefaultHosts bool
	explicitHost    bool
}

// Value supplies the per-request Meta in its final response location. | Value 在最终响应位置提供逐请求 Meta。
func (s *responseState) Value(key any) any {
	switch key.(type) {
	case metaKey:
		return &s.response.Meta
	case useDefaultHostsKey:
		return s.useDefaultHosts
	case defaultHostKey:
		return s.defaultHost
	case explicitHostKey:
		return s.explicitHost
	}
	return s.Context.Value(key)
}

// finishState executes a request and fills the combined response state. | finishState 执行请求并填充组合响应状态。
func (c *Client) finishState(req *http.Request, state *responseState) (*Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	c.engine.fireComplete(req.Context(), &state.response.Meta)
	state.response.Response = resp
	return &state.response, nil
}

// Get issues a GET request. | Get 发起 GET 请求。
func (c *Client) Get(ctx context.Context, rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodGet, rawURL, nil, opts...)
}

// Head issues a HEAD request. | Head 发起 HEAD 请求。
func (c *Client) Head(ctx context.Context, rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodHead, rawURL, nil, opts...)
}

// Post issues a POST request. | Post 发起 POST 请求。
func (c *Client) Post(ctx context.Context, rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodPost, rawURL, body, opts...)
}

// Put issues a PUT request. | Put 发起 PUT 请求。
func (c *Client) Put(ctx context.Context, rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodPut, rawURL, body, opts...)
}

// Patch issues a PATCH request. | Patch 发起 PATCH 请求。
func (c *Client) Patch(ctx context.Context, rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodPatch, rawURL, body, opts...)
}

// Delete issues a DELETE request. | Delete 发起 DELETE 请求。
func (c *Client) Delete(ctx context.Context, rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodDelete, rawURL, body, opts...)
}

// Options issues an OPTIONS request. | Options 发起 OPTIONS 请求。
func (c *Client) Options(ctx context.Context, rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodOptions, rawURL, nil, opts...)
}

// Trace issues a TRACE request. | Trace 发起 TRACE 请求。
func (c *Client) Trace(ctx context.Context, rawURL string, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodTrace, rawURL, nil, opts...)
}

// Connect issues a CONNECT request; a 2xx response body is the tunnel stream. | Connect 发起 CONNECT 请求；2xx 响应正文即隧道流。
func (c *Client) Connect(ctx context.Context, rawURL string, body any, opts ...RequestOption) (*Response, error) {
	return c.Send(ctx, http.MethodConnect, rawURL, body, opts...)
}
