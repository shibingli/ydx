package client

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/shibingli/ydx/errs"
)

// requestConfig accumulates per-request options. | requestConfig 累加逐请求选项。
type requestConfig struct {
	timeout time.Duration
	headers http.Header
	query   url.Values
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
		if c.headers == nil {
			c.headers = make(http.Header, 4)
		}
		c.headers.Add(key, value)
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
	cfg := requestConfig{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	rc, getBody, contentType, err := prepareBody(body)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolved, err := c.resolveRequestURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, resolved, rc)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	if getBody != nil {
		req.GetBody = getBody
	}
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}
	for key, values := range cfg.headers {
		if http.CanonicalHeaderKey(key) == "Host" {
			if len(values) > 0 {
				req.Host = values[0]
			}
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
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
		return c.finish(req)
	}
	deadlineCtx, cancel := context.WithTimeout(req.Context(), cfg.timeout)
	resp, err := c.Do(req.WithContext(deadlineCtx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{body: resp.Body, cancel: cancel}
	return &Response{Response: resp}, nil
}

// resolveRequestURL resolves a convenience-method URL against BaseURL. | resolveRequestURL 用 BaseURL 解析便捷方法的 URL。
func (c *Client) resolveRequestURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errs.Wrap(err, ErrInvalidRequest)
	}
	if parsed.IsAbs() {
		return raw, nil
	}
	if c.opts.BaseURL == nil {
		return "", ErrRelativeURL
	}
	return c.opts.BaseURL.ResolveReference(parsed).String(), nil
}

// finish executes a request and wraps the response. | finish 执行请求并包装响应。
func (c *Client) finish(req *http.Request) (*Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	return &Response{Response: resp}, nil
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
