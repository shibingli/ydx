package client

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// StreamOptions configures an outbound SSE stream. | StreamOptions 配置出站 SSE 流。
type StreamOptions struct {
	// MaxReconnects is the reconnect attempt count; <=0 disables reconnects. | MaxReconnects 是重连次数；<=0 禁用重连。
	MaxReconnects int
	// Backoff is the default reconnect delay; <=0 means 1s. | Backoff 是默认重连延迟；<=0 表示 1s。
	Backoff time.Duration
	// IdleTimeout bounds the wait for one event; <=0 disables it. | IdleTimeout 限制单个事件的等待；<=0 禁用。
	IdleTimeout time.Duration
}

// StreamOption mutates StreamOptions. | StreamOption 修改 StreamOptions。
type StreamOption func(*StreamOptions)

// WithStreamReconnect enables reconnect with a maximum and backoff. | WithStreamReconnect 启用重连并设置上限与退避。
func WithStreamReconnect(max int, backoff time.Duration) StreamOption {
	return func(o *StreamOptions) {
		o.MaxReconnects = max
		if backoff > 0 {
			o.Backoff = backoff
		}
	}
}

// WithStreamIdleTimeout bounds the wait for one event. | WithStreamIdleTimeout 限制单个事件的等待。
func WithStreamIdleTimeout(d time.Duration) StreamOption {
	return func(o *StreamOptions) {
		if d > 0 {
			o.IdleTimeout = d
		}
	}
}

// streamRequestKey marks a request whose body must outlive rule timeouts. | streamRequestKey 标记正文不应受规则超时影响的请求。
type streamRequestKey struct{}

// streamingRequest reports whether the request is an SSE stream. | streamingRequest 报告请求是否为 SSE 流。
func streamingRequest(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(streamRequestKey{}).(bool)
	return value
}

// Stream is an outbound SSE stream with optional reconnects. | Stream 是带可选重连的出站 SSE 流。
type Stream struct {
	body     io.ReadCloser
	client   *Client
	template *http.Request
	reader   *EventReader
	meta     *Meta

	lastID string
	opts   StreamOptions

	retryHint  time.Duration
	retrySet   bool
	reconnects int

	mu sync.Mutex

	closed  atomic.Bool
	rawMode bool
}

// OpenStream opens an SSE request through the client engine. Up to ten
// redirects are followed, honoring CheckRedirect and stripping sensitive
// headers across hosts; a final 3xx without a usable Location reports
// ErrSSEProtocol. | OpenStream 通过客户端引擎打开 SSE 请求。最多跟随十次
// 重定向，遵循 CheckRedirect，并在跨主机时剥离敏感头；最终 3xx 无可用的
// Location 时返回 ErrSSEProtocol。
func (c *Client) OpenStream(ctx context.Context, req *http.Request, opts ...StreamOption) (*Stream, error) {
	if c == nil || c.engine == nil {
		closeRequestBody(req)
		return nil, ErrInvalidConfig
	}
	if c.closed.Load() {
		closeRequestBody(req)
		return nil, ErrClosed
	}
	if req == nil || req.URL == nil {
		closeRequestBody(req)
		return nil, ErrInvalidRequest
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolved, err := c.resolveRequestURL(req.URL.String())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	parsed, err := url.Parse(resolved)
	if err != nil {
		closeRequestBody(req)
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	template := req.Clone(ctx)
	raw := req.URL.String()
	if !rawURLHasScheme(raw) && !strings.HasPrefix(raw, "//") {
		template = template.WithContext(context.WithValue(template.Context(), useDefaultHostsKey{}, true))
	}
	template.URL = parsed
	if template.Header == nil {
		template.Header = make(http.Header)
	}
	if template.Header.Get("Accept") == "" {
		template.Header.Set("Accept", "text/event-stream")
	}
	if template.Header.Get("Cache-Control") == "" {
		template.Header.Set("Cache-Control", "no-cache")
	}
	if template.Header.Get("Accept-Encoding") == "" {
		template.Header.Set("Accept-Encoding", "identity")
	}
	cfg := StreamOptions{Backoff: time.Second}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	stream := &Stream{client: c, template: template, opts: cfg}
	if err := stream.open(ctx); err != nil {
		return nil, err
	}
	c.engine.counters.sseSessions.Add(1)
	if c.engine.hooks.OnStreamStart != nil {
		_ = callHook(func() error {
			c.engine.hooks.OnStreamStart(ctx, req)
			return nil
		})
	}
	return stream, nil
}

// maxStreamRedirects bounds redirect following for an SSE stream. | maxStreamRedirects
// 限制 SSE 流跟随重定向的次数。
const maxStreamRedirects = 10

// isStreamRedirect reports whether status is a redirect status. | isStreamRedirect
// 报告 status 是否为重定向状态码。
func isStreamRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// open issues one SSE request and validates the response. | open 发起一次 SSE 请求并校验响应。
func (s *Stream) open(ctx context.Context) error {
	meta := &Meta{}
	var jar http.CookieJar
	if s.client.hc != nil {
		jar = s.client.hc.Jar
	}
	template := s.template.Clone(ctx)
	via := make([]*http.Request, 0, 4)
	suppressInjected := false
	for redirects := 0; ; redirects++ {
		req := template.Clone(ctx)
		if (redirects > 0 || s.reconnects > 0) && req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				return ErrBodyNotReplayable
			}
			body, err := req.GetBody()
			if err != nil {
				return errs.Wrap(err, ErrBodyNotReplayable)
			}
			req.Body = body
			req.ContentLength = template.ContentLength
		}
		if s.lastID != "" && !suppressInjected {
			// Never re-add the resume id after a cross-origin hop stripped it. |
			// 跨源跳转移除 Last-Event-ID 后不得再次注入。
			req.Header.Set("Last-Event-ID", s.lastID)
		}
		req = req.WithContext(context.WithValue(req.Context(), streamRequestKey{}, true))
		req = req.WithContext(context.WithValue(req.Context(), metaKey{}, meta))
		if suppressInjected {
			req = req.WithContext(context.WithValue(req.Context(), suppressInjectedKey{}, true))
		}
		if jar != nil {
			for _, cookie := range jar.Cookies(req.URL) {
				req.AddCookie(cookie)
			}
		}
		resp, err := s.client.engine.RoundTrip(req)
		if err != nil {
			return err
		}
		if jar != nil {
			jar.SetCookies(req.URL, resp.Cookies())
		}
		if s.closed.Load() {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			return ErrClosed
		}
		if isStreamRedirect(resp.StatusCode) {
			if redirects >= maxStreamRedirects {
				drainAndClose(resp.Body, 64<<10)
				return &Error{
					Op:       "open_stream",
					Method:   req.Method,
					URL:      safeURL(req.URL),
					Attempts: 1,
					Err:      errs.Detail(ErrSSEProtocol, "too many redirects | 重定向次数过多"),
				}
			}
			location, locationErr := resp.Location()
			if locationErr != nil || location == nil {
				drainAndClose(resp.Body, 64<<10)
				return &Error{
					Op:       "open_stream",
					Method:   req.Method,
					URL:      safeURL(req.URL),
					Attempts: 1,
					Err:      errs.Detail(ErrSSEProtocol, "redirect without Location | 重定向缺少 Location"),
				}
			}
			if location.Scheme != "http" && location.Scheme != "https" {
				drainAndClose(resp.Body, 64<<10)
				return errs.Detail(ErrSSEProtocol, "redirect scheme %q | 重定向 scheme %q", location.Scheme, location.Scheme)
			}
			if !sameOrigin(req.URL, location) {
				// A cross-origin stream hop must not carry rule-injected credentials. Remove
				// the standard sensitive set and suppress all rule and host header injection for
				// the rest of this redirect chain. | 跨源流跳不得携带规则注入的凭据。移除标准敏感
				// 头集合，并在本次重定向链的后续请求中禁止全部规则与 Host 头注入。
				for _, name := range []string{
					"Authorization", "Cookie", "Cookie2", "Proxy-Authorization", "Last-Event-ID",
				} {
					template.Header.Del(name)
				}
				suppressInjected = true
			}
			switch {
			case resp.StatusCode == http.StatusSeeOther,
				(resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) &&
					template.Method != http.MethodGet && template.Method != http.MethodHead:
				template.Method = http.MethodGet
				template.Body = nil
				template.GetBody = nil
				template.ContentLength = 0
				template.Header.Del("Content-Type")
			case resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect:
				if template.Body != nil && template.Body != http.NoBody && template.GetBody == nil {
					drainAndClose(resp.Body, 64<<10)
					return ErrBodyNotReplayable
				}
			}
			template.URL = location
			template.Host = ""
			next := template.Clone(ctx)
			next.Response = resp
			via = append(via, req)
			if s.client.opts.CheckRedirect != nil {
				if err := safeCheckRedirect(s.client.opts.CheckRedirect)(next, via); err != nil {
					drainAndClose(resp.Body, 64<<10)
					return err
				}
			}
			drainAndClose(resp.Body, 64<<10)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			drainAndClose(resp.Body, 64<<10)
			return &Error{
				Op:       "open_stream",
				Method:   req.Method,
				URL:      safeURL(req.URL),
				Attempts: 1,
				Err:      errs.Detail(ErrSSEProtocol, "status %d", resp.StatusCode),
			}
		}
		if !isEventStream(resp.Header) {
			_ = resp.Body.Close()
			return errs.Detail(ErrSSEProtocol, "content type %q", resp.Header.Get("Content-Type"))
		}
		s.mu.Lock()
		if s.closed.Load() {
			s.mu.Unlock()
			_ = resp.Body.Close()
			return ErrClosed
		}
		s.template = template
		s.body = resp.Body
		s.reader = nil
		s.meta = meta
		s.mu.Unlock()
		return nil
	}
}

// Next returns the next event, reconnecting when configured. | Next 返回下一个事件，并在配置时重连。
func (s *Stream) Next(ctx context.Context) (Event, error) {
	if s == nil {
		return Event{}, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if s.closed.Load() {
			s.closeBody()
			return Event{}, ErrClosed
		}
		s.mu.Lock()
		raw := s.rawMode
		reader := s.reader
		body := s.body
		if !raw && reader == nil && body != nil {
			reader = NewEventReader(body)
			s.reader = reader
		}
		s.mu.Unlock()
		if raw {
			return Event{}, ErrStreamMode
		}
		if reader == nil || body == nil {
			return Event{}, ErrSSEProtocol
		}
		event, err := s.readEvent(ctx, reader, body)
		if err == nil {
			if event.IDSet {
				s.lastID = event.ID
			}
			if event.RetrySet {
				s.retryHint = event.Retry
				s.retrySet = true
			}
			s.client.engine.counters.sseEvents.Add(1)
			if s.client.engine.hooks.OnStreamEvent != nil {
				_ = callHook(func() error {
					s.client.engine.hooks.OnStreamEvent(ctx, event)
					return nil
				})
			}
			return event, nil
		}
		if ctx.Err() != nil {
			s.closeBody()
			return Event{}, ctx.Err()
		}
		if s.closed.Load() {
			s.closeBody()
			return Event{}, ErrClosed
		}
		if errors.Is(err, ErrSSETooLarge) || errors.Is(err, ErrSSEProtocol) {
			s.closeBody()
			return Event{}, err
		}
		if s.opts.MaxReconnects <= 0 || s.reconnects >= s.opts.MaxReconnects {
			s.closeBody()
			return Event{}, err
		}
		s.reconnects++
		s.closeBody()
		delay := s.opts.Backoff
		if s.retrySet {
			delay = s.retryHint
		}
		if err := sleepContext(ctx, delay); err != nil {
			return Event{}, err
		}
		if s.closed.Load() {
			return Event{}, ErrClosed
		}
		if err := s.open(ctx); err != nil {
			return Event{}, err
		}
	}
}

// readEvent waits for one event with an optional idle timeout. | readEvent 在可选空闲超时下等待一个事件。
func (s *Stream) readEvent(ctx context.Context, reader *EventReader, body io.ReadCloser) (Event, error) {
	// Without an idle timeout and without a cancellable context there is
	// nothing to select on; read inline instead of spawning a goroutine per
	// event. | 无空闲超时且 ctx 不可取消时无需 select，直接读取，避免每个事件
	// 创建 goroutine。
	if s.opts.IdleTimeout <= 0 && ctx.Done() == nil {
		return reader.Next()
	}
	type result struct {
		err   error
		event Event
	}
	done := make(chan result, 1)
	go func() {
		event, err := reader.Next()
		done <- result{event: event, err: err}
	}()
	var timeout <-chan time.Time
	if s.opts.IdleTimeout > 0 {
		timer := time.NewTimer(s.opts.IdleTimeout)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case outcome := <-done:
		return outcome.event, outcome.err
	case <-timeout:
		_ = body.Close()
		<-done
		return Event{}, ErrSSEIdle
	case <-ctx.Done():
		_ = body.Close()
		<-done
		return Event{}, ctx.Err()
	}
}

// Raw switches the stream to raw mode and returns the response body. | Raw 把流切换为原始模式并返回响应正文。
func (s *Stream) Raw() io.ReadCloser {
	if s == nil {
		return http.NoBody
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.body == nil {
		return http.NoBody
	}
	s.rawMode = true
	if s.reader != nil {
		return &bufioReadCloser{Reader: s.reader.reader, closer: s.body}
	}
	return s.body
}

// bufioReadCloser preserves buffered reader bytes while closing the underlying body. | bufioReadCloser 在关闭底层正文的同时保留已缓冲字节。
type bufioReadCloser struct {
	*bufio.Reader
	closer io.Closer
}

// Close closes the underlying body. | Close 关闭底层正文。
func (r *bufioReadCloser) Close() error {
	return r.closer.Close()
}

// Close closes the stream and stops reconnects. | Close 关闭流并停止重连。
func (s *Stream) Close() error {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.closeBody()
	if s.client != nil && s.client.engine.hooks.OnStreamEnd != nil {
		_ = callHook(func() error {
			s.client.engine.hooks.OnStreamEnd(context.Background(), nil)
			return nil
		})
	}
	return nil
}

// closeBody closes and clears the current body. | closeBody 关闭并清空当前正文。
func (s *Stream) closeBody() {
	s.mu.Lock()
	body := s.body
	s.body = nil
	s.reader = nil
	s.mu.Unlock()
	if body != nil {
		_ = body.Close()
	}
}
