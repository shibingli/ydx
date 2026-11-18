package client

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"
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
	reconnects int

	mu sync.Mutex

	closed  atomic.Bool
	rawMode bool
}

// OpenStream opens an SSE request through the client engine. | OpenStream 通过客户端引擎打开 SSE 请求。
func (c *Client) OpenStream(ctx context.Context, req *http.Request, opts ...StreamOption) (*Stream, error) {
	if c == nil || c.closed.Load() {
		return nil, ErrClosed
	}
	if req == nil || req.URL == nil {
		return nil, ErrInvalidRequest
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolved, err := c.resolveRequestURL(req.URL.String())
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(resolved)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	template := req.Clone(ctx)
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

// open issues one SSE request and validates the response. | open 发起一次 SSE 请求并校验响应。
func (s *Stream) open(ctx context.Context) error {
	req := s.template.Clone(ctx)
	if s.lastID != "" {
		req.Header.Set("Last-Event-ID", s.lastID)
	}
	meta := &Meta{}
	req = req.WithContext(context.WithValue(req.Context(), streamRequestKey{}, true))
	req = req.WithContext(context.WithValue(req.Context(), metaKey{}, meta))
	resp, err := s.client.engine.RoundTrip(req)
	if err != nil {
		return err
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
	s.body = resp.Body
	s.reader = nil
	s.meta = meta
	s.mu.Unlock()
	return nil
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
			if event.ID != "" {
				s.lastID = event.ID
			}
			if event.Retry > 0 {
				s.retryHint = event.Retry
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
		if s.opts.MaxReconnects <= 0 || s.reconnects >= s.opts.MaxReconnects {
			s.closeBody()
			return Event{}, err
		}
		s.reconnects++
		s.closeBody()
		delay := s.opts.Backoff
		if s.retryHint > 0 {
			delay = s.retryHint
		}
		if err := sleepContext(ctx, delay); err != nil {
			return Event{}, err
		}
		if err := s.open(ctx); err != nil {
			return Event{}, err
		}
	}
}

// readEvent waits for one event with an optional idle timeout. | readEvent 在可选空闲超时下等待一个事件。
func (s *Stream) readEvent(ctx context.Context, reader *EventReader, body io.ReadCloser) (Event, error) {
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
