package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ForwardOptions configures Forward and Handler. | ForwardOptions 配置 Forward 与 Handler。
type ForwardOptions struct {
	// StripHeaders lists extra inbound headers to remove. | StripHeaders 列出额外移除的入站头。
	StripHeaders []string
	// FlushInterval throttles intermediate flushes; <=0 flushes every chunk. | FlushInterval 限制中间刷新；<=0 表示每块刷新。
	FlushInterval time.Duration
	// SSEIdleTimeout bounds the upstream silence; <=0 disables it. | SSEIdleTimeout 限制上游静默；<=0 禁用。
	SSEIdleTimeout time.Duration
	// SSEHeartbeat injects ": ping" comments while idle; <=0 disables it. | SSEHeartbeat 在空闲时注入 ": ping"；<=0 禁用。
	SSEHeartbeat time.Duration
	// BodyTimeout bounds a non-SSE upstream body; <=0 disables it. | BodyTimeout 限制非 SSE 上游正文；<=0 禁用。
	BodyTimeout time.Duration
	// MaxBodyBytes caps non-SSE forwarded bodies; <=0 means unlimited. | MaxBodyBytes 限制非 SSE 转发正文；<=0 表示不限制。
	MaxBodyBytes int64
	// PreserveHost keeps the inbound Host header. | PreserveHost 保留入站 Host 头。
	PreserveHost bool
	// AddForwardedFor appends X-Forwarded-For/Proto/Host. | AddForwardedFor 追加 X-Forwarded-For/Proto/Host。
	AddForwardedFor bool
	// SSEReconnect is reserved for future upstream resume support. | SSEReconnect 预留给未来的上游续传。
	SSEReconnect bool
}

// ForwardOption mutates ForwardOptions. | ForwardOption 修改 ForwardOptions。
type ForwardOption func(*ForwardOptions) error

// WithForwardPreserveHost keeps the inbound Host header. | WithForwardPreserveHost 保留入站 Host 头。
func WithForwardPreserveHost(ok bool) ForwardOption {
	return func(o *ForwardOptions) error {
		o.PreserveHost = ok
		return nil
	}
}

// WithForwardSSEIdleTimeout bounds upstream SSE silence. | WithForwardSSEIdleTimeout 限制上游 SSE 静默。
func WithForwardSSEIdleTimeout(d time.Duration) ForwardOption {
	return func(o *ForwardOptions) error {
		o.SSEIdleTimeout = d
		return nil
	}
}

// WithForwardSSEHeartbeat injects SSE heartbeat comments. | WithForwardSSEHeartbeat 注入 SSE 心跳注释。
func WithForwardSSEHeartbeat(d time.Duration) ForwardOption {
	return func(o *ForwardOptions) error {
		o.SSEHeartbeat = d
		return nil
	}
}

// copySSE streams an upstream SSE body to w, teeing to sinks when configured. | copySSE 把上游 SSE 正文流式写给 w，并在配置时 tee 到 sink。
func (c *Client) copySSE(ctx context.Context, w http.ResponseWriter, resp *http.Response, in *http.Request, opts ForwardOptions) error {
	if c == nil || w == nil || resp == nil || resp.Body == nil {
		return ErrInvalidRequest
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer resp.Body.Close()

	var rule *Rule
	if in != nil {
		if rules := c.engine.rules.Load(); rules != nil {
			rule, _, _ = rules.MatchRequest(in)
		}
	}
	var workers []*teeSinkWorker
	var eventPump *sseEventPump
	if policy, ok := c.engine.mirrorFor(rule); ok && policy.Mode == MirrorTee {
		workers = c.engine.teeSinks(policy)
		if len(policy.TeeEventSinks) > 0 {
			eventWorkers := make([]*eventSinkWorker, 0, len(policy.TeeEventSinks))
			for _, sink := range policy.TeeEventSinks {
				eventWorkers = append(eventWorkers, newEventSinkWorker(sink, policy.TeeQueue, policy.TeeDrop, policy.TeeTimeout, &c.engine.mirrorDrops))
			}
			eventPump = startSSEEventPump(eventWorkers)
		}
	}
	defer closeTeeWorkers(workers)
	defer eventPump.Close()

	skip := hopByHopSet(resp.Header)
	header := w.Header()
	for key, values := range resp.Header {
		canonical := http.CanonicalHeaderKey(key)
		if skip[canonical] || canonical == "Content-Length" {
			continue
		}
		for _, value := range values {
			header.Add(key, value)
		}
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "text/event-stream; charset=utf-8")
	}
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache, no-transform")
	}
	if header.Get("X-Accel-Buffering") == "" {
		header.Set("X-Accel-Buffering", "no")
	}
	w.WriteHeader(resp.StatusCode)
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	if err := flushResponseWriter(w); err != nil {
		return err
	}

	type streamChunk struct {
		err  error
		data []byte
	}
	chunks := make(chan streamChunk, 1)
	readCtx, cancelRead := context.WithCancel(ctx)
	defer cancelRead()
	go func() {
		buffer := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buffer)
			if n > 0 {
				data := append([]byte(nil), buffer[:n]...)
				select {
				case chunks <- streamChunk{data: data}:
				case <-readCtx.Done():
					return
				}
			}
			if err != nil {
				select {
				case chunks <- streamChunk{err: err}:
				case <-readCtx.Done():
				}
				return
			}
		}
	}()

	var idleTimer *time.Timer
	var idleC <-chan time.Time
	if opts.SSEIdleTimeout > 0 {
		idleTimer = time.NewTimer(opts.SSEIdleTimeout)
		defer idleTimer.Stop()
		idleC = idleTimer.C
	}
	var heartbeat *time.Ticker
	var heartbeatC <-chan time.Time
	if opts.SSEHeartbeat > 0 {
		heartbeat = time.NewTicker(opts.SSEHeartbeat)
		defer heartbeat.Stop()
		heartbeatC = heartbeat.C
	}
	lastData := time.Now()
	lastFlush := time.Now()
	flushInterval := opts.FlushInterval
	for {
		select {
		case outcome := <-chunks:
			if len(outcome.data) > 0 {
				lastData = time.Now()
				if idleTimer != nil {
					resetForwardTimer(idleTimer, opts.SSEIdleTimeout)
				}
				if _, err := w.Write(outcome.data); err != nil {
					_ = resp.Body.Close()
					return err
				}
				writeTeeChunk(workers, outcome.data)
				eventPump.Write(outcome.data)
				if flushInterval <= 0 || time.Since(lastFlush) >= flushInterval {
					if err := flushResponseWriter(w); err != nil {
						_ = resp.Body.Close()
						return err
					}
					lastFlush = time.Now()
				}
			}
			if outcome.err != nil {
				if errors.Is(outcome.err, io.EOF) {
					return nil
				}
				return outcome.err
			}
		case <-idleC:
			_ = resp.Body.Close()
			return ErrSSEIdle
		case <-heartbeatC:
			if time.Since(lastData) >= opts.SSEHeartbeat {
				if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
					_ = resp.Body.Close()
					return err
				}
				if err := flushResponseWriter(w); err != nil {
					_ = resp.Body.Close()
					return err
				}
			}
		case <-ctx.Done():
			_ = resp.Body.Close()
			return ctx.Err()
		}
	}
}

// mirrorSSE schedules independent shadow SSE streams. | mirrorSSE 调度独立的影子 SSE 流。
func (c *Client) mirrorSSE(ctx context.Context, req *http.Request, logical *url.URL, policy *MirrorPolicy) {
	if c == nil || req == nil || logical == nil || policy == nil {
		return
	}
	prepared, err := prepareMirror(policy)
	if err != nil {
		return
	}
	var rule *Rule
	if rules := c.engine.rules.Load(); rules != nil {
		rule, _, _ = rules.MatchRequest(req)
	}
	c.engine.mirrors.submitSSE(ctx, req, logical, rule, prepared)
}

// submitSSE runs shadow SSE streams under the mirrorer's concurrency limit. | submitSSE 在 mirrorer 并发限制下运行影子 SSE 流。
func (m *mirrorer) submitSSE(parent context.Context, req *http.Request, logical *url.URL, rule *Rule, policy *MirrorPolicy) {
	if m == nil || policy == nil || len(policy.targets) == 0 || !m.active() {
		return
	}
	if !mirrorSampled(logical, rule, policy.Percent) {
		return
	}
	var getBody func() (io.ReadCloser, error)
	if req.Body != nil && req.Body != http.NoBody {
		getBody = req.GetBody
		if getBody == nil {
			for _, target := range policy.targets {
				m.drop(target.String(), "body not replayable")
			}
			return
		}
	}
	var local sync.WaitGroup
	for _, target := range policy.targets {
		if !m.active() {
			return
		}
		select {
		case m.sem <- struct{}{}:
		default:
			m.drop(target.String(), "mirror inflight limit")
			return
		}
		if m.engine != nil {
			m.engine.counters.mirrors.Add(1)
			if m.engine.hooks.OnMirrorStart != nil {
				_ = callHook(func() error {
					m.engine.hooks.OnMirrorStart(parent, MirrorInfo{Target: target.String()})
					return nil
				})
			}
		}
		if !m.reserve() {
			<-m.sem
			return
		}
		local.Add(1)
		go func(target *url.URL) {
			defer m.wg.Done()
			defer local.Done()
			defer func() { <-m.sem }()
			m.runSSE(parent, req, logical, rule, policy, target, getBody)
		}(target)
	}
	if policy.Sync {
		waitGroup(&local, policy.Wait)
	}
}

// runSSE consumes one shadow SSE stream to EOF or timeout. | runSSE 消费一条影子 SSE 流直到 EOF 或超时。
func (m *mirrorer) runSSE(parent context.Context, req *http.Request, logical *url.URL, rule *Rule, policy *MirrorPolicy, target *url.URL, getBody func() (io.ReadCloser, error)) {
	if m.engine != nil {
		defer func() {
			if m.engine.hooks.OnMirrorDone != nil {
				_ = callHook(func() error {
					m.engine.hooks.OnMirrorDone(parent, MirrorInfo{Target: target.String()})
					return nil
				})
			}
		}()
	}
	ctx := m.ctx
	var detach func()
	if policy.FollowCancel && parent != nil {
		parentCtx, parentCancel := context.WithCancel(parent)
		stop := context.AfterFunc(m.ctx, parentCancel)
		detach = func() {
			stop()
			parentCancel()
		}
		ctx = parentCtx
	}
	ctx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()
	if detach != nil {
		defer detach()
	}
	out := req.Clone(ctx)
	out.URL = targetURL(logical, &Host{URL: target}, rule)
	out.RequestURI = ""
	out.Host = out.URL.Host
	out.Header = req.Header.Clone()
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	for _, name := range policy.StripHeaders {
		out.Header.Del(name)
	}
	out.Header.Set("Accept", "text/event-stream")
	out.Header.Set("Accept-Encoding", "identity")
	if getBody != nil {
		body, err := getBody()
		if err != nil {
			return
		}
		out.Body = body
	}
	out.GetBody = getBody
	base := m.base
	if m.engine != nil {
		base = m.engine.transportForURL(out.URL)
	}
	resp, err := base.RoundTrip(out)
	if err != nil {
		if m.engine != nil {
			m.engine.counters.mirrorErrors.Add(1)
		}
		return
	}
	defer resp.Body.Close()
	if !isEventStream(resp.Header) {
		drainAndClose(resp.Body, policy.MaxBodyBytes)
		return
	}
	reader := NewEventReader(resp.Body)
	for {
		if _, err := reader.Next(); err != nil {
			return
		}
	}
}

// flushResponseWriter flushes through ResponseController with a Flusher fallback. | flushResponseWriter 通过 ResponseController 刷新，失败时回退 Flusher。
func flushResponseWriter(w http.ResponseWriter) error {
	if err := http.NewResponseController(w).Flush(); err != nil {
		if errors.Is(err, http.ErrNotSupported) {
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
				return nil
			}
		}
		return err
	}
	return nil
}

// resetForwardTimer resets a timer safely. | resetForwardTimer 安全重置定时器。
func resetForwardTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}
