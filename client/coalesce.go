package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// CoalescePolicy configures concurrent request merging. | CoalescePolicy 配置并发请求合并。
type CoalescePolicy struct {
	// Methods lists mergeable methods; nil means GET/HEAD. | Methods 列出可合并方法；nil 表示 GET/HEAD。
	Methods []string
	// MaxBodyBytes caps a shareable response body; <=0 means 4 MiB. | MaxBodyBytes 限制可共享响应正文；<=0 表示 4 MiB。
	MaxBodyBytes int64
}

// withDefaults fills zero-value coalesce fields. | withDefaults 填充零值合并字段。
func (p CoalescePolicy) withDefaults() CoalescePolicy {
	if p.Methods == nil {
		p.Methods = []string{http.MethodGet, http.MethodHead}
	}
	if p.MaxBodyBytes <= 0 {
		p.MaxBodyBytes = 4 << 20
	}
	return p
}

// WithCoalesce sets the client-wide coalescing policy. | WithCoalesce 设置客户端级请求合并策略。
func WithCoalesce(policy CoalescePolicy) Option {
	return func(o *options) error {
		o.Coalesce = &policy
		return nil
	}
}

// errCoalesceBypass signals that a follower must execute independently. | errCoalesceBypass 表示 follower 必须独立执行。
var errCoalesceBypass = errs.New("client: coalesce bypass | client：合并旁路")

// flight is one in-progress coalesced request. | flight 是一个进行中的合并请求。
type flight struct {
	done   chan struct{}
	resp   *http.Response
	body   []byte
	err    error
	bypass bool
}

// flightGroup deduplicates concurrent requests by key. | flightGroup 按键去重并发请求。
type flightGroup struct {
	mu      sync.Mutex
	flights map[string]*flight
}

// newFlightGroup builds an empty flight group. | newFlightGroup 构建空的合并组。
func newFlightGroup() *flightGroup {
	return &flightGroup{flights: make(map[string]*flight)}
}

// Do joins the in-flight leader or becomes the leader. The leader result reports
// whether followers may share it. | Do 加入在途 leader 或成为 leader；leader 结果报告
// follower 是否可共享。
func (g *flightGroup) Do(ctx context.Context, key string, leader func() (*http.Response, []byte, bool, error)) (*http.Response, []byte, bool, error) {
	g.mu.Lock()
	if existing, ok := g.flights[key]; ok {
		g.mu.Unlock()
		select {
		case <-existing.done:
			if existing.bypass {
				return nil, nil, true, errCoalesceBypass
			}
			if existing.err != nil {
				return nil, nil, true, existing.err
			}
			return cloneFlightResponse(existing.resp, existing.body), existing.body, true, nil
		case <-ctx.Done():
			return nil, nil, false, ctx.Err()
		}
	}
	current := &flight{done: make(chan struct{})}
	g.flights[key] = current
	g.mu.Unlock()

	resp, body, shareable, err := leader()
	current.resp, current.body, current.err = resp, body, err
	switch {
	case err != nil:
		current.bypass = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	case !shareable:
		current.bypass = true
	}
	close(current.done)
	g.mu.Lock()
	delete(g.flights, key)
	g.mu.Unlock()
	return resp, body, false, err
}

// cloneFlightResponse materializes a shared response for one follower. | cloneFlightResponse 为一个 follower 物化共享响应。
func cloneFlightResponse(template *http.Response, body []byte) *http.Response {
	resp := &http.Response{Header: make(http.Header), Body: http.NoBody}
	if template != nil {
		if template.Header != nil {
			resp.Header = template.Header.Clone()
		}
		resp.Status = template.Status
		resp.StatusCode = template.StatusCode
		resp.Proto = template.Proto
		resp.ProtoMajor = template.ProtoMajor
		resp.ProtoMinor = template.ProtoMinor
		resp.Uncompressed = template.Uncompressed
	}
	if body != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
	}
	return resp
}

// coalesceFor resolves the rule or client coalescing policy. | coalesceFor 解析规则或客户端合并策略。
func (e *engine) coalesceFor(rule *Rule) (CoalescePolicy, bool) {
	var policy *CoalescePolicy
	if rule != nil && rule.Coalesce != nil {
		policy = rule.Coalesce
	} else if e.opts.Coalesce != nil {
		policy = e.opts.Coalesce
	}
	if policy == nil {
		return CoalescePolicy{}, false
	}
	return policy.withDefaults(), true
}

// shouldCoalesce reports whether the request may join a flight. | shouldCoalesce 报告请求是否可加入合并。
func shouldCoalesce(req *http.Request, policy CoalescePolicy) bool {
	if req == nil || req.URL == nil || req.Body != nil {
		return false
	}
	allowed := false
	for _, method := range policy.Methods {
		if method == req.Method {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	if strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream") {
		return false
	}
	if strings.Contains(strings.ToLower(req.Header.Get("Cache-Control")), "no-store") {
		return false
	}
	return true
}

// coalesceKey builds a key that separates methods, URLs, rules and negotiation headers. | coalesceKey 构建区分方法、URL、规则与协商头的键。
func coalesceKey(req *http.Request, rule *Rule) string {
	var builder strings.Builder
	builder.WriteString(req.Method)
	builder.WriteByte(0)
	builder.WriteString(req.URL.Scheme)
	builder.WriteString("://")
	builder.WriteString(req.URL.Host)
	builder.WriteString(req.URL.EscapedPath())
	if req.URL.RawQuery != "" {
		builder.WriteByte('?')
		builder.WriteString(req.URL.RawQuery)
	}
	builder.WriteByte(0)
	if rule != nil {
		builder.WriteString(rule.Name)
	}
	for _, name := range [...]string{"Authorization", "Cookie", "Accept", "Accept-Language", "Accept-Encoding"} {
		builder.WriteByte(0)
		builder.WriteString(name)
		builder.WriteByte('=')
		builder.WriteString(headerValue(req.Header, name))
	}
	return builder.String()
}

// coalesceRoundTrip runs the leader or joins an existing flight. | coalesceRoundTrip 执行 leader 或加入已有合并。
func (e *engine) coalesceRoundTrip(req *http.Request, rule *Rule, meta *Meta, hosts *HostSet, key string, policy CachePolicy, store Store, coalescePolicy CoalescePolicy, postMirror bool) (*http.Response, error) {
	flightKey := coalesceKey(req, rule)
	resp, _, coalesced, err := e.flights.Do(req.Context(), flightKey, func() (*http.Response, []byte, bool, error) {
		resp, err := e.execute(req, rule, meta, hosts, key, policy, store, postMirror)
		if err != nil {
			return nil, nil, false, err
		}
		if resp == nil || resp.Body == nil {
			return resp, nil, true, nil
		}
		max := coalescePolicy.MaxBodyBytes
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if readErr != nil {
			resp.Body = &multiReadCloser{Reader: io.MultiReader(bytes.NewReader(data), resp.Body), closer: resp.Body}
			return resp, nil, false, nil
		}
		if int64(len(data)) > max {
			resp.Body = &multiReadCloser{Reader: io.MultiReader(bytes.NewReader(data), resp.Body), closer: resp.Body}
			return resp, nil, false, nil
		}
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.TransferEncoding = nil
		resp.Header.Del("Transfer-Encoding")
		return resp, data, true, nil
	})
	if e.hooks.OnCoalesce != nil {
		_ = callHook(func() error {
			e.hooks.OnCoalesce(req.Context(), req, coalesced)
			return nil
		})
	}
	if coalesced {
		e.counters.coalesced.Add(1)
	}
	if errors.Is(err, errCoalesceBypass) {
		return e.execute(req, rule, meta, hosts, key, policy, store, false)
	}
	if err != nil {
		return nil, err
	}
	if coalesced {
		resp.Request = req
		if resp.Body == nil {
			resp.Body = http.NoBody
		}
		if meta != nil {
			meta.Coalesced = true
			meta.Attempts = 0
			meta.Hops = append(meta.Hops, HopMeta{
				URL:    safeURL(req.URL),
				Status: resp.StatusCode,
			})
		}
	}
	return resp, nil
}
