package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// errCoalesceLeaderPanic is reported to followers when the coalesced leader
// panics; the panic is re-raised to the leader's caller. |
// errCoalesceLeaderPanic 在合并请求领头者 panic 时报告给跟随者；panic 会重新抛给
// 领头者的调用方。
var errCoalesceLeaderPanic = errs.New("client: coalesced leader panic | client：合并请求领头者 panic")

// CoalescePolicy configures concurrent request merging. | CoalescePolicy 配置并发请求合并。
type CoalescePolicy struct {
	// Methods lists mergeable methods; nil means GET/HEAD. | Methods 列出可合并方法；nil 表示 GET/HEAD。
	Methods []string
	// MaxBodyBytes caps a shareable response body; <=0 means 4 MiB. | MaxBodyBytes 限制可共享响应正文；<=0 表示 4 MiB。
	MaxBodyBytes int64
}

// withDefaults fills zero-value coalesce fields. | withDefaults 填充零值合并字段。
var defaultCoalesceMethods = []string{http.MethodGet, http.MethodHead}

func (p CoalescePolicy) withDefaults() CoalescePolicy {
	if p.Methods == nil {
		p.Methods = defaultCoalesceMethods
	}
	if p.MaxBodyBytes <= 0 {
		p.MaxBodyBytes = 4 << 20
	}
	return p
}

// WithCoalesce sets the client-wide coalescing policy. | WithCoalesce 设置客户端级请求合并策略。
func WithCoalesce(policy CoalescePolicy) Option {
	policy.Methods = cloneSlice(policy.Methods)
	return func(o *options) error {
		o.Coalesce = &policy
		return nil
	}
}

// errCoalesceBypass signals that a follower must execute independently. | errCoalesceBypass 表示 follower 必须独立执行。
var errCoalesceBypass = errs.New("client: coalesce bypass | client：合并旁路")

// flight is one in-progress coalesced request. | flight 是一个进行中的合并请求。
type flight struct {
	err    error
	done   chan struct{}
	resp   *http.Response
	body   []byte
	bypass bool
}

// flightShardCount spreads coalescing locks across independent shards. | flightShardCount
// 把合并锁分散到独立分片。
const flightShardCount = 16

// flightShard is one independently locked flight map. | flightShard 是一个独立
// 加锁的合并映射。
type flightShard struct {
	flights map[string]*flight
	mu      sync.Mutex
}

// flightGroup deduplicates concurrent requests by key. | flightGroup 按键去重并发请求。
type flightGroup struct {
	shards [flightShardCount]flightShard
}

// newFlightGroup builds an empty flight group. | newFlightGroup 构建空的合并组。
func newFlightGroup() *flightGroup {
	group := &flightGroup{}
	for i := range group.shards {
		group.shards[i].flights = make(map[string]*flight)
	}
	return group
}

// shardFor returns the shard owning key. | shardFor 返回 key 所属分片。
func (g *flightGroup) shardFor(key string) *flightShard {
	return &g.shards[fnv64aString(key)%flightShardCount]
}

// Do joins the in-flight leader or becomes the leader. The leader result reports
// whether followers may share it. | Do 加入在途 leader 或成为 leader；leader 结果报告
// follower 是否可共享。
func (g *flightGroup) Do(ctx context.Context, key string, leader func() (*http.Response, []byte, bool, error)) (*http.Response, []byte, bool, error) {
	shard := g.shardFor(key)
	shard.mu.Lock()
	if existing, ok := shard.flights[key]; ok {
		shard.mu.Unlock()
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
	shard.flights[key] = current
	shard.mu.Unlock()
	// Complete the flight on every path, including a leader panic, so waiters
	// are never parked on a done channel that is never closed and the key is not
	// permanently blackholed. | 任何路径都必须完成在途请求，包括领头者 panic，避免
	// 等待者永远阻塞在该 key 上。
	defer func() {
		if r := recover(); r != nil {
			current.err = errCoalesceLeaderPanic
			close(current.done)
			shard.mu.Lock()
			delete(shard.flights, key)
			shard.mu.Unlock()
			panic(r)
		}
		close(current.done)
		shard.mu.Lock()
		delete(shard.flights, key)
		shard.mu.Unlock()
	}()

	resp, body, shareable, err := leader()
	current.body = body
	current.err = err
	if resp != nil {
		// Snapshot before closing done so followers never read a header map the
		// leader's caller or response hook may mutate later. | 在关闭 done 前快照，
		// 避免 follower 读取 leader 调用方或响应钩子随后修改的 Header。
		snapshot := *resp
		if resp.Header != nil {
			snapshot.Header = resp.Header.Clone()
		}
		if resp.Trailer != nil {
			snapshot.Trailer = resp.Trailer.Clone()
		}
		current.resp = &snapshot
	}
	switch {
	case err != nil:
		current.bypass = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	case !shareable:
		current.bypass = true
	}
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
		if template.Trailer != nil {
			resp.Trailer = template.Trailer.Clone()
		}
	}
	if body != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if template != nil {
			resp.ContentLength = template.ContentLength
		} else {
			resp.ContentLength = int64(len(body))
		}
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
	if req == nil || req.URL == nil || (req.Body != nil && req.Body != http.NoBody) {
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
	if conditionalRequest(req) {
		return false
	}
	return true
}

// conditionalRequest reports whether the response may depend on per-request
// validators or a byte range. | conditionalRequest 报告响应是否可能依赖逐请求校验器或字节范围。
func conditionalRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	header := req.Header
	return header.Get("Range") != "" || header.Get("If-Range") != "" ||
		header.Get("If-None-Match") != "" || header.Get("If-Modified-Since") != "" ||
		header.Get("If-Match") != "" || header.Get("If-Unmodified-Since") != ""
}

// coalesceKey builds a key that separates methods, URLs, rules and negotiation headers. | coalesceKey 构建区分方法、URL、规则与协商头的键。
func coalesceKey(req *http.Request, rule *Rule) string {
	var builder strings.Builder
	builder.WriteString(req.Method)
	builder.WriteByte(0)
	builder.WriteString(req.URL.Scheme)
	builder.WriteString("://")
	builder.WriteString(req.URL.Host)
	if req.URL.User != nil {
		builder.WriteByte(0)
		builder.WriteString(req.URL.User.String())
	}
	builder.WriteString(req.URL.EscapedPath())
	if req.URL.RawQuery != "" {
		builder.WriteByte('?')
		builder.WriteString(req.URL.RawQuery)
	}
	builder.WriteByte(0)
	if rule != nil {
		builder.WriteString(rule.Name)
		builder.WriteByte(0)
		var id [20]byte
		_, _ = builder.Write(strconv.AppendUint(id[:0], rule.id, 10))
	}
	builder.WriteByte(0)
	builder.WriteString(req.Host)
	keys := make([]string, 0, len(req.Header))
	for key := range req.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		builder.WriteByte(0)
		appendLowerASCII(&builder, key)
		builder.WriteByte('=')
		for i, value := range req.Header.Values(key) {
			if i > 0 {
				builder.WriteByte(0)
			}
			builder.WriteString(value)
		}
	}
	return builder.String()
}

// appendLowerASCII appends an ASCII-lowercased string without allocating for
// header names. | appendLowerASCII 以不分配的方式追加 ASCII 小写字符串，用于
// 请求头名。
func appendLowerASCII(builder *strings.Builder, value string) {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			builder.WriteString(strings.ToLower(value))
			return
		}
	}
	var scratch [64]byte
	lower := scratch[:0]
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		lower = append(lower, ch)
		if len(lower) == len(scratch) {
			_, _ = builder.Write(lower)
			lower = lower[:0]
		}
	}
	_, _ = builder.Write(lower)
}

// coalesceRoundTrip runs the leader or joins an existing flight. | coalesceRoundTrip 执行 leader 或加入已有合并。
func (e *engine) coalesceRoundTrip(req *http.Request, rule *Rule, meta *Meta, hosts *HostSet, key string, policy CachePolicy, store Store, coalescePolicy CoalescePolicy, postMirror bool, sp *spool) (*http.Response, error) {
	flightKey := coalesceKey(req, rule)
	resp, _, coalesced, err := e.flights.Do(req.Context(), flightKey, func() (*http.Response, []byte, bool, error) {
		resp, err := e.execute(req, rule, meta, hosts, key, policy, store, postMirror, sp)
		if err != nil {
			return nil, nil, false, err
		}
		if resp == nil || resp.Body == nil {
			return resp, nil, true, nil
		}
		if isEventStream(resp.Header) {
			return resp, nil, false, nil
		}
		if len(resp.Header.Values("Set-Cookie")) > 0 {
			// A per-client cookie must never be shared with followers. | 逐客户端
			// Cookie 不得共享给 follower。
			return resp, nil, false, nil
		}
		max := coalescePolicy.MaxBodyBytes
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, saturatingPlusOne(max)))
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
		if req.Method != http.MethodHead && resp.StatusCode != http.StatusNotModified {
			resp.ContentLength = int64(len(data))
		} else if n, parseErr := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); parseErr == nil {
			resp.ContentLength = n
		}
		resp.TransferEncoding = nil
		resp.Header.Del("Transfer-Encoding")
		return resp, data, true, nil
	})
	if errors.Is(err, errCoalesceBypass) {
		if e.hooks.OnCoalesce != nil {
			_ = callHook(func() error {
				e.hooks.OnCoalesce(req.Context(), req, false)
				return nil
			})
		}
		return e.execute(req, rule, meta, hosts, key, policy, store, false, sp)
	}
	if e.hooks.OnCoalesce != nil {
		_ = callHook(func() error {
			e.hooks.OnCoalesce(req.Context(), req, coalesced)
			return nil
		})
	}
	if coalesced {
		e.counters.coalesced.Add(1)
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
