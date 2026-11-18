package client

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// MirrorMode names the traffic mirroring strategy. | MirrorMode 命名流量镜像策略。
type MirrorMode string

const (
	// MirrorUpstream replays the request against shadow upstreams. | MirrorUpstream 把请求重放到影子上游。
	MirrorUpstream MirrorMode = "upstream"
	// MirrorTee copies the primary response stream to sinks. | MirrorTee 把主流响应复制到 sink。
	MirrorTee MirrorMode = "tee"
)

// DropPolicy controls what a full tee queue discards. | DropPolicy 控制 tee 队列满时丢弃什么。
type DropPolicy int

const (
	// DropNewest discards the incoming chunk. | DropNewest 丢弃新到的块。
	DropNewest DropPolicy = iota
	// DropOldest discards the oldest queued chunk. | DropOldest 丢弃队列中最旧的块。
	DropOldest
)

// MirrorResult describes one shadow upstream attempt. | MirrorResult 描述一次影子上游尝试。
type MirrorResult struct {
	// Err is the shadow failure. | Err 是影子失败。
	Err error
	// Target is the shadow base URL. | Target 是影子 base URL。
	Target string
	// Status is the shadow response status. | Status 是影子响应状态码。
	Status int
	// Duration is the shadow attempt duration. | Duration 是影子尝试耗时。
	Duration time.Duration
	// Dropped reports that the payload was dropped. | Dropped 报告载荷是否被丢弃。
	Dropped bool
}

// MirrorPolicy configures A shadow replay or B tee mirroring. | MirrorPolicy 配置 A 影子上游重放或 B tee 镜像。
type MirrorPolicy struct {
	// Mode is MirrorUpstream (default) or MirrorTee. | Mode 是 MirrorUpstream（默认）或 MirrorTee。
	Mode MirrorMode
	// Targets are shadow base URLs for Mode A. | Targets 是 Mode A 的影子 base URL。
	Targets []string
	// StripHeaders lists headers removed from shadow requests; nil uses defaults. | StripHeaders 列出影子请求移除的头；nil 使用默认值。
	StripHeaders []string
	// TeeSinks receive primary response chunks in Mode B. | TeeSinks 在 Mode B 接收主流响应块。
	TeeSinks []Sink
	// TeeEventSinks receive parsed SSE events in Mode B. | TeeEventSinks 在 Mode B 接收解析后的 SSE 事件。
	TeeEventSinks []EventSink

	targets []*url.URL
	// Percent samples requests deterministically; <=0 means 100. | Percent 确定性抽样；<=0 表示 100。
	Percent int
	// Wait bounds synchronous mirror waiting; <=0 means 5s. | Wait 限制同步镜像等待；<=0 表示 5s。
	Wait time.Duration
	// Timeout bounds one shadow request; <=0 means 5s. | Timeout 限制单个影子请求；<=0 表示 5s。
	Timeout time.Duration
	// MaxBodyBytes caps shadow body draining and tee queues; <=0 means 1 MiB. | MaxBodyBytes 限制影子正文排空与 tee 队列；<=0 表示 1 MiB。
	MaxBodyBytes int64
	// TeeQueue is each sink queue length; <=0 means 64. | TeeQueue 是每个 sink 队列长度；<=0 表示 64。
	TeeQueue int
	// TeeDrop selects DropNewest or DropOldest. | TeeDrop 选择 DropNewest 或 DropOldest。
	TeeDrop DropPolicy
	// TeeTimeout bounds one sink write; <=0 means 5s. | TeeTimeout 限制单次 sink 写入；<=0 表示 5s。
	TeeTimeout time.Duration

	// Sync waits for shadow requests up to Wait. | Sync 等待影子请求直到 Wait。
	Sync bool
	// Parallel starts shadow requests before the primary when possible. | Parallel 尽可能在主流前启动影子请求。
	Parallel bool
	// FollowCancel ties shadow lifetime to the caller's context. | FollowCancel 让影子生命周期跟随调用方 context。
	FollowCancel bool
}

// defaultMirrorStripHeaders are removed from shadow requests. | defaultMirrorStripHeaders 从影子请求中移除。
var defaultMirrorStripHeaders = []string{"Authorization", "Cookie", "Host", "Proxy-Authorization"}

// prepareMirror validates a policy and resolves its targets. | prepareMirror 校验策略并解析目标。
func prepareMirror(policy *MirrorPolicy) (*MirrorPolicy, error) {
	if policy == nil {
		return nil, nil
	}
	prepared := *policy
	prepared.Targets = append([]string(nil), policy.Targets...)
	prepared.TeeSinks = append([]Sink(nil), policy.TeeSinks...)
	prepared.TeeEventSinks = append([]EventSink(nil), policy.TeeEventSinks...)
	if prepared.Mode == "" {
		prepared.Mode = MirrorUpstream
	}
	if prepared.Percent < 0 || prepared.Percent > 100 {
		return nil, errs.Detail(ErrInvalidConfig, "mirror percent must be 0..100 | 镜像比例必须在 0..100")
	}
	if prepared.Percent == 0 {
		prepared.Percent = 100
	}
	if prepared.Wait <= 0 {
		prepared.Wait = 5 * time.Second
	}
	if prepared.Timeout <= 0 {
		prepared.Timeout = 5 * time.Second
	}
	if prepared.MaxBodyBytes <= 0 {
		prepared.MaxBodyBytes = 1 << 20
	}
	strip := append([]string(nil), defaultMirrorStripHeaders...)
	seen := make(map[string]bool, len(strip)+len(prepared.StripHeaders))
	for _, name := range strip {
		seen[strings.ToLower(name)] = true
	}
	for _, name := range prepared.StripHeaders {
		if !seen[strings.ToLower(name)] {
			seen[strings.ToLower(name)] = true
			strip = append(strip, name)
		}
	}
	prepared.StripHeaders = strip
	if prepared.TeeQueue <= 0 {
		prepared.TeeQueue = 64
	}
	if prepared.TeeTimeout <= 0 {
		prepared.TeeTimeout = 5 * time.Second
	}
	switch prepared.Mode {
	case MirrorUpstream:
		if len(prepared.Targets) == 0 {
			return nil, errs.Detail(ErrInvalidConfig, "mirror mode upstream needs targets | 影子上游模式需要目标")
		}
		prepared.targets = make([]*url.URL, 0, len(prepared.Targets))
		for _, raw := range prepared.Targets {
			parsed, err := url.Parse(raw)
			if err != nil || !parsed.IsAbs() || parsed.Host == "" ||
				(parsed.Scheme != "http" && parsed.Scheme != "https") {
				return nil, errs.Detail(ErrInvalidConfig, "invalid mirror target %q | 非法的镜像目标 %q", raw, raw)
			}
			prepared.targets = append(prepared.targets, parsed)
		}
	case MirrorTee:
		if len(prepared.TeeSinks) == 0 && len(prepared.TeeEventSinks) == 0 {
			return nil, errs.Detail(ErrInvalidConfig, "mirror mode tee needs sinks | 镜像 tee 模式需要 sink")
		}
	default:
		return nil, errs.Detail(ErrInvalidConfig, "unknown mirror mode %q | 未知镜像模式 %q", prepared.Mode, prepared.Mode)
	}
	return &prepared, nil
}

// WithMirror sets the client-wide mirror policy. | WithMirror 设置客户端级镜像策略。
func WithMirror(policy MirrorPolicy) Option {
	return func(o *options) error {
		prepared, err := prepareMirror(&policy)
		if err != nil {
			return err
		}
		o.Mirror = prepared
		return nil
	}
}

// WithMaxMirrorInflight bounds concurrent shadow requests. | WithMaxMirrorInflight 限制并发影子请求。
func WithMaxMirrorInflight(n int) Option {
	return func(o *options) error {
		if n <= 0 {
			return errs.Detail(ErrInvalidConfig, "max mirror inflight must be positive | 最大镜像并发必须为正")
		}
		o.MaxMirrorInflight = n
		return nil
	}
}

// mirrorTrackKey carries a per-request mirror result collector. | mirrorTrackKey 携带逐请求的镜像结果收集器。
type mirrorTrackKey struct{}

// MirrorResults is a concurrent shadow-result collector for asynchronous
// mirrors. | MirrorResults 是异步镜像的并发安全结果收集器。
type MirrorResults struct {
	mu      sync.Mutex
	results []MirrorResult
}

// Snapshot returns a safe copy of all completed shadow results. | Snapshot 返回全部已完成影子结果的安全副本。
func (t *MirrorResults) Snapshot() []MirrorResult {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]MirrorResult(nil), t.results...)
}

// add appends one result. | add 追加一个结果。
func (t *MirrorResults) add(result MirrorResult) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.results = append(t.results, result)
	t.mu.Unlock()
}

// snapshot returns a copy of the collected results. | snapshot 返回已收集结果的副本。
func (t *MirrorResults) snapshot() []MirrorResult {
	return t.Snapshot()
}

// recordMirror appends a shadow result to the request tracker. | recordMirror 把影子结果追加到请求收集器。
func recordMirror(ctx context.Context, result MirrorResult) {
	if ctx == nil {
		return
	}
	if tracker, ok := ctx.Value(mirrorTrackKey{}).(*MirrorResults); ok {
		tracker.add(result)
	}
}

// mirrorer runs shadow upstream requests with bounded concurrency. | mirrorer 以有界并发运行影子上游请求。
type mirrorer struct {
	base   http.RoundTripper
	ctx    context.Context
	sem    chan struct{}
	cancel context.CancelFunc
	engine *engine
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
}

// newMirrorer builds a mirrorer; a zero max uses 64. | newMirrorer 构建 mirrorer；max 为 0 时使用 64。
func newMirrorer(base http.RoundTripper, max int) *mirrorer {
	if max <= 0 {
		max = 64
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &mirrorer{
		base:   base,
		sem:    make(chan struct{}, max),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Close cancels and waits for every shadow request. | Close 取消并等待全部影子请求。
func (m *mirrorer) Close() {
	_ = m.CloseContext(context.Background())
}

// CloseContext cancels shadows and bounds the wait by ctx. | CloseContext 取消影子请求并以 ctx 限制等待。
func (m *mirrorer) CloseContext(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// active reports whether new shadows may be reserved. | active 报告是否还能预留新影子请求。
func (m *mirrorer) active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && m.ctx.Err() == nil
}

// reserve registers one shadow before Close can start waiting. | reserve 在 Close 开始等待前登记一个影子请求。
func (m *mirrorer) reserve() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return false
	}
	m.wg.Add(1)
	return true
}

// submit samples and schedules shadow replays. | submit 抽样并调度影子重放。
func (m *mirrorer) submit(parent context.Context, req *http.Request, logical *url.URL, rule *Rule, policy *MirrorPolicy, sp *spool) {
	if m == nil || policy == nil || policy.Mode != MirrorUpstream || len(policy.targets) == 0 || !m.active() {
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
		if m.ctx.Err() != nil {
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
		if sp != nil {
			sp.retain()
		}
		local.Add(1)
		go func(target *url.URL) {
			defer m.wg.Done()
			defer local.Done()
			defer func() { <-m.sem }()
			if sp != nil {
				defer sp.release()
			}
			m.run(parent, req, logical, rule, policy, target, getBody)
		}(target)
	}
	if policy.Sync {
		waitGroup(&local, policy.Wait)
	}
}

// run executes one shadow request against target. | run 对一个目标执行影子请求。
func (m *mirrorer) run(parent context.Context, req *http.Request, logical *url.URL, rule *Rule, policy *MirrorPolicy, target *url.URL, getBody func() (io.ReadCloser, error)) {
	start := time.Now()
	result := MirrorResult{Target: target.String()}
	defer func() {
		result.Duration = time.Since(start)
		recordMirror(req.Context(), result)
	}()
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
	if getBody != nil {
		body, err := getBody()
		if err != nil {
			result.Err = err
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
		closeResponseBody(resp)
		err = redactRequestError(err, out.URL)
		result.Err = err
		if m.engine != nil {
			m.engine.counters.mirrorErrors.Add(1)
		}
		return
	}
	if resp == nil {
		result.Err = ErrInvalidResponse
		if m.engine != nil {
			m.engine.counters.mirrorErrors.Add(1)
		}
		return
	}
	result.Status = resp.StatusCode
	drainAndClose(resp.Body, policy.MaxBodyBytes)
}

// drop records a dropped mirror payload. | drop 记录丢弃的镜像载荷。
func (m *mirrorer) drop(target, reason string) {
	if m == nil || m.engine == nil {
		return
	}
	m.engine.mirrorDrops.Add(1)
	if m.engine.hooks.OnMirrorDrop != nil {
		_ = callHook(func() error {
			m.engine.hooks.OnMirrorDrop(context.Background(), MirrorInfo{Target: target}, reason)
			return nil
		})
	}
}

// mirrorSampled reports whether the request is selected by Percent. | mirrorSampled 报告请求是否被 Percent 选中。
func mirrorSampled(logical *url.URL, rule *Rule, percent int) bool {
	if percent >= 100 {
		return true
	}
	hash := uint32(2166136261)
	if logical != nil {
		hash = fnv32aUpdate(hash, logical.String())
	}
	if rule != nil {
		hash = fnv32aUpdate(hash, rule.Name)
	}
	return int(hash%100) < percent
}

// waitGroup waits for wg or the timeout. | waitGroup 等待 wg 或超时。
func waitGroup(wg *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// mirrorFor resolves the rule or client mirror policy. | mirrorFor 解析规则或客户端镜像策略。
func (e *engine) mirrorFor(rule *Rule) (*MirrorPolicy, bool) {
	if rule != nil && rule.Mirror != nil {
		return rule.Mirror, true
	}
	if e.opts.Mirror != nil {
		return e.opts.Mirror, true
	}
	return nil, false
}
