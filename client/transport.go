package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// engine is the policy RoundTripper behind a Client. | engine 是 Client 背后的策略 RoundTripper。
type engine struct {
	hooks      Hooks
	base       http.RoundTripper
	cacheStore Store
	rules      atomic.Pointer[RuleSet]
	hosts      atomic.Pointer[HostSet]
	budget     *retryBudget
	budgets    map[float64]*retryBudget
	budgetMu   sync.Mutex
	closed     atomic.Bool
	bare       atomic.Bool
	ipGuard    bool

	flights *flightGroup
	mirrors *mirrorer

	baseTransport *http.Transport
	h2c           *http.Transport
	scheme        *schemeTransport
	tlsByConfig   map[*TLSConfig]*tlsState
	hostTLS       map[string]*tlsState
	defaultTLS    *tlsState

	ua          *UAPolicy
	opts        options
	tlsStates   []*tlsState
	counters    counters
	mirrorDrops atomic.Uint64

	uaCounter atomic.Uint64

	cacheMu      sync.RWMutex
	tlsMu        sync.RWMutex
	ruleHostsMu  sync.Mutex
	ruleHosts    map[*HostSet]struct{}
	retiredHosts []*HostSet
	ownsCache    bool
}

// newEngine builds the engine and a default transport when none was supplied. | newEngine 构建引擎，并在未提供 Transport 时创建默认传输。
func newEngine(o options, rules *RuleSet) (*engine, error) {
	base := o.Transport
	ipGuard := false
	var baseTransport *http.Transport
	guardNeeded := hasIPCheckPolicies(o, rules)
	if base == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		if o.AccessPolicy != nil {
			dialer.Control = o.AccessPolicy.dialControl
		}
		baseTransport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		}
		installGuardedDial(baseTransport, dialer)
		ipGuard = true
		base = baseTransport
	} else if tr, ok := base.(*http.Transport); ok {
		if guardNeeded {
			if tr.Dial != nil || tr.DialContext != nil || tr.DialTLS != nil || tr.DialTLSContext != nil {
				return nil, errs.Detail(ErrInvalidConfig, "custom dialers cannot enforce the IP guard | 自定义拨号器无法执行 IP 守卫")
			}
			tr = tr.Clone()
			dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
			if o.AccessPolicy != nil {
				dialer.Control = o.AccessPolicy.dialControl
			}
			installGuardedDial(tr, dialer)
			ipGuard = true
			base = tr
		}
		baseTransport = tr
	} else if guardNeeded {
		return nil, errs.Detail(ErrInvalidConfig, "IP guard requires an *http.Transport | IP 守卫需要 *http.Transport")
	}
	var h2cTransport *http.Transport
	if o.H2C {
		if baseTransport == nil {
			return nil, errs.Detail(ErrInvalidConfig, "H2C needs an *http.Transport | H2C 需要 *http.Transport")
		}
		h2cTransport = baseTransport.Clone()
		protocols := new(http.Protocols)
		protocols.SetHTTP2(true)
		protocols.SetUnencryptedHTTP2(true)
		h2cTransport.Protocols = protocols
	}
	eng := &engine{
		base:          base,
		baseTransport: baseTransport,
		h2c:           h2cTransport,
		ipGuard:       ipGuard,
		opts:          o,
		budget:        newRetryBudget(0.1),
		budgets:       make(map[float64]*retryBudget),
		flights:       newFlightGroup(),
		tlsByConfig:   make(map[*TLSConfig]*tlsState),
		hostTLS:       make(map[string]*tlsState),
		ruleHosts:     make(map[*HostSet]struct{}),
	}
	if o.TLSConfig != nil {
		eng.noteInsecure(o.TLSConfig)
		state, err := newTLSState(*o.TLSConfig, baseTransport)
		if err != nil {
			return nil, err
		}
		eng.defaultTLS = state
		eng.tlsByConfig[o.TLSConfig] = state
		eng.tlsStates = append(eng.tlsStates, state)
	}
	for host, cfg := range o.HostTLS {
		eng.noteInsecure(&cfg)
		if baseTransport == nil {
			return nil, errs.Detail(ErrTLSConfig, "host TLS needs an *http.Transport | Host TLS 需要 *http.Transport")
		}
		state, err := newTLSState(cfg, baseTransport)
		if err != nil {
			return nil, err
		}
		eng.hostTLS[strings.ToLower(host)] = state
		eng.tlsStates = append(eng.tlsStates, state)
	}
	if h2cTransport != nil {
		secure := http.RoundTripper(baseTransport)
		if eng.defaultTLS != nil {
			secure = eng.defaultTLS.current()
		}
		eng.scheme = &schemeTransport{plain: h2cTransport, secure: secure, secureState: eng.defaultTLS}
	}
	mirrorBase := http.RoundTripper(base)
	if eng.defaultTLS != nil {
		mirrorBase = eng.defaultTLS.current()
	}
	eng.mirrors = newMirrorer(mirrorBase, o.MaxMirrorInflight)
	eng.mirrors.engine = eng
	eng.rules.Store(&RuleSet{})
	return eng, nil
}

// useDefaultHostsKey marks requests resolved from a relative URL or Forward. | useDefaultHostsKey 标记由相对 URL 或 Forward 解析出的请求。
type useDefaultHostsKey struct{}

// useDefaultHosts reports whether the default host pool may be used. | useDefaultHosts 报告是否允许使用默认 Host 池。
func useDefaultHosts(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(useDefaultHostsKey{}).(bool)
	return value
}

// tryBare executes a request without policy layers when possible. | tryBare 在可能时绕过策略层执行请求。
func (e *engine) tryBare(req *http.Request) (*http.Response, error, bool) {
	meta := metaFromContext(req.Context())
	hosts := e.hosts.Load()
	if hosts == nil {
		e.counters.requests.Add(1)
		e.counters.inflight.Add(1)
		if req.ContentLength > 0 {
			e.counters.bytesSent.Add(uint64(req.ContentLength))
		}
		start := time.Now()
		resp, err := e.defaultTransport().RoundTrip(req)
		e.counters.inflight.Add(-1)
		if err != nil {
			closeResponseBody(resp)
			e.counters.errors.Add(1)
			return nil, e.wrapError("roundtrip", req, "", 1, err), true
		}
		if resp == nil {
			e.counters.errors.Add(1)
			return nil, e.wrapError("roundtrip", req, "", 1, ErrInvalidResponse), true
		}
		if resp.ContentLength > 0 {
			e.counters.bytesReceived.Add(uint64(resp.ContentLength))
		}
		e.counters.responses.Add(1)
		return e.finishResponse(resp, req, meta, nil, 1, start), nil, true
	}
	if hosts.Len() != 1 {
		return nil, nil, false
	}
	if !canPassThroughHost(hosts.entries[0].host, nil, req.URL, req) {
		return nil, nil, false
	}
	host, err := hosts.Pick(req, nil)
	if err != nil {
		e.counters.errors.Add(1)
		return nil, e.wrapError("roundtrip", req, "", 0, err), true
	}
	transport, err := e.transportFor(host)
	if err != nil {
		hosts.MarkFailure(host, err)
		e.counters.errors.Add(1)
		return nil, e.wrapError("roundtrip", req, host.Name, 0, err), true
	}
	e.counters.requests.Add(1)
	e.counters.inflight.Add(1)
	if req.ContentLength > 0 {
		e.counters.bytesSent.Add(uint64(req.ContentLength))
	}
	start := time.Now()
	resp, err := transport.RoundTrip(req)
	e.counters.inflight.Add(-1)
	if err != nil {
		closeResponseBody(resp)
		if req.Context().Err() != nil {
			hosts.Release(host)
		} else {
			hosts.MarkFailure(host, err)
		}
		e.counters.errors.Add(1)
		return nil, e.wrapError("roundtrip", req, host.Name, 1, err), true
	}
	if resp == nil {
		hosts.MarkFailure(host, ErrInvalidResponse)
		e.counters.errors.Add(1)
		return nil, e.wrapError("roundtrip", req, host.Name, 1, ErrInvalidResponse), true
	}
	if resp.ContentLength > 0 {
		e.counters.bytesReceived.Add(uint64(resp.ContentLength))
	}
	if host.IsFailureStatus(resp.StatusCode) {
		hosts.MarkFailure(host, errs.Detail(ErrUpstreamStatus, "status %d", resp.StatusCode))
	} else {
		hosts.MarkSuccess(host)
	}
	e.counters.responses.Add(1)
	return e.finishResponse(resp, req, meta, host, 1, start), nil, true
}

// isBareEngine reports whether the engine can bypass all policy layers. | isBareEngine 报告引擎是否可绕过全部策略层。
func isBareEngine(o options, rules *RuleSet, hosts *HostSet) bool {
	if hosts != nil {
		if hosts.Len() != 1 {
			return false
		}
		host := hosts.entries[0].host
		if len(host.Headers) > 0 || host.URL.RawPath != "" || host.URL.RawQuery != "" || host.URL.ForceQuery ||
			host.URL.Fragment != "" || host.URL.User != nil || host.URL.Opaque != "" ||
			(host.URL.Path != "" && host.URL.Path != "/") {
			return false
		}
	}
	return (rules == nil || rules.Len() == 0) && o.Hooks.empty() &&
		o.Cache == nil && o.Coalesce == nil && o.Mirror == nil && o.Guard == nil &&
		o.AccessPolicy == nil && o.Retry == nil && o.UserAgent == nil && !o.Trace &&
		len(o.HostTLS) == 0 && o.ConnMode != ConnShort
}

// RoundTrip applies rules, host selection and retries before the base transport. | RoundTrip 在底层传输前应用规则、Host 选择与重试。
func (e *engine) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req != nil {
		defer func() {
			if err != nil && req.Body != nil {
				_ = req.Body.Close()
			}
		}()
	}
	if e.closed.Load() {
		return nil, ErrClosed
	}
	if req == nil || req.URL == nil {
		return nil, ErrInvalidConfig
	}
	if _, pathErr := matchPath(req.URL); pathErr != nil {
		return nil, e.wrapError("route", req, "", 0, pathErr)
	}
	if e.bare.Load() {
		if resp, tripErr, handled := e.tryBare(req); handled {
			return resp, tripErr
		}
	}
	if e.ua != nil && uaApplies(req, e.ua) {
		req = req.Clone(req.Context())
		e.applyUA(req, e.ua)
	}
	e.counters.requests.Add(1)
	e.counters.inflight.Add(1)
	defer e.counters.inflight.Add(-1)
	defer func() {
		if err != nil {
			e.counters.errors.Add(1)
			var clientErr *Error
			if !errors.As(err, &clientErr) {
				clientErr = e.wrapError("roundtrip", req, "", 0, err)
				err = clientErr
			}
			e.fireError(req.Context(), clientErr)
			return
		}
		if resp != nil {
			e.counters.responses.Add(1)
		}
	}()
	if hookErr := e.fireRequest(req.Context(), req); hookErr != nil {
		return nil, e.wrapError("hook", req, "", 0, hookErr)
	}
	meta := metaFromContext(req.Context())
	if meta != nil {
		meta.CacheHit = false
		meta.Coalesced = false
		meta.Rule = nil
		meta.Params.Reset()
		meta.Host = nil
		meta.Guard = nil
		meta.Attempts = 0
		meta.BytesSent = 0
		meta.BytesRead = 0
		meta.Timings = Timings{}
		meta.Mirrors = nil
		meta.MirrorResults = nil
	}
	var trace *traceTimings
	if meta != nil && e.opts.Trace {
		trace = newTraceTimings()
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace.clientTrace()))
	}
	rules := e.rules.Load()
	var rule *Rule
	var params Params
	if rules != nil {
		var matchErr error
		rule, params, _, matchErr = rules.matchRequest(req)
		if matchErr != nil {
			return nil, e.wrapError("route", req, "", 0, matchErr)
		}
	}
	if meta != nil {
		meta.Rule = rule
		meta.Params = params
	}
	if policies := dialPoliciesFor(e.opts, rule); len(policies) > 0 {
		req = req.WithContext(context.WithValue(req.Context(), dialPoliciesKey{}, policies))
	}
	if rule != nil && rule.UA != nil && uaApplies(req, rule.UA) {
		req = req.Clone(req.Context())
		e.applyUA(req, rule.UA)
	}
	if hookErr := e.fireRoute(req.Context(), req, rule, params); hookErr != nil {
		return nil, e.wrapError("hook", req, "", 0, hookErr)
	}
	if mode := e.connectionMode(rule); mode == ConnShort {
		req = req.WithContext(context.WithValue(req.Context(), connModeKey{}, mode))
	}
	if guard := e.guardFor(rule); guard != nil {
		decision, guardErr := callGuard(guard, req.Context(), req)
		if guardErr != nil {
			return nil, e.wrapError("guard", req, "", 0, errs.Wrap(guardErr, ErrGuard))
		}
		if meta != nil {
			meta.Guard = &decision
		}
		if !decision.Allowed {
			e.counters.blocked.Add(1)
			if e.hooks.OnBlocked != nil {
				_ = callHook(func() error {
					e.hooks.OnBlocked(req.Context(), req, decision)
					return nil
				})
			}
			message := decision.Message
			if message == "" {
				message = "blocked"
			}
			blocked := e.wrapError("guard", req, "", 0, errs.Detail(ErrBlocked, "%s", message))
			blocked.Status = decision.Status
			return nil, blocked
		}
	}
	hosts := e.hosts.Load()
	useDefault := useDefaultHosts(req.Context())
	if useDefault && !e.opts.RewriteAll {
		if expected := defaultHostFrom(req.Context()); expected != "" && !strings.EqualFold(req.URL.Host, expected) {
			useDefault = false
		}
	}
	if rule != nil && rule.HostSet != nil {
		hosts = rule.HostSet
	} else if !e.opts.RewriteAll && !useDefault {
		hosts = nil
	}
	policy, store, caching := e.cacheFor(rule)
	var key string
	if caching && (cacheReadable(req, policy) || cacheWritable(req, policy)) {
		key, _ = cacheKey(req, rule, &policy)
	}
	if caching && key != "" && cacheReadable(req, policy) {
		if entry, ok := store.Get(key); ok && entry.matches(req) {
			e.counters.cacheHits.Add(1)
			if e.hooks.OnCacheHit != nil {
				_ = callHook(func() error {
					e.hooks.OnCacheHit(req.Context(), req)
					return nil
				})
			}
			if req.Body != nil {
				_ = req.Body.Close()
			}
			if meta != nil {
				meta.CacheHit = true
				meta.Attempts = 0
				meta.BytesSent = req.ContentLength
				meta.BytesRead = int64(len(entry.Body))
				hopURL := meta.urlHint
				if hopURL == "" {
					hopURL = safeURL(req.URL)
				} else {
					meta.urlHint = ""
				}
				meta.Hops = append(meta.Hops, HopMeta{
					URL:      hopURL,
					Status:   entry.StatusCode,
					CacheHit: true,
				})
			}
			if trace != nil {
				meta.Timings = trace.finish()
			}
			return e.finalizeResponse(req, rule, meta, cachedResponse(req, entry))
		}
		e.counters.cacheMisses.Add(1)
		if e.hooks.OnCacheMiss != nil {
			_ = callHook(func() error {
				e.hooks.OnCacheMiss(req.Context(), req)
				return nil
			})
		}
	}
	var ruleCancel context.CancelFunc
	var forwardHeaderTimer *time.Timer
	var forwardHeaderDone chan struct{}
	var forwardTimedOut atomic.Bool
	if rule != nil && rule.Timeout > 0 && !streamingRequest(req.Context()) {
		if forwardNoDefaultRetry(req.Context()) {
			// Forward applies the rule timeout to upstream response headers only;
			// the body remains governed by the inbound context and BodyTimeout. | Forward
			// 的规则超时只覆盖上游响应头；正文由入站 ctx 与 BodyTimeout 控制。
			ctx, cancel := context.WithCancel(req.Context())
			req = req.WithContext(ctx)
			ruleCancel = cancel
			forwardHeaderDone = make(chan struct{})
			forwardHeaderTimer = time.AfterFunc(rule.Timeout, func() {
				forwardTimedOut.Store(true)
				cancel()
				close(forwardHeaderDone)
			})
		} else {
			ctx, cancel := context.WithTimeout(req.Context(), rule.Timeout)
			req = req.WithContext(ctx)
			ruleCancel = cancel
		}
	}
	mirrorPolicy, mirroring := e.mirrorFor(rule)
	var mirrorResults *MirrorResults
	if mirroring && !mirrorSampled(req.URL, rule, mirrorPolicy.Percent) {
		mirroring = false
	}
	if mirroring && mirrorPolicy.Mode == MirrorUpstream {
		mirrorResults = &MirrorResults{}
		req = req.WithContext(context.WithValue(req.Context(), mirrorTrackKey{}, mirrorResults))
	}
	var mirrorSpool *spool
	if mirroring && mirrorPolicy.Mode == MirrorUpstream && req.Body != nil && req.Body != http.NoBody &&
		req.GetBody == nil {
		// Mirror A must replay the body; a bounded disk spool is allowed even
		// when retry spooling itself is memory-only. | Mirror A 必须重放正文；即使
		// 重试仅允许内存暂存，也允许有界磁盘暂存。
		spooled, spoolErr := e.spoolBodyWith(req, true)
		if spoolErr != nil {
			return nil, e.wrapError("prepare_body", req, "", 0, spoolErr)
		}
		mirrorSpool = spooled
		defer spooled.release()
	}
	preMirror := mirroring && mirrorPolicy.Mode == MirrorUpstream && mirrorPolicy.Parallel && !mirrorPolicy.Sync
	if preMirror {
		if strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream") {
			e.mirrors.submitSSE(req.Context(), req, req.URL, rule, mirrorPolicy, mirrorSpool)
		} else {
			e.mirrors.submit(req.Context(), req, req.URL, rule, mirrorPolicy, mirrorSpool)
		}
	}
	postMirror := mirroring && mirrorPolicy.Mode == MirrorUpstream && !preMirror
	if coalescePolicy, ok := e.coalesceFor(rule); ok && shouldCoalesce(req, coalescePolicy) {
		resp, err = e.coalesceRoundTrip(req, rule, meta, hosts, key, policy, store, coalescePolicy, postMirror, mirrorSpool)
	} else {
		resp, err = e.execute(req, rule, meta, hosts, key, policy, store, postMirror, mirrorSpool)
	}
	if forwardHeaderTimer != nil {
		if !forwardHeaderTimer.Stop() {
			<-forwardHeaderDone
		}
	}
	if err != nil {
		if ruleCancel != nil {
			ruleCancel()
		}
		if forwardTimedOut.Load() {
			err = errs.Wrap(err, ErrForwardTimeout)
		}
		return nil, err
	}
	if forwardTimedOut.Load() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if ruleCancel != nil {
			ruleCancel()
		}
		return nil, errs.Detail(ErrForwardTimeout, "upstream response headers timed out | 上游响应头超时")
	}
	if meta != nil && mirrorResults != nil {
		meta.MirrorResults = mirrorResults
		meta.Mirrors = mirrorResults.snapshot()
	}
	if ruleCancel != nil {
		if resp.Body == nil {
			ruleCancel()
		} else {
			resp.Body = &cancelBody{body: resp.Body, cancel: ruleCancel}
		}
	}
	if trace != nil {
		meta.Timings = trace.finish()
	}
	return e.finalizeResponse(req, rule, meta, resp)
}

// finalizeResponse applies tee mirroring and the response hook. | finalizeResponse 应用 tee 镜像与响应钩子。
func (e *engine) finalizeResponse(req *http.Request, rule *Rule, meta *Meta, resp *http.Response) (*http.Response, error) {
	if resp == nil {
		return nil, e.wrapError("response", req, "", 0, ErrInvalidRequest)
	}
	// Forward's SSE path applies its own tee while copying; wrapping here would
	// deliver every chunk twice. | Forward 的 SSE 路径在复制时自行 tee；此处再包装会导致每个分块重复投递。
	if !(forwardCopySSE(req.Context()) && isEventStream(resp.Header)) {
		resp = e.applyTee(req, rule, resp)
	}
	if e.hooks.OnResponse != nil {
		metaValue := Meta{}
		if meta != nil {
			metaValue = *meta
		}
		if hookErr := e.fireResponse(req.Context(), &Response{Response: resp, Meta: metaValue}); hookErr != nil {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			return nil, e.wrapError("hook", req, "", 0, hookErr)
		}
	}
	return resp, nil
}

// execute runs the attempt loop and stores a cacheable response. | execute 执行尝试循环并存储可缓存响应。
func (e *engine) execute(req *http.Request, rule *Rule, meta *Meta, hosts *HostSet, key string, policy CachePolicy, store Store, scheduleMirror bool, sp *spool) (*http.Response, error) {
	var resp *http.Response
	var err error
	if hosts == nil || hosts.Len() == 0 {
		resp, err = e.roundTripDirect(req, rule, meta, sp)
	} else {
		resp, err = e.roundTripHosts(req, rule, meta, hosts, sp)
	}
	if err == nil && key != "" && resp != nil && cacheableStatus(policy, resp.StatusCode) {
		e.storeCacheResponse(resp, req, key, policy, store)
	}
	if err == nil && scheduleMirror {
		if mirrorPolicy, ok := e.mirrorFor(rule); ok && mirrorPolicy.Mode == MirrorUpstream {
			if isEventStream(resp.Header) {
				e.mirrors.submitSSE(req.Context(), req, req.URL, rule, mirrorPolicy, sp)
			} else {
				e.mirrors.submit(req.Context(), req, req.URL, rule, mirrorPolicy, sp)
			}
		}
	}
	return resp, err
}

// retryPolicy resolves the rule policy, the client policy, or the default. | retryPolicy 依次解析规则策略、客户端策略与默认策略。
func (e *engine) retryPolicy(req *http.Request, rule *Rule, hostCount int) RetryPolicy {
	if rule != nil && rule.Retry != nil {
		return rule.Retry.withDefaults(hostCount)
	}
	if e.opts.Retry != nil {
		return e.opts.Retry.withDefaults(hostCount)
	}
	if req != nil && forwardNoDefaultRetry(req.Context()) {
		return RetryPolicy{MaxAttempts: 1}.withDefaults(hostCount)
	}
	return defaultRetryPolicy(hostCount)
}

// roundTripDirect handles requests without a host pool; the original URL is used. | roundTripDirect 处理无 Host 池的请求，直接使用原 URL。
func (e *engine) roundTripDirect(req *http.Request, rule *Rule, meta *Meta, sp *spool) (*http.Response, error) {
	policy := e.retryPolicy(req, rule, 1)
	budget := e.budgetFor(policy.Budget)
	attempts := policy.MaxAttempts
	if !retryableMethod(policy, req) {
		attempts = 1
	}
	var err error
	ownedSpool := false
	if sp == nil && attempts > 1 && req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		sp, err = e.spoolBody(req)
		if err != nil {
			if errors.Is(err, errSpoolDowngrade) {
				attempts = 1
			} else {
				return nil, e.wrapError("prepare_body", req, "", 0, err)
			}
		} else {
			ownedSpool = true
		}
	}
	if ownedSpool {
		defer sp.release()
	}
	if sp == nil && attempts == 1 && (rule == nil || (len(rule.Headers) == 0 && rule.Rewrite == nil)) &&
		connModeFrom(req.Context()) != ConnShort && policy.PerAttemptTimeout <= 0 {
		if e.hooks.OnAttempt != nil {
			e.fireAttempt(req.Context(), AttemptInfo{Attempt: 1, Method: req.Method, URL: safeURL(req.URL)})
		}
		if req.ContentLength > 0 {
			e.counters.bytesSent.Add(uint64(req.ContentLength))
		}
		start := time.Now()
		resp, err := e.transportForURL(req.URL).RoundTrip(req)
		if err != nil {
			closeResponseBody(resp)
			return nil, e.wrapError("roundtrip", req, "", 1, err)
		}
		if resp == nil {
			return nil, e.wrapError("roundtrip", req, "", 1, ErrInvalidResponse)
		}
		if resp.ContentLength > 0 {
			e.counters.bytesReceived.Add(uint64(resp.ContentLength))
		}
		return e.finishResponse(resp, req, meta, nil, 1, start), nil
	}
	var lastErr error
	attempted := 0
	for attempt := 1; attempt <= attempts; attempt++ {
		attempted = attempt
		attemptReq, attemptCancel := attemptWithTimeout(req, policy.PerAttemptTimeout)
		target, targetErr := directTarget(attemptReq.URL, rule)
		if targetErr != nil {
			if attemptCancel != nil {
				attemptCancel()
			}
			return nil, e.wrapError("prepare_attempt", req, "", attempt-1, targetErr)
		}
		out, err := e.cloneAttempt(attemptReq, attempt, target, req.Host, rule, nil, sp)
		if err != nil {
			if attemptCancel != nil {
				attemptCancel()
			}
			return nil, e.wrapError("prepare_attempt", req, "", attempt-1, err)
		}
		if e.hooks.OnAttempt != nil {
			e.fireAttempt(req.Context(), AttemptInfo{Attempt: attempt, Method: req.Method, URL: safeURL(req.URL)})
		}
		if out.ContentLength > 0 {
			e.counters.bytesSent.Add(uint64(out.ContentLength))
		}
		start := time.Now()
		resp, err := e.transportForURL(out.URL).RoundTrip(out)
		if resp == nil && err == nil {
			err = ErrInvalidResponse
		}
		finishAttempt(resp, attemptCancel, err)
		if err != nil {
			lastErr = err
			if attempt >= attempts || policy.DisableNetworkRetry ||
				!retryableError(err, req.Context()) || !budget.allow() {
				break
			}
			delay := backoffDelay(policy, attempt)
			e.counters.retries.Add(1)
			e.fireRetry(req.Context(), RetryInfo{Attempt: attempt, Delay: delay, Reason: "network"})
			if err := sleepContext(req.Context(), delay); err != nil {
				lastErr = err
				break
			}
			continue
		}
		if resp.ContentLength > 0 {
			e.counters.bytesReceived.Add(uint64(resp.ContentLength))
		}
		if retryStatus(policy, resp.StatusCode) && attempt < attempts {
			if !budget.allow() {
				return e.finishResponse(resp, req, meta, nil, attempt, start), nil
			}
			delay := backoffDelay(policy, attempt)
			if !policy.DisableRetryAfter {
				if wait, ok := retryAfterValue(resp.Header, policy.MaxBackoff); ok {
					delay = wait
				}
			}
			drainAndClose(resp.Body, 64<<10)
			e.counters.retries.Add(1)
			e.fireRetry(req.Context(), RetryInfo{Attempt: attempt, Delay: delay, Reason: "status"})
			if err := sleepContext(req.Context(), delay); err != nil {
				lastErr = err
				break
			}
			continue
		}
		rewriteRedirectLocation(resp, out.URL, nil, rule)
		return e.finishResponse(resp, req, meta, nil, attempt, start), nil
	}
	if lastErr == nil {
		lastErr = ErrRetryExhausted
	}
	return nil, e.wrapError("roundtrip", req, "", attempted, errs.Wrap(lastErr, ErrRetryExhausted))
}

// roundTripHosts runs the failover attempt loop across a host pool. | roundTripHosts 在 Host 池上执行故障切换尝试循环。
func (e *engine) roundTripHosts(req *http.Request, rule *Rule, meta *Meta, hosts *HostSet, sp *spool) (*http.Response, error) {
	policy := e.retryPolicy(req, rule, hosts.Len())
	budget := e.budgetFor(policy.Budget)
	attempts := policy.MaxAttempts
	if !retryableMethod(policy, req) {
		attempts = 1
	}
	var err error
	ownedSpool := false
	if sp == nil && attempts > 1 && req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		sp, err = e.spoolBody(req)
		if err != nil {
			if errors.Is(err, errSpoolDowngrade) {
				attempts = 1
			} else {
				return nil, e.wrapError("prepare_body", req, "", 0, err)
			}
		} else {
			ownedSpool = true
		}
	}
	if ownedSpool {
		defer sp.release()
	}
	logical := req.URL
	originalHost := req.Host
	if originalHost == "" {
		originalHost = logical.Host
	}
	var tried map[string]struct{}
	var lastErr error
	attempted := 0
	var lastHost *Host
	for attempt := 1; attempt <= attempts; attempt++ {
		attempted = attempt
		host, pickErr := hosts.Pick(req, tried)
		if pickErr != nil && errors.Is(pickErr, ErrClosed) {
			// A hot reload retired the pool after this request snapshotted it;
			// retry against the replacement instead of failing the request. | 热更新
			// 在请求快照后退役了该池；改用替换池重试，避免请求失败。
			if current := e.hosts.Load(); current != nil && current != hosts && current.Len() > 0 {
				hosts = current
				tried = nil
				host, pickErr = hosts.Pick(req, nil)
			}
		}
		if pickErr != nil && errors.Is(pickErr, ErrNoHealthyHosts) && len(tried) > 0 {
			tried = make(map[string]struct{}, hosts.Len())
			host, pickErr = hosts.Pick(req, tried)
		}
		if pickErr != nil {
			if lastErr == nil {
				lastErr = pickErr
			}
			break
		}
		if tried != nil {
			tried[host.Name] = struct{}{}
		}
		lastHost = host
		e.fireHost(req.Context(), req, host)
		transport, transportErr := e.transportFor(host)
		if transportErr != nil {
			hosts.MarkFailure(host, transportErr)
			lastErr = transportErr
			break
		}
		if sp == nil && attempt == 1 && attempts == 1 && policy.PerAttemptTimeout <= 0 && canPassThroughHost(host, rule, logical, req) {
			if e.hooks.OnAttempt != nil {
				e.fireAttempt(req.Context(), AttemptInfo{Attempt: 1, Host: host, Method: req.Method, URL: safeURL(logical)})
			}
			if req.ContentLength > 0 {
				e.counters.bytesSent.Add(uint64(req.ContentLength))
			}
			start := time.Now()
			resp, err := transport.RoundTrip(req)
			if err != nil {
				closeResponseBody(resp)
				if req.Context().Err() != nil {
					hosts.Release(host)
				} else {
					hosts.MarkFailure(host, err)
				}
				return nil, e.wrapError("roundtrip", req, host.Name, 1, err)
			}
			if resp == nil {
				hosts.MarkFailure(host, ErrInvalidResponse)
				return nil, e.wrapError("roundtrip", req, host.Name, 1, ErrInvalidResponse)
			}
			if resp.ContentLength > 0 {
				e.counters.bytesReceived.Add(uint64(resp.ContentLength))
			}
			if host.IsFailureStatus(resp.StatusCode) {
				hosts.MarkFailure(host, errs.Detail(ErrUpstreamStatus, "status %d", resp.StatusCode))
			} else {
				hosts.MarkSuccess(host)
			}
			return e.finishResponse(resp, req, meta, host, 1, start), nil
		}
		attemptReq, attemptCancel := attemptWithTimeout(req, policy.PerAttemptTimeout)
		target, targetErr := targetURL(logical, host, rule)
		if targetErr != nil {
			if attemptCancel != nil {
				attemptCancel()
			}
			hosts.Release(host)
			lastErr = e.wrapError("prepare_attempt", req, host.Name, attempt-1, targetErr)
			break
		}
		out, prepErr := e.cloneAttempt(attemptReq, attempt, target, originalHost, rule, host, sp)
		if prepErr != nil {
			if attemptCancel != nil {
				attemptCancel()
			}
			hosts.Release(host)
			lastErr = prepErr
			break
		}
		if e.hooks.OnAttempt != nil {
			e.fireAttempt(req.Context(), AttemptInfo{Attempt: attempt, Host: host, Method: req.Method, URL: safeURL(logical)})
		}
		if out.ContentLength > 0 {
			e.counters.bytesSent.Add(uint64(out.ContentLength))
		}
		start := time.Now()
		resp, err := transport.RoundTrip(out)
		if resp == nil && err == nil {
			err = ErrInvalidResponse
		}
		finishAttempt(resp, attemptCancel, err)
		if err != nil {
			if req.Context().Err() != nil {
				hosts.Release(host)
			} else {
				hosts.MarkFailure(host, err)
			}
			lastErr = err
			if meta != nil {
				meta.Attempts = attempt
				meta.Host = host
			}
			if attempt >= attempts || policy.DisableNetworkRetry ||
				!retryableError(err, req.Context()) || !budget.allow() {
				break
			}
			delay := backoffDelay(policy, attempt)
			e.counters.retries.Add(1)
			e.fireRetry(req.Context(), RetryInfo{Attempt: attempt, Delay: delay, Reason: "network"})
			if err := sleepContext(req.Context(), delay); err != nil {
				lastErr = err
				break
			}
			if tried == nil {
				tried = make(map[string]struct{}, hosts.Len())
			}
			tried[host.Name] = struct{}{}
			continue
		}
		if resp.ContentLength > 0 {
			e.counters.bytesReceived.Add(uint64(resp.ContentLength))
		}
		if retryStatus(policy, resp.StatusCode) && attempt < attempts {
			if host.IsFailureStatus(resp.StatusCode) {
				hosts.MarkFailure(host, errs.Detail(ErrUpstreamStatus, "status %d", resp.StatusCode))
			} else {
				hosts.Release(host)
			}
			if !budget.allow() {
				return e.finishResponse(resp, req, meta, host, attempt, start), nil
			}
			delay := backoffDelay(policy, attempt)
			if !policy.DisableRetryAfter {
				if wait, ok := retryAfterValue(resp.Header, policy.MaxBackoff); ok {
					delay = wait
				}
			}
			drainAndClose(resp.Body, 64<<10)
			e.counters.retries.Add(1)
			e.fireRetry(req.Context(), RetryInfo{Attempt: attempt, Delay: delay, Reason: "status"})
			if err := sleepContext(req.Context(), delay); err != nil {
				lastErr = err
				break
			}
			if tried == nil {
				tried = make(map[string]struct{}, hosts.Len())
			}
			tried[host.Name] = struct{}{}
			continue
		}
		rewriteRedirectLocation(resp, out.URL, host, rule)
		if host.IsFailureStatus(resp.StatusCode) {
			hosts.MarkFailure(host, errs.Detail(ErrUpstreamStatus, "status %d", resp.StatusCode))
		} else {
			hosts.MarkSuccess(host)
		}
		return e.finishResponse(resp, req, meta, host, attempt, start), nil
	}
	if lastErr == nil {
		lastErr = ErrRetryExhausted
	}
	hostName := ""
	if lastHost != nil {
		hostName = lastHost.Name
	}
	return nil, e.wrapError("roundtrip", req, hostName, attempted, errs.Wrap(lastErr, ErrRetryExhausted))
}

// crossOriginRedirect reports whether req is a redirect hop that changes scheme, host or port. |
// crossOriginRedirect 报告 req 是否为改变 scheme、Host 或端口的重定向跳。
func crossOriginRedirect(req *http.Request) bool {
	if req == nil || req.Response == nil || req.Response.Request == nil || req.URL == nil {
		return false
	}
	previous := req.Response.Request.URL
	if previous == nil {
		return false
	}
	return !sameOrigin(previous, req.URL)
}

// sameOrigin reports whether a and b share a scheme and authority. | sameOrigin 报告 a 与 b 是否
// 具有相同 scheme 与 authority。
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	return strings.EqualFold(a.Host, b.Host)
}

// suppressInjectedKey marks a redirect hop on which rule and host headers must not be injected. |
// suppressInjectedKey 标记不得注入规则与 Host 头的重定向跳。
type suppressInjectedKey struct{}

// suppressInjectedHeaders reports whether header injection is disabled for the request. |
// suppressInjectedHeaders 报告请求是否禁用头注入。
func suppressInjectedHeaders(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, _ := ctx.Value(suppressInjectedKey{}).(bool)
	return value
}

// cloneAttempt clones the request for one attempt without mutating the caller's request. | cloneAttempt 为单次尝试克隆请求，不修改调用方请求。
func (e *engine) cloneAttempt(req *http.Request, attempt int, target *url.URL, originalHost string, rule *Rule, host *Host, sp *spool) (*http.Request, error) {
	out := req.Clone(req.Context())
	out.URL = target
	out.RequestURI = ""
	if req.Trailer != nil {
		out.Trailer = req.Trailer
	}
	suppressInjected := suppressInjectedHeaders(req.Context()) || crossOriginRedirect(req)
	if host != nil {
		explicitHost := req.Host != "" && (!strings.EqualFold(req.Host, req.URL.Host) || explicitHostFrom(req.Context()))
		preserve := (rule != nil && rule.PreserveHost) || explicitHost
		if forwardPreserveHost(out.Context()) {
			preserve = true
		}
		if preserve {
			out.Host = originalHost
		} else {
			out.Host = target.Host
		}
	}
	out.Close = req.Close || connModeFrom(out.Context()) == ConnShort
	// Request.Clone already deep-copied Header. | Request.Clone 已深拷贝 Header。
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	if suppressInjected {
		// A cross-origin hop must start from a clean credential surface: remove every rule and
		// host header, plus authentication headers copied by the standard redirect logic. |
		// 跨源跳必须从干净的凭据面开始：移除全部规则与 Host 头，以及标准重定向逻辑复制的认证头。
		if rule != nil {
			for key := range rule.Headers {
				out.Header.Del(key)
			}
		}
		if host != nil {
			for key := range host.Headers {
				out.Header.Del(key)
			}
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Www-Authenticate", "Cookie2"} {
			out.Header.Del(name)
		}
	}
	if rule != nil {
		for key, values := range rule.Headers {
			if suppressInjected {
				continue
			}
			if strings.EqualFold(key, "Host") {
				if len(values) > 0 {
					out.Host = values[len(values)-1]
				}
				continue
			}
			for _, value := range values {
				if strings.EqualFold(key, "Content-Type") {
					out.Header.Set(key, value)
				} else {
					out.Header.Add(key, value)
				}
			}
		}
	}
	if host != nil {
		for key, values := range host.Headers {
			if suppressInjected {
				continue
			}
			if strings.EqualFold(key, "Host") {
				if len(values) > 0 {
					out.Host = values[len(values)-1]
				}
				continue
			}
			for _, value := range values {
				if strings.EqualFold(key, "Content-Type") {
					out.Header.Set(key, value)
				} else {
					out.Header.Add(key, value)
				}
			}
		}
	}
	out.GetBody = req.GetBody
	switch {
	case sp != nil:
		body, err := sp.open()
		if err != nil {
			return nil, err
		}
		out.Body = body
		out.GetBody = sp.getBody
		out.ContentLength = sp.length
		out.TransferEncoding = nil
		out.Header.Del("Transfer-Encoding")
	case req.Body == nil:
		out.Body = nil
		out.GetBody = nil
	case req.Body == http.NoBody:
		out.Body = http.NoBody
	case attempt == 1:
		out.Body = req.Body
	case req.GetBody != nil:
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		out.Body = body
	default:
		return nil, ErrBodyNotReplayable
	}
	return out, nil
}

// canPassThroughHost reports whether the logical request already equals the host target. | canPassThroughHost 报告逻辑请求是否已等于 Host 目标。
func canPassThroughHost(host *Host, rule *Rule, logical *url.URL, req *http.Request) bool {
	if host == nil || host.URL == nil || logical == nil || req == nil {
		return false
	}
	if logical.User != nil {
		return false
	}
	if connModeFrom(req.Context()) == ConnShort {
		return false
	}
	if rule != nil && (len(rule.Headers) > 0 || rule.Rewrite != nil || rule.PreserveHost) {
		return false
	}
	if len(host.Headers) > 0 || host.URL.RawPath != "" || host.URL.RawQuery != "" || host.URL.ForceQuery ||
		host.URL.Fragment != "" || host.URL.User != nil || host.URL.Opaque != "" {
		return false
	}
	if host.URL.Path != "" && host.URL.Path != "/" {
		return false
	}
	return host.URL.Scheme == logical.Scheme && host.URL.Host == logical.Host
}

// rewriteRedirectLocation maps a wire-space Location back to logical space
// after a host base path was prefixed. | rewriteRedirectLocation 把带 Host base
// path 的 wire 空间 Location 还原为逻辑空间。
func rewriteRedirectLocation(resp *http.Response, wire *url.URL, host *Host, rule *Rule) {
	if resp == nil || wire == nil || resp.Header == nil {
		return
	}
	base := ""
	if host != nil && host.URL != nil {
		base = host.URL.EscapedPath()
		if base == "/" {
			base = ""
		}
	}
	if base == "" && (rule == nil || rule.Rewrite == nil) {
		return
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return
	}
	resolved, err := wire.Parse(location)
	if err != nil || !strings.EqualFold(resolved.Scheme, wire.Scheme) || !strings.EqualFold(resolved.Host, wire.Host) {
		return
	}
	path := resolved.EscapedPath()
	if base != "" {
		if path != base && !strings.HasPrefix(path, base+"/") && !(strings.HasSuffix(base, "/") && strings.HasPrefix(path, base)) {
			return
		}
		path = strings.TrimPrefix(path, base)
	}
	if path == "" {
		path = "/"
	} else if path[0] != '/' {
		path = "/" + path
	}
	trimmed := unrewritePath(rule, path)
	if resolved.RawQuery != "" {
		trimmed += "?" + resolved.RawQuery
	}
	if resolved.Fragment != "" {
		trimmed += "#" + resolved.EscapedFragment()
	}
	resp.Header.Set("Location", trimmed)
}

// unrewritePath reverses a rule Rewrite for redirect mapping. | unrewritePath 为重定向映射反向应用规则 Rewrite。
func unrewritePath(rule *Rule, path string) string {
	if rule == nil || rule.Rewrite == nil {
		return path
	}
	rw := rule.Rewrite
	if rw.AddPrefix != "" {
		prefix := strings.TrimSuffix(rw.AddPrefix, "/")
		if path == prefix {
			path = "/"
		} else if strings.HasPrefix(path, prefix+"/") {
			path = strings.TrimPrefix(path, prefix)
		}
	}
	if rw.StripPrefix != "" {
		path = strings.TrimSuffix(rw.StripPrefix, "/") + path
	}
	if path == "" {
		return "/"
	}
	return path
}

// directTarget applies a rule rewrite without a host base path. It rejects rewrites that resolve
// outside the root. | directTarget 在无 Host base path 时应用规则重写。解析到根之外的重写会被拒绝。
func directTarget(logical *url.URL, rule *Rule) (*url.URL, error) {
	target := *logical
	if rule == nil || rule.Rewrite == nil {
		return &target, nil
	}
	escaped := logical.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	escaped = applyRewrite(rule.Rewrite, escaped)
	rawPath, path, err := resolveTargetPaths(escaped)
	if err != nil {
		return nil, err
	}
	target.RawPath = rawPath
	target.Path = path
	return &target, nil
}

// targetURL builds the wire URL from the logical URL, the rule rewrite and the host base path. It
// rejects rewrites or request paths whose dot segments escape the host base path. | targetURL 由
// 逻辑 URL、规则重写与 Host base path 构造连接 URL。点段越出 Host base path 的重写或请求路径会被
// 拒绝。
func targetURL(logical *url.URL, host *Host, rule *Rule) (*url.URL, error) {
	target := *host.URL
	escaped := logical.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	if rule != nil && rule.Rewrite != nil {
		escaped = applyRewrite(rule.Rewrite, escaped)
	}
	rawPath, path, err := targetPathForms(target.Path, target.EscapedPath(), escaped)
	if err != nil {
		return nil, err
	}
	target.RawPath = rawPath
	target.Path = path
	target.RawQuery, target.ForceQuery = mergeQueries(host.URL, logical)
	target.Fragment = ""
	return &target, nil
}

// mergeQueries combines a host base URL query with the logical request query. | mergeQueries
// 合并 Host base URL 查询与逻辑请求查询。
func mergeQueries(host, logical *url.URL) (string, bool) {
	hostQuery, hostForce := "", false
	logicalQuery, logicalForce := "", false
	if host != nil {
		hostQuery, hostForce = host.RawQuery, host.ForceQuery
	}
	if logical != nil {
		logicalQuery, logicalForce = logical.RawQuery, logical.ForceQuery
	}
	switch {
	case hostQuery == "" && logicalQuery == "":
		return "", hostForce || logicalForce
	case hostQuery == "":
		return logicalQuery, logicalForce
	case logicalQuery == "":
		return hostQuery, hostForce || logicalForce
	default:
		return hostQuery + "&" + logicalQuery, false
	}
}

// finishResponse attaches metadata to a returned response. | finishResponse 给返回的响应附加元数据。
func (e *engine) finishResponse(resp *http.Response, req *http.Request, meta *Meta, host *Host, attempt int, start time.Time) *http.Response {
	if resp == nil {
		return nil
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Request = req
	if meta != nil {
		meta.Attempts = attempt
		meta.BytesSent = req.ContentLength
		meta.BytesRead = resp.ContentLength
		hopURL := meta.urlHint
		if hopURL != "" {
			meta.urlHint = ""
		} else {
			hopURL = safeURL(req.URL)
		}
		hostName := ""
		if host != nil {
			meta.Host = host
			hostName = host.Name
		}
		meta.Hops = append(meta.Hops, HopMeta{
			URL:      hopURL,
			Host:     hostName,
			Status:   resp.StatusCode,
			Duration: time.Since(start),
		})
	}
	return resp
}

// safeURL formats a URL without query or userinfo. | safeURL 格式化不含查询与 userinfo 的 URL。
func safeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Host == "" {
		return u.Path
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// wrapError builds a client error without leaking query or credentials. | wrapError 构建不泄露查询与凭据的客户端错误。
func (e *engine) wrapError(op string, req *http.Request, host string, attempts int, err error) *Error {
	if err == nil {
		err = ErrRetryExhausted
	}
	if isTLSError(err) && !errors.Is(err, ErrTLS) {
		err = errs.Wrap(err, ErrTLS)
	}
	err = redactRequestError(err, req.URL)
	return &Error{
		Op:       op,
		Method:   req.Method,
		URL:      safeURL(req.URL),
		Host:     host,
		Attempts: attempts,
		Err:      err,
	}
}

// CloseIdleConnections closes idle connections for base and TLS transports. | CloseIdleConnections 关闭基础与 TLS 传输的空闲连接。
func (e *engine) CloseIdleConnections() {
	if e == nil {
		return
	}
	e.closeIdleConnections()
	e.closeTLSIdle()
}

// closeIdleConnections releases idle connections held by the base transport. | closeIdleConnections 释放底层传输持有的空闲连接。
func (e *engine) closeIdleConnections() {
	if closer, ok := e.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	if e.h2c != nil {
		e.h2c.CloseIdleConnections()
	}
}

// traceTimings collects httptrace callbacks under a mutex; the callbacks may
// run concurrently and may fire after RoundTrip returns. | traceTimings 在互斥锁
// 下收集 httptrace 回调；这些回调可能并发执行，也可能在 RoundTrip 返回后触发。
type traceTimings struct {
	hopStart time.Time
	dnsStart time.Time
	tlsStart time.Time
	connects map[string]time.Time
	timings  Timings
	mu       sync.Mutex
	finished bool
}

// newTraceTimings starts one hop's timing collection. | newTraceTimings 开始一跳的计时收集。
func newTraceTimings() *traceTimings {
	return &traceTimings{hopStart: time.Now(), connects: make(map[string]time.Time, 2)}
}

// clientTrace builds the guarded httptrace callbacks. | clientTrace 构建带保护的 httptrace 回调。
func (t *traceTimings) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.mu.Lock()
			if !t.finished {
				t.dnsStart = time.Now()
			}
			t.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.mu.Lock()
			if !t.finished && !t.dnsStart.IsZero() {
				t.timings.DNS = time.Since(t.dnsStart)
			}
			t.mu.Unlock()
		},
		ConnectStart: func(network, addr string) {
			t.mu.Lock()
			if !t.finished {
				t.connects[network+"\x00"+addr] = time.Now()
			}
			t.mu.Unlock()
		},
		ConnectDone: func(network, addr string, _ error) {
			key := network + "\x00" + addr
			t.mu.Lock()
			if !t.finished {
				if start, ok := t.connects[key]; ok {
					if elapsed := time.Since(start); elapsed > t.timings.Connect {
						t.timings.Connect = elapsed
					}
					delete(t.connects, key)
				}
			}
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			if !t.finished {
				t.tlsStart = time.Now()
			}
			t.mu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			t.mu.Lock()
			if !t.finished && !t.tlsStart.IsZero() {
				t.timings.TLSHandshake = time.Since(t.tlsStart)
			}
			t.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			if !t.finished {
				t.timings.TTFB = time.Since(t.hopStart)
			}
			t.mu.Unlock()
		},
	}
}

// finish freezes the timings snapshot; later callbacks become no-ops. | finish
// 冻结计时快照；后续回调不再生效。
func (t *traceTimings) finish() Timings {
	t.mu.Lock()
	t.finished = true
	t.timings.Total = time.Since(t.hopStart)
	out := t.timings
	t.connects = nil
	t.mu.Unlock()
	return out
}

// cancelBody cancels a request-scoped context when the body is exhausted or closed. | cancelBody 在正文读完或关闭时取消请求级 context。
type cancelBody struct {
	body interface {
		Read([]byte) (int, error)
		Close() error
	}
	cancel context.CancelFunc
	once   sync.Once
}

// Read reads from the wrapped body and cancels on EOF or error. | Read 从包装的正文读取，并在 EOF 或错误时取消。
func (b *cancelBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if err != nil {
		b.stop()
	}
	return n, err
}

// Close closes the wrapped body and cancels the request context. | Close 关闭包装的正文并取消请求 context。
func (b *cancelBody) Close() error {
	b.stop()
	return b.body.Close()
}

// stop cancels the context exactly once. | stop 只取消一次 context。
func (b *cancelBody) stop() {
	b.once.Do(b.cancel)
}
