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

	flights *flightGroup
	mirrors *mirrorer

	baseTransport *http.Transport
	h2c           *http.Transport
	tlsByConfig   map[*TLSConfig]*tlsState
	hostTLS       map[string]*tlsState
	defaultTLS    *tlsState

	ua          *UAPolicy
	opts        options
	tlsStates   []*tlsState
	counters    counters
	mirrorDrops atomic.Uint64

	uaCounter atomic.Uint64

	cacheMu     sync.Mutex
	tlsMu       sync.Mutex
	ruleHostsMu sync.Mutex
	ruleHosts   map[*HostSet]struct{}
	ownsCache   bool
}

// newEngine builds the engine and a default transport when none was supplied. | newEngine 构建引擎，并在未提供 Transport 时创建默认传输。
func newEngine(o options) (*engine, error) {
	base := o.Transport
	var baseTransport *http.Transport
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
		base = baseTransport
	} else if tr, ok := base.(*http.Transport); ok {
		baseTransport = tr
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
	if e.ua != nil {
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
	}
	if meta != nil && e.opts.Trace {
		hopStart := time.Now()
		defer func() { meta.Timings.Total = time.Since(hopStart) }()
		var dnsStart, connectStart, tlsStart time.Time
		trace := &httptrace.ClientTrace{
			DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
			DNSDone:              func(httptrace.DNSDoneInfo) { meta.Timings.DNS = time.Since(dnsStart) },
			ConnectStart:         func(string, string) { connectStart = time.Now() },
			ConnectDone:          func(string, string, error) { meta.Timings.Connect = time.Since(connectStart) },
			TLSHandshakeStart:    func() { tlsStart = time.Now() },
			TLSHandshakeDone:     func(tls.ConnectionState, error) { meta.Timings.TLSHandshake = time.Since(tlsStart) },
			GotFirstResponseByte: func() { meta.Timings.TTFB = time.Since(hopStart) },
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}
	rules := e.rules.Load()
	var rule *Rule
	var params Params
	if rules != nil {
		rule, params, _ = rules.MatchRequest(req)
	}
	if meta != nil {
		meta.Rule = rule
		meta.Params = params
	}
	if rule != nil && rule.UA != nil {
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
		decision, guardErr := guard.Check(req.Context(), req)
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
	if rule != nil && rule.HostSet != nil {
		hosts = rule.HostSet
	} else if !e.opts.RewriteAll && !useDefaultHosts(req.Context()) {
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
				meta.Hops = append(meta.Hops, HopMeta{
					URL:      safeURL(req.URL),
					Status:   entry.StatusCode,
					CacheHit: true,
				})
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
	if rule != nil && rule.Timeout > 0 && !forwardNoDefaultRetry(req.Context()) && !streamingRequest(req.Context()) {
		ctx, cancel := context.WithTimeout(req.Context(), rule.Timeout)
		req = req.WithContext(ctx)
		ruleCancel = cancel
	}
	mirrorPolicy, mirroring := e.mirrorFor(rule)
	var mirrorResults *mirrorTracker
	if mirroring {
		mirrorResults = &mirrorTracker{}
		req = req.WithContext(context.WithValue(req.Context(), mirrorTrackKey{}, mirrorResults))
	}
	var mirrorSpool *spool
	if mirroring && mirrorPolicy.Mode == MirrorUpstream && req.Body != nil && req.Body != http.NoBody &&
		req.GetBody == nil && (e.opts.SpoolToDisk || (e.opts.SpoolLimit > 0 && req.ContentLength > 0 && req.ContentLength <= e.opts.SpoolLimit)) {
		spooled, spoolErr := e.spoolBody(req)
		if spoolErr != nil {
			return nil, e.wrapError("prepare_body", req, "", 0, spoolErr)
		}
		mirrorSpool = spooled
		defer spooled.release()
		req.GetBody = spooled.getBody
		req.ContentLength = spooled.length
	} else if mirroring && mirrorPolicy.Mode == MirrorUpstream && req.Body != nil &&
		req.Body != http.NoBody && req.GetBody == nil {
		for _, target := range mirrorPolicy.targets {
			recordMirror(req.Context(), MirrorResult{Target: target.String(), Dropped: true, Err: ErrBodyNotReplayable})
		}
		mirroring = false
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
	if err != nil {
		if ruleCancel != nil {
			ruleCancel()
		}
		return nil, err
	}
	if meta != nil && mirrorResults != nil {
		meta.Mirrors = mirrorResults.snapshot()
	}
	if ruleCancel != nil {
		if resp.Body == nil {
			ruleCancel()
		} else {
			resp.Body = &cancelBody{body: resp.Body, cancel: ruleCancel}
		}
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
		resp = e.applyTee(rule, resp)
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
			return nil, e.wrapError("prepare_body", req, "", 0, err)
		}
		ownedSpool = true
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
			return nil, e.wrapError("roundtrip", req, "", 1, err)
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
		target := directTarget(attemptReq.URL, rule)
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
				if wait := retryAfterDelay(resp.Header, policy.MaxBackoff); wait > delay {
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
			return nil, e.wrapError("prepare_body", req, "", 0, err)
		}
		ownedSpool = true
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
	if attempts > 1 {
		tried = make(map[string]struct{}, hosts.Len())
	}
	var lastErr error
	attempted := 0
	var lastHost *Host
	for attempt := 1; attempt <= attempts; attempt++ {
		attempted = attempt
		host, pickErr := hosts.Pick(req, tried)
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
				if req.Context().Err() != nil {
					hosts.Release(host)
				} else {
					hosts.MarkFailure(host, err)
				}
				return nil, e.wrapError("roundtrip", req, host.Name, 1, err)
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
		target := targetURL(logical, host, rule)
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
				if wait := retryAfterDelay(resp.Header, policy.MaxBackoff); wait > delay {
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
		rewriteRedirectLocation(resp, out.URL, host)
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

// cloneAttempt clones the request for one attempt without mutating the caller's request. | cloneAttempt 为单次尝试克隆请求，不修改调用方请求。
func (e *engine) cloneAttempt(req *http.Request, attempt int, target *url.URL, originalHost string, rule *Rule, host *Host, sp *spool) (*http.Request, error) {
	out := req.Clone(req.Context())
	out.URL = target
	out.RequestURI = ""
	if req.Trailer != nil {
		out.Trailer = req.Trailer
	}
	if host != nil {
		preserve := rule != nil && rule.PreserveHost
		if forwardPreserveHost(out.Context()) {
			preserve = true
		}
		if preserve {
			out.Host = originalHost
		} else {
			out.Host = target.Host
		}
	}
	out.Close = connModeFrom(out.Context()) == ConnShort
	out.Header = req.Header.Clone()
	if out.Header == nil {
		out.Header = make(http.Header)
	}
	if rule != nil {
		for key, values := range rule.Headers {
			for _, value := range values {
				out.Header.Add(key, value)
			}
		}
	}
	if host != nil {
		for key, values := range host.Headers {
			for _, value := range values {
				out.Header.Add(key, value)
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
	case req.Body == nil:
		out.Body = nil
		out.GetBody = nil
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
	if connModeFrom(req.Context()) == ConnShort {
		return false
	}
	if rule != nil && (len(rule.Headers) > 0 || rule.Rewrite != nil || rule.PreserveHost) {
		return false
	}
	if len(host.Headers) > 0 || host.URL.RawPath != "" || host.URL.RawQuery != "" ||
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
func rewriteRedirectLocation(resp *http.Response, wire *url.URL, host *Host) {
	if resp == nil || wire == nil || host == nil || host.URL == nil || resp.Header == nil {
		return
	}
	base := host.URL.EscapedPath()
	if base == "" || base == "/" {
		return
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return
	}
	resolved, err := wire.Parse(location)
	if err != nil || resolved.Scheme != wire.Scheme || resolved.Host != wire.Host {
		return
	}
	path := resolved.EscapedPath()
	if path != base && !strings.HasPrefix(path, base+"/") && !(strings.HasSuffix(base, "/") && strings.HasPrefix(path, base)) {
		return
	}
	trimmed := strings.TrimPrefix(path, base)
	if trimmed == "" {
		trimmed = "/"
	} else if trimmed[0] != '/' {
		trimmed = "/" + trimmed
	}
	if resolved.RawQuery != "" {
		trimmed += "?" + resolved.RawQuery
	}
	resp.Header.Set("Location", trimmed)
}

// directTarget applies a rule rewrite without a host base path. | directTarget 在无 Host base path 时应用规则重写。
func directTarget(logical *url.URL, rule *Rule) *url.URL {
	target := *logical
	if rule == nil || rule.Rewrite == nil {
		return &target
	}
	escaped := logical.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	escaped = applyRewrite(rule.Rewrite, escaped)
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		decoded = escaped
	}
	target.RawPath = escaped
	target.Path = decoded
	return &target
}

// targetURL builds the wire URL from the logical URL, the rule rewrite and the host base path. | targetURL 由逻辑 URL、规则重写与 Host base path 构造连接 URL。
func targetURL(logical *url.URL, host *Host, rule *Rule) *url.URL {
	target := *host.URL
	escaped := logical.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	if rule != nil && rule.Rewrite != nil {
		escaped = applyRewrite(rule.Rewrite, escaped)
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		decoded = escaped
	}
	target.RawPath = joinBasePath(target.Path, escaped)
	target.Path = joinBasePath(target.Path, decoded)
	target.RawQuery = logical.RawQuery
	target.Fragment = ""
	return &target
}

// joinBasePath joins a host base path with a request path. | joinBasePath 拼接 Host base path 与请求路径。
func joinBasePath(base, path string) string {
	if base == "" || base == "/" {
		if path == "" {
			return "/"
		}
		if path[0] != '/' {
			return "/" + path
		}
		return path
	}
	base = strings.TrimSuffix(base, "/")
	if path == "" || path == "/" {
		return base + "/"
	}
	if path[0] != '/' {
		return base + "/" + path
	}
	return base + path
}

// finishResponse attaches metadata to a returned response. | finishResponse 给返回的响应附加元数据。
func (e *engine) finishResponse(resp *http.Response, req *http.Request, meta *Meta, host *Host, attempt int, start time.Time) *http.Response {
	if resp == nil {
		return nil
	}
	resp.Request = req
	if meta != nil {
		meta.Attempts = attempt
		meta.BytesSent = req.ContentLength
		meta.BytesRead = resp.ContentLength
		hostName := ""
		if host != nil {
			meta.Host = host
			hostName = host.Name
		}
		meta.Hops = append(meta.Hops, HopMeta{
			URL:      safeURL(req.URL),
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
	return &Error{
		Op:       op,
		Method:   req.Method,
		URL:      safeURL(req.URL),
		Host:     host,
		Attempts: attempts,
		Err:      err,
	}
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
