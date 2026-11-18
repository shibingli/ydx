package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// engine is the policy RoundTripper behind a Client. | engine 是 Client 背后的策略 RoundTripper。
type engine struct {
	base   http.RoundTripper
	opts   options
	rules  atomic.Pointer[RuleSet]
	hosts  atomic.Pointer[HostSet]
	budget *retryBudget

	cacheMu    sync.Mutex
	cacheStore Store
	ownsCache  bool

	flights     *flightGroup
	mirrors     *mirrorer
	mirrorDrops atomic.Uint64

	baseTransport *http.Transport
	tlsMu         sync.Mutex
	tlsByConfig   map[*TLSConfig]*tlsState
	tlsStates     []*tlsState
	hostTLS       map[string]*tlsState
	defaultTLS    *tlsState

	ua        *UAPolicy
	uaCounter atomic.Uint64
	hooks     Hooks
	counters  counters
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
	if o.H2C {
		if baseTransport == nil {
			return nil, errs.Detail(ErrInvalidConfig, "H2C needs an *http.Transport | H2C 需要 *http.Transport")
		}
		protocols := new(http.Protocols)
		protocols.SetHTTP2(true)
		protocols.SetUnencryptedHTTP2(true)
		baseTransport.Protocols = protocols
	}
	eng := &engine{
		base:          base,
		baseTransport: baseTransport,
		opts:          o,
		budget:        newRetryBudget(0.1),
		flights:       newFlightGroup(),
		tlsByConfig:   make(map[*TLSConfig]*tlsState),
		hostTLS:       make(map[string]*tlsState),
	}
	if o.TLSConfig != nil {
		state, err := newTLSState(*o.TLSConfig, baseTransport)
		if err != nil {
			return nil, err
		}
		eng.defaultTLS = state
		eng.tlsByConfig[o.TLSConfig] = state
		eng.tlsStates = append(eng.tlsStates, state)
	}
	for host, cfg := range o.HostTLS {
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

// RoundTrip applies rules, host selection and retries before the base transport. | RoundTrip 在底层传输前应用规则、Host 选择与重试。
func (e *engine) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req == nil || req.URL == nil {
		return nil, ErrInvalidConfig
	}
	if e.ua != nil {
		req = req.Clone(req.Context())
		e.applyUA(req)
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
			return nil, e.wrapError("guard", req, "", 0, errs.Detail(ErrBlocked, "%s", message))
		}
	}
	hosts := e.hosts.Load()
	if rule != nil && rule.HostSet != nil {
		hosts = rule.HostSet
	}
	policy, store, caching := e.cacheFor(rule)
	var key string
	if caching && cacheableRequest(req, policy) {
		key, _ = cacheKey(req, rule, &policy)
		if entry, ok := store.Get(key); ok && entry.matches(req) {
			e.counters.cacheHits.Add(1)
			if e.hooks.OnCacheHit != nil {
				_ = callHook(func() error {
					e.hooks.OnCacheHit(req.Context(), req)
					return nil
				})
			}
			if meta != nil {
				meta.CacheHit = true
				meta.Attempts = 0
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
	mirrorPolicy, mirroring := e.mirrorFor(rule)
	preMirror := mirroring && mirrorPolicy.Mode == MirrorUpstream && mirrorPolicy.Parallel && !mirrorPolicy.Sync
	if preMirror {
		if strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream") {
			e.mirrors.submitSSE(req.Context(), req, req.URL, rule, mirrorPolicy)
		} else {
			e.mirrors.submit(req.Context(), req, req.URL, rule, mirrorPolicy)
		}
	}
	postMirror := mirroring && mirrorPolicy.Mode == MirrorUpstream && !preMirror
	if coalescePolicy, ok := e.coalesceFor(rule); ok && shouldCoalesce(req, coalescePolicy) {
		resp, err = e.coalesceRoundTrip(req, rule, meta, hosts, key, policy, store, coalescePolicy, postMirror)
	} else {
		resp, err = e.execute(req, rule, meta, hosts, key, policy, store, postMirror)
	}
	if err != nil {
		return nil, err
	}
	return e.finalizeResponse(req, rule, meta, resp)
}

// finalizeResponse applies tee mirroring and the response hook. | finalizeResponse 应用 tee 镜像与响应钩子。
func (e *engine) finalizeResponse(req *http.Request, rule *Rule, meta *Meta, resp *http.Response) (*http.Response, error) {
	if resp == nil {
		return nil, e.wrapError("response", req, "", 0, ErrInvalidRequest)
	}
	resp = e.applyTee(rule, resp)
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
func (e *engine) execute(req *http.Request, rule *Rule, meta *Meta, hosts *HostSet, key string, policy CachePolicy, store Store, scheduleMirror bool) (*http.Response, error) {
	var resp *http.Response
	var err error
	if hosts == nil || hosts.Len() == 0 {
		resp, err = e.roundTripDirect(req, rule, meta)
	} else {
		resp, err = e.roundTripHosts(req, rule, meta, hosts)
	}
	if err == nil && key != "" && resp != nil && cacheableStatus(policy, resp.StatusCode) {
		e.storeCacheResponse(resp, req, key, policy, store)
	}
	if err == nil && scheduleMirror {
		if mirrorPolicy, ok := e.mirrorFor(rule); ok && mirrorPolicy.Mode == MirrorUpstream {
			if isEventStream(resp.Header) {
				e.mirrors.submitSSE(req.Context(), req, req.URL, rule, mirrorPolicy)
			} else {
				e.mirrors.submit(req.Context(), req, req.URL, rule, mirrorPolicy)
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
func (e *engine) roundTripDirect(req *http.Request, rule *Rule, meta *Meta) (*http.Response, error) {
	policy := e.retryPolicy(req, rule, 1)
	attempts := policy.MaxAttempts
	if !retryableMethod(policy, req.Method) {
		attempts = 1
	}
	var sp *spool
	var err error
	if attempts > 1 && req.Body != nil && req.GetBody == nil {
		sp, err = e.spoolBody(req)
		if err != nil {
			return nil, e.wrapError("prepare_body", req, "", 0, err)
		}
		defer sp.cleanup()
	}
	if attempts == 1 && (rule == nil || len(rule.Headers) == 0) && connModeFrom(req.Context()) != ConnShort {
		e.fireAttempt(req.Context(), AttemptInfo{Attempt: 1, Method: req.Method, URL: safeURL(req.URL)})
		if req.ContentLength > 0 {
			e.counters.bytesSent.Add(uint64(req.ContentLength))
		}
		start := time.Now()
		resp, err := e.defaultTransport().RoundTrip(req)
		if err != nil {
			return nil, e.wrapError("roundtrip", req, "", 1, err)
		}
		if resp.ContentLength > 0 {
			e.counters.bytesReceived.Add(uint64(resp.ContentLength))
		}
		return e.finishResponse(resp, req, meta, nil, 1, start), nil
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		target := *req.URL
		out, err := e.cloneAttempt(req, attempt, &target, req.Host, rule, nil, sp)
		if err != nil {
			return nil, e.wrapError("prepare_attempt", req, "", attempt-1, err)
		}
		e.fireAttempt(req.Context(), AttemptInfo{Attempt: attempt, Method: req.Method, URL: safeURL(req.URL)})
		if out.ContentLength > 0 {
			e.counters.bytesSent.Add(uint64(out.ContentLength))
		}
		start := time.Now()
		resp, err := e.defaultTransport().RoundTrip(out)
		if err != nil {
			lastErr = err
			if attempt >= attempts || policy.DisableNetworkRetry ||
				!retryableError(err, req.Context()) || !e.budget.allow() {
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
			if !e.budget.allow() {
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
	return nil, e.wrapError("roundtrip", req, "", attempts, errs.Wrap(lastErr, ErrRetryExhausted))
}

// roundTripHosts runs the failover attempt loop across a host pool. | roundTripHosts 在 Host 池上执行故障切换尝试循环。
func (e *engine) roundTripHosts(req *http.Request, rule *Rule, meta *Meta, hosts *HostSet) (*http.Response, error) {
	policy := e.retryPolicy(req, rule, hosts.Len())
	attempts := policy.MaxAttempts
	if !retryableMethod(policy, req.Method) {
		attempts = 1
	}
	var sp *spool
	var err error
	if attempts > 1 && req.Body != nil && req.GetBody == nil {
		sp, err = e.spoolBody(req)
		if err != nil {
			return nil, e.wrapError("prepare_body", req, "", 0, err)
		}
		defer sp.cleanup()
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
	var lastHost *Host
	for attempt := 1; attempt <= attempts; attempt++ {
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
		if attempt == 1 && attempts == 1 && canPassThroughHost(host, rule, logical, req) {
			e.fireAttempt(req.Context(), AttemptInfo{Attempt: 1, Host: host, Method: req.Method, URL: safeURL(logical)})
			if req.ContentLength > 0 {
				e.counters.bytesSent.Add(uint64(req.ContentLength))
			}
			start := time.Now()
			resp, err := transport.RoundTrip(req)
			if err != nil {
				hosts.MarkFailure(host, err)
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
		target := targetURL(logical, host, rule)
		out, prepErr := e.cloneAttempt(req, attempt, target, originalHost, rule, host, sp)
		if prepErr != nil {
			hosts.MarkFailure(host, prepErr)
			lastErr = prepErr
			break
		}
		e.fireAttempt(req.Context(), AttemptInfo{Attempt: attempt, Host: host, Method: req.Method, URL: safeURL(logical)})
		if out.ContentLength > 0 {
			e.counters.bytesSent.Add(uint64(out.ContentLength))
		}
		start := time.Now()
		resp, err := transport.RoundTrip(out)
		if err != nil {
			hosts.MarkFailure(host, err)
			lastErr = err
			if meta != nil {
				meta.Attempts = attempt
				meta.Host = host
			}
			if attempt >= attempts || policy.DisableNetworkRetry ||
				!retryableError(err, req.Context()) || !e.budget.allow() {
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
			if !e.budget.allow() {
				hosts.MarkFailure(host, errs.Detail(ErrUpstreamStatus, "status %d", resp.StatusCode))
				return e.finishResponse(resp, req, meta, host, attempt, start), nil
			}
			hosts.MarkFailure(host, errs.Detail(ErrUpstreamStatus, "status %d", resp.StatusCode))
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
	return nil, e.wrapError("roundtrip", req, hostName, attempts, errs.Wrap(lastErr, ErrRetryExhausted))
}

// cloneAttempt clones the request for one attempt without mutating the caller's request. | cloneAttempt 为单次尝试克隆请求，不修改调用方请求。
func (e *engine) cloneAttempt(req *http.Request, attempt int, target *url.URL, originalHost string, rule *Rule, host *Host, sp *spool) (*http.Request, error) {
	out := req.Clone(req.Context())
	out.URL = target
	out.RequestURI = ""
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
		body, err := sp.getBody()
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
	if len(host.Headers) > 0 || host.URL.RawPath != "" {
		return false
	}
	if host.URL.Path != "" && host.URL.Path != "/" {
		return false
	}
	return host.URL.Scheme == logical.Scheme && host.URL.Host == logical.Host
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
