package client

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// HealthPolicy controls passive and active host health. | HealthPolicy 控制 Host 的被动与主动健康。
type HealthPolicy struct {
	// Path is the active health check path; empty means "/". | Path 是主动检查路径；为空表示 "/"。
	Path string
	// ExpectStatus lists accepted statuses; empty accepts 2xx. | ExpectStatus 列出可接受状态码；为空接受 2xx。
	ExpectStatus []int
	// FailStatus lists statuses the engine treats as host failures. | FailStatus 列出引擎视为 Host 失败的状态码。
	FailStatus []int
	// Interval is the active check interval; <=0 means 10s. | Interval 是主动检查间隔；<=0 表示 10s。
	Interval time.Duration
	// Timeout is one active check timeout; <=0 means 2s. | Timeout 是单次主动检查超时；<=0 表示 2s。
	Timeout time.Duration
	// FailThreshold is the consecutive failure count that opens the circuit; <=0 means 3. | FailThreshold 是打开熔断的连续失败数；<=0 表示 3。
	FailThreshold int
	// Cooldown is the initial unhealthy period; <=0 means 1s. | Cooldown 是初始不健康期；<=0 表示 1s。
	Cooldown time.Duration
	// MaxCooldown caps exponential cooldown; <=0 means 30s. | MaxCooldown 是冷却上限；<=0 表示 30s。
	MaxCooldown time.Duration
	// Active enables the periodic active health check. | Active 启用周期性主动健康检查。
	Active bool
}

// Host is one upstream base URL with selection and health settings. | Host 是一个带选择与健康设置的上游 base URL。
type Host struct {
	// URL is the base URL used for the host. | URL 是该 Host 使用的 base URL。
	URL *url.URL
	// Headers are added to requests sent to this host. | Headers 添加到发往该 Host 的请求。
	Headers http.Header
	// TLS overrides the client TLS configuration for this host. | TLS 为该 Host 覆盖客户端 TLS 配置。
	TLS *TLSConfig

	entry *hostEntry
	// Name identifies the host; empty derives it from URL. | Name 标识 Host；为空时由 URL 推导。
	Name string
	// Health configures passive and active health. | Health 配置被动与主动健康。
	Health HealthPolicy
	// Weight is the weighted round-robin weight; <=0 means 1. | Weight 是加权轮询权重；<=0 表示 1。
	Weight int
	// MaxInflight caps concurrent requests; 0 means unlimited. | MaxInflight 限制并发请求；0 表示不限制。
	MaxInflight int
}

// IsFailureStatus reports whether code is configured as a host failure. | IsFailureStatus 报告 code 是否配置为 Host 失败。
func (h *Host) IsFailureStatus(code int) bool {
	if h == nil {
		return false
	}
	for _, status := range h.Health.FailStatus {
		if status == code {
			return true
		}
	}
	return false
}

// HostStats is a point-in-time view of one host. | HostStats 是单个 Host 的时间点视图。
type HostStats struct {
	// CooldownUntil is when the host becomes eligible again. | CooldownUntil 是 Host 重新可用的时间。
	CooldownUntil time.Time
	// Name is the host name. | Name 是 Host 名称。
	Name string
	// Requests is the number of selected requests. | Requests 是被选中的请求数。
	Requests uint64
	// Failures is the number of recorded failures. | Failures 是记录的失败数。
	Failures uint64
	// Inflight is the current in-flight request count. | Inflight 是当前在途请求数。
	Inflight int64
	// Healthy reports the circuit state. | Healthy 报告熔断状态。
	Healthy bool
	// HalfOpen reports whether this host is the current half-open probe. | HalfOpen 报告该 Host 是否处于半开探测。
	HalfOpen bool
}

// hostEntry is the mutable state of one host. | hostEntry 是单个 Host 的可变状态。
type hostEntry struct {
	host *Host
	set  *HostSet

	inflight      atomic.Int64
	requests      atomic.Uint64
	failures      atomic.Uint64
	cooldownUntil atomic.Int64
	consecutive   atomic.Int32

	healthy       atomic.Bool
	halfOpen      atomic.Bool
	cooldownLevel atomic.Int32
}

// HostSetOptions configures a HostSet. | HostSetOptions 配置 HostSet。
type HostSetOptions struct {
	// HashKey derives the consistent-hash key; nil uses the URL path. | HashKey 生成一致性哈希键；nil 使用 URL 路径。
	HashKey func(*http.Request) string
	// Balance is the selection strategy; empty means weighted. | Balance 是选择策略；为空表示加权。
	Balance Balance
	// Wait bounds waiting for a full MaxInflight slot; 0 waits for the request
	// context, <0 disables waiting. | Wait 限制等待 MaxInflight 空位；0 等待请求
	// context，<0 禁用等待。
	Wait time.Duration
}

// HostSet is a mutable-health, immutable-membership host pool. | HostSet 是成员不可变、健康状态可变的 Host 池。
type HostSet struct {
	hashKey func(*http.Request) string
	now     func() time.Time

	healthCancel context.CancelFunc

	balance  Balance
	entries  []*hostEntry
	ring     []int
	healthWG sync.WaitGroup
	next     atomic.Uint64

	failOpen atomic.Uint64

	healthMu sync.Mutex
	waitMu   sync.Mutex
	waitCh   chan struct{}
	waiters  atomic.Int32
	closed   atomic.Bool

	wait          time.Duration
	healthStarted bool
}

// NewHostSet builds a weighted host pool with default options. | NewHostSet 用默认选项构建加权 Host 池。
func NewHostSet(hosts ...Host) (*HostSet, error) {
	return NewHostSetWithOptions(HostSetOptions{}, hosts...)
}

// NewHostSetWithOptions validates hosts and builds an immutable membership snapshot. | NewHostSetWithOptions 校验 Host 并构建不可变成员快照。
func NewHostSetWithOptions(opts HostSetOptions, hosts ...Host) (*HostSet, error) {
	if opts.Balance == "" {
		opts.Balance = BalanceWeighted
	}
	if !validBalance(opts.Balance) {
		return nil, errs.Detail(ErrUnknownBalance, "%q", string(opts.Balance))
	}
	if opts.HashKey == nil {
		opts.HashKey = func(req *http.Request) string {
			if req == nil || req.URL == nil {
				return ""
			}
			return req.URL.Path
		}
	}
	hs := &HostSet{balance: opts.Balance, hashKey: opts.HashKey, now: time.Now, wait: opts.Wait, waitCh: make(chan struct{})}
	seen := make(map[string]struct{}, len(hosts))
	totalWeight := 0
	for i := range hosts {
		host := hosts[i]
		if host.URL == nil || !host.URL.IsAbs() || host.URL.Host == "" ||
			(host.URL.Scheme != "http" && host.URL.Scheme != "https") {
			return nil, errs.Detail(ErrInvalidConfig, "invalid host URL | 非法的 Host URL")
		}
		cloned := *host.URL
		host.URL = &cloned
		if host.Name == "" {
			host.Name = host.URL.Host
			if _, exists := seen[host.Name]; exists {
				host.Name = host.URL.Host + host.URL.Path
			}
		}
		if _, exists := seen[host.Name]; exists || host.Name == "" {
			return nil, errs.Detail(ErrDuplicateHost, "%q", host.Name)
		}
		seen[host.Name] = struct{}{}
		if host.Weight <= 0 {
			host.Weight = 1
		}
		if host.Weight > 1000 {
			return nil, errs.Detail(ErrInvalidConfig, "host weight %d exceeds 1000 | Host 权重 %d 超过 1000", host.Weight, host.Weight)
		}
		totalWeight += host.Weight
		if totalWeight > 10000 {
			return nil, errs.Detail(ErrInvalidConfig, "total host weight exceeds 10000 | Host 总权重超过 10000")
		}
		if host.MaxInflight < 0 {
			return nil, errs.Detail(ErrInvalidConfig, "negative max inflight | 最大在途数为负")
		}
		if host.Headers != nil {
			host.Headers = host.Headers.Clone()
		}
		if host.TLS != nil {
			tlsCfg := cloneTLSConfig(*host.TLS)
			host.TLS = &tlsCfg
		}
		host.Health = normalizeHealth(host.Health)
		host.Health.FailStatus = append([]int(nil), host.Health.FailStatus...)
		entry := &hostEntry{host: &host, set: hs}
		entry.healthy.Store(true)
		host.entry = entry
		hs.entries = append(hs.entries, entry)
	}
	hs.ring = buildRing(hs.entries, totalWeight)
	return hs, nil
}

// normalizeHealth fills HealthPolicy defaults. | normalizeHealth 填充 HealthPolicy 默认值。
func normalizeHealth(h HealthPolicy) HealthPolicy {
	if h.Path == "" {
		h.Path = "/"
	}
	if h.Interval <= 0 {
		h.Interval = 10 * time.Second
	}
	if h.Timeout <= 0 {
		h.Timeout = 2 * time.Second
	}
	if h.FailThreshold <= 0 {
		h.FailThreshold = 3
	}
	if h.Cooldown <= 0 {
		h.Cooldown = time.Second
	}
	if h.MaxCooldown <= 0 {
		h.MaxCooldown = 30 * time.Second
	}
	if h.MaxCooldown < h.Cooldown {
		h.MaxCooldown = h.Cooldown
	}
	if len(h.FailStatus) == 0 {
		h.FailStatus = []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout}
	}
	return h
}

// FailOpen returns the number of fail-open selections. | FailOpen 返回 fail-open 选择次数。
func (hs *HostSet) FailOpen() uint64 {
	if hs == nil {
		return 0
	}
	return hs.failOpen.Load()
}

// Len returns the number of hosts. | Len 返回 Host 数量。
func (hs *HostSet) Len() int {
	if hs == nil {
		return 0
	}
	return len(hs.entries)
}

// AnyActive reports whether any host enables active health checks. | AnyActive 报告是否有 Host 启用主动健康检查。
func (hs *HostSet) AnyActive() bool {
	if hs == nil {
		return false
	}
	for _, entry := range hs.entries {
		if entry.host.Health.Active {
			return true
		}
	}
	return false
}

// firstBaseURL returns scheme://host of the first host for relative URLs. | firstBaseURL 返回第一个 Host 的 scheme://host，用于解析相对 URL。
func (hs *HostSet) firstBaseURL() *url.URL {
	if hs == nil || hs.closed.Load() || len(hs.entries) == 0 {
		return nil
	}
	first := hs.entries[0].host.URL
	return &url.URL{Scheme: first.Scheme, Host: first.Host}
}

// Pick selects an eligible host, applies fail-open when none is healthy, and
// increments its in-flight count; callers must MarkSuccess, MarkFailure or Release. | Pick
// 选择可用 Host，在全部不健康时 fail-open，并增加在途数；调用方必须 MarkSuccess、
// MarkFailure 或 Release。
func (hs *HostSet) Pick(req *http.Request, exclude map[string]struct{}) (*Host, error) {
	if hs == nil || hs.closed.Load() {
		return nil, ErrClosed
	}
	if len(hs.entries) == 0 {
		return nil, ErrNoHosts
	}
	var deadline time.Time
	if hs.wait > 0 {
		deadline = time.Now().Add(hs.wait)
	}
	host, err := hs.pickOnce(req, exclude)
	if err != ErrNoHealthyHosts || hs.wait < 0 || !hs.capacityLimited(exclude) {
		return host, err
	}
	for {
		hs.waiters.Add(1)
		signal := hs.waitSignal()
		host, err = hs.pickOnce(req, exclude)
		if err != ErrNoHealthyHosts || hs.wait < 0 || !hs.capacityLimited(exclude) {
			hs.waiters.Add(-1)
			return host, err
		}
		ctx := context.Background()
		if req != nil && req.Context() != nil {
			ctx = req.Context()
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			hs.waiters.Add(-1)
			return nil, ctx.Err()
		case <-signal:
			if timer != nil {
				timer.Stop()
			}
			hs.waiters.Add(-1)
		case <-timerC:
			hs.waiters.Add(-1)
			return nil, ErrNoHealthyHosts
		}
	}
}

// capacityLimited reports whether a host was excluded only by MaxInflight. | capacityLimited 报告 Host 是否仅因 MaxInflight 被排除。
func (hs *HostSet) capacityLimited(exclude map[string]struct{}) bool {
	for _, entry := range hs.entries {
		if entry.host.MaxInflight <= 0 {
			continue
		}
		if _, skipped := exclude[entry.host.Name]; skipped {
			continue
		}
		return true
	}
	return false
}

// waitSignal returns the channel closed on the next release. | waitSignal 返回下一次释放时关闭的通道。
func (hs *HostSet) waitSignal() <-chan struct{} {
	hs.waitMu.Lock()
	defer hs.waitMu.Unlock()
	if hs.waitCh == nil {
		hs.waitCh = make(chan struct{})
	}
	return hs.waitCh
}

// signalWait wakes every waiter after a slot is released. | signalWait 在释放名额后唤醒全部等待者。
func (hs *HostSet) signalWait() {
	if hs.waiters.Load() == 0 {
		return
	}
	hs.waitMu.Lock()
	if hs.waitCh != nil {
		close(hs.waitCh)
	}
	hs.waitCh = make(chan struct{})
	hs.waitMu.Unlock()
}

// pickOnce makes one host selection without waiting. | pickOnce 执行一次不等待的 Host 选择。
func (hs *HostSet) pickOnce(req *http.Request, exclude map[string]struct{}) (*Host, error) {
	if hs == nil || hs.closed.Load() {
		return nil, ErrClosed
	}
	if len(hs.entries) == 0 {
		return nil, ErrNoHosts
	}
	if len(hs.entries) == 1 {
		entry := hs.entries[0]
		_, excluded := exclude[entry.host.Name]
		if !excluded && entry.healthy.Load() && entry.acquire() {
			entry.requests.Add(1)
			return entry.host, nil
		}
	}
	now := hs.now()
	var inline [16]bool
	var eligible []bool
	if len(hs.entries) <= len(inline) {
		eligible = inline[:len(hs.entries)]
	} else {
		eligible = make([]bool, len(hs.entries))
	}
	anyEligible := false
	for i, entry := range hs.entries {
		if !hostSelectable(entry, exclude) {
			continue
		}
		if entry.eligible(now) {
			eligible[i] = true
			anyEligible = true
		}
	}
	failOpen := false
	if !anyEligible {
		failOpen = true
		for i, entry := range hs.entries {
			if hostSelectable(entry, exclude) {
				eligible[i] = true
				anyEligible = true
			}
		}
	}
	if !anyEligible {
		return nil, ErrNoHealthyHosts
	}
	index := hs.choose(req, eligible)
	if index < 0 {
		return nil, ErrNoHealthyHosts
	}
	entry := hs.entries[index]
	for !entry.acquire() {
		eligible[index] = false
		index = hs.choose(req, eligible)
		if index < 0 {
			return nil, ErrNoHealthyHosts
		}
		entry = hs.entries[index]
	}
	if failOpen {
		hs.failOpen.Add(1)
	}
	entry.requests.Add(1)
	return entry.host, nil
}

// acquire reserves one in-flight slot atomically. | acquire 原子预留一个在途名额。
func (e *hostEntry) acquire() bool {
	if e.host.MaxInflight <= 0 {
		e.inflight.Add(1)
		return true
	}
	limit := int64(e.host.MaxInflight)
	for {
		current := e.inflight.Load()
		if current >= limit {
			return false
		}
		if e.inflight.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// hostSelectable reports whether the host is not excluded and below its in-flight cap. | hostSelectable 报告 Host 未被排除且未超在途上限。
func hostSelectable(entry *hostEntry, exclude map[string]struct{}) bool {
	if exclude != nil {
		if _, skip := exclude[entry.host.Name]; skip {
			return false
		}
	}
	return entry.host.MaxInflight == 0 || entry.inflight.Load() < int64(entry.host.MaxInflight)
}

// eligible reports whether the host may be selected now, claiming a half-open probe. | eligible 报告 Host 当前是否可选，并占用半开探测。
func (e *hostEntry) eligible(now time.Time) bool {
	if e.healthy.Load() {
		return true
	}
	if e.halfOpen.Load() {
		return false
	}
	until := e.cooldownUntil.Load()
	if until == 0 || now.UnixNano() < until {
		return false
	}
	return e.halfOpen.CompareAndSwap(false, true)
}

// MarkSuccess records a successful request and releases its in-flight slot. | MarkSuccess 记录成功请求并释放在途名额。
func (hs *HostSet) MarkSuccess(host *Host) {
	hs.finish(host, nil)
}

// MarkFailure records a failed request and releases its in-flight slot. | MarkFailure 记录失败请求并释放在途名额。
func (hs *HostSet) MarkFailure(host *Host, err error) {
	if err == nil {
		err = ErrHealthCheck
	}
	hs.finish(host, err)
}

// Release only releases an in-flight slot without changing health. | Release 只释放在途名额，不改变健康状态。
func (hs *HostSet) Release(host *Host) {
	entry := hs.entryOf(host)
	if entry == nil {
		return
	}
	if entry.inflight.Load() > 0 {
		entry.inflight.Add(-1)
		hs.signalWait()
	}
	// A released half-open probe must not leave the host permanently
	// unselectable. | 释放半开探测后不能让 Host 永久不可选。
	if entry.halfOpen.CompareAndSwap(true, false) {
		entry.cooldownUntil.Store(hs.now().UnixNano())
	}
}

// finish releases the in-flight slot and records the outcome. | finish 释放在途名额并记录结果。
func (hs *HostSet) finish(host *Host, err error) {
	entry := hs.entryOf(host)
	if entry == nil {
		return
	}
	if entry.inflight.Load() > 0 {
		entry.inflight.Add(-1)
		hs.signalWait()
	}
	if err == nil {
		hs.recordSuccess(entry)
		return
	}
	hs.recordFailure(entry, err)
}

// entryOf returns the entry owned by this set. | entryOf 返回由该集合拥有的条目。
func (hs *HostSet) entryOf(host *Host) *hostEntry {
	if hs == nil || host == nil || host.entry == nil || host.entry.set != hs {
		return nil
	}
	return host.entry
}

// recordSuccess resets circuit state. | recordSuccess 重置熔断状态。
func (hs *HostSet) recordSuccess(entry *hostEntry) {
	if entry.healthy.Load() && entry.consecutive.Load() == 0 {
		return
	}
	entry.consecutive.Store(0)
	entry.healthy.Store(true)
	entry.halfOpen.Store(false)
	entry.cooldownLevel.Store(0)
	entry.cooldownUntil.Store(0)
}

// recordFailure advances the circuit toward open and schedules the cooldown. | recordFailure 推进熔断并安排冷却。
func (hs *HostSet) recordFailure(entry *hostEntry, err error) {
	_ = err
	entry.failures.Add(1)
	consecutive := entry.consecutive.Add(1)
	entry.halfOpen.Store(false)
	if entry.healthy.Load() && consecutive < int32(entry.host.Health.FailThreshold) {
		return
	}
	entry.healthy.Store(false)
	level := entry.cooldownLevel.Add(1)
	cooldown := entry.host.Health.Cooldown
	maxCooldown := entry.host.Health.MaxCooldown
	for i := int32(1); i < level; i++ {
		if cooldown >= maxCooldown/2 {
			cooldown = maxCooldown
			break
		}
		cooldown *= 2
	}
	if cooldown > maxCooldown {
		cooldown = maxCooldown
	}
	entry.cooldownUntil.Store(hs.now().Add(cooldown).UnixNano())
}

// Stats returns a point-in-time snapshot of every host. | Stats 返回每个 Host 的时间点快照。
func (hs *HostSet) Stats() []HostStats {
	if hs == nil {
		return nil
	}
	now := hs.now()
	out := make([]HostStats, len(hs.entries))
	for i, entry := range hs.entries {
		until := entry.cooldownUntil.Load()
		var cooldownUntil time.Time
		if until > 0 {
			cooldownUntil = time.Unix(0, until)
		}
		out[i] = HostStats{
			Name:          entry.host.Name,
			Requests:      entry.requests.Load(),
			Failures:      entry.failures.Load(),
			Inflight:      entry.inflight.Load(),
			Healthy:       entry.healthy.Load(),
			HalfOpen:      entry.halfOpen.Load(),
			CooldownUntil: cooldownUntil,
		}
		_ = now
	}
	return out
}

// Close stops active health checks and rejects future picks. | Close 停止主动健康检查并拒绝后续选择。
func (hs *HostSet) Close() error {
	return hs.CloseContext(context.Background())
}

// CloseContext stops health checks and bounds the wait by ctx. | CloseContext 停止健康检查并以 ctx 限制等待。
func (hs *HostSet) CloseContext(ctx context.Context) error {
	if hs == nil || !hs.closed.CompareAndSwap(false, true) {
		return nil
	}
	hs.healthMu.Lock()
	cancel := hs.healthCancel
	hs.healthMu.Unlock()
	if cancel != nil {
		cancel()
	}
	hs.signalWait()
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		hs.healthWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WithHosts sets the default host pool from base URLs. | WithHosts 从 base URL 设置默认 Host 池。
func WithHosts(hosts ...string) Option {
	return func(o *options) error {
		for _, raw := range hosts {
			parsed, err := url.Parse(raw)
			if err != nil || !parsed.IsAbs() || parsed.Host == "" ||
				(parsed.Scheme != "http" && parsed.Scheme != "https") {
				return errs.Detail(ErrInvalidConfig, "invalid host %q | 非法的 Host %q", raw, raw)
			}
			o.Hosts = append(o.Hosts, Host{URL: parsed, Weight: 1})
		}
		return nil
	}
}

// WithHostSet sets a prebuilt default host pool. | WithHostSet 设置预构建的默认 Host 池。
func WithHostSet(hs *HostSet) Option {
	return func(o *options) error {
		if hs == nil {
			return errs.Detail(ErrInvalidConfig, "nil host set | 空 Host 池")
		}
		o.HostSet = hs
		return nil
	}
}

// UpdateHosts atomically replaces the default host pool and closes the old pool. | UpdateHosts 原子替换默认 Host 池并关闭旧池。
func (c *Client) UpdateHosts(hosts ...Host) error {
	if c == nil || c.engine == nil {
		return ErrClosed
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.closed.Load() {
		return ErrClosed
	}
	hs, err := NewHostSet(hosts...)
	if err != nil {
		return err
	}
	old := c.engine.hosts.Swap(hs)
	hs.startHealth(context.Background(), c.engine.healthTransport, c.opts.Logger)
	c.engine.pruneTLS()
	if old != nil {
		_ = old.Close()
	}
	c.engine.bare.Store(isBareEngine(c.opts, c.engine.rules.Load(), hs))
	return nil
}
