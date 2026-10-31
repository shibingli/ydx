package waf

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// Alert describes one aggregated security notification. | Alert 描述一次聚合的安全通知。
type Alert struct {
	Time          time.Time     `json:"time"`
	FirstSeen     time.Time     `json:"first_seen"`
	LastSeen      time.Time     `json:"last_seen"`
	Interruption  *Interruption `json:"interruption,omitempty"`
	ID            string        `json:"id"`
	NodeID        string        `json:"node_id,omitempty"`
	Severity      string        `json:"severity"`
	Action        string        `json:"action,omitempty"`
	Method        string        `json:"method,omitempty"`
	Path          string        `json:"path,omitempty"`
	ClientIP      string        `json:"client_ip,omitempty"`
	Message       string        `json:"message,omitempty"`
	RuleVersion   string        `json:"rule_version,omitempty"`
	Error         string        `json:"error,omitempty"`
	Tags          []string      `json:"tags,omitempty"`
	RuleID        int           `json:"rule_id"`
	Status        int           `json:"status,omitempty"`
	Count         int           `json:"count"`
	WindowSeconds int64         `json:"window_seconds,omitempty"`
}

// AlertSink delivers alerts. Send may be called concurrently and should honor ctx.
// | AlertSink 投递报警。Send 可能被并发调用，并应尊重 ctx。
type AlertSink interface {
	Name() string
	Send(context.Context, Alert) error
	Close() error
}

// AlertConfig configures the alerting pipeline. The zero value is disabled. | AlertConfig 配置报警
// 管线；零值表示关闭。
type AlertConfig struct {
	// Email, when set, adds a built-in SMTP sink. | Email 非空时添加内置 SMTP Sink。
	Email *EmailConfig
	// Filter may drop events before aggregation. | Filter 可在聚合前丢弃事件。
	Filter func(Event) bool
	// MinSeverity is the least severe level delivered; default WARNING. | MinSeverity 是投递的最低
	// 严重级别；默认 WARNING。
	MinSeverity string
	// NodeID identifies this instance in multi-machine deployments. | NodeID 在多机部署中标识本实例。
	NodeID string
	// Sinks receive alerts. | Sinks 接收报警。
	Sinks []AlertSink
	// Retry configures per-sink delivery retries; zero selects three attempts. | Retry 配置每个 Sink
	// 的投递重试；零值选择三次尝试。
	Retry RetryPolicy
	// Threshold is the number of events in Window before an alert is emitted; default 3.
	// | Threshold 是 Window 内触发报警的事件数；默认 3。
	Threshold int
	// CriticalThreshold overrides Threshold for CRITICAL and above; default 1.
	// | CriticalThreshold 覆盖 CRITICAL 及以上的 Threshold；默认 1。
	CriticalThreshold int
	// Window is the aggregation window; default 1 minute. | Window 是聚合窗口；默认 1 分钟。
	Window time.Duration
	// Cooldown suppresses the same rule/client pair after an alert; default 10 minutes.
	// | Cooldown 在报警后抑制相同规则/客户端组合；默认 10 分钟。
	Cooldown time.Duration
	// MinInterval is the minimum gap between any two delivered alerts; default 10 seconds.
	// | MinInterval 是任意两次报警之间的最小间隔；默认 10 秒。
	MinInterval time.Duration
	// MaxPerHour and MaxPerDay cap delivered alerts globally; defaults 30 and 200.
	// | MaxPerHour 与 MaxPerDay 全局限制投递数量；默认 30 与 200。
	MaxPerHour int
	MaxPerDay  int
	// QueueSize bounds the asynchronous delivery queue; default 1024. A full queue drops alerts
	// instead of slowing requests. | QueueSize 限制异步投递队列；默认 1024。队列满时丢弃报警而非
	// 拖慢请求。
	QueueSize int
	// Enabled turns alert delivery on. | Enabled 开启报警投递。
	Enabled bool
}

// Alert defaults. | 报警默认值。
const (
	defaultAlertThreshold         = 3
	defaultAlertCriticalThreshold = 1
	defaultAlertWindow            = time.Minute
	defaultAlertCooldown          = 10 * time.Minute
	defaultAlertMinInterval       = 10 * time.Second
	defaultAlertMaxPerHour        = 30
	defaultAlertMaxPerDay         = 200
	defaultAlertQueueSize         = 1024
	defaultAlertSinkTimeout       = 10 * time.Second
	alertSinkFailureThreshold     = 5
	alertSinkDisableCooldown      = 5 * time.Minute
	maxAlertBuckets               = 4096
)

// alertBucket aggregates events for one rule/client pair. | alertBucket 为一个规则/客户端组合聚合事件。
type alertBucket struct {
	first         time.Time
	last          time.Time
	cooldownUntil time.Time
	sample        Alert
	count         int
}

// sinkState tracks one sink's circuit breaker. | sinkState 跟踪一个 Sink 的熔断器。
type sinkState struct {
	disabledUntil time.Time
	sink          AlertSink
	failures      int
}

// alerter aggregates events and delivers alerts asynchronously with hard rate limits.
// | alerter 聚合同步事件并以硬性限流异步投递报警。
type alerter struct {
	lastSent  time.Time
	hourStart time.Time
	dayStart  time.Time
	ctx       context.Context
	logger    *log.Logger
	counts    *counters
	cancel    context.CancelFunc
	queue     chan Alert
	done      chan struct{}
	buckets   map[string]*alertBucket
	sinks     []sinkState

	cfg AlertConfig

	hourCount int
	dayCount  int

	mu sync.Mutex
}

// newAlerter builds the alerting pipeline and starts its worker. | newAlerter 构建报警管线并启动
// 工作协程。
func newAlerter(cfg AlertConfig, logger *log.Logger, counts *counters) (*alerter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	normalized, err := normalizeAlertConfig(cfg)
	if err != nil {
		return nil, err
	}
	sinks := append([]AlertSink(nil), normalized.Sinks...)
	if normalized.Email != nil {
		email, err := NewEmailSink(*normalized.Email)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, email)
	}
	if len(sinks) == 0 {
		return nil, errs.Detail(ErrInvalidOption, "alerting enabled without sinks | 报警已开启但没有 Sink")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &alerter{
		cfg:     normalized,
		logger:  logger,
		counts:  counts,
		ctx:     ctx,
		cancel:  cancel,
		queue:   make(chan Alert, normalized.QueueSize),
		done:    make(chan struct{}),
		buckets: make(map[string]*alertBucket, 64),
	}
	for _, sink := range sinks {
		if sink != nil {
			a.sinks = append(a.sinks, sinkState{sink: sink})
		}
	}
	if len(a.sinks) == 0 {
		return nil, errs.Detail(ErrInvalidOption, "alerting enabled without sinks | 报警已开启但没有 Sink")
	}
	go a.worker()
	return a, nil
}

// normalizeAlertConfig fills defaults and validates thresholds. | normalizeAlertConfig 填充默认值
// 并校验阈值。
func normalizeAlertConfig(cfg AlertConfig) (AlertConfig, error) {
	n := cfg
	if n.MinSeverity == "" {
		n.MinSeverity = "WARNING"
	}
	n.MinSeverity = normalizeSeverity(n.MinSeverity)
	if n.Threshold <= 0 {
		n.Threshold = defaultAlertThreshold
	}
	if n.CriticalThreshold <= 0 {
		n.CriticalThreshold = defaultAlertCriticalThreshold
	}
	if n.Window <= 0 {
		n.Window = defaultAlertWindow
	}
	if n.Cooldown <= 0 {
		n.Cooldown = defaultAlertCooldown
	}
	if n.MinInterval < 0 {
		return AlertConfig{}, ErrInvalidOption
	}
	if n.MinInterval == 0 {
		n.MinInterval = defaultAlertMinInterval
	}
	if n.MaxPerHour < 0 || n.MaxPerDay < 0 {
		return AlertConfig{}, ErrInvalidOption
	}
	if n.MaxPerHour == 0 {
		n.MaxPerHour = defaultAlertMaxPerHour
	}
	if n.MaxPerDay == 0 {
		n.MaxPerDay = defaultAlertMaxPerDay
	}
	if n.MaxPerHour > n.MaxPerDay {
		n.MaxPerHour = n.MaxPerDay
	}
	if n.QueueSize <= 0 {
		n.QueueSize = defaultAlertQueueSize
	}
	if n.QueueSize > 65536 {
		n.QueueSize = 65536
	}
	n.Retry = n.Retry.normalized()
	n.Sinks = append([]AlertSink(nil), cfg.Sinks...)
	return n, nil
}

// notify aggregates one event and enqueues an alert when its thresholds are met. It never blocks.
// | notify 聚合一个事件并在达到阈值时入队报警；它绝不阻塞。
func (a *alerter) notify(event Event) {
	if a == nil || event.Interruption == nil && event.Err == nil {
		return
	}
	if !a.allowedByFilter(event) {
		return
	}
	alert, ok := alertFromEvent(event, a.cfg.NodeID, a.cfg.Window)
	if !ok {
		return
	}
	if severityValue(alert.Severity) > severityValue(a.cfg.MinSeverity) {
		return
	}
	now := time.Now()
	key := strconv.Itoa(alert.RuleID) + "|" + alert.ClientIP + "|" + alert.Path
	threshold := a.cfg.Threshold
	if severityValue(alert.Severity) <= 2 {
		threshold = a.cfg.CriticalThreshold
	}
	a.mu.Lock()
	bucket := a.buckets[key]
	if bucket == nil {
		if len(a.buckets) >= maxAlertBuckets {
			a.pruneBucketsLocked(now)
		}
		bucket = &alertBucket{}
		a.buckets[key] = bucket
	}
	if bucket.first.IsZero() {
		bucket.first = now
	}
	bucket.last = now
	bucket.count++
	bucket.sample = alert
	if now.Before(bucket.cooldownUntil) {
		a.counts.alertsSuppressed.Add(1)
		a.mu.Unlock()
		return
	}
	if bucket.count < threshold {
		a.mu.Unlock()
		return
	}
	if !a.allowLocked(now) {
		a.counts.alertsSuppressed.Add(1)
		a.mu.Unlock()
		return
	}
	alert.Time = now
	alert.FirstSeen = bucket.first
	alert.LastSeen = now
	alert.Count = bucket.count
	bucket.count = 0
	bucket.first = time.Time{}
	bucket.cooldownUntil = now.Add(a.cfg.Cooldown)
	a.lastSent = now
	a.hourCount++
	a.dayCount++
	a.mu.Unlock()
	select {
	case a.queue <- alert:
	default:
		a.counts.alertsDropped.Add(1)
	}
}

// allowedByFilter runs the user filter with panic isolation. | allowedByFilter 在 panic 隔离下运行
// 用户过滤器。
func (a *alerter) allowedByFilter(event Event) (allowed bool) {
	if a.cfg.Filter == nil {
		return true
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			allowed = false
			a.logger.Error("waf alert filter panicked | WAF 报警过滤器发生 panic",
				log.Any("panic", recovered))
		}
	}()
	return a.cfg.Filter(event)
}

// allowLocked applies global rate limits; the caller holds mu. | allowLocked 应用全局限流；调用方
// 持有 mu。
func (a *alerter) allowLocked(now time.Time) bool {
	if !a.lastSent.IsZero() && now.Sub(a.lastSent) < a.cfg.MinInterval {
		return false
	}
	if a.hourStart.IsZero() || now.Sub(a.hourStart) >= time.Hour {
		a.hourStart = now
		a.hourCount = 0
	}
	if a.dayStart.IsZero() || now.Sub(a.dayStart) >= 24*time.Hour {
		a.dayStart = now
		a.dayCount = 0
	}
	if a.hourCount >= a.cfg.MaxPerHour {
		return false
	}
	if a.dayCount >= a.cfg.MaxPerDay {
		return false
	}
	return true
}

// pruneBucketsLocked drops buckets outside the aggregation and cooldown windows. | pruneBucketsLocked
// 丢弃聚合与冷却窗口之外的桶。
func (a *alerter) pruneBucketsLocked(now time.Time) {
	cutoff := now.Add(-(a.cfg.Window + a.cfg.Cooldown))
	for key, bucket := range a.buckets {
		if bucket.last.Before(cutoff) && bucket.cooldownUntil.Before(now) {
			delete(a.buckets, key)
		}
	}
}

// worker delivers queued alerts. | worker 投递已入队报警。
func (a *alerter) worker() {
	defer close(a.done)
	for {
		select {
		case <-a.ctx.Done():
			return
		case alert := <-a.queue:
			a.deliver(alert)
		}
	}
}

// deliver sends an alert through every healthy sink with retry and a circuit breaker.
// | deliver 带重试与熔断地把报警发送给每个健康 Sink。
func (a *alerter) deliver(alert Alert) {
	delivered := false
	for index := range a.sinks {
		state := &a.sinks[index]
		if time.Now().Before(state.disabledUntil) {
			continue
		}
		err := a.cfg.Retry.do(a.ctx, func(ctx context.Context) error {
			callCtx, cancel := context.WithTimeout(ctx, defaultAlertSinkTimeout)
			defer cancel()
			return state.sink.Send(callCtx, alert)
		})
		if err != nil {
			state.failures++
			a.counts.alertsFailed.Add(1)
			a.logger.Error("waf alert delivery failed | WAF 报警投递失败",
				log.Str("sink", state.sink.Name()), log.Err(err))
			if state.failures >= alertSinkFailureThreshold {
				state.disabledUntil = time.Now().Add(alertSinkDisableCooldown)
				state.failures = 0
				a.logger.Error("waf alert sink disabled | WAF 报警 Sink 已禁用",
					log.Str("sink", state.sink.Name()), log.Dur("cooldown", alertSinkDisableCooldown))
			}
			continue
		}
		state.failures = 0
		delivered = true
	}
	if delivered {
		a.counts.alertsSent.Add(1)
	}
}

// close stops the worker and closes every sink. | close 停止工作协程并关闭每个 Sink。
func (a *alerter) close() {
	if a == nil {
		return
	}
	a.cancel()
	<-a.done
	for _, state := range a.sinks {
		if err := state.sink.Close(); err != nil {
			a.logger.Error("waf alert sink close failed | WAF 报警 Sink 关闭失败",
				log.Str("sink", state.sink.Name()), log.Err(err))
		}
	}
}

// alertFromEvent converts an interesting event into an alert sample. | alertFromEvent 把值得注意的
// 事件转换为报警样本。
func alertFromEvent(event Event, nodeID string, window time.Duration) (Alert, bool) {
	alert := Alert{
		ID:            event.ID,
		Time:          time.Now(),
		NodeID:        nodeID,
		Method:        event.Method,
		Path:          event.Path,
		ClientIP:      event.ClientIP,
		Status:        event.Status,
		RuleVersion:   event.RuleVersion,
		WindowSeconds: int64(window / time.Second),
	}
	if event.Interruption != nil {
		alert.RuleID = event.Interruption.RuleID
		alert.Severity = event.Interruption.Severity
		alert.Action = event.Interruption.Action
		alert.Message = event.Interruption.Message
		alert.Tags = event.Interruption.Tags
		alert.Interruption = event.Interruption
		if alert.Status == 0 {
			alert.Status = event.Interruption.Status
		}
	}
	if event.Err != nil {
		alert.Error = event.Err.Error()
		if alert.Severity == "" {
			alert.Severity = "ERROR"
		}
	}
	if alert.Severity == "" {
		alert.Severity = "WARNING"
	}
	return alert, alert.Interruption != nil || alert.Error != ""
}
