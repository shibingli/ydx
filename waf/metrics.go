package waf

import "sync/atomic"

// counters keeps lock-free instance statistics. | counters 保存无锁实例统计。
type counters struct {
	inspected        atomic.Int64
	blocked          atomic.Int64
	detected         atomic.Int64
	errors           atomic.Int64
	bypassed         atomic.Int64
	rejected         atomic.Int64
	reloads          atomic.Int64
	inflight         atomic.Int64
	plugins          atomic.Int64
	alertsSent       atomic.Int64
	alertsSuppressed atomic.Int64
	alertsDropped    atomic.Int64
	alertsFailed     atomic.Int64
}

// Stats is a point-in-time snapshot of the instance counters. | Stats 是实例计数器的瞬时快照。
type Stats struct {
	// Inspected counts requests that entered rule evaluation. | Inspected 统计进入规则求值的请求数。
	Inspected int64
	// Blocked counts requests interrupted in blocking mode. | Blocked 统计拦截模式下被中断的请求数。
	Blocked int64
	// Detected counts disruptive matches in detection-only mode. | Detected 统计仅检测模式下的破坏性命中数。
	Detected int64
	// Errors counts rule build, source, hook and plugin failures. | Errors 统计规则构建、来源、钩子与插件失败数。
	Errors int64
	// Bypassed counts excluded requests and requests handled while the engine was off.
	// | Bypassed 统计被排除以及引擎关闭时放行的请求数。
	Bypassed int64
	// Rejected counts requests refused because the instance was closed. | Rejected 统计因实例关闭被拒绝的请求数。
	Rejected int64
	// Reloads counts successful rule snapshot swaps. | Reloads 统计成功的规则快照替换次数。
	Reloads int64
	// InFlight is the number of requests currently holding an engine reservation.
	// | InFlight 是当前持有引擎预留的请求数。
	InFlight int64
	// PluginFailures counts plugin invocation failures. | PluginFailures 统计插件调用失败数。
	PluginFailures int64
	// AlertsSent counts alerts delivered to at least one sink. | AlertsSent 统计至少成功投递到一个
	// Sink 的报警数。
	AlertsSent int64
	// AlertsSuppressed counts alerts suppressed by aggregation or rate limits.
	// | AlertsSuppressed 统计被聚合或限流抑制的报警数。
	AlertsSuppressed int64
	// AlertsDropped counts alerts dropped because the delivery queue was full.
	// | AlertsDropped 统计因投递队列已满而丢弃的报警数。
	AlertsDropped int64
	// AlertsFailed counts failed sink deliveries. | AlertsFailed 统计失败的 Sink 投递次数。
	AlertsFailed int64
}

// snapshot converts the atomic counters into a Stats value. | snapshot 把原子计数器转换为 Stats 值。
func (c *counters) snapshot() Stats {
	return Stats{
		Inspected:        c.inspected.Load(),
		Blocked:          c.blocked.Load(),
		Detected:         c.detected.Load(),
		Errors:           c.errors.Load(),
		Bypassed:         c.bypassed.Load(),
		Rejected:         c.rejected.Load(),
		Reloads:          c.reloads.Load(),
		InFlight:         c.inflight.Load(),
		PluginFailures:   c.plugins.Load(),
		AlertsSent:       c.alertsSent.Load(),
		AlertsSuppressed: c.alertsSuppressed.Load(),
		AlertsDropped:    c.alertsDropped.Load(),
		AlertsFailed:     c.alertsFailed.Load(),
	}
}
