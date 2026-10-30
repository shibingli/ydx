package waf

import (
	"net/http"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

// Interruption describes a disruptive rule match in a framework-neutral form. | Interruption
// 以与框架无关的形式描述一次破坏性规则命中。
type Interruption struct {
	// ID is the Coraza transaction identifier. | ID 是 Coraza 事务标识。
	ID string
	// Action is the Coraza action: deny, redirect or drop. | Action 是 Coraza 动作：deny、redirect 或 drop。
	Action string
	// Data carries redirect targets and other rule parameters. It is never echoed to the client
	// by the default handler. | Data 携带重定向目标及其它规则参数；默认处理器绝不把它回显给客户端。
	Data string
	// RuleID is the identifier of the rule that interrupted the request. | RuleID 是中断请求的规则标识。
	RuleID int
	// Status is the effective HTTP status, already defaulted when the rule did not set one.
	// | Status 是生效的 HTTP 状态码；规则未设置时已填充默认值。
	Status int
	// Phase is the lifecycle stage that produced the interruption. | Phase 是产生中断的生命周期阶段。
	Phase Phase
}

// ErrorHandler writes the response for an interrupted request. | ErrorHandler 写出被中断请求的响应。
//
// Implementations must write a complete response. They receive the original writer, so their
// output is not inspected by the WAF (which is what prevents recursive blocking). | 实现必须写出完整
// 响应。它拿到的是原始写入器，因此其输出不会被 WAF 再次检测（避免递归拦截）。
type ErrorHandler func(http.ResponseWriter, *http.Request, *Interruption)

// Match is a value snapshot of one matched rule. | Match 是一次规则命中的值快照。
type Match struct {
	// Message is the expanded rule message. | Message 是展开后的规则消息。
	Message string
	// Severity is the rule severity name, such as "critical". | Severity 是规则严重级别名称，例如 "critical"。
	Severity string
	// Tags lists the rule tags. | Tags 列出规则标签。
	Tags []string
	// RuleID is the rule identifier. | RuleID 是规则标识。
	RuleID int
	// Phase is the SecLang phase number (1 through 5). | Phase 是 SecLang 阶段号（1 到 5）。
	Phase int
	// Disruptive reports whether the match performs a disruptive action. | Disruptive 报告该命中是否
	// 执行破坏性动作。
	Disruptive bool
}

// Event is the per-request observation passed to Options.Observer. | Event 是传给 Options.Observer
// 的每请求观察记录。
//
// Blocked and Detected are mutually exclusive: Blocked is a real interruption, while Detected is
// a would-be interruption recorded by detection-only mode. | Blocked 与 Detected 互斥：Blocked 是
// 真实中断，Detected 是仅检测模式记录下的“本应中断”。
type Event struct {
	// Err carries an internal failure. When set, the request was rejected with 500 or 413. |
	// Err 携带内部错误；设置时请求以 500 或 413 被拒绝。
	Err error
	// Interruption carries the interruption details when Blocked or Detected is true. | Interruption
	// 在 Blocked 或 Detected 为真时携带中断细节。
	Interruption *Interruption
	// ID is the Coraza transaction identifier. | ID 是 Coraza 事务标识。
	ID string
	// Method is the HTTP method. | Method 是 HTTP 方法。
	Method string
	// Path is the request path without the query string. | Path 是不含查询串的请求路径。
	Path string
	// ClientIP is the client address reported to Coraza. | ClientIP 是报告给 Coraza 的客户端地址。
	ClientIP string
	// Matches lists every matched rule in evaluation order. It is populated for the observer and
	// for blocked or detected requests. | Matches 按求值顺序列出所有命中规则。观察者以及被拦截、
	// 被检测的请求会填充该字段。
	Matches []Match
	// Status is the final response status seen by the client. It is zero when the response was
	// not wrapped, such as a CONNECT tunnel or a rule set with no response-phase rules and no
	// observer. | Status 是客户端看到的最终响应状态；响应未被包装时为零，例如 CONNECT 隧道，
	// 或没有响应阶段规则且没有观察者的规则集。
	Status int
	// Duration measures the time spent inside the middleware, including the handler. | Duration
	// 测量中间件内部的耗时（包含业务处理器）。
	Duration time.Duration
	// Blocked reports a real interruption. | Blocked 报告真实中断。
	Blocked bool
	// Detected reports a detection-only interruption. | Detected 报告仅检测模式下的中断。
	Detected bool
	// Phase is the stage that produced the interruption; PhaseNone for clean requests. |
	// Phase 是产生中断的阶段；正常请求为 PhaseNone。
	Phase Phase
}

// DefaultErrorHandler writes a generic block response without rule details. | DefaultErrorHandler
// 写出不含规则细节的通用拦截响应。
//
// A redirect action with a non-empty target becomes a Location redirect; every other action
// becomes http.Error with the interruption status. | 带非空目标的重定向动作写成 Location 跳转；
// 其余动作以中断状态码调用 http.Error。
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, it *Interruption) {
	status := http.StatusForbidden
	action, data := "", ""
	if it != nil {
		if it.Status >= http.StatusContinue && it.Status <= 599 {
			status = it.Status
		}
		action, data = it.Action, it.Data
	}
	if action == "redirect" && data != "" {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, data, status)
		return
	}
	text := http.StatusText(status)
	if text == "" {
		text = "blocked"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, text, status)
}

// interruptionStatus derives the effective HTTP status from a Coraza interruption. | interruptionStatus
// 从 Coraza 中断派生生效的 HTTP 状态码。
func interruptionStatus(it *types.Interruption) int {
	if it == nil {
		return http.StatusForbidden
	}
	if it.Status >= http.StatusContinue && it.Status <= 599 {
		return it.Status
	}
	if it.Action == "redirect" {
		return http.StatusFound
	}
	return http.StatusForbidden
}

// newInterruption converts a Coraza interruption into the public value. | newInterruption 把
// Coraza 中断转换为公开值。
func newInterruption(id string, it *types.Interruption, phase Phase) *Interruption {
	if it == nil {
		return nil
	}
	return &Interruption{
		ID:     id,
		RuleID: it.RuleID,
		Action: it.Action,
		Status: interruptionStatus(it),
		Data:   it.Data,
		Phase:  phase,
	}
}

// detectionTransaction exposes Coraza's detection-only bookkeeping, which is not part of the
// types.Transaction interface. | detectionTransaction 暴露 Coraza 的仅检测记录，它不属于
// types.Transaction 接口。
type detectionTransaction interface {
	IsDetectionOnlyInterrupted() bool
	DetectionOnlyInterruption() *types.Interruption
}

// detectionInterruption returns the would-be interruption recorded in detection-only mode. |
// detectionInterruption 返回仅检测模式记录下的“本应中断”。
func detectionInterruption(tx types.Transaction) *types.Interruption {
	d, ok := tx.(detectionTransaction)
	if !ok || !d.IsDetectionOnlyInterrupted() {
		return nil
	}
	return d.DetectionOnlyInterruption()
}

// collectMatches snapshots the matched rules for observation. | collectMatches 为观察快照已命中的规则。
func collectMatches(tx types.Transaction) []Match {
	rules := tx.MatchedRules()
	if len(rules) == 0 {
		return nil
	}
	out := make([]Match, 0, len(rules))
	for _, matched := range rules {
		meta := matched.Rule()
		tags := meta.Tags()
		var copiedTags []string
		if len(tags) > 0 {
			copiedTags = append([]string(nil), tags...)
		}
		out = append(out, Match{
			RuleID:     meta.ID(),
			Message:    matched.Message(),
			Severity:   meta.Severity().String(),
			Tags:       copiedTags,
			Phase:      int(meta.Phase()),
			Disruptive: matched.Disruptive(),
		})
	}
	return out
}
