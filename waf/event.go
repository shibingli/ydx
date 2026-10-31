package waf

import (
	"net/http"
	"time"
)

// Event describes one inspected request. | Event 描述一次被检测的请求。
type Event struct {
	// Err reports the internal failure to Go callers. | Err 向 Go 调用方报告内部失败。
	Err error `json:"-"`
	// Interruption carries the rule and action that interrupted the request, when any.
	// | Interruption 携带中断请求的规则与动作（若有）。
	Interruption *Interruption `json:"interruption,omitempty"`
	// ID is the unique transaction identifier. | ID 是唯一的事务标识。
	ID string `json:"id"`
	// Method is the HTTP method. | Method 是 HTTP 方法。
	Method string `json:"method,omitempty"`
	// Path is the request path without the query string. | Path 是不含查询串的请求路径。
	Path string `json:"path,omitempty"`
	// ClientIP is the client host reported to rules and observers. | ClientIP 是报告给规则与观察者的客户端主机。
	ClientIP string `json:"client_ip,omitempty"`
	// RuleVersion identifies the rule bundle that evaluated the request. | RuleVersion 标识求值该请求的规则包。
	RuleVersion string `json:"rule_version,omitempty"`
	// Error is the internal failure text, when one prevented a complete inspection.
	// | Error 是阻止完整检测的内部错误文本。
	Error string `json:"error,omitempty"`
	// Matches lists the rules that matched, in evaluation order. | Matches 按求值顺序列出命中的规则。
	Matches []Match `json:"matches,omitempty"`
	// Status is the response status observed or written by the WAF. | Status 是观察到的或被 WAF 写出的响应状态。
	Status int `json:"status,omitempty"`
	// Duration is the time spent from entering the middleware to finishing the transaction.
	// | Duration 是从进入中间件到事务结束所花费的时间。
	Duration time.Duration `json:"duration_ns,omitempty"`
	// Phase identifies the phase that produced an interruption or the last inspected phase.
	// | Phase 标识产生中断的阶段或最后检测的阶段。
	Phase Phase `json:"phase"`
	// Blocked reports that the request was interrupted in blocking mode. | Blocked 表示请求在拦截模式下被中断。
	Blocked bool `json:"blocked,omitempty"`
	// Detected reports that a disruptive rule matched in detection-only mode, or that a
	// blocking rule matched and the request was blocked. | Detected 表示仅检测模式下破坏性规则命中，或拦截
	// 规则命中且请求已被拦截。
	Detected bool `json:"detected,omitempty"`
	// Dropped reports that the interrupting action requested a connection drop.
	// | Dropped 表示中断动作要求断开连接。
	Dropped bool `json:"dropped,omitempty"`
}

// Interruption describes the disruptive outcome of a rule match. | Interruption 描述规则命中的中断结果。
type Interruption struct {
	// Action is deny, drop, block or redirect. | Action 是 deny、drop、block 或 redirect。
	Action string `json:"action"`
	// Data carries the redirect target for redirect actions. | Data 携带 redirect 动作的目标地址。
	Data string `json:"data,omitempty"`
	// Message is the rule message, after macro expansion. | Message 是宏展开后的规则消息。
	Message string `json:"message,omitempty"`
	// Severity is the rule severity name. | Severity 是规则严重级别名称。
	Severity string `json:"severity,omitempty"`
	// Tags lists the rule tags. | Tags 列出规则标签。
	Tags []string `json:"tags,omitempty"`
	// RuleID is the identifier of the interrupting rule. | RuleID 是中断规则的标识。
	RuleID int `json:"rule_id"`
	// Status is the HTTP status written for the client. | Status 是写给客户端的 HTTP 状态。
	Status int `json:"status,omitempty"`
	// Phase is the phase that produced the interruption. | Phase 是产生中断的阶段。
	Phase Phase `json:"phase"`
}

// Match describes one rule match. | Match 描述一次规则命中。
type Match struct {
	// Var is the collection name that matched. | Var 是命中的集合名称。
	Var string `json:"var,omitempty"`
	// Key is the collection key when the variable was targeted. | Key 是变量被指定键时的集合键。
	Key string `json:"key,omitempty"`
	// Value is the matched value, bounded by the engine's event policy.
	// | Value 是命中的取值，受引擎事件策略约束。
	Value string `json:"value,omitempty"`
	// Message is the rule message after macro expansion. | Message 是宏展开后的规则消息。
	Message string `json:"message,omitempty"`
	// Severity is the rule severity name. | Severity 是规则严重级别名称。
	Severity string `json:"severity,omitempty"`
	// Tags lists the rule tags. | Tags 列出规则标签。
	Tags []string `json:"tags,omitempty"`
	// RuleID is the matched rule identifier. | RuleID 是命中规则的标识。
	RuleID int `json:"rule_id"`
	// Phase is the phase in which the rule ran. | Phase 是规则运行的阶段。
	Phase Phase `json:"phase"`
}

// ErrorHandler writes the response for an interrupted request. It must not echo rule details
// to the client. | ErrorHandler 写出被中断请求的响应，不得向客户端回显规则细节。
type ErrorHandler func(http.ResponseWriter, *http.Request, *Interruption)

// DefaultErrorHandler writes a bare status response. | DefaultErrorHandler 写出仅含状态的响应。
func DefaultErrorHandler(w http.ResponseWriter, _ *http.Request, interruption *Interruption) {
	status := http.StatusForbidden
	if interruption != nil && interruption.Status > 0 {
		status = interruption.Status
	}
	if status == http.StatusMovedPermanently || status == http.StatusFound ||
		status == http.StatusSeeOther || status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect {
		if interruption != nil && interruption.Data != "" {
			w.Header().Set("Location", interruption.Data)
		}
	}
	http.Error(w, http.StatusText(status), status)
}

// Transaction is the request-scoped view passed to hooks and plugins. It is valid only during
// the hook call and must not be retained. | Transaction 是传给钩子与插件的请求级视图，仅在钩子调用
// 期间有效，禁止长期持有。
type Transaction struct {
	tx *transaction
}

// ID returns the transaction identifier. | ID 返回事务标识。
func (t *Transaction) ID() string {
	if t == nil || t.tx == nil {
		return ""
	}
	return t.tx.id
}

// Request returns the request being inspected. | Request 返回被检测的请求。
func (t *Transaction) Request() *http.Request {
	if t == nil || t.tx == nil {
		return nil
	}
	return t.tx.req
}

// GetVar returns the last value of a TX variable. | GetVar 返回 TX 变量的最后一个取值。
func (t *Transaction) GetVar(name string) string {
	if t == nil || t.tx == nil {
		return ""
	}
	return t.tx.lastTX(name)
}

// SetVar replaces a TX variable with one value. | SetVar 用一个值替换 TX 变量。
func (t *Transaction) SetVar(name, value string) {
	if t == nil || t.tx == nil {
		return
	}
	t.tx.setTXValue(name, value, 0)
}

// AddVar appends a value to a TX variable. | AddVar 向 TX 变量追加一个值。
func (t *Transaction) AddVar(name, value string) {
	if t == nil || t.tx == nil {
		return
	}
	t.tx.addTX(name, value, 0)
}

// DeleteVar removes a TX variable. | DeleteVar 删除 TX 变量。
func (t *Transaction) DeleteVar(name string) {
	if t == nil || t.tx == nil {
		return
	}
	t.tx.deleteTX(name)
}

// Matches returns the matches recorded so far. The slice is a snapshot and may be retained.
// | Matches 返回目前已记录的命中；切片是快照，可以保留。
func (t *Transaction) Matches() []Match {
	if t == nil || t.tx == nil {
		return nil
	}
	return t.tx.matchSnapshot()
}

// ClientIP returns the resolved client address. | ClientIP 返回解析后的客户端地址。
func (t *Transaction) ClientIP() string {
	if t == nil || t.tx == nil {
		return ""
	}
	return t.tx.clientIP
}
