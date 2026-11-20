package waf

import (
	"net/http"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// Decision is the request-level outcome of a WAF evaluation without a response writer. | Decision
// 是无 ResponseWriter 的 WAF 请求级求值结果。
type Decision struct {
	// Allowed reports whether the request may proceed. | Allowed 报告请求是否可继续。
	Allowed bool
	// Blocked reports an interrupting rule match. | Blocked 报告命中中断规则。
	Blocked bool
	// Detected reports a detection-mode match. | Detected 报告检测模式命中。
	Detected bool
	// Status is the interruption status. | Status 是中断状态码。
	Status int
	// Action is the interruption action. | Action 是中断动作。
	Action string
	// RuleID is the interrupting or detecting rule id. | RuleID 是中断或检测规则 id。
	RuleID int
	// Message is the rule message. | Message 是规则消息。
	Message string
	// Matches lists the matched rules. | Matches 列出命中的规则。
	Matches []Match
}

// Evaluate runs request phases 1 and 2 without writing a response or wrapping a
// ResponseWriter. | Evaluate 执行请求阶段 1 与 2，不写响应、不包装 ResponseWriter。
func (w *WAF) Evaluate(r *http.Request) (Decision, error) {
	if w == nil || r == nil {
		return Decision{}, ErrInternal
	}
	e, ok := w.acquire()
	if !ok {
		if w.failOpen.Load() {
			return Decision{Allowed: true}, nil
		}
		return Decision{
			Blocked: true,
			Status:  http.StatusServiceUnavailable,
			Action:  "deny",
			Message: "waf unavailable | WAF 不可用",
		}, ErrClosed
	}
	released := false
	releaseOnce := func() {
		if released {
			return
		}
		released = true
		w.release(e)
	}
	defer releaseOnce()
	if e.cfg.Exclude != nil && e.cfg.Exclude(r) {
		w.counts.bypassed.Add(1)
		releaseOnce()
		return Decision{Allowed: true}, nil
	}
	tx := e.pool.Get().(*transaction)
	e.initTransaction(tx, r, resolveClientIP(e.cfg, r))
	if e.off || e.mode(tx) == ModeOff {
		w.counts.bypassed.Add(1)
		resetTransaction(tx)
		e.pool.Put(tx)
		releaseOnce()
		return Decision{Allowed: true}, nil
	}
	w.counts.inspected.Add(1)
	start := time.Now()
	status := 0
	var evalErr error
	defer func() {
		e.processLogging(tx)
		e.runHook(HookRequestComplete, tx, PhaseLogging, nil, nil, evalErr)
		w.emitEvent(e, tx, status, evalErr, time.Since(start))
		if cap(tx.requestBody) > 1<<20 {
			tx.requestBody = nil
		}
		if cap(tx.responseBody) > 1<<20 {
			tx.responseBody = nil
		}
		resetTransaction(tx)
		e.pool.Put(tx)
		releaseOnce()
	}()

	status, evalErr = w.evaluateRequest(e, tx, r)
	decision := Decision{Allowed: tx.interruption == nil, Matches: tx.matchSnapshot()}
	if evalErr != nil && !w.failOpen.Load() && tx.interruption == nil {
		// Fail closed in the decision itself, not only in the returned error. A caller that
		// checks Allowed (the documented pattern) must not publish traffic when inspection
		// could not complete, for example because the body read failed. | 在 Decision 本身失败
		// 关闭，而不只是返回 error。按文档只检查 Allowed 的调用方在检测无法完成（例如正文读取
		// 失败）时绝不能放行流量。
		decision.Allowed = false
		decision.Blocked = true
		decision.Status = status
		if decision.Status == 0 {
			decision.Status = http.StatusBadRequest
		}
		decision.Message = "inspection failed | 检测失败"
	}
	if tx.interruption != nil {
		decision.Blocked = true
		decision.Allowed = false
		decision.Status = tx.interruption.Status
		decision.Action = tx.interruption.Action
		decision.RuleID = tx.interruption.RuleID
		decision.Message = tx.interruption.Message
		status = tx.interruption.Status
	}
	if tx.detected != nil {
		decision.Detected = true
		if decision.Status == 0 {
			decision.Status = tx.detected.Status
		}
		if decision.Action == "" {
			decision.Action = tx.detected.Action
		}
		if decision.RuleID == 0 {
			decision.RuleID = tx.detected.RuleID
		}
		if decision.Message == "" {
			decision.Message = tx.detected.Message
		}
	}
	return decision, evalErr
}

// evaluateRequest runs request phases 1 and 2 for both serve and Evaluate. | evaluateRequest 为
// serve 与 Evaluate 执行请求阶段 1 与 2。
func (w *WAF) evaluateRequest(e *engine, tx *transaction, r *http.Request) (int, error) {
	e.processRequestHeaders(tx)
	if tx.interruption != nil {
		return tx.interruption.Status, nil
	}
	if tx.allowScope == allowAll || tx.allowScope == allowRequest || e.mode(tx) == ModeOff {
		// Request-scoped allow ends the request phases; response phases still run.
		// | 请求级 allow 结束请求阶段；响应阶段仍会运行。
		return 0, nil
	}
	if r.Method != http.MethodConnect && tx.requestBodyAccess && e.rules.needsBody &&
		(e.cfg.InspectRequestBody == nil || e.cfg.InspectRequestBody(r)) {
		data, tooLarge, err := captureRequestBody(r, tx.bodyLimit, tx.bodyLimitAction)
		if err != nil {
			w.counts.errors.Add(1)
			wrapped := errs.Wrap(err, ErrBodyRead)
			if !w.failOpen.Load() {
				return http.StatusBadRequest, wrapped
			}
			// The body is already lost to the read error; continue with header and phase 2
			// evaluation over the remaining variables. | 正文已因读取错误丢失；继续执行头部与
			// 其余变量上的 phase 2 求值。
			w.logger.Warn("waf request body read failed, failing open without body inspection | WAF 读取请求正文失败，失败放行并跳过正文检测",
				log.Err(err))
		} else {
			tx.requestBody = data
			tx.bodyRead = true
			tx.argsCombinedReady = false
			tx.bodyTooLarge = tooLarge
			if tooLarge && tx.bodyLimitAction == LimitReject {
				tx.interruption = &Interruption{
					Action:  "deny",
					Status:  http.StatusRequestEntityTooLarge,
					Phase:   PhaseRequestBody,
					Message: "request body too large | 请求正文过大",
				}
				return http.StatusRequestEntityTooLarge, ErrRequestBodyTooLarge
			}
		}
	}
	if e.rules.hasPhaseRules(PhaseRequestBody) {
		e.processRequestBody(tx)
		if tx.interruption != nil {
			return tx.interruption.Status, nil
		}
		if tx.allowScope >= allowRequest || e.mode(tx) == ModeOff {
			return 0, nil
		}
	}
	return 0, nil
}
