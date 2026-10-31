package waf

import (
	"net/http"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/log"
)

// serve runs the complete WAF lifecycle for one request. It reports whether the caller's handler
// was invoked; false means the WAF answered the request. | serve 为一个请求运行完整 WAF 生命周期。
// 它报告调用方处理器是否被调用；false 表示 WAF 已应答请求。
func (w *WAF) serve(rw http.ResponseWriter, r *http.Request, run func(http.ResponseWriter)) bool {
	start := time.Now()
	e, ok := w.acquire()
	if !ok {
		w.counts.rejected.Add(1)
		http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return false
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
		run(rw)
		return true
	}
	tx := e.pool.Get().(*transaction)
	e.initTransaction(tx, r, resolveClientIP(e.cfg, r))
	if e.off || e.mode(tx) == ModeOff {
		w.counts.bypassed.Add(1)
		resetTransaction(tx)
		e.pool.Put(tx)
		releaseOnce()
		run(rw)
		return true
	}
	w.counts.inspected.Add(1)
	status := 0
	var serveErr error
	finished := false
	finish := func() {
		if finished {
			return
		}
		finished = true
		e.processLogging(tx)
		e.runHook(HookRequestComplete, tx, PhaseLogging, nil, nil, serveErr)
		w.emitEvent(e, tx, status, serveErr, time.Since(start))
		if cap(tx.requestBody) > 1<<20 {
			tx.requestBody = nil
		}
		if cap(tx.responseBody) > 1<<20 {
			tx.responseBody = nil
		}
		resetTransaction(tx)
		e.pool.Put(tx)
		releaseOnce()
	}
	// The cleanup defer runs before the panic rethrow because defers are LIFO. | 由于 defer 为
	// LIFO，清理先于 panic 重抛执行。
	defer finish()
	defer func() {
		if recovered := recover(); recovered != nil {
			serveErr = errs.Detail(ErrInternal, "panic: %v | panic：%v", recovered, recovered)
			panic(recovered)
		}
	}()

	e.processRequestHeaders(tx)
	if tx.interruption != nil {
		w.respondInterruption(rw, r, e, tx, &status)
		return false
	}
	if tx.allow || e.mode(tx) == ModeOff {
		run(rw)
		return true
	}
	if r.Method != http.MethodConnect && tx.requestBodyAccess && e.rules.needsBody &&
		(e.cfg.InspectRequestBody == nil || e.cfg.InspectRequestBody(r)) {
		data, tooLarge, err := captureRequestBody(r, tx.bodyLimit, tx.bodyLimitAction)
		if err != nil {
			w.counts.errors.Add(1)
			serveErr = errs.Wrap(err, ErrBodyRead)
			status = http.StatusBadRequest
			http.Error(rw, http.StatusText(status), status)
			return false
		}
		tx.requestBody = data
		tx.bodyRead = true
		tx.argsCombinedReady = false
		tx.bodyTooLarge = tooLarge
		if tooLarge && tx.bodyLimitAction == LimitReject {
			serveErr = ErrRequestBodyTooLarge
			tx.interruption = &Interruption{
				Action:  "deny",
				Status:  http.StatusRequestEntityTooLarge,
				Phase:   PhaseRequestBody,
				Message: "request body too large | 请求正文过大",
			}
			w.respondInterruption(rw, r, e, tx, &status)
			return false
		}
	}
	if e.rules.hasPhaseRules(PhaseRequestBody) {
		e.processRequestBody(tx)
		if tx.interruption != nil {
			w.respondInterruption(rw, r, e, tx, &status)
			return false
		}
		if tx.allow || e.mode(tx) == ModeOff {
			run(rw)
			return true
		}
	}
	if r.Method == http.MethodConnect {
		finish()
		run(rw)
		return true
	}
	inspectHeaders := e.rules.needsResponseHeaders
	inspectBody := e.rules.needsResponseBody && tx.responseBodyAccess
	if inspectBody && e.cfg.InspectResponseBody != nil && !e.cfg.InspectResponseBody(r) {
		inspectBody = false
	}
	inspectPhase4 := e.rules.hasPhaseRules(PhaseResponseBody)
	if !inspectHeaders && !inspectBody && !inspectPhase4 {
		run(rw)
		if tx.responseStatus > 0 {
			status = tx.responseStatus
		}
		return true
	}
	writer := newResponseWriter(rw, r, e, tx, inspectHeaders, inspectBody)
	run(writer)
	if err := writer.finish(); err != nil {
		w.counts.errors.Add(1)
		serveErr = err
	}
	status = writer.status
	if status == 0 {
		status = tx.responseStatus
	}
	return true
}

// respondInterruption writes the interruption response or drops the connection. | respondInterruption
// 写出中断响应或断开连接。
func (w *WAF) respondInterruption(rw http.ResponseWriter, r *http.Request, e *engine, tx *transaction, status *int) {
	interruption := tx.interruption
	if interruption == nil {
		return
	}
	meta := ruleMeta(e, interruption.RuleID)
	e.runHook(HookBeforeInterrupt, tx, interruption.Phase, meta, nil, nil)
	if tx.interruption != nil {
		interruption = tx.interruption
	}
	if interruption.Action == "drop" {
		if hijacker, ok := rw.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				*status = interruption.Status
				if *status == 0 {
					*status = http.StatusForbidden
				}
				e.runHook(HookAfterInterrupt, tx, interruption.Phase, ruleMeta(e, interruption.RuleID), nil, nil)
				_ = conn.Close()
				return
			}
		}
	}
	e.cfg.errorHandler()(rw, r, interruption)
	*status = interruption.Status
	if *status == 0 {
		*status = http.StatusForbidden
	}
	e.runHook(HookAfterInterrupt, tx, interruption.Phase, ruleMeta(e, interruption.RuleID), nil, nil)
}

// emitEvent records a transaction and forwards it to log, Observer and alerting. | emitEvent 记录
// 事务并转发给日志、Observer 与报警。
func (w *WAF) emitEvent(e *engine, tx *transaction, status int, err error, duration time.Duration) {
	interesting := tx.interruption != nil || tx.detected != nil || err != nil
	var matches []Match
	if interesting || e.cfg.Observer != nil || e.cfg.AuditWriter != nil {
		matches = tx.matchSnapshot()
	}
	event := Event{
		ID:          tx.id,
		Method:      "",
		Path:        "",
		ClientIP:    tx.clientIP,
		Status:      status,
		Duration:    duration,
		RuleVersion: e.version,
		Matches:     matches,
		Err:         err,
	}
	if tx.req != nil {
		event.Method = tx.req.Method
		event.Path = tx.req.URL.Path
	}
	if err != nil {
		event.Error = err.Error()
	}
	if tx.interruption != nil {
		event.Blocked = true
		event.Detected = true
		event.Dropped = tx.interruption.Action == "drop"
		event.Phase = tx.interruption.Phase
		event.Interruption = tx.interruption
		if event.Status == 0 {
			event.Status = tx.interruption.Status
		}
		w.counts.blocked.Add(1)
	} else if tx.detected != nil {
		event.Detected = true
		event.Phase = tx.detected.Phase
		event.Interruption = tx.detected
		w.counts.detected.Add(1)
	}
	if event.Status == 0 && tx.responseStatus > 0 {
		event.Status = tx.responseStatus
	}
	interesting = event.Blocked || event.Detected || event.Err != nil
	if interesting {
		fields := []log.Field{
			log.Str("tx_id", event.ID),
			log.Str("method", event.Method),
			log.Str("path", event.Path),
			log.Str("client_ip", event.ClientIP),
			log.Int("status", event.Status),
			log.Str("phase", event.Phase.String()),
			log.Int("rules", len(event.Matches)),
			log.Dur("duration", event.Duration),
		}
		if event.Interruption != nil {
			fields = append(fields,
				log.Int("rule_id", event.Interruption.RuleID),
				log.Str("action", event.Interruption.Action))
		}
		if len(event.Matches) > 0 {
			fields = append(fields, log.Int("first_match_rule_id", event.Matches[0].RuleID))
		}
		switch {
		case event.Err != nil:
			e.logger.Error("waf inspection failed | WAF 检测失败", append(fields, log.Err(event.Err))...)
		case event.Blocked:
			e.logger.Warn("waf blocked request | WAF 已拦截请求", fields...)
		case event.Detected:
			e.logger.Warn("waf detected request | WAF 检测到攻击请求", fields...)
		}
	}
	if e.cfg.Observer != nil {
		e.cfg.Observer(event)
	}
	if interesting && e.cfg.AuditWriter != nil {
		if data, marshalErr := json.Marshal(event); marshalErr == nil {
			w.auditMu.Lock()
			_, _ = e.cfg.AuditWriter.Write(append(data, '\n'))
			w.auditMu.Unlock()
		}
	}
	if alerter := w.alerter.Load(); alerter != nil {
		alerter.notify(event)
	}
}
