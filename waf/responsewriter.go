package waf

import (
	"bufio"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
)

// responseWriter buffers a response body for phase 4 inspection while preserving the underlying
// writer's optional interfaces. | responseWriter 为 phase 4 检测缓冲响应正文，同时保留底层写入器
// 的可选接口。
type responseWriter struct {
	rw  http.ResponseWriter
	req *http.Request
	e   *engine
	tx  *transaction

	buffer []byte

	status         int
	wroteHeader    bool
	headerSent     bool
	inspectHeaders bool
	inspectBody    bool
	inspectPhase4  bool
	buffering      bool
	streaming      bool
	interrupted    bool
	hijacked       bool
	tooLarge       bool
}

// newResponseWriter creates a response wrapper. | newResponseWriter 创建响应包装器。
func newResponseWriter(rw http.ResponseWriter, req *http.Request, e *engine, tx *transaction, inspectHeaders, inspectBody bool) *responseWriter {
	return &responseWriter{
		rw:             rw,
		req:            req,
		e:              e,
		tx:             tx,
		inspectHeaders: inspectHeaders,
		inspectBody:    inspectBody,
		inspectPhase4:  e.rules.hasPhaseRules(PhaseResponseBody),
	}
}

// Header returns the underlying header map. | Header 返回底层头部映射。
func (w *responseWriter) Header() http.Header { return w.rw.Header() }

// WriteHeader evaluates phase 3 before sending response headers. | WriteHeader 在发送响应头之前
// 求值 phase 3。
func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader || w.hijacked {
		return
	}
	w.wroteHeader = true
	w.status = code
	w.tx.setResponseHeaders(w.rw.Header(), code, w.req.Proto)
	if w.inspectHeaders {
		w.e.processResponseHeaders(w.tx)
		if w.tx.interruption != nil {
			w.writeBlock()
			return
		}
	}
	w.buffering = w.inspectBody && w.tx.responseBodyAccess && w.e.rules.needsResponseBody &&
		bodyAllowed(code, w.req.Method) && w.eligibleContentType()
	if !w.buffering && w.inspectPhase4 {
		// Phase 4 rules that do not need a buffered body still run before headers are sent, so
		// they can interrupt the response. | 不需要缓冲正文的 phase 4 规则仍在发送响应头之前运行，
		// 因此它们可以中断响应。
		w.tx.setResponseBody(nil)
		w.e.processResponseBody(w.tx)
		if w.tx.interruption != nil {
			w.writeBlock()
			return
		}
	}
	if !w.buffering {
		w.rw.WriteHeader(code)
		w.headerSent = true
	}
}

// Write buffers eligible response bodies and passes everything else through. | Write 缓冲可检测的
// 响应正文，其余内容直接透传。
func (w *responseWriter) Write(p []byte) (int, error) {
	written := len(p)
	if w.hijacked {
		return written, nil
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.interrupted {
		return written, nil
	}
	if !w.buffering {
		return w.rw.Write(p)
	}
	limit := w.tx.responseBodyLimit
	if limit <= 0 {
		limit = defaultResponseBodyLimit
	}
	if len(w.buffer)+len(p) <= limit {
		w.buffer = append(w.buffer, p...)
		return written, nil
	}
	w.tooLarge = true
	if w.tx.responseBodyLimitAction == LimitReject {
		if len(w.buffer) < limit {
			remaining := limit - len(w.buffer)
			w.buffer = append(w.buffer, p[:remaining]...)
		}
		return written, nil
	}
	if len(w.buffer) < limit {
		remaining := limit - len(w.buffer)
		w.buffer = append(w.buffer, p[:remaining]...)
		p = p[remaining:]
	}
	if !w.flushPartial() {
		return written, nil
	}
	w.buffering = false
	w.streaming = true
	if len(p) > 0 {
		if _, err := w.rw.Write(p); err != nil {
			return 0, err
		}
	}
	return written, nil
}

// flushPartial inspects the buffered prefix and sends it. It reports whether sending continued.
// | flushPartial 检测已缓冲前缀并发送；返回是否继续发送。
func (w *responseWriter) flushPartial() bool {
	w.tx.setResponseBody(w.buffer)
	w.e.processResponseBody(w.tx)
	if w.tx.interruption != nil {
		w.writeBlock()
		return false
	}
	if !w.headerSent {
		w.rw.WriteHeader(w.status)
		w.headerSent = true
	}
	if len(w.buffer) > 0 {
		_, _ = w.rw.Write(w.buffer)
	}
	w.buffer = w.buffer[:0]
	return true
}

// Flush inspects the buffered prefix and flushes the underlying writer. | Flush 检测已缓冲前缀并
// 刷新底层写入器。
func (w *responseWriter) Flush() {
	if w.hijacked {
		return
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.interrupted {
		return
	}
	if w.buffering {
		if !w.flushPartial() {
			return
		}
		w.buffering = false
		w.streaming = true
	}
	if flusher, ok := w.rw.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack delegates to the underlying writer and disables response inspection for the tunnel.
// | Hijack 委托给底层写入器，并关闭隧道的响应检测。
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.rw.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, readWriter, err := hijacker.Hijack()
	if err == nil {
		w.hijacked = true
		w.buffer = w.buffer[:0]
	}
	return conn, readWriter, err
}

// Push delegates to the underlying pusher. | Push 委托给底层推送器。
func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.rw.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Unwrap exposes the underlying writer to http.ResponseController. | Unwrap 向
// http.ResponseController 暴露底层写入器。
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.rw }

// ReadFrom preserves the underlying ReaderFrom fast path when no buffering is active.
// | ReadFrom 在未缓冲时保留底层 ReaderFrom 快路径。
func (w *responseWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.buffering || w.hijacked || w.interrupted {
		return io.Copy(plainWriter{Writer: w}, r)
	}
	if readerFrom, ok := w.rw.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(w.rw, r)
}

// finish inspects the buffered response body and sends it. | finish 检测已缓冲响应正文并发送。
func (w *responseWriter) finish() error {
	if w.hijacked || w.interrupted {
		return nil
	}
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.interrupted || w.hijacked {
		return nil
	}
	if !w.buffering {
		return nil
	}
	if w.tooLarge && w.tx.responseBodyLimitAction == LimitReject {
		w.rw.WriteHeader(http.StatusInternalServerError)
		w.headerSent = true
		w.status = http.StatusInternalServerError
		return ErrResponseBodyTooLarge
	}
	if !w.flushPartial() {
		return nil
	}
	w.buffering = false
	return nil
}

// writeBlock writes the interruption response when headers have not been sent yet. | writeBlock 在
// 响应头尚未发送时写出中断响应。
func (w *responseWriter) writeBlock() {
	w.interrupted = true
	if w.headerSent {
		return
	}
	interruption := w.tx.interruption
	if interruption == nil {
		interruption = &Interruption{Action: "deny", Status: http.StatusForbidden}
	}
	meta := ruleMeta(w.e, interruption.RuleID)
	w.e.runHook(HookBeforeInterrupt, w.tx, interruption.Phase, meta, nil, nil)
	if w.tx.interruption != nil {
		interruption = w.tx.interruption
	}
	if interruption.Action == "drop" {
		if hijacker, ok := w.rw.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				w.hijacked = true
				w.buffer = w.buffer[:0]
				w.status = interruption.Status
				if w.status == 0 {
					w.status = http.StatusForbidden
				}
				w.headerSent = true
				w.e.runHook(HookAfterInterrupt, w.tx, interruption.Phase, ruleMeta(w.e, interruption.RuleID), nil, nil)
				_ = conn.Close()
				return
			}
		}
	}
	w.e.cfg.errorHandler()(w.rw, w.req, interruption)
	w.status = interruption.Status
	w.headerSent = true
	w.e.runHook(HookAfterInterrupt, w.tx, interruption.Phase, ruleMeta(w.e, interruption.RuleID), nil, nil)
}

// eligibleContentType reports whether the response content type is configured for inspection.
// | eligibleContentType 报告响应内容类型是否配置为可检测。
func (w *responseWriter) eligibleContentType() bool {
	contentType := w.rw.Header().Get("Content-Type")
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	}
	mediaType = strings.ToLower(mediaType)
	for _, eligible := range w.e.rules.responseMime {
		eligible = strings.ToLower(eligible)
		if eligible == "*/*" || eligible == mediaType {
			return true
		}
		if strings.HasSuffix(eligible, "/*") && strings.HasPrefix(mediaType, strings.TrimSuffix(eligible, "*")) {
			return true
		}
	}
	return false
}

// bodyAllowed reports whether a response status and method carry a body. | bodyAllowed 报告响应
// 状态与方法是否携带正文。
func bodyAllowed(status int, method string) bool {
	if method == http.MethodHead {
		return false
	}
	switch {
	case status >= 100 && status < 200:
		return false
	case status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	default:
		return true
	}
}

// plainWriter hides responseWriter's ReadFrom to avoid recursive io.Copy. | plainWriter 隐藏
// responseWriter 的 ReadFrom，避免 io.Copy 递归。
type plainWriter struct {
	io.Writer
}

// ruleMeta resolves the metadata for an interrupting rule. | ruleMeta 解析中断规则的元数据。
func ruleMeta(e *engine, id int) *Rule {
	if e == nil || e.rules == nil || id <= 0 {
		return nil
	}
	if rule, ok := e.rules.byID[id]; ok {
		return rule.meta
	}
	return nil
}
