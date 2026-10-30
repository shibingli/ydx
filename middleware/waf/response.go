package waf

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/corazawaf/coraza/v3/types"
)

// responseInspection controls which response stages need Coraza processing. Skipping stages
// with no matching rules avoids header collection and body buffering on the hot path. |
// responseInspection 控制哪些响应阶段需要 Coraza 处理。跳过没有对应规则的阶段可以避免热路径上的
// 响应头采集与正文缓冲。
type responseInspection struct {
	headers bool
	body    bool
}

// interceptor wraps the response writer for the duration of one request. It mirrors Coraza's
// official interceptor: headers are fed to phase 3, body bytes are buffered for phase 4 when
// response access is enabled, and an interruption replaces the pending response with the
// configured error response. | interceptor 在单个请求期间包装响应写入器。它与 Coraza 官方拦截器
// 一致：响应头送入阶段 3，开启响应访问时正文按字节缓冲以供阶段 4 检测，中断则用配置的错误响应
// 替换尚未发出的响应。
type interceptor struct {
	w            http.ResponseWriter
	tx           types.Transaction
	req          *http.Request
	handler      ErrorHandler
	interruption *types.Interruption
	proto        string

	inspectHeaders bool
	inspectBody    bool

	status        int
	wroteHeader   bool
	flushed       bool
	wroteBuffered bool
	allowFlush    bool
	hijacked      bool
	interrupted   bool
	failed        bool
	finished      bool
}

// interceptorPool recycles the wrapper. The wrapper is returned to the pool only after the
// response has been finished or the request has unwound, so no handler can observe a reused
// instance. | interceptorPool 复用包装器。只有响应结束或请求展开后才会归还池中，因此处理器
// 绝不会观察到被复用的实例。
var interceptorPool = sync.Pool{New: func() any { return new(interceptor) }}

// newResponseWriter builds the writer passed to the next handler. It preserves http.Hijacker and
// http.Pusher only when the underlying writer supports them, keeping interface assertions
// honest. | newResponseWriter 构造传给下一个处理器的写入器。仅当底层写入器支持时才暴露
// http.Hijacker 与 http.Pusher，从而保证接口断言的真实性。
func newResponseWriter(w http.ResponseWriter, r *http.Request, tx types.Transaction, handler ErrorHandler, inspect responseInspection) (http.ResponseWriter, *interceptor) {
	i := interceptorPool.Get().(*interceptor)
	*i = interceptor{
		w:              w,
		tx:             tx,
		req:            r,
		handler:        handler,
		proto:          r.Proto,
		inspectHeaders: inspect.headers,
		inspectBody:    inspect.body,
		status:         http.StatusOK,
	}
	hijacker, hasHijacker := w.(http.Hijacker)
	pusher, hasPusher := w.(http.Pusher)
	switch {
	case hasHijacker && hasPusher:
		return &hijackPushWriter{interceptor: i, hijacker: hijacker, pusher: pusher}, i
	case hasHijacker:
		return &hijackWriter{interceptor: i, hijacker: hijacker}, i
	case hasPusher:
		return &pushWriter{interceptor: i, pusher: pusher}, i
	default:
		return i, i
	}
}

// releaseInterceptor clears request references and returns the wrapper to the pool. | releaseInterceptor
// 清除请求引用并把包装器归还池中。
func releaseInterceptor(i *interceptor) {
	*i = interceptor{}
	interceptorPool.Put(i)
}

// Header implements http.ResponseWriter. | Header 实现 http.ResponseWriter。
func (i *interceptor) Header() http.Header { return i.w.Header() }

// Unwrap exposes the original writer to http.ResponseController. | Unwrap 向
// http.ResponseController 暴露原始写入器。
func (i *interceptor) Unwrap() http.ResponseWriter { return i.w }

// WriteHeader implements http.ResponseWriter. | WriteHeader 实现 http.ResponseWriter。
func (i *interceptor) WriteHeader(code int) {
	if i.wroteHeader || i.interrupted || i.failed {
		return
	}
	i.wroteHeader = true
	i.status = code
	if i.inspectHeaders {
		for key, values := range i.w.Header() {
			for _, value := range values {
				i.tx.AddResponseHeader(key, value)
			}
		}
		if it := i.tx.ProcessResponseHeaders(code, i.proto); it != nil {
			i.block(it)
			return
		}
	}
	if code == http.StatusSwitchingProtocols {
		i.flushHeader()
	}
	if !i.inspectBody || !i.tx.IsResponseBodyAccessible() || !i.tx.IsResponseBodyProcessable() {
		// The body will be streamed, so flushing must not wait for a phase-4 decision. |
		// 正文将直接流式下发，因此 Flush 不必等待阶段 4 的结论。
		i.allowFlush = true
	}
}

// Write implements http.ResponseWriter. | Write 实现 http.ResponseWriter。
func (i *interceptor) Write(b []byte) (int, error) {
	if i.interrupted || i.failed {
		// The response has already been replaced; report success so handlers stop retrying. |
		// 响应已被替换；返回成功以避免处理器反复重试。
		return len(b), nil
	}
	if !i.wroteHeader {
		// Calling the underlying WriteHeader would suppress net/http's content sniffing, so
		// reproduce it here before committing the header. | 直接调用底层 WriteHeader 会抑制
		// net/http 的内容嗅探，因此在提交响应头之前复现该行为。
		if i.w.Header().Get("Content-Type") == "" && len(b) > 0 {
			i.w.Header().Set("Content-Type", http.DetectContentType(b))
		}
		i.WriteHeader(http.StatusOK)
		if i.interrupted || i.failed {
			return len(b), nil
		}
	}
	if i.inspectBody && i.tx.IsResponseBodyAccessible() && i.tx.IsResponseBodyProcessable() && !i.wroteBuffered {
		it, n, err := i.tx.WriteResponseBody(b)
		if it != nil {
			i.block(it)
			return len(b), nil
		}
		if err != nil {
			i.failInternal()
			return n, err
		}
		if n == len(b) {
			return n, nil
		}
		// The limit was reached with ProcessPartial: release the buffered prefix, then stream
		// the rest without further buffering. | 达到上限且动作为 ProcessPartial：先释放已缓冲的
		// 前缀，再直接流式发送剩余部分。
		if err := i.flushBufferedBody(); err != nil {
			return n, err
		}
		n2, err := i.w.Write(b[n:])
		return n + n2, err
	}
	i.flushHeader()
	i.allowFlush = true
	return i.w.Write(b)
}

// ReadFrom implements io.ReaderFrom. When the response is streamed, the copy is delegated to
// the underlying writer so file serving keeps its ReaderFrom fast path; when the body must be
// inspected, every byte flows through Write. | ReadFrom 实现 io.ReaderFrom。响应直接流式下发时，
// 拷贝委托给底层写入器，保留文件服务的 ReaderFrom 快路径；正文需要检测时，每个字节都经过 Write。
func (i *interceptor) ReadFrom(r io.Reader) (int64, error) {
	if i.interrupted || i.failed {
		return 0, nil
	}
	if !i.wroteHeader {
		// Without an explicit Content-Type, fall through to Write so net/http-compatible
		// content sniffing still happens on the first chunk. | 未显式设置 Content-Type 时走 Write，
		// 保留与 net/http 一致的首块内容嗅探。
		if i.w.Header().Get("Content-Type") == "" {
			return io.Copy(struct{ io.Writer }{i}, r)
		}
		i.WriteHeader(http.StatusOK)
		if i.interrupted || i.failed {
			return 0, nil
		}
	}
	if i.inspectBody && i.tx.IsResponseBodyAccessible() && i.tx.IsResponseBodyProcessable() {
		// Hide the ReaderFrom implementation from io.Copy to avoid infinite recursion. | 对 io.Copy
		// 隐藏 ReaderFrom 实现，避免无限递归。
		return io.Copy(struct{ io.Writer }{i}, r)
	}
	i.allowFlush = true
	i.flushHeader()
	if readerFrom, ok := i.w.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(i.w, r)
}

// Flush implements http.Flusher. A response whose body is being buffered defers the flush until
// phase 4 has decided, which is what prevents a blocked body from reaching the client. | Flush
// 实现 http.Flusher。正在缓冲正文的响应会推迟到阶段 4 得出结论后再刷新，从而避免被拦截的正文
// 提前到达客户端。
func (i *interceptor) Flush() {
	if i.interrupted || i.failed {
		return
	}
	if !i.wroteHeader {
		i.WriteHeader(http.StatusOK)
	}
	if i.interrupted || i.failed || !i.allowFlush {
		return
	}
	i.flushHeader()
	if flusher, ok := i.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

// finish completes phase 4 and releases any buffered response body. | finish 完成阶段 4 并释放
// 已缓冲的响应正文。
func (i *interceptor) finish() error {
	if i.finished {
		return nil
	}
	i.finished = true
	if i.hijacked || i.interrupted || i.failed {
		return nil
	}
	if !i.wroteHeader {
		i.WriteHeader(http.StatusOK)
		if i.interrupted || i.failed {
			return nil
		}
	}
	if i.tx.IsInterrupted() {
		i.block(i.tx.Interruption())
		return nil
	}
	if i.inspectBody && i.tx.IsResponseBodyAccessible() && i.tx.IsResponseBodyProcessable() && !i.wroteBuffered {
		it, err := i.tx.ProcessResponseBody()
		if err != nil {
			i.failInternal()
			return err
		}
		if it != nil {
			i.block(it)
			return nil
		}
		return i.flushBufferedBody()
	}
	i.allowFlush = true
	i.flushHeader()
	return nil
}

// block replaces the pending response with the configured error response. | block 用配置的错误
// 响应替换尚未发出的响应。
func (i *interceptor) block(it *types.Interruption) {
	if i.interrupted || i.failed {
		return
	}
	i.interrupted = true
	i.interruption = it
	if i.flushed {
		// Part of the response is already on the wire; nothing can be replaced. | 响应的一部分
		// 已经发出，无法再替换。
		return
	}
	i.cleanHeaders()
	i.status = interruptionStatus(it)
	i.flushed = true
	handler := i.handler
	if handler == nil {
		handler = DefaultErrorHandler
	}
	handler(i.w, i.req, newInterruption(i.tx.ID(), it, PhaseResponse))
}

// failInternal writes a generic 500 when the response has not been committed yet. | failInternal
// 在响应尚未提交时写出通用 500。
func (i *interceptor) failInternal() {
	if i.failed || i.interrupted {
		return
	}
	i.failed = true
	if i.flushed {
		return
	}
	i.cleanHeaders()
	i.status = http.StatusInternalServerError
	i.flushed = true
	http.Error(i.w, http.StatusText(i.status), i.status)
}

// flushHeader commits the status line and headers exactly once. | flushHeader 只提交一次状态行与
// 响应头。
func (i *interceptor) flushHeader() {
	if i.flushed {
		return
	}
	i.w.WriteHeader(i.status)
	i.flushed = true
}

// flushBufferedBody copies the bytes Coraza buffered back to the client. | flushBufferedBody 把
// Coraza 缓冲的字节回拷给客户端。
func (i *interceptor) flushBufferedBody() error {
	if i.wroteBuffered {
		return nil
	}
	reader, err := i.tx.ResponseBodyReader()
	if err != nil {
		i.failInternal()
		return err
	}
	i.flushHeader()
	if _, err := io.Copy(i.w, reader); err != nil {
		return err
	}
	i.wroteBuffered = true
	i.allowFlush = true
	return nil
}

// cleanHeaders removes every pending header so a blocked response cannot leak application
// headers. | cleanHeaders 删除所有待发响应头，避免被拦截的响应泄漏业务响应头。
func (i *interceptor) cleanHeaders() {
	header := i.w.Header()
	for key := range header {
		header.Del(key)
	}
}

// hijackWriter preserves http.Hijacker. | hijackWriter 保留 http.Hijacker。
type hijackWriter struct {
	*interceptor
	hijacker http.Hijacker
}

// Hijack implements http.Hijacker. | Hijack 实现 http.Hijacker。
func (h *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := h.hijacker.Hijack()
	if err == nil {
		h.interceptor.hijacked = true
	}
	return conn, rw, err
}

// pushWriter preserves http.Pusher. | pushWriter 保留 http.Pusher。
type pushWriter struct {
	*interceptor
	pusher http.Pusher
}

// Push implements http.Pusher. | Push 实现 http.Pusher。
func (p *pushWriter) Push(target string, opts *http.PushOptions) error {
	return p.pusher.Push(target, opts)
}

// hijackPushWriter preserves both optional interfaces. | hijackPushWriter 同时保留两个可选接口。
type hijackPushWriter struct {
	*interceptor
	hijacker http.Hijacker
	pusher   http.Pusher
}

// Hijack implements http.Hijacker. | Hijack 实现 http.Hijacker。
func (h *hijackPushWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := h.hijacker.Hijack()
	if err == nil {
		h.interceptor.hijacked = true
	}
	return conn, rw, err
}

// Push implements http.Pusher. | Push 实现 http.Pusher。
func (h *hijackPushWriter) Push(target string, opts *http.PushOptions) error {
	return h.pusher.Push(target, opts)
}
