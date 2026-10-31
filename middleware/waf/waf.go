package waf

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// WAF is a Coraza-backed web application firewall with a complete per-request lifecycle:
// request headers, request body, response headers, response body, logging phase and transaction
// cleanup. One instance is safe for concurrent use and can be shared by every route. | WAF 是
// 基于 Coraza 的 Web 应用防火墙，覆盖完整的每请求生命周期：请求头、请求正文、响应头、响应正文、
// 日志阶段与事务清理。单个实例可并发安全地共享给所有路由。
type WAF struct {
	current atomic.Pointer[engine]
	// retiring holds engines replaced by Reload that still have in-flight requests. Shutdown
	// waits for them as well, so a reload cannot hide a request from graceful draining. |
	// retiring 保存被 Reload 替换但仍带有在途请求的引擎。Shutdown 同样等待它们，避免重载让某个
	// 请求逃过优雅排空。
	retiring []*engine
	opts     Options
	counts   counters
	mu       sync.Mutex
	closed   atomic.Bool
}

// counters keeps lock-free statistics. | counters 保存无锁统计。
type counters struct {
	inspected atomic.Int64
	blocked   atomic.Int64
	detected  atomic.Int64
	errors    atomic.Int64
	bypassed  atomic.Int64
	rejected  atomic.Int64
	reloads   atomic.Int64
	inflight  atomic.Int64
}

// Stats is a point-in-time snapshot of the instance counters. | Stats 是实例计数器的瞬时快照。
type Stats struct {
	// Inspected counts requests that entered a Coraza transaction. | Inspected 统计进入 Coraza
	// 事务的请求数。
	Inspected int64
	// Blocked counts requests interrupted in blocking mode. | Blocked 统计拦截模式下被中断的请求数。
	Blocked int64
	// Detected counts requests that would have been blocked in detection-only mode. | Detected
	// 统计仅检测模式下本应被拦截的请求数。
	Detected int64
	// Errors counts inspection, build and reload failures. | Errors 统计检测、构建与重载失败数。
	Errors int64
	// Bypassed counts excluded requests and requests handled while the engine was off. | Bypassed
	// 统计被排除以及引擎关闭时放行的请求数。
	Bypassed int64
	// Rejected counts requests refused because the instance was closed. | Rejected 统计因实例关闭
	// 而被拒绝的请求数。
	Rejected int64
	// Reloads counts successful rule reloads. | Reloads 统计成功的规则重载次数。
	Reloads int64
	// InFlight is the number of requests currently holding an engine reservation. Long-lived
	// bypassed or CONNECT requests release it as soon as inspection ends. | InFlight 是当前持有
	// 引擎预留的请求数；被旁路或 CONNECT 的长连接在检测结束后立即释放。
	InFlight int64
}

// New builds a WAF instance. An empty rule set is rejected: a WAF without rules would only add
// latency while protecting nothing. | New 构造 WAF 实例。空规则集会被拒绝：没有规则的 WAF 只会
// 增加延迟而不会提供任何保护。
func New(o Options) (*WAF, error) {
	normalized, err := o.normalize()
	if err != nil {
		return nil, err
	}
	e, err := buildEngine(normalized, normalized.loggerOrDefault())
	if err != nil {
		return nil, err
	}
	w := &WAF{opts: normalized}
	w.current.Store(e)
	return w, nil
}

// Middleware returns the YD router entry point. | Middleware 返回 YD 路由入口。
//
// Register it before other middleware: the YD chain unwinds outwards, so middleware registered
// after the WAF is covered, while middleware registered before it can write after inspection.
// Request and response bodies of the covered inner chain are inspected. | 请在其他中间件之前注册：
// YD 链向外展开，因此注册在 WAF 之后的中间件会被覆盖，而注册在它之前的中间件可以在检测结束后写入。
// 被覆盖的内层链的请求与响应正文都会被检测。
func (w *WAF) Middleware() router.Middleware {
	return func(c *router.Ctx) {
		if !w.serve(c.Writer, c.Request, func(writer http.ResponseWriter) {
			original := c.Writer
			c.Writer = writer
			defer func() { c.Writer = original }()
			c.Next()
		}) {
			// YD's chain continues unless it is explicitly aborted; a blocked request must not
			// reach the route handler. | YD 链会继续执行，除非显式终止；被拦截的请求绝不能进入
			// 路由处理器。
			c.Abort()
		}
	}
}

// HTTPMiddleware returns the native net/http entry point. A nil next behaves as http.NotFound.
// | HTTPMiddleware 返回原生 net/http 入口。next 为 nil 时按 http.NotFound 处理。
func (w *WAF) HTTPMiddleware(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.serve(rw, r, func(writer http.ResponseWriter) {
			next.ServeHTTP(writer, r)
		})
	})
}

// serve runs the request through the full lifecycle. It reports whether run was invoked; a
// false result means the request was answered by the WAF and the caller must stop the chain. |
// serve 让请求走完整生命周期。它报告是否调用了 run；返回 false 表示请求已由 WAF 应答，调用方
// 必须终止链。
func (w *WAF) serve(rw http.ResponseWriter, r *http.Request, run func(http.ResponseWriter)) bool {
	start := time.Now()
	e, ok := w.acquire()
	if !ok {
		w.counts.rejected.Add(1)
		http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return false
	}
	released := false
	defer func() {
		if !released {
			w.release(e)
		}
	}()

	if e.cfg.Exclude != nil && e.cfg.Exclude(r) {
		w.counts.bypassed.Add(1)
		// No inspection happens after this point, so a long-lived handler must not pin the
		// engine (and block reload retirement or shutdown draining). | 此后不再检测，长时间运行的
		// 处理器不得继续占用引擎（否则会阻塞重载退休或关闭排空）。
		w.release(e)
		released = true
		run(rw)
		return true
	}
	if e.off {
		w.counts.bypassed.Add(1)
		w.release(e)
		released = true
		run(rw)
		return true
	}

	w.counts.inspected.Add(1)
	client := clientIP(e.cfg, r)
	tx := e.newTx(r.Context())
	txClosed := false
	defer func() {
		if !txClosed {
			e.closeTransaction(tx)
		}
	}()

	readBody := e.readRequestBody && r.Method != http.MethodConnect
	if readBody && e.cfg.InspectRequestBody != nil && !e.cfg.InspectRequestBody(r) {
		readBody = false
	}
	interruption, err := processRequest(tx, r, client, readBody)
	if err != nil {
		status := requestErrorStatus(err)
		w.counts.errors.Add(1)
		http.Error(rw, http.StatusText(status), status)
		w.emitEvent(e, Event{
			ID:       tx.ID(),
			Method:   r.Method,
			Path:     r.URL.Path,
			ClientIP: client,
			Status:   status,
			Duration: time.Since(start),
			Err:      err,
		}, tx)
		return false
	}
	requestDetected := detectionInterruption(tx) != nil
	if interruption != nil {
		intr := newInterruption(tx.ID(), interruption, PhaseRequest)
		w.counts.blocked.Add(1)
		handler := e.cfg.ErrorHandler
		if handler == nil {
			handler = DefaultErrorHandler
		}
		handler(rw, r, intr)
		w.emitEvent(e, Event{
			ID:           tx.ID(),
			Method:       r.Method,
			Path:         r.URL.Path,
			ClientIP:     client,
			Status:       intr.Status,
			Blocked:      true,
			Phase:        PhaseRequest,
			Interruption: intr,
			Duration:     time.Since(start),
		}, tx)
		return false
	}

	if r.Method == http.MethodConnect {
		// CONNECT carries a tunnel (WebSocket over HTTP/2/3, WebTransport, raw TCP). Transport
		// handlers assert concrete writer interfaces such as http3.Settingser and
		// http3.HTTPStreamer, which no generic wrapper can preserve, so the response phase is
		// skipped entirely. The request line and headers were already inspected above. |
		// CONNECT 携带隧道（HTTP/2/3 WebSocket、WebTransport、原始 TCP）。传输层处理器会断言
		// http3.Settingser、http3.HTTPStreamer 等具体写入器接口，任何通用包装器都无法保留，
		// 因此这里整体跳过响应阶段；请求行与请求头已在上面完成检测。
		event := Event{
			ID:       tx.ID(),
			Method:   r.Method,
			Path:     r.URL.Path,
			ClientIP: client,
			Duration: time.Since(start),
		}
		if detected := detectionInterruption(tx); detected != nil {
			w.counts.detected.Add(1)
			event.Detected = true
			event.Phase = PhaseRequest
			event.Interruption = newInterruption(tx.ID(), detected, PhaseRequest)
		}
		w.emitEvent(e, event, tx)
		// A tunnel can stay open for hours; do not keep its transaction alive for that long. |
		// 隧道可能保持数小时，因此不要让事务一直存活到这里。
		e.closeTransaction(tx)
		txClosed = true
		w.release(e)
		released = true
		run(rw)
		return true
	}

	inspect := e.inspectResponse
	if inspect.body && e.cfg.InspectResponseBody != nil && !e.cfg.InspectResponseBody(r) {
		inspect.body = false
	}
	// No response-phase rule and no observer means nothing needs the response writer wrapper.
	// Hand the original writer to the handler so Flusher/Hijacker/Pusher and net/http content
	// sniffing keep their native fast paths. | 没有响应阶段规则且没有观察者时，响应写入器包装器
	// 没有用途。直接把原始写入器交给处理器，保留 Flusher/Hijacker/Pusher 与 net/http 的
	// Content-Type 嗅探快路径。
	if !inspect.headers && !inspect.body && e.cfg.Observer == nil {
		run(rw)
		if detected := detectionInterruption(tx); detected != nil {
			w.counts.detected.Add(1)
			w.emitEvent(e, Event{
				ID:           tx.ID(),
				Method:       r.Method,
				Path:         r.URL.Path,
				ClientIP:     client,
				Detected:     true,
				Phase:        PhaseRequest,
				Interruption: newInterruption(tx.ID(), detected, PhaseRequest),
				Duration:     time.Since(start),
			}, tx)
		}
		return true
	}

	writer, ic := newResponseWriter(rw, r, tx, e.cfg.ErrorHandler, inspect)
	defer releaseInterceptor(ic)
	run(writer)

	if err := ic.finish(); err != nil {
		w.counts.errors.Add(1)
		w.emitEvent(e, Event{
			ID:       tx.ID(),
			Method:   r.Method,
			Path:     r.URL.Path,
			ClientIP: client,
			Status:   ic.status,
			Duration: time.Since(start),
			Err:      errs.Wrap(err, ErrResponseBody),
		}, tx)
		return true
	}

	event := Event{
		ID:       tx.ID(),
		Method:   r.Method,
		Path:     r.URL.Path,
		ClientIP: client,
		Status:   ic.status,
		Duration: time.Since(start),
	}
	if ic.interruption != nil {
		w.counts.blocked.Add(1)
		event.Blocked = true
		event.Phase = PhaseResponse
		event.Interruption = newInterruption(tx.ID(), ic.interruption, PhaseResponse)
	} else if detected := detectionInterruption(tx); detected != nil {
		w.counts.detected.Add(1)
		event.Detected = true
		event.Phase = PhaseResponse
		if requestDetected {
			event.Phase = PhaseRequest
		}
		event.Interruption = newInterruption(tx.ID(), detected, event.Phase)
	}
	w.emitEvent(e, event, tx)
	return true
}

// acquire loads the current engine and reserves it for one request. A request that races with a
// reload retries against the new pointer; a closed instance returns false. | acquire 加载当前引擎
// 并为单次请求预留。与重载竞争的请求会针对新指针重试；实例关闭后返回 false。
func (w *WAF) acquire() (*engine, bool) {
	for attempt := 0; attempt < 8; attempt++ {
		e := w.current.Load()
		if e == nil {
			return nil, false
		}
		if e.acquire() {
			w.counts.inflight.Add(1)
			return e, true
		}
	}
	return nil, false
}

// release returns one request reservation. | release 归还一次请求预留。
func (w *WAF) release(e *engine) {
	w.counts.inflight.Add(-1)
	e.release()
}

// closeTransaction runs the logging phase and releases transaction buffers. | closeTransaction
// 执行日志阶段并释放事务缓冲。
func (e *engine) closeTransaction(tx types.Transaction) {
	defer func() {
		if err := tx.Close(); err != nil {
			e.logger.Error("waf transaction close failed | WAF 事务关闭失败",
				log.Str("tx_id", tx.ID()), log.Err(err))
		}
	}()
	tx.ProcessLogging()
}

// emitEvent logs interesting outcomes and forwards every observed request. Matched rules are
// materialized only when the observer or a block/detection/error path needs them. | emitEvent
// 记录值得关注的结果，并转发每个被观察的请求。仅在观察者或拦截/检测/错误路径需要时才生成命中规则。
func (w *WAF) emitEvent(e *engine, event Event, tx types.Transaction) {
	interesting := event.Blocked || event.Detected || event.Err != nil
	if !interesting && e.cfg.Observer == nil {
		return
	}
	event.Matches = collectMatches(tx)
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
			// The interrupting rule is often CRS's anomaly-evaluation rule (949xxx); the first
			// match points at the attack rule that actually scored. | 中断规则通常是 CRS 的异常分
			// 评估规则（949xxx）；首个命中指向真正计分的攻击规则。
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
}

// RulesCount returns the number of rules in the active engine, or zero after Close. | RulesCount
// 返回当前引擎的规则数，关闭后返回零。
func (w *WAF) RulesCount() int {
	e := w.current.Load()
	if e == nil {
		return 0
	}
	return e.rules
}

// Stats returns a snapshot of the instance counters. | Stats 返回实例计数器快照。
func (w *WAF) Stats() Stats {
	return Stats{
		Inspected: w.counts.inspected.Load(),
		Blocked:   w.counts.blocked.Load(),
		Detected:  w.counts.detected.Load(),
		Errors:    w.counts.errors.Load(),
		Bypassed:  w.counts.bypassed.Load(),
		Rejected:  w.counts.rejected.Load(),
		Reloads:   w.counts.reloads.Load(),
		InFlight:  w.counts.inflight.Load(),
	}
}

// Reload re-reads RuleFiles and recompiles Directives with the current options. The new engine is
// swapped atomically; if compilation fails, the old engine keeps serving and the error is
// returned. | Reload 使用当前配置重新读取 RuleFiles 并重新编译 Directives。新引擎原子替换；编译
// 失败时旧引擎继续服务并返回错误。
func (w *WAF) Reload() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return ErrClosed
	}
	return w.reloadLocked(w.opts)
}

// ReloadWith replaces the options, then recompiles and swaps the engine. The provided Options
// replace every previous field, including Logger, DebugLogWriter, Observer, Exclude and
// ErrorHandler. On failure the previous options and engine remain active. | ReloadWith 先替换
// 配置，再重新编译并替换引擎。提供的 Options 会替换此前的所有字段，包括 Logger、
// DebugLogWriter、Observer、Exclude 与 ErrorHandler。失败时保留原有配置与引擎。
func (w *WAF) ReloadWith(o Options) error {
	normalized, err := o.normalize()
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return ErrClosed
	}
	return w.reloadLocked(normalized)
}

// reloadLocked compiles and swaps while the caller holds mu. | reloadLocked 在调用方持有 mu 时
// 编译并替换。
func (w *WAF) reloadLocked(o Options) error {
	logger := o.loggerOrDefault()
	next, err := buildEngine(o, logger)
	if err != nil {
		w.counts.errors.Add(1)
		logger.Error("waf reload failed | WAF 重载失败", log.Err(err))
		return err
	}
	previous := w.current.Swap(next)
	w.opts = o
	if previous != nil {
		previous.retire()
		w.retiring = append(w.retiring, previous)
		w.pruneRetiredLocked()
	}
	w.counts.reloads.Add(1)
	logger.Info("waf rules reloaded | WAF 规则已重新加载",
		log.Int("rules", next.rules),
		log.Str("mode", o.Mode.String()))
	return nil
}

// pruneRetiredLocked drops engines that have already drained; the caller holds mu. |
// pruneRetiredLocked 丢弃已经排空的引擎；调用方持有 mu。
func (w *WAF) pruneRetiredLocked() {
	kept := w.retiring[:0]
	for _, old := range w.retiring {
		if !old.isDrained() {
			kept = append(kept, old)
		}
	}
	w.retiring = kept
}

// Close stops accepting requests and releases the engine once in-flight transactions finish. It
// is idempotent and does not block; use Shutdown for graceful draining. | Close 停止接收请求，并在
// 在途事务结束后释放引擎。它是幂等的且不阻塞；优雅排空请使用 Shutdown。
func (w *WAF) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Swap(true) {
		return nil
	}
	if e := w.current.Swap(nil); e != nil {
		e.retire()
	}
	// Retired engines close themselves once their last request leaves; dropping the references
	// here lets the garbage collector reclaim them after that. | 退休引擎会在最后一个请求离开后
	// 自行关闭；这里丢弃引用，使其随后可被垃圾回收。
	w.retiring = nil
	return nil
}

// Shutdown stops accepting requests and waits until every in-flight transaction has finished or
// ctx expires. The returned error wraps ErrShutdownTimeout and the context error when draining
// times out. After a timeout the instance stays closed: remaining engines close as their
// requests finish, and a later Shutdown returns immediately. | Shutdown 停止接收请求，并等待所有
// 在途事务结束或 ctx 到期。排空超时时返回的错误同时包装 ErrShutdownTimeout 与上下文错误。超时后
// 实例保持关闭：剩余引擎会在各自请求结束后关闭，之后的 Shutdown 调用立即返回。
func (w *WAF) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.Lock()
	if w.closed.Swap(true) {
		w.mu.Unlock()
		return nil
	}
	engines := make([]*engine, 0, len(w.retiring)+1)
	if e := w.current.Swap(nil); e != nil {
		engines = append(engines, e)
	}
	engines = append(engines, w.retiring...)
	w.retiring = nil
	w.mu.Unlock()
	for _, e := range engines {
		e.retire()
		if err := e.wait(ctx); err != nil {
			return errs.Wrap(err, ErrShutdownTimeout)
		}
	}
	return nil
}
