package waf

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// WAF is a rule-driven web application firewall with atomic hot reload. One instance is safe for
// concurrent use and can be shared by every route. | WAF 是带原子热更新的规则驱动 Web 应用防火墙。
// 单个实例可并发安全地共享给所有路由。
type WAF struct {
	current atomic.Pointer[engine]
	bundle  *Bundle
	hooks   *hookRegistry
	alerter atomic.Pointer[alerter]
	logger  *log.Logger

	watchCancel context.CancelFunc
	// retiring holds engines replaced by Reload that still have in-flight requests. | retiring
	// 保存被 Reload 替换但仍带有在途请求的引擎。
	retiring []*engine
	opts     Options
	counts   counters
	watchWG  sync.WaitGroup

	mu      sync.Mutex
	auditMu sync.Mutex
	closed  atomic.Bool
}

// New builds a WAF instance from rules, a rule source or explicit directives. | New 从规则、规则
// 来源或显式指令构建 WAF 实例。
func New(o Options) (*WAF, error) {
	normalized, err := o.normalize()
	if err != nil {
		return nil, err
	}
	logger := normalized.loggerOrDefault()
	w := &WAF{opts: normalized, logger: logger}
	w.hooks = newHookRegistry(normalized.Hooks, logger, &w.counts, normalized.PluginTimeout)
	alerting, err := newAlerter(normalized.Alerting, logger, &w.counts)
	if err != nil {
		return nil, err
	}
	w.alerter.Store(alerting)
	bundle, err := w.initialBundle(context.Background(), normalized)
	if err != nil {
		w.closeAlerter()
		return nil, err
	}
	e, err := buildEngine(normalized, bundle, logger, w.hooks, &w.counts)
	if err != nil {
		w.closeAlerter()
		return nil, err
	}
	w.bundle = bundle
	w.current.Store(e)
	if normalized.WatchInterval > 0 && normalized.Source != nil {
		w.startWatcher()
	}
	return w, nil
}

// Middleware returns the YD router entry point. Register it before middleware whose output must
// also be inspected. | Middleware 返回 YD 路由入口。请把需要检测其输出的中间件注册在它之后。
func (w *WAF) Middleware() router.Middleware {
	return func(c *router.Ctx) {
		if !w.serve(c.Writer, c.Request, func(writer http.ResponseWriter) {
			original := c.Writer
			c.Writer = writer
			defer func() { c.Writer = original }()
			c.Next()
		}) {
			c.Abort()
		}
	}
}

// HTTPMiddleware returns the native net/http entry point. A nil next behaves as http.NotFound.
// | HTTPMiddleware 返回原生 net/http 入口；next 为 nil 时按 http.NotFound 处理。
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

// initialBundle resolves the first bundle, trying the source, the last-known-good cache and
// local rules in that order. | initialBundle 解析首个规则包，按来源、last-known-good 缓存与本地
// 规则的顺序回退。
func (w *WAF) initialBundle(ctx context.Context, opts Options) (*Bundle, error) {
	if opts.Source == nil {
		bundle, warnings, err := loadLocalSource(opts)
		w.logWarnings(warnings)
		return bundle, err
	}
	bundle, err := w.loadSource(ctx, opts)
	if err == nil {
		w.persist(opts, bundle)
		return bundle, nil
	}
	w.logger.Warn("waf rule source failed, trying fallback | WAF 规则来源失败，尝试回退",
		log.Err(err), log.Str("fallback", "last-known-good"))
	if opts.LastKnownGood != "" {
		if cached, cacheErr := readLastKnownGood(opts.LastKnownGood); cacheErr == nil {
			w.logger.Warn("waf using last-known-good bundle | WAF 使用 last-known-good 规则包",
				log.Str("version", cached.Version), log.Str("digest", cached.Digest))
			return cached, nil
		} else {
			w.logger.Warn("waf last-known-good unavailable | WAF last-known-good 不可用", log.Err(cacheErr))
		}
	}
	if len(opts.RuleFiles) > 0 || len(opts.Directives) > 0 {
		local, warnings, localErr := loadLocalSource(opts)
		w.logWarnings(warnings)
		if localErr == nil {
			w.logger.Warn("waf using local rules after source failure | WAF 来源失败后使用本地规则")
			return local, nil
		}
	}
	return nil, errs.Wrap(err, ErrSource)
}

// loadSource loads one bundle with retry. | loadSource 带重试地加载一个规则包。
func (w *WAF) loadSource(ctx context.Context, opts Options) (*Bundle, error) {
	var bundle *Bundle
	err := opts.Retry.do(ctx, func(callCtx context.Context) error {
		loaded, loadErr := opts.Source.Load(callCtx)
		if loadErr != nil {
			return loadErr
		}
		bundle = loaded
		return nil
	})
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, ErrInvalidBundle
	}
	return bundle, nil
}

// resolveBundle loads a bundle for reload, falling back to the last-known-good cache.
// | resolveBundle 为重载加载规则包，失败时回退到 last-known-good 缓存。
func (w *WAF) resolveBundle(ctx context.Context, opts Options) (*Bundle, error) {
	if opts.Source == nil {
		bundle, warnings, err := loadLocalSource(opts)
		w.logWarnings(warnings)
		return bundle, err
	}
	bundle, err := w.loadSource(ctx, opts)
	if err == nil {
		return bundle, nil
	}
	if errors.Is(err, ErrNotModified) {
		return nil, err
	}
	w.logger.Warn("waf rule source reload failed, trying fallback | WAF 规则来源重载失败，尝试回退",
		log.Err(err))
	if opts.LastKnownGood != "" {
		if cached, cacheErr := readLastKnownGood(opts.LastKnownGood); cacheErr == nil {
			return cached, nil
		}
	}
	return nil, err
}

// persist writes the last-known-good cache. | persist 写入 last-known-good 缓存。
func (w *WAF) persist(opts Options, bundle *Bundle) {
	if opts.LastKnownGood == "" || bundle == nil {
		return
	}
	if err := writeLastKnownGood(opts.LastKnownGood, bundle); err != nil {
		w.counts.errors.Add(1)
		w.logger.Error("waf last-known-good write failed | WAF last-known-good 写入失败", log.Err(err))
	}
}

// logWarnings logs loader warnings. | logWarnings 记录加载器警告。
func (w *WAF) logWarnings(warnings []string) {
	for _, warning := range warnings {
		w.logger.Warn("waf rule warning | WAF 规则警告", log.Str("warning", warning))
	}
}

// Reload re-reads the configured source or files and swaps the engine atomically. A failed build
// keeps the previous engine serving. | Reload 重新读取配置的来源或文件并原子替换引擎；构建失败时
// 旧引擎继续服务。
func (w *WAF) Reload() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return ErrClosed
	}
	opts := w.opts
	bundle, err := w.resolveBundle(context.Background(), opts)
	if err != nil {
		if errors.Is(err, ErrNotModified) {
			return nil
		}
		w.counts.errors.Add(1)
		w.logger.Error("waf reload failed | WAF 重载失败", log.Err(err))
		return err
	}
	w.persist(opts, bundle)
	return w.reloadLocked(opts, bundle)
}

// ReloadWith replaces the options and rebuilds the engine. When the source reports no change,
// the existing bundle is recompiled with the new options. | ReloadWith 替换配置并重建引擎；来源报告
// 未变化时使用现有规则包按新配置重新编译。
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
	bundle, err := w.resolveBundle(context.Background(), normalized)
	if err != nil {
		if !errors.Is(err, ErrNotModified) {
			w.counts.errors.Add(1)
			w.logger.Error("waf reload failed | WAF 重载失败", log.Err(err))
			return err
		}
		bundle = w.bundle
		if bundle == nil {
			return ErrNoRules
		}
	} else {
		w.persist(normalized, bundle)
	}
	nextAlerter, alertErr := newAlerter(normalized.Alerting, w.logger, &w.counts)
	if alertErr != nil {
		return alertErr
	}
	if err := w.reloadLocked(normalized, bundle); err != nil {
		if nextAlerter != nil {
			nextAlerter.close()
		}
		return err
	}
	previous := w.alerter.Swap(nextAlerter)
	if previous != nil {
		previous.close()
	}
	return nil
}

// ApplyBundle compiles and applies an externally pushed bundle atomically. | ApplyBundle 原子编译
// 并应用外部推送的规则包。
func (w *WAF) ApplyBundle(bundle *Bundle) error {
	if bundle == nil {
		return ErrInvalidBundle
	}
	if err := bundle.seal(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return ErrClosed
	}
	w.persist(w.opts, bundle)
	return w.reloadLocked(w.opts, bundle)
}

// reloadLocked builds, validates and swaps while the caller holds mu. | reloadLocked 在调用方持有
// mu 时构建、校验并替换。
func (w *WAF) reloadLocked(opts Options, bundle *Bundle) error {
	next, err := buildEngine(opts, bundle, w.logger, w.hooks, &w.counts)
	if err != nil {
		w.counts.errors.Add(1)
		w.logger.Error("waf reload failed | WAF 重载失败", log.Err(err))
		return err
	}
	previous := w.current.Swap(next)
	w.opts = opts
	w.bundle = bundle
	if len(opts.Hooks) > 0 {
		w.hooks.Replace(opts.Hooks)
	}
	if previous != nil {
		previous.retire()
		w.retiring = append(w.retiring, previous)
		w.pruneRetiredLocked()
	}
	w.counts.reloads.Add(1)
	w.logger.Info("waf rules reloaded | WAF 规则已重新加载",
		log.Str("version", next.version), log.Str("digest", next.digest),
		log.Int("rules", next.rulesCount()))
	w.hooks.run(&HookContext{Point: HookReload, Version: next.version})
	return nil
}

// resolveWatch reloads one polling iteration. | resolveWatch 执行一次轮询重载。
func (w *WAF) resolveWatch(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return ErrClosed
	}
	opts := w.opts
	bundle, err := w.resolveBundle(ctx, opts)
	if err != nil {
		if errors.Is(err, ErrNotModified) {
			return err
		}
		w.counts.errors.Add(1)
		return err
	}
	if w.bundle != nil && bundle.Digest == w.bundle.Digest {
		return ErrNotModified
	}
	w.persist(opts, bundle)
	return w.reloadLocked(opts, bundle)
}

// startWatcher launches the polling goroutine. | startWatcher 启动轮询协程。
func (w *WAF) startWatcher() {
	if w.opts.WatchInterval <= 0 || w.opts.Source == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.watchCancel = cancel
	w.watchWG.Add(1)
	go func() {
		defer w.watchWG.Done()
		interval := w.opts.WatchInterval
		delay := interval
		timer := time.NewTimer(delay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			err := w.resolveWatch(ctx)
			switch {
			case err == nil, errors.Is(err, ErrNotModified):
				delay = interval
			case errors.Is(err, ErrClosed):
				return
			default:
				delay *= 2
				if delay > 10*interval {
					delay = 10 * interval
				}
				w.logger.Warn("waf rule poll failed | WAF 规则轮询失败",
					log.Err(err), log.Dur("next", delay))
			}
			timer.Reset(delay)
		}
	}()
}

// stopWatcher stops and waits for the polling goroutine. | stopWatcher 停止并等待轮询协程。
func (w *WAF) stopWatcher() {
	if w.watchCancel != nil {
		w.watchCancel()
		w.watchWG.Wait()
	}
}

// AddHook registers a lifecycle hook. | AddHook 注册生命周期钩子。
func (w *WAF) AddHook(hook Hook) error {
	if w.closed.Load() {
		return ErrClosed
	}
	return w.hooks.Add(hook)
}

// RemoveHook removes every hook with the given name. | RemoveHook 删除所有指定名称的钩子。
func (w *WAF) RemoveHook(name string) bool {
	return w.hooks.Remove(name)
}

// acquire loads the current engine and reserves it for one request. | acquire 加载当前引擎并为单次
// 请求预留。
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

// pruneRetiredLocked drops drained engines; the caller holds mu. | pruneRetiredLocked 丢弃已排空的
// 引擎；调用方持有 mu。
func (w *WAF) pruneRetiredLocked() {
	kept := w.retiring[:0]
	for _, retired := range w.retiring {
		if !retired.isDrained() {
			kept = append(kept, retired)
		}
	}
	w.retiring = kept
}

// Close stops accepting requests and releases engines as their requests finish. It is idempotent
// and does not block. | Close 停止接收请求，并在请求结束后释放引擎。它幂等且不阻塞。
func (w *WAF) Close() error {
	w.stopWatcher()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Swap(true) {
		return nil
	}
	if e := w.current.Swap(nil); e != nil {
		e.retire()
	}
	w.retiring = nil
	w.closeAlerter()
	return nil
}

// closeAlerter stops the alert worker once. | closeAlerter 停止一次报警工作协程。
func (w *WAF) closeAlerter() {
	if a := w.alerter.Swap(nil); a != nil {
		a.close()
	}
}

// Shutdown stops accepting requests and waits until every in-flight transaction finishes or ctx
// expires. | Shutdown 停止接收请求并等待所有在途事务结束或上下文到期。
func (w *WAF) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	w.stopWatcher()
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
	w.closeAlerter()
	for _, e := range engines {
		e.retire()
		if err := e.wait(ctx); err != nil {
			return errs.Wrap(err, ErrShutdownTimeout)
		}
	}
	return nil
}

// Stats returns a snapshot of the instance counters. | Stats 返回实例计数器快照。
func (w *WAF) Stats() Stats { return w.counts.snapshot() }

// RulesCount returns the number of rules in the active engine. | RulesCount 返回当前引擎的规则数。
func (w *WAF) RulesCount() int {
	if e := w.current.Load(); e != nil {
		return e.rulesCount()
	}
	return 0
}

// RuleVersion returns the active bundle version. | RuleVersion 返回当前规则包版本。
func (w *WAF) RuleVersion() string {
	if e := w.current.Load(); e != nil {
		return e.version
	}
	return ""
}
