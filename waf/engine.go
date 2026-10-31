package waf

import (
	"context"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// engineSeq makes transaction identifiers unique across concurrently built engines.
// | engineSeq 使并发构建的引擎之间的事务标识唯一。
var engineSeq atomic.Uint64

// engine owns one immutable rule snapshot, its configuration, plugin instances and an in-flight
// counter. | engine 持有一个不可变规则快照、配置、插件实例与在途计数。
type engine struct {
	pool    sync.Pool
	rules   *ruleSet
	logger  *log.Logger
	hooks   *hookRegistry
	plugins *pluginManager

	drained chan struct{}

	version         string
	digest          string
	parallelWorkers int

	idPrefix string

	cfg          Options
	nextTx       atomic.Uint64
	active       atomic.Int64
	inflight     int
	autoParallel bool
	parallelCap  int64

	mu      sync.Mutex
	off     bool
	retired bool
	closed  bool
}

// buildEngine parses and compiles one bundle into an engine. | buildEngine 把一个规则包解析并编译
// 为引擎。
func buildEngine(opts Options, bundle *Bundle, logger *log.Logger, hooks *hookRegistry, counters *counters) (*engine, error) {
	if bundle == nil || len(bundle.Data) == 0 {
		return nil, ErrNoRules
	}
	source := string(bundle.Data)
	if bundle.Format == FormatJSON {
		converted, err := jsonBundleToSecLang(bundle.Data)
		if err != nil {
			return nil, err
		}
		source = converted
	}
	var warnings []string
	parseWarn := func(message string) {
		warnings = append(warnings, message)
	}
	directives, err := parseSecLang(source, bundle.Version, parseOptions{
		Strict: !opts.Lenient,
		Warn:   parseWarn,
	})
	if err != nil {
		return nil, errs.Wrap(err, ErrBuild)
	}
	cc := compileContext{
		fsys:   opts.RootFS,
		strict: !opts.Lenient,
		warn:   parseWarn,
	}
	rules, compileWarnings, err := compileRuleSet(directives, opts, cc)
	if err != nil {
		return nil, errs.Wrap(err, ErrBuild)
	}
	warnings = append(warnings, compileWarnings...)
	for _, warning := range warnings {
		logger.Warn("waf rule warning | WAF 规则警告", log.Str("warning", warning))
	}
	plugins, err := buildPlugins(opts, bundle, logger, counters, hooks)
	if err != nil {
		return nil, err
	}
	e := &engine{
		rules:           rules,
		cfg:             opts,
		logger:          logger,
		hooks:           hooks,
		plugins:         plugins,
		version:         bundle.Version,
		digest:          bundle.Digest,
		parallelWorkers: opts.ParallelWorkers,
		autoParallel:    opts.parallelAuto,
		parallelCap:     parallelAdmissionCap(),
		idPrefix: strconv.FormatInt(time.Now().UnixNano(), 36) + "-" +
			strconv.FormatUint(engineSeq.Add(1), 36),
		drained: make(chan struct{}),
	}
	e.off = rules.engineMode == ModeOff
	e.pool.New = func() any {
		return &transaction{
			tx:             make(map[string]txValue, 8),
			removedRules:   make(map[int]struct{}, 2),
			removedTargets: make(map[int][]varSelector, 2),
		}
	}
	return e, nil
}

// acquire reserves the engine for one request. | acquire 为单个请求预留引擎。
func (e *engine) acquire() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retired {
		return false
	}
	e.inflight++
	e.active.Add(1)
	return true
}

// release returns one request reservation and closes the engine when it was the last one.
// | release 归还一次请求预留，并在它是最后一个时关闭引擎。
func (e *engine) release() {
	e.mu.Lock()
	if e.inflight > 0 {
		e.inflight--
		e.active.Add(-1)
	}
	doClose := e.retired && e.inflight == 0 && !e.closed
	if doClose {
		e.closed = true
		close(e.drained)
	}
	e.mu.Unlock()
	if doClose {
		e.close()
	}
}

// retire stops new reservations and closes the engine once in-flight requests drain. | retire
// 停止新的预留，并在在途请求排空后关闭引擎。
func (e *engine) retire() {
	e.mu.Lock()
	e.retired = true
	doClose := e.inflight == 0 && !e.closed
	if doClose {
		e.closed = true
		close(e.drained)
	}
	e.mu.Unlock()
	if doClose {
		e.close()
	}
}

// wait blocks until the retired engine drains or ctx expires. | wait 阻塞到退休引擎排空或上下文到期。
func (e *engine) wait(ctx context.Context) error {
	select {
	case <-e.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isDrained reports whether the engine has finished closing. | isDrained 报告引擎是否已完成关闭。
func (e *engine) isDrained() bool {
	select {
	case <-e.drained:
		return true
	default:
		return false
	}
}

// close releases plugin resources. | close 释放插件资源。
func (e *engine) close() {
	if e.plugins != nil {
		e.plugins.close()
	}
}

// rulesCount returns the number of compiled rules. | rulesCount 返回已编译规则数量。
func (e *engine) rulesCount() int {
	if e.rules == nil {
		return 0
	}
	return len(e.rules.rules)
}

// parallelAdmissionCap limits automatic per-request rule parallelism under concurrent load. | parallelAdmissionCap
// 限制并发负载下的自动每请求规则并行度。
func parallelAdmissionCap() int64 {
	limit := int64(runtime.GOMAXPROCS(0) / 4)
	if limit < 1 {
		limit = 1
	}
	return limit
}

// newID returns a unique transaction identifier. | newID 返回唯一事务标识。
func (e *engine) newID() string {
	return e.idPrefix + "-" + strconv.FormatUint(e.nextTx.Add(1), 36)
}
