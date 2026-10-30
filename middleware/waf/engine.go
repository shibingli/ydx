package waf

import (
	"context"
	"io"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// engine owns one immutable Coraza instance together with its configuration snapshot and an
// in-flight counter. A request acquires the engine before it starts and releases it when the
// transaction is closed; reload and shutdown retire the engine and close Coraza only after the
// last in-flight request has left. | engine 持有单个不可变 Coraza 实例、对应配置快照与在途计数。
// 请求开始时获取引擎，事务关闭时释放；重载与关闭会退休引擎，并在最后一个在途请求离开后才关闭
// Coraza。
type engine struct {
	waf    coraza.WAF
	logger *log.Logger

	drained chan struct{}

	// newTx binds a transaction to the request context so cancellation reaches Coraza plugins.
	// | newTx 把事务绑定到请求上下文，使取消信号能传递给 Coraza 插件。
	newTx func(context.Context) types.Transaction

	cfg Options

	// readRequestBody is false when no rule can observe the request body. |
	// readRequestBody 在没有规则能观察请求正文时为 false。
	readRequestBody bool
	// inspectResponse records whether response headers/body need Coraza processing. |
	// inspectResponse 记录响应头/正文是否需要交给 Coraza 处理。
	inspectResponse responseInspection

	rules    int
	inflight int

	mu      sync.Mutex
	off     bool
	retired bool
	closed  bool
}

// optionsWAF is implemented by Coraza's wafWrapper; it lets connectors pass a request context.
// | optionsWAF 由 Coraza 的 wafWrapper 实现，使连接器可以传入请求上下文。
type optionsWAF interface {
	NewTransactionWithOptions(experimental.Options) types.Transaction
}

// ruleObserverConfig is implemented by Coraza's WAFConfig; it lets the builder count rules per
// phase before the WAF is compiled. | ruleObserverConfig 由 Coraza 的 WAFConfig 实现，使构建期
// 能在编译前按阶段统计规则。
type ruleObserverConfig interface {
	WithRuleObserver(func(types.RuleMetadata)) coraza.WAFConfig
}

// buildEngine compiles the directives into a Coraza instance. | buildEngine 把指令编译为 Coraza 实例。
func buildEngine(o Options, logger *log.Logger) (*engine, error) {
	if len(o.Directives) == 0 && len(o.RuleFiles) == 0 {
		return nil, ErrNoRules
	}
	cfg := coraza.NewWAFConfig()
	if o.RootFS != nil {
		cfg = cfg.WithRootFS(slashFS{fsys: o.RootFS})
	}
	// Coraza attaches the transaction ID to its debug logger on every transaction. The default
	// logger allocates for that even when debugging is off; a no-op logger keeps the hot path
	// allocation-free unless the caller explicitly enables debug output. | Coraza 会在每个事务上
	// 把事务 ID 附加到调试日志器；即使关闭调试，默认日志器也会因此分配。no-op 日志器让热路径
	// 无分配，除非调用方显式开启调试输出。
	if o.DebugLogWriter != nil {
		cfg = cfg.WithDebugLogger(debuglog.Default().WithOutput(o.DebugLogWriter).WithLevel(debuglog.LevelDebug))
	} else {
		cfg = cfg.WithDebugLogger(noopDebugLogger{})
	}
	// Rule files load first so the security baseline cannot be weakened by a third-party
	// configuration file; inline Directives load last and keep the final word. | 先加载规则文件，
	// 使第三方配置文件无法削弱安全基线；内联 Directives 最后加载并拥有最终决定权。
	for _, file := range o.RuleFiles {
		cfg = cfg.WithDirectivesFromFile(file)
	}
	cfg = cfg.WithDirectives(o.directiveBlock())
	for _, directive := range o.Directives {
		cfg = cfg.WithDirectives(directive)
	}
	// Count rules per phase so the hot path can skip body buffering and response header
	// collection when no rule can observe them. SecMarkers report PhaseUnknown and are ignored.
	// | 按阶段统计规则，使热路径在没有规则能观察正文/响应头时跳过缓冲与采集。SecMarker 报告
	// PhaseUnknown，忽略即可。
	var phases [6]int
	observed := false
	auditRisk := auditConfigured(o.Directives)
	if observedConfig, ok := cfg.(ruleObserverConfig); ok {
		cfg = observedConfig.WithRuleObserver(func(meta types.RuleMetadata) {
			phase := int(meta.Phase())
			if phase > 0 && phase < len(phases) {
				phases[phase]++
			}
			if strings.Contains(strings.ToLower(meta.Raw()), "auditengine") {
				auditRisk = true
			}
		})
		observed = true
	}
	cfg = cfg.WithErrorCallback(func(matched types.MatchedRule) {
		meta := matched.Rule()
		logger.Error("waf rule error | WAF 规则错误",
			log.Int("rule_id", meta.ID()),
			log.Str("severity", meta.Severity().String()),
			log.Str("message", matched.Message()))
	})
	compiled, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, errs.Wrap(err, ErrBuild)
	}
	rules := 0
	if counter, ok := compiled.(interface{ RulesCount() int }); ok {
		rules = counter.RulesCount()
	}
	if rules == 0 {
		if closeErr := closeWAF(compiled); closeErr != nil {
			logger.Error("waf close failed | WAF 关闭失败", log.Err(closeErr))
		}
		return nil, ErrNoRules
	}
	probe := compiled.NewTransaction()
	off := probe.IsRuleEngineOff()
	requestBodyAccess := probe.IsRequestBodyAccessible()
	responseBodyAccess := probe.IsResponseBodyAccessible()
	if closeErr := probe.Close(); closeErr != nil {
		logger.Error("waf probe close failed | WAF 探针事务关闭失败", log.Err(closeErr))
	}
	newTx := func(context.Context) types.Transaction { return compiled.NewTransaction() }
	if withOptions, ok := compiled.(optionsWAF); ok {
		newTx = func(ctx context.Context) types.Transaction {
			return withOptions.NewTransactionWithOptions(experimental.Options{Context: ctx})
		}
	}
	readBody := requestBodyAccess
	inspectResponse := responseInspection{headers: true, body: responseBodyAccess}
	if observed {
		requestRules := phases[2]+phases[3]+phases[4]+phases[5] > 0
		responseHeaderRules := phases[3]+phases[4]+phases[5] > 0
		responseBodyRules := phases[4]+phases[5] > 0
		if auditRisk {
			requestRules = true
			responseHeaderRules = true
			responseBodyRules = true
		}
		readBody = requestBodyAccess && requestRules
		inspectResponse.headers = responseHeaderRules
		inspectResponse.body = responseBodyAccess && responseBodyRules
	}
	return &engine{
		waf:             compiled,
		rules:           rules,
		off:             off,
		logger:          logger,
		cfg:             o,
		newTx:           newTx,
		readRequestBody: readBody,
		inspectResponse: inspectResponse,
		drained:         make(chan struct{}),
	}, nil
}

// auditConfigured reports whether inline directives mention the audit engine. Any mention is
// treated conservatively: auto-skipping body buffering must not strip audit log contents. Rules
// that enable audit via ctl are detected separately from RuleMetadata.Raw. | auditConfigured
// 报告内联指令是否提及审计引擎。任何提及都按保守处理：自动跳过正文缓冲不能移除审计日志内容。
// 通过 ctl 开启审计的规则会另外从 RuleMetadata.Raw 中识别。
func auditConfigured(directives []string) bool {
	for _, directive := range directives {
		if strings.Contains(strings.ToLower(directive), "auditengine") {
			return true
		}
	}
	return false
}

// acquire reserves the engine for one request. It fails only after the engine has been retired.
// | acquire 为单个请求预留引擎；仅在引擎已退休后失败。
func (e *engine) acquire() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retired {
		return false
	}
	e.inflight++
	return true
}

// release returns one request reservation and closes the engine when it was the last one. |
// release 归还一次请求预留，并在它是最后一个时关闭引擎。
func (e *engine) release() {
	e.mu.Lock()
	if e.inflight > 0 {
		e.inflight--
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

// retire stops new reservations and closes the engine once the in-flight requests drain. |
// retire 停止新的预留，并在在途请求排空后关闭引擎。
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

// wait blocks until the retired engine has drained or the context expires. | wait 阻塞到退休引擎
// 排空或上下文到期。
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

// close releases the Coraza instance. | close 释放 Coraza 实例。
func (e *engine) close() {
	if err := closeWAF(e.waf); err != nil {
		e.logger.Error("waf close failed | WAF 关闭失败", log.Err(err))
	}
}

// closeWAF closes a Coraza instance when it implements io.Closer. | closeWAF 在 Coraza 实例实现
// io.Closer 时关闭它。
func closeWAF(compiled coraza.WAF) error {
	if closer, ok := compiled.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
