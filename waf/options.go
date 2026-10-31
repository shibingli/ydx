package waf

import (
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/shibingli/ydx/log"
)

// Mode selects how the engine reacts to disruptive rule matches. | Mode 选择引擎对破坏性规则命中的反应方式。
type Mode uint8

// Engine modes. ModeDefault uses the SecRuleEngine directive from the rule set and falls back
// to blocking when the directive is absent. | 引擎模式。ModeDefault 使用规则集中的 SecRuleEngine
// 指令，未出现该指令时回退为拦截。
const (
	// ModeDefault defers to the rule set; absent a directive the engine blocks.
	// | ModeDefault 交由规则集决定；没有指令时引擎拦截。
	ModeDefault Mode = iota
	// ModeBlock blocks interrupted requests. | ModeBlock 拦截被中断的请求。
	ModeBlock
	// ModeDetection records disruptive matches without interrupting. | ModeDetection 记录破坏性命中但不中断。
	ModeDetection
	// ModeOff disables rule evaluation and lets every request through. | ModeOff 关闭规则求值并放行所有请求。
	ModeOff
)

// String returns the mode name used in logs and events. | String 返回日志与事件中使用的模式名称。
func (m Mode) String() string {
	switch m {
	case ModeDefault:
		return "default"
	case ModeBlock:
		return "block"
	case ModeDetection:
		return "detection"
	case ModeOff:
		return "off"
	default:
		return "unknown"
	}
}

// Phase identifies a stage of the request lifecycle. | Phase 标识请求生命周期的一个阶段。
type Phase uint8

// Lifecycle phases, matching the ModSecurity numbering. | 生命周期阶段，与 ModSecurity 编号一致。
const (
	// PhaseNone means no phase has run. | PhaseNone 表示尚未运行任何阶段。
	PhaseNone Phase = 0
	// PhaseRequestHeaders covers the request line and headers. | PhaseRequestHeaders 覆盖请求行与请求头。
	PhaseRequestHeaders Phase = 1
	// PhaseRequestBody covers the request body. | PhaseRequestBody 覆盖请求正文。
	PhaseRequestBody Phase = 2
	// PhaseResponseHeaders covers response headers. | PhaseResponseHeaders 覆盖响应头。
	PhaseResponseHeaders Phase = 3
	// PhaseResponseBody covers the response body. | PhaseResponseBody 覆盖响应正文。
	PhaseResponseBody Phase = 4
	// PhaseLogging covers the logging phase. | PhaseLogging 覆盖日志阶段。
	PhaseLogging Phase = 5
)

// String returns the phase name used in logs and events. | String 返回日志与事件中使用的阶段名称。
func (p Phase) String() string {
	switch p {
	case PhaseRequestHeaders:
		return "request_headers"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeaders:
		return "response_headers"
	case PhaseResponseBody:
		return "response_body"
	case PhaseLogging:
		return "logging"
	default:
		return "none"
	}
}

// LimitAction selects what happens when a body exceeds its configured limit.
// | LimitAction 选择正文超过配置上限时的处理方式。
type LimitAction uint8

// Body limit actions. | 正文超限动作。
const (
	// LimitDefault selects the context default: reject for requests, process partial for responses.
	// | LimitDefault 选择上下文默认值：请求拒绝，响应处理部分内容。
	LimitDefault LimitAction = iota
	// LimitReject rejects the request or response. | LimitReject 拒绝请求或响应。
	LimitReject
	// LimitProcessPartial inspects the prefix within the limit and lets the rest pass.
	// | LimitProcessPartial 检测上限内的前缀并放行其余部分。
	LimitProcessPartial
)

// String returns the limit action name used in logs. | String 返回日志中使用的超限动作名称。
func (l LimitAction) String() string {
	switch l {
	case LimitReject:
		return "reject"
	case LimitProcessPartial:
		return "process_partial"
	default:
		return "default"
	}
}

// Default body limits. | 默认正文上限。
const (
	defaultRequestBodyLimit  = 8 << 20
	defaultResponseBodyLimit = 1 << 20
	defaultArgumentsLimit    = 1000
	maxBodyLimit             = 1 << 30
	maxArgumentsLimit        = 1 << 20
	defaultPluginTimeout     = 100 * time.Millisecond
)

// defaultResponseBodyMimeTypes lists the content types eligible for response body inspection.
// | defaultResponseBodyMimeTypes 列出可进行响应正文检测的内容类型。
var defaultResponseBodyMimeTypes = []string{
	"text/plain",
	"text/html",
	"application/json",
	"application/xml",
	"application/xhtml+xml",
	"text/xml",
}

// Options configures a WAF instance. The zero value applies the secure baseline: blocking mode
// from the rule set, request body access on, an 8 MiB request limit, response body access off,
// strict rule parsing and plugin/hook failure isolation. | Options 配置 WAF 实例。零值即安全基线：
// 由规则集决定拦截模式、开启请求正文访问、请求上限 8 MiB、关闭响应正文访问、严格解析规则，并隔离
// 插件/钩子失败。
type Options struct {

	// RootFS resolves RuleFiles and Include directives. A nil RootFS uses the operating system.
	// | RootFS 解析 RuleFiles 与 Include 指令；为空时使用操作系统文件系统。
	RootFS fs.FS
	// Source supplies rule bundles for hot reload and multi-machine distribution. When nil,
	// RuleFiles and Directives are used and WatchInterval is ignored. | Source 提供用于热更新与
	// 多机分发的规则包；为空时使用 RuleFiles 与 Directives，并忽略 WatchInterval。
	Source Source
	// AuditWriter, when non-nil, receives one JSON line per blocked or detected request.
	// | AuditWriter 非空时，每个被拦截或检测的请求写入一行 JSON。
	AuditWriter io.Writer
	// Exclude reports whether a request bypasses inspection entirely. It may be called
	// concurrently. | Exclude 报告请求是否完全跳过检测；可能被并发调用。
	Exclude func(*http.Request) bool
	// InspectRequestBody reports whether one request body should be buffered and inspected.
	// | InspectRequestBody 报告单个请求正文是否应被缓冲检测。
	InspectRequestBody func(*http.Request) bool
	// InspectResponseBody reports whether one response body should be buffered and inspected.
	// | InspectResponseBody 报告单个响应正文是否应被缓冲检测。
	InspectResponseBody func(*http.Request) bool
	// ClientIP overrides the client host reported to rules and events. It must return a host
	// without a port. | ClientIP 覆盖报告给规则与事件的客户端主机，必须返回不含端口的主机。
	ClientIP func(*http.Request) string
	// Logger receives block, detection, reload and internal-error records. Nil selects the
	// process default. | Logger 接收拦截、检测、重载与内部错误记录；为空使用进程默认日志器。
	Logger *log.Logger
	// Observer receives one Event per inspected request. It runs on the request goroutine and
	// must be cheap and concurrency-safe. | Observer 为每个被检测请求接收一个 Event；它在请求
	// 协程上运行，必须轻量且并发安全。
	Observer func(Event)
	// ErrorHandler writes the response for an interrupted request. Nil uses DefaultErrorHandler.
	// | ErrorHandler 写出被中断请求的响应；为空使用 DefaultErrorHandler。
	ErrorHandler ErrorHandler
	// LastKnownGood is the filesystem prefix of the bundle cache written after every successful
	// build. On startup, a failed source falls back to this cache. Empty disables the cache.
	// | LastKnownGood 是每次成功构建后写入的规则包缓存前缀。启动时来源失败会回退到该缓存；为空
	// 表示关闭缓存。
	LastKnownGood string
	// Directives are inline SecLang directives applied after every rule file. | Directives 是
	// 在每个规则文件之后应用的内联 SecLang 指令。
	Directives []string
	// RuleFiles lists SecLang files or glob patterns loaded before Directives. | RuleFiles 列出在
	// Directives 之前加载的 SecLang 文件或 glob 模式。
	RuleFiles []string
	// TrustedProxies lists CIDRs whose X-Forwarded-For / X-Real-Ip headers are trusted when
	// ClientIP is nil. Empty means proxy headers are ignored and RemoteAddr is used.
	// | TrustedProxies 列出 ClientIP 为空时可信的代理 CIDR；为空表示忽略代理头并使用 RemoteAddr。
	TrustedProxies []string
	// Hooks are lifecycle hooks registered with the instance. | Hooks 是注册到实例的生命周期钩子。
	Hooks []Hook
	// Plugins are native plugins initialized with each engine snapshot. | Plugins 是随每个引擎
	// 快照初始化的原生插件。
	Plugins []Plugin
	// WASMPlugins are WebAssembly plugins initialized with each engine snapshot. | WASMPlugins
	// 是随每个引擎快照初始化的 WebAssembly 插件。
	WASMPlugins []WASMPluginConfig
	// ResponseBodyMimeTypes lists the response content types eligible for inspection. Empty uses
	// the recommended text/html, text/plain, JSON and XML types. | ResponseBodyMimeTypes 列出可检测
	// 的响应内容类型；为空使用推荐的 text/html、text/plain、JSON 与 XML 类型。
	ResponseBodyMimeTypes []string

	// trusted holds the parsed TrustedProxies prefixes. | trusted 保存解析后的 TrustedProxies 前缀。
	trusted []netip.Prefix
	// Alerting configures the alert pipeline. The zero value is disabled. Alerts are aggregated,
	// deduplicated and rate limited so a burst of attacks cannot cause an email or SMS storm.
	// | Alerting 配置报警管线；零值表示关闭。报警会聚合、去重并限流，避免攻击突发造成邮件或短信
	// 炸弹。
	Alerting AlertConfig

	// Retry configures source fetch retries. The zero value selects five attempts with exponential
	// backoff and jitter. | Retry 配置来源拉取重试；零值选择五次尝试、指数退避与抖动。
	Retry RetryPolicy
	// WatchInterval enables periodic source polling. Zero disables the watcher. | WatchInterval
	// 开启周期性来源轮询；零值关闭 watcher。
	WatchInterval time.Duration
	// ParallelWorkers sets the maximum workers for pure evaluation of consecutive independent
	// rules. Results and actions are still committed in source order. Zero selects automatic mode
	// (up to four workers, capped by GOMAXPROCS); one disables parallel rule evaluation. Hooks or
	// plugins subscribed to HookRuleMatch disable it automatically because they may mutate
	// transaction state during a match. | ParallelWorkers 设置连续独立规则纯求值的最大工作协程数；
	// 结果与动作仍按源码顺序提交。零值选择自动模式（最多四个工作协程，并受 GOMAXPROCS 限制）；
	// 一值关闭并行规则求值。订阅 HookRuleMatch 的钩子或插件会自动关闭并行，因为它们可能在命中时
	// 修改事务状态。
	ParallelWorkers int
	// parallelAuto records that ParallelWorkers was left at zero and selected by normalize. |
	// parallelAuto 记录 ParallelWorkers 留空并由 normalize 选择自动模式。
	parallelAuto bool
	// RequestBodyLimit caps the buffered request body in bytes; zero selects 8 MiB. | RequestBodyLimit
	// 限制被缓冲的请求正文字节数；零值使用 8 MiB。
	RequestBodyLimit int
	// ResponseBodyLimit caps the buffered response body in bytes; zero selects 1 MiB. | ResponseBodyLimit
	// 限制被缓冲的响应正文字节数；零值使用 1 MiB。
	ResponseBodyLimit int
	// ArgumentsLimit caps the number of arguments parsed per collection; zero selects 1000.
	// | ArgumentsLimit 限制每个集合解析的参数数量；零值使用 1000。
	ArgumentsLimit int
	// PluginTimeout bounds one native or WASM plugin/hook invocation. Zero selects 100ms.
	// Native Go hooks cannot be preempted; the bound is advisory for them. | PluginTimeout 限制
	// 单次原生或 WASM 插件/钩子调用；零值使用 100ms。原生 Go 钩子无法被抢占，该上限对它们只是建议值。
	PluginTimeout time.Duration
	// Mode overrides the SecRuleEngine directive. | Mode 覆盖 SecRuleEngine 指令。
	Mode Mode
	// Lenient skips unsupported or invalid rules with a warning instead of failing the build.
	// Keep it false in production. | Lenient 跳过不支持或无效的规则并记录警告，而不是让构建失败。
	// 生产环境保持 false。
	Lenient bool
	// ResponseBodyAccess enables response body buffering and phase 4 rules. It is off by default.
	// | ResponseBodyAccess 开启响应正文缓冲与 phase 4 规则，默认关闭。
	ResponseBodyAccess bool
	// DisableRequestBodyAccess turns off request body buffering; phase 2 body variables stay
	// empty while phase 1 still runs. | DisableRequestBodyAccess 关闭请求正文缓冲；phase 2 的
	// 正文变量为空，phase 1 仍然运行。
	DisableRequestBodyAccess bool
	// RequestBodyLimitAction selects reject or process-partial on an oversized request body.
	// | RequestBodyLimitAction 选择请求正文超限时拒绝或处理部分内容。
	RequestBodyLimitAction LimitAction
	// ResponseBodyLimitAction selects reject or process-partial on an oversized response body.
	// | ResponseBodyLimitAction 选择响应正文超限时拒绝或处理部分内容。
	ResponseBodyLimitAction LimitAction
}

// normalize validates the options and fills defaults. | normalize 校验选项并填充默认值。
func (o Options) normalize() (Options, error) {
	if o.Mode > ModeOff {
		return Options{}, ErrInvalidMode
	}
	if o.RequestBodyLimit < 0 || o.RequestBodyLimit > maxBodyLimit ||
		o.ResponseBodyLimit < 0 || o.ResponseBodyLimit > maxBodyLimit {
		return Options{}, ErrInvalidLimit
	}
	if o.ArgumentsLimit < 0 || o.ArgumentsLimit > maxArgumentsLimit {
		return Options{}, ErrInvalidLimit
	}
	if o.WatchInterval < 0 || o.PluginTimeout < 0 {
		return Options{}, ErrInvalidOption
	}
	if o.ParallelWorkers < 0 || o.ParallelWorkers > 256 {
		return Options{}, ErrInvalidOption
	}
	if o.ParallelWorkers == 0 {
		o.parallelAuto = true
		workers := runtime.GOMAXPROCS(0)
		if workers > 4 {
			workers = 4
		}
		if workers < 1 {
			workers = 1
		}
		o.ParallelWorkers = workers
	}
	if o.RequestBodyLimitAction > LimitProcessPartial || o.ResponseBodyLimitAction > LimitProcessPartial {
		return Options{}, ErrInvalidOption
	}
	n := o
	n.Directives = append([]string(nil), o.Directives...)
	n.RuleFiles = append([]string(nil), o.RuleFiles...)
	n.ResponseBodyMimeTypes = append([]string(nil), o.ResponseBodyMimeTypes...)
	n.TrustedProxies = append([]string(nil), o.TrustedProxies...)
	n.Hooks = append([]Hook(nil), o.Hooks...)
	n.Plugins = append([]Plugin(nil), o.Plugins...)
	n.WASMPlugins = append([]WASMPluginConfig(nil), o.WASMPlugins...)
	n.trusted = nil
	if n.RequestBodyLimit == 0 {
		n.RequestBodyLimit = defaultRequestBodyLimit
	}
	if n.ResponseBodyLimit == 0 {
		n.ResponseBodyLimit = defaultResponseBodyLimit
	}
	if n.ArgumentsLimit == 0 {
		n.ArgumentsLimit = defaultArgumentsLimit
	}
	if n.PluginTimeout == 0 {
		n.PluginTimeout = defaultPluginTimeout
	}
	if n.RequestBodyLimitAction == LimitDefault {
		n.RequestBodyLimitAction = LimitReject
	}
	if n.ResponseBodyLimitAction == LimitDefault {
		n.ResponseBodyLimitAction = LimitProcessPartial
	}
	if len(n.ResponseBodyMimeTypes) == 0 {
		n.ResponseBodyMimeTypes = append([]string(nil), defaultResponseBodyMimeTypes...)
	}
	for _, mime := range n.ResponseBodyMimeTypes {
		if mime == "" || strings.ContainsAny(mime, " \t\r\n") {
			return Options{}, ErrInvalidOption
		}
	}
	n.Retry = n.Retry.normalized()
	for _, file := range n.RuleFiles {
		if strings.TrimSpace(file) == "" {
			return Options{}, ErrInvalidOption
		}
	}
	for _, proxy := range n.TrustedProxies {
		prefix, err := parseTrustedProxy(proxy)
		if err != nil {
			return Options{}, ErrInvalidOption
		}
		n.trusted = append(n.trusted, prefix)
	}
	return n, nil
}

// loggerOrDefault returns the child logger owned by one engine. | loggerOrDefault 返回单个引擎使用的子日志器。
func (o Options) loggerOrDefault() *log.Logger {
	if o.Logger != nil {
		return o.Logger.Named("waf")
	}
	return log.Default().Named("waf")
}

// errorHandler returns the configured error handler or the default. | errorHandler 返回配置的错误处理器或默认值。
func (o Options) errorHandler() ErrorHandler {
	if o.ErrorHandler != nil {
		return o.ErrorHandler
	}
	return DefaultErrorHandler
}

// hasRules reports whether the inline configuration alone can produce an engine.
// | hasRules 报告仅靠内联配置是否可能产生引擎。
func (o Options) hasRules() bool {
	return len(o.Directives) > 0 || len(o.RuleFiles) > 0 || o.Source != nil
}
