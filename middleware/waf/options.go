package waf

import (
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/log"
)

// Mode selects how Coraza reacts to disruptive rule matches. | Mode 选择 Coraza 对破坏性规则命中的反应方式。
type Mode uint8

// Engine modes. The zero value blocks, so the secure default needs no extra configuration.
// | 引擎模式。零值即拦截，因此安全默认值无需额外配置。
const (
	// ModeBlock denies interrupted requests. | ModeBlock 拦截被中断的请求。
	ModeBlock Mode = iota
	// ModeDetection logs disruptive matches without blocking; use it for staged rollouts.
	// | ModeDetection 记录破坏性命中但不拦截，用于灰度上线。
	ModeDetection
	// ModeOff disables rule evaluation and lets every request through. | ModeOff 关闭规则求值，
	// 放行所有请求。
	ModeOff
)

// String returns the mode name used in logs. | String 返回日志中使用的模式名称。
func (m Mode) String() string {
	switch m {
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

// Phase identifies the request lifecycle stage that produced an interruption. | Phase 标识产生
// 中断的请求生命周期阶段。
type Phase uint8

// Interruption phases. | 中断阶段。
const (
	// PhaseNone means the request was not interrupted. | PhaseNone 表示请求未被中断。
	PhaseNone Phase = iota
	// PhaseRequest covers URI, request headers and request body evaluation. | PhaseRequest
	// 覆盖 URI、请求头与请求正文求值。
	PhaseRequest
	// PhaseResponse covers response headers and response body evaluation. | PhaseResponse
	// 覆盖响应头与响应正文求值。
	PhaseResponse
)

// String returns the phase name used in logs. | String 返回日志中使用的阶段名称。
func (p Phase) String() string {
	switch p {
	case PhaseRequest:
		return "request"
	case PhaseResponse:
		return "response"
	default:
		return "none"
	}
}

// Default body limits. Request bodies are inspected by default; response bodies are opt-in
// because buffering them costs memory and latency on every response. | 默认正文上限。请求正文
// 默认检测；响应正文需要显式开启，因为缓冲它会为每个响应增加内存与延迟。
const (
	defaultRequestBodyLimit         = 8 << 20
	defaultRequestBodyInMemoryLimit = 128 << 10
	defaultResponseBodyLimit        = 1 << 20
	maxBodyLimit                    = 1 << 30
	maxArgumentsLimit               = 1 << 20
)

// defaultResponseBodyMimeTypes mirrors the content types that Coraza's recommended configuration
// inspects. | defaultResponseBodyMimeTypes 对应 Coraza 推荐配置会检测的内容类型。
var defaultResponseBodyMimeTypes = []string{
	"text/plain",
	"text/html",
	"application/json",
	"application/xml",
	"application/xhtml+xml",
	"text/xml",
}

// Options configures a WAF instance. | Options 配置 WAF 实例。
//
// The zero value already applies the secure baseline: blocking mode, request body access, an
// 8 MiB request limit with 128 KiB kept in memory, and a 1 MiB response limit when response
// access is enabled. Rule files load first and Directives load last, so a third-party rule file
// cannot weaken the baseline while explicit inline directives can still override it. | 零值即应用
// 安全基线：拦截模式、开启请求正文访问、请求上限 8 MiB（其中 128 KiB 驻留内存），开启响应检测时
// 响应上限 1 MiB。规则文件最先加载、Directives 最后加载，因此第三方规则文件无法削弱基线，而显式
// 内联指令仍可覆盖它。
type Options struct {
	// RootFS resolves RuleFiles and Include directives. Use os.DirFS or an embed.FS to load rules
	// shipped inside the binary. Paths are relative to the filesystem root. | RootFS 解析
	// RuleFiles 与 Include 指令。可用 os.DirFS 或 embed.FS 加载随二进制分发的规则；路径相对于
	// 文件系统根。
	RootFS fs.FS
	// Exclude reports whether a request bypasses inspection entirely. Use it for health checks,
	// metrics endpoints and uploads that must not be buffered. It may be called concurrently and
	// must be safe for concurrent use. | Exclude 报告请求是否完全跳过检测。适用于健康检查、
	// 指标端点以及不应被缓冲的上传。它可能被并发调用，必须并发安全。
	Exclude func(*http.Request) bool
	// InspectRequestBody reports whether one request body should be buffered for inspection. It
	// is consulted only when the rule set would otherwise inspect a body. Returning false keeps
	// URI and header inspection, leaves REQUEST_BODY and ARGS_POST empty, and hands the raw body
	// to the handler. Use it for per-route body policy on a single shared WAF instance. It may be
	// called concurrently and must be cheap and safe for concurrent use. | InspectRequestBody
	// 报告单个请求的正文是否应被缓冲检测。仅当规则集本会检测正文时才会调用。返回 false 仍保留
	// URI 与请求头检测，但 REQUEST_BODY 与 ARGS_POST 为空，处理器直接拿到原始正文。用于在单个
	// 共享 WAF 实例上实现按路由的正文策略。它可能被并发调用，必须轻量且并发安全。
	InspectRequestBody func(*http.Request) bool
	// InspectResponseBody reports whether one response body should be buffered for inspection. It
	// is consulted only when the rule set would otherwise inspect a body. Returning false keeps
	// response header inspection, but phase 4-5 rules cannot see the body and the response is
	// streamed. It may be called concurrently and must be cheap and safe for concurrent use. |
	// InspectResponseBody 报告单个请求的响应正文是否应被缓冲检测。仅当规则集本会检测正文时才会
	// 调用。返回 false 仍保留响应头检测，但 phase 4-5 规则看不到正文，响应直接流式下发。它可能
	// 被并发调用，必须轻量且并发安全。
	InspectResponseBody func(*http.Request) bool
	// ClientIP overrides the client host reported to Coraza and observers, for deployments
	// behind a trusted proxy. It must return a host without a port and be safe for concurrent
	// use. The default parses the host part of RemoteAddr. | ClientIP 覆盖报告给 Coraza 与观察者的
	// 客户端主机，用于可信代理之后的部署；必须返回不含端口的主机，并保证并发安全。默认解析
	// RemoteAddr 的主机部分。
	ClientIP func(*http.Request) string
	// Logger receives block, detection and internal-error records. A nil logger selects the
	// process default. | Logger 接收拦截、检测与内部错误记录；为空时使用进程默认日志器。
	Logger *log.Logger
	// DebugLogWriter, when non-nil, enables Coraza's internal debug log at debug level. Keep it
	// nil in production: the default no-op logger avoids per-transaction allocations. The debug
	// log may contain sensitive request details, so enable it only for troubleshooting. |
	// DebugLogWriter 非空时以 debug 级别开启 Coraza 内部日志。生产环境保持 nil：默认 no-op
	// 日志器避免每事务分配。调试日志可能包含敏感请求内容，仅在排障时开启。
	DebugLogWriter io.Writer
	// Observer receives one Event per inspected request. It runs on the request goroutine and may
	// be called concurrently, so it must be safe for concurrent use and should be cheap;
	// expensive work belongs in a queue. | Observer 为每个被检测请求接收一个 Event。它在请求
	// goroutine 上执行且可能被并发调用，因此必须并发安全并保持轻量；耗时工作应放入队列。
	Observer func(Event)
	// ErrorHandler writes the response for a blocked request. A nil handler uses
	// DefaultErrorHandler, which never echoes rule details to the client. The handler may be
	// called concurrently and must write a complete response. | ErrorHandler 写出被拦截请求的响应。
	// 为空时使用 DefaultErrorHandler，它绝不向客户端回显规则细节。处理器可能被并发调用，并且必须
	// 写出完整响应。
	ErrorHandler ErrorHandler
	// Directives are inline SecLang directives applied in order after the baseline. They have
	// the final word over both RuleFiles and the baseline. | Directives 是安全基线之后按顺序应用的
	// 内联 SecLang 指令，对 RuleFiles 与基线都拥有最终决定权。
	Directives []string
	// RuleFiles lists SecLang files loaded before the baseline. Paths resolve through RootFS when
	// it is set, and through the operating system otherwise. Glob patterns are supported. |
	// RuleFiles 列出在安全基线之前加载的 SecLang 文件。设置 RootFS 时经它解析，否则走操作系统；
	// 支持 glob 模式。
	RuleFiles []string
	// ResponseBodyMimeTypes lists the content types eligible for response inspection. An empty
	// list selects text/plain, text/html, application/json, application/xml,
	// application/xhtml+xml and text/xml. | ResponseBodyMimeTypes 列出可检测的响应内容类型。
	// 空列表使用 text/plain、text/html、application/json、application/xml、application/xhtml+xml
	// 与 text/xml。
	ResponseBodyMimeTypes []string
	// ArgumentsLimit caps the number of arguments Coraza parses per collection. Zero keeps
	// Coraza's default (1000). Public endpoints can lower it to bound the per-argument rule cost;
	// the ARGUMENTS_LIMIT_REACHED variable is set when the cap is hit. | ArgumentsLimit 限制
	// Coraza 每个集合解析的参数数量。零值保持 Coraza 默认值（1000）。公开端点可以调低该值以限制
	// 每个参数触发的规则成本；达到上限时会设置 ARGUMENTS_LIMIT_REACHED 变量。
	ArgumentsLimit int
	// RequestBodyLimit caps the inspected request body in bytes; zero selects 8 MiB. | RequestBodyLimit
	// 限制被检测的请求正文字节数；零值使用 8 MiB。
	RequestBodyLimit int
	// RequestBodyInMemoryLimit caps the bytes kept in memory before spilling to a temporary file;
	// zero selects 128 KiB. Values above RequestBodyLimit are clamped. | RequestBodyInMemoryLimit
	// 限制驻留内存的字节数，超出后写入临时文件；零值使用 128 KiB。大于 RequestBodyLimit 时会被收敛。
	RequestBodyInMemoryLimit int
	// ResponseBodyLimit caps the inspected response body in bytes; zero selects 1 MiB. |
	// ResponseBodyLimit 限制被检测的响应正文字节数；零值使用 1 MiB。
	ResponseBodyLimit int
	// Mode selects blocking, detection-only or off. | Mode 选择拦截、仅检测或关闭。
	Mode Mode
	// DisableRequestBodyAccess turns off request body buffering. Header and URI rules keep
	// working, but REQUEST_BODY variables stay empty. Even when false, buffering is skipped
	// automatically when no rule in phases 2-5 can observe the body, so the handler receives the
	// raw body. | DisableRequestBodyAccess 关闭请求正文缓冲。请求头与 URI 规则仍然生效，但
	// REQUEST_BODY 变量为空。即使为 false，只要没有 phase 2-5 规则能观察正文，缓冲也会被自动
	// 跳过，处理器直接拿到原始正文。
	DisableRequestBodyAccess bool
	// ResponseBodyAccess enables response body buffering and inspection. It is off by default.
	// Even when true, buffering is skipped when no phase 4-5 rule exists and audit logging is
	// not configured. | ResponseBodyAccess 开启响应正文缓冲与检测，默认关闭。即使为 true，
	// 只要没有 phase 4-5 规则且未配置审计日志，缓冲也会被自动跳过。
	ResponseBodyAccess bool
}

// normalize validates the options and fills the defaults. | normalize 校验配置并填充默认值。
func (o Options) normalize() (Options, error) {
	if o.Mode > ModeOff {
		return Options{}, ErrInvalidMode
	}
	if o.RequestBodyLimit < 0 || o.RequestBodyLimit > maxBodyLimit {
		return Options{}, ErrInvalidLimit
	}
	if o.RequestBodyInMemoryLimit < 0 || o.RequestBodyInMemoryLimit > maxBodyLimit {
		return Options{}, ErrInvalidLimit
	}
	if o.ResponseBodyLimit < 0 || o.ResponseBodyLimit > maxBodyLimit {
		return Options{}, ErrInvalidLimit
	}
	if o.ArgumentsLimit < 0 || o.ArgumentsLimit > maxArgumentsLimit {
		return Options{}, ErrInvalidLimit
	}
	n := o
	n.Directives = append([]string(nil), o.Directives...)
	n.RuleFiles = append([]string(nil), o.RuleFiles...)
	n.ResponseBodyMimeTypes = append([]string(nil), o.ResponseBodyMimeTypes...)
	if n.RequestBodyLimit == 0 {
		n.RequestBodyLimit = defaultRequestBodyLimit
	}
	if n.RequestBodyInMemoryLimit == 0 {
		n.RequestBodyInMemoryLimit = defaultRequestBodyInMemoryLimit
	}
	if n.RequestBodyInMemoryLimit > n.RequestBodyLimit {
		n.RequestBodyInMemoryLimit = n.RequestBodyLimit
	}
	if n.ResponseBodyLimit == 0 {
		n.ResponseBodyLimit = defaultResponseBodyLimit
	}
	if len(n.ResponseBodyMimeTypes) == 0 {
		n.ResponseBodyMimeTypes = append([]string(nil), defaultResponseBodyMimeTypes...)
	}
	for _, mime := range n.ResponseBodyMimeTypes {
		if mime == "" || strings.ContainsAny(mime, " \t\r\n") {
			return Options{}, ErrInvalidMimeType
		}
	}
	for _, file := range n.RuleFiles {
		if strings.TrimSpace(file) == "" {
			return Options{}, ErrInvalidOption
		}
	}
	return n, nil
}

// loggerOrDefault returns the child logger used by one engine. | loggerOrDefault 返回单个引擎使用的子日志器。
func (o Options) loggerOrDefault() *log.Logger {
	if o.Logger != nil {
		return o.Logger.Named("waf")
	}
	return log.Default().Named("waf")
}

// directiveBlock renders the security baseline. It is applied after RuleFiles and before
// Directives. | directiveBlock 渲染安全基线，在 RuleFiles 之后、Directives 之前应用。
func (o Options) directiveBlock() string {
	var b strings.Builder
	b.WriteString("SecRuleEngine ")
	switch o.Mode {
	case ModeDetection:
		b.WriteString("DetectionOnly")
	case ModeOff:
		b.WriteString("Off")
	default:
		b.WriteString("On")
	}
	b.WriteByte('\n')
	// Coraza's zero-value AuditEngine is On, which builds a full audit record for every
	// transaction even when no writer is configured. The middleware logs blocks and detections
	// through ydx/log and the Observer instead; audit logging stays opt-in through Directives. |
	// Coraza 的零值 AuditEngine 为 On，即使没有配置写入器也会为每个事务构建完整审计记录。
	// 本中间件通过 ydx/log 与 Observer 记录拦截和检测；审计日志改为经 Directives 显式开启。
	b.WriteString("SecAuditEngine Off\n")
	if o.DisableRequestBodyAccess {
		b.WriteString("SecRequestBodyAccess Off\n")
	} else {
		b.WriteString("SecRequestBodyAccess On\n")
	}
	// Emit the limits even when access is off: a later inline directive may turn access back
	// on, and it must not fall back to Coraza's 128 MiB default. | 即使关闭访问也写出上限：后续
	// 内联指令可能重新开启访问，此时不得回落到 Coraza 的 128 MiB 默认值。
	b.WriteString("SecRequestBodyLimit ")
	b.WriteString(strconv.Itoa(o.RequestBodyLimit))
	b.WriteByte('\n')
	b.WriteString("SecRequestBodyInMemoryLimit ")
	b.WriteString(strconv.Itoa(o.RequestBodyInMemoryLimit))
	b.WriteByte('\n')
	b.WriteString("SecRequestBodyLimitAction Reject\n")
	if o.ArgumentsLimit > 0 {
		b.WriteString("SecArgumentsLimit ")
		b.WriteString(strconv.Itoa(o.ArgumentsLimit))
		b.WriteByte('\n')
	}
	if o.ResponseBodyAccess {
		b.WriteString("SecResponseBodyAccess On\n")
	} else {
		b.WriteString("SecResponseBodyAccess Off\n")
	}
	// Same rationale as the request limits: a later inline directive may enable response
	// access, which must inherit the bounded defaults rather than Coraza's defaults. | 与请求
	// 上限同理：后续内联指令可能开启响应访问，此时应继承有界默认值而不是 Coraza 默认值。
	b.WriteString("SecResponseBodyLimit ")
	b.WriteString(strconv.Itoa(o.ResponseBodyLimit))
	b.WriteByte('\n')
	b.WriteString("SecResponseBodyLimitAction ProcessPartial\n")
	b.WriteString("SecResponseBodyMimeType ")
	b.WriteString(strings.Join(o.ResponseBodyMimeTypes, " "))
	b.WriteByte('\n')
	return b.String()
}
