// Package waf is a self-contained, high-performance web application firewall that evaluates
// ModSecurity/Coraza SecLang rules without embedding the Coraza engine. | Package waf 是一个
// 自包含的高性能 Web 应用防火墙，直接求值 ModSecurity/Coraza SecLang 规则，不内嵌 Coraza 引擎。
//
// # Rule compatibility | 规则兼容
//
// The engine parses SecLang files and inline directives, expands Include recursively, supports
// SecRule, SecAction, SecMarker, SecDefaultAction, SecRuleUpdate* and SecRuleRemove* directives,
// rule chains, capture, markers with skip/skipAfter, per-transaction ctl changes and the OWASP
// CRS anomaly-scoring pattern. Operators include @rx, @pm, @pmFromFile, @contains,
// @containsWord, @beginsWith, @endsWith, @eq/@ne/@gt/@ge/@lt/@le, @strmatch, @within,
// @ipMatch/@ipMatchF/@ipMatchFromFile, @validateByteRange, @validateUrlEncoding,
// @validateUtf8Encoding, @detectSQLi and @detectXSS. Transformations include the urlDecode,
// urlDecodeUni, htmlEntityDecode, jsDecode, cssDecode, base64/hex, normalizePath, comment,
// whitespace, hash and case families used by OWASP CRS. | 引擎解析 SecLang 文件与内联指令，递归
// 展开 Include，支持 SecRule、SecAction、SecMarker、SecDefaultAction、SecRuleUpdate* 与
// SecRuleRemove* 指令、规则链、capture、带 skip/skipAfter 的标记、事务级 ctl 变更以及 OWASP CRS
// 异常计分模式。算子包括 @rx、@pm、@pmFromFile、@contains、@containsWord、@beginsWith、@endsWith、
// @eq/@ne/@gt/@ge/@lt/@le、@strmatch、@within、@ipMatch/@ipMatchF/@ipMatchFromFile、
// @validateByteRange、@validateUrlEncoding、@validateUtf8Encoding、@detectSQLi 与 @detectXSS。
// 变换包括 OWASP CRS 使用的 urlDecode、urlDecodeUni、htmlEntityDecode、jsDecode、cssDecode、
// base64/hex、normalizePath、注释、空白、哈希与大小写系列。
//
// Unsupported constructs fail the build by default (Lenient skips them with a warning):
// SecRuleScript, @geoLookup, @inspectFile, @fuzzyHash, exec/proxy/pause and remote rule
// directives. | 默认情况下不支持的构造会让构建失败（Lenient 会记录警告并跳过）：SecRuleScript、
// @geoLookup、@inspectFile、@fuzzyHash、exec/proxy/pause 与远程规则指令。
//
// The SecLang block action executes the disruptive action selected by SecDefaultAction, so OWASP
// CRS keeps its pass-and-score model and blocks through the anomaly evaluation rule. The
// validation operators match invalid input, matching ModSecurity. OWASP CRS v4.29.0 was verified
// locally in strict mode: 703 rules loaded with no skips, benign traffic allowed, and SQL
// injection, XSS and path traversal blocked by CRS anomaly scoring. | SecLang 的 block 动作执行
// SecDefaultAction 选定的破坏性动作，因此 OWASP CRS 保持“计分后统一拦截”的模型。校验类算子在
// 非法输入上命中，与 ModSecurity 一致。本地已在严格模式下验证 OWASP CRS v4.29.0：703 条规则
// 全部加载、无跳过；良性流量放行，SQL 注入、XSS 与路径穿越由 CRS 异常计分拦截。
//
// A native JSON rule format is also accepted, which makes generated or imported rule libraries
// first-class input: | 同时接受原生 JSON 规则格式，使生成或导入的规则库成为一等输入：
//
//	{"version":"v1","mode":"on","rules":[{"id":1,"phase":1,
//	 "variables":"REQUEST_URI","operator":"@contains","pattern":"/etc/passwd",
//	 "actions":{"deny":true,"status":403,"msg":"path traversal"}}]}
//
// # Parallel evaluation | 并行求值
//
// Consecutive rules that only read immutable request collections are evaluated concurrently, but
// their matches and actions are still committed in source order. Setvar, expirevar, capture and
// multiMatch are therefore safe inside a parallel run. Rules that read TX, MATCHED_*, RULE or
// control flow (ctl, allow, skip/skipAfter, chains) remain barriers. ParallelWorkers zero selects
// automatic mode (up to four workers, automatically yielding to request-level concurrency under
// load); one disables rule parallelism; larger values are honored explicitly. Hooks or plugins
// subscribed to HookRuleMatch disable parallelism because they may mutate transaction state. |
// 只读取不可变请求集合的连续规则会并发求值，但命中与动作仍按源码顺序提交。因此 setvar、
// expirevar、capture 与 multiMatch 在并行段内是安全的。读取 TX、MATCHED_*、RULE 或带控制流
// （ctl、allow、skip/skipAfter、链）的规则仍是屏障。ParallelWorkers 为零时选择自动模式（最多
// 四个工作协程，并在高并发下自动让位于请求级并发）；一值关闭规则并行；更大值按显式配置执行。
// 订阅 HookRuleMatch 的钩子或插件会关闭并行，因为它们可能修改事务状态。
//
// # Performance | 性能
//
// Rules are parsed, compiled, chained and bucketed by phase at load time; request handling only
// reads immutable snapshots. The request line is cached per transaction, r.RequestURI is reused when
// present, and ARGS_COMBINED_SIZE is cached until query or body reading/parsing changes the argument set.
// @pm and @pmFromFile use case-insensitive Aho-Corasick with dense root transitions, @ipMatch uses
// net/netip, and regex operators receive conservative literal, byte-set and minimum-length
// prefilters before the regex engine runs. SecMarker is a configuration-stream position: a
// skipAfter in any phase resumes at the marker's source position, so rules declared after it in
// later files still run.
// Transform results use compact chain IDs and per-transaction caching; a per-rule L1 cache also
// serves repeated values during parallel evaluation. Negative operator results are cached per rule
// for repeated values, TX variables use precomputed hashes, and capture uses caller-provided regex
// buffers. | 规则在加载期完成解析、编译、链展开与阶段分桶；请求处理只读不可变快照。请求行按事务
// 缓存；r.RequestURI 存在时直接复用；ARGS_COMBINED_SIZE 在查询串或正文读取/解析改变参数集合前缓存。
// @pm 与 @pmFromFile 使用大小写不敏感的密集根转移 Aho-Corasick，@ipMatch 使用 net/netip；正则算子
// 在进入引擎前接受保守的字面量、字节集与最小长度预过滤。SecMarker 是配置流中的位置：任一阶段的
// skipAfter 都在标记的源码位置恢复，因此后续文件中声明于标记之后的规则仍会执行。变换结果使用紧凑链 ID 与事务级缓存；规则级 L1 缓存在并行求值时
// 也能复用重复取值。否定算子结果按规则缓存重复取值；TX 变量使用预计算哈希；捕获使用调用方缓冲区。
//
// Consecutive independent rules can run on up to four workers; actions and matches are committed
// in source order. Set ParallelWorkers to one to disable rule-level parallelism, or to an explicit
// larger value to pin the worker count. | 连续独立规则最多使用四个工作协程并发求值，动作与命中按
// 源码顺序提交。把 ParallelWorkers 设为 1 可关闭规则级并行，设为更大的显式值可固定工作协程数：
//
//	engine, _ := waf.New(waf.Options{
//		RuleFiles:       []string{"rules/*.conf"},
//		ParallelWorkers: 4,
//	})
//
// regexpx v0.1.12 adds AST-level required-byte/literal prefilters, minimum-length short circuits
// and a lazy ASCII search DFA. The WAF module requires that release, calls Regexp.Warm when the
// engine is built, and uses the caller-provided capture buffers, so these optimizations apply
// automatically. | regexpx v0.1.12 新增 AST 必需字节/字面量预过滤、最小长度短路与惰性 ASCII 搜索
// DFA。WAF 模块依赖该版本，在引擎构建时调用 Regexp.Warm，并使用调用方捕获缓冲区，因此这些优化
// 自动生效。
//
// # YD router | YD 路由
//
//	engine, err := waf.New(waf.Options{
//		RuleFiles: []string{"rules/*.conf"},
//		Directives: []string{`SecRuleEngine On`},
//	})
//	if err != nil {
//		return err
//	}
//	defer engine.Close()
//	r.Use(engine.Middleware())
//
// # Native net/http | 原生 net/http
//
//	handler := engine.HTTPMiddleware(mux)
//	_ = http.ListenAndServe(":8080", handler)
//
// # Hot reload and distribution | 热更新与分发
//
// A Source supplies immutable bundles. HTTPSource pulls from a rule server, sends If-None-Match,
// verifies an optional HMAC-SHA256 signature and applies exponential retries. LastKnownGood keeps
// the last bundle that compiled; if the source is unreachable, that bundle keeps serving and a
// failed reload never replaces a working engine. | Source 提供不可变规则包。HTTPSource 从规则服务器
// 拉取，发送 If-None-Match，校验可选的 HMAC-SHA256 签名并执行指数退避重试。LastKnownGood 保存最后
// 一个编译成功的规则包；来源不可达时该规则包继续服务，失败的重载绝不会替换可用引擎。
//
//	engine, err := waf.New(waf.Options{
//		Source: &waf.HTTPSource{
//			URL:          "https://rules.example.com/waf",
//			SignatureKey: signingKey,
//		},
//		WatchInterval: 30 * time.Second,
//		LastKnownGood: "/var/lib/ydx-waf/rules.cache",
//		Retry:         waf.RetryPolicy{MaxAttempts: 5},
//	})
//
// In a multi-machine deployment every instance polls the same bundle URL (or receives pushed
// bundles through ApplyBundle). NodeID tags alerts with the instance identity. | 多机部署中，每个
// 实例轮询同一个规则包 URL（或通过 ApplyBundle 接收推送）。NodeID 会在报警中标记实例身份。
//
// # Hooks | 钩子
//
// Hooks run at before/after phase, rule match, before/after interrupt, reload, plugin error and
// request completion. They are panic-isolated and ordered by priority. A hook may deny the
// transaction: | 钩子在阶段前后、规则命中、中断前后、重载、插件错误与请求完成时运行。它们有 panic
// 隔离并按优先级排序。钩子可以拒绝事务：
//
//	engine.AddHook(waf.HookFunc{
//		HookName:     "geo",
//		HookPriority: 10,
//		Fn: func(ctx *waf.HookContext) error {
//			if ctx.Point == waf.HookBeforePhase && blockedCountry(ctx.Request) {
//				ctx.Deny(http.StatusForbidden, "blocked region")
//			}
//			return nil
//		},
//	})
//
// # Plugins | 插件
//
// Native plugins implement Plugin. WebAssembly plugins implement the documented ABI and run in a
// pure-Go wazero runtime with an instance pool, call timeout, memory cap, panic/trap isolation
// and a circuit breaker. | 原生插件实现 Plugin。WebAssembly 插件实现文档化 ABI，运行在纯 Go 的
// wazero 运行时中，具备实例池、调用超时、内存上限、panic/trap 隔离与熔断器。
//
//	engine, err := waf.New(waf.Options{
//		WASMPlugins: []waf.WASMPluginConfig{{
//			Name:         "custom-scoring",
//			Path:         "plugins/scoring.wasm",
//			Timeout:      20 * time.Millisecond,
//			MaxInstances: 16,
//			FailClosed:   false,
//		}},
//	})
//
// See WASM.md for the complete ABI. | 完整 ABI 见 WASM.md。
//
// # Alerting | 报警
//
// Alerts aggregate by rule, client and path; a threshold must be reached within a window before
// anything is sent. Per-key cooldown, a global minimum interval, hourly/daily caps, a bounded
// asynchronous queue and a per-sink circuit breaker prevent email or SMS storms. Email is built
// in; webhook and JSON-lines file sinks cover chat, SIEM and SMS gateways. | 报警按规则、客户端与
// 路径聚合；必须在窗口内达到阈值才会发送。按键冷却、全局最小间隔、小时/日上限、有界异步队列与
// 每 Sink 熔断器共同防止邮件或短信炸弹。内置邮件；webhook 与 JSON-lines 文件 Sink 覆盖聊天、SIEM
// 与短信网关。
//
//	engine, err := waf.New(waf.Options{
//		Alerting: waf.AlertConfig{
//			Enabled:     true,
//			MinSeverity: "WARNING",
//			Threshold:   5,
//			Window:      time.Minute,
//			Cooldown:    10 * time.Minute,
//			MaxPerHour:  10,
//			MaxPerDay:   50,
//			NodeID:      "edge-01",
//			Email: &waf.EmailConfig{
//				Host:     "smtp.example.com",
//				Port:     587,
//				Username: "waf",
//				Password: os.Getenv("WAF_SMTP_PASSWORD"),
//				From:     "waf@example.com",
//				To:       []string{"security@example.com"},
//			},
//		},
//	})
//
// # Lifecycle | 生命周期
//
// Rules are compiled into an immutable snapshot. Requests reserve the current snapshot, and a
// reload swaps a fully built snapshot with one atomic pointer store. Replaced snapshots retire
// after their last in-flight request; Shutdown drains them. Request and response bodies are
// bounded, replayed to handlers and inspected only when a rule or hook needs them. | 规则被编译为
// 不可变快照。请求预留当前快照，重载通过一次原子指针替换完整构建的快照。被替换的快照在最后一个在途
// 请求结束后退休；Shutdown 会排空它们。请求与响应正文有界、会回放给处理器，并且仅在规则或钩子需要
// 时检测。
package waf
