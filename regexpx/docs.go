// Package regexpx is the repository's single regular-expression entry point, implemented by a
// self-developed engine instead of by wrapping a third-party library.
// | Package regexpx 是本仓唯一的正则表达式入口，由自研引擎实现，而不是包装第三方库。
//
// # Syntax | 语法
//
// The parser accepts RE2 syntax plus the .NET constructs existing code relies on: lookahead,
// lookbehind, backreferences, named groups, atomic groups and possessive quantifiers. | 解析器接受
// RE2 语法，并支持现有代码依赖的 .NET 构造：先行、后行、反向引用、命名分组、原子组与占有量词。
//
// # Engines | 引擎
//
// Two execution engines sit behind one API: | 一个 API 背后有两个执行引擎：
//
//   - Patterns without lookaround or backreferences run on a linear-time Pike VM. It never
//     backtracks, so its cost is linear in the input and it needs no timeout. | 不含环视与反向引用的
//     模式运行在线性时间 Pike VM 上。它不回溯，代价与输入长度线性相关，无需超时。
//   - Patterns that need those constructs run on a backtracking VM under a mandatory MatchTimeout and
//     a hard step budget. A match that exceeds either is reported as no match, so validation callers
//     fail closed. | 需要这些构造的模式运行在回溯 VM 上，并受强制 MatchTimeout 与硬步数预算约束。超过
//     任一限制的匹配按未匹配处理，因此校验类调用失败关闭。
//
// # Fast paths | 快速路径
//
// Several common shapes bypass the general engines: | 多种常见形态绕过通用引擎：
//
//   - a whole-pattern literal uses a SIMD byte scan; | 整模式字面量使用 SIMD 字节扫描；
//   - a single repeated single-rune matcher such as \w+ uses a linear run scan; | \w+ 这类单个单符文
//     匹配器的重复使用线性运行扫描；
//   - a literal surrounded by dot-all wildcards, such as (?s).*Holmes.*, uses one literal search; |
//     被 dot-all 通配符包围的字面量（如 (?s).*Holmes.*）使用一次字面量搜索；
//   - fixed-length sequences such as \d{4}-\d{2}-\d{2} use a deterministic loop, and a punctuation
//     literal inside a fixed pattern is used as the search anchor instead of its first byte; |
//     \d{4}-\d{2}-\d{2} 这类定长序列使用确定循环；固定模式内的标点字面量作为搜索锚点，而不扫描
//     首字节；
//   - fixed and optional ASCII atoms with one trailing run, such as a URL shape, use a deterministic
//     walk with a step budget; | 固定与可选 ASCII 原子加一个尾运行（如 URL 形态）使用带步数预算的
//     确定性遍历；
//   - the address shape local@domain.tld is located from '@' with a reverse local-part scan; | 邮箱
//     地址形态 local@domain.tld 从 '@' 定位并反向扫描局部部分；
//   - anchored ^body$ validation patterns build a compact ASCII DFA lazily on first use; |
//     锚定的 ^body$ 校验模式在首次使用时惰性构建紧凑 ASCII DFA；
//   - large, broad general patterns build a lazy ASCII search DFA on first use (or via Warm at
//     startup) and fall back to the Pike VM for non-ASCII input, unsupported assertions or
//     state-budget overflow. | 大型宽首字节通用模式在首次使用时（或通过启动期 Warm）构建惰性 ASCII
//     搜索 DFA；非 ASCII 输入、不支持的断言或状态预算溢出时回退到 Pike VM。
//
// # SIMD | 指令集
//
// Byte and byte-set prefilters have amd64 SSE4.1 / SSE4.2 / AVX2 / AVX-512BW and arm64 NEON kernels
// selected at init; case-insensitive literals use a two-byte folded scan. AVX-512 kernels require
// AVX512F, AVX512BW and OS support for opmask/ZMM state, not VBMI or VBMI2, so Skylake-era and newer
// AVX-512 CPUs use the same kernels. Without AVX2 the dispatcher prefers SSE4.2, then SSE4.1, with
// 16-byte kernels, and finally portable scalar code; only CPUs without these extensions use the
// scalar path. Results are identical on every path. | 字节与字节集合预过滤在初始化时选择 amd64
// SSE4.1 / SSE4.2 / AVX2 / AVX-512BW 与 arm64 NEON 内核；大小写不敏感字面量使用双字节折叠扫描。
// AVX-512 内核要求 AVX512F、AVX512BW 与操作系统对 opmask/ZMM 状态的支持，不要求 VBMI/VBMI2，因此
// Skylake 代及更新的 AVX-512 处理器使用同一套内核。没有 AVX2 时按 SSE4.2、SSE4.1、标量的顺序回退，
// SSE 内核一次处理 16 字节；只有不具备这些扩展的 CPU 才走标量路径。各路径结果一致。
//
// # Large input and parallelism | 大输入与并行
//
// The linear engine is streaming and allocation-light. FindAllStringParallel and
// FindAllStringIndexParallel split large inputs across cores when a sound, selective start filter
// exists. Patterns that can match empty, anchored patterns and backtracking patterns run
// sequentially. Results are identical to the sequential methods. | 线性引擎是流式的且分配很少。当存在
// 可靠且具有选择性的起点过滤器时，FindAllStringParallel 与 FindAllStringIndexParallel 把大输入拆分到
// 多个核心。可匹配空串的模式、锚定模式与回溯模式按顺序执行。结果与顺序方法一致。
//
// # Indices | 下标
//
// All indices are byte offsets regardless of the engine. | 无论走哪个引擎，索引一律是字节偏移。
//
// # Standard library parity | 标准库兼容
//
// The exported surface mirrors regexp: CompilePOSIX / MustCompilePOSIX, Longest, LiteralPrefix,
// Expand / ExpandString, ReplaceAllLiteral / ReplaceAllLiteralString, MatchReader,
// FindReaderIndex, FindReaderSubmatchIndex, MarshalText / UnmarshalText, AppendText, Copy, and
// the package-level Match / MatchString / MatchReader functions. | 导出接口镜像 regexp：
// CompilePOSIX / MustCompilePOSIX、Longest、LiteralPrefix、Expand / ExpandString、
// ReplaceAllLiteral / ReplaceAllLiteralString、MatchReader、FindReaderIndex、
// FindReaderSubmatchIndex、MarshalText / UnmarshalText、AppendText、Copy，以及包级
// Match / MatchString / MatchReader。
//
// CompilePOSIX selects leftmost-longest matching and rejects the Perl/.NET escapes and groups that
// the standard library excludes from POSIX mode. Longest is a configuration method and must not
// run concurrently with matching. For patterns that need lookaround or backreferences, Longest
// finds the longest end by testing candidate end positions on the backtracking engine. | CompilePOSIX
// 选择最左最长匹配，并拒绝标准库在 POSIX 模式下排除的 Perl/.NET 转义与分组。Longest 是配置方法，
// 不得与匹配并发执行。对需要环视或反向引用的模式，Longest 在回溯引擎上测试候选结束位置以找到
// 最长结束点。
//
// LiteralPrefix and Longest's submatch and replacement paths use a lazily compiled standard-library
// view for patterns regexp accepts; regexp-only (regexpx .NET) constructs stay on the native engine.
// This keeps POSIX subexpression semantics aligned without putting stdlib on the group-zero hot path.
// | LiteralPrefix 与 Longest 的子匹配、替换路径对 regexp 可接受的模式使用惰性编译的标准库视图；
// regexpx 独有的 .NET 构造仍走原生引擎。这样在不把标准库放进分组 0 热路径的前提下对齐 POSIX
// 子表达式语义。
//
// # Usage | 用法
//
// YD route | YD 路由：
//
//	var tenantRe = regexpx.MustCompile(`^[a-z][a-z0-9_-]*$`)
//	router.GET("/tenants/:name", func(c *router.Context) {
//		if !tenantRe.MatchString(c.Param("name")) {
//			c.Status(http.StatusBadRequest)
//		}
//	})
//
// Native Go | 原生 Go：
//
//	var dateRe = regexpx.MustCompile(`\d{4}-\d{2}-\d{2}`)
//	if loc := dateRe.FindStringIndex(text); loc != nil {
//		fmt.Println(text[loc[0]:loc[1]])
//	}
//
// The common methods mirror the standard library, and the E variants expose ErrMatchTimeout. |
// 常用方法镜像标准库，E 变体暴露 ErrMatchTimeout。
//
// # Startup warm-up | 启动预热
//
// Call Warm once after Compile to initialize the lazy unanchored search DFA before serving traffic.
// Warm does not accept input and never runs the backtracking engine. | 在 Compile 后调用一次 Warm，
// 可在开始服务前初始化惰性未锚定搜索 DFA。Warm 不接收输入，也不会运行回溯引擎。
//
//	re.Warm()
//
// # Caller-provided buffers | 调用方缓冲区
//
// The *Into variants reuse caller storage for submatch results: | *Into 变体复用调用方存储返回子匹配：
//
//	var indexBuf [16]int
//	var stringBuf [8]string
//	index := re.FindStringSubmatchIndexInto(indexBuf[:0], value)
//	groups := re.FindStringSubmatchInto(stringBuf[:0], value)
//
// When dst has enough capacity the returned slice aliases dst; otherwise a new slice is allocated.
// A no-match result is nil. Returned strings are substrings of the input. Warm linear-engine calls
// allocate nothing; backtracking patterns may still allocate engine-internal capture state. |
// dst 容量足够时返回切片复用 dst，否则分配新切片。无匹配返回 nil。返回字符串是输入的子串。预热后
// 线性引擎调用不分配内存；回溯模式仍可能分配引擎内部捕获状态。
package regexpx
