# middleware/waf 性能优化指南与源码级优化备忘

本文件分两部分：

- **A. 零源码改动优化清单**：只改配置、规则、中间件顺序、部署方式，不修改本模块或
  Coraza 源码，可直接落地。
- **B. 源码级深入优化备忘**：需要修改本模块或上游 Coraza 的优化项，记录预期收益、
  复杂度、风险与优先级，作为后续迭代输入。

验证环境：Windows 11、Intel i9-10980HK、Go 1.27.3、`httptest`（含 recorder 开销）。
数字只用于相对比较，生产以目标机器与真实规则/流量实测为准。

## A0. 本模块已内置的源码级优化

这些优化已经在 `middleware/waf` 源码中实现，不需要任何配置：

| 优化 | 效果 |
|---|---|
| Coraza 事务调试上下文 no-op | 每事务少约 5 次分配；16 核并行约 -11% |
| `RequestURI` 原始目标 | 每请求少一次 `URL.String()` 分配 |
| 规则阶段自省 | 无 phase 2-5 规则时不缓冲请求正文；无 phase 4-5 规则时不缓冲响应正文；无 phase 3-5 规则时不采集响应头 |
| 无响应规则快速路径 | 无响应阶段规则且无 `Observer` 时直接把原始 writer 交给业务，不包装 |
| `buffpool` 分块读取正文 | 每个正文请求省约 32 KiB 分配；1 KiB 表单请求从 ~90–120 µs 降到 ~45–60 µs |
| 拦截器池化 + `ReaderFrom` 快路径 | 复用响应包装器；流式响应不额外拷贝 |
| `Exclude`/`ModeOff`/`CONNECT` 提前释放引擎 | 长连接不阻塞重载退休与关闭排空 |
| 审计默认关闭、响应正文默认关闭 | 避免每事务审计构建与不必要的响应缓冲 |

实测（单条规则/子集，Windows + httptest，含 recorder）：

- 仅 phase 1 规则 GET：~6.0–7.3 µs，51 allocs/op
- 仅 phase 1 规则 POST（正文自动跳过）：~10–15 µs，64 allocs/op
- phase 2 规则 + 1 KiB 表单：~45–57 µs，~44 KB/op
- Go/HTML/SQL/JavaScript 默认子集（377 条）：GET ~430–465 µs，表单 POST ~660–820 µs
- 最小 941/942 子集（182 条）：GET ~220 µs，表单 POST ~320 µs

> 单次 `-benchtime=1s` 结果，Windows 上波动约 ±10–20%；只用于相对比较。

## A. 零源码改动优化清单（按收益排序）

### A1. 规则子集：先砍规则，再谈微优化

| 规则集 | 规则数 | 冒烟 GET | 表单 POST |
|---|---:|---:|---:|
| 最小 941/942 + 901/905/949 | 182 | ~220 µs | ~320 µs |
| Go/HTML/SQL/JavaScript 默认子集（推荐） | 377 | ~430–465 µs | ~660–820 µs |
| 完整 CRS | 619 | ~580 µs | ~840 µs |

**Go/HTML/SQL/JavaScript 默认子集**：保留语言无关的协议、LFI/RFI/RCE、JavaScript/Node.js、
XSS、SQLi 与阻断评估，剔除 PHP/Java/IIS、响应侧规则，以及 934 中的 Ruby/PHP/Perl 子规则：

```go
RuleFiles: []string{
	"@coraza.conf-recommended",
	"@crs-setup.conf.example",
	"@owasp_crs/REQUEST-901-INITIALIZATION.conf",
	"@owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf",
	"@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf",
	"@owasp_crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	"@owasp_crs/REQUEST-921-PROTOCOL-ATTACK.conf",
	"@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
	"@owasp_crs/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
	"@owasp_crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
	"@owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
	"@owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	"@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf",
},
Directives: []string{
	"SecRuleRemoveById 934140 934150 934170", // 934 中的 Ruby/PHP/Perl 子规则
},
```

| 文件 | 默认 | 说明 |
|---|---|---|
| 901/905/949 | 必须 | 初始化、常见例外、异常分阻断 |
| 911/920/921 | 保留 | 方法/协议/协议攻击，语言无关，适用 Go 服务 |
| 930/931/932 | 保留 | LFI/RFI/RCE |
| 934 | 保留（裁剪） | JavaScript/Node.js、原型污染、SSRF |
| 941 | 保留 | XSS（HTML/JavaScript） |
| 942 | 保留 | SQLi |
| 913 | 按需 | 扫描器识别；可能拦截安全工具 |
| 922 | 按需 | multipart 攻击；WAF 覆盖上传时加载 |
| 943 | 按需 | 会话固定；Cookie 会话考虑 |
| 933/944 | 排除 | PHP/Java 专用 |
| 950-980 | 排除 | 响应侧且多为 PHP/Java/IIS |

**最小 941/942 子集**：只保留 901/905/941/942/949，共 182 条，适合只关心 XSS/SQLi 且
追求最低成本的服务。

要点：

- 941/942 只累计异常分，949 才真正 deny；901 提供初始化。
- Go/HTML/SQL/JavaScript 技术栈通常用不到 PHP/Java/IIS 规则，以及 934 中的 Ruby/PHP/Perl
  子规则。
- 完整 CRS 适合灰度/审计，不建议作为高 QPS 生产默认。

### A2. 按路由组挂载：最大结构性收益

```go
r := router.New()

// 静态资源、健康检查、指标：完全不进入 WAF
r.GET("/healthz", healthHandler)
r.GET("/assets/*", staticHandler)

// 只保护高风险路由
api := r.Group("/api", engine.Middleware())
api.POST("/login", loginHandler)
api.POST("/pay", payHandler)
api.GET("/admin/users", adminHandler)
```

预期：绝大多数请求（静态、健康检查、公开读接口）不支付规则求值成本。

注意：只挂路由组时，未注册路径的 404 不经过 WAF；如果威胁模型要求全站覆盖，需要全局
挂载并接受成本，或对全局 WAF 使用更小的规则集。如果只想对部分路由跳过正文而不是整条
旁路，用单实例的 `InspectRequestBody` / `InspectResponseBody`（见 A3）。

### A3. 请求正文策略：正文解析是 POST 的主要成本

- 只有请求头/URI 规则的接口：`DisableRequestBodyAccess: true`。
- 上传、文件流、长连接：独立路由组或 `Exclude`。
- 正文上限按业务最小值设置：

```go
headerOnly := waf.Options{
	Directives:               rules,
	DisableRequestBodyAccess: true,
}
uploads := waf.Options{
	Directives:               rules,
	DisableRequestBodyAccess: true,
}
```

```go
forms := r.Group("/api", formEngine.Middleware())     // 需要正文规则
upload := r.Group("/upload", uploadEngine.Middleware()) // 不缓冲正文
```

不想为每种策略拆引擎时，可以用一个全局实例按请求决定正文策略：

```go
engine, err := waf.New(waf.Options{
	RuleFiles:      rules,
	ArgumentsLimit: 200, // 0 表示 Coraza 默认 1000
	InspectRequestBody: func(r *http.Request) bool {
		return r.URL.Path != "/upload"
	},
	InspectResponseBody: func(r *http.Request) bool {
		return !strings.HasPrefix(r.URL.Path, "/download/")
	},
})
```

- 返回 `false` 只跳过正文缓冲；URI、请求头与响应头规则照常执行。
- 回调只在规则集本会检测正文时调用，没有正文规则时不增加每请求开销。
- `ArgumentsLimit` 限制每个集合解析的参数数量，直接约束「参数数 × 规则数」的最坏成本；
  URLENCODED 与 JSON 解析都会停止在上限处，并设置 `ARGUMENTS_LIMIT_REACHED`。
- 需要整条请求旁路时用 `Exclude`，不要用正文回调模拟。

不要为了“以防万一”在所有路由保持正文检测；正文解析（URLENCODED/multipart/JSON）是
POST 延迟与分配的主要来源。源码层已经做两件事：没有 phase 2-5 规则时自动跳过缓冲；需要
缓冲时用 `buffpool` 分块读取，避免每请求 32 KiB 的 `io.Copy` 分配。

**内存上限与临时文件**：默认 `RequestBodyInMemoryLimit` 为 128 KiB，超过后正文会落到
临时文件。若典型 API 正文大于 128 KiB，可提高到与业务匹配的值（不得超过
`RequestBodyLimit`），避免磁盘 I/O；并发内存上限约为 `并发数 × InMemoryLimit`，需要
同时评估内存占用。临时目录使用操作系统默认位置，生产应确保它在快速本地盘上。

### A4. 响应正文策略：没有响应规则就不要开

- 默认 `ResponseBodyAccess: false`。
- 只有确实需要防泄露的接口开启，并收窄 MIME 与上限：

```go
waf.Options{
	ResponseBodyAccess:   true,
	ResponseBodyMimeTypes: []string{"application/json"},
	ResponseBodyLimit:    2 << 20,
}
```

- 大文件下载、SSE、长轮询不开启；避免 `Flush` 被推迟。
- `RESPONSE-*` 规则必须开启正文访问才会检测正文。
- 响应显式设置 `Content-Type`：既避免 net/http 嗅探成本，也让 MIME 列表判定稳定；
  未设置时 WAF 仍会按 net/http 语义嗅探首块。

### A5. 中间件顺序：限流前置、压缩后置

推荐 YD 顺序：

```go
r.Use(
	middleware.RequestID(""),
	middleware.Recover(logger),
	middleware.AccessLog(logger),
	middleware.RateLimit(rateLimitOptions), // 先丢弃洪峰
	middleware.Compress(compress.CompressOptions{}), // 压缩在 WAF 之外
	engine.Middleware(),                            // 检测明文
	authMiddleware,
)
```

理由：

- **RateLimit 在 WAF 之前**：被限流请求不进入规则求值，洪峰成本显著下降。
- **AccessLog 在 RateLimit 之前**：429 也能被记录。
- **Compress 在 WAF 之前**：WAF 看到明文；压缩发生在检测之后。反过来只能看到压缩字节。
- **AccessLog/Recover 在 WAF 之前**：能记录 WAF 产生的 403/503，并兜住 panic。
- **Auth 在 WAF 之后**更安全；如果认证很便宜且流量巨大，可把认证提前以省 WAF 成本，
  但登录/鉴权端点本身仍应单独挂 WAF。

### A6. 排除清单：健康检查、指标、静态资源、上传、流式接口

```go
Exclude: func(r *http.Request) bool {
	switch {
	case r.URL.Path == "/healthz", r.URL.Path == "/metrics":
		return true
	case strings.HasPrefix(r.URL.Path, "/assets/"):
		return true
	case strings.HasPrefix(r.URL.Path, "/upload/"):
		return true
	case strings.HasPrefix(r.URL.Path, "/events/"):
		return true
	}
	return false
}
```

`Exclude` 是“整条旁路”（请求与响应都不检测）；如果仍想检测请求头，给该路由组单独挂一个
`DisableRequestBodyAccess: true` 的引擎。

### A7. 开启 `SecRxPreFilter`（实验性，实测有收益）

Coraza v3.8.1 支持运行时指令 `SecRxPreFilter On`，通过字面量预过滤跳过不可能匹配的
完整正则求值。默认 `Off`，属于实验性功能，建议先回归再上线：

```go
engine, _ := waf.New(waf.Options{
	Directives: []string{"SecRxPreFilter On"},
	RuleFiles:  crsSubset,
})
```

本机多次测量（同一规则集，仅加该指令）：Go/HTML/SQL/JavaScript 子集的 GET 约快 4–5%、
表单 POST 约快 5–12%；完整 CRS 的 GET/POST 约快 5–10%。Windows 上单次波动可达 ±10–20%，
不要把这些数字当固定承诺；上线前用真实规则在预发回归，确认无漏报后再上生产。

### A8. 预检规则前置：让明显的坏请求先被拒绝

把廉价、明确的拒绝规则放在 CRS 之前（`RuleFiles` 顺序）：

```text
# /etc/ydx/waf/00-preflight.conf
SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$" \
    "id:900001,phase:1,deny,status:405,msg:'method not allowed',tag:'ydx/preflight'"

SecRule REQUEST_HEADERS:Host "!@rx ^(?:api\.example\.com|www\.example\.com)$" \
    "id:900002,phase:1,deny,status:421,msg:'host not allowed',tag:'ydx/preflight'"

SecRule REQUEST_URI "@rx .{4096,}" \
    "id:900003,phase:1,deny,status:414,msg:'uri too long',tag:'ydx/preflight'"
```

```go
RuleFiles: []string{
	"/etc/ydx/waf/00-preflight.conf", // 先于 CRS
	"@coraza.conf-recommended",
	"@crs-setup.conf.example",
	"@owasp_crs/*.conf",
},
```

同阶段规则按加载顺序求值；预检命中会在进入昂贵规则前中断，适合洪峰与扫描流量。

### A9. CRS 降噪与降本

优先级从高到低：

1. **缩小规则目标**：`SecRuleUpdateTargetById 942100 "!ARGS:content"`；
2. **按 ID 停用**：`SecRuleRemoveById 942100 942200`；
3. **排除整条路径**：`Exclude`；
4. **调低 paranoia level / 提高异常分阈值**：必须放在 CRS 初始化之前，并回归测试。

```go
RuleFiles: []string{
	"@coraza.conf-recommended",
	"@crs-setup.conf.example",
	"/etc/ydx/waf/crs-tune.conf", // 在 CRS 规则之前
	"@owasp_crs/*.conf",
},
```

```text
# crs-tune.conf
SecAction "id:900001,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=10"
SecAction "id:900002,phase:1,nolog,pass,setvar:tx.blocking_paranoia_level=2"
```

降低 PL 会减少规则求值与误报，但也降低检出率；这是安全与体验的显式权衡，不能只按性能决定。

### A10. 日志与观察者：避免把 WAF 变慢变吵

- `Logger` 使用异步或更高阈值（例如只在 Error 级别输出）以抑制攻击洪峰下的日志放大。
- `Observer` 回调必须轻量，耗时工作放队列；不要在其中做同步磁盘/网络 I/O。
- 生产保持 `DebugLogWriter: nil`（默认 no-op，零分配）。
- 默认日志不输出规则 Message/Data；需要细节时用 `Observer` 送入受控管道。
- 审计默认 `SecAuditEngine Off`；开启时用 `RelevantOnly`、窄化 `SecAuditLogParts`、避免
  正文 part，高流量用 `Concurrent` 或改走异步 `Observer` 管道。

```go
logger := log.New(log.Options{
	Writer: wafLogWriter,
	Async:  true, // ydx/log 异步模式
})
```

### A11. 启动与重载

- 规则用 `embed.FS` 随二进制分发，避免启动/重载时的磁盘 I/O 与路径问题。
- 复用同一个 `*waf.WAF` 实例，不要每请求 `New`。
- 避免高频 `Reload`；每次重载都会重新编译规则。规则发布按配置发布节奏执行。
- 重载失败保留旧引擎，不需要回滚文件即可继续服务。

### A12. HTTP 服务器与部署层

以下不属于 WAF 模块，但直接决定 WAF 实际收益：

- 设置 `http.Server.MaxHeaderBytes`、`ReadHeaderTimeout`、`ReadTimeout`，在进入 WAF 前
  限制异常头/慢连接。
- 在反向代理/网关层做连接数限制与粗粒度限流，WAF 只处理通过前置层的请求。
- 根据压测调整 `GOMAXPROCS`、`GOMEMLIMIT`；WAF 是 CPU 与分配密集型组件。
- 多进程部署时每进程独立引擎；规则文件/版本保持一致。

### A13. 压测方法

1. 分别测：无 WAF、单条规则、941/942 子集、完整 CRS。
2. 使用真实规则、真实 Content-Type 与正文形状；不要只用空 GET。
3. 用 `b.RunParallel` + `-cpu 1,4,16` 观察扩展性；用 `-benchmem` 看分配。
4. 用 `-cpuprofile` / `-memprofile` / `-mutexprofile` 定位瓶颈；不要猜。
5. 关注 p50/p95/p99，而不只是平均值；攻击流量与正常流量分开测。
6. 把 WAF 开销和 `httptest` recorder 开销分开看；生产以真实 writer 为准。
7. 上线前用影子流量跑 `ModeDetection`，对比误报与延迟。

### A14. 组合示例：高性能 API 部署

把上述配置组合起来的最小生产骨架：

```go
rules := []string{
	"@coraza.conf-recommended",
	"@crs-setup.conf.example",
	"@owasp_crs/REQUEST-901-INITIALIZATION.conf",
	"@owasp_crs/REQUEST-905-COMMON-EXCEPTIONS.conf",
	"@owasp_crs/REQUEST-911-METHOD-ENFORCEMENT.conf",
	"@owasp_crs/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	"@owasp_crs/REQUEST-921-PROTOCOL-ATTACK.conf",
	"@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
	"@owasp_crs/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
	"@owasp_crs/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
	"@owasp_crs/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
	"@owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	"@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf",
}

engine, err := waf.New(waf.Options{
	RootFS:    coreruleset.FS,
	RuleFiles: rules,
	Directives: []string{
		"SecRxPreFilter On",                 // 实验性；预发回归后启用
		"SecRuleRemoveById 934140 934150 934170", // 934 中的 Ruby/PHP/Perl 子规则
	},
	Mode: waf.ModeDetection, // 灰度后 ReloadWith(ModeBlock)
	Exclude: func(r *http.Request) bool {
		return r.URL.Path == "/healthz" || r.URL.Path == "/metrics"
	},
})
if err != nil {
	return err
}
defer engine.Close()

r := router.New()
r.Use(
	middleware.RequestID(""),
	middleware.Recover(logger),
	middleware.AccessLog(logger),
	middleware.RateLimit(rateLimitOptions),
	middleware.Compress(compress.CompressOptions{}),
)

// 只给 API 组挂 WAF；静态资源/健康检查完全绕过
api := r.Group("/api", engine.Middleware())
api.POST("/login", loginHandler)
api.POST("/pay", payHandler)

// 上传组：使用同一规则集但关闭正文缓冲
upload, err := waf.New(waf.Options{
	RootFS:                   coreruleset.FS,
	RuleFiles:                rules,
	Directives:               []string{"SecRxPreFilter On"},
	DisableRequestBodyAccess: true,
	Mode:                     waf.ModeDetection,
})
if err != nil {
	return err
}
defer upload.Close()
r.Group("/upload", upload.Middleware()).POST("/", uploadHandler)
```

说明：

- `Exclude` 与组挂载是两道保险：健康检查不进 WAF，上传不缓冲正文。
- 规则文件内嵌（`coreruleset.FS`）避免启动/重载磁盘 I/O。
- 确认误报后把两个引擎都 `ReloadWith` 到 `ModeBlock`。
- 如果不需要正文规则，`/api` 引擎也可以关闭正文访问，成本会进一步下降。

## B. 仍需深入优化的备忘

本轮已经把能在本模块源码内完成的优化全部落地（见 A0）：规则阶段自省、请求/响应缓冲
自动跳过、无响应规则快速路径、`buffpool` 分块正文读取、no-op 调试日志、`RequestURI`。
以下是尚未实施、且需要本模块继续改源码或上游 Coraza 配合的项。

| 优先级 | 优化项 | 预期收益 | 复杂度/风险 | 去向 |
|---|---|---|---|---|
| P1 | `benchmarks/waf` 正式基准 | 测量与回归门禁 | 低；需先打模块标签 | 基准模块 |
| P2 | 更细粒度的规则目标自省 | 中高（含响应规则的规则集也能跳过请求正文） | 中高；需要解析规则变量，存在漏判风险 | 本模块 |
| P2 | 攻击洪峰下的异步/采样拦截日志 | 高（日志风暴时） | 中；审计日志不能静默丢弃 | 本模块 |
| P2 | 相同规则集的编译结果共享/缓存 | 中（多实例/多租户） | 中高；Coraza 实例状态隔离复杂 | 本模块 |
| P3 | Hijacker/Pusher 包装器池化 | 每请求省 1–2 次小分配 | 低中；收益约 2–4% | 本模块 |
| P3 | 引擎引用计数改纯原子 | 低（已测非瓶颈） | 中；需要证明 retire/close 一次性语义 | 本模块 |
| P3 | 构建标签裁剪未用操作符/OCSF | 二进制体积、编译时间 | 低；运行时收益有限 | 部署 |
| P4 | Event/Match 切片复用 | 低（仅拦截/观察路径） | 低 | 本模块 |
| P4 | 事务 ID 与 request-id 打通 | 可观测性，不是性能 | 低 | 本模块 |
| P4 | 上游 `BodyBuffer` 支持 `ReaderFrom` | 中高（正文路径） | 高；需上游接受 | Coraza 上游 |
| P4 | 上游 URLENCODED/JSON 处理器缓冲复用 | 中高（正文路径） | 高；需上游接受 | Coraza 上游 |
| P4 | 上游消除 `debuglog.Str` 每事务闭包 | 每事务少一次分配 | 中；需上游接受 | Coraza 上游 |
| 避免 | fork Coraza 做零拷贝正文或异步审计 | 高 | 维护成本极高，安全修复脱节 | 不推荐 |

### B1. 更细粒度的规则目标自省（P2）

当前阶段自省是保守的：只要存在 phase 3/4/5 规则，就会为请求正文保留缓冲（因为这些阶段
的规则理论上可以引用 `REQUEST_BODY`/`ARGS`）；只要存在 phase 5 规则，就会保留响应正文。
更激进的做法是解析 `RuleMetadata.Raw()` 中的变量名，只在本阶段规则确实引用正文变量时才
缓冲。风险是规则语法/变量别名/宏可能被漏判，一旦漏判就是检测缺失；必须只作为显式 opt-in，
并有完整规则回归集。收益主要出现在“请求规则 + 少量响应头规则”的混合规则集。

### B2. 异步/采样拦截日志（P2）

`emitEvent` 对每个拦截/检测请求写一条结构化日志。攻击洪峰下日志 I/O 可能成为瓶颈。可增加
非阻塞队列、按规则/路径的采样与速率限制；`Observer` 保持无损。运行日志可以采样，合规审计
日志不能静默丢弃。实现时要避免队列满时阻塞请求 goroutine。

### B3. 编译结果共享/缓存（P2）

多租户或多实例场景下，相同规则集会被重复编译。可按规则文件内容哈希 + 关键配置缓存编译后
的 Coraza WAF，再为每个实例绑定独立的观察者、错误响应与统计。难点是 Coraza WAF 内部持有
logger、error callback 等实例状态，需要仔细隔离；收益主要在启动/重载时间与内存。

### B4. 包装器池化（P3）

真实 `net/http` 的 writer 通常实现 `Hijacker`，当前在需要响应处理时每请求会额外分配一个
薄包装器。可为 `hijackWriter` / `pushWriter` / `hijackPushWriter` 各建 `sync.Pool`，预计
省 1–2 次小分配、约 32 B/请求。相对完整 CRS 的约 2700 allocs/op 收益不到 0.1%，优先级低。

### B5. 引擎引用计数改纯原子（P3）

`engine.acquire/release` 使用短临界区互斥锁。并行基准 16 核约 2.6 µs/op，mutex profile
显示主要竞争来自 Coraza/GC；改为原子引用计数收益有限，且需要处理 retire/close 的精确
一次性语义。暂不优先。

### B6. 上游优化（P4）

- `BodyBuffer` 实现 `io.ReaderFrom`；
- URLENCODED/JSON body processor 复用解码缓冲；
- `newTransaction` 不再为 no-op 调试日志创建 `debuglog.Str` 闭包；
- 审计 writer 异步化；
- OCSF/JSON schema 依赖通过构建标签裁剪；
- 预过滤默认值调整（实验性能力，应由上游决定）。

这些需要上游接受或 fork；fork 会与安全修复脱节，除非收益足够大并有维护预算，否则不推荐。

## C. 配置级优化检查清单

- [ ] 默认使用 Go/HTML/SQL/JavaScript 子集（377 条：901/905/911/920/921/930/931/932/934/
      941/942/949，并移除 934 的 Ruby/PHP/Perl 子规则），而非完整 CRS；按需追加
      913/922/943，排除 933/944 与 950-980。
- [ ] WAF 只挂高风险路由组；静态/健康检查/指标不挂。
- [ ] 不需要正文规则的路由关闭 `RequestBodyAccess`（阶段自省也会自动跳过）；全局实例可用
  `InspectRequestBody` / `InspectResponseBody` 按路径跳过正文。
- [ ] 对公开表单设置 `ArgumentsLimit`，限制每个参数触发的规则成本。
- [ ] 没有响应规则的路由不开启 `ResponseBodyAccess`（阶段自省也会自动跳过）。
- [ ] 响应检测只收窄到需要的 MIME 与上限。
- [ ] RateLimit 在 WAF 之前，AccessLog 在 RateLimit 之前。
- [ ] Compress 在 WAF 之前，WAF 检测明文。
- [ ] 上传、SSE、长轮询、WebSocket/WebTransport 独立挂载或排除。
- [ ] `SecRxPreFilter On` 已评估（实验性，预发回归通过）。
- [ ] 预检规则先于 CRS 加载。
- [ ] 误报用目标排除优先，停用规则有审计记录。
- [ ] 生产 `DebugLogWriter` 为 nil；日志级别/异步策略已评估。
- [ ] 用真实流量在预发做 `ModeDetection`，并记录 P99 与误报。
- [ ] 已建立目标机器上的 WAF 基准与回归门禁。

## D. 相关链接

- [使用手册与最佳实践](README.md)
- [Coraza 官方文档](https://coraza.io/docs/)
- [OWASP CRS](https://coreruleset.org/)
