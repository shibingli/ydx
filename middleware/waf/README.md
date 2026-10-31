# middleware/waf — WAF 中间件使用手册与最佳实践

`github.com/shibingli/ydx/middleware/waf` 是基于 [OWASP Coraza v3](https://github.com/corazawaf/coraza)
的 Web 应用防火墙。本手册覆盖安装、配置、规则编写与调优、常见场景、最佳实践、FAQ 与故障
排查，目标是让团队在不牺牲用户体验的前提下安全上线 WAF。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/waf` |
| 包名 | `waf` |
| Go 版本 | 1.27.3 |
| WAF 引擎 | Coraza v3.8.1（Apache-2.0） |
| 许可证 | Apache-2.0 |

> 零源码改动的优化清单、实测配置收益与源码级优化备忘见
> [PERFORMANCE.md](PERFORMANCE.md)。

## 目录

1. [定位与能力边界](#1-定位与能力边界)
2. [安装与模块边界](#2-安装与模块边界)
3. [快速开始](#3-快速开始)
4. [配置参考](#4-配置参考)
5. [规则编写与管理](#5-规则编写与管理)
6. [请求与响应生命周期](#6-请求与响应生命周期)
7. [常见场景配置](#7-常见场景配置)
8. [最佳实践](#8-最佳实践)
9. [可观测性与审计](#9-可观测性与审计)
10. [FAQ](#10-faq)
11. [故障排查速查表](#11-故障排查速查表)
12. [升级、版本与发布](#12-升级版本与发布)
13. [附录](#13-附录)

---

## 1. 定位与能力边界

**能做什么**

- 在 HTTP 入口检测请求行、请求头、请求正文、响应头与响应正文。
- 使用 Coraza SecLang 规则与 OWASP CRS，支持拦截、仅检测、应急关闭。
- 覆盖完整生命周期：请求阶段、响应阶段、日志阶段、事务清理。
- 原子热重载规则、优雅关闭、每请求观察事件与无锁统计。
- 同时服务 YD 路由（`router.Middleware`）与原生 `net/http`。

**不能做什么**

- 不是反向代理、TLS 终结器、限流器或认证系统；这些继续由对应中间件负责。
- 不替代参数化 SQL、输出编码、最小权限等基础安全工程。
- 不捆绑 CRS；规则需要应用自行选择并加载。
- 不做“失败放行”：WAF 内部错误默认 fail-closed。
- 不会自动理解业务语义；规则调优是上线工作的核心部分。

**处理流程**

```
请求
  │
  ├─ acquire 引擎（关闭 → 503）
  ├─ Exclude / ModeOff → 直接放行
  ├─ 请求阶段：连接/URI/头 → 正文缓冲 → 回放
  │     └─ 命中 deny/redirect → 错误响应，结束
  ├─ 业务处理器（响应写入器被拦截器包装）
  │     └─ 响应头阶段、响应正文阶段
  │           └─ 命中 → 替换为错误响应
  └─ 日志阶段 → 观察者/统计 → 关闭事务 → 释放引擎
```

**核心理念**

- 默认安全：拦截、正文有界、响应检测关闭、审计关闭。
- 用规则子集和路由分组控制成本；不为静态资源与健康检查支付 WAF 开销。
- 先检测、后拦截；用 `Observer` 和 `Stats` 量化误报与性能。
- 规则文件可以更新，但安全基线不能被第三方规则文件削弱。

---

## 2. 安装与模块边界

```bash
# 标签发布后
go get github.com/shibingli/ydx/middleware/waf@v0.1.0
```

新模块需要先发布子目录标签 `middleware/waf/v0.1.0`；未发布前下游无法按版本引用。

**为什么不在 `middleware` 聚合门面里**

Coraza 会带来 OCSF 审计 schema、protobuf、jsonschema 等传递依赖。实测模块缓存源码约
60 MB，最终二进制通常增加数 MB。把 WAF 放进 `ydx/middleware` 会让所有中间件使用者都
承担这份成本，因此本模块保持独立：

```go
import "github.com/shibingli/ydx/middleware/waf" // 只有需要 WAF 的服务才导入
```

**纯 Go**

Coraza 与本模块均无 cgo，生产构建保持 `CGO_ENABLED=0`；只有 `-race` 测试需要 C 编译器
（Windows 上按仓库约定使用 `CC=clang`）。

**CRS 可选**

```bash
go get github.com/corazawaf/coraza-coreruleset@v0.0.0-20240226094324-415b1017abdc
```

不使用 CRS 的服务无需引入该模块。

---

## 3. 快速开始

### 3.1 YD 路由

```go
engine, err := waf.New(waf.Options{
	Directives: []string{
		`SecRule REQUEST_URI "@contains /etc/passwd" "id:9001,phase:1,deny,status:403,msg:'path traversal'"`,
		`SecRule ARGS "@detectSQLi" "id:9002,phase:2,deny,status:403,msg:'sql injection'"`,
	},
	Exclude: func(r *http.Request) bool {
		return r.URL.Path == "/healthz" || r.URL.Path == "/metrics"
	},
})
if err != nil {
	return err
}
defer engine.Close()

r.Use(engine.Middleware()) // 在业务中间件与路由之前
```

### 3.2 原生 net/http

```go
handler := engine.HTTPMiddleware(mux)
_ = http.ListenAndServe(":8080", handler)
```

`next` 为 `nil` 时按 `http.NotFound` 处理。包装器保留 `Flusher`、`Hijacker`、`Pusher`
与 `Unwrap`，WebSocket、SSE 与 `http.ResponseController` 可正常工作。

### 3.3 先检测、后拦截

```go
engine, err := waf.New(waf.Options{
	Directives: rules,
	Mode:       waf.ModeDetection,
	Observer: func(ev waf.Event) {
		for _, m := range ev.Matches {
			// 按 m.RuleID 统计命中与误报
		}
	},
})
```

确认误报可接受后：

```go
blocked := opts // 应用此前使用的完整 Options
blocked.Mode = waf.ModeBlock
if err := engine.ReloadWith(blocked); err != nil {
	// 失败时旧规则继续服务
}
```

### 3.4 验证

```bash
# 正常请求
curl -i http://127.0.0.1:8080/api/items?name=hello

# 触发自定义 URI 规则
curl -i 'http://127.0.0.1:8080/?q=../../etc/passwd'

# 触发 CRS SQLi 子集
curl -i --data-urlencode "q=1' OR '1'='1" http://127.0.0.1:8080/login
```

预期：正常请求 200；命中规则 403（或规则指定状态）；检测模式全部放行但产生告警与
`Stats.Detected`。

---

## 4. 配置参考

### 4.1 Options

零值即安全基线；只有 `Directives` 或 `RuleFiles` 至少有一个非空才允许构造。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `Directives` | `[]string` | 空 | 内联 SecLang，最后加载，优先级最高 |
| `RuleFiles` | `[]string` | 空 | SecLang 文件或 glob，最先加载；可经 `RootFS` 解析 |
| `RootFS` | `fs.FS` | `nil` | 嵌入式规则根，如 `os.DirFS`、`embed.FS`、`coreruleset.FS` |
| `Mode` | `Mode` | `ModeBlock` | `ModeBlock` / `ModeDetection` / `ModeOff` |
| `DisableRequestBodyAccess` | `bool` | `false` | 关闭请求正文缓冲（正文规则将看不到内容） |
| `RequestBodyLimit` | `int` | 8 MiB | 请求正文检测上限，超限 Reject → 413 |
| `RequestBodyInMemoryLimit` | `int` | 128 KiB | 内存驻留上限，超出后写临时文件；大于总上限时收敛 |
| `ResponseBodyAccess` | `bool` | `false` | 开启响应正文缓冲与检测 |
| `ResponseBodyLimit` | `int` | 1 MiB | 响应正文检测上限；超出按 ProcessPartial 处理 |
| `ResponseBodyMimeTypes` | `[]string` | `text/plain` 等 6 种 | 参与响应正文检测的 Content-Type |
| `Exclude` | `func(*http.Request) bool` | `nil` | 完全旁路（请求与响应都不检测） |
| `InspectRequestBody` | `func(*http.Request) bool` | `nil` | 按请求决定是否缓冲请求正文；返回 false 时仍检测 URI/头，正文原样交给处理器 |
| `InspectResponseBody` | `func(*http.Request) bool` | `nil` | 按请求决定是否缓冲响应正文；返回 false 时仍检测响应头，正文直接流式下发 |
| `ArgumentsLimit` | `int` | `0`（Coraza 默认 1000） | 每个集合解析的参数上限；调低可限制每个参数触发的规则成本 |
| `ClientIP` | `func(*http.Request) string` | 解析 `RemoteAddr` | 报告给 Coraza 的客户端主机，不含端口 |
| `Logger` | `*log.Logger` | 进程默认 | 拦截/检测/错误日志；自动命名 `waf` |
| `DebugLogWriter` | `io.Writer` | `nil` | 打开 Coraza 内部 debug 日志；生产保持 nil（no-op 免分配） |
| `Observer` | `func(Event)` | `nil` | 每请求事件，可能并发调用 |
| `ErrorHandler` | `ErrorHandler` | `DefaultErrorHandler` | 自定义拦截响应；必须写完整响应 |

并发契约：`Exclude`、`InspectRequestBody`、`InspectResponseBody`、`ClientIP`、`Observer`、
`ErrorHandler` 都可能被并发调用，必须并发安全；`Directives`、`RuleFiles`、
`ResponseBodyMimeTypes` 在构造时复制，调用方之后修改原切片不会影响实例。

**自动跳过**：中间件在编译期按规则阶段统计需求，热路径会自动省掉无用工作：

- 没有 phase 2-5 规则能观察正文 → 不缓冲请求正文，处理器直接拿到原始正文；
- 没有 phase 4-5 规则、且未配置审计 → 即使 `ResponseBodyAccess: true` 也不缓冲响应正文；
- 没有 phase 3-5 规则、且没有 `Observer`/审计 → 响应阶段直接使用原始写入器，不包装。

这些优化不改变检测结果；规则集变化后 `Reload` 会重新统计。

### 4.2 安全基线

规则文件先加载，基线其次，内联指令最后：

```
RuleFiles → 安全基线 → Directives
```

| 指令 | 基线值 | 覆盖方式 |
|---|---|---|
| `SecRuleEngine` | `On`（`ModeBlock`） | `Options.Mode` 或内联指令 |
| `SecAuditEngine` | `Off` | 内联指令 |
| `SecRequestBodyAccess` | `On` | `DisableRequestBodyAccess` 或内联指令 |
| `SecArgumentsLimit` | 未设置（Coraza 默认 1000） | `Options.ArgumentsLimit`（大于 0 时写入） |
| `SecRequestBodyLimit` | 8388608 | `RequestBodyLimit` 或内联指令 |
| `SecRequestBodyInMemoryLimit` | 131072 | `RequestBodyInMemoryLimit` 或内联指令 |
| `SecRequestBodyLimitAction` | `Reject` | 内联指令 |
| `SecResponseBodyAccess` | `Off` | `ResponseBodyAccess` 或内联指令 |
| `SecResponseBodyLimit` | 1048576 | `ResponseBodyLimit` 或内联指令 |
| `SecResponseBodyLimitAction` | `ProcessPartial` | 内联指令 |
| `SecResponseBodyMimeType` | `text/plain text/html application/json application/xml application/xhtml+xml text/xml` | `ResponseBodyMimeTypes` 或内联指令 |

说明：

- 正文上限即使关闭正文访问也会写出，防止后续内联指令重新开启时回落到 Coraza 的
  128 MiB 默认值。
- 审计默认关闭是因为 Coraza 零值 `AuditEngine` 为 On，会为每个事务构建审计记录，即使
  没有配置写入器。
- `SecRuleEngine` 在规则文件之后应用，因此 CRS 的 `@coraza.conf-recommended` 无法把
  拦截模式改回 DetectionOnly；最终模式由 `Options.Mode` 决定。
- 若把 CRS 通过 `Directives` 的 `Include` 加载，文件中的引擎/审计设置会覆盖基线；推荐
  始终通过 `RuleFiles` 加载规则文件。

### 4.3 Mode、Phase 与状态

| 类型 | 取值 | 含义 |
|---|---|---|
| `ModeBlock` | 0 | 命中破坏性规则时拦截 |
| `ModeDetection` | 1 | 记录“本应拦截”，但放行；`Stats.Detected` 增加 |
| `ModeOff` | 2 | 不执行规则；`Stats.Bypassed` 增加 |
| `PhaseNone` | 0 | 未中断 |
| `PhaseRequest` | 1 | 请求行/头/正文阶段中断 |
| `PhaseResponse` | 2 | 响应头/正文阶段中断 |

请求被拦截时的状态：

| 情况 | 状态 |
|---|---|
| 规则 `deny` 未指定 status | 403 |
| 规则 `deny,status:N` | N |
| 规则 `redirect:URL` | 302（或规则指定 status） |
| `drop` | 403（net/http 无法直接关闭连接） |
| 请求正文超过上限（Reject） | 413 |
| 检测内部错误 | 500 |
| 实例已关闭 | 503 |

### 4.4 API

| 方法 | 说明 |
|---|---|
| `New(Options) (*WAF, error)` | 编译规则并构造实例；空规则集返回 `ErrNoRules` |
| `(*WAF).Middleware() router.Middleware` | YD 路由入口；被拦截时内部调用 `c.Abort()` |
| `(*WAF).HTTPMiddleware(next) http.Handler` | 原生入口；`nil` → 404 |
| `(*WAF).RulesCount() int` | 当前引擎规则数；关闭后 0 |
| `(*WAF).Stats() Stats` | 实例累计计数快照（Reload 不清零） |
| `(*WAF).Reload() error` | 重新读取规则文件并原子替换；失败保留旧引擎 |
| `(*WAF).ReloadWith(Options) error` | 替换全部 Options 后重载；失败两者都保留 |
| `(*WAF).Close() error` | 立即停止接收；在途请求结束后释放引擎 |
| `(*WAF).Shutdown(ctx) error` | 等待当前与重载退休引擎排空；超时返回 `ErrShutdownTimeout` |

错误哨兵：`ErrNoRules`、`ErrInvalidMode`、`ErrInvalidLimit`、`ErrInvalidMimeType`、
`ErrInvalidOption`、`ErrBuild`、`ErrRequestBody`、`ErrResponseBody`、`ErrClosed`、
`ErrShutdownTimeout`。

### 4.5 事件与命中

`Event` 字段：`ID`、`Method`、`Path`、`ClientIP`、`Status`、`Blocked`、`Detected`、
`Phase`、`Interruption`、`Matches`、`Duration`、`Err`。

`Match` 字段：`RuleID`、`Message`、`Severity`、`Tags`、`Phase`、`Disruptive`。

`Interruption` 字段：`ID`、`RuleID`、`Action`、`Status`、`Data`、`Phase`。

注意：

- `Event.Matches` 只在观察者存在、请求被拦截/检测或发生内部错误时填充。
- `Event.Status` 对 CONNECT 隧道为 0（响应阶段未检测）。
- `Blocked` 与 `Detected` 互斥。
- 默认日志不输出 `Message`/`Data`，避免把攻击载荷写入日志；需要细节时用 `Observer`
  写入队列或审计日志。

### 4.6 Stats

| 字段 | 含义 |
|---|---|
| `Inspected` | 进入 Coraza 事务的请求数 |
| `Blocked` | 拦截模式下真实中断的请求数 |
| `Detected` | 仅检测模式下本应中断的请求数 |
| `Errors` | 检测、构建、重载失败数 |
| `Bypassed` | `Exclude` 或 `ModeOff` 放行数 |
| `Rejected` | 实例关闭后拒绝的请求数 |
| `Reloads` | 成功重载次数 |
| `InFlight` | 当前持有引擎预留的请求数 |

`InFlight` 不是“HTTP 连接数”：`Exclude`、`ModeOff` 与 `CONNECT` 在检测结束后立即释放
引擎，因此长连接不会阻塞重载退休或关闭排空。

---

## 5. 规则编写与管理

### 5.1 SecLang 最小语法

```text
SecRule VARIABLES "OPERATOR" "id:N,phase:P,ACTION,ACTION"
```

- 变量：`REQUEST_URI`、`REQUEST_HEADERS:User-Agent`、`ARGS`、`ARGS_POST`、
  `REQUEST_BODY`、`RESPONSE_HEADERS:X`、`RESPONSE_BODY`、`REMOTE_ADDR` 等。
- 操作符：`@contains`、`@streq`、`@rx`、`@detectSQLi`、`@detectXSS`、`@beginsWith` 等。
- 阶段：`phase:1` 请求头、`phase:2` 请求正文、`phase:3` 响应头、`phase:4` 响应正文、
  `phase:5` 日志。
- 动作：`deny`、`redirect`、`drop`、`pass`、`status`、`msg`、`tag`、`severity`、
  `chain`、`ctl`、`setvar`。
- 转换：`t:lowercase`、`t:urlDecodeUni`、`t:utf8toUnicode`、`t:removeNulls` 等。

示例：

```text
# 路径穿越（示例规则，生产需按业务调整）
SecRule REQUEST_URI "@rx (?i)(?:\.\./|%2e%2e(?:%2f|/))" \
    "id:9001,phase:1,deny,status:403,msg:'path traversal',severity:'CRITICAL'"

# SQL 注入（查询串 + 表单/JSON 展开后的 ARGS）
SecRule ARGS "@detectSQLi" \
    "id:9002,phase:2,deny,status:403,msg:'sql injection',severity:'CRITICAL'"

# XSS
SecRule ARGS "@detectXSS" \
    "id:9003,phase:2,deny,status:403,msg:'xss',severity:'CRITICAL'"

# 方法白名单
SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$" \
    "id:9004,phase:1,deny,status:405,msg:'method not allowed'"

# 响应头泄露（示例：只拦截特定调试头）
SecRule RESPONSE_HEADERS:X-Debug-Token "@rx .+" \
    "id:9005,phase:3,deny,status:500,msg:'debug header leak'"
```

规则编写原则：

- 自定义规则使用 `deny` 或 `redirect`；CRS 的 `block` 是占位动作，依赖 949 评估规则。
- 规则 ID 必须唯一且纳入变更管理；不要复用已删除规则的 ID。
- 优先缩小变量范围（如只匹配 `ARGS:username`），减少误报和求值成本。
- 正文规则依赖 body processor：表单/multipart 自动解析；JSON 需要显式 `ctl`。

### 5.2 Directives、RuleFiles 与 RootFS

| 来源 | 适用 | 加载顺序 |
|---|---|---|
| `RuleFiles` | CRS、团队规则包、可热更新文件 | 最先 |
| `Directives` | 少量内联规则、覆盖设置、审计开关 | 最后 |
| `RootFS` | `embed.FS`、`os.DirFS`、`coreruleset.FS` | 配合 `RuleFiles`/`Include` |

```go
// 从磁盘目录加载（支持 glob）
engine, _ := waf.New(waf.Options{
	RuleFiles: []string{"/etc/ydx/waf/*.conf"},
})

// 从二进制内嵌规则加载
//go:embed rules/*.conf
var rulesFS embed.FS
engine, _ = waf.New(waf.Options{
	RootFS:    rulesFS,
	RuleFiles: []string{"rules/*.conf"},
})
```

Windows 上 Coraza 解析器会用 `filepath.Join` 产生反斜杠路径，本模块的 `slashFS` 会自动
转换，因此嵌入式规则的 `Include` 与 glob 在 Windows 也可用。

### 5.3 使用 CRS

**Go/HTML/SQL/JavaScript 默认子集（推荐）**

默认规则围绕 Go 服务端、HTML/JavaScript 前端与 SQL 数据访问：保留语言无关的协议、
LFI/RFI/RCE、通用攻击、XSS、SQLi 与异常分阻断；剔除 PHP/Java/IIS 以及 934 中的
Ruby/PHP/Perl 子规则：

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
	// 934 中仅保留 JavaScript/Node.js 与 SSRF，剔除 Ruby/PHP/Perl 专用规则。
	"SecRuleRemoveById 934140 934150 934170",
},
```

当前 `coraza-coreruleset` 下该子集约 **377 条规则**，已验证正常请求放行，XSS/SQLi/路径
穿越拦截。

| 规则文件 | 默认 | 说明 |
|---|---|---|
| 901、905、949 | 必须 | 初始化、常见例外、异常分阻断 |
| 911、920、921 | 保留 | 方法/协议/协议攻击，语言无关，适用 Go 服务 |
| 930、931、932 | 保留 | LFI/RFI/RCE，Go 服务调用文件/命令时同样适用 |
| 934 | 保留（裁剪） | JavaScript/Node.js、原型污染、SSRF；移除 Ruby/PHP/Perl 子规则 |
| 941 | 保留 | XSS，覆盖 HTML/JavaScript 上下文 |
| 942 | 保留 | SQLi，覆盖 SQL 数据访问 |
| 913 | 按需 | 扫描器识别；可能拦截安全扫描工具 |
| 922 | 按需 | multipart 攻击；仅在 WAF 覆盖上传时加载 |
| 943 | 按需 | 会话固定；使用 Cookie 会话时考虑 |
| 933、944 | 排除 | PHP/Java 专用 |
| 950-980 | 排除 | 响应侧规则，且多为 PHP/Java/IIS；需要响应检测时再单独评估 |

**最小 941/942 子集**

只关心 XSS/SQLi、追求最低成本时，可只加载 901/905/941/942/949，共 **182 条规则**。

**完整 CRS**

```go
RuleFiles: []string{
	"@coraza.conf-recommended",
	"@crs-setup.conf.example",
	"@owasp_crs/*.conf",
},
```

当前版本共 **619 条规则**。已验证正常请求放行、XSS/SQLi 拦截。

重要：

- 941/942 只累计异常分；没有 949 就不会真正 `deny`。
- 901 提供阈值与变量初始化；没有 901 时异常分逻辑不完整。
- 905 提供常见误报例外，建议保留。
- 完整 CRS 包含 PHP/Java/ASP/IIS、扫描器、协议等规则；Go/HTML/SQL/JavaScript 技术栈应
  使用默认子集或最小子集。
- `RESPONSE-*` 规则只有在 `ResponseBodyAccess: true` 时才检测正文。

### 5.4 调优流程

1. **选规则**：默认使用「Go/HTML/SQL/JavaScript 默认子集」
   （901/905/911/920/921/930/931/932/934/941/942/949，并移除 934 的 Ruby/PHP/Perl 子规则）；
   按威胁模型追加 913（扫描器）、922（multipart）、943（会话固定），或退到最小 941/942 子集。
   不要加载 933/944（PHP/Java）与 950-980 响应规则，除非确有对应技术栈或响应检测需求。
2. **灰度**：`ModeDetection` + `Observer`，按 `rule_id`、路径、命中频率聚合。
3. **降噪优先级**：
   - `SecRuleUpdateTargetById 942100 "!ARGS:content"`：保留规则，排除具体字段；
   - `SecRuleRemoveById 942100 942200`：确认规则不适用时定向停用；
   - `Exclude`：健康检查、指标、静态资源、上传、流式接口整条旁路；
   - 调高异常分阈值/paranoia level：需在 CRS 初始化前生效，建议用自定义 setup 文件并
     回归测试。

   ```go
   RuleFiles: []string{
       "@coraza.conf-recommended",
       "@crs-setup.conf.example",
       "/etc/ydx/waf/crs-tune.conf", // 放在 CRS 规则之前
       "@owasp_crs/*.conf",
   },
   ```

   `crs-tune.conf`：

   ```text
   SecAction "id:900001,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=10"
   SecAction "id:900002,phase:1,nolog,pass,setvar:tx.blocking_paranoia_level=2"
   ```

   阈值/PL 会直接影响检出率与误报率，每次调整都必须用真实流量回归。
4. **验证**：预发/影子流量，观察 `Stats.Detected`、`Stats.Errors`、P99 与 Observer 事件。
5. **拦截**：`ReloadWith(ModeBlock)`；按路由组逐步扩大范围。
6. **持续**：阻断模式 `Stats.Detected` 应为 0；规则更新走 Reload 并保留回滚版本。

### 5.5 热重载

```go
if err := engine.Reload(); err != nil {
	// 旧引擎继续服务；查看 Stats.Errors 与日志
}
```

- `Reload` 重新读取 `RuleFiles`，按当前 Options 重编译。
- `ReloadWith` 替换**全部** Options（Logger/DebugLogWriter/Observer/Exclude/
  InspectRequestBody/InspectResponseBody/ArgumentsLimit/ErrorHandler 也会被替换）。
- 重载是原子的：新请求使用新引擎；旧引擎在最后一个在途请求结束后关闭。
- 失败时不切换，旧引擎继续服务。
- 没有内置文件监听器；在配置发布流程中调用 `Reload` 或定时调用。

---

## 6. 请求与响应生命周期

### 6.1 请求阶段

- 连接信息、URI、请求头、`Host`、`Transfer-Encoding` 送入 Coraza。
- 请求正文按 `RequestBodyLimit` 缓冲；检测后通过 `io.MultiReader` 完整回放给业务处理器。
- 没有 phase 2-5 规则能观察正文时自动跳过缓冲，处理器直接读取原始正文（不改变检测结果）。
- 超过上限且动作为 Reject → 413；`MaxBytesReader` 触发的超限同样映射为 413。
- `DisableRequestBodyAccess: true` 时只检测请求行/头；`REQUEST_BODY`/`ARGS_POST` 为空。
- `CONNECT` 不缓冲请求正文（隧道/字节流）。
- 请求阶段命中：默认写 403（或规则状态/重定向），不进入业务处理器；YD 入口调用
  `c.Abort()`。

正文处理器：

| Content-Type | 行为 |
|---|---|
| `application/x-www-form-urlencoded` | 自动 URLENCODED，填充 `ARGS_POST` 与 `REQUEST_BODY` |
| `multipart/form-data` | 自动 multipart，填充上传/表单变量；大文件建议排除 |
| `application/json` | 默认不自动解析；规则需 `ctl:requestBodyProcessor=JSON` |
| 其它/未设置 | 不解析；`REQUEST_BODY` 可能为空（取决于 processor） |

JSON 示例：

```text
SecRule REQUEST_HEADERS:Content-Type "@contains application/json" \
    "id:910000,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule ARGS "@detectSQLi" \
    "id:910001,phase:2,deny,status:403,msg:'json sqli'"
```

### 6.2 响应阶段

- 响应头进入阶段 3；响应正文按 MIME 与 `ResponseBodyAccess` 决定是否缓冲。
- 没有 phase 4-5 规则且未配置审计时，即使开启 `ResponseBodyAccess` 也自动跳过正文缓冲；
  没有 phase 3-5 规则且无 `Observer` 时直接使用原始写入器。
- 默认响应正文检测关闭，正文直接流式下发。
- 开启后，命中 MIME 的正文被缓冲到 `ResponseBodyLimit`：
  - ProcessPartial（默认）：检测前缀，完整正文仍会下发；
  - Reject（内联指令覆盖）：超限返回 500。
- 命中阶段 3/4：清除待发响应头，写出错误响应，避免业务正文/敏感头泄露。
- `Content-Type` 未显式设置时，首块正文按 net/http 语义嗅探，保证响应检测与浏览器行为一致。
- `Flush` 在正文待检测时会被推迟到阶段 4 得出结论；SSE/长轮询请排除对应 MIME 或用
  `Exclude`。
- 保留 `Hijacker`/`Pusher`/`Unwrap`；101、204、HEAD、空响应有专门处理。
- `CONNECT` 响应阶段整体跳过，以保留传输层专用写入器接口。

### 6.3 中间件顺序

推荐 YD 顺序：

```go
r.Use(
	middleware.RequestID(""),
	middleware.Recover(logger),
	middleware.AccessLog(logger),
	middleware.RateLimit(rateLimitOptions), // 先丢弃洪峰，再进入昂贵的 WAF
	middleware.Compress(compress.CompressOptions{}), // 响应变换在 WAF 之外
	engine.Middleware(),                            // 检测明文，再交给压缩
	authMiddleware,
)
```

原则：

- WAF 在业务处理器与业务中间件之前，才能覆盖它们的请求/响应。
- `ratelimit` 在 WAF 之前：被限流的请求不进入规则求值，显著降低洪峰成本，同时让
  `accesslog` 仍能记录 429（访问日志在限流之前/外层）。
- `compress` 在 WAF 之前，WAF 看到明文；压缩发生在检测之后。
- `accesslog`/`recover` 在 WAF 之前，能记录 WAF 产生的 403/503 并兜住 panic。
- `auth` 在 WAF 之后更安全（未认证流量也检测）；如果认证很便宜且流量巨大，可把
  `auth` 放到 WAF 之前节省成本，但登录/鉴权端点本身仍应单独挂 WAF。
- `CONNECT`/WebSocket/WebTransport 路由独立挂载，不叠加压缩等写入器包装。
- 原生 `net/http` 用 `engine.HTTPMiddleware(next)` 包裹最终 handler；与其它原生中间件
  组合时遵循同样的内外层原则。

### 6.4 异常与关闭

- 业务 panic：WAF 关闭事务并释放引擎，响应处理跳过，panic 继续向上传播。
- WAF 内部错误：500；正文超限：413；实例关闭：503。
- `Close` 不等待；`Shutdown` 等待当前与重载退休引擎的在途请求。
- 关闭/超时后实例不可重新打开；重新上线需要新的 `New`。

---

## 7. 常见场景配置

### 7.1 公网 API 基线（Go/HTML/SQL/JavaScript 默认子集）

```go
base := waf.Options{
	RootFS: coreruleset.FS,
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
		"SecRuleRemoveById 934140 934150 934170", // Ruby/PHP/Perl 子规则
	},
	Mode: waf.ModeDetection,
	Exclude: func(r *http.Request) bool {
		switch r.URL.Path {
		case "/healthz", "/metrics", "/favicon.ico":
			return true
		}
		return false
	},
}
engine, err := waf.New(base)
```

上线后按 Observer 统计调优，再 `ReloadWith` 切换 `ModeBlock`。

### 7.2 只保护敏感路由组

```go
r := router.New()
// 静态资源、健康检查：不挂 WAF
r.GET("/healthz", healthHandler)

api := r.Group("/api", engine.Middleware())
api.POST("/login", loginHandler)
api.POST("/pay", payHandler)
api.GET("/admin/users", adminHandler)
```

这是高吞吐系统最有效的成本控制方式：WAF 只覆盖真正需要防护的路由。

### 7.3 JSON / REST API

```go
engine, _ := waf.New(waf.Options{
	Directives: []string{
		`SecRule REQUEST_HEADERS:Content-Type "@contains application/json" "id:910000,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"`,
		`SecRule ARGS "@detectSQLi" "id:910001,phase:2,deny,status:403,msg:'json sqli'"`,
		`SecRule ARGS "@detectXSS" "id:910002,phase:2,deny,status:403,msg:'json xss'"`,
	},
	ResponseBodyAccess:   true,
	ResponseBodyMimeTypes: []string{"application/json"},
	ResponseBodyLimit:    2 << 20,
})
```

注意：JSON 展开后的 `ARGS` 可能包含大段文本（Markdown、代码、富文本），建议用
`SecRuleUpdateTargetById` 排除特定字段，而不是删除规则。

### 7.4 文件上传与下载

上传路径通常不应整体缓冲：

```go
uploads := r.Group("/upload", uploadEngine.Middleware())
```

其中 `uploadEngine` 使用与主引擎相同的规则，但：

```go
waf.Options{
	Directives:               rules,
	DisableRequestBodyAccess: true, // 不在 WAF 里缓冲上传
}
```

或者直接 `Exclude` 上传路径。下载/大文件响应保持 `ResponseBodyAccess: false`，让
`ReadFrom` 走底层快路径。

### 7.4.1 单实例按路由控制正文

不必为每一种正文策略拆多个引擎：一个全局实例可以用 `InspectRequestBody` /
`InspectResponseBody` 按路径决定是否缓冲正文，URI 与头规则仍然生效。

```go
engine, err := waf.New(waf.Options{
	RuleFiles:      crsSubset,
	ArgumentsLimit: 200, // 公开表单的参数上限；0 表示 Coraza 默认 1000
	InspectRequestBody: func(r *http.Request) bool {
		switch r.URL.Path {
		case "/upload", "/webhooks/stripe":
			return false // 不缓冲；REQUEST_BODY/ARGS_POST 为空，处理器读原始正文
		}
		return true
	},
	InspectResponseBody: func(r *http.Request) bool {
		return !strings.HasPrefix(r.URL.Path, "/download/")
	},
})
if err != nil {
	return err
}
r.Use(engine.Middleware())
```

- 返回 `false` 只跳过正文缓冲，不跳过请求行、URI 与请求头检测。
- 响应侧返回 `false` 时仍执行阶段 3 的响应头规则；阶段 4-5 的正文规则看不到正文。
- 回调只在规则集本会检测正文时调用；没有正文规则时没有额外开销。
- 需要整条请求都不检测时用 `Exclude`，不要用这两个回调模拟旁路。

### 7.5 SSE、长轮询与流式响应

- 默认响应正文检测关闭，无需特殊处理。
- 若开启 `ResponseBodyAccess`，不要把 `text/event-stream` 加入
  `ResponseBodyMimeTypes`；否则 `Flush` 会被推迟到响应结束。
- 或者对 SSE 路由使用 `Exclude` / 独立路由组。
- 请求侧长连接（上传流）应关闭正文访问或排除，否则会被缓冲到上限。

### 7.6 WebSocket / WebTransport / extended CONNECT

- HTTP/1.1 WebSocket（GET + Upgrade）：包装器保留 `Hijacker`，握手头参与检测。
- HTTP/2/3 extended CONNECT、WebTransport：只检测请求行/头；响应阶段跳过，写入器保持
  原始类型。
- 不要在这些路由上叠加压缩等会包装 `http.ResponseWriter` 的中间件。
- 建议独立挂载：

```go
ws := r.Group("/ws", engine.Middleware())
```

### 7.7 反向代理之后

```go
// isTrustedProxy 由应用根据代理网段/节点列表实现。
ClientIP: func(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !isTrustedProxy(host) {
		return host // 非可信对端：忽略 XFF
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	first, _, _ := strings.Cut(xff, ",")
	return strings.TrimSpace(first)
}
```

要点：

- 只有对端在可信代理列表内才读取 `X-Forwarded-For`，否则任何客户端都能伪造。
- `ClientIP` 返回主机，不含端口。
- 与访问日志使用同一套可信代理规则，避免日志和执行层看到的 IP 不一致。

### 7.8 多实例与多租户

```go
engineA, _ := waf.New(tenantAOptions)
engineB, _ := waf.New(tenantBOptions)
r.Group("/tenant/a", engineA.Middleware())
r.Group("/tenant/b", engineB.Middleware())
```

- 实例之间不共享规则、统计、观察者或引擎状态。
- 每个实例独立编译规则并持有内存；租户很多时优先使用一个引擎 + Host/路径规则，而不是
  每租户一个引擎。
- 多进程部署时每个进程独立；规则文件/配置需一致，审计日志按进程分文件或使用
  Concurrent 模式。

### 7.9 灰度与热更新

```go
// 1) 检测模式观察
engine, _ := waf.New(waf.Options{Directives: rules, Mode: waf.ModeDetection, Observer: observe})

// 2) 发布新规则文件后
if err := engine.Reload(); err != nil {
	logger.Error("waf reload failed", log.Err(err))
}

// 3) 确认误报后切拦截
blocked := base
blocked.Mode = waf.ModeBlock
_ = engine.ReloadWith(blocked)
```

建议把 `rules`/`base` 保存在应用配置对象中，避免 `ReloadWith` 只传入部分字段导致
Logger/Observer/Exclude 被清空。

### 7.10 应急关闭

```go
off := base        // base 是完整的原始 Options
off.Mode = waf.ModeOff
if err := engine.ReloadWith(off); err != nil {
	// 保留旧模式
}
```

`ModeOff` 保留规则和热重载能力，只是停止求值；比删除规则或回滚版本更快。恢复时用
`ReloadWith(base)` 或 `ModeBlock`。空规则集仍会被拒绝，因此应急配置必须包含规则。

### 7.11 自定义 JSON 错误响应

```go
ErrorHandler: func(w http.ResponseWriter, r *http.Request, it *waf.Interruption) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(it.Status)
	_, _ = io.WriteString(w, `{"error":"request blocked","code":"waf_blocked"}`)
},
```

不要回显 `it.RuleID`、`it.Data` 或匹配内容；这些信息只应进入受控日志/审计。

### 7.12 审计与 SIEM

默认审计关闭。需要时通过内联指令开启：

```go
Directives: []string{
	`SecAuditEngine RelevantOnly`,
	`SecAuditLog /var/log/ydx/waf-audit.log`,
	`SecAuditLogType Serial`,
	`SecAuditLogFormat JSON`,
	`SecAuditLogParts ABFHZ`, // 不含请求/响应正文
},
```

要点：

- `Serial` 单文件、有写锁；高流量用 `Concurrent`（需 `SecAuditLogStorageDir`）或 `HTTPS`
  / `Syslog`。
- `SecAuditLogParts` 不要包含 `C`/`E`/`G`（正文）除非合规要求，并做好脱敏与访问控制。
- 审计写入发生在日志阶段，属于同步 I/O；高流量请评估磁盘/网络成本。
- 也可以不用 Coraza 审计，改用 `Observer` 把事件送入已有的日志/SIEM 队列。

### 7.13 高吞吐低延迟

- 只在高风险路由组挂 WAF；静态资源/健康检查不挂。
- 规则子集优先；完整 CRS 仅用于灰度/审计。
- 延迟极敏感接口关闭请求正文访问或使用 `Exclude`。
- 响应正文检测默认关闭；需要时按接口开启，并设置小上限。
- 不要用 WAF 的纳秒级对比衡量；规则求值才是主导成本。
- 在目标机器上用真实规则与流量压测，不依赖开发机数字。

### 7.14 本地测试与 CI

```go
func TestBlockSQLi(t *testing.T) {
	engine, err := waf.New(waf.Options{
		Directives: []string{
			`SecRule ARGS "@detectSQLi" "id:9002,phase:2,deny,status:403"`,
		},
		Logger: log.New(log.Options{Writer: io.Discard}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	h := engine.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?q=1%27%20OR%20%271%27%3D%271", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
}
```

CI 中同时跑正常请求与攻击请求；并发测试加 `-race`。

---

## 8. 最佳实践

### 8.1 安全清单

- [ ] 先 `ModeDetection` 观察，再按路由/规则逐步切 `ModeBlock`。
- [ ] 使用最小规则集；完整 CRS 只作灰度/审计起点。
- [ ] CRS 必带 901/905/949；自定义规则用 `deny`/`redirect`。
- [ ] 误报优先用目标排除（`SecRuleUpdateTargetById`），其次按 ID 停用，最后才排除整条路径。
- [ ] 版本化规则文件；规则变更走评审、预发、灰度、回滚。
- [ ] 拦截响应不含规则细节，设置 `Cache-Control: no-store`。
- [ ] 请求正文上限按业务最小值设置；上传/流式接口关闭正文访问或排除。
- [ ] 响应正文检测只对需要的接口开启，并设置小上限。
- [ ] 可信代理之后才读取 `X-Forwarded-For`；`ClientIP` 返回主机不含端口。
- [ ] 审计默认关闭；开启时避免正文 part，保护日志文件权限。
- [ ] 不把口令、Token、DSN、完整请求体写入日志。
- [ ] 为 `Stats.Errors`、`Stats.Rejected`、`Stats.Detected` 配置告警。
- [ ] WAF 不能替代参数化 SQL、输出编码、认证与最小权限。
- [ ] 定期升级 Coraza/CRS 并重跑规则回归。

### 8.2 性能清单

- [ ] 只在高风险路由组挂载 WAF。
- [ ] 静态资源、健康检查、指标、上传、SSE 排除或独立引擎。
- [ ] 规则子集优先；完整 CRS 会增加约 2 倍规则求值成本。
- [ ] `ModeDetection` 不是性能优化：它仍执行全部规则与正文缓冲。
- [ ] 正文解析是主要成本；不需要正文规则时关闭正文访问。
- [ ] 响应正文默认关闭；开启时按接口与 MIME 收窄。
- [ ] 设置合理上限，避免并发 × 上限造成内存压力。
- [ ] 生产构建 `CGO_ENABLED=0`。
- [ ] 用目标机器、真实规则和真实流量做基线；不要把路由 ns 数字与 WAF 对比。
- [ ] 关注 `Observer` 回调成本；耗时工作放队列。
- [ ] 完整优化清单与源码级备忘见 [PERFORMANCE.md](PERFORMANCE.md)。

### 8.3 运维清单

- [ ] 启动时检查 `New` 错误，不要带病启动。
- [ ] 记录 `RulesCount`、`Mode` 与规则文件版本。
- [ ] 等待信号时调用 `Shutdown(ctx)`；超时后再 `Close`。
- [ ] 规则发布后调用 `Reload`/`ReloadWith`，检查日志与 `Stats.Errors`。
- [ ] 监控 `Blocked`、`Detected`、`Errors`、`Rejected`、`InFlight` 与 P99。
- [ ] 阻断模式 `Detected` 应保持 0；非零说明仍有规则在灰度路径命中。
- [ ] 多实例/多进程部署时，规则版本与审计输出保持一致。
- [ ] 为新模块打 `middleware/waf/vX.Y.Z` 子目录标签；升级同步 README 体积说明。

### 8.4 上线检查表

1. 规则在本地/CI 用正常与攻击样本回归通过。
2. 预发环境 `ModeDetection` 跑真实/影子流量，错误率与 P99 可接受。
3. 误报规则已用目标排除/ID 停用处理，保留审计记录。
4. 健康检查、上传、SSE、WebSocket/WebTransport 路由已验证不受影响。
5. 告警接入 `Detected`、`Errors`、`Rejected`。
6. 灰度切 `ModeBlock`，按路由逐步放量。
7. 准备回滚：`ReloadWith(ModeDetection)` 或 `ModeOff`，旧规则文件可恢复。
8. 记录本次规则版本、Coraza/CRS 版本与验证命令。

---

## 9. 可观测性与审计

### 9.1 日志字段

默认拦截/检测/错误日志字段：

```
tx_id, method, path, client_ip, status, phase, rules,
duration, rule_id, action, first_match_rule_id, error
```

- `rule_id` 是产生中断的规则；CRS 下通常是 949xxx 异常分评估。
- `first_match_rule_id` 是首个命中规则，通常指向真正的攻击规则（如 942100）。
- 不记录查询串、正文、规则 Message/Data。

高流量攻击下可用更高日志级别或 `Observer` 指标抑制日志放大。

### 9.2 指标映射

| 指标 | 来源 | 告警建议 |
|---|---|---|
| 请求量 | `Stats.Inspected` 增速 | 基线异常 |
| 拦截量 | `Stats.Blocked` 增速 | 突增/突降 |
| 检测量 | `Stats.Detected` | 阻断模式下应恒为 0 |
| 内部错误 | `Stats.Errors` | 任意增长都告警 |
| 关闭拒绝 | `Stats.Rejected` | 实例关闭/滚动发布期间关注 |
| 在途 | `Stats.InFlight` | 长时间不降 → 长连接/泄漏排查 |
| 规则数 | `RulesCount` | 与预期规则版本对比 |

### 9.3 审计

- Coraza 审计：通过 `Directives` 开启 `SecAuditEngine` + `SecAuditLog*`；适合合规/取证。
- 应用审计：`Observer` 把 `Event` 写入队列，再由现有日志/SIEM 管道处理，避免请求
  goroutine 做阻塞 I/O。
- 不要把完整正文写入审计，除非确有合规要求并完成脱敏、访问控制与保留策略。

### 9.4 Coraza 内部调试

排障时可设置 `DebugLogWriter` 打开 Coraza 的 debug 日志：

```go
engine, _ := waf.New(waf.Options{
	Directives:     rules,
	DebugLogWriter: os.Stderr, // 只应在排障环境开启
})
```

生产环境保持为 nil：默认使用零分配的 no-op 日志器，避免 Coraza 为每个事务分配调试上下文。
调试日志可能包含 URI、规则和请求细节，不要长期开启，也不要写入共享日志。

### 9.5 内置性能优化

- Coraza 事务 ID 调试上下文默认 no-op，避免每事务分配；需要时用 `DebugLogWriter` 开启。
- 请求 URI 使用 `RequestURI` 原始目标，避免 `URL.String()` 的每请求分配。
- 编译期按阶段统计规则：无相应规则时自动跳过请求正文缓冲、响应头采集或响应正文缓冲；
  无响应规则且无观察者时直接使用原始写入器。
- 请求正文使用 `buffpool` 池化 32 KiB 块读取，并在归还前清零；达到上限时只复制未写入的
  块尾，避免 `io.Copy` 的每请求大块分配。
- 响应拦截器池化；流式响应委托底层 `ReaderFrom`。
- 审计默认关闭、响应正文检测默认关闭。
- 引擎获取使用短临界区；并行基准在 16 核上仍能随核心数扩展。

---

## 10. FAQ

**Q1. 规则命中了，但没有拦截？**

依次检查：`Mode` 是否为 `ModeDetection`；规则动作是否为 `block`（CRS 需要 949）；
是否缺少 `REQUEST-949-BLOCKING-EVALUATION.conf`；规则阶段是否与变量匹配；请求正文访问
是否关闭；JSON 是否缺少 `ctl:requestBodyProcessor=JSON`；路径是否被 `Exclude`；引擎是否
被指令设为 `Off`。`Stats.Detected`/日志能快速区分“命中但未阻断”和“根本没命中”。

**Q2. 为什么全量 CRS 后误报暴增？**

全量包含 PHP/Java/ASP/IIS、扫描器、协议等规则，Go/HTML/SQL/JavaScript 技术栈用不到很大
一部分。默认改用「Go/HTML/SQL/JavaScript 子集」（377 条）：保留
911/920/921/930/931/932/934/941/942/949，剔除 933/944、950-980 以及 934 中的
Ruby/PHP/Perl 子规则；再按需追加 913/922/943。误报字段用 `SecRuleUpdateTargetById` 排除，
不要直接删除整类规则。

**Q3. 如何排除某个参数或路径？**

参数：`SecRuleUpdateTargetById 942100 "!ARGS:content"`；规则：`SecRuleRemoveById ...`；
整条路径：`Options.Exclude`。优先目标排除，其次规则停用，最后整路径旁路。

**Q4. 如何只记录不拦截？**

`ModeDetection`。`Stats.Detected` 与 `Observer` 会记录本应拦截的请求；确认后
`ReloadWith(ModeBlock)`。

**Q5. 如何应急关闭 WAF？**

`ReloadWith` 同一份完整 Options，只把 `Mode` 改为 `ModeOff`。保留规则与热重载能力，比
删除规则或回滚版本更快。

**Q6. 请求正文什么时候被缓冲？**

默认开启，上限 8 MiB/内存 128 KiB；表单/multipart 会解析，JSON 需要 `ctl`。即使开启，
只要没有 phase 2-5 规则能观察正文，也会自动跳过缓冲。不需要正文规则时用
`DisableRequestBodyAccess: true` 或 `Exclude`；上传/流式接口必须排除或关闭。

**Q7. 业务处理器收到的请求正文为什么是完整的？**

WAF 缓冲后通过 `io.MultiReader` 回放，业务看到原始正文。只有在请求被拦截或 WAF 内部
错误时不会进入处理器。

**Q8. 为什么 SSE/长轮询卡住？**

开启响应正文检测且 `text/event-stream` 在 MIME 列表时，`Flush` 会被推迟到响应结束。
把该 MIME 从列表移除，或对 SSE 路由 `Exclude`/独立挂载。

**Q9. 为什么响应正文规则不生效？**

检查是否真的存在 phase 4-5 规则（没有时即使开启 `ResponseBodyAccess` 也会自动跳过缓冲）；
`ResponseBodyAccess` 是否为 true；Content-Type 是否在 `ResponseBodyMimeTypes` 中；响应是否
被压缩（压缩必须发生在 WAF 之后/之外，即 `compress` 注册在 WAF 之前）；响应是否超过
`ResponseBodyLimit` 且只检测了前缀。

**Q10. 为什么压缩后的响应检测不到？**

WAF 只能检测它看到的字节。`compress` 应在 WAF 之前注册，让 WAF 处理明文，再由压缩写出；
若顺序相反，WAF 看到的是 gzip/brotli 字节。

**Q11. 为什么业务读到的请求体为空或不完整？**

检查是否有外层中间件在 WAF 之前读取了正文且未回放；确认 WAF 在链中的位置；确认没有
`DisableRequestBodyAccess` 与正文规则混用；超限被 413 时处理器不会执行。

**Q12. 413/500/503 分别是什么？**

413：请求正文超过上限（Reject）；500：WAF 内部检测/响应正文处理失败（fail-closed）；
503：实例已 `Close`/`Shutdown`，新请求被拒绝。

**Q13. Shutdown 超时怎么办？**

检查长连接/SSE/长耗时 handler，`Stats.InFlight` 与日志能定位。`CONNECT` 与排除请求会提前
释放引擎，不会阻塞排空；普通长请求仍会等待到 ctx 超时。超时后实例保持关闭，剩余引擎在
请求结束时自行关闭。

**Q14. Reload 后规则没变化？**

确认路径/glob/`RootFS` 是否正确；检查 `Reload` 返回错误与 `Stats.Errors`；确认规则文件
确实被重新读取（相对路径取决于进程工作目录）；确认 `Mode`/`Exclude` 没有让规则失效。
`RulesCount` 可快速确认新引擎规则数。

**Q15. 为什么 `go get` 找不到版本？**

新模块需要先打并推送 `middleware/waf/vX.Y.Z` 子目录标签；未发布前只能用本地 replace
开发，发布态禁止 replace。

**Q16. 为什么 `middleware.WAF` 不存在？**

WAF 刻意不并入聚合门面，避免 Coraza/OCSF 依赖影响所有中间件使用者。直接导入
`github.com/shibingli/ydx/middleware/waf`。

**Q17. 支持 CGO_ENABLED=0 吗？**

支持。Coraza 与 ydx WAF 都是纯 Go；只有 `-race` 测试需要 C 编译器。

**Q18. 能用于 WebSocket / WebTransport / HTTP/3 吗？**

可以。HTTP/1.1 WebSocket 通过 `Hijacker`；HTTP/2/3 extended CONNECT 与 WebTransport 的
请求行/头会被检测，响应阶段跳过以保留传输层专用写入器接口。不要在这些路由上叠加压缩等
写入器包装。

**Q19. 如何接入 SIEM？**

两种方式：`Observer` 把事件写入队列/日志管道；或通过 `SecAuditLog*` 指令写 JSON/OCSF
审计。审计默认关闭，正文 part 慎用。

**Q20. 多实例会共享规则/统计吗？**

不会。每个 `*WAF` 独立编译规则、独立计数与观察者；多进程也各自独立。租户很多时优先
单引擎 + Host/路径规则，避免过多引擎的内存与编译成本。

**Q21. 为什么日志里的 `rule_id` 是 949110？**

949110 是 CRS 异常分阻断规则，不是攻击检测规则。看 `first_match_rule_id` 或
`Observer.Matches` 获取真正计分的规则（如 942100）。

**Q22. 支持哪些 SecLang/操作符？**

支持 Coraza v3.8.1 的 SecLang 与 CRS；部分 ModSecurity 指令会被接受但忽略。上线前用
`New`/`Reload` 编译验证，并用正常/攻击样本回归。

**Q23. 如何测试规则？**

用 `httptest` + `ModeDetection`/`ModeBlock` 写单元测试（见 7.14）；并发用 `-race`；预发
用真实/影子流量；不要只在开发机手工 curl。

**Q24. 性能开销多大？**

数量级：单条 URI/头规则微秒级；941/942 子集数百微秒；完整 CRS 可达毫秒级；正文解析是
主要变量。开发机参考（Windows、httptest、含 recorder）：仅请求头规则 GET ~6–7 µs；
Go/HTML/SQL/JavaScript 默认子集 GET ~430–465 µs、表单 POST ~660–820 µs；最小 941/942
子集 GET ~220 µs、表单 POST ~320 µs；完整 CRS GET ~520–580 µs、表单 POST ~780–840 µs；
需要正文解析的 1 KiB 表单请求约 45–57 µs。以目标
机器实测为准。

**Q25. gRPC / GraphQL 怎么处理？**

gRPC 正文是二进制/protobuf，默认 body processor 不解析；建议只检测头/方法或排除，避免
无意义缓冲。GraphQL 是 JSON，可用 `ctl:requestBodyProcessor=JSON` + `ARGS`，但查询文本
容易触发 SQLi/XSS 误报，需要目标排除或自定义规则。

**Q26. 为什么 ClientIP 不是客户端真实 IP？**

默认解析 `RemoteAddr`；在反向代理后需要配置 `ClientIP` 并从可信代理的
`X-Forwarded-For` 提取。绝不能在未校验对端的情况下信任 XFF。

**Q27. 关闭后还能重新打开吗？**

不能。`Close`/`Shutdown` 后实例不可复用；重新上线需要 `New`。滚动发布时先启动新实例，
再关闭旧实例。

**Q28. 与 Coraza 官方 `http.WrapHandler` 有什么区别？**

本模块在官方适配器设计基础上增加了 ydx 生命周期（请求上下文、观察者、统计、错误响应、
热重载、优雅关闭、CONNECT 处理、审计/日志基线、安全默认值）。规则语义仍由 Coraza 决定。

**Q29. WAF 会修改请求或响应正文吗？**

不会改正文。请求正文缓冲后原样回放；响应正文原样回传；仅在命中规则时替换为错误响应。
未显式设置 `Content-Type` 时，会按 net/http 的规则补全嗅探结果；除此之外不修改业务头。

**Q30. 如何排查 Coraza 内部行为？**

优先看 `Stats()`、拦截/检测日志与 `Observer.Matches`。仍有疑问时在排障环境设置
`DebugLogWriter: os.Stderr` 打开 Coraza debug 日志；生产保持 nil（no-op 日志器零分配）。
调试输出可能包含敏感请求细节，不要长期开启。

**Q31. `ModeDetection` 会更快吗？**

不会。检测模式仍然执行全部规则并缓冲请求正文，只是不返回 403、把结果记入
`Stats.Detected`。真正降低开销的手段是：规则子集、路由分组、关闭不需要的正文/响应检测、
排除健康检查/静态资源/上传/流式接口，以及在 WAF 之前先做限流。

---

## 11. 故障排查速查表

| 现象 | 优先检查 | 处理 |
|---|---|---|
| 规则不生效 | `Mode`、规则动作、949、阶段、正文访问、JSON processor、`Exclude`、`RulesCount` | 切 Block/补 949/改阶段/开正文或 processor |
| 误报太多 | 规则集是否全量、paranoia level、命中字段 | 子集、目标排除、停用 ID、阈值/PL、灰度 |
| 403 太多但找不到规则 | `first_match_rule_id`、Observer.Matches、日志 | 按规则 ID 定向排除 |
| 请求体为空 | 外层中间件是否提前读取、WAF 顺序、正文访问 | 调整顺序、开启/关闭正文访问 |
| 413 | 正文上限、路由器 MaxBodySize、上传路径 | 提高合理上限、排除上传 |
| 500 | `Stats.Errors`、日志 error 字段、响应正文处理 | 修规则/上限；fail-closed 属预期 |
| 503 | 实例是否已 Close/Shutdown | 重启实例/检查信号处理 |
| SSE/WebSocket 卡住 | 响应 MIME 列表、Flush、compress 顺序、CONNECT | 移除 MIME/排除/调整顺序 |
| Reload 无效 | 路径、RootFS、glob、返回错误、RulesCount | 修正路径、查看 Stats.Errors |
| Shutdown 超时 | InFlight、长请求、SSE/长轮询 | 缩短 ctx 后再 Close、优化长请求 |
| 日志过多 | 日志级别、检测模式、攻击流量 | 提高级别、Observer 指标、限流 |
| 性能差 | 全量 CRS、正文解析、路由范围、响应检测 | 子集、分组、关正文/响应检测、压测 |
| 内存高 | 并发 × 正文上限、响应缓冲、临时文件 | 降低上限、排除大请求、监控磁盘 |
| `go get` 失败 | 模块标签是否发布 | 打 `middleware/waf/vX.Y.Z` 标签 |

排查顺序建议：

1. `RulesCount()` 是否符合预期；
2. `Stats()` 中 Inspected/Blocked/Detected/Errors/Bypassed/Rejected 的分布；
3. 打开 `Observer` 看 `Event.Matches` 与 `Phase`；
4. 检查 `Mode`、`Exclude`、规则文件路径与加载顺序；
5. 用最小规则 + `httptest` 复现，再回到完整规则集。

---

## 12. 升级、版本与发布

- 本模块锁定 `github.com/corazawaf/coraza/v3 v3.8.1`；升级需单独评审，并重新跑规则
  回归、race 测试与 CRS 端到端验证。
- `coraza-coreruleset` 由应用显式引入；升级 CRS 后必须重跑误报统计。
- 每个模块按子目录标签发布，例如 `middleware/waf/v0.1.0`；已推送标签不可移动。
- 发布前：所有模块测试、`repotest`、全模块构建通过；新模块需要先发布标签，下游才能按
  版本引用。
- 正式基准待首个标签发布后补充 `benchmarks/waf`（基准模块不能引用未打标签的新模块）。
- 升级检查表：
  1. 阅读 Coraza/CRS changelog 与安全公告；
  2. 在预发用 `ModeDetection` 跑真实流量；
  3. 对比 `RulesCount`、命中规则、P99、错误率；
  4. 灰度切 Block，保留回滚；
  5. 更新 go.mod/go.sum、README 体积说明与版本记录。

---

## 13. 附录

### A. 安全基线速查

```
SecRuleEngine On | DetectionOnly | Off
SecAuditEngine Off
SecRequestBodyAccess On | Off
SecRequestBodyLimit 8388608
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off | On
SecResponseBodyLimit 1048576
SecResponseBodyLimitAction ProcessPartial
SecResponseBodyMimeType text/plain text/html application/json application/xml application/xhtml+xml text/xml
```

顺序：`RuleFiles → 基线 → Directives`。

### B. 自定义规则包模板

```text
# 自定义规则建议使用独立文件，纳入版本管理。
# 规则 ID 段：900000+（项目自定义）；CRS 规则 ID 不要复用。

SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$" \
    "id:900001,phase:1,deny,status:405,msg:'method not allowed',tag:'ydx/waf'"

SecRule REQUEST_URI "@rx (?i)(?:\.\./|%2e%2e(?:%2f|/))" \
    "id:900002,phase:1,deny,status:403,msg:'path traversal',severity:'CRITICAL',tag:'ydx/waf'"

SecRule ARGS "@detectSQLi" \
    "id:900003,phase:2,deny,status:403,msg:'sql injection',severity:'CRITICAL',tag:'ydx/waf'"

SecRule ARGS "@detectXSS" \
    "id:900004,phase:2,deny,status:403,msg:'xss',severity:'CRITICAL',tag:'ydx/waf'"
```

### C. 完整 CRS 配置

```go
engine, err := waf.New(waf.Options{
	RootFS: coreruleset.FS,
	RuleFiles: []string{
		"@coraza.conf-recommended",
		"@crs-setup.conf.example",
		"@owasp_crs/*.conf",
	},
	Mode: waf.ModeDetection,
})
```

完整 CRS 当前 619 条规则；正常请求放行，XSS/SQLi 已被端到端验证拦截。生产建议从子集
开始，按 Observer 数据裁剪。

### D. 术语

| 术语 | 含义 |
|---|---|
| SecLang | ModSecurity/Coraza 规则语言 |
| CRS | OWASP Core Rule Set |
| 异常分 | CRS 对命中规则累计的分值，949 根据阈值决定 deny |
| Paranoia Level | CRS 规则严格程度，越高越安全也越易误报 |
| Transaction | Coraza 的每请求事务 |
| Interruption | 规则产生的中断（deny/redirect/drop） |
| ProcessPartial | 达到正文上限后只检测前缀，其余继续下发 |
| fail-closed | 检测失败时拒绝请求而不是放行 |
| extended CONNECT | HTTP/2/3 上的 WebSocket/WebTransport 升级 |

### E. 相关模块

- [`router`](../../router/README.md)：路由与中间件链。
- [`middleware/compress`](../compress/README.md)：响应压缩，注意顺序。
- [`middleware/accesslog`](../accesslog/README.md)：访问日志。
- [`middleware/recovery`](../recovery/README.md)：panic 恢复。
- [`middleware/ratelimit`](../ratelimit/README.md)：限流（WAF 不负责限流）。
- [`middleware`](../README.md)：聚合门面（不包含 WAF）。

### F. 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`corazawaf/coraza/v3`](https://github.com/corazawaf/coraza) | v3.8.1 | Apache-2.0 | WAF 引擎、SecLang、事务生命周期 |
| [`corazawaf/coraza-coreruleset`](https://github.com/corazawaf/coraza-coreruleset) | 可选 | Apache-2.0 | OWASP CRS 嵌入式规则 |

Coraza 的主要传递依赖：`libinjection-go`、`aho-corasick`、`gjson`、`jsonschema`、
`ocsf-schema-golang`、`protobuf`、`golang.org/x/net`、`binaryregexp`。

模块缓存源码约 60 MB，最终二进制通常增加数 MB；这正是本模块不并入 `middleware` 聚合
门面的原因。请求适配与响应拦截设计参考 Coraza 官方 `net/http` 适配器（Apache-2.0）。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
