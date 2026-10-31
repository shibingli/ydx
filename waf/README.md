# ydx/waf — 高性能 SecLang WAF

`github.com/shibingli/ydx/waf` 是 ydx 唯一的 Web 应用防火墙实现：不内嵌 Coraza 引擎，
直接解析并求值 ModSecurity/Coraza/OWASP CRS SecLang 规则，原生支持 `ydx/router` 与
`net/http`。原 `middleware/waf`（Coraza 封装 v1）已移除，新项目直接导入：

```go
import "github.com/shibingli/ydx/waf"
```

## 特性

- **规则兼容**：SecLang 文件/内联指令、`Include` 递归、`SecRule`/`SecAction`/`SecMarker`/
  `SecDefaultAction`、`SecRuleUpdate*`/`SecRuleRemove*`、链式规则、`capture`、`skip`/
  `skipAfter`、`ctl` 事务级控制、CRS 异常计分。
- **原生 JSON 规则**：便于从其它 WAF 规则库生成或转换。
- **热更新**：不可变快照原子替换；`FileSource`/`HTTPSource`/`FuncSource`；ETag/304、
  HMAC-SHA256 验签、指数退避+抖动重试、last-known-good 单文件缓存、失败重载保留旧引擎。
- **双入口**：`WAF.Middleware()`（ydx/router）与 `WAF.HTTPMiddleware(next)`（net/http）。
- **高性能**：规则编译期预编译；必需字面量/字节集/最小长度预过滤；`@pm` 使用
  Aho-Corasick；变换链事务缓存；变量集合按需构建；正文有界读取并零拷贝回放；快照引用计数；
  无反射热路径。
- **并行求值**：连续独立规则并发纯求值，命中动作与匹配仍按源码顺序提交；默认自动并行
  （最多 4 个工作协程），并发请求升高时自动退回串行以保吞吐；`ParallelWorkers: 1` 可关闭。
- **高稳定**：钩子/插件 panic 隔离；WASM trap/超时/内存上限；插件熔断；请求/响应正文上限；
  优雅排空；报警异步限流。
- **模块化钩子**：阶段前后、规则命中、中断前后、重载、插件错误、请求完成。
- **插件系统**：原生 Go 插件 + WASI/纯 Wasm 插件（wazero，纯 Go，无 cgo）。
- **单机/多机**：单实例多路由共享；多实例轮询同一规则源或推送 `ApplyBundle`；报警携带
  `NodeID`。
- **内置报警**：邮件、Webhook、JSON-lines 文件；聚合、去重、冷却、全局小时/日上限、最小间隔、
  有界队列、Sink 熔断，避免邮件/短信炸弹。

## 快速开始

### ydx/router

```go
engine, err := waf.New(waf.Options{
    RuleFiles: []string{"rules/*.conf"},
    Directives: []string{
        `SecRuleEngine On`,
        `SecAction "id:900000,phase:1,pass,nolog,setvar:tx.anomaly_score=0"`,
        `SecRule ARGS "@detectSQLi" "id:942100,phase:2,pass,nolog,setvar:tx.anomaly_score=+5"`,
        `SecRule TX:anomaly_score "@ge 5" "id:949110,phase:2,deny,status:403,msg:'SQL injection'"`,
    },
})
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

r := router.New()
r.Use(engine.Middleware())
```

### net/http

```go
handler := engine.HTTPMiddleware(mux)
server := &http.Server{Addr: ":8080", Handler: handler}
```

### 优雅关闭

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
_ = engine.Shutdown(ctx)
```

## 规则兼容

| 类别 | 支持 |
|---|---|
| 指令 | `SecRule` `SecAction` `SecMarker` `SecDefaultAction` `SecRuleUpdateActionById` `SecRuleUpdateTargetById/ByTag/ByMsg` `SecRuleRemoveById/ByTag/ByMsg` `SecRuleRemoveTargetById` `Include` `IncludeOptional` |
| 配置 | `SecRuleEngine` `SecRequestBodyAccess` `SecResponseBodyAccess` 正文/响应上限与超限动作、MIME 列表、`SecArgumentsLimit` `SecArgumentSeparator` `SecCollectionTimeout` `SecAuditEngine` 等（不影响检测的配置项解析后忽略） |
| 变量 | `ARGS*` `REQUEST_HEADERS*` `REQUEST_COOKIES*` `FILES*` `REQUEST_URI*` `REQUEST_LINE` `REQUEST_FILENAME` `REQUEST_BASENAME` `QUERY_STRING` `REQUEST_METHOD/PROTOCOL` `REQUEST_BODY*` `RESPONSE_*` `REMOTE_ADDR/PORT` `SERVER_*` `TX` `MATCHED_*` `RULE` `ENGINE` `DURATION` `TIME*` `JSON` `XML` 等 |
| 算子 | `@rx` `@pm` `@pmFromFile` `@contains` `@containsWord` `@beginsWith` `@endsWith` `@eq` `@ne` `@gt` `@ge` `@lt` `@le` `@strmatch` `@within` `@ipMatch` `@ipMatchF` `@ipMatchFromFile` `@validateByteRange` `@validateUrlEncoding` `@validateUtf8Encoding` `@detectSQLi` `@detectXSS` `@unconditionalMatch` `@noMatch` |
| 变换 | `none` `lowercase` `uppercase` `urlDecode` `urlDecodeUni` `htmlEntityDecode` `jsDecode` `cssDecode` `escapeSeqDecode` `base64Decode` `base64DecodeExt` `base64Encode` `hexDecode` `hexEncode` `normalizePath` `normalizePathWin` `cmdLine` `removeNulls` `replaceNulls` `removeComments` `replaceComments` `compressWhitespace` `removeWhitespace` `trim/trimLeft/trimRight` `length` `md5` `sha1` `sha256` `crc32` `utf8toUnicode` `urlEncode` `sqlHexDecode` |
| 动作 | `id` `phase` `rev` `ver` `msg` `logdata` `tag` `severity` `maturity` `accuracy` `status` `log/nolog` `auditlog/noauditlog` `capture` `multiMatch` `chain` `skip` `skipAfter` `pass` `allow` `deny` `drop` `block` `redirect` `setvar` `expirevar` `ctl` `t` |
| ctl | `ruleRemoveById` `ruleRemoveTargetById` `ruleEngine` `requestBodyProcessor` `forceRequestBodyVariable` `requestBodyAccess` `responseBodyAccess` `requestBodyLimit` `bodyLimitAction` `auditEngine` |

**不支持**（严格模式报错，`Lenient: true` 时记录警告并跳过）：`SecRuleScript`、`@geoLookup`、
`@inspectFile`、`@fuzzyHash`、`exec`/`proxy`/`pause`、远程规则指令。

**CRS 语义**：`block` 动作按 ModSecurity 语义执行 `SecDefaultAction` 选定的破坏性动作；CRS 默认
`pass`，因此攻击规则只计分，由 `949110`（`deny`）在异常分达到阈值时统一拦截。`@validateByteRange`、
`@validateUrlEncoding`、`@validateUtf8Encoding` 在校验失败时命中。`SecRuleUpdateTarget*`
按 ModSecurity 语义追加/排除目标，不替换原列表。

```go
// OWASP CRS 目录通常以 Include 组织，直接指向入口文件即可：
engine, _ := waf.New(waf.Options{RuleFiles: []string{"crs/crs-setup.conf", "crs/rules/*.conf"}})
```

本地已验证 OWASP CRS v4.29.0：严格模式加载 703 条规则、0 条跳过；良性请求放行，SQLi、XSS、
路径穿越请求分别由 941100/942100/930100 计分并由 `949110` 以 403 拦截。CRS 规则文件不随本仓
分发，需由使用方自行获取。

## 原生 JSON 规则

```json
{
  "version": "v1",
  "mode": "on",
  "rules": [{
    "id": 1,
    "phase": 1,
    "variables": "REQUEST_URI",
    "operator": "@contains",
    "pattern": "/etc/passwd",
    "actions": {"deny": true, "status": 403, "msg": "path traversal",
                "transformations": ["urlDecodeUni", "lowercase"]}
  }]
}
```

`Bundle.Format = waf.FormatJSON` 即可通过 `Source`/`ApplyBundle` 加载。

## 热更新与多机分发

```go
engine, err := waf.New(waf.Options{
    Source: &waf.HTTPSource{
        URL:          "https://rules.example.com/waf/bundle",
        SignatureKey: signingKey, // 可选 HMAC-SHA256
    },
    WatchInterval: 30 * time.Second,
    LastKnownGood: "/var/lib/ydx-waf/rules.cache",
    Retry: waf.RetryPolicy{
        MaxAttempts:    5,
        InitialBackoff: 250 * time.Millisecond,
        MaxBackoff:     30 * time.Second,
        Multiplier:     2,
        Jitter:         0.2,
    },
})
```

行为保证：

1. 新规则包先完整编译；编译失败不替换旧引擎。
2. 来源失败时按退避重试；仍失败则使用 last-known-good（单文件原子替换）。
3. 轮询发现 digest 未变化时不重建引擎。
4. 推送场景调用 `engine.ApplyBundle(bundle)`；旧快照在最后一个在途请求结束后释放。

多机部署建议：所有实例使用同一 `HTTPSource` URL 与验签密钥；规则服务器返回 `ETag`、
`X-YDX-WAF-Version`、`X-YDX-WAF-Digest`，可选 `X-YDX-WAF-Signature`。`ApplyBundle` 亦可由
配置中心、Redis/NATS 消费者等自行接入。

## 告警

```go
Alerting: waf.AlertConfig{
    Enabled:     true,
    MinSeverity: "WARNING",
    Threshold:   5,                 // 窗口内至少 5 次才报警
    CriticalThreshold: 1,           // CRITICAL 及以上立即报警
    Window:      time.Minute,
    Cooldown:    10 * time.Minute,  // 同规则+客户端+路径冷却
    MinInterval: 30 * time.Second,  // 任意两次报警最小间隔
    MaxPerHour:  10,
    MaxPerDay:   50,
    NodeID:      "edge-01",
    Email: &waf.EmailConfig{
        Host: "smtp.example.com", Port: 587, // 587 默认 STARTTLS；465 设 ImplicitTLS
        Username: "waf", Password: os.Getenv("WAF_SMTP_PASSWORD"),
        From: "waf@example.com", To: []string{"security@example.com"},
    },
    Sinks: []waf.AlertSink{
        waf.NewFileSink("/var/log/ydx-waf/alerts.jsonl"),
        mustWebhook("https://siem.example.com/hooks/waf", signingKey),
    },
}
```

防轰炸设计：

- 按 `rule_id + client_ip + path` 聚合，达到阈值才发送；
- 发送后同键冷却；全局最小间隔 + 每小时/每日上限；
- 有界异步队列，队列满丢弃并计数，绝不阻塞请求；
- 每个 Sink 独立重试与熔断（连续失败 5 次禁用 5 分钟）；
- 过滤器 panic、Sink 失败、SMTP 失败均被隔离，只影响报警不影响检测。

指标：`Stats.AlertsSent/AlertsSuppressed/AlertsDropped/AlertsFailed`。

## 钩子

```go
engine.AddHook(waf.HookFunc{
    HookName:     "risk-score",
    HookPriority: 10,
    Points:       []waf.HookPoint{waf.HookRuleMatch},
    Fn: func(ctx *waf.HookContext) error {
        if ctx.Match != nil && ctx.Match.RuleID == 942100 {
            ctx.SetVar("tx.risk", "high")
        }
        return nil
    },
})
```

钩子可调用 `ctx.Deny(status, msg)` / `ctx.Drop(status, msg)` 中断请求；panic 与错误会被隔离并
计入 `Stats.Errors`。

## 插件

原生插件：

```go
type myPlugin struct{}
func (myPlugin) Name() string { return "my-plugin" }
func (myPlugin) Init(*waf.PluginContext) error { return nil }
func (myPlugin) OnHook(ctx *waf.HookContext) error { return nil }
func (myPlugin) Close() error { return nil }
```

WASM 插件：

```go
WASMPlugins: []waf.WASMPluginConfig{{
    Name:         "scoring",
    Path:         "plugins/scoring.wasm",
    Timeout:      20 * time.Millisecond,
    MaxMemoryPages: 256,   // 16 MiB
    MaxInstances: 16,
    FailClosed:   false,   // true 时插件失败返回 503
    Config:       []byte(`{"strict":true}`),
    Points:       []waf.HookPoint{waf.HookRuleMatch, waf.HookBeforeInterrupt},
}},
```

完整 ABI 见 [WASM.md](WASM.md)。

## 性能与稳定性

### 热路径优化

- 规则在装配期完成解析、算子编译、链展开与阶段分桶；请求期只读快照。
- `@rx` 在正则引擎前叠加四层保守预过滤：字面量前缀、必需字面量集合（多值时用 4-gram
  布隆过滤）、必需 ASCII 字节集、最小匹配长度。预过滤只可能误放行，绝不会拒绝真实命中。
- 多段或昂贵变换链在事务内缓存结果；纯并行求值阶段改用无共享缓存，避免数据竞争。
- 标量变量属性与 TX 键在编译期确定，热路径不再查 `scalarVariables` 映射或重复大小写转换。
- 变量集合惰性构建并按事务缓存；无正文规则不读正文；无响应规则不包装 writer。
- 请求行按事务缓存；`RequestURI` 头/字段存在时直接复用，缺少时才回退到 `URL.RequestURI()`；
  参数总大小在查询串或正文读取/解析改变参数集合前缓存，避免逐规则重复遍历 ARGS。仅依赖
  `ARGS_COMBINED_SIZE`、`ARGS_NAMES`、多部件或文件合计大小的规则也会正确触发正文读取。
- `@pm` 使用 Aho-Corasick 一次扫描；`@ipMatch` 使用 `net/netip`。
- 独立规则并发纯求值，命中动作按源码顺序提交；只有参数/头等值足够多时才启动工作协程，
  自动模式在并发请求升高时退回串行，避免请求级并行与规则级并行互相抢占。
- `regexpx v0.1.11` 新增 AST 必需字节/字面量、最小长度预过滤与惰性 ASCII 搜索 DFA；WAF
  已升级到该版本，可直接获得大型宽首字节规则的数十倍加速。WAF 捕获路径后续可改用
  `regexpx` 调用方缓冲区 API，消除子匹配切片分配。

并行度可以显式控制：

```go
// 0 = 自动（最多 4 个工作协程，高并发时退回串行）
// 1 = 关闭规则级并行
// >1 = 固定工作协程数
engine, err := waf.New(waf.Options{
    RuleFiles:       []string{"rules/*.conf"},
    ParallelWorkers: 4,
})
```

规则级并行只对连续、无共享状态依赖的规则生效；带 `ctl`、`skip`、`allow`、链或读取动态
`TX`/`MATCHED_*` 的规则仍是串行屏障。命中事件与 `setvar` 按源码顺序提交，因此并行不会改变
拦截语义。

### 本地基准

环境：Intel i9-10980HK（8 核 / 16 线程）、Windows 11、Go 1.27.3、OWASP CRS 4.29.0、
`ParallelWorkers` 默认自动模式。

| 场景 | 延迟 | 内存 | 分配 |
|---|---:|---:|---:|
| CRS 善意单请求 | 约 124–141 µs | 约 2.5 KB | 111 allocs |
| CRS 善意并发请求 | 约 21–23 µs/op（约 43–47k req/s） | 约 2.5 KB | 111 allocs |
| CRS 善意 + 50 个唯一参数（单请求） | 约 670 µs | 约 58 KB | 2945 allocs |
| 小型 10 规则放行 | 约 1.3 µs | 56 B | 4 allocs |

对比优化前（同一 CRS、同一机器）：单请求约 243 µs / 16.4 KB / 316 allocs，50 参数约
4.8 ms；并发善意请求约 46 µs/op。历史 v1 Coraza 封装同条件约 716 µs / 139 KB / 2872
allocs。绝对值受 CPU 频率和后台负载影响，跨机器比较请以相对值为准。

WAF 当前依赖 `regexpx v0.1.11`。启用惰性 ASCII 搜索 DFA、请求行缓存、`RequestURI` 复用
与参数总大小缓存后：CRS 善意单请求约 124–141 µs / 2.5 KB / 111 allocs，并发约
21–23 µs/op；50 个唯一参数约 670 µs / 58 KB / 2945 allocs（对比 `v0.1.10` 基线约
0.97–1.02 ms / 64 KB / 3000 allocs）。首次请求需构建 DFA，比不使用 DFA 时多约
1.1–1.4 ms、冷内存约 300 KB；之后进入稳态。对延迟敏感的部署可在就绪探针通过前发送一条
覆盖主要规则的良性请求预热，或接受首个真实请求的一次性构建成本。

升级 `regexpx` 时不要添加本地 `replace`；开发期联调使用仓库外的临时 `go.work`，发布前运行
`GOWORK=off go test ./... -race`。

- 请求/响应正文有上限；请求正文在检测后零拷贝回放给处理器。
- 快照引用计数 + 原子指针替换；失败重载保留旧引擎；后台 watcher 有明确退出路径。
- 报警与插件均有有界队列/超时/熔断，异常不会拖垮请求路径。
- 基准模块需在 `waf` 发布标签后加入 `benchmarks/waf`（当前阶段不允许本地 `replace`）。

## 测试

```bash
cd waf
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race
cd ../repotest && GOWORK=off go test ./...
```

## 已知边界

- `@geoLookup`、`@inspectFile`、`@fuzzyHash`、Lua `SecRuleScript`、`exec/proxy/pause`
  未内置；可通过 Sink/钩子/自定义扩展接入。
- XML 集合为尽力解析，支持 `XML:/*` 与 `XML://@*` 通配；复杂命名空间与混合内容不保证与
  Coraza 完全一致。
- `MULTIPART_PART_HEADERS` 按部件头名称/值尽力提供；`initcol`/`setsid`/`setuid`/`setrsc`/`setenv`
  被接受但不持久化 IP/SESSION/USER 集合。
- 响应经 `Flush`/`Hijack` 后只能检测已缓冲前缀；流式剩余部分不再检测。
- 规则正则基于 `ydx/regexpx`；PCRE 专有构造若无法编译会在严格模式下拒绝该规则。
