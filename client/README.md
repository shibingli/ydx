# ydx/client

基于 `net/http` 的策略化 HTTP 客户端、SSE/反向代理转发引擎与请求编排模块。

## 能力

| 能力 | 说明 |
|---|---|
| HTTP 方法 | GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT + 自定义方法；CONNECT 的 2xx Body 即隧道流 |
| 路径规则 | `:id`、`{id}`、`:id(regex)`、`{id:regex}`、段内 `*.jpg`、末段 `*path`、多参数；`Expand` 反向生成 URL |
| Host 池 | 加权/最少在途/随机/一致性哈希/顺序；被动健康、冷却/半开、可选主动检查、fail-open、换 Host 重试；`MaxInflight` 满时等待（`HostSetOptions.Wait`） |
| 请求体 | `[]byte`/string/JSON/XML/Form/Multipart/文件/Reader；Multipart 已知 ≤1 MiB 缓冲、更大流式；重试/镜像时按上限 spool（可选落盘，`SpoolMaxBytes` 总量上限）；GET/直通路径零额外 clone |
| 缓存 | 可选内置分片 LRU+TTL，支持 `Cache-Control`、`Age`/`Date`、`Expires`、`Vary`、自定义 `Store`/Key |
| 重定向/Cookie | 默认内存 Cookie Jar，301/302/303/307/308 自动带入 Set-Cookie；`CheckRedirect`/`Jar` 保持标准语义；`WithoutCookieJar` 可关闭；Host base path 的 Location 自动还原到逻辑路径 |
| 请求合并 | 相同并发 GET/HEAD 合并（singleflight）；超大/不可共享响应自动 bypass |
| 镜像 | A：影子上游重放（默认，可同步/异步/抽样/并行；不可重放 body 自动有界 spool，含磁盘）；B：主流 tee 到 Sink/EventSink，慢消费者丢弃 |
| SSE | EventReader、出站 Stream（重定向/CheckRedirect/重连/Last-Event-ID/空闲超时）、Forward/Handler 逐块 Flush、A/B 镜像 |
| 安全 | Guard 链、AccessPolicy 黑白名单/IDNA/CIDR/私网拦截、拨号期 IP 固定与代理失败关闭、内置 WAF 适配模块 |
| TLS | 系统根/私有 CA、mTLS、SPKI 固定、会话复用、按 Host 覆盖、`ReloadTLS` 热更新 |
| UA | Fixed/Random/Rotate/Weighted，内置桌面/移动 UA，Force 语义，companion headers |
| 编排 | Pipeline：Serial/Parallel/Step/Func/Vars，JSON/Header/Status/Regexp/Func 提取，FailFast 取消 |
| 元数据 | `Meta.Timings`（`WithTrace`）、`Meta.Mirrors`（同步快照）、`Meta.MirrorResults.Snapshot()`（异步）、Hops、Attempts、BytesSent/Read；规则级 `Rule.UA` |
| 观测 | Hooks、原子 Stats、HostStats、请求/重试/响应元数据、ydx/log 结构化日志 |
| 连接 | Long/Short、h2c（HTTPS 不受影响）、连接预热、连接池参数、响应排空复用、`CloseIdleConnections` |
| 绝对 URL | 默认直连；`WithRewriteAll(true)` 强制走默认 Host 池；规则 Hosts 始终优先；Forward 绝对形式目标默认拒绝，需 `WithForwardAllowAbsoluteURLs(true)` |

## 设计边界

- 核心不 import `ydx/waf`、`ydx/cache`（Redis/gorm）或 `ydx/sse`（router）；WAF 与 SSE
  扇出适配分别在可选模块 `client/waf`、`client/sse`。
- `net/http` 对外发 body 没有内核零拷贝；“零拷贝”指正文只读一次、fan-out 共享只读字节、
  不重复序列化、池化缓冲与流式透传。
- v1 不做任意 DAG、WebSocket/Upgrade 转发、完整 RFC 9111 缓存或分布式缓存。

## 最小用法

```go
c, err := client.New(
    client.WithHosts("https://api-a.example.com", "https://api-b.example.com"),
    client.WithRule(client.Rule{
        Name:    "user",
        Pattern: "/api/user/{id}",
        Cache:   &client.CachePolicy{TTL: 30 * time.Second},
    }),
)
if err != nil { /* ... */ }
defer c.Close()

resp, err := c.Get(ctx, "/api/user/42")
```

反向代理：

```go
r.HandleRaw(http.MethodGet, "/gateway", c.Handler().ServeHTTP)
http.Handle("/gateway/", http.StripPrefix("/gateway", c.Handler()))
```

SSE 转发/镜像：

```go
c, _ := client.New(
    client.WithHosts("https://sse.example.com"),
    client.WithRule(client.Rule{
        Name:    "events",
        Pattern: "/events",
        Mirror: &client.MirrorPolicy{
            Targets: []string{"https://shadow.example.com"},
            Percent: 100,
        },
    }),
)
```
