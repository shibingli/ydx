# middleware/accesslog — 访问日志

`github.com/shibingli/ydx/middleware/accesslog` 为每个请求记录一条结构化日志：方法、路径、
查询串、状态码、响应字节数、客户端地址、耗时与请求 ID。它使用 `middleware/reqlog` 的池化
捕获包装响应写入器，升级请求从不包装，保证 WebSocket 握手仍有可用的 `http.Hijacker`。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/accesslog` |
| 包名 | `accesslog` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `AccessLog(logger, opts...)`：YD 路由中间件。
- `Middleware(logger, opts...)`：原生 `net/http` 包装器，共享同一实现。
- `AccessLogOptions`：`reqlog.Options` 的别名，同步/异步插件接受同一配置。
- 记录字段：`request_id`、`method`、`path`、`query`、`status`、`bytes`、`remote_ip`、
  `duration`（JSON 中为毫秒）。

## 特性

- **池化捕获**：响应写入器捕获对象来自池，避免每请求分配捕获结构。
- **升级请求直通**：`IsUpgradeRequest` 为真时不包装，保留 `http.Hijacker`。
- **可信代理模型**：`remote_ip` 取自 `router.Ctx.ClientIP`，只有 `TrustedProxies` 声明
  对端是代理时才读取 `X-Forwarded-For`，伪造头无法决定日志地址。
- **panic 不吞掉**：记录完成后重新抛出 panic，由外层 `Recovery` 负责最终响应。
- **状态码兜底**：未显式写状态时按 200 记录；panic 逃逸时按 500 记录。
- **nil 日志器直通**：`logger == nil` 时中间件退化为直通，便于测试或按环境关闭。

## 快速开始

### YD 路由

```go
r.Use(
	requestid.RequestID(""),
	accesslog.AccessLog(logger),
)
```

### 原生 net/http

```go
handler := accesslog.Middleware(logger)(mux)
```

自定义可信代理：

```go
prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
r.Use(accesslog.AccessLog(logger, accesslog.AccessLogOptions{
	TrustedProxies: prefixes,
}))
```

## 应用场景

- **审计日志**：记录每个请求的状态、字节数与来源。
- **可观测性**：接入日志平台后按 `request_id` 关联全链路。
- **慢请求分析**：按 `duration` 聚合 P95/P99。
- **安全排查**：在可信代理模型下记录真实客户端地址。
- **按环境开关**：测试环境传 nil 日志器即可关闭。

## 性能指标

基准模块：[`benchmarks/middleware`](../../benchmarks/middleware/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | 耗时 | 说明 |
|---|---:|---|
| 无中间件基线（YD 路由） | 319.4 ns | 含路由、Ctx 池、记录器 |
| 访问日志同步（丢弃写入器） | 821.5 ns | 完整字段与日志编码 |
| 访问日志同步（100 µs 慢写入器） | 1.054 ms | 请求路径承担写入延迟 |
| 访问日志异步（同一慢写入器） | 487.2 ns | 请求路径只交接 |
| 异步提交 | 258.8 ns | 队列/克隆/溢出处理 |
| 完整基准 `AccessLogSync` | 699.50 ns，1.013 KiB，10 allocs | 与上表口径不同 |

- 同步访问日志相对于路由基线增加约 500 ns（丢弃写入器），主要用于字段采集与日志编码。
- 慢目的地场景异步把请求路径从 1.054 ms 降到 487.2 ns；目的地为 `io.Discard` 时异步
  反而比同步多约 0.77 µs（1.592 µs vs 821.5 ns），这是队列与交接的固定成本。

> 完整表格与口径见基准 README；同一轮内小于约 5% 的差异视为噪声。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`middleware/reqlog`](../reqlog/README.md)：池化响应捕获与头处理。
- [`middleware/requestid`](../requestid/README.md)：请求 ID。
- [`log`](../../log/README.md)：结构化日志。
- [`router`](../../router/README.md)：YD 路由与 `ClientIP`。
- `errs`、`json`：错误与序列化支持。

## 相关模块

- [`middleware/asyncafter`](../asyncafter/README.md)：响应后异步管线。
- [`middleware/requestid`](../requestid/README.md)：请求 ID。
- [`middleware/recovery`](../recovery/README.md)：panic 恢复。
- [`middleware/reqlog`](../reqlog/README.md)：共享捕获设施。
- [`log`](../../log/README.md)：日志器。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
