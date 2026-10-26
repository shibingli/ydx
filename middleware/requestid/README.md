# middleware/requestid — 请求 ID

`github.com/shibingli/ydx/middleware/requestid` 为每个请求分配唯一 ID。若请求携带配置的
头（默认 `X-Request-Id`）则沿用其值，否则用 `crypto/rand` 生成新的 UUIDv4。ID 以
`RequestIDKey` 存入路由上下文，并通过同名响应头回显。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/requestid` |
| 包名 | `requestid` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认头 | `X-Request-Id` |
| 上下文键 | `request_id`（`RequestIDKey`） |

## 功能

- `RequestID(header)`：YD 路由中间件。
- `Middleware(header)`：原生 `net/http` 包装器。
- `FromContext(c)`：读取当前请求 ID；中间件未启用时返回空串。
- 响应头回显同名 ID，便于客户端与服务端日志关联。

## 特性

- **沿用上游 ID**：网关或负载均衡器已生成请求 ID 时直接沿用，保持全链路一致。
- **UUIDv4 兜底**：缺少头时用 `crypto/rand` 生成 RFC 4122 v4 UUID。
- **构造期规范化**：头名在装配期做一次 canonical 化，请求路径直接查表，避免每请求重复
  扫描。
- **无额外分配设计**：UUID 直接写入 36 字节数组，避免多次字符串拼接。
- **双入口共享实现**：原生路径用 `router.Adapt` 复用同一中间件，每请求只付一次适配成本。
- **降级随机源**：`crypto/rand` 不可用时用时钟与序列号驱动的 xorshift64 兜底，保证仍能
  生成 ID（安全性要求高的场景应确保随机源可用）。

> 本中间件沿用客户端提供的头值，不校验其格式。若请求 ID 会进入日志/审计且不可信，
> 应在网关或本中间件之前做长度与字符集校验，避免日志注入。

## 快速开始

### YD 路由

```go
r.Use(requestid.RequestID(""))
r.GET("/", func(c *router.Ctx) {
	id := requestid.FromContext(c)
	_ = c.String(http.StatusOK, id)
})
```

### 原生 net/http

```go
handler := requestid.Middleware("")(mux)
```

自定义头：

```go
r.Use(requestid.RequestID("X-Correlation-Id"))
```

## 应用场景

- **分布式追踪**：网关生成 ID，全链路日志关联。
- **访问日志**：`accesslog` 自动记录 `request_id`。
- **错误排查**：用户报错时提供请求 ID 快速定位。
- **审计**：把请求 ID 写入审计事件。
- **panic 关联**：`recovery` 记录同一 ID。

## 性能指标

基准模块：[`benchmarks/middleware`](../../benchmarks/middleware/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | ydx/requestid | chi RequestID | 无中间件 |
|---|---:|---:|---:|
| 带 `X-Request-Id` 响应的 GET | **170.2 ns** | 275.0 ns | 4.14 ns |

- 领先 chi 适配路径约 38%；80 B/op、3 allocs/op（响应头与 UUID 相关）。
- chi 原生只写请求上下文；基准适配器把 ID 写回响应头后两者才可观测一致。
- 原生路径经 `router.Adapt`，与 YD 路径共享同一实现。

> 完整表格与口径见基准 README。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`router`](../../router/README.md)：YD 路由与 `Ctx`。

`go.mod` 中的 `regexpx` 仅用于测试/校验辅助，不进入运行时热路径。

## 相关模块

- [`middleware/accesslog`](../accesslog/README.md)：记录请求 ID。
- [`middleware/asyncafter`](../asyncafter/README.md)：异步记录请求 ID。
- [`middleware/recovery`](../recovery/README.md)：panic 日志关联。
- [`middleware`](../README.md)：聚合门面。
- [`router`](../../router/README.md)：路由上下文。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
