# middleware/recovery — panic 恢复

`github.com/shibingli/ydx/middleware/recovery` 捕获下游处理器 panic，记录 panic 值与
goroutine 调用栈，终止链上剩余处理器，并写出一个不含内部细节的 500 响应。若响应头已经
写出，则跳过 500，保证已经开始输出的响应不被破坏。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/recovery` |
| 包名 | `recovery` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `Recover(logger)`：YD 路由中间件。
- `Middleware(logger)`：原生 `net/http` 包装器。
- 记录字段：`request_id`、`method`、`path`、`panic`、`stack`。

## 特性

- **不泄露内部细节**：响应只写 `500 Internal Server Error` 文本，不包含 panic 值或栈。
- **中止剩余链**：`c.Abort()` 后不再执行后续处理器。
- **已写响应保护**：YD 入口通过 `Ctx.Written()` 检查；已开始输出的响应不会追加 500。
- **请求 ID 关联**：YD 入口记录 `requestid.FromContext(c)`，便于与访问日志关联。
- **原生入口更轻**：原生形态是值处理器，不经过路由上下文池、reset 与链遍历；没有 panic
  的常态路径成本更低。
- **nil 日志器安全**：不记录日志但仍完成恢复与响应。
- **与访问日志协作**：`accesslog` 记录后重新抛出 panic，由本中间件负责最终响应。

## 快速开始

### YD 路由

```go
r.Use(
	requestid.RequestID(""),
	recovery.Recover(logger),
)
```

### 原生 net/http

```go
handler := recovery.Middleware(logger)(mux)
```

## 应用场景

- **生产兜底**：任何处理器 panic 都不应终止进程或泄露栈。
- **中间件链最外层**：通常放在 `RequestID` 之后、业务中间件之前。
- **原生服务**：不使用 YD 路由时用 `Middleware` 获得同等保护。
- **与审计配合**：panic 事件进入日志平台并关联请求 ID。

## 性能指标

基准模块：[`benchmarks/middleware`](../../benchmarks/middleware/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | ydx/recovery | chi Recoverer | 无中间件 |
|---|---:|---:|---:|
| 无 panic 常态路径 | **7.85 ns** | 8.62 ns | 4.87 ns |
| YD 路由 Recover（含路由/Ctx） | 432.4 ns | — | 319.4 ns 基线 |

- 领先 chi 约 9%；常态路径 0 B/op、0 allocs/op。
- YD 路由路径的 432.4 ns 包含路由、Ctx 池与记录器，不能与原生微基准直接混比。
- 原生入口不经过路由适配器，是成本最低的恢复形态。

> 完整表格与口径见基准 README。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`log`](../../log/README.md)：panic 与栈记录。
- [`middleware/requestid`](../requestid/README.md)：请求 ID。
- [`router`](../../router/README.md)：YD 路由与 `Ctx.Written`。
- `json`：字段序列化支持。

基准对比对象 chi `Recoverer`，仅出现在 `benchmarks/middleware`。

## 相关模块

- [`middleware/accesslog`](../accesslog/README.md)：记录后重抛 panic。
- [`middleware`](../README.md)：聚合门面。
- [`log`](../../log/README.md)：结构化日志。
- [`errs`](../../errs/README.md)：错误哨兵。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
