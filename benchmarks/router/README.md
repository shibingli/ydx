# benchmarks/router — 路由分发对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/router` 是基数树路由器，同时提供原生 `http.Handler` 适配（`Adapt`）。本基准在
同一张路由表上比较静态、命名参数、通配与未命中四类请求的分发成本，并单独测量原生
适配器与下载辅助函数的开销。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/router | v0.1.5 | 基数树 + `Ctx` 对象池 |
| `net/http.ServeMux` | Go 1.27.2 | Go 1.22+ 方法/参数模式 |
| `github.com/julienschmidt/httprouter` | v1.3.0 | 经典基数树路由 |
| `github.com/go-chi/chi/v5` | v5.5.0 | 轻量组合式路由 |
| `github.com/gin-gonic/gin` | v1.12.0 | `gin.New()`，不挂默认中间件 |

## 场景

每个实现注册相同的三条路由：

- `GET /api/v1/users`（静态）
- `GET /api/v1/users/:id/profile`（参数；stdlib 为 `{id}`，chi 为 `{id}`）
- `GET /files/*filepath`（通配；stdlib 为 `{path...}`，chi 为 `*`）

请求分别为静态、参数、通配与未命中；处理器为空或只读取路径参数，响应写入器丢弃
响应。请求在计时前构造一次，路由表只注册一次。

## 关键结果

| 场景 | ydx | stdlib | httprouter | chi | gin |
|---|---:|---:|---:|---:|---:|
| 静态 | 27.29 ns | 323.5 ns | 53.14 ns | 366.0 ns | 49.54 ns |
| 参数 | 30.52 ns | 274.8 ns | 65.91 ns | 394.6 ns | 74.53 ns |
| 通配 | 33.26 ns | 573.7 ns | 60.21 ns | 505.4 ns | 73.41 ns |
| 未命中 | 47.60 ns | 763.4 ns | 393.1 ns | 532.2 ns | 68.12 ns |

- ydx 在四类请求上都最快；静态/参数/通配约为 gin 的 41%–55%、httprouter 的
  46%–55%，未命中路径优势更大。
- gin 的静态与未命中路径很快（49.54 ns / 68.12 ns），参数与通配略慢于 ydx。
- stdlib `ServeMux` 与 chi 的微基准包含更完整的模式匹配/中间件上下文路径，绝对数字
  高于专用路由；这不代表它们在真实服务中的端到端表现。
- ydx 路由基准为 0 B/op、0 allocs/op；chi 的静态路径为 2 allocs/op、368 B/op。

**适配器与下载路径（仅 ydx）**

| 场景 | 耗时 | 分配 |
|---|---:|---:|
| 直连 `http.Handler` | 2.843 ns | 0 |
| `Adapt` 0 个中间件 | 31.95 ns | 0 |
| `Adapt` 1 个中间件 | 36.18 ns | 0 |
| `Adapt` 2 个中间件 | 39.66 ns | 0 |
| `DownloadBytes` 4 KiB | 618.7 ns | 101 B / 5 allocs |
| `DownloadReader` 4 KiB | 442.4 ns | 52 B / 4 allocs |

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/router**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `Adapt/direct` | 2.843 ns | 0 | 0 |  |
| `Adapt/adapt-0` | 31.95 ns | 0 | 0 |  |
| `Adapt/adapt-1` | 36.18 ns | 0 | 0 |  |
| `Adapt/adapt-2` | 39.66 ns | 0 | 0 |  |
| `RouterStatic` | 35.31 ns | 0 | 0 |  |
| `RouterParam` | 52.04 ns | 0 | 0 |  |
| `RouterMixedSegment` | 66.80 ns | 0 | 0 |  |
| `RouterWildcard` | 35.00 ns | 0 | 0 |  |
| `RouterMiss` | 54.08 ns | 0 | 0 |  |
| `DownloadBytes` | 618.7 ns | 101 | 5 | 6.165 GiB/s |
| `DownloadReader` | 442.4 ns | 52 | 4 | 8.623 GiB/s |
| `RouterCompare/static/ydx` | 27.29 ns | 0 | 0 |  |
| `RouterCompare/static/stdlib` | 323.5 ns | 0 | 0 |  |
| `RouterCompare/static/httprouter` | 53.14 ns | 0 | 0 |  |
| `RouterCompare/static/chi` | 366.0 ns | 368 | 2 |  |
| `RouterCompare/static/gin` | 49.54 ns | 0 | 0 |  |
| `RouterCompare/param/ydx` | 30.52 ns | 0 | 0 |  |
| `RouterCompare/param/stdlib` | 274.8 ns | 16 | 1 |  |
| `RouterCompare/param/httprouter` | 65.91 ns | 32 | 1 |  |
| `RouterCompare/param/chi` | 394.6 ns | 368 | 2 |  |
| `RouterCompare/param/gin` | 74.53 ns | 0 | 0 |  |
| `RouterCompare/wildcard/ydx` | 33.26 ns | 0 | 0 |  |
| `RouterCompare/wildcard/stdlib` | 573.7 ns | 88 | 5 |  |
| `RouterCompare/wildcard/httprouter` | 60.21 ns | 32 | 1 |  |
| `RouterCompare/wildcard/chi` | 505.4 ns | 704 | 4 |  |
| `RouterCompare/wildcard/gin` | 73.41 ns | 0 | 0 |  |
| `RouterCompare/miss/ydx` | 47.60 ns | 0 | 0 |  |
| `RouterCompare/miss/stdlib` | 763.4 ns | 160 | 10 |  |
| `RouterCompare/miss/httprouter` | 393.1 ns | 48 | 3 |  |
| `RouterCompare/miss/chi` | 532.2 ns | 416 | 5 |  |
| `RouterCompare/miss/gin` | 68.12 ns | 0 | 0 |  |
</details>

## 复现

```bash
cd benchmarks/router
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 这是**分发微基准**：处理器为空，不包含业务逻辑、序列化、日志或真实网络 I/O。
- 各实现的路由表都注册了三条路由；请求路径相同，但参数语法不同（`:id`、`{id}`、
  `*filepath`、`*`），这是各库的惯用写法。
- gin 的 `gin.New()` 不带 Logger/Recovery，但仍有自己的 `Context` 获取/归还与响应
  写入器包装；chi 的 `Mux` 也有自己的上下文。它们的基础开销计入结果。
- 未命中基准只测“找不到路由”的分发；各库的 404 响应体/Content-Type 处理可能不同。
- 既有 `RouterStatic` 等基准使用不同的请求/记录器构造，数字与 `RouterCompare` 略有
  差异；跨库比较请使用 `RouterCompare` 表。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
