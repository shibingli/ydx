# benchmarks/router — 路由分发对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/router` 是基数树路由器，同时提供原生 `http.Handler` 适配（`Adapt`）。本基准在
同一张路由表上比较静态、命名参数、通配与未命中四类请求的分发成本，并单独测量原生
适配器与下载辅助函数的开销。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/router | 本仓源码（工作区） | 基数树 + `Ctx` 对象池；静态路由走 `GETRaw` 无上下文快路径 |
| `net/http.ServeMux` | Go 1.27.3 | Go 1.22+ 方法/参数模式 |
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
| 静态 | **8.395 ns** | 60.15 ns | 12.86 ns | 114.9 ns | 33.17 ns |
| 参数 | **18.89 ns** | 104.7 ns | 29.02 ns | 165.9 ns | 41.83 ns |
| 通配 | **18.94 ns** | 165.4 ns | 28.06 ns | 223.0 ns | 25.62 ns |
| 未命中 | **25.75 ns** | 283.5 ns | 158.3 ns | 199.2 ns | 28.07 ns |

- ydx 在四类请求上都最快；静态为 httprouter 的 65%、gin 的 25%，参数为 httprouter
  的 65%、gin 的 45%，通配为 gin 的 74%、httprouter 的 67%；未命中领先 gin 约 8%、
  领先 httprouter 约 84%。
- 静态用例按文档把完全静态路由注册为 `GETRaw`（无 `Ctx`、无参数提取），参数与通配
  仍走常规 `Ctx` 路径；其它实现没有等价的“无上下文”注册形态，因此静态行是 ydx 的
  最佳形态对手方的最佳形态。
- stdlib `ServeMux` 与 chi 的微基准包含更完整的模式匹配/中间件上下文路径，绝对数字
  高于专用路由；这不代表它们在真实服务中的端到端表现（chi 的静态路径另有 368 B/op、
  2 allocs/op）。
- ydx 四类路由均为 0 B/op、0 allocs/op；httprouter 的参数/通配路径各有 32 B/op、
  1 alloc/op。
- `RouterStatic` 等既有用例（17.01 ns）每轮新建记录器并经过完整 `Ctx` 流程，与
  `RouterCompare` 的请求复用口径不同，不能直接与上表比较。

**适配器与下载路径（仅 ydx）**

| 场景 | 耗时 | 分配 |
|---|---:|---:|
| 直连 `http.Handler` | 1.566 ns | 0 |
| `Adapt` 0 个中间件 | 18.42 ns | 0 |
| `Adapt` 1 个中间件 | 21.80 ns | 0 |
| `Adapt` 2 个中间件 | 24.24 ns | 0 |
| `DownloadBytes` 4 KiB | 275.3 ns | 102 B / 5 allocs |
| `DownloadReader` 4 KiB | 200.7 ns | 53 B / 4 allocs |

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/router**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `Adapt/direct` | 1.566 ns | 0 | 0 |  |
| `Adapt/adapt-0` | 18.42 ns | 0 | 0 |  |
| `Adapt/adapt-1` | 21.80 ns | 0 | 0 |  |
| `Adapt/adapt-2` | 24.24 ns | 0 | 0 |  |
| `RouterStatic` | 17.01 ns | 0 | 0 |  |
| `RouterParam` | 16.81 ns | 0 | 0 |  |
| `RouterMixedSegment` | 17.13 ns | 0 | 0 |  |
| `RouterWildcard` | 17.14 ns | 0 | 0 |  |
| `RouterMiss` | 24.98 ns | 0 | 0 |  |
| `DownloadBytes` | 275.3 ns | 102 | 5 | 14.59 GiB/s |
| `DownloadReader` | 200.7 ns | 53 | 4 | 19.90 GiB/s |
| `RouterCompare/static/ydx` | 8.395 ns | 0 | 0 |  |
| `RouterCompare/static/stdlib` | 60.15 ns | 0 | 0 |  |
| `RouterCompare/static/httprouter` | 12.86 ns | 0 | 0 |  |
| `RouterCompare/static/chi` | 114.9 ns | 368 | 2 |  |
| `RouterCompare/static/gin` | 33.17 ns | 0 | 0 |  |
| `RouterCompare/param/ydx` | 18.89 ns | 0 | 0 |  |
| `RouterCompare/param/stdlib` | 104.7 ns | 16 | 1 |  |
| `RouterCompare/param/httprouter` | 29.02 ns | 32 | 1 |  |
| `RouterCompare/param/chi` | 165.9 ns | 368 | 2 |  |
| `RouterCompare/param/gin` | 41.83 ns | 0 | 0 |  |
| `RouterCompare/wildcard/ydx` | 18.94 ns | 0 | 0 |  |
| `RouterCompare/wildcard/stdlib` | 165.4 ns | 88 | 5 |  |
| `RouterCompare/wildcard/httprouter` | 28.06 ns | 32 | 1 |  |
| `RouterCompare/wildcard/chi` | 223.0 ns | 705 | 4 |  |
| `RouterCompare/wildcard/gin` | 25.62 ns | 0 | 0 |  |
| `RouterCompare/miss/ydx` | 25.75 ns | 0 | 0 |  |
| `RouterCompare/miss/stdlib` | 283.5 ns | 160 | 10 |  |
| `RouterCompare/miss/httprouter` | 158.3 ns | 48 | 3 |  |
| `RouterCompare/miss/chi` | 199.2 ns | 417 | 5 |  |
| `RouterCompare/miss/gin` | 28.07 ns | 0 | 0 |  |
| `Routers/static/yd` | 1.119 ns | 0 | 0 |  |
| `Routers/static/stdlib` | 24.99 ns | 0 | 0 |  |
| `Routers/static/gin` | 2.016 ns | 0 | 0 |  |
| `Routers/static/chi` | 81.28 ns | 368 | 2 |  |
| `Routers/static/echo` | 1.760 ns | 0 | 0 |  |
| `Routers/static/httprouter` | 0.955 ns | 0 | 0 |  |
| `Routers/static/fiber` | 3.881 ns | 0 | 0 |  |
| `Routers/param/yd` | 1.114 ns | 0 | 0 |  |
| `Routers/param/stdlib` | 37.07 ns | 16 | 1 |  |
| `Routers/param/gin` | 1.885 ns | 0 | 0 |  |
| `Routers/param/chi` | 155.6 ns | 704 | 4 |  |
| `Routers/param/echo` | 2.009 ns | 0 | 0 |  |
| `Routers/param/httprouter` | 8.576 ns | 32 | 1 |  |
| `Routers/param/fiber` | 4.348 ns | 0 | 0 |  |
| `Routers/deep/yd` | 1.197 ns | 0 | 0 |  |
| `Routers/deep/stdlib` | 38.23 ns | 16 | 1 |  |
| `Routers/deep/gin` | 2.051 ns | 0 | 0 |  |
| `Routers/deep/chi` | 161.2 ns | 704 | 4 |  |
| `Routers/deep/echo` | 2.024 ns | 0 | 0 |  |
| `Routers/deep/httprouter` | 8.655 ns | 32 | 1 |  |
| `Routers/deep/fiber` | 5.333 ns | 0 | 0 |  |
| `Routers/wildcard/yd` | 1.184 ns | 0 | 0 |  |
| `Routers/wildcard/stdlib` | 63.88 ns | 88 | 5 |  |
| `Routers/wildcard/gin` | 2.082 ns | 0 | 0 |  |
| `Routers/wildcard/chi` | 164.6 ns | 704 | 4 |  |
| `Routers/wildcard/echo` | 1.736 ns | 0 | 0 |  |
| `Routers/wildcard/httprouter` | 8.789 ns | 32 | 1 |  |
| `Routers/wildcard/fiber` | 4.351 ns | 0 | 0 |  |
| `Routers/miss/yd` | 1.639 ns | 0 | 0 |  |
| `Routers/miss/stdlib` | 132.5 ns | 192 | 12 |  |
| `Routers/miss/gin` | 2.134 ns | 0 | 0 |  |
| `Routers/miss/chi` | 116.2 ns | 417 | 5 |  |
| `Routers/miss/echo` | 150.6 ns | 458 | 8 |  |
| `Routers/miss/httprouter` | 25.40 ns | 48 | 3 |  |
| `Routers/miss/fiber` | 5.122 ns | 0 | 0 |  |
| `UpgradeRouter/raw-http` | 5.531 µs | 33.13 KiB | 9 |  |
| `UpgradeRouter/router` | 5.727 µs | 33.18 KiB | 9 |  |

`Routers/*` 只测路由查找本身（不构造请求、不写响应），因此低于 `RouterCompare`；
它用于横向看各库查找内核的相对位置，httprouter 在该口径下为 0.955–25.40 ns。
`UpgradeRouter/*` 是真实 HTTP 往返升级基准（含 TCP 读写），不参与分发比较。
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
