# benchmarks/middleware — 中间件与主流实现对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/middleware` 及插件同时提供 YD 路由中间件与原生 `net/http` 适配器。本基准在
**普通 `http.Handler`** 上对比 CORS、请求 ID、panic 恢复、限流与压缩，并保留
YD 路由路径上的访问日志同步/异步、压缩协商与压缩编码用例。

## 对比对象

| 能力 | ydx | 对比实现 | 版本 |
|---|---|---|---|
| CORS | `middleware/cors` | `github.com/rs/cors` | v1.11.1 |
| 请求 ID | `middleware/requestid` | `chi/middleware.RequestID` | chi v5.5.0 |
| panic 恢复 | `middleware/recovery` | `chi/middleware.Recoverer` | chi v5.5.0 |
| 限流 | `middleware/ratelimit` | `golang.org/x/time/rate` | v0.16.0 |
| gzip 压缩 | `middleware/compress` | `klauspost/compress/gzhttp` | v1.20.3 |

## 场景

- `CORSCompare`：带 `Origin: https://example.com` 的 GET，终端写小响应。
- `RequestIDCompare`：GET，检查响应头 `X-Request-Id`。
- `RecoverCompare`：无 panic 的常态路径。
- `RateLimitCompare`：放行路径；ydx 用极大 Rate/Burst 保证不限流。
- `CompressCompare`：16 KiB `text/html`，`Accept-Encoding: gzip`；计时前校验
  确实输出 `Content-Encoding: gzip`。
- 既有 YD 路由基准：`BaselineNoMiddleware`、`Recover`、`AccessLog`、`RateLimit`、
  `CompressNegotiate`、`Compress`、`AccessLogSync/Async*`。

## 关键结果（2026-10-24，Zen 5 + Go 1.27.3）

| 场景 | none | ydx | 对比实现 |
|---|---:|---:|---:|
| CORS GET | 4.30 ns | **36.69 ns** | rs/cors 53.16 ns |
| Request ID | 4.14 ns | **170.2 ns** | chi 275.0 ns |
| 恢复（无 panic） | 4.87 ns | **7.85 ns** | chi 8.62 ns |
| 限流放行（默认按 IP + 3 头） | 4.66 ns | **136.5 ns** | x/time/rate 59.92 ns（全局、不写头）；+headers 127.8 ns；按 IP + headers 139.0 ns |
| 16 KiB gzip | 35.65 ns | 5.268 µs | gzhttp 5.213 µs |

- CORS：预计算策略 + 无分配来源拆分 + 直接写响应头，36.69 ns，领先 rs/cors 约 31%。
- 请求 ID：170.2 ns，领先 chi 适配路径约 38%；chi 原生只写请求上下文，基准适配器把 ID
  写回响应头后两者才可观测一致。
- 恢复：7.85 ns 对 chi 8.62 ns，领先约 9%；原生入口不经过路由适配器。
- 限流：136.5 ns。单全局 limiter 且不写 `X-RateLimit-*` 的 x/time/rate 为 59.92 ns；
  补上同样三个头后为 127.8 ns；再按 IP 分桶（与 ydx 默认一致）后为 139.0 ns，ydx 领先
  1.8%，在噪声内记为持平。该变体使用固定的头值，而 ydx 每请求实时计算剩余令牌与重置时间，
  并保留可替换的 `LimitStore` 抽象，两者能力并不等价。
- 压缩：5.268 µs 对 5.213 µs，差异约 1%，同一轮内视为持平；ydx 额外支持 brotli/zstd。

**YD 路由路径与访问日志（内部对照）**

| 场景 | 耗时 | 说明 |
|---|---:|---|
| 无中间件基线 | 319.4 ns | 含路由、Ctx 池、记录器 |
| Recover | 432.4 ns | 常态路径 |
| AccessLog 同步 | 821.5 ns | 丢弃写入器 |
| RateLimit | 539.8 ns | 放行路径 |
| 压缩协商 map 解析 | 246.6 ns | 旧路径 |
| 压缩协商无分配扫描 | 114.4 ns | 当前路径 |
| 16 KiB gzip（串行） | 8.960 µs | 完整中间件 |
| 16 KiB zstd（串行） | 7.628 µs | 完整中间件 |
| 16 KiB brotli（串行） | 14.074 µs | 完整中间件 |
| AccessLog 同步（100 µs 慢写入器） | 1.054 ms | 请求路径承担写入延迟 |
| AccessLog 异步（同一慢写入器） | 487.2 ns | 请求路径只交接 |
| AccessLog 异步提交 | 258.8 ns | 队列/克隆/溢出处理 |

异步访问日志在慢目的地场景把请求路径从 1.054 ms 降到 487.2 ns；当目的地是
`io.Discard` 时，异步反而比同步多约 0.77 µs（1.592 µs vs 821.5 ns），这是队列与
交接的固定成本。

压缩比（输入字节 / 输出字节，越大越好）：

| 编码 | 压缩比 |
|---|---:|
| gzip | 136.5 |
| zstd | 277.7 |
| brotli | 364.1 |
| JSON + gzip | 109.2 |

异步过载指标（`OverflowDropNew`，故意不施加背压）：

| 场景 | drops | drop_ratio | handled/s |
|---|---:|---:|---:|
| `AccessLogAsyncSlowHandler` | 497.3k | — | — |
| `workers1_queue16` | 3.928M | 99.97% | 1,923 |
| `workers4_queue256` | 4.087M | 99.87% | 7,780 |
| `workersN_queue4096` | 5.225M | 99.59% | 34,270 |

这些 drop 数字是“生产者远快于 10 µs 处理器”时的预期结果，不是中间件缺陷；它的意义
是证明过载时请求路径仍返回而不阻塞。需要不丢日志时应增大队列/worker 或改用带背压的
策略。`drops`/`handled` 是整轮基准的累计值，会随 `-benchtime`、CPU 与机器变化；
横向比较时优先看 `drop_ratio` 与 `handled/s`。

## 完整数据

<details>
<summary>5 轮中位数（Zen 5 + Go 1.27.3，2026-10-24）</summary>

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `AccessLogSync` | 699.50 ns | 1.013 KiB | 10 |  |
| `AccessLogAsync` | 1.592 µs |  |  |  |
| `AccessLogSyncSlowHandler` | 1.054 ms | 1.008 KiB | 10 |  |
| `AccessLogAsyncSlowHandler` | 487.20 ns |  |  |  |
| `AccessLogAsyncSubmit` | 258.80 ns |  |  |  |
| `AccessLogAsyncThroughput/workers1_queue16` | 49.79 ns |  |  |  |
| `AccessLogAsyncThroughput/workers4_queue256` | 53.47 ns |  |  |  |
| `AccessLogAsyncThroughput/workersN_queue4096` | 96.42 ns |  |  |  |
| `BaselineNoMiddleware` | 319.40 ns | 1.011 KiB | 10 |  |
| `BaselineLargeBodyNoMiddleware` | 6.280 µs | 33.008 KiB | 10 |  |
| `Recover` | 432.40 ns | 1.011 KiB | 10 |  |
| `AccessLog` | 821.50 ns | 1.016 KiB | 10 |  |
| `RateLimit` | 539.80 ns | 1.120 KiB | 12 |  |
| `CompressNegotiate/map_parse` | 246.60 ns | 384 | 6 |  |
| `CompressNegotiate/scan_negotiate` | 114.40 ns | 0 | 0 |  |
| `Compress/skip_small_html` | 596.70 ns | 1.016 KiB | 10 |  |
| `Compress/skip_already_encoded_json` | 6.851 µs | 33.117 KiB | 11 |  |
| `Compress/html_16k_brotli` | 14.074 µs |  |  | 1164.13 |
| `Compress/html_16k_zstd` | 7.628 µs |  |  | 2147.97 |
| `Compress/html_16k_gzip` | 8.960 µs |  |  | 1869.23 |
| `Compress/json_16k_gzip` | 8.201 µs |  |  | 1874.88 |
| `CORSCompare/none` | 4.30 ns | 0 | 0 |  |
| `CORSCompare/ydx` | 36.69 ns | 16 | 1 |  |
| `CORSCompare/rs-cors` | 53.16 ns | 16 | 1 |  |
| `RequestIDCompare/none` | 4.14 ns | 0 | 0 |  |
| `RequestIDCompare/ydx` | 170.20 ns | 80 | 3 |  |
| `RequestIDCompare/chi` | 275.00 ns | 473 | 7 |  |
| `RecoverCompare/none` | 4.87 ns | 0 | 0 |  |
| `RecoverCompare/ydx` | 7.85 ns | 0 | 0 |  |
| `RecoverCompare/chi` | 8.62 ns | 0 | 0 |  |
| `RateLimitCompare/none` | 4.66 ns | 0 | 0 |  |
| `RateLimitCompare/ydx` | 136.50 ns | 64 | 2 |  |
| `RateLimitCompare/x-time-rate` | 59.92 ns | 0 | 0 |  |
| `RateLimitCompare/x-time-rate+headers` | 127.80 ns | 64 | 2 |  |
| `RateLimitCompare/x-time-rate+per-ip+headers` | 139.00 ns | 64 | 2 |  |
| `CompressCompare/none` | 35.65 ns | 16 | 1 | 441924.68 |
| `CompressCompare/ydx-gzip` | 5.268 µs | 58 | 3 | 3108.20 |
| `CompressCompare/gzhttp` | 5.213 µs | 73 | 4 | 3158.83 |
| `CompressMiddleware/gzip` | 192.60 ns | 62 | 3 | 36164.22 |
| `CompressMiddleware/brotli` | 642.10 ns | 74 | 3 | 10939.47 |
| `CompressMiddleware/zstd` | 170.40 ns | 70 | 3 | 40405.84 |
| `CompressMiddleware/passthrough` | 8.85 ns | 0 | 0 |  |
</details>

## 复现

```bash
cd benchmarks/middleware
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- `*Compare` 用例包装普通 `http.Handler`，使用同一个终端处理器、同一请求与复用
  丢弃写入器；`BaselineNoMiddleware` 等既有用例走 YD 路由并每轮新建记录器，两者
  不可直接混比。
- CORS 用例只测简单 GET，不测预检/凭证/多来源；rs/cors 与 ydx 的策略能力不同。
- chi 的 `RequestID` 原生不写响应头；基准适配器把上下文 ID 写回响应头，使两个用例
  产生相同可观测结果。
- 限流对比不是等价实现：ydx 支持分布式 Store 与标准限流响应头，x/time/rate 是
  单进程令牌桶；249.0 ns 与 48.49 ns 的差异包含这些能力。
- 压缩对比只覆盖 gzip；ydx 的 brotli/zstd 在 `CompressMiddleware` 中单独报告。
  `CompressMiddleware` 使用 `RunParallel`，其 ns/op 是并发均摊值；`CompressCompare`
  是串行值。`CompressCompare/none` 的 MB/s 只是丢弃写入器的有效载荷吞吐，不是压缩
  吞吐，不应与 gzip 行比较。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
