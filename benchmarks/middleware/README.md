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

## 关键结果

| 场景 | none | ydx | 对比实现 |
|---|---:|---:|---:|
| CORS GET | 5.904 ns | 374.5 ns | rs/cors 102.7 ns |
| Request ID | 5.846 ns | 372.4 ns | chi 515.5 ns |
| 恢复（无 panic） | 5.940 ns | 39.43 ns | chi 11.63 ns |
| 限流放行 | 5.980 ns | 249.0 ns | x/time/rate 48.49 ns |
| 16 KiB gzip | 67.69 ns | 9.151 µs | gzhttp 9.060 µs |

- CORS：rs/cors 102.7 ns 明显快于 ydx 374.5 ns；ydx 支持通配/子域匹配、
  credentials 规则与预检短路，rs/cors 的默认路径更精简。
- 请求 ID：ydx 372.4 ns 快于 chi 515.5 ns（chi 用例包含把上下文 ID 写回响应头的
  适配器；chi 原生只写请求上下文）。
- 恢复：chi Recoverer 的常态路径 11.63 ns，快于 ydx 39.43 ns；两者都是 0 分配。
- 限流：x/time/rate 48.49 ns 快于 ydx 249.0 ns；ydx 额外写三个 `X-RateLimit-*`
  响应头，并支持共享 MemoryStore/Redis Store 与 `FailClosed` 策略。
- 压缩：两者在 16 KiB gzip 上几乎持平（9.151 µs vs 9.060 µs，差约 1%）；ydx 还支持
  brotli 与 zstd（见完整数据中的 `CompressMiddleware`）。

**YD 路由路径与访问日志（内部对照）**

| 场景 | 耗时 | 说明 |
|---|---:|---|
| 无中间件基线 | 805.3 ns | 含路由、Ctx 池、记录器 |
| Recover | 874.6 ns | 常态路径 |
| AccessLog 同步 | 1.397 µs | 丢弃写入器 |
| RateLimit | 1.218 µs | 放行路径 |
| 压缩协商 map 解析 | 623.5 ns | 旧路径 |
| 压缩协商无分配扫描 | 284.8 ns | 当前路径 |
| 16 KiB gzip（串行） | 21.00 µs | 完整中间件 |
| 16 KiB zstd（串行） | 15.93 µs | 完整中间件 |
| 16 KiB brotli（串行） | 34.52 µs | 完整中间件 |
| AccessLog 同步（100 µs 慢写入器） | 556.4 µs | 请求路径承担写入延迟 |
| AccessLog 异步（同一慢写入器） | 1.370 µs | 请求路径只交接 |
| AccessLog 异步提交 | 513.2 ns | 队列/克隆/溢出处理 |

异步访问日志在慢目的地场景把请求路径从 556.4 µs 降到 1.370 µs；当目的地是
`io.Discard` 时，异步反而比同步多约 1.4 µs（2.827 µs vs 1.404 µs），这是队列与
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
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/middleware**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `AccessLogSync` | 1.404 µs | 1.010 KiB | 10 |  |
| `AccessLogAsync` | 2.827 µs | 1.036 KiB | 13 |  |
| `AccessLogSyncSlowHandler` | 556.4 µs | 1.008 KiB | 10 |  |
| `AccessLogAsyncSlowHandler` | 1.370 µs | 1.035 KiB | 13 |  |
| `AccessLogAsyncSubmit` | 513.2 ns | 80 | 5 |  |
| `AccessLogAsyncThroughput/workers1_queue16` | 149.0 ns | 80 | 5 |  |
| `AccessLogAsyncThroughput/workers4_queue256` | 165.3 ns | 80 | 5 |  |
| `AccessLogAsyncThroughput/workersN_queue4096` | 119.1 ns | 80 | 5 |  |
| `BaselineNoMiddleware` | 805.3 ns | 1.009 KiB | 10 |  |
| `BaselineLargeBodyNoMiddleware` | 18.37 µs | 32.96 KiB | 10 |  |
| `Recover` | 874.6 ns | 1.009 KiB | 10 |  |
| `AccessLog` | 1.397 µs | 1.011 KiB | 10 |  |
| `RateLimit` | 1.218 µs | 1.118 KiB | 12 |  |
| `CompressNegotiate/map_parse` | 623.5 ns | 384 | 6 |  |
| `CompressNegotiate/scan_negotiate` | 284.8 ns | 0 | 0 |  |
| `Compress/skip_small_html` | 1.102 µs | 1.011 KiB | 10 |  |
| `Compress/skip_already_encoded_json` | 31.03 µs | 33.02 KiB | 11 |  |
| `Compress/html_16k_brotli` | 34.52 µs | 20.08 KiB | 12 | 452.7 MiB/s |
| `Compress/html_16k_zstd` | 15.93 µs | 22.44 KiB | 12 | 981.1 MiB/s |
| `Compress/html_16k_gzip` | 21.00 µs | 21.04 KiB | 12 | 743.9 MiB/s |
| `Compress/json_16k_gzip` | 20.80 µs | 21.24 KiB | 12 | 751.3 MiB/s |
| `CORSCompare/none` | 5.904 ns | 0 | 0 |  |
| `CORSCompare/ydx` | 374.5 ns | 160 | 2 |  |
| `CORSCompare/rs-cors` | 102.7 ns | 16 | 1 |  |
| `RequestIDCompare/none` | 5.846 ns | 0 | 0 |  |
| `RequestIDCompare/ydx` | 372.4 ns | 80 | 3 |  |
| `RequestIDCompare/chi` | 515.5 ns | 456 | 7 |  |
| `RecoverCompare/none` | 5.940 ns | 0 | 0 |  |
| `RecoverCompare/ydx` | 39.43 ns | 0 | 0 |  |
| `RecoverCompare/chi` | 11.63 ns | 0 | 0 |  |
| `RateLimitCompare/none` | 5.980 ns | 0 | 0 |  |
| `RateLimitCompare/ydx` | 249.0 ns | 64 | 2 |  |
| `RateLimitCompare/x-time-rate` | 48.49 ns | 0 | 0 |  |
| `CompressCompare/none` | 67.69 ns | 16 | 1 | 225.4 GiB/s |
| `CompressCompare/ydx-gzip` | 9.151 µs | 81 | 3 | 1.667 GiB/s |
| `CompressCompare/gzhttp` | 9.060 µs | 96 | 4 | 1.684 GiB/s |
| `CompressMiddleware/gzip` | 975.0 ns | 85 | 3 | 6.686 GiB/s |
| `CompressMiddleware/brotli` | 4.021 µs | 126 | 3 | 1.621 GiB/s |
| `CompressMiddleware/zstd` | 991.0 ns | 102 | 3 | 6.579 GiB/s |
| `CompressMiddleware/passthrough` | 38.56 ns | 0 | 0 |  |
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
