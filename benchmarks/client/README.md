# ydx/client 基准

对比 `net/http`、`ydx/client`、`go-resty/resty/v2`、`imroc/req/v3` 与 `valyala/fasthttp`。

## 场景

- `BenchmarkGET_Small`：小型 JSON GET，顺序执行。
- `BenchmarkGET_Parallel`：并发 GET。
- `BenchmarkPOST_JSON`：小型 JSON POST。
- `BenchmarkGET_1MiB`：1 MiB 响应体，按 MB/s 报告。
- `BenchmarkGET_ShortConn`：`Connection: close` 短连接。
- `BenchmarkGET_TLS`：TLS keep-alive GET。
- `BenchmarkPipeline_Parallel10`：ydx/client Pipeline 10 路并发。

## 运行

```bash
cd benchmarks/client
GOWORK=off go test -bench . -benchmem -count=5 -timeout 20m
```

结果使用 benchstat 比较，至少 `-count=5`。

## 环境

- OS：Windows 11 Pro for Workstations 10.0.28000
- Go：1.27.4 windows/amd64
- 客户端库版本见 `go.mod`。

## 结果

`-benchtime=300ms -count=6` + benchstat；1 MiB、短连接与 Pipeline 为补充单次运行
（Windows 笔记本噪声较大，短连接单独运行）：

| 场景 | native | ydx/client | resty | req | fasthttp |
|---|---:|---:|---:|---:|---:|
| GET Small (ns/op) | 138.6µ | 135.2µ | 140.6µ | 151.6µ | 100.7µ |
| GET Parallel (ns/op) | 22.88µ | 21.92µ | 22.09µ | 66.58µ | 14.77µ |
| POST JSON (ns/op) | 136.1µ | 140.1µ | 149.9µ | 157.5µ | 103.0µ |
| GET TLS (ns/op) | 136.1µ | 141.9µ | 152.3µ | 149.3µ | 103.6µ |
| GET 1 MiB (MB/s) | 1161 | 1127 | 497 | 501 | 639 |
| GET ShortConn (ns/op) | 540897 | 582091 | 591306 | 613730 | 633464 |
| Pipeline Parallel10 (ns/op) | — | 459678 | — | — | — |

| 场景 | native | ydx/client | resty | req | fasthttp |
|---|---:|---:|---:|---:|---:|
| GET Small allocs/op | 69 | 74 | 86 | 115 | 21 |
| GET Parallel allocs/op | 67 | 72 | 84 | 130 | 20 |
| POST JSON allocs/op | 85 | 92 | 105 | 138 | 25 |
| GET TLS allocs/op | 64 | 73 | 85 | 107 | 16 |

`count=6` + benchstat（± 为 95% 置信区间）。直通与并发 GET 已与 native 持平或更快；
POST 约慢 3%，TLS 约慢 4%；分配比 native 多 5–7 次/请求，仍显著少于 resty/req。

优化前后（同一套基准，非同一进程；用于说明趋势）：

| 场景 | 优化前 | 优化后 |
|---|---:|---:|
| GET Small | 232µs / 90 allocs | 135µs / 74 allocs |
| POST JSON | 250µs / 119 allocs | 140µs / 92 allocs |

“功能全开”（规则 + 缓存 + 合并 + 镜像）没有跨库可比对象，其正确性由 `client` 包测试覆盖；
本表只测直通热路径，避免把不同语义的实现放在一起比较。基准中的 ydx 客户端使用
`WithoutCookieJar()`，避免默认 Cookie Jar 的额外语义影响直通对比。

结论：

- 直通 GET 与并发 GET 已持平或略优于 native；均优于 resty/req。
- POST JSON 约慢 3%，TLS 约慢 4%，短连接约慢 8%。
- 1 MiB 响应与 native 基本持平，且比 resty/req/fasthttp 少约 2 MiB/op 的分配。
- fasthttp 在纯 HTTP/1.1 小请求上仍最快，但其 API 不兼容 `net/http`；本库以兼容性换取了
  接近 native 的性能。
- 关键优化：共享默认重试状态码切片、单 Host 直通快路径、单 Host 健康 `Pick` 快路径、
  未配置 UA 时不 clone、显式 ContentLength 避免 chunked、Header/Response 缓冲区复用、
  `OnAttempt` 未配置时跳过 `safeURL`、`transportFor` 无 Host TLS 时快速返回。

注意：Windows 短连接基准会耗尽临时端口，`BenchmarkGET_ShortConn` 建议单独运行
`-benchtime=100ms -count=1`，并等待 TIME_WAIT 清理；全量 `-count=5/6` 不应包含该场景。