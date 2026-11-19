# ydx/client 基准

对比 `net/http`、`ydx/client`、`go-resty/resty/v2`、`imroc/req/v3` 与 `valyala/fasthttp`。

## 场景

直通与编排：

- `BenchmarkGET_Small`：小型 JSON GET，顺序执行。
- `BenchmarkGET_Parallel`：并发 GET。
- `BenchmarkPOST_JSON`：小型 JSON POST。
- `BenchmarkGET_1MiB`：1 MiB 响应体，按 MB/s 报告。
- `BenchmarkGET_ShortConn`：`Connection: close` 短连接。
- `BenchmarkGET_TLS`：TLS keep-alive GET。
- `BenchmarkPipeline_Parallel10`：ydx/client Pipeline 10 路并发。

扩展路径：

- `BenchmarkSSEEventReader`：512 事件 SSE 流解析。
- `BenchmarkSSEForward`：`Handler` 转发 32 事件 SSE 响应。
- `BenchmarkMultipartUpload/{1MiB,8MiB}`：multipart 上传；用于观察缓冲/流式阈值与内存占用。
- `BenchmarkGuardCheckCached`：同一主机重复 `AccessPolicy.Check`，覆盖 DNS TTL 缓存。
- `BenchmarkCoalesceParallel`：不同键的并行请求经过合并 flight group。

## 运行

```bash
cd benchmarks/client

# 直通与编排（短连接除外）
GOWORK=off go test -bench 'Benchmark(GET_Small|GET_Parallel|POST_JSON|GET_1MiB|GET_TLS|Pipeline_Parallel10)' \
  -benchmem -benchtime=300ms -count=5 -timeout 20m

# 扩展路径
GOWORK=off go test -bench 'Benchmark(SSE|Multipart|Guard|Coalesce)' \
  -benchmem -benchtime=300ms -count=5 -timeout 20m

# 短连接单独运行，并等待 TIME_WAIT 清理
GOWORK=off go test -bench '^BenchmarkGET_ShortConn/ydx$' \
  -benchmem -benchtime=100ms -count=1 -timeout 10m
```

结果使用 benchstat 比较，至少 `-count=5`。Windows 上并发 `fasthttp` 子基准可能耗尽临时端口，可单独运行或排除该子基准。

## 环境

- OS：Windows 11 Pro for Workstations 10.0.28000
- CPU：Intel Core i9-10980HK
- Go：1.27.4 windows/amd64
- 客户端库版本见 `go.mod`（当前 `client v0.1.11`）

## 结果（client v0.1.11）

`-benchtime=500ms`、聚焦 ydx 场景 `-count=10`、其他客户端同轮高样本；`benchstat` 95% 置信区间。Windows 笔记本计时噪声较大，分配次数稳定，版本对比以分配与回归趋势为主要依据。

| 场景 | native | ydx/client | resty | req | fasthttp |
|---|---:|---:|---:|---:|---:|
| GET Small (ns/op) | 160.2µ | **147.3µ** | 164.1µ | 178.0µ | 124.7µ |
| GET Parallel (ns/op) | 18.91µ | **19.78µ** | 20.93µ | —¹ | —¹ |
| POST JSON (ns/op) | 159.6µ | **148.3µ** | 152.4µ | 159.6µ | 107.5µ |
| GET TLS (ns/op) | 141.4µ | **144.0µ** | 154.4µ | 156.1µ | 114.6µ |
| GET 1 MiB (MB/s) | 1306 | **1114** | 544 | 511 | 546 |
| GET ShortConn (ns/op) | —² | **521.9µ** | —² | —² | —² |
| Pipeline Parallel10 (ns/op) | — | **522.1µ** | — | — | — |

¹ 并行 `req`/`fasthttp` 在 Windows 上触发临时端口耗尽，未纳入同行对比。
² 短连接仅做 ydx 版本间对比，避免多客户端同时耗尽端口。

| 场景 | native | ydx/client | resty | req | fasthttp |
|---|---:|---:|---:|---:|---:|
| GET Small allocs/op | 69 | **70** | 86 | 115 | 21 |
| GET Parallel allocs/op | 67 | **68** | 84 | — | — |
| POST JSON allocs/op | 85 | **89** | 105 | 138 | 25 |
| GET TLS allocs/op | 64 | **69** | 85 | 107 | 16 |
| GET 1 MiB allocs/op | 67 | **68** | 127 | 150 | 26 |

**结论**：直通小 GET/POST 在 net/http 兼容客户端中最快；TLS 基本与 native 持平并优于 resty/req；1 MiB 吞吐约为 resty/req/fasthttp 的 2 倍，`B/op` 比它们低约 2 MiB。fasthttp 仍是纯 HTTP/1.1 小请求最快，但 API 不兼容 `net/http`。

### 扩展路径

| 场景 | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| SSE EventReader（512 事件） | 100.6µ | 41.26Ki | 1033 | 188 |
| SSE Forward（32 事件） | 172.4µ | 10.96Ki | 107 | — |
| Guard Check（DNS 缓存命中） | 1.127µ | 278 | 8 | — |
| Coalesce Parallel | 28.5µ | 7.37Ki | 81 | — |
| Multipart Upload / 1MiB | 3.86ms | 11.1Ki | 148 | 272 |
| Multipart Upload / 8MiB | 28.8ms | 24.5Ki | 379 | 291 |

说明：

- `BenchmarkGuardCheckCached` 预热后命中 30s DNS TTL 缓存；首次解析仍执行真实 DNS 查询。
- v0.1.11 的 multipart 全量走流式路径，`1MiB/op` 仅约 11 KiB 分配；工作区的下一版将加入“≤1 MiB 缓冲、更大流式”的阈值混合，发布后需同步更新本模块依赖并复测。
- 扩展场景可在同一台机器上做版本间对比；跨机器比较请使用 `benchstat`，并优先看分配次数与 `B/op`。

### 版本趋势（历史）

| 场景 | 审计前 v0.1.8 | v0.1.10 | v0.1.11 |
|---|---:|---:|---:|
| GET Small | 148.0µ / 70 allocs | 151.2µ / 70 allocs | **150.0µ / 70 allocs** |
| POST JSON | 145.7µ / 89 allocs | 144.6µ / 89 allocs | **146.2µ / 89 allocs** |
| GET TLS | 150.4µ / 69 allocs | 151.1µ / 69 allocs | **146.2µ / 69 allocs** |
| Pipeline Parallel10 | 492.4µ / 957 allocs | 514.5µ / 957 allocs | **522.1µ / 953 allocs** |
| GET 1 MiB | ~1191.9µ / 68 allocs | 919.6µ / 68 allocs | **840.3µ / 68 allocs** |
| GET ShortConn | 534.1µ / 151 allocs | 520.8µ / 149 allocs | **521.9µ / 150 allocs** |

直通热路径无分配回退，时间差异在 Windows 噪声范围内。关键优化：SSE 行解析缓冲复用、无 tee SSE 内联转发、coalesce 分片与键构造、Guard DNS 缓存、单 Host 快路径、Header/Response 复用、未配置 UA 时跳过 clone、显式 ContentLength 等。

“功能全开”（规则 + 缓存 + 合并 + 镜像）没有跨库可比对象，其正确性由 `client` 包测试覆盖；本表只测直通热路径，避免把不同语义的实现放在一起比较。基准中的 ydx 客户端使用 `WithoutCookieJar()`，避免默认 Cookie Jar 的额外语义影响直通对比；并显式 `WithRewriteAll(true)`，让绝对 URL 仍走 Host 池，以覆盖 Host 选择快路径。

发布级性能数据建议在空闲 Linux 机器上复测；Windows 笔记本的计时噪声较大，分配数据更稳定。