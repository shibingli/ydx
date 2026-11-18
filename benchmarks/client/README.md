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

单次代表性运行（`-benchtime=300ms -count=1`；Windows 笔记本噪声较大，正式对比请用
`-count=5` + `benchstat`）：

| 场景 | native | ydx/client | resty | req | fasthttp |
|---|---:|---:|---:|---:|---:|
| GET Small (ns/op) | 144819 | 155196 | 166091 | 218902 | 137052 |
| GET Parallel (ns/op) | 22851 | 24669 | 24534 | 64927 | 16327 |
| POST JSON (ns/op) | 156193 | 160064 | 170272 | 170166 | 112578 |
| GET 1 MiB (MB/s) | 1161 | 1127 | 497 | 501 | 639 |
| GET ShortConn (ns/op) | 540897 | 582091 | 591306 | 613730 | 633464 |
| GET TLS (ns/op) | 157474 | 165762 | 171326 | 172836 | 115534 |
| Pipeline Parallel10 (ns/op) | — | 459678 | — | — | — |

| 场景 | native | ydx/client | resty | req | fasthttp |
|---|---:|---:|---:|---:|---:|
| GET Small allocs/op | 69 | 75 | 86 | 115 | 21 |
| POST JSON allocs/op | 85 | 93 | 105 | 138 | 25 |

结论（本机单次运行）：

- 直通 GET 比 native 慢约 7%，并发 GET 约 8%；均优于或持平 resty，明显优于 req。
- POST JSON 与 native 基本持平（约 2.5%），优于 resty/req。
- 1 MiB 响应与 native 基本持平，且比 resty/req/fasthttp 少约 2 MiB/op 的分配。
- TLS 约慢 5%，短连接约慢 8%，仍优于 resty/req。
- fasthttp 在纯 HTTP/1.1 小请求上仍最快，但其 API 不兼容 `net/http`；本库以兼容性换取了
  接近 native 的性能。
- 关键优化：共享默认重试状态码切片、单 Host 直通快路径、去掉未配置 UA 时的整请求
  clone、显式设置 ContentLength 避免 chunked、Header/Response 缓冲区复用。