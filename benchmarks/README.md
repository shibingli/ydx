# ydx 基准与主流实现对比

本目录是 ydx 的基准模块集合。每个带 `go.mod` 的子目录都是一个**独立的 Go 模块**，
只依赖 ydx 的最新子目录标签（base64 v0.1.7、json v0.1.8，其余模块 v0.1.4）与对应的
对比库；`cache/local` 是 `cache` 基准模块内的子包。产品模块本身不包含任何 `Benchmark*`，也不依赖基准专用库。

- 实测日期：2026-10-23
- 运行环境：`base64`/`json` 的数字来自 Linux AMD Ryzen AI MAX+ 395（Zen 5，32 逻辑
  CPU，AVX-512 VBMI/VBMI2）与 Linux Neoverse-N2（4 vCPU）两台主机，Go 1.27.2；
  其余模块的数字来自较早一轮 Windows 11 / Intel Core i9-10980HK（16 逻辑 CPU），
  `GOMAXPROCS=16`。各行来源不同，**不要跨行比较绝对值**。
- 采样方式：每项 `-count=3` 或 `-count=5`、`-benchtime=500ms`、`-benchmem`，取中位数
  或均值；同一轮内样本不足以给出 95% 置信区间，因此**同一轮内小于约 5% 的差异视为噪声**。
- 跨轮漂移：CPU 的频率/温度与后台负载会让同一份代码在不同轮次的绝对 ns/op 相差数十个
  百分点。只比较**同一轮表格内**的相对关系；不要把不同模块/不同时间的绝对值直接混比。

## 模块与对比对象

| 基准模块 | 对比的主流实现 | 指标文档 |
|---|---|---|
| `benchmarks/base64` | `encoding/base64`、`cristalhq/base64` | [base64/README.md](base64/README.md) |
| `benchmarks/buffpool` | `sync.Pool`、`valyala/bytebufferpool` | [buffpool/README.md](buffpool/README.md) |
| `benchmarks/cache` | `bigcache`、`freecache`、`ristretto`、`sync.Map`、`go-cache` | [cache/README.md](cache/README.md) |
| `benchmarks/json` | `encoding/json`、`goccy/go-json`、`json-iterator/go`、`bytedance/sonic`、`segmentio/encoding`、`go-json-experiment/json` | [json/README.md](json/README.md) |
| `benchmarks/jwt` | `golang-jwt/jwt/v5`、`lestrrat-go/jwx/v4`、`go-jose/v4` | [jwt/README.md](jwt/README.md) |
| `benchmarks/log` | `zap`、`zerolog`、`slog`、`logrus` | [log/README.md](log/README.md) |
| `benchmarks/middleware` | `rs/cors`、`chi`、`klauspost/compress/gzhttp`、`x/time/rate` | [middleware/README.md](middleware/README.md) |
| `benchmarks/render` | `html/template`、`text/template` | [render/README.md](render/README.md) |
| `benchmarks/router` | `net/http.ServeMux`、`httprouter`、`chi`、`gin` | [router/README.md](router/README.md) |
| `benchmarks/sse` | `gin-contrib/sse`、手写 `fmt.Fprintf` 基线 | [sse/README.md](sse/README.md) |
| `benchmarks/websocket` | `gorilla/websocket`、`coder/websocket` | [websocket/README.md](websocket/README.md) |

## 关键结果速览

下表只摘录每个模块最具代表性的同机实测数字；各行来自各自模块的一轮采样，不是同一
进程/同一轮的同表对比，不宜跨行做严格比例推断。完整表格与口径说明见各模块文档。

| 模块 | 场景 | ydx | 对比实现 |
|---|---|---:|---:|
| base64 | `Encode` 1 KiB | 23.4 ns | stdlib 470 ns / cristalhq 200 ns |
| base64 | `Decode` 1 KiB | 42.1 ns | stdlib 455 ns / cristalhq 274 ns |
| buffpool | 4 KiB `Get`/`Put` | 18.00 ns | `sync.Pool` 12.08 ns / bytebufferpool 20.78 ns |
| cache/local | `Get` 命中 | 83.02 ns | bigcache 125.7 ns / freecache 106.9 ns / ristretto 98.97 ns / `sync.Map` 24.49 ns |
| json | `Marshal` 64 对象 | 2.51 µs | stdlib 12.8 µs / goccy 4.19 µs / sonic 3.00 µs |
| json | `Unmarshal` 64 对象 | 6.43 µs | stdlib 29.7 µs / goccy 6.90 µs / sonic 10.7 µs |
| jwt | HS256 `Parse` | 2.819 µs | golang-jwt 7.676 µs / jwx 11.20 µs / go-jose 13.29 µs |
| log | 5 字段 JSON Info | 394.4 ns | zap 779.7 ns / zerolog 337.9 ns / slog 1.086 µs / logrus 4.867 µs |
| middleware | CORS GET | 374.5 ns | rs/cors 102.7 ns |
| middleware | 16 KiB gzip | 9.151 µs | gzhttp 9.060 µs |
| middleware | 限流放行 | 249.0 ns | `x/time/rate` 48.49 ns |
| render | 带绑定渲染 | 635.3 ns | `html/template` 6.985 µs / `text/template` 4.437 µs |
| router | 静态路由 | 27.29 ns | gin 49.54 ns / httprouter 53.14 ns / `ServeMux` 323.5 ns / chi 366.0 ns |
| sse | 4 KiB `WriteData` | 2.558 µs | gin-contrib 3.387 µs / 手写 108.3 ns |
| websocket | 32 B 回显往返 | 65.85 µs | gorilla 63.61 µs / coder 69.62 µs |
| websocket | 64×1 KiB 批量写 | 305.6 µs | gorilla 1.699 ms / coder 1.780 ms |

> 这些数字只回答“同一台机器、同一轮采样下的相对成本”，不是跨硬件的性能承诺。网络类
> 基准（WebSocket）受回环栈、Windows 定时器与 GC 影响尤其明显。

## 指标口径

- **ns/op**：单次操作的平均墙钟时间；并发基准（`RunParallel`）是对所有 goroutine
  求和后的均摊值，不能与串行基准直接混比。
- **B/op、allocs/op**：每次操作的堆分配字节数与分配次数。B/op 列沿用 `benchstat`
  的 KiB/MiB 单位显示。不同库的返回值语义不同（例如 bigcache/freecache 的 `Get`
  返回副本，`ristretto` 的 `Set` 是异步入队），表格中的分配差异包含这些语义差异。
- **MB/s**：仅当基准调用 `SetBytes` 时出现，表示基准声明的有效载荷吞吐；不是整机
  网络或磁盘吞吐。
- **Brotli/Zstd/Gzip**：压缩基准的 `ns/op` 包含压缩、写入丢弃器与中间件开销；
  `CompressMiddleware` 使用 `RunParallel`，其 ns/op 是并发均摊值。
- **异步日志/中间件**：`drops`、`handled`、`writes/op` 等自定义指标只出现在对应
  用例中，含义见该模块文档。

## 公平性约定

1. 所有实现使用同一份载荷、同一个请求/连接构造方式与同一类丢弃写入器；显式预热与
   预填充都在计时区之外。
2. 每个库使用其惯用配置，并在必要时对齐语义：例如 jsoniter 使用
   `ConfigCompatibleWithStandardLibrary`，zap 使用生产风格 JSON encoder，gin 使用
   `gin.New()`（不挂默认中间件）以单独测量路由分发。
3. 语义不完全等价的地方在各模块“口径与限制”中显式说明，例如：
   - `ristretto.Set` 异步准入，`LocalSetCompare` 不等待写入可见；
   - `go-jose` 只做签名验证，声明校验由基准手工补齐；
   - `chi.RequestID` 只写请求上下文，基准适配器把它写回响应头；
   - gorilla/coder 没有批量写 API，批量用例逐条调用 `WriteMessage`；
   - `gin`/`chi` 的路由基准包含各自的上下文/中间件基础开销。
4. 对比库版本锁定在各模块 `go.mod`；ydx 组件按最新子目录标签解析（base64 v0.1.7、
   json v0.1.8，其余产品模块 v0.1.4）。

## 复现

单个模块：

```bash
cd benchmarks/json
GOWORK=off go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

全量（POSIX）：

```bash
for d in benchmarks/*/; do
  (cd "$d" && GOWORK=off go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms)
done
```

Windows PowerShell：

```powershell
Get-ChildItem benchmarks -Directory | ForEach-Object {
  Push-Location $_.FullName
  $env:GOWORK = 'off'
  go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
  Pop-Location
}
```

汇总：

```bash
cd benchmarks/json
GOWORK=off go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms > result.txt
benchstat result.txt
```

## 发布前用本地源码跑基准

基准模块的 `go.mod` 按已发布标签引用 ydx 组件。若刚修改了组件源码、尚未打新标签，
可在**两个仓库之外**临时创建 `go.work` 指向本地模块；`go.work` 与本地 `replace` 都
不得提交。组件源码与对应子目录标签一致时，直接运行即可复现本文数字。

## 目录约定

- 每个基准模块的根目录文件只有 `docs.go`、`go.mod`、`go.sum` 与 `*_test.go`；包名
  等于目录名（`cache/local` 这类子包除外）。
- 对比库只进入 `benchmarks/*/go.mod`，不进入任何产品模块。
- 新增对比实现时，必须同时提供正确性校验或一次预检，确保测到的是等价路径。
