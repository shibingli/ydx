# ydx 基准与主流实现对比

本目录是 ydx 的基准模块集合，共 **14 个独立 Go 模块**。原 yd 仓 `benchmarks/` 的独有场景
已全部并入本目录（json 的 7 字段载荷、base64 的 32 B/1 MiB、jwt 的 cristal/jwt 与
kataras/jwt、log 的 prebound 场景、router 的 echo/fiber、websocket 的 gobwas/gws、
cache 的 TTL/命中率轨迹，以及 compress/crypto/template 整模块；render 的微基准已并入
template 模块，避免同一引擎在两处重复对比），yd 仓不再保留基准目录。
每个模块只依赖 ydx 的已发布子目录标签与对应的对比库；`cache/local` 与 `cache/compare`
是 `cache` 模块内的子包。产品模块本身不包含任何 `Benchmark*`，也不依赖基准专用库。

- 实测日期：2026-10-24
- 主表运行环境：Linux AMD Ryzen AI MAX+ 395（Zen 5，16 核 32 线程，AVX-512
  VBMI/VBMI2），Ubuntu 26.04.1，Go **1.27.3** linux/amd64，`GOMAXPROCS=32`。
- 架构补充：Linux Neoverse-N2（4 vCPU，arm64）与旧指令集 x86_64（4 vCPU）的冒烟结果见
  [optimization-report.md](optimization-report.md)。
- 采样方式：`-count=5`、`-benchtime=500ms`、`-benchmem`，取中位数；同一轮内小于约 5%
  的差异视为噪声。网络类基准受回环栈与调度影响，单独注明。
- 跨轮漂移：CPU 频率/温度与后台负载会让同一份代码在不同轮次的绝对 ns/op 相差数十个
  百分点；只比较同一轮表格内的相对关系，不要把不同模块/不同时间的绝对值直接混比。
- 低效点定位、优化前后对比与公平性说明见
  [optimization-report.md](optimization-report.md)。

## 模块与对比对象

| 基准模块 | 对比的主流实现 | 指标文档 |
|---|---|---|
| `benchmarks/base64` | `encoding/base64`、`cristalhq/base64`、`cloudwego/base64x` | [base64/README.md](base64/README.md) |
| `benchmarks/buffpool` | `sync.Pool`、`valyala/bytebufferpool` | [buffpool/README.md](buffpool/README.md) |
| `benchmarks/cache` | `bigcache`、`freecache`、`ristretto`、`sync.Map`、`go-cache`、`theine`、`ttlcache`、`golang-lru` | [cache/README.md](cache/README.md) |
| `benchmarks/compress` | 标准库 gzip、klauspost gzip/zstd、brotli、snappy、lz4 | [compress/README.md](compress/README.md) |
| `benchmarks/crypto` | 标准库 SHA-256/AES-GCM/ChaCha20-Poly1305/ECDSA/Ed25519、维护版与旧版 gmsm | [crypto/README.md](crypto/README.md) |
| `benchmarks/json` | `encoding/json`、`goccy/go-json`、`json-iterator/go`、`bytedance/sonic`、`segmentio/encoding`、`go-json-experiment/json` | [json/README.md](json/README.md) |
| `benchmarks/jwt` | `golang-jwt/jwt/v5`、`lestrrat-go/jwx/v4`、`go-jose/v4`、`cristalhq/jwt/v5`、`kataras/jwt` | [jwt/README.md](jwt/README.md) |
| `benchmarks/log` | `zap`、`zerolog`、`slog`、`logrus` | [log/README.md](log/README.md) |
| `benchmarks/middleware` | `rs/cors`、`chi`、`klauspost/compress/gzhttp`、`x/time/rate` | [middleware/README.md](middleware/README.md) |
| `benchmarks/regexpx` | 标准库 `regexp`、`grafana/regexp`、`regexp2`、`go-re2` | [regexpx/README.md](regexpx/README.md) |
| `benchmarks/router` | `net/http.ServeMux`、`httprouter`、`chi`、`gin`、`echo`、`fiber` | [router/README.md](router/README.md) |
| `benchmarks/sse` | `gin-contrib/sse`、手写 `fmt.Fprintf` 基线 | [sse/README.md](sse/README.md) |
| `benchmarks/template` | `html/template`、`text/template`、Jet、Pongo2、Liquid、Raymond、Mustache、quicktemplate、templ | [template/README.md](template/README.md) |
| `benchmarks/websocket` | `gorilla/websocket`、`coder/websocket`、`gobwas/ws`、`lxzan/gws` | [websocket/README.md](websocket/README.md) |

## 关键结果速览

下表摘录每个模块最具代表性的同机实测数字；各行来自同一主机的同一轮采样，但不同模块
不是同一进程，**不宜跨行做严格比例推断**。完整表格、全部对比实现与口径说明见各模块
README 与 [optimization-report.md](optimization-report.md)。

| 模块 | 场景 | ydx | 对比实现 |
|---|---|---:|---:|
| base64 | `Encode` 32 B | 5.58 ns | cristalhq 9.57 ns / stdlib 14.38 ns |
| base64 | `Decode` 32 B | 10.47 ns | cristalhq 12.93 ns / stdlib 19.92 ns |
| base64 | `Encode` 1 MiB | 55.5 GB/s | cristalhq 5.05 GB/s / stdlib 2.39 GB/s |
| buffpool | 4 KiB `Get`/`Put` | 9.94 ns | `sync.Pool` 7.23 ns / bytebufferpool 9.49 ns |
| cache | L1 `Get` 命中（防御性副本） | 45.1 ns | ristretto 35.7 ns / `sync.Map` 13.4 ns |
| cache | L1 `GetAppend` / `View`（零拷贝） | 38.3 / 36.6 ns | ristretto 35.7 ns |
| cache | L1 `Set` | **49.07 ns** | freecache 75.5 ns / bigcache 95.8 ns |
| compress | 16 KiB gzip 中间件 | 5.268 µs | gzhttp 5.213 µs |
| crypto | SM3 4 KiB | 7.36 µs | SHA-256 约 23% 的吞吐（无 SHA-NI 对应指令） |
| crypto | SM2 签名 / 验签 | **14.02 / 33.91 µs** | 旧版 tjfoc 130.5 / 686.5 µs；快于 ECDSA P-256（17.67 / 38.54 µs） |
| json | `Marshal` 64 对象 | 2.59 µs | goccy 4.23 µs / sonic 2.99 µs / stdlib 12.8 µs |
| json | `Unmarshal` 64 对象 | 6.51 µs | goccy 6.87 µs / sonic 10.9 µs / stdlib 28.7 µs |
| json | 7 字段 `Marshal` n=1000 | **89.68 µs** | go-json 116.19 µs / stdlib 302.24 µs |
| json | 7 字段 `Unmarshal` n=1000 | **174.3 µs** | go-json 195.2 µs / stdlib 708.0 µs |
| jwt | HS256 `Sign` | 1.257 µs（类型化 535.3 ns） | cristalhq 1.061 µs（类型化）/ jwx 2.237 µs / golang-jwt 2.544 µs |
| jwt | HS256 `Parse` | 782.6 ns | golang-jwt 3.170 µs / jwx 4.726 µs |
| log | 5 字段 JSON Info | 134.1 ns | zerolog 168.6 ns / zap 395.2 ns / slog 529.9 ns |
| log | 5 字段并发 Info | 8.08 ns | zerolog 10.53 ns / zap 140.9 ns |
| middleware | CORS GET | **36.7 ns** | rs/cors 53.2 ns |
| middleware | 恢复（无 panic） | **7.85 ns** | chi 8.62 ns |
| middleware | 限流放行 | 136.5 ns | `x/time/rate` 59.92 ns（全局、不写头）；+headers 127.8 ns；按 IP + headers 139.0 ns |
| regexpx | `FindAll/email` | **94.98 µs** | go-re2 732.3 µs / stdlib 5.679 ms |
| router | 静态路由（`GETRaw`） | **8.40 ns** | httprouter 12.86 ns / stdlib 60.15 ns |
| router | 参数 / 通配 / 未命中 | **18.9 / 18.9 / 25.8 ns** | httprouter 29.0 / 28.1 / 158.3 ns；gin 41.8 / 25.6 / 28.1 ns |
| sse | 32 B / 4 KiB `WriteData` | 14.1 ns / 63.7 ns | gin-contrib 47.5 ns / 1.45 µs；手写 33.6 ns / 52.3 ns |
| template | 100 行页面（物化） | **18.78 µs** | quicktemplate 21.46 µs / html/template 473.2 µs |
| template | 绑定渲染微基准（`BenchmarkRender`） | **253.7 ns** | html/template 3.43 µs / text/template 2.12 µs |
| websocket | 32 B 回显往返 | **4.07 µs** | gorilla 4.26 µs / gobwas 4.34 µs / coder 5.59 µs |
| websocket | 64×1 KiB 批量写 | **14.06 µs** | coder 73.7 µs / gorilla 124.3 µs |

> 说明：`base64` 的 cloudwego/base64x 对照在 Windows 开发机上单独采集（见
> [base64/README.md](base64/README.md)），未并入本表；其绝对数字不与 Linux 主表混比。
> `cache` 的 `sync.Map`/ristretto/go-cache/golang-lru 返回缓存内引用，`ydx` 的
> `Get` 返回副本；带 TTL 的读写还要支付本机约 43 ns 的 `time.Now()`；`buffpool` 的
> `sync.Pool` 基线为每个尺寸预建一个池，不含尺寸分级；`middleware` 的限流对比另给出
> 补头（127.8 ns）与按 IP 分桶（139.0 ns）两个变体，全局 59.92 ns 不写头；`sse` 的手写
> 基线不做 CR/LF 规整。语义差异与完整数字见 [optimization-report.md](optimization-report.md)。

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
4. 对比库版本锁定在各模块 `go.mod`；ydx 组件按已发布子目录标签解析。**最终主表使用本地
   ydx 源码**（在两仓之外创建 `go.work` 指向本仓各组件模块），因此复现主表需要先发布
   本次修改的组件新标签，或使用同样的临时 `go.work`；`go.work` 不得提交。

## 复现

单个模块：

```bash
cd benchmarks/json
GOWORK=off go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

使用本地源码（示例；`go.work` 位于两个仓库之外）：

```bash
workdir=$(mktemp -d)
(cd "$workdir" && go work init $(find /path/to/ydx -name go.mod -printf '%h\n'))
GOWORK="$workdir/go.work" go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
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

## 复现最终主表

基准模块的 `go.mod` 已锁定到本次发布的 ydx 子目录标签，`GOWORK=off` 即可直接复现本文
数字，无需任何工作区。若刚修改了组件源码、尚未打新标签，可在**两个仓库之外**临时创建
`go.work` 指向本地模块；`go.work` 与本地 `replace` 都不得提交。

## 目录约定

- 每个基准模块的根目录文件只有 `docs.go`、`go.mod`、`go.sum` 与 `*_test.go`；包名
  等于目录名（`cache/local` 这类子包除外）。
- 对比库只进入 `benchmarks/*/go.mod`，不进入任何产品模块。
- 新增对比实现时，必须同时提供正确性校验或一次预检，确保测到的是等价路径。
