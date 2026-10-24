# ydx — YunDev 可独立引用的 Go 组件集

`ydx` 是 [yd](https://github.com/shibingli/yd) 全栈框架的可复用组件仓库。每个带
`go.mod` 的组件目录都是一个**独立的 Go 模块**，可以单独 `go get`，也可以由 yd 主仓
直接引用；HTTP 相关模块同时提供 YD 路由（`router.Middleware`）与原生 `net/http`
两种入口。

- 源码仓库：<https://github.com/shibingli/ydx>
- 开源协议：Apache-2.0（见 `LICENSE`）
- Go 版本：1.27.3
- 仓库根目录**不是** Go 模块，也没有 `go.work`；组件按子目录标签单独发布，例如
  `errs/v0.1.0`、`middleware/cors/v0.1.0`。根目录的 `docs.go` 只是文档锚点，不是
  可导入模块。

## 模块索引

| 导入路径 | 包名 | 职责 |
|---|---|---|
| `github.com/shibingli/ydx/errs` | `errs` | 声明式哨兵错误与上下文包装 |
| `github.com/shibingli/ydx/sysinfo` | `sysinfo` | GOMAXPROCS / cgroup / 主机内存探测 |
| `github.com/shibingli/ydx/buffpool` | `buffpool` | 按尺寸分级的字节缓冲池 |
| `github.com/shibingli/ydx/protocol` | `protocol` | HTTP 协议判定（extended CONNECT 等） |
| `github.com/shibingli/ydx/base64` | `base64` | 硬件自适应 Base64 |
| `github.com/shibingli/ydx/json` | `json` | 硬件自适应 JSON |
| `github.com/shibingli/ydx/afs` | `afs` | afero 之上的文件系统门面（OS / 内存 / embed） |
| `github.com/shibingli/ydx/config` | `config` | 多源分层配置（flags > env > file > defaults） |
| `github.com/shibingli/ydx/log` | `log` | 零拷贝结构化日志 |
| `github.com/shibingli/ydx/regexpx` | `regexpx` | 自研正则引擎（线性 NFA + 回溯 + SIMD 预过滤） |
| `github.com/shibingli/ydx/router` | `router` | 基数树路由 + 原生 http 适配 |
| `github.com/shibingli/ydx/gorm` | `gorm` | GORM 装配、连接串预置与自动建库 |
| `github.com/shibingli/ydx/redis` | `redis` | go-redis 通用客户端、探活与读透缓存 |
| `github.com/shibingli/ydx/asynq` | `asynq` | 基于 asynq 的异步任务层（注册表、客户端、服务端） |
| `github.com/shibingli/ydx/cache` | `cache` | 二级缓存（L1 环形缓存 + Redis） |
| `github.com/shibingli/ydx/sse` | `sse` | Server-Sent Events 写入器与广播器 |
| `github.com/shibingli/ydx/websocket` | `websocket` | RFC 6455 / 7692 / 8441 WebSocket |
| `github.com/shibingli/ydx/render` | `render` | 编译式 `html/template` 引擎 |
| `github.com/shibingli/ydx/i18n` | `i18n` | 多语言目录加载、语言协商与路由中间件 |
| `github.com/shibingli/ydx/openapi` | `openapi` | OpenAPI 3.0/3.1 文档构建、注解解析与自包含查看器（标准 `net/http`，不依赖路由） |
| `github.com/shibingli/ydx/openapi/ydrouter` | `ydrouter` | `ydx/router` 适配：路由树转 OpenAPI 文档与路由处理器 |
| `github.com/shibingli/ydx/jwt` | `jwt` | 免反射 JWT 签发、验签与中间件 |
| `github.com/shibingli/ydx/middleware` | `middleware` | 中间件聚合门面（保持旧 API） |
| `github.com/shibingli/ydx/middleware/accesslog` | `accesslog` | 访问日志 |
| `github.com/shibingli/ydx/middleware/asyncafter` | `asyncafter` | 响应后异步管线 |
| `github.com/shibingli/ydx/middleware/compress` | `compress` | 响应压缩协商 |
| `github.com/shibingli/ydx/middleware/cors` | `cors` | CORS |
| `github.com/shibingli/ydx/middleware/ratelimit` | `ratelimit` | 限流（内存 / Redis） |
| `github.com/shibingli/ydx/middleware/recovery` | `recovery` | panic 恢复 |
| `github.com/shibingli/ydx/middleware/requestid` | `requestid` | 请求 ID |
| `github.com/shibingli/ydx/middleware/reqlog` | `reqlog` | 中间件共享的计数写入器与头处理（公开路径，无稳定性承诺） |
| `github.com/shibingli/ydx/repotest` | `repotest` | 仓库级守卫（模块文件、命名、依赖与架构约束） |

基准模块统一放在 `benchmarks/` 下，每个基准模块也拥有独立的 `go.mod`、`go.sum` 与
`docs.go`；组件模块本身不包含基准，也不依赖基准专用库。完整的方法、指标口径与本机实测
结果见 [benchmarks/README.md](benchmarks/README.md)。

| 基准模块 | 对比的主流实现 | 指标文档 |
|---|---|---|
| `benchmarks/base64` | `encoding/base64`、`cristalhq/base64` | [base64](benchmarks/base64/README.md) |
| `benchmarks/buffpool` | `sync.Pool`、`bytebufferpool` | [buffpool](benchmarks/buffpool/README.md) |
| `benchmarks/cache` | `bigcache`、`freecache`、`ristretto`、`sync.Map`、`go-cache`、`theine`、`ttlcache`、`golang-lru` | [cache](benchmarks/cache/README.md) |
| `benchmarks/compress` | 标准库 gzip、klauspost gzip/zstd、brotli、snappy、lz4 | [compress](benchmarks/compress/README.md) |
| `benchmarks/crypto` | 标准库 SHA-256/AES-GCM/ChaCha20-Poly1305/ECDSA/Ed25519、维护版与旧版 gmsm | [crypto](benchmarks/crypto/README.md) |
| `benchmarks/json` | `encoding/json`、`goccy/go-json`、`json-iterator`、`sonic`、`segmentio/encoding`、`go-json-experiment` | [json](benchmarks/json/README.md) |
| `benchmarks/jwt` | `golang-jwt/jwt`、`jwx`、`go-jose`、`cristalhq/jwt`、`kataras/jwt` | [jwt](benchmarks/jwt/README.md) |
| `benchmarks/log` | `zap`、`zerolog`、`slog`、`logrus` | [log](benchmarks/log/README.md) |
| `benchmarks/middleware` | `rs/cors`、`chi`、`gzhttp`、`x/time/rate` | [middleware](benchmarks/middleware/README.md) |
| `benchmarks/regexpx` | 标准库 `regexp`、`grafana/regexp`、`regexp2`、`go-re2` | [regexpx](benchmarks/regexpx/README.md) |
| `benchmarks/render` | `html/template`、`text/template` | [render](benchmarks/render/README.md) |
| `benchmarks/router` | `net/http.ServeMux`、`httprouter`、`chi`、`gin`、`echo`、`fiber` | [router](benchmarks/router/README.md) |
| `benchmarks/sse` | `gin-contrib/sse`、手写 `fmt.Fprintf` 基线 | [sse](benchmarks/sse/README.md) |
| `benchmarks/template` | `html/template`、`text/template`、Jet、Pongo2、Liquid、Raymond、Mustache、quicktemplate、templ | [template](benchmarks/template/README.md) |
| `benchmarks/websocket` | `gorilla/websocket`、`coder/websocket`、`gobwas/ws`、`lxzan/gws` | [websocket](benchmarks/websocket/README.md) |

> 目录名、模块名与包名三者一致；每个带实现代码的包还必须有一个与包同名的 `<package>.go`
> 主文件（例如 `cache/cache.go`，而不是 `cache/cachex.go`）。从 yd 迁移时需要同时更新
> import 路径与包标识符。

## YD 路由用法

```go
import (
	"github.com/shibingli/ydx/middleware"
	"github.com/shibingli/ydx/middleware/compress"
	"github.com/shibingli/ydx/middleware/cors"
	"github.com/shibingli/ydx/router"
)

r := router.New()
r.Use(
	middleware.RequestID(""),
	cors.CORS(cors.CORSOptions{}),
	compress.Compress(compress.CompressOptions{}),
)
r.GET("/", func(c *router.Ctx) { _ = c.String(200, "ok") })
```

## 原生 net/http 用法

```go
import (
	"net/http"

	"github.com/shibingli/ydx/middleware"
	"github.com/shibingli/ydx/middleware/compress"
	"github.com/shibingli/ydx/middleware/cors"
)

mux := http.NewServeMux()
mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok"))
})

handler := middleware.Adapt(mux,
	cors.CORS(cors.CORSOptions{}),
	compress.Compress(compress.CompressOptions{}),
)
_ = http.ListenAndServe(":8080", handler)
```

每个插件也提供 `Middleware(...) func(http.Handler) http.Handler`，可单独组合：

```go
handler := cors.Middleware(cors.CORSOptions{})(mux)
```

`jwt` 使用 `HTTPMiddleware` / `FromRequest`，`sse` 使用 `HTTPHandler`，`websocket` 使用 `HtmxHTTPHandler`。

`openapi` 的前端资源与 Go 代码完全隔离：页面模板在 `openapi/pages/page/index.html`，样式表、
图标 sprite 与查看器脚本在 `openapi/pages/assets/`，全部经 `go:embed` 随模块发布
（`ViewerHTML` / `ViewerCSS` / `ViewerIcons` / `ViewerScript` 可取原始字节）。`HTTPHandler`
同时提供 JSON 文档、查看器页面与 `AssetsPath` 下的三类资源，标准 `net/http` 只需把同一个处理器
挂载到 `Path`、`DocsPath` 与 `AssetsPath`。需要完全静态部署时，`ViewerPage` 返回完整页面字节，
四个资源字节可直接写入磁盘并由任意文件服务器托管；接自有静态管线时，把 `Options.ViewerScript`
/ `ViewerCSS` / `ViewerIcons` 指向自己的 URL。`ydx/router` 项目改用 `openapi/ydrouter` 的
`FromRouter` / `Handler`；核心模块因此不依赖任何路由器。

## 基准与对比

基准统一在 `benchmarks/*` 中运行，产品模块不依赖任何基准库。默认采集口径为每项
`-count=5 -benchtime=500ms -benchmem`，再用 `benchstat` 汇总：

```bash
cd benchmarks/json
GOWORK=off go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms

# 或对全部基准模块依次执行
for d in benchmarks/*/; do
  (cd "$d" && GOWORK=off go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms)
done
```

参考主机（Linux Zen 5，Ryzen AI MAX+ 395，`GOMAXPROCS=32`，Go 1.27.3，`-count=5
-benchtime=500ms`）的几组代表结果（完整表格见 [benchmarks/README.md](benchmarks/README.md)）：

- `json`：`Marshal` 64 对象 2.59 µs，标准库 12.8 µs；goccy 4.23 µs、sonic 2.99 µs。
- `jwt`：HS256 `Parse`（同一规范 token）782.6 ns，golang-jwt 3.170 µs、jwx 4.726 µs、
  go-jose 5.846 µs。
- `log`：5 字段 JSON 134.1 ns，zap 395.2 ns、zerolog 168.6 ns、slog 529.9 ns。
- `router`：静态路由 8.40 ns，httprouter 12.86 ns、gin 33.17 ns、`ServeMux` 60.15 ns。
- `render`：带绑定渲染 258.2 ns，`html/template` 3.473 µs、`text/template` 2.208 µs。

这些数字只用于同机相对比较，不是跨硬件或跨轮次承诺；CPU 频率/温度会让同一份代码在
不同轮次的绝对 ns/op 漂移数十个百分点。每个模块的完整表格、语义差异与
复现命令见 [benchmarks/README.md](benchmarks/README.md)。对比库只出现在
`benchmarks/*/go.mod`，不会进入产品模块。

## 版本与本地开发

- 每个模块独立打子目录标签，例如 `errs/v0.1.0`、`middleware/cors/v0.1.0`。
- 消费方直接用版本号引用；仓库内**不提交** `go.work`、**不使用** `replace` 指向本地路径。
- 同时修改多个模块（或要在发布前用本地源码跑基准）时，在两个仓库**之外**创建临时
  工作区，路径相对于该临时目录，结束后删除：

```bash
mkdir ../ydx-dev && cd ../ydx-dev
go work init
go work use ../yd ../ydx/errs ../ydx/router # 按需添加
```

基准模块按各组件**已发布的子目录标签**解析（例如 `json v0.1.10`、`middleware v0.1.10`）；
组件源码与标签一致时无需工作区。发布本次修改前，最终主表用两个仓库之外的临时 `go.work`
指向本地源码采集；该工作区只用于本地联调与基准，不得提交。

## 验证

```bash
# POSIX
./scripts/test-all.sh

# Windows PowerShell
pwsh ./scripts/test-all.ps1
```

脚本对每个模块执行 `go build ./... && go vet ./... && go test ./... -race`。Windows
下脚本在未指定 `CC` 时会优先使用 `clang` 并设置 `CGO_ENABLED=1`，以支持 race
检测器。基准不在 `test-all` 中运行，避免拖慢流水线；按需运行方式见
[benchmarks/README.md](benchmarks/README.md)：

```bash
cd benchmarks/log
GOWORK=off go test -run '^$' -bench . -benchmem
```

每个产品模块都必须包含 `docs.go`、`go.mod`、`go.sum`；`docs.go` 给出包文档与
YD/原生两种用法。每个基准模块同样包含 `docs.go`、`go.mod`、`go.sum`，其 `docs.go`
描述基准与对比对象。
`repotest` 还会校验模块路径、包名、主文件名、本地 `replace`、标准库编解码与 `regexp` 直引、
`fmt.Errorf`、直接 `panic`、外键、cgo SQLite 以及基准位置：

```bash
cd repotest
GOWORK=off go test ./...
```
