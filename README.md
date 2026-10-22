# ydx — YunDev 可独立引用的 Go 组件集

`ydx` 是 [yd](https://github.com/shibingli/yd) 全栈框架的可复用组件仓库。每个目录都是一个**独立的 Go 模块**，可以单独 `go get`，也可以由 yd 主仓直接引用；HTTP 相关模块同时提供 YD 路由（`router.Middleware`）与原生 `net/http` 两种入口。

- 源码仓库：<https://github.com/shibingli/ydx>
- 开源协议：Apache-2.0（见 `LICENSE`）
- Go 版本：1.27.2

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
| `github.com/shibingli/ydx/regexpx` | `regexpx` | 统一正则入口（RE2 快路径 + regexp2 兼容路径） |
| `github.com/shibingli/ydx/router` | `router` | 基数树路由 + 原生 http 适配 |
| `github.com/shibingli/ydx/gorm` | `gorm` | GORM 装配、连接串预置与自动建库 |
| `github.com/shibingli/ydx/cache` | `cache` | 二级缓存（L1 环形缓存 + Redis） |
| `github.com/shibingli/ydx/sse` | `sse` | Server-Sent Events 写入器与广播器 |
| `github.com/shibingli/ydx/websocket` | `websocket` | RFC 6455 / 7692 / 8441 WebSocket |
| `github.com/shibingli/ydx/render` | `render` | 编译式 `html/template` 引擎 |
| `github.com/shibingli/ydx/jwt` | `jwt` | 免反射 JWT 签发、验签与中间件 |
| `github.com/shibingli/ydx/middleware` | `middleware` | 中间件聚合门面（保持旧 API） |
| `github.com/shibingli/ydx/middleware/accesslog` | `accesslog` | 访问日志 |
| `github.com/shibingli/ydx/middleware/asyncafter` | `asyncafter` | 响应后异步管线 |
| `github.com/shibingli/ydx/middleware/compress` | `compress` | 响应压缩协商 |
| `github.com/shibingli/ydx/middleware/cors` | `cors` | CORS |
| `github.com/shibingli/ydx/middleware/ratelimit` | `ratelimit` | 限流（内存 / Redis） |
| `github.com/shibingli/ydx/middleware/recovery` | `recovery` | panic 恢复 |
| `github.com/shibingli/ydx/middleware/requestid` | `requestid` | 请求 ID |
| `github.com/shibingli/ydx/middleware/reqlog` | `reqlog` | 中间件内部共享的计数写入器与头处理（中间件共享实现（公开路径，无稳定性承诺）） |

> 目录名、模块名与包名三者一致；从 yd 迁移时需要同时更新 import 路径与包标识符。

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

## 版本与本地开发

- 每个模块独立打子目录标签，例如 `errs/v0.1.0`、`middleware/cors/v0.1.0`。
- 消费方直接用版本号引用；仓库内**不提交** `go.work`、**不使用** `replace` 指向本地路径。
- 同时修改多个模块时，可在两个仓库之外创建临时工作区：

```bash
go work init
go work use ./yd ./ydx/errs ./ydx/router # ...
```

## 验证

```bash
# POSIX
./scripts/test-all.sh

# Windows PowerShell
pwsh ./scripts/test-all.ps1
```

脚本对每个模块执行 `go build ./... && go vet ./... && go test ./... -race`。

每个模块都必须包含 `docs.go`、`go.mod`、`go.sum`；`docs.go` 给出包文档与 YD/原生两种用法。
