# router — 基数树路由与原生 http 适配

`github.com/shibingli/ydx/router` 提供自研高性能基数树（Radix Tree）路由器。除常规静态段
与参数段外，它原生支持单段内的混合静态/动态匹配，并通过 `Adapt` 让同一套中间件同时服务
YD 路由与原生 `net/http`。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/router` |
| 包名 | `router` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- 路由注册：`GET`、`POST`、`PUT`、`PATCH`、`DELETE`、`HEAD`、`OPTIONS`，以及
  `Handle` / `HandleRaw` 注册任意方法。
- 参数与通配：`:id`、`*filepath`，以及单段混合模式。
- 路由组：`Group` 前缀与组级中间件。
- 中间件：`Use`、`New` 选项、`Adapt` 包裹原生 `http.Handler`。
- 处理器形态：`HandlerFunc`（带 `*Ctx`）与 `HandlerFuncRaw`（原生 `http.ResponseWriter`）。
- 静态文件、模板渲染、下载、上传、自动 OPTIONS、最大 Body 限制、自定义 404/405/panic
  处理器。
- 路由表内省：`Routes()` / `RouteInfo`，供 OpenAPI 文档生成。
- `Router` 实现 `http.Handler`。

## 特性

- **单段混合匹配**：同一路径段内可以混合字面量与动态捕获：

  ```text
  /avatar/:id.jpg        捕获 id，且必须以 .jpg 结尾
  /report/:id-xx.png     捕获 id，剥离静态后缀 -xx.png
  /archive/:y-:m-:d.html 单段内捕获三个参数
  /static/*filepath      末段通配，捕获含 "/" 的剩余内容
  ```

- **转义**：字面量中的 `:`、`*`、`\` 可用反斜杠转义。
- **零分配分发**：静态、参数、通配与未命中路径均为 0 B/op、0 allocs/op。
- **Ctx 对象池**：常规路由复用 `*Ctx`；完全静态路由可注册为 `GETRaw`，走无上下文快路径。
- **双入口**：`Router` 直接作为 `http.Handler`；`Adapt(next, mw...)` 把同一中间件套在
  任意原生处理器上，每请求只支付一次适配成本。
- **扩展式转义**：扩展 CONNECT 通过 `protocol` 模块识别并分发到 GET 路由。

## 快速开始

### YD 路由

```go
package main

import (
	"net/http"

	"github.com/shibingli/ydx/router"
)

func main() {
	r := router.New()
	r.Use(func(c *router.Ctx) {
		c.SetHeader("X-App", "demo")
		c.Next()
	})

	r.GET("/", func(c *router.Ctx) {
		_ = c.String(http.StatusOK, "ok")
	})
	r.GET("/users/:id/profile", func(c *router.Ctx) {
		_ = c.JSON(http.StatusOK, map[string]string{"id": c.Param("id")})
	})
	r.GET("/files/*filepath", func(c *router.Ctx) {
		_ = c.String(http.StatusOK, c.Param("filepath"))
	})

	_ = http.ListenAndServe(":8080", r)
}
```

### 原生 net/http

```go
mux := http.NewServeMux()
mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("ok"))
})

handler := router.Adapt(mux, func(c *router.Ctx) {
	c.SetHeader("X-App", "demo")
	c.Next()
})
_ = http.ListenAndServe(":8080", handler)
```

## 应用场景

- **REST API**：路径参数、通配、路由组与统一中间件。
- **高吞吐网关**：静态路由零分配分发，参数/通配路径也保持零分配。
- **混合前缀资源**：`/avatar/:id.jpg`、`/report/:id-xx.png` 等 CDN 风格路径。
- **渐进迁移**：既有 `net/http` 处理器通过 `Adapt` 接入 YD 中间件，无需重写路由表。
- **文档生成**：把 `Routes()` 交给 `openapi/ydrouter` 生成 OpenAPI 文档。
- **WebSocket / SSE / WebTransport**：与各传输模块共享路由与中间件。

## 性能指标

基准模块：[`benchmarks/router`](../benchmarks/router/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | ydx/router | `net/http.ServeMux` | httprouter | chi | gin |
|---|---:|---:|---:|---:|---:|
| 静态 | **8.40 ns** | 60.15 ns | 12.86 ns | 114.9 ns | 33.17 ns |
| 参数 | **18.89 ns** | 104.7 ns | 29.02 ns | 165.9 ns | 41.83 ns |
| 通配 | **18.94 ns** | 165.4 ns | 28.06 ns | 223.0 ns | 25.62 ns |
| 未命中 | **25.75 ns** | 283.5 ns | 158.3 ns | 199.2 ns | 28.07 ns |

- 四类请求均为 0 B/op、0 allocs/op；httprouter 的参数/通配路径为 32 B/op、1 alloc/op。
- 静态用例使用 `GETRaw`（无 `Ctx`、无参数提取）；其它实现没有等价的“无上下文”注册形态。
- 适配器成本：`Adapt` 0/1/2 个中间件为 18.42 / 21.80 / 24.24 ns，均零分配。
- 下载辅助：`DownloadBytes` 4 KiB 275.3 ns（102 B / 5 allocs），`DownloadReader`
  200.7 ns（53 B / 4 allocs）。

> 这是分发微基准，处理器为空，不含业务逻辑、序列化、日志或真实网络 I/O；完整表格与
> 口径见基准 README。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 静态文件与模板文件系统 |

仓库内依赖：`afs`、`errs`、`json`、`log`、`protocol`。

基准对比对象：标准库 `net/http.ServeMux`、[`julienschmidt/httprouter`](https://github.com/julienschmidt/httprouter)、
[`go-chi/chi`](https://github.com/go-chi/chi)、[`gin-gonic/gin`](https://github.com/gin-gonic/gin)、
echo 与 fiber，仅出现在 `benchmarks/router`。

## 相关模块

- [`openapi/ydrouter`](../openapi/ydrouter/README.md)：路由树转 OpenAPI 文档。
- [`middleware`](../middleware/README.md)：中间件聚合门面。
- [`sse`](../sse/README.md)、[`websocket`](../websocket/README.md)、
  [`webtransport`](../webtransport/README.md)：传输层处理器。
- [`render`](../render/README.md)：模板渲染。
- [`protocol`](../protocol/README.md)：Extended CONNECT 判定。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
