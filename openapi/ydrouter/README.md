# openapi/ydrouter — ydx/router 的 OpenAPI 适配

`github.com/shibingli/ydx/openapi/ydrouter` 是 `ydx/router` 与独立 `ydx/openapi` 模块之间的
唯一桥梁。`openapi` 核心不感知任何路由器；本包把路由树转换为 `openapi.Route`，并合并
源码注解。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/openapi/ydrouter` |
| 包名 | `ydrouter` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `FromRouter(r, info, o)`：把 `*router.Router` 的路由表转换为 `*openapi.Document`。
- `FromRouterWithAnnotations(r, info, o, ...)`：在转换时合并源码注解与类型注解。
- `Routes(r)`：只做路由转换，返回 `[]openapi.Route`。
- `Handler(d, o)`：返回 YD 路由可挂载的 `router.HandlerFunc`，提供 JSON 文档、查看器与
  内嵌资源。

## 特性

- **单向依赖**：`openapi` 核心不 import `ydx/router`；只有本包同时依赖两者。
- **路由树内省**：直接消费 `Router.Routes()` 的方法/路径/处理器信息。
- **注解合并**：处理器注解与类型注解在文档构建时合并，支持覆盖率报告。
- **双入口**：YD 项目用 `Handler`；原生 `net/http` 项目可继续使用
  `openapi.HTTPHandler`，只依赖 `openapi`。
- **零请求期反射**：转换与注解解析发生在启动期/构建期，请求路径只做文档/资源写出。

## 快速开始

```go
package main

import (
	"net/http"

	"github.com/shibingli/ydx/openapi"
	"github.com/shibingli/ydx/openapi/ydrouter"
	"github.com/shibingli/ydx/router"
)

func main() {
	r := router.New()
	r.GET("/users/:id", func(c *router.Ctx) {
		_ = c.JSON(http.StatusOK, map[string]string{"id": c.Param("id")})
	})

	info := openapi.Info{Title: "Demo", Version: "1.0.0"}
	opts := openapi.Options{}
	doc := ydrouter.FromRouter(r, info, opts)
	if err := doc.Validate(); err != nil {
		return
	}

	h := ydrouter.Handler(doc, opts)
	r.GET(opts.Path, h)
	r.GET(opts.DocsPath, h)
	r.GET(opts.AssetsPath+"*filepath", h)

	_ = http.ListenAndServe(":8080", r)
}
```

带源码注解：

```go
annots, err := openapi.ParseAnnotations(afs.NewOS("internal/handler"), []string{"."})
if err != nil {
	return err
}
var report openapi.Report
doc := ydrouter.FromRouterWithAnnotations(r, info, opts, annots, &report)
```

`report` 会填入 `Matched`、`Missing`、`Orphan`、`Incomplete` 等覆盖率视图；`annots` 与
`report` 都允许为 nil。

## 应用场景

- **YD 项目文档**：从现有路由表直接生成 OpenAPI，无需重复声明路径。
- **契约校验**：在 CI 中生成文档并运行 `Document.Validate`。
- **注解驱动**：处理器源码中的 `@Summary` 等注解自动进入文档。
- **渐进接入**：原生 `net/http` 项目只依赖 `openapi`，不引入 `router`。
- **生产下线**：`openapi.Options.Blocked` 关闭端点。

## 性能指标

本模块没有独立基准；成本集中在启动期：

- `FromRouter` / `Routes` 遍历一次路由表，转换路径参数并构造文档对象。
- `FromRouterWithAnnotations` 额外扫描源码目录，成本与源文件数成正比。
- `Handler` 在请求路径只做文档/资源字节写出，不执行反射或注解解析。
- 文档 JSON 可在启动期序列化并复用；大型路由表建议缓存序列化结果。

> 请求期开销与 `openapi.HTTPHandler` 相同；本包不增加额外中间件或每请求转换。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`openapi`](../../openapi/README.md)：文档模型、Builder、查看器资源。
- [`router`](../../router/README.md)：路由树与处理器。

## 相关模块

- [`openapi`](../../openapi/README.md)：核心文档模型与标准 `net/http` 处理器。
- [`router`](../../router/README.md)：路由注册与 `Routes()` 内省。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
