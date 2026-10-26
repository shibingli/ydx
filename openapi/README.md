# openapi — OpenAPI 3.0/3.1 文档构建与自包含查看器

`github.com/shibingli/ydx/openapi` 依据路由定义构建 OpenAPI 文档、合并源码注解，并连同
自包含查看器页面一起对外提供。默认规范版本为 3.0.3；把 `Document.OpenAPI` 设为
`LatestSpecVersion` 可启用 3.1 的对象补充。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/openapi` |
| 包名 | `openapi` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认规范版本 | 3.0.3（`SpecVersion`） |

## 功能

- **文档模型**：`Document`、`PathItem`、`Operation`、`Components`、`Schema` 等，只经
  `ydx/json` 序列化。
- **Builder**：手工装配文档，并通过反射从 Go 结构体推导 JSON Schema（仅构建期）。
- **FromRoutes** / `FromRoutesWithAnnotations`：把 `openapi.Route` 转换为路径，并合并
  `@Summary` 风格注解。
- **注解解析**：`ParseSource`、`ParseAnnotations`、`ParseTypeAnnotations`、
  `CollectFromSource`、`Report`（覆盖率）。
- **校验**：`Document.Validate` 检查结构规则与 3.0/3.1 方言。
- **查看器**：`HTTPHandler` 同时提供 JSON 文档、内置查看器与内嵌资源；
  `ViewerPage`、`ViewerHTML`、`ViewerCSS`、`ViewerIcons`、`ViewerScript` 可取原始字节。
- **静态部署**：把页面与资源写入磁盘，由任意文件服务器托管。
- **自定义资源 URL**：`Options.ViewerScript` / `ViewerCSS` / `ViewerIcons` 指向自有 URL。
- **生产下线**：`Options.Blocked` 关闭文档端点。

## 特性

- **不依赖路由器**：核心只接受 `openapi.Route`，通过 `HTTPHandler` 提供标准
  `net/http` 处理器；`ydx/router` 的桥接位于独立模块 `openapi/ydrouter`。
- **构建期反射**：Schema 推导只发生在构建期，不进入请求热路径。
- **源码注解**：一次扫描源码树，返回处理器注解与类型注解。
- **扩展字段**：所有以结构体表示的对象都通过 `Extensions` 承载 `x-*` 扩展。
- **自包含查看器**：页面模板、样式表、图标 sprite 与脚本全部经 `go:embed` 随模块发布，
  不引用任何外部 CDN。
- **按需挂载**：同一个处理器可挂载到 `Path`、`DocsPath`、`AssetsPath` 三个端点。
- **覆盖率报告**：`Report.Missing` 列出未注解的路由；`SkipPrefixes` 排除内部端点。

## 快速开始

### 标准 net/http

```go
package main

import (
	"net/http"

	"github.com/shibingli/ydx/openapi"
)

func main() {
	routes := []openapi.Route{
		{
			Method: "GET",
			Path:   "/users/{id}",
			Params: []openapi.Parameter{{Name: "id", In: "path", Required: true}},
		},
	}
	info := openapi.Info{Title: "Demo", Version: "1.0.0"}
	opts := openapi.Options{}

	doc := openapi.FromRoutes(routes, info, opts)
	if err := doc.Validate(); err != nil {
		return
	}

	h := openapi.HTTPHandler(doc, opts)
	mux := http.NewServeMux()
	mux.Handle("/openapi.json", h)
	mux.Handle("/docs", h)
	mux.Handle("/openapi/assets/", h)
	_ = http.ListenAndServe(":8080", mux)
}
```

### YD 路由

核心不感知路由器；YD 项目使用 [`openapi/ydrouter`](ydrouter/README.md)：

```go
doc := ydrouter.FromRouter(r, openapi.Info{Title: "Demo", Version: "1.0.0"}, openapi.Options{})
h := ydrouter.Handler(doc, openapi.Options{})
r.GET("/openapi.json", h)
r.GET("/docs", h)
r.GET("/openapi/assets/*filepath", h)
```

### 静态部署

```go
page, _ := openapi.ViewerPage(doc, openapi.Options{
	ViewerScript: "./index.js",
	ViewerCSS:    "./index.css",
	ViewerIcons:  "./icons.svg",
})
_ = os.WriteFile("public/docs/index.html", page, 0o644)
_ = os.WriteFile("public/docs/index.js", openapi.ViewerScript(), 0o644)
_ = os.WriteFile("public/docs/index.css", openapi.ViewerCSS(), 0o644)
_ = os.WriteFile("public/docs/icons.svg", openapi.ViewerIcons(), 0o644)
```

## 应用场景

- **API 文档站**：内部或对外 API 的交互式文档。
- **SDK 生成**：以 OpenAPI 文档作为代码生成输入。
- **契约先行**：从路由与注解生成契约，并在 CI 中校验。
- **多团队协作**：统一路径、参数、响应与错误模型。
- **生产环境下线**：`Blocked` 在非开发环境关闭文档端点。
- **完全静态托管**：把页面与资源导出到 CDN/对象存储。

## 性能指标

本模块没有独立基准；成本集中在构建期与服务静态资源：

- `FromRoutes` / `FromRoutesWithAnnotations` 在启动期或构建期执行，遍历路由与注解。
- Schema 推导使用反射，但只发生在构建期，不在请求热路径。
- `HTTPHandler` 请求路径只做路径分流与字节写出；JSON 文档可预先序列化/缓存。
- 查看器资源是 `go:embed` 的静态字节，不访问文件系统、不引用 CDN。
- 源码注解扫描是一次性文件遍历，规模与源文件数成正比。

> 文档 JSON 的体积与路由/Schema 数量成正比；大型 API 建议在构建期生成并缓存，
> 生产环境用静态文件服务器托管。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 源码/资源文件系统 |
| [`go.yaml.in/yaml/v3`](https://gopkg.in/yaml.v3) | v3.0.5 | MIT / Apache-2.0 双许可 | 注解与 YAML 解析 |

仓库内依赖：`afs`、`errs`、`json`、`log`、`sysinfo`。

查看器前端资源为本仓自研，随模块 `go:embed` 发布；未使用 Swagger UI、Redoc 等第三方
查看器，因此不依赖外部 CDN 或前端包管理器。

## 相关模块

- [`openapi/ydrouter`](ydrouter/README.md)：`ydx/router` 适配。
- [`router`](../router/README.md)：路由表与处理器。
- [`json`](../json/README.md)：文档序列化。
- [`afs`](../afs/README.md)：源码与资源文件系统。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
