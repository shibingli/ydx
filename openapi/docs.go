// Package openapi builds OpenAPI 3.0 documents from yd router definitions, merges
// source level annotations and serves the result together with a self-contained
// viewer page. The default specification version is 3.0.3; setting Document.OpenAPI to
// LatestSpecVersion switches on the 3.1 object additions. | Package openapi 依据 yd 路由定义
// 构建 OpenAPI 3.0 文档、合并源码注解，并连同自包含的查看器页面一起对外提供。默认规范版本为
// 3.0.3；把 Document.OpenAPI 设为 LatestSpecVersion 可启用 3.1 的对象补充。
//
// Three layers are provided: | 本包提供三层能力：
//
//   - the document model (Document, PathItem, Operation, ...) which is only ever
//     serialized through ydx/json; | 文档模型（Document、PathItem、Operation 等），只经 ydx/json 序列化；
//   - Builder, which assembles documents by hand and derives JSON Schemas from Go
//     structs by reflection (build time only, never on the request path); | Builder，
//     用于手工装配文档，并通过反射从 Go 结构体推导 JSON Schema（仅构建期，不进请求热路径）；
//   - FromRouter / FromRouterWithAnnotations, which turn router.Routes() into paths and
//     merge @Summary style annotations parsed from handler source. | FromRouter /
//     FromRouterWithAnnotations，把 router.Routes() 转换为路径，并合并从处理器源码解析出的
//     @Summary 风格注解。
//
// ParseSource scans the source tree once and returns both handler and type annotations;
// Document.Validate checks the structural rules and the 3.0/3.1 dialect, and every struct based
// object carries x-* extensions through its Extensions field. | ParseSource 一次扫描源码树并返回
// 处理器注解与类型注解；Document.Validate 检查结构规则与 3.0/3.1 方言；所有以结构体表示的对象都
// 通过 Extensions 字段承载 x-* 扩展。
//
// Handler serves the JSON document, the built-in viewer and the embedded viewer script
// without referencing any external CDN. | Handler 同时提供 JSON 文档、内置查看器与内嵌查看器
// 脚本，且不引用任何外部 CDN。
//
// Typical wiring: | 典型装配方式：
//
//	info := openapi.Info{Title: "Demo", Version: "1.0.0"}
//	opts := openapi.Options{AssetsPath: openapi.DefaultAssetsPath}
//	doc := openapi.FromRouter(r, info, opts)
//	h := openapi.Handler(doc, opts)
//	r.GET(opts.Path, h)
//	r.GET(opts.DocsPath, h)
//	r.GET(opts.AssetsPath+"*filepath", h)
//
// The viewer script is embedded in this module. With a standard net/http server, mount the
// same handler on the three endpoints; no framework static filesystem is required: | 查看器脚本
// 内嵌在本模块中。使用标准 net/http 服务时，把同一个处理器挂载到三个端点上即可，无需任何框架
// 静态文件系统：
//
//	h := openapi.HTTPHandler(doc, openapi.Options{})
//	mux.Handle("/openapi.json", h)
//	mux.Handle("/docs", h)
//	mux.Handle("/openapi/assets/", h)
//
// Frontend resources are isolated from Go code: the page template lives in
// pages/page/index.html, while pages/assets/ holds the stylesheet, the icon sprite and the
// viewer script. All four ship with the module through go:embed and are available as
// ViewerHTML, ViewerCSS, ViewerIcons and ViewerScript. For a fully static deployment,
// ViewerPage returns the complete page bytes; write them and the three assets to disk and
// serve them with any file server: | 前端资源与 Go 代码相互隔离：页面模板位于
// pages/page/index.html，pages/assets/ 存放样式表、图标 sprite 与查看器脚本。四者都经 go:embed
// 随模块发布，可分别通过 ViewerHTML、ViewerCSS、ViewerIcons 与 ViewerScript 取得。完全静态部署时，
// ViewerPage 返回完整页面字节；把页面与三个资源写入磁盘并用任意文件服务器托管：
//
//	page, _ := openapi.ViewerPage(doc, openapi.Options{
//		ViewerScript: "./index.js", ViewerCSS: "./index.css", ViewerIcons: "./icons.svg",
//	})
//	os.WriteFile("public/docs/index.html", page, 0o644)
//	os.WriteFile("public/docs/index.js", openapi.ViewerScript(), 0o644)
//	os.WriteFile("public/docs/index.css", openapi.ViewerCSS(), 0o644)
//	os.WriteFile("public/docs/icons.svg", openapi.ViewerIcons(), 0o644)
//
// Callers that package the viewer through their own pipeline can use ViewerScript, ViewerCSS
// and ViewerIcons to obtain the embedded bytes and point the matching Options fields at the
// URLs they serve. | 通过自有管线打包查看器的调用方可以用 ViewerScript、ViewerCSS 与
// ViewerIcons 取得内嵌字节，并把对应的 Options 字段指向自己的 URL。
//
// This package deliberately knows nothing about routers. It accepts converted openapi.Route
// values through FromRoutes and serves standard net/http handlers through HTTPHandler; the
// ydx/router bridge lives in the separate openapi/ydrouter module. | 本包刻意不感知任何路由器：
// 它通过 FromRoutes 接收转换后的 openapi.Route，通过 HTTPHandler 提供标准 net/http 处理器；
// ydx/router 的桥接位于独立的 openapi/ydrouter 模块。
package openapi
