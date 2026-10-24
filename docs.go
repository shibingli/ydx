// Package ydx documents the repository layout of the YunDev reusable Go component set.
//
// The repository root is intentionally not a Go module: every component directory with a
// go.mod is an independent module with its own go.sum and docs.go, so consumers can depend on
// one component without pulling in the rest of the repository. The root package exists only as
// a documentation anchor; import the concrete component module instead. |
// Package ydx 记录 YunDev 可复用 Go 组件集的仓库布局。
//
// 仓库根目录刻意不是 Go 模块：每个带 go.mod 的组件目录都是独立模块，拥有自己的 go.sum 与
// docs.go，因此消费方可以只依赖单个组件而不引入整个仓库。根包仅作为文档锚点存在；实际使用时
// 请导入具体的组件模块。
//
// Product modules live directly under the repository root, for example errs, sysinfo, gc,
// buffpool, protocol, nodeid, base64, json, afs, config, log, regexpx, router, gorm, redis,
// asynq, cache, sse, websocket, webtransport, realtime, render, i18n, openapi and jwt, plus the
// openapi/ydrouter adapter and the middleware plugins under middleware/. Benchmarks are kept outside the product modules in
// benchmarks/, one independent module per component, so product modules never depend on
// benchmark-only libraries. The repository guard lives in repotest. |
// 产品模块直接位于仓库根目录下，例如 errs、sysinfo、gc、buffpool、protocol、nodeid、base64、json、
// afs、config、log、regexpx、router、gorm、redis、asynq、cache、sse、websocket、webtransport、
// realtime、render、i18n、openapi 与 jwt，以及 openapi/ydrouter 适配器与 middleware/ 下的中间件插件。基准统一放在产品模块
// 之外的 benchmarks/，每个组件一个独立模块，使产品模块永不依赖仅用于基准的库。仓库守卫位于 repotest。
//
// Each module is versioned by a subdirectory tag such as errs/v0.1.0 or middleware/cors/v0.1.0.
// See README.md for the module index and the two HTTP entry points, and benchmarks/README.md for
// the comparison methodology and per-module results. |
// 每个模块使用子目录标签发布，例如 errs/v0.1.0 或 middleware/cors/v0.1.0。模块索引与两种 HTTP
// 入口见 README.md；对比方法与本机实测结果见 benchmarks/README.md。
package ydx
