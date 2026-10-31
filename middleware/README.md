# middleware — 中间件聚合门面

`github.com/shibingli/ydx/middleware` 是 ydx 中间件插件的聚合门面。每个插件都在独立模块
中——`accesslog`、`asyncafter`、`compress`、`cors`、`ratelimit`、`recovery`、`requestid`——
本包以原有的 `middleware.*` 名称重新导出它们的公开 API，并额外提供 `Chain`、`Adapt` 与
`CacheBypass`。

> WAF 已迁移到独立模块 `github.com/shibingli/ydx/waf`（自研 SecLang 引擎），不在
> `middleware/` 目录下，也**不在**本门面重新导出；原 `middleware/waf`（Coraza 封装 v1）
> 已移除。需要 WAF 的服务请直接导入 `github.com/shibingli/ydx/waf`。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware` |
| 包名 | `middleware` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- 重新导出插件 API：`RequestID`、`CORS`、`Compress`、`AccessLog`、`AccessLogAsync`、
  `RateLimit`、`Recover`，以及相关 Options 类型。
- `Chain(mw...)`：把多个 `router.Middleware` 组合为一个。
- `Adapt(next, mw...)`：把同一套中间件套在原生 `http.Handler` 上。
- `CacheBypass(match)`：请求级缓存旁路中间件。
- 重新导出 `KeyFunc`、`LimitStore`、`MemoryStore`、`RedisStore`、`AsyncAfter`、
  `OverflowPolicy` 等类型。

## 特性

- **兼容旧 API**：既有 YD 调用点可继续使用 `middleware.Recover`、`middleware.CORS` 等名称，
  只需依赖本模块。
- **按需拆分**：对依赖图敏感的项目可以直接依赖单个插件模块，避免把全部插件及其传递依赖
  带进来。
- **双入口**：每个插件同时提供 YD 路由中间件与原生 `net/http` 包装器。
- **组合安全**：`Chain` / `Adapt` 只做组合，不改变插件语义；中间件顺序仍由调用方决定。
- **缓存旁路**：`CacheBypass` 与 `cache.WithBypass` 配合，让特定请求跳过缓存。

## 快速开始

### YD 路由

```go
import (
	"github.com/shibingli/ydx/middleware"
	"github.com/shibingli/ydx/router"
)

r := router.New()
r.Use(
	middleware.RequestID(""),
	middleware.Recover(logger),
	middleware.CORS(middleware.CORSOptions{AllowOrigins: []string{"*"}}),
	middleware.Compress(middleware.CompressOptions{}),
)
```

### 原生 net/http

```go
handler := middleware.Adapt(mux,
	middleware.RequestID(""),
	middleware.Recover(logger),
	middleware.CORS(middleware.CORSOptions{AllowOrigins: []string{"*"}}),
	middleware.Compress(middleware.CompressOptions{}),
)
_ = http.ListenAndServe(":8080", handler)
```

### 组合与缓存旁路

```go
chain := middleware.Chain(
	middleware.RequestID(""),
	middleware.Recover(logger),
)

r.Use(chain)
r.Use(middleware.CacheBypass(func(req *http.Request) bool {
	return req.Header.Get("Cache-Control") == "no-cache"
}))
```

## 应用场景

- **统一接入**：新项目一次性引入全部常用中间件。
- **渐进迁移**：旧代码继续使用 `middleware.*` 名称，内部逐步切换为独立插件。
- **自定义组合**：按路由组或环境组合不同中间件链。
- **缓存一致性**：写后读请求通过 `CacheBypass` 跳过缓存。
- **原生服务**：不使用 YD 路由时用 `Adapt` 复用同一套实现。

## 性能指标

本模块本身没有独立基准；它只做符号重导出与组合，运行时成本等于所选插件之和。各插件的
实测数据见对应基准：

| 插件 | 代表结果 | 基准 |
|---|---|---|
| CORS | 36.7 ns（GET） | [benchmarks/middleware](../benchmarks/middleware/README.md) |
| Recovery | 7.85 ns（无 panic） | 同上 |
| Request ID | 170.2 ns | 同上 |
| Rate limit | 136.5 ns（放行） | 同上 |
| Compress | 5.268 µs（16 KiB gzip） | 同上 |
| Access log | 821.5 ns（丢弃写入器） | 同上 |

> `Chain` / `Adapt` 只增加一次函数调用/适配开销；`Adapt` 0/1/2 个中间件约
> 18.4/21.8/24.2 ns（见 router 基准）。中间件顺序会影响语义与成本，请按插件文档组合。

## 第三方依赖与鸣谢

本模块的直接依赖全部是 ydx 内部模块（cache、log、各插件、router），没有直接第三方
运行时依赖。传递依赖来自插件：

| 传递依赖 | 版本 | 许可证 | 来源插件 |
|---|---|---|---|
| [`andybalholm/brotli`](https://github.com/andybalholm/brotli) | v1.2.7 | MIT | `middleware/compress` |
| [`klauspost/compress`](https://github.com/klauspost/compress) | v1.20.3 | BSD-3-Clause | `middleware/compress` |
| [`redis/go-redis/v9`](https://github.com/redis/go-redis) | v9.23.0 | BSD-2-Clause | `middleware/ratelimit` |

测试使用 [`alicebob/miniredis/v2`](https://github.com/alicebob/miniredis)（MIT）。

## 相关模块

- [`middleware/accesslog`](accesslog/README.md)
- [`middleware/asyncafter`](asyncafter/README.md)
- [`middleware/compress`](compress/README.md)
- [`middleware/cors`](cors/README.md)
- [`middleware/ratelimit`](ratelimit/README.md)
- [`middleware/recovery`](recovery/README.md)
- [`middleware/requestid`](requestid/README.md)
- [`middleware/reqlog`](reqlog/README.md)
- [`waf`](../waf/README.md)（独立模块，不在本门面重导出）
- [`router`](../router/README.md)、[`cache`](../cache/README.md)

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
