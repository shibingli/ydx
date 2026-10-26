# middleware/cors — 跨源资源共享

`github.com/shibingli/ydx/middleware/cors` 应用给定的跨源策略。它强制三条硬规则：开启
`AllowCredentials` 时响应绝不回 `*`，而是回显具体来源；预检请求直接以 204 短路；来源未
匹配时不写任何 CORS 头，而不是返回错误。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/cors` |
| 包名 | `cors` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `CORS(CORSOptions)`：YD 路由中间件。
- `Middleware(CORSOptions)`：原生 `net/http` 包装器。
- `CORSOptions`：
  - `AllowOrigins`：`*`、`*.example.com` 子域匹配、带协议的精确匹配。
  - `AllowMethods`、`AllowHeaders`、`ExposeHeaders`。
  - `AllowCredentials`、`MaxAge`。

## 特性

- **凭证安全**：`AllowCredentials` 为真时绝不以 `*` 作为 `Access-Control-Allow-Origin`，
  而是回显请求的具体来源。
- **预检短路**：`OPTIONS` + `Access-Control-Request-Method` 直接 204，不进入业务链。
- **未匹配不报错**：来源不在允许列表时不写 CORS 头，由浏览器执行同源策略。
- **无分配来源拆分**：`splitOrigin` 用逐字节扫描代替 `url.Parse`，避免每请求构造 URL、
  userinfo 与 host 字符串。
- **构造期预计算**：来源模式在装配期解析，请求路径只做匹配与写头。
- **双入口共享实现**：YD 与原生路径语义一致。

## 快速开始

### YD 路由

```go
r.Use(cors.CORS(cors.CORSOptions{
	AllowOrigins:     []string{"https://app.example.com", "*.example.org"},
	AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	AllowHeaders:     []string{"Authorization", "Content-Type"},
	ExposeHeaders:    []string{"X-Request-Id"},
	AllowCredentials: true,
	MaxAge:           10 * time.Minute,
}))
```

### 原生 net/http

```go
handler := cors.Middleware(cors.CORSOptions{
	AllowOrigins: []string{"*"},
})(mux)
```

## 应用场景

- **SPA + API 分离**：前端域名与 API 域名不同。
- **多租户子域**：`*.example.com` 匹配租户子域。
- **携带 Cookie/Authorization**：`AllowCredentials` 与精确来源回显。
- **预检优化**：`MaxAge` 减少预检请求。
- **内部工具**：按环境收窄允许来源。

## 性能指标

基准模块：[`benchmarks/middleware`](../../benchmarks/middleware/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | ydx/cors | rs/cors | 无中间件 |
|---|---:|---:|---:|
| 带 `Origin` 的 GET | **36.69 ns** | 53.16 ns | 4.30 ns |

- 领先 rs/cors 约 31%；16 B/op、1 alloc/op（响应头值）。
- 预计算策略 + 无分配来源拆分 + 直接写响应头是主要收益来源。
- 简单 GET 之外的能力（预检、凭证、多来源）语义与 rs/cors 不完全等价，比较仅覆盖该
  微基准。

> 完整表格与口径见基准 README。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`middleware/reqlog`](../reqlog/README.md)：头处理辅助。
- [`router`](../../router/README.md)：YD 路由与 `Ctx`。

基准对比对象 [`rs/cors`](https://github.com/rs/cors)（MIT），仅出现在
`benchmarks/middleware`。

## 相关模块

- [`middleware`](../README.md)：聚合门面。
- [`router`](../../router/README.md)：路由与中间件。
- [`middleware/compress`](../compress/README.md)：另一个按请求头协商的插件。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
