# middleware/reqlog — 共享请求日志设施

`github.com/shibingli/ydx/middleware/reqlog` 保存 ydx 中间件插件共享的请求日志机制：
池化的响应写入器捕获，以及热路径使用的头部辅助函数。它以公开路径发布，供各插件模块共享
同一份实现；其 API 属于共享实现细节，不构成稳定性承诺。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/reqlog` |
| 包名 | `reqlog` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 稳定性 | 共享实现细节，无稳定性承诺 |

## 功能

- `Begin(c)` / `End(c, capture)`：开始/结束一次响应捕获。
- `Capture`：记录状态码与响应字节数。
- `Options`：`TrustedProxies` 等共享选项。
- `AppendVary(h, value)`：安全追加 `Vary` 头。
- `HeaderValue(h, canonicalKey)`：读取已规范化头的首值。
- `IsUpgradeRequest(r)`：判断协议升级请求。
- `Capture.Status()` / `Capture.Bytes()`：读取捕获结果。

## 特性

- **池化捕获**：`Capture` 从池中获取、用完归还，避免每请求分配捕获结构。
- **升级请求识别**：`IsUpgradeRequest` 让访问日志与压缩插件跳过 WebSocket 握手。
- **头处理零分配**：`AppendVary` 与 `HeaderValue` 针对热路径优化，避免重复规范化与
  临时切片。
- **单一实现**：accesslog、asyncafter、compress、cors 等插件共享，避免多份捕获逻辑
  漂移。
- **语义稳定优先**：不追求公开 API 兼容承诺，插件可以随仓库一起演进。
- **缓冲复用**：与 `buffpool` 配合复用捕获/拷贝缓冲。

## 快速开始

`reqlog` 主要供中间件插件使用。自定义插件可以这样捕获响应：

```go
package mymiddleware

import (
	"github.com/shibingli/ydx/middleware/reqlog"
	"github.com/shibingli/ydx/router"
)

func MyLog() router.Middleware {
	return func(c *router.Ctx) {
		if reqlog.IsUpgradeRequest(c.Request) {
			c.Next()
			return
		}
		capture := reqlog.Begin(c)
		defer func() {
			status := capture.Status()
			bytes := capture.Bytes()
			reqlog.End(c, capture)
			// 记录 status 与 bytes。
			_ = status
			_ = bytes
		}()
		c.Next()
	}
}
```

追加 `Vary`：

```go
reqlog.AppendVary(w.Header(), "Accept-Encoding")
```

## 应用场景

- **自定义访问日志**：复用池化捕获，避免自行包装 `ResponseWriter`。
- **压缩插件**：判断是否需要包装响应。
- **访问日志/异步日志**：共享状态码与字节数采集。
- **CORS/Vary 头**：安全追加缓存区分头。
- **升级请求**：在 WebSocket 握手前快速判断并跳过包装。

## 性能指标

本模块没有独立基准；其收益体现在使用它的插件基准中：

- `Capture` 来自池，避免每请求分配捕获对象。
- `accesslog` 同步路径在丢弃写入器上约 821.5 ns（含字段与日志编码）；池化捕获是其中
  固定成本的一部分。
- `AppendVary` / `HeaderValue` 在热路径上避免重复 canonical 化与临时切片。
- `IsUpgradeRequest` 是 O(1) 头/连接检查，不做 body 读取。
- 具体数字见 [`benchmarks/middleware`](../../benchmarks/middleware/README.md) 与
  [`middleware/accesslog`](../accesslog/README.md)。

> 本包 API 可能随插件演进调整；外部项目若需要稳定 API，应直接使用具体插件模块。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`buffpool`](../../buffpool/README.md)：缓冲复用。
- [`router`](../../router/README.md)：YD 路由与 `Ctx`。

## 相关模块

- [`middleware/accesslog`](../accesslog/README.md)
- [`middleware/asyncafter`](../asyncafter/README.md)
- [`middleware/compress`](../compress/README.md)
- [`middleware/cors`](../cors/README.md)
- [`middleware`](../README.md)

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
