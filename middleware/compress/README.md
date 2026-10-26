# middleware/compress — 响应压缩协商

`github.com/shibingli/ydx/middleware/compress` 依据 `Accept-Encoding` 协商并应用 brotli、
zstd 或 gzip 响应压缩。编码只在响应确实大到值得压缩时才协商；HEAD 请求、协议升级、排除
前缀、SSE、无正文/已编码正文、小于 `MinSize` 的正文，以及带 `Cache-Control: no-transform`
的响应一律不包装。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/compress` |
| 包名 | `compress` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认最小压缩 | 1024 B |
| 默认优先级 | zstd > brotli > gzip |

## 功能

- `Compress(CompressOptions)`：YD 路由中间件。
- `Middleware(CompressOptions)`：原生 `net/http` 包装器。
- `ParseAcceptEncoding(h)`：把 `Accept-Encoding` 解析为 `encoding → q` 映射。
- `Negotiate(acceptEncoding, algos)`：按客户端偏好与算法优先级选择编码。
- `Algorithm`：`Gzip`、`Brotli`、`Zstd`，含 `Name()` 与 `Encoding()`。
- `CompressOptions`：算法优先级、最小大小、排除前缀、压缩级别。

## 特性

- **默认优先级**：`Zstd > Brotli > Gzip`；zstd 在动态载荷上压缩率与 brotli 持平或更好，
  CPU 成本更低；gzip 作为通用兜底。
- **Brotli 质量 4**：默认质量 4，在保持压缩率的同时显著降低 CPU（库默认 6）。
- **跳过规则**：HEAD、协议升级、排除前缀（默认 `/ws`、`/sse`、`/events`）、SSE、
  无正文、已编码、`no-transform`、小于 `MinSize`。
- **池化复用**：编码器与待压缩正文缓冲来自池，响应结束后归还。
- **q 值解析**：支持 `q=0` 显式禁用与 `*` 通配。
- **双入口共享实现**：YD 与原生路径语义一致。
- **Vary 头**：正确追加 `Accept-Encoding`，便于缓存分层。

## 快速开始

### YD 路由

```go
r.Use(compress.Compress(compress.CompressOptions{
	Algorithms: []compress.Algorithm{compress.Zstd, compress.Brotli, compress.Gzip},
	MinSize:    1024,
}))
```

### 原生 net/http

```go
handler := compress.Middleware(compress.CompressOptions{})(mux)
```

自定义排除前缀：

```go
r.Use(compress.Compress(compress.CompressOptions{
	ExcludePatterns: []string{"/ws", "/sse", "/events", "/download"},
}))
```

## 应用场景

- **API 网关**：JSON 响应压缩，降低带宽与尾延迟。
- **HTML/SSR**：页面压缩，优先 zstd/brotli。
- **静态资源**：与预压缩资源配合（已编码响应跳过）。
- **SSE/WebSocket**：默认跳过，避免流式协议被压缩缓冲破坏。
- **带宽敏感部署**：移动网络、跨地域链路。

## 性能指标

基准模块：[`benchmarks/compress`](../../benchmarks/compress/README.md) 与
[`benchmarks/middleware`](../../benchmarks/middleware/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

16 KiB `text/html`、`Accept-Encoding: gzip`：

| 场景 | ydx/compress | gzhttp |
|---|---:|---:|
| 16 KiB gzip | 5.268 µs | 5.213 µs |

压缩比（输入字节 / 输出字节，越大越好）：

| 编码 | 压缩比 |
|---|---:|
| gzip | 136.5 |
| zstd | 277.7 |
| brotli | 364.1 |

完整中间件（YD 路由，16 KiB）：

| 编码 | 串行 | 并行均摊 |
|---|---:|---:|
| gzip | 8.960 µs | 192.60 ns |
| zstd | 7.628 µs | 170.40 ns |
| brotli | 14.074 µs | 642.10 ns |
| 直通（不压缩） | — | 8.85 ns |

- gzip 与 gzhttp 差异约 1%，同一轮内视为持平；ydx 额外支持 brotli/zstd。
- 协商解析：无分配扫描 114.4 ns，旧 map 解析路径 246.6 ns。

> 压缩是 CPU 密集操作；绝对 ns 受载荷可压缩性与 CPU 影响。完整表格、压缩率与资源占用见
> 基准 README。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`andybalholm/brotli`](https://github.com/andybalholm/brotli) | v1.2.7 | MIT | brotli 编码 |
| [`klauspost/compress`](https://github.com/klauspost/compress) | v1.20.3 | BSD-3-Clause | gzip 与 zstd 编码 |

仓库内依赖：`buffpool`、`errs`、`middleware/reqlog`、`router`。

## 相关模块

- [`middleware`](../README.md)：聚合门面。
- [`buffpool`](../../buffpool/README.md)：压缩缓冲复用。
- [`websocket`](../../websocket/README.md)：permessage-deflate。
- [`sse`](../../sse/README.md)：默认跳过压缩。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
