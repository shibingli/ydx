# json — 硬件自适应 JSON 编解码

`github.com/shibingli/ydx/json` 是 ydx 的 JSON 统一入口。默认构建使用自研原生编解码器：
amd64 使用手写 SSE2/AVX2/AVX-512BW 字符串扫描内核，arm64 使用手写 NEON，其它架构使用
可移植 SWAR/标量路径；显式 `jsonx_std` 标签可回退到标准库。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/json` |
| 包名 | `json` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- 导出与 `encoding/json` 对齐的符号集：`Marshal`、`Unmarshal`、`MarshalIndent`、`Valid`、
  `NewEncoder`、`NewDecoder`。
- `Prewarm(samples ...any)`：启动期预编译编码/解码计划。
- `Backend()`：返回 `"yd-native"` 或 `"encoding/json"`。
- 跨后端稳定错误：`ErrSyntax`、`ErrTypeMismatch`，可用 `errors.Is` 判定。

## 特性

- **语义基线是标准库**：字符串 HTML 转义、map key 排序、`[]byte` 走 StdEncoding Base64、
  `time.Time` 走 RFC3339Nano，并兼容 `json.Marshaler`、`json.TextMarshaler`、
  `json.RawMessage`、`omitempty`。
- **无反射热路径**：按类型缓存编码/解码计划；字段可直接按内存读取的结构体走无反射快速
  编码器；字符串扫描由 SIMD 内核完成。
- **池化缓冲**：中/大载荷先写池化缓冲，再复制为精确大小结果；结构体切片使用按类型池化
  缓冲与一次精确最终分配；字符串使用只追加 arena。
- **启动期预热**：固定载荷类型的服务可在启动期调用 `Prewarm`，把计划构建成本移出首个
  请求；嵌套结构体、切片、数组与 map 递归预热。
- **并发扩展**：解码使用每 P 的解码器池，16→32 P 仍继续提升。
- **无 `GOEXPERIMENT`**：不需要 `GOEXPERIMENT=simd`，也不依赖 cgo。

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/json"
)

type User struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

func main() {
	// 启动期预热固定载荷类型。
	json.Prewarm(User{}, (*User)(nil), (*[]User)(nil))

	b, err := json.Marshal(User{ID: 1, Name: "Ada"})
	if err != nil {
		return
	}

	var out User
	if err := json.Unmarshal(b, &out); err != nil {
		return
	}
	fmt.Println(string(b), out.Name)
}
```

回退到标准库排障：

```bash
go build -tags jsonx_std ./...
```

## 应用场景

- **高 QPS API**：请求/响应体编解码，减少 CPU 与分配。
- **固定载荷服务**：启动期 `Prewarm`，避免首个请求承担计划构建延迟。
- **网关/BFF**：大数组与嵌套对象的序列化。
- **日志与审计**：结构化记录中的嵌套字段编码。
- **跨架构部署**：amd64、arm64 与其它架构共用一套 API。

## 性能指标

基准模块：[`benchmarks/json`](../benchmarks/json/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395（Zen 5，AVX-512）、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms`
中位数。

| 场景 | ydx/json | `encoding/json` | goccy | sonic |
|---|---:|---:|---:|---:|
| `Marshal/one` | **61.2 ns** | 305.7 ns | 93.1 ns | 89.0 ns |
| `Marshal/many`（64 对象） | **2.50 µs** | 12.9 µs | 4.18 µs | 3.01 µs |
| `Marshal/large`（1024 对象） | **39.8 µs** | 204 µs | 66.8 µs | 46.7 µs |
| `Unmarshal/one` | **136.5 ns** | 600.2 ns | 142.0 ns | 229.1 ns |
| `Unmarshal/many` | **7.71 µs** | 30.9 µs | 7.77 µs | 13.0 µs |
| `Unmarshal/large` | **120.2 µs** | 481.1 µs | 131.6 µs | 214.0 µs |

7 字段 `record` 载荷（含 `time.Time` 与长小数）：

| 场景 | ydx/json | go-json | sonic-std | `encoding/json` |
|---|---:|---:|---:|---:|
| `Marshal/n=1000` | **89.68 µs** | 116.19 µs | 152.54 µs | 302.24 µs |
| `Unmarshal/n=1000` | **174.3 µs** | 195.2 µs | 330.6 µs | 708.0 µs |

- 相对标准库：编码快约 5.0–5.2 倍，解码快约 4.0–4.4 倍。
- 相对 goccy：六个主场景全部领先；相对 sonic：编码快约 15%–31%，解码快约 40%–44%。
- 分配特征与代码生成型实现持平：`Marshal/one` 96 B / 1 alloc，`Marshal/many` 约
  6.1 KiB / 1 alloc；`Unmarshal` 的分配包含目标值本身。
- `Prewarm` 对复杂类型可把首次 `Marshal` 从 42.1 µs 降到 6.43 µs（约 6.6×），
  首次 `Unmarshal` 从 20.8 µs 降到 8.35 µs（约 2.5×）。

> 完整表格、arm64 与并行数据见基准 README；同一轮内小于约 5% 的差异视为噪声。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只依赖 Go 标准库与 ydx 内部模块（`base64`、`errs`、`sysinfo`）。

基准对比对象：`encoding/json`、[`goccy/go-json`](https://github.com/goccy/go-json)、
[`json-iterator/go`](https://github.com/json-iterator/go)、
[`bytedance/sonic`](https://github.com/bytedance/sonic)、
[`segmentio/encoding`](https://github.com/segmentio/encoding) 与
[`go-json-experiment/json`](https://github.com/go-json-experiment/json)。这些库只出现在
`benchmarks/json`，不进入产品模块依赖。

## 相关模块

- [`base64`](../base64/README.md)：`[]byte` 字段的 Base64 编码。
- [`redis`](../redis/README.md)、[`cache`](../cache/README.md)：缓存载荷序列化。
- [`asynq`](../asynq/README.md)：任务 Payload 编解码。
- [`openapi`](../openapi/README.md)：文档模型只经本模块序列化。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
