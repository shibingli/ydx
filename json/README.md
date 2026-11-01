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

- 导出与 `encoding/json` 完全对齐的符号集：
  - 函数：`Marshal`、`Unmarshal`、`MarshalIndent`、`Valid`、`Compact`、`Indent`、
    `HTMLEscape`、`NewEncoder`、`NewDecoder`。
  - `Encoder`：`Encode`、`SetEscapeHTML`、`SetIndent`。
  - `Decoder`：`Decode`、`UseNumber`、`DisallowUnknownFields`、`Token`、`More`、
    `Buffered`、`InputOffset`。
  - 类型别名：`Number`、`RawMessage`、`Delim`、`Token`、`Marshaler`、`Unmarshaler`，以及
    全部标准错误类型（`SyntaxError`、`UnmarshalTypeError`、`InvalidUnmarshalError`、
    `UnsupportedTypeError`、`UnsupportedValueError`、`MarshalerError` 与两个已弃用类型）
    和 v1/v2 `Options` 辅助函数。
- `Prewarm(samples ...any)`：启动期预编译编码/解码计划。
- `Backend()`：返回 `"yd-native"` 或 `"encoding/json"`。
- 跨后端稳定错误：`ErrSyntax`、`ErrTypeMismatch`，可用 `errors.Is` 判定；同时可用
  `errors.As` 取出与标准库同类型、同文案、同字节偏移的 `*json.SyntaxError`、
  `*json.UnmarshalTypeError` 等错误。

## 兼容 API

与 `encoding/json` v1 逐项对齐的完整接口：

| 类别 | 符号 |
|---|---|
| 函数 | `Marshal`、`Unmarshal`、`MarshalIndent`、`Valid`、`Compact`、`Indent`、`HTMLEscape`、`NewEncoder`、`NewDecoder` |
| `Encoder` | `Encode`、`SetEscapeHTML`、`SetIndent` |
| `Decoder` | `Decode`、`UseNumber`、`DisallowUnknownFields`、`Token`、`More`、`Buffered`、`InputOffset` |
| 类型 | `Number`、`RawMessage`、`Delim`、`Token`、`Marshaler`、`Unmarshaler`（均为 `encoding/json` 类型别名，方法与语义完全继承） |
| 错误类型 | `SyntaxError`、`UnmarshalTypeError`、`InvalidUnmarshalError`、`UnsupportedTypeError`、`UnsupportedValueError`、`MarshalerError`、`InvalidUTF8Error`、`UnmarshalFieldError` |
| v1/v2 选项 | `Options` 与全部 `DefaultOptionsV1` / `CallMethodsWithLegacySemantics` 等辅助函数 |

错误类型、错误文案与字节偏移在两个后端下都与标准库一致，`errors.As` 可直接使用；
`Token` 序列、`More`/`Buffered`/`InputOffset`、`SetIndent`、`DisallowUnknownFields`
的行为均有逐项对拍测试覆盖。

Unicode 与标签别名同样逐项对拍 `encoding/json`：CJK、表情符号（含 ZWJ 组合）、组合
附加符、RTL 文本、控制字符、U+2028/U+2029 与非法 UTF-8 在字符串、对象键与字段名中的
编码/解码；`json:"别名"`、`json:"🚀"`、含空格或标点的标签名、保留字符截断规则、
`omitempty`/`omitzero`/`string`/`-` 选项以及 `SetEscapeHTML` 对字段名的转义。

## 特性

- **语义基线是标准库**：字符串 HTML 转义、map key 排序、`[]byte` 走 StdEncoding Base64、
  `time.Time` 走 RFC3339Nano，并兼容 `json.Marshaler`、`json.TextMarshaler`、
  `json.RawMessage`、`omitempty`。`Compact` / `Indent` / `HTMLEscape` 的输出、
  `Decoder.Token` / `More` / `Buffered` / `InputOffset` 的行为、`SetIndent` /
  `DisallowUnknownFields` 的语义均与 `encoding/json` 对拍一致。
- **错误类型兼容**：错误路径上用标准库复解析失败输入，取得与 `encoding/json` 完全相同的
  错误类型、文案与偏移；成功路径不受影响。
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
| `Marshal/one` | **61.88 ns** | 318.5 ns | 99.23 ns | 94.86 ns |
| `Marshal/many`（64 对象） | **2.799 µs** | 12.93 µs | 4.503 µs | 3.357 µs |
| `Marshal/large`（1024 对象） | **43.07 µs** | 208.4 µs | 71.58 µs | 50.01 µs |
| `Unmarshal/one` | **120.7 ns** | 559.2 ns | 137.2 ns | 193.0 ns |
| `Unmarshal/many` | **7.233 µs** | 30.15 µs | 7.697 µs | 12.28 µs |
| `Unmarshal/large` | **110.1 µs** | 458.4 µs | 121.1 µs | 160.2 µs |

7 字段 `record` 载荷（含 `time.Time` 与长小数）：

| 场景 | ydx/json | go-json | sonic-std | `encoding/json` |
|---|---:|---:|---:|---:|
| `Marshal/n=1000` | **87.91 µs** | 110.4 µs | 157.1 µs | 295.1 µs |
| `Unmarshal/n=1000` | **162.1 µs** | 180.9 µs | 286.9 µs | 691.1 µs |

- 相对标准库：编码快约 4.6–5.1 倍，解码快约 4.2–4.6 倍。
- 相对 goccy：六个主场景全部领先；相对 sonic：编码快约 14%–35%，解码快约 31%–41%。
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
