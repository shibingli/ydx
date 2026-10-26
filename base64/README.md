# base64 — 硬件自适应 Base64 编解码

`github.com/shibingli/ydx/base64` 是 ydx 的 Base64 统一入口。它在所有架构上默认使用
自研编解码器，按 CPU 指令集在运行时选择最宽的内核，并对外暴露与 `encoding/base64`
一致的四个编码变体与方法集。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/base64` |
| 包名 | `base64` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- 四个编码变体：`StdEncoding`、`RawStdEncoding`、`URLEncoding`、`RawURLEncoding`。
- 与 `encoding/base64` 对齐的方法：`Encode`、`Decode`、`EncodeToString`、`DecodeString`、
  `EncodedLen`、`DecodedLen`、`AppendEncode`、`AppendDecode`。
- 额外提供 `AppendDecodeString`（直接读取字符串，不转 `[]byte`）以及
  `EncodeParallel` / `DecodeParallel`（按 `sysinfo.Parallelism()` 自动分块）。
- `Backend()` 返回当前后端名称：默认构建为 `"yd-native"`，`b64x_std` 标签下为
  `"encoding/base64"`。

## 特性

- **运行时指令集分流**：amd64 按 `VBMI2 > VBMI > AVX-512BW > AVX2 > 标量` 选择手写内核；
  arm64 使用手写 NEON；其它架构使用纯 Go 标量内核。不需要 `GOEXPERIMENT=simd`。
- **零拷贝 append**：`AppendEncode` / `AppendDecode` 在目标缓冲容量充足时复用底层数组，
  不产生新的分配；`DecodeString` 只分配结果本身。
- **错误可判定**：目标缓冲过短返回 `ErrShortBuffer` 而不是越界 panic；非法数据可用
  `errors.Is(err, ErrInvalidData)` 判定，同时保留底层错误。
- **语义一致**：长度计算与编码结果与 `encoding/base64` 逐字节一致；所有后端行为一致。
- **可控回退**：显式 `b64x_std` 构建标签可切回标准库，用于排障与兼容性对照。
- **无 cgo**：纯 Go + 手写汇编内核，默认 `CGO_ENABLED=0` 可构建。

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/base64"
)

func main() {
	// 复用调用方缓冲，避免中间分配。
	dst := make([]byte, 0, base64.StdEncoding.EncodedLen(1024))
	dst = base64.StdEncoding.AppendEncode(dst, []byte("hello ydx"))
	fmt.Println(string(dst))

	raw, err := base64.URLEncoding.DecodeString("aGVsbG8teWR4")
	if err != nil {
		return
	}
	fmt.Println(string(raw))
}
```

## 应用场景

- **JWT**：`RawURLEncoding` 用于 header/payload/signature 的无填充 URL 安全编码。
- **API 载荷**：把二进制字段嵌入 JSON 或表单。
- **Data URL / 内联资源**：图片、字体、图标等小资源的文本封装。
- **协议与消息**：WebSocket、SSE、消息队列中的二进制转文本。
- **高吞吐网关**：大文件或大消息的 Base64 编解码，依赖 SIMD 块内核降低 CPU 成本。

## 性能指标

基准模块：[`benchmarks/base64`](../benchmarks/base64/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395（Zen 5，AVX-512 VBMI/VBMI2，`GOMAXPROCS=32`）、Go 1.27.3、Linux，
`-count=3~5`、`-benchtime=500ms` 中位数。上方 Linux 主表采集于 v0.1.9；cloudwego
同机对照见本节末尾，使用当前 go.mod 固定的 v0.1.11，来自另一台 Windows 开发机，
不能与上表跨机比较。

| 场景 | ydx/base64 | cristalhq/base64 | `encoding/base64` |
|---|---:|---:|---:|
| `Encode` 32 B | **5.58 ns** | 9.57 ns | 14.38 ns |
| `Decode` 32 B | **10.47 ns** | 12.93 ns | 19.92 ns |
| `Encode` 1 KiB | **23.4 ns** | 200 ns | 470 ns |
| `Decode` 1 KiB | **42.1 ns** | 274 ns | 455 ns |
| `Encode` 64 KiB | **1.03 µs** | 12.8 µs | 29.9 µs |
| `Decode` 64 KiB | **2.34 µs** | 17.4 µs | 28.6 µs |
| `Encode` 1 MiB | **55.5 GB/s** | 5.05 GB/s | 2.39 GB/s |
| `Decode` 1 MiB | **27.1 GB/s** | 3.73 GB/s | 2.28 GB/s |

- 块路径（1 KiB / 64 KiB）领先 cristalhq 约 6.5–12.5 倍，领先标准库约 11–29 倍。
- 16 B 短路径领先 cristalhq 约 1%–14%，其中 `EncodeToString` 16 B 的 1% 已在噪声边界。
- `DecodeString` / `EncodeToString` 均只有结果分配；`AppendEncode` / `AppendDecode`
  在容量充足时零分配。
- arm64 上 NEON 块内核同样领先两个对照实现；短输入走标量 SWAR 路径，不额外引入
  NEON 短块开销。

### cloudwego/base64x 同机对照（Windows 开发机）

以下数字来自 Intel Core i9-10980HK（AVX2，16 逻辑 CPU）、Windows 11、Go 1.27.3、
`GOMAXPROCS=16`、`-count=5 -benchtime=500ms` 中位数；与上方 Linux Zen 5 表不是同一台
主机，不能跨表比较绝对 ns/op。完整表（含字符串入口与并行场景）见
[`benchmarks/base64`](../benchmarks/base64/README.md)。

| 场景 | ydx/base64 | cloudwego/base64x |
|---|---:|---:|
| `Encode` 32 B | **17.29 ns** | 19.21 ns |
| `Encode` 1 KiB | 114.7 ns | 110.7 ns |
| `Encode` 1 MiB | 110.24 µs | **103.91 µs** |
| `Decode` 32 B | **27.95 ns** | 35.34 ns |
| `Decode` 1 KiB | 167.9 ns | 169.7 ns |
| `Decode` 1 MiB | 161.09 µs | **151.58 µs** |

- 短输入（32 B）ydx 领先；1 KiB 基本持平；1 MiB 块路径 cloudwego 领先约 6%，差距处于
  同一量级。
- cloudwego v0.1.7 的 JIT 加载器依赖 `sonic/loader`；上游请求的 v0.5.1 在 Go 1.27.3 上
  会中止进程，基准模块显式固定为 v0.5.2。
- 正确性由 `TestCodecFixtures` / `TestCodecsAgree` 覆盖：四种实现输出逐字节一致，
  并能互相解码。

> 绝对值受 CPU 频率/温度与后台负载影响；同一轮内小于约 5% 的差异视为噪声。完整表格、
> arm64 数据与复现命令见基准 README。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只依赖 Go 标准库与 ydx 内部模块（`errs`、`sysinfo`）。

基准对比对象：

- Go 标准库 `encoding/base64`（BSD-3-Clause）。
- [`cristalhq/base64`](https://github.com/cristalhq/base64)（MIT），纯 Go SWAR 实现。
- [`cloudwego/base64x`](https://github.com/cloudwego/base64x)（Apache-2.0），JIT/汇编实现。
  基准模块通过 `sonic/loader v0.5.2` 覆盖其请求的 v0.5.1，避免 Go 1.27.3 上的 JIT 加载
  崩溃；该依赖只出现在 `benchmarks/base64`，不进入本产品模块。

## 相关模块

- [`json`](../json/README.md)：`[]byte` 字段按标准 Base64 编码，复用本模块语义。
- [`jwt`](../jwt/README.md)：JWS 的 Base64URL 编解码。
- [`log`](../log/README.md)：`[]byte` 字段按 RFC 4648 标准 Base64 输出。
- [`guomi`](../guomi/README.md)：密文/签名的文本编码。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
