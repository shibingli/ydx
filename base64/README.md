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

- **运行时指令集分流**：amd64 编码按 `VBMI > AVX-512BW > AVX2 > 标量`、解码按
  `AVX-512BW > AVX2 > 标量` 选择手写内核；arm64 使用手写 NEON；其它架构使用纯 Go
  标量内核。不需要 `GOEXPERIMENT=simd`。
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
AI MAX+ 395（Zen 5，AVX-512 VBMI，`GOMAXPROCS=32`）、Go 1.27.3、Linux；1 KiB/64 KiB 行取
同进程 `BenchmarkEncode`/`BenchmarkDecode`（`-count=10`、`-benchtime=500ms`），32 B/1 MiB
行取按实现独立进程的 `BenchmarkFrameworkEncode`/`BenchmarkFrameworkDecode`（`-count=10`、
`-benchtime=500ms`），均为中位数。

| 场景 | ydx/base64 | cloudwego/base64x | cristalhq/base64 | `encoding/base64` |
|---|---:|---:|---:|---:|
| `Encode` 32 B | **5.83 ns** | 7.51 ns | 9.59 ns | 15.04 ns |
| `Decode` 32 B | **10.40 ns** | 11.58 ns | 12.77 ns | 19.35 ns |
| `Encode` 1 KiB | **19.94 ns** | 42.40 ns | 200.10 ns | 472.15 ns |
| `Decode` 1 KiB | **30.52 ns** | 59.00 ns | 274.90 ns | 453.95 ns |
| `Encode` 64 KiB | **1.027 µs** | 2.536 µs | 12.917 µs | 29.879 µs |
| `Decode` 64 KiB | **1.590 µs** | 3.178 µs | 17.459 µs | 28.317 µs |
| `Encode` 1 MiB | **56.3 GB/s** | 25.6 GB/s | 5.04 GB/s | 2.19 GB/s |
| `Decode` 1 MiB | **41.4 GB/s** | 20.4 GB/s | 3.73 GB/s | 2.30 GB/s |

- 对 cloudwego/base64x：1 KiB 编码/解码领先约 2.1×/1.9×，64 KiB 约 2.5×/2.0×，
  1 MiB 约 2.2×/2.0×。
- 对 cristalhq/base64：1 KiB/64 KiB 块路径领先约 9.0–12.6×；对 `encoding/base64`
  领先约 14.9–29.1×。
- 32 B 短路径领先 cloudwego 约 29%/11%，领先 cristalhq 约 64%/23%。
- `DecodeString` / `EncodeToString` 均只有结果分配；`AppendEncode` / `AppendDecode`
  在容量充足时零分配。
- arm64 Neoverse-N2 上 1 KiB 编码/解码为 134.5 ns/281.3 ns，领先 cloudwego 约
  5.9×/2.9×；1 MiB 解码 269.7 µs，领先约 3.0×。完整数据见基准 README。

### cloudwego/base64x 同机对照（Windows 开发机）

以下数字来自 Intel Core i9-10980HK（AVX2，16 逻辑 CPU）、Windows 11、Go 1.27.3、
`GOMAXPROCS=16`、`-count=5 -benchtime=500ms` 中位数；与上方 Linux Zen 5 表不是同一台
主机，不能跨表比较绝对 ns/op。完整表（含字符串入口与并行场景）见
[`benchmarks/base64`](../benchmarks/base64/README.md)。

| 场景 | ydx/base64 | cloudwego/base64x | cristalhq/base64 | `encoding/base64` |
|---|---:|---:|---:|---:|
| `Encode` 32 B | **14.78 ns** | 16.96 ns | 22.35 ns | 32.46 ns |
| `Encode` 1 KiB | **93.56 ns** | 111.00 ns | 419.10 ns | 874.30 ns |
| `Encode` 64 KiB | **5.167 µs** | 5.364 µs | 26.672 µs | 56.104 µs |
| `Encode` 1 MiB | **88.07 µs** | 89.22 µs | 511.93 µs | 899.25 µs |
| `Decode` 32 B | **22.46 ns** | 28.27 ns | 27.29 ns | 43.80 ns |
| `Decode` 1 KiB | **142.90 ns** | 151.60 ns | 576.00 ns | 981.90 ns |
| `Decode` 64 KiB | 7.671 µs | **7.579 µs** | 40.841 µs | 61.998 µs |
| `Decode` 1 MiB | **123.77 µs** | 125.87 µs | 585.85 µs | 986.37 µs |

- 短输入（32 B）ydx 领先约 15%（编码）与 26%（解码）。
- 1 KiB/64 KiB/1 MiB：除 64 KiB 解码 cloudwego 领先约 1.2%（噪声边界）外，ydx 在其余
  项略优或持平，差距均在 5% 以内。
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
