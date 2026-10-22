# benchmarks/base64 — 自适应 Base64 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/base64` 在编译期/运行期选择后端：amd64 默认使用纯 Go 标量内核，启用
`GOEXPERIMENT=simd` 后按 CPU 选择 AVX-512 VBMI2/VBMI、AVX-512 或 AVX2；其它
cristalhq 支持的架构使用 `cristalhq/base64`；显式 `b64x_std` 构建标签或 loong64
回退到 `encoding/base64`。本基准在同一台机器上比较标量构建、SIMD 构建、标准库与
cristalhq。

## 对比对象

| 实现 | 版本/构建 | 说明 |
|---|---|---|
| ydx/base64 | v0.1.0，默认 amd64 | 纯 Go 标量内核 |
| ydx/base64 | v0.1.0，`GOEXPERIMENT=simd` | 运行时 SIMD 分派 |
| `encoding/base64` | Go 1.27.2 | 标准库对照 |
| `github.com/cristalhq/base64` | v0.1.2 | 第三方 SIMD/汇编实现 |

## 场景

- `Encode` / `Decode`：复用目标缓冲区，测纯编解码成本；覆盖 16 B、1 KiB、64 KiB。
- `EncodeToString` / `DecodeString`：分配式入口；覆盖 16 B 到 64 KiB。
- `RawURLEncode`：JWT 使用的无填充 URL 安全变体。
- `AppendEncodeDecode`：零拷贝 append 入口。

## 关键结果

**默认标量构建（`GOWORK=off`，无 `GOEXPERIMENT=simd`）**

| 场景 | ydx | stdlib | cristalhq |
|---|---:|---:|---:|
| `Encode` 1 KiB | 1.245 µs | 972.3 ns | 505.4 ns |
| `Encode` 64 KiB | 81.47 µs | 60.44 µs | 31.56 µs |
| `Decode` 1 KiB | 1.266 µs | 1.094 µs | 661.5 ns |
| `Decode` 64 KiB | 78.21 µs | 68.44 µs | 40.25 µs |
| `EncodeToString` 1 KiB | 2.138 µs | 1.643 µs | 698.4 ns |
| `DecodeString` 1 KiB | 1.743 µs | 1.325 µs | 934.2 ns |

默认构建下，amd64 标量内核在 1 KiB/64 KiB 原地路径上**慢于**标准库与 cristalhq；
这是未启用 SIMD 实验特性时的预期结果，不应把它当作 ydx 的最终性能。

**`GOEXPERIMENT=simd` 构建**

| 场景 | ydx | stdlib | cristalhq |
|---|---:|---:|---:|
| `Encode` 1 KiB | 124.5 ns | 782.5 ns | 373.5 ns |
| `Encode` 64 KiB | 5.538 µs | 50.42 µs | 25.26 µs |
| `Decode` 1 KiB | 215.7 ns | 1.068 µs | 570.9 ns |
| `Decode` 64 KiB | 11.62 µs | 102.7 µs | 38.80 µs |
| `RawURLEncode` 1 KiB | 136.9 ns | 875.9 ns | 439.4 ns |
| `EncodeToString` 1 KiB | 551.2 ns | 1.326 µs | 654.8 ns |

启用 SIMD 后，原地 `Encode`/`Decode` 比标准库快约 5–9 倍，64 KiB 场景接近或超过
cristalhq；分配式 `EncodeToString`/`DecodeString` 仍包含结果分配，优势小于原地路径。

## 完整数据

<details>
<summary>默认构建（5 轮均值）</summary>

**github.com/shibingli/ydx/benchmarks/base64**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `Encode/b64x/16` | 24.48 ns | 0 | 0 | 623.4 MiB/s |
| `Encode/stdlib/16` | 19.62 ns | 0 | 0 | 777.8 MiB/s |
| `Encode/cristalhq/16` | 13.81 ns | 0 | 0 | 1.079 GiB/s |
| `Encode/b64x/1024` | 1.245 µs | 0 | 0 | 784.1 MiB/s |
| `Encode/stdlib/1024` | 972.3 ns | 0 | 0 | 1004.4 MiB/s |
| `Encode/cristalhq/1024` | 505.4 ns | 0 | 0 | 1.887 GiB/s |
| `Encode/b64x/65536` | 81.47 µs | 0 | 0 | 767.2 MiB/s |
| `Encode/stdlib/65536` | 60.44 µs | 0 | 0 | 1.010 GiB/s |
| `Encode/cristalhq/65536` | 31.56 µs | 0 | 0 | 1.934 GiB/s |
| `EncodeToString/b64x/16` | 44.85 ns | 24 | 1 | 340.2 MiB/s |
| `EncodeToString/stdlib/16` | 45.97 ns | 24 | 1 | 331.9 MiB/s |
| `EncodeToString/cristalhq/16` | 33.54 ns | 24 | 1 | 455.0 MiB/s |
| `EncodeToString/b64x/1024` | 2.138 µs | 2.750 KiB | 2 | 456.8 MiB/s |
| `EncodeToString/stdlib/1024` | 1.643 µs | 2.750 KiB | 2 | 594.3 MiB/s |
| `EncodeToString/cristalhq/1024` | 698.4 ns | 1.375 KiB | 1 | 1.366 GiB/s |
| `RawURLEncode/b64x/16` | 41.96 ns | 0 | 0 | 363.7 MiB/s |
| `RawURLEncode/stdlib/16` | 39.67 ns | 0 | 0 | 384.7 MiB/s |
| `RawURLEncode/cristalhq/16` | 31.65 ns | 0 | 0 | 482.1 MiB/s |
| `RawURLEncode/b64x/1024` | 2.309 µs | 0 | 0 | 422.9 MiB/s |
| `RawURLEncode/stdlib/1024` | 970.9 ns | 0 | 0 | 1005.9 MiB/s |
| `RawURLEncode/cristalhq/1024` | 479.1 ns | 0 | 0 | 1.991 GiB/s |
| `RawURLEncode/b64x/65536` | 87.03 µs | 0 | 0 | 718.1 MiB/s |
| `RawURLEncode/stdlib/65536` | 82.28 µs | 0 | 0 | 759.6 MiB/s |
| `RawURLEncode/cristalhq/65536` | 66.48 µs | 0 | 0 | 940.1 MiB/s |
| `Decode/b64x/16` | 87.54 ns | 0 | 0 | 174.3 MiB/s |
| `Decode/stdlib/16` | 64.93 ns | 0 | 0 | 235.0 MiB/s |
| `Decode/cristalhq/16` | 33.26 ns | 0 | 0 | 458.8 MiB/s |
| `Decode/b64x/1024` | 1.266 µs | 0 | 0 | 771.4 MiB/s |
| `Decode/stdlib/1024` | 1.094 µs | 0 | 0 | 892.9 MiB/s |
| `Decode/cristalhq/1024` | 661.5 ns | 0 | 0 | 1.442 GiB/s |
| `Decode/b64x/65536` | 78.21 µs | 0 | 0 | 799.2 MiB/s |
| `Decode/stdlib/65536` | 68.44 µs | 0 | 0 | 913.3 MiB/s |
| `Decode/cristalhq/65536` | 40.25 µs | 0 | 0 | 1.516 GiB/s |
| `DecodeString/b64x/16` | 71.61 ns | 40 | 2 | 213.1 MiB/s |
| `DecodeString/stdlib/16` | 44.23 ns | 16 | 1 | 345.0 MiB/s |
| `DecodeString/cristalhq/16` | 36.89 ns | 24 | 1 | 413.6 MiB/s |
| `DecodeString/b64x/256` | 419.5 ns | 608 | 2 | 582.0 MiB/s |
| `DecodeString/stdlib/256` | 326.9 ns | 256 | 1 | 746.8 MiB/s |
| `DecodeString/cristalhq/256` | 254.4 ns | 288 | 1 | 959.8 MiB/s |
| `DecodeString/b64x/1024` | 1.743 µs | 2.375 KiB | 2 | 560.3 MiB/s |
| `DecodeString/stdlib/1024` | 1.325 µs | 1.000 KiB | 1 | 737.3 MiB/s |
| `DecodeString/cristalhq/1024` | 934.2 ns | 1.125 KiB | 1 | 1.021 GiB/s |
| `DecodeString/b64x/65536` | 92.90 µs | 152.0 KiB | 2 | 672.8 MiB/s |
| `DecodeString/stdlib/65536` | 71.83 µs | 64.00 KiB | 1 | 870.2 MiB/s |
| `DecodeString/cristalhq/65536` | 52.27 µs | 72.00 KiB | 1 | 1.168 GiB/s |
| `AppendEncodeDecode/append_encode` | 1.112 µs | 0 | 0 | 878.4 MiB/s |
| `AppendEncodeDecode/append_decode` | 1.075 µs | 0 | 0 | 908.3 MiB/s |
</details>

<details>
<summary>GOEXPERIMENT=simd（5 轮均值）</summary>

**github.com/shibingli/ydx/benchmarks/base64**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `Encode/b64x/16` | 22.26 ns | 0 | 0 | 685.6 MiB/s |
| `Encode/stdlib/16` | 15.46 ns | 0 | 0 | 987.0 MiB/s |
| `Encode/cristalhq/16` | 12.89 ns | 0 | 0 | 1.156 GiB/s |
| `Encode/b64x/1024` | 124.5 ns | 0 | 0 | 7.659 GiB/s |
| `Encode/stdlib/1024` | 782.5 ns | 0 | 0 | 1.219 GiB/s |
| `Encode/cristalhq/1024` | 373.5 ns | 0 | 0 | 2.553 GiB/s |
| `Encode/b64x/65536` | 5.538 µs | 0 | 0 | 11.02 GiB/s |
| `Encode/stdlib/65536` | 50.42 µs | 0 | 0 | 1.211 GiB/s |
| `Encode/cristalhq/65536` | 25.26 µs | 0 | 0 | 2.416 GiB/s |
| `EncodeToString/b64x/16` | 40.77 ns | 24 | 1 | 374.3 MiB/s |
| `EncodeToString/stdlib/16` | 33.15 ns | 24 | 1 | 460.2 MiB/s |
| `EncodeToString/cristalhq/16` | 28.14 ns | 24 | 1 | 542.3 MiB/s |
| `EncodeToString/b64x/1024` | 551.2 ns | 2.750 KiB | 2 | 1.730 GiB/s |
| `EncodeToString/stdlib/1024` | 1.326 µs | 2.750 KiB | 2 | 736.3 MiB/s |
| `EncodeToString/cristalhq/1024` | 654.8 ns | 1.375 KiB | 1 | 1.456 GiB/s |
| `RawURLEncode/b64x/16` | 24.89 ns | 0 | 0 | 613.0 MiB/s |
| `RawURLEncode/stdlib/16` | 15.22 ns | 0 | 0 | 1002.4 MiB/s |
| `RawURLEncode/cristalhq/16` | 16.58 ns | 0 | 0 | 920.5 MiB/s |
| `RawURLEncode/b64x/1024` | 136.9 ns | 0 | 0 | 6.967 GiB/s |
| `RawURLEncode/stdlib/1024` | 875.9 ns | 0 | 0 | 1.089 GiB/s |
| `RawURLEncode/cristalhq/1024` | 439.4 ns | 0 | 0 | 2.170 GiB/s |
| `RawURLEncode/b64x/65536` | 7.353 µs | 0 | 0 | 8.301 GiB/s |
| `RawURLEncode/stdlib/65536` | 54.92 µs | 0 | 0 | 1.111 GiB/s |
| `RawURLEncode/cristalhq/65536` | 26.24 µs | 0 | 0 | 2.326 GiB/s |
| `Decode/b64x/16` | 44.06 ns | 0 | 0 | 346.3 MiB/s |
| `Decode/stdlib/16` | 32.16 ns | 0 | 0 | 474.4 MiB/s |
| `Decode/cristalhq/16` | 16.71 ns | 0 | 0 | 913.0 MiB/s |
| `Decode/b64x/1024` | 215.7 ns | 0 | 0 | 4.422 GiB/s |
| `Decode/stdlib/1024` | 1.068 µs | 0 | 0 | 914.4 MiB/s |
| `Decode/cristalhq/1024` | 570.9 ns | 0 | 0 | 1.670 GiB/s |
| `Decode/b64x/65536` | 11.62 µs | 0 | 0 | 5.251 GiB/s |
| `Decode/stdlib/65536` | 102.7 µs | 0 | 0 | 608.8 MiB/s |
| `Decode/cristalhq/65536` | 38.80 µs | 0 | 0 | 1.573 GiB/s |
| `DecodeString/b64x/16` | 88.48 ns | 40 | 2 | 172.5 MiB/s |
| `DecodeString/stdlib/16` | 49.90 ns | 16 | 1 | 305.8 MiB/s |
| `DecodeString/cristalhq/16` | 42.78 ns | 24 | 1 | 356.6 MiB/s |
| `DecodeString/b64x/256` | 248.1 ns | 608 | 2 | 984.0 MiB/s |
| `DecodeString/stdlib/256` | 387.2 ns | 256 | 1 | 630.6 MiB/s |
| `DecodeString/cristalhq/256` | 292.5 ns | 288 | 1 | 834.6 MiB/s |
| `DecodeString/b64x/1024` | 762.9 ns | 2.375 KiB | 2 | 1.250 GiB/s |
| `DecodeString/stdlib/1024` | 1.816 µs | 1.000 KiB | 1 | 537.9 MiB/s |
| `DecodeString/cristalhq/1024` | 1.074 µs | 1.125 KiB | 1 | 909.3 MiB/s |
| `DecodeString/b64x/65536` | 50.65 µs | 152.0 KiB | 2 | 1.205 GiB/s |
| `DecodeString/stdlib/65536` | 120.3 µs | 64.00 KiB | 1 | 519.4 MiB/s |
| `DecodeString/cristalhq/65536` | 66.56 µs | 72.00 KiB | 1 | 939.1 MiB/s |
| `AppendEncodeDecode/append_encode` | 138.8 ns | 0 | 0 | 6.871 GiB/s |
| `AppendEncodeDecode/append_decode` | 154.0 ns | 0 | 0 | 6.192 GiB/s |
</details>

## 复现

```bash
cd benchmarks/base64
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
GOWORK=off GOEXPERIMENT=simd go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 默认构建与 SIMD 构建是两次独立编译；两次运行的 CPU 频率/背景负载可能不同。
- `GOEXPERIMENT=simd` 是 Go 1.27 的实验特性；生产构建需确认工具链与目标 CPU 支持。
- `Encode`/`Decode` 复用目标缓冲区，`EncodeToString`/`DecodeString` 包含结果分配；
  后者的分配次数差异（ydx 2 次 vs 标准库 1 次）来自结果构造与内部缓冲路径。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
