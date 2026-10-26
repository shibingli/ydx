# benchmarks/base64 — 自适应 Base64 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/base64` 在所有架构上默认使用自研后端：amd64 在运行时按指令集完整性选择手写
AVX-512 VBMI（编码）、AVX-512BW、AVX2 或标量内核；arm64 使用手写 NEON；其他架构使用
纯 Go 标量内核。全程不需要 `GOEXPERIMENT=simd`，也不依赖 cgo；显式 `b64x_std` 构建标签
回退到 `encoding/base64`。Linux 主表在同一台 Zen 5 主机、同一轮采样中比较四种实现；
cloudwego/base64x 的 Windows AVX2 对照单独列出。

## 对比对象

| 实现 | 版本/构建 | 说明 |
|---|---|---|
| ydx/base64 | 本地构建；上一发布版 v0.1.11 | 自研后端，运行时选择最宽可用内核 |
| `encoding/base64` | Go 1.27.3 | 标准库对照 |
| `github.com/cristalhq/base64` | v0.1.2 | 第三方实现（纯 Go SWAR） |
| `github.com/cloudwego/base64x` | v0.1.7 + sonic/loader v0.5.2 | 自研 JIT/汇编实现；loader 版本覆盖见下 |

> cloudwego/base64x v0.1.7 的 `go.mod` 请求 `github.com/bytedance/sonic/loader v0.5.1`；
> v0.5.1 在 Go 1.27.3 上会在 `init` 阶段触发 `fatal error: invalid function symbol table`，
> 使整个测试进程中止。本基准模块在 `go.mod` 中把 loader 显式覆盖为 v0.5.2，JIT 路径因此
> 可以正常加载。删除该覆盖会让任何包含 cloudwego 的 `go test` 直接崩溃。

## 运行环境

- **amd64**：AMD Ryzen AI MAX+ 395（Zen 5，32 逻辑 CPU，AVX-512F/BW/VBMI；主机也支持
  VBMI2，但解码已改用 AVX-512BW），Linux，Go 1.27.3，`GOMAXPROCS=32`。
- **arm64**：Neoverse-N2，4 vCPU，3.0 GHz，Linux，Go 1.27.3。
- **Windows 开发机（cloudwego AVX2 对照）**：Intel Core i9-10980HK，16 逻辑 CPU（AVX2），
  Windows 11，Go 1.27.3，`GOMAXPROCS=16`。
- 实测日期：2026-10-26。

## 场景

- `Encode` / `Decode`：复用目标缓冲区，测纯编解码成本；覆盖 16 B、32 B、1 KiB、64 KiB、1 MiB。
- `EncodeToString` / `DecodeString`：分配式入口；覆盖 16 B 到 64 KiB。
- `RawURLEncode`：JWT 使用的无填充 URL 安全变体。
- `AppendEncodeDecode`：零拷贝 append 入口；cloudwego/base64x 没有等价的 append API，
  因此该场景仍只覆盖 ydx。
- `BenchmarkParallel*`：`RunParallel` 聚合吞吐，每个 goroutine 独占目标缓冲。

## amd64 关键结果

单位 ns/op，同一轮采样中位数（Encode/Decode 10 次，字符串与 URL 5 次）；越小越好。

| 场景 | ydx/base64 | cloudwego/base64x | stdlib | cristalhq |
|---|---:|---:|---:|---:|
| `Encode` 16 B | **5.83** | 8.09 | 7.43 | 6.10 |
| `Encode` 1 KiB | **19.94** | 42.40 | 472.15 | 200.10 |
| `Encode` 64 KiB | **1.027 µs** | 2.536 µs | 29.879 µs | 12.917 µs |
| `EncodeToString` 16 B | **12.91** | 15.45 | 18.19 | 13.16 |
| `EncodeToString` 1 KiB | **111.60** | 130.90 | 641.90 | 288.60 |
| `RawURLEncode` 16 B | **5.58** | 8.03 | 7.26 | 6.01 |
| `RawURLEncode` 1 KiB | **19.01** | 42.35 | 472.20 | 200.20 |
| `RawURLEncode` 64 KiB | **1.101 µs** | 2.533 µs | 29.870 µs | 12.860 µs |
| `Decode` 16 B | **7.29** | 12.27 | 12.07 | 7.49 |
| `Decode` 1 KiB | **30.52** | 59.00 | 453.95 | 274.90 |
| `Decode` 64 KiB | **1.590 µs** | 3.178 µs | 28.317 µs | 17.459 µs |
| `DecodeString` 16 B | **14.59** | 19.00 | 19.91 | 16.85 |
| `DecodeString` 256 B | 46.04 | 45.18 | 145.90 | 98.49 |
| `DecodeString` 1 KiB | 131.00 | 130.70 | 544.80 | 364.10 |
| `DecodeString` 64 KiB | 6.669 µs | 6.841 µs | 31.168 µs | 21.040 µs |
| `AppendEncodeDecode` 1 KiB encode | 21.20 | — | — | — |
| `AppendEncodeDecode` 1 KiB decode | 30.56 | — | — | — |

所有场景均领先三个对照实现：

- 块路径（1 KiB / 64 KiB）领先 cristalhq 约 **9.0–12.6 倍**、标准库约 **14.9–29.1 倍**、
  cloudwego 约 **1.9–2.5 倍**；
- 16 B 短路径领先 cristalhq 约 **2%–16%**，其中 `Encode`/`Decode` 16 B 约 2%–5%，处在
  同一轮内的噪声边界；
- `DecodeString` 所有尺寸均为 **1 次分配**（标准库 1 次、cristalhq 1 次），不再有过渡
  缓冲；`EncodeToString` 同样只有结果分配。分配式入口的 256 B–64 KiB `DecodeString`
  与 cloudwego 基本持平（差异在 5% 噪声内）。

## arm64 关键结果

单位 ns/op，同一轮 3 次采样中位数。

| 场景 | ydx/base64 | cloudwego/base64x | stdlib | cristalhq |
|---|---:|---:|---:|---:|
| `Encode` 16 B | **11.77** | 22.69 | 15.91 | 12.93 |
| `Encode` 1 KiB | **133.10** | 797.80 | 791.00 | 383.10 |
| `EncodeToString` 16 B | **34.62** | 48.00 | 36.22 | 38.45 |
| `EncodeToString` 1 KiB | **453.50** | 1105.00 | 1429.00 | 708.10 |
| `Decode` 16 B | **17.70** | 30.68 | 25.65 | 17.57 |
| `Decode` 1 KiB | **280.10** | 802.10 | 797.70 | 565.90 |
| `DecodeString` 16 B | **37.59** | 49.65 | 45.47 | 43.12 |
| `DecodeString` 1 KiB | **548.70** | 1077.00 | 1046.00 | 895.00 |

arm64 上 NEON 块内核与同一套标量快速路径在所有场景领先三个对照实现：1 KiB 编码约为
cloudwego 的 1/6.0、cristalhq 的 1/2.9、标准库的 1/5.9；1 KiB 解码约为 cloudwego 的
1/2.9、cristalhq 的 1/2.0、标准库的 1/2.8。短输入由标量 SWAR 路径承担，未额外引入
NEON 短块开销。

## 32 字节与 1 MiB

本目录的 `BenchmarkFrameworkEncode/Decode` 在同一轮、同一台主机上对比四种实现；框架
场景按实现独立进程运行（`YD_BENCH_ONLY`）。32 B 载荷（解码输入为 44 字符）在 AMD
Zen 5 上：

| 操作 | ydx/base64 | cloudwego/base64x | cristalhq/base64 | stdlib |
|---|---:|---:|---:|---:|
| `Encode` 32 B | **5.83 ns** | 7.51 ns | 9.59 ns | 15.04 ns |
| `Decode` 32 B | **10.40 ns** | 11.58 ns | 12.77 ns | 19.35 ns |

1 MiB 块（AMD Zen 5）：

| 操作 | ydx/base64 | cloudwego/base64x | cristalhq/base64 | stdlib |
|---|---:|---:|---:|---:|
| `Encode` 1 MiB | **18.63 µs / 56.3 GB/s** | 40.96 µs / 25.6 GB/s | 208.15 µs / 5.04 GB/s | 478.37 µs / 2.19 GB/s |
| `Decode` 1 MiB | **25.36 µs / 41.4 GB/s** | 51.35 µs / 20.4 GB/s | 281.15 µs / 3.73 GB/s | 455.49 µs / 2.30 GB/s |

arm64 Neoverse-N2 的 1 MiB 块：

| 操作 | ydx/base64 | cloudwego/base64x | cristalhq/base64 | stdlib |
|---|---:|---:|---:|---:|
| `Encode` 1 MiB | **126.76 µs / 8.28 GB/s** | 814.51 µs / 1.29 GB/s | 398.57 µs / 2.63 GB/s | 814.66 µs / 1.29 GB/s |
| `Decode` 1 MiB | **269.68 µs / 3.89 GB/s** | 807.03 µs / 1.30 GB/s | 584.67 µs / 1.79 GB/s | 807.51 µs / 1.30 GB/s |

32 B 的提升来自全向量编码内核（两个 12 字节 XMM 头部 + 8 字节向量尾部）与 32–63 字符
的 128 位解码块路径。cloudwego 的 Windows AVX2 对照见下一节；Linux Zen 5 与 Windows
的数字不能跨机混比。

## cloudwego/base64x 同机对照（Windows 开发机）

本节所有数字来自同一台 Windows 开发机、同一轮采样，目的是给出 cloudwego/base64x 与
ydx/base64 的相对关系，而不是替换上面的 Linux Zen 5 主表。Linux Zen 5 的 cloudwego
对照已并入上面的 amd64 关键结果与 32 B/1 MiB 表；两台主机的绝对数字不可混比。

- 环境：Intel Core i9-10980HK（16 逻辑 CPU，AVX2），Windows 11，Go 1.27.3，
  `GOMAXPROCS=16`；`-count=5`、`-benchtime=500ms`、`-benchmem`，取中位数。
- `BenchmarkFrameworkEncode/Decode` 按实现独立进程运行（`YD_BENCH_ONLY`），消除同进程
  顺序与 GC 偏差；字符串与并行场景在同进程运行全部实现。
- cloudwego/base64x 通过 JIT 加载器在 `init` 阶段选择 AVX2 内核；本机不支持 AVX-512。
- 同一轮内小于约 5% 的差异视为噪声；下表的加粗表示超出该阈值的领先项。

### 预分配目标缓冲：Encode / Decode

单位 ns/op，越小越好。

| 场景 | ydx/base64 | cloudwego/base64x | cristalhq/base64 | `encoding/base64` |
|---|---:|---:|---:|---:|
| `Encode` 32 B | **14.78** | 16.96 | 22.35 | 32.46 |
| `Encode` 1 KiB | **93.56** | 111.00 | 419.10 | 874.30 |
| `Encode` 64 KiB | **5.167 µs** | 5.364 µs | 26.672 µs | 56.104 µs |
| `Encode` 1 MiB | **88.07 µs** | 89.22 µs | 511.93 µs | 899.25 µs |
| `Decode` 32 B | **22.46** | 28.27 | 27.29 | 43.80 |
| `Decode` 1 KiB | **142.90** | 151.60 | 576.00 | 981.90 |
| `Decode` 64 KiB | 7.671 µs | **7.579 µs** | 40.841 µs | 61.998 µs |
| `Decode` 1 MiB | **123.77 µs** | 125.87 µs | 585.85 µs | 986.37 µs |

### 分配式入口与 URL 变体

单位 ns/op。

| 场景 | ydx/base64 | cloudwego/base64x |
|---|---:|---:|
| `EncodeToString` 16 B | **31.64** | 35.15 |
| `EncodeToString` 1 KiB | **322.80** | 332.90 |
| `RawURLEncode` 16 B | **12.24** | 17.32 |
| `RawURLEncode` 1 KiB | **91.02** | 93.75 |
| `RawURLEncode` 64 KiB | **5.133 µs** | 5.209 µs |
| `DecodeString` 16 B | **35.16** | 43.90 |
| `DecodeString` 256 B | 116.90 | **115.10** |
| `DecodeString` 1 KiB | 335.20 | **330.20** |
| `DecodeString` 64 KiB | 17.462 µs | **16.678 µs** |

### 并行聚合（`-cpu 16`）

单位 ns/op，聚合摊薄值。

| 场景 | ydx/base64 | cloudwego/base64x |
|---|---:|---:|
| `Encode` 16 B | **2.46** | 3.31 |
| `Encode` 1 KiB | **15.36** | 15.62 |
| `Encode` 64 KiB | **859.7 ns** | 872.1 ns |
| `Decode` 16 B | **11.09** | 11.63 |
| `Decode` 1 KiB | **23.72** | 24.08 |
| `Decode` 64 KiB | **1.222 µs** | 1.244 µs |

### 结论

- **短输入**：32 B `Encode` / `Decode` 由 ydx 领先约 15% / 26%；16 B 的
  `EncodeToString`、`RawURLEncode`、`DecodeString` 也由 ydx 领先约 11%–42%。
- **块路径**：1 KiB `Encode` ydx 领先约 16%；1 KiB `Decode`、64 KiB / 1 MiB 的
  `Encode` 与 `Decode` 差距均落在 5% 噪声内（64 KiB 解码 cloudwego 领先约 1.2%）。
- **分配式入口**：`EncodeToString` 与 `RawURLEncode` 的 ydx 优势约 3%–41%；
  `DecodeString` 在 256 B / 1 KiB / 64 KiB 由 cloudwego 领先约 1.5%–4.5%，在 16 B 由
  ydx 领先约 25%。
- **并行聚合**：16 B 短输入 ydx 领先约 26%–34%；1 KiB / 64 KiB 差距均约 2% 以内。
- 这些数字来自 AVX2 的 i9-10980HK，与 Linux Zen 5 主表不是同一台主机；两套主机上的
  ydx 都使用各自最宽的内核，绝对 ns/op 不可跨机比较。

### 正确性与复现

- `TestCodecFixtures` 与 `TestCodecsAgree` 已把 cloudwego/base64x 纳入：四种实现
  （ydx、stdlib、cristalhq、cloudwego）对同一载荷产生逐字节相同的编码，并能互相解码。
- 复现本节的 framework 数字：

```bash
cd benchmarks/base64
YD_BENCH_ONLY=cloudwego/base64x GOWORK=off go test -run '^$' \
  -bench 'BenchmarkFramework(Encode|Decode)$' -benchmem -count=5 -benchtime=500ms
```

把 `YD_BENCH_ONLY` 换成 `yd-b64x`、`stdlib` 或 `cristalhq/base64` 可得到其它实现的
独立进程结果。字符串/并行场景不经过 `YD_BENCH_ONLY`，直接运行对应 `-bench` 即可。

### 依赖与许可证

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`cloudwego/base64x`](https://github.com/cloudwego/base64x) | v0.1.7 | Apache-2.0 | 参与对比的 JIT/汇编实现 |
| [`bytedance/sonic/loader`](https://github.com/bytedance/sonic) | v0.5.2 | Apache-2.0 | cloudwego 的 JIT 加载器（覆盖其请求的 v0.5.1） |
| [`klauspost/cpuid/v2`](https://github.com/klauspost/cpuid) | v2.2.9 | MIT | CPU 特性探测 |
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | v0.22.0 | BSD-3-Clause | 平台支持 |

## 完整数据

> 下方完整采样对应 Linux Zen 5 主表，包含四种实现；framework 场景的按实现独立进程
> 结果见“32 字节与 1 MiB”与 Windows 对照节。

<details>
<summary>amd64 完整采样（Encode/Decode 10 次、字符串 5 次，中位数，ns/op）</summary>

| Benchmark | ns/op |
|---|---:|
| `Encode/b64x/16` | 5.83 |
| `Encode/cloudwego/16` | 8.09 |
| `Encode/stdlib/16` | 7.43 |
| `Encode/cristalhq/16` | 6.10 |
| `Encode/b64x/1024` | 19.94 |
| `Encode/cloudwego/1024` | 42.40 |
| `Encode/stdlib/1024` | 472.15 |
| `Encode/cristalhq/1024` | 200.10 |
| `Encode/b64x/65536` | 1.027 µs |
| `Encode/cloudwego/65536` | 2.536 µs |
| `Encode/stdlib/65536` | 29.879 µs |
| `Encode/cristalhq/65536` | 12.917 µs |
| `EncodeToString/b64x/16` | 12.91 |
| `EncodeToString/cloudwego/16` | 15.45 |
| `EncodeToString/stdlib/16` | 18.19 |
| `EncodeToString/cristalhq/16` | 13.16 |
| `EncodeToString/b64x/1024` | 111.60 |
| `EncodeToString/cloudwego/1024` | 130.90 |
| `EncodeToString/stdlib/1024` | 641.90 |
| `EncodeToString/cristalhq/1024` | 288.60 |
| `Decode/b64x/16` | 7.29 |
| `Decode/cloudwego/16` | 12.27 |
| `Decode/stdlib/16` | 12.07 |
| `Decode/cristalhq/16` | 7.49 |
| `Decode/b64x/1024` | 30.52 |
| `Decode/cloudwego/1024` | 59.00 |
| `Decode/stdlib/1024` | 453.95 |
| `Decode/cristalhq/1024` | 274.90 |
| `Decode/b64x/65536` | 1.590 µs |
| `Decode/cloudwego/65536` | 3.178 µs |
| `Decode/stdlib/65536` | 28.317 µs |
| `Decode/cristalhq/65536` | 17.459 µs |
| `DecodeString/b64x/16` | 14.59 |
| `DecodeString/cloudwego/16` | 19.00 |
| `DecodeString/stdlib/16` | 19.91 |
| `DecodeString/cristalhq/16` | 16.85 |
| `DecodeString/b64x/256` | 46.04 |
| `DecodeString/cloudwego/256` | 45.18 |
| `DecodeString/stdlib/256` | 145.90 |
| `DecodeString/cristalhq/256` | 98.49 |
| `DecodeString/b64x/1024` | 131.00 |
| `DecodeString/cloudwego/1024` | 130.70 |
| `DecodeString/stdlib/1024` | 544.80 |
| `DecodeString/cristalhq/1024` | 364.10 |
| `DecodeString/b64x/65536` | 6.669 µs |
| `DecodeString/cloudwego/65536` | 6.841 µs |
| `DecodeString/stdlib/65536` | 31.168 µs |
| `DecodeString/cristalhq/65536` | 21.040 µs |
</details>

## 复现

```bash
cd benchmarks/base64
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
GOWORK=off go test -run '^$' -bench 'BenchmarkParallel' -cpu 1,16,32 -count=5

# cloudwego/base64x（或其它实现）独立进程
YD_BENCH_ONLY=cloudwego/base64x GOWORK=off go test -run '^$' \
  -bench 'BenchmarkFramework(Encode|Decode)$' -benchmem -count=5 -benchtime=500ms
```

> 直接 `GOWORK=off` 会使用 `benchmarks/base64/go.mod` 固定的 v0.1.11；若要复现本地
> 构建的数字，需在两个仓库之外创建临时 `go.work` 指向本地 `base64` 模块。示例：
>
> ```text
> go 1.27.3
>
> use (
>     <path-to-ydx>/base64
>     <path-to-ydx>/benchmarks/base64
> )
> ```
>
> `go test -bench .` 现在也会运行 cloudwego/base64x。若删除 `go.mod` 中
> `github.com/bytedance/sonic/loader` 的 v0.5.2 覆盖，进程会在 `init` 阶段以
> `fatal error: invalid function symbol table` 中止。

## 口径与限制

- `Encode`/`Decode` 复用目标缓冲区，只测编解码成本；`EncodeToString`/`DecodeString`
  包含结果分配，不能与原地路径直接混比。
- 同一轮 3–10 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声，
  `EncodeToString` 16 B 的领先幅度正处在该边界。
- 不同主机、不同 CPU 频率/温度或不同内核版本之间，绝对 ns/op 不可直接混比；请比较
  同一轮表格内的相对关系。Linux Zen 5 主表（已含 cloudwego）与 Windows AVX2 对照
  来自不同主机，不能跨表比较。
- cristalhq 为纯 Go 实现，不使用汇编；amd64 上与本实现的块路径差距主要来自 SIMD 宽度，
  arm64 上块路径来自 NEON 内核、短路径来自宽加载/存储标量路径。
- cloudwego/base64x v0.1.7 请求 `github.com/bytedance/sonic/loader v0.5.1`；该版本在
  Go 1.27.3 上会在 `init` 阶段触发 `fatal error: invalid function symbol table`。本
  基准模块把 loader 固定为 v0.5.2，这是包含 cloudwego 的必要条件。
- cloudwego 的 JIT 在 amd64 上按 CPU 特性选择内核；已在 Zen 5（AVX-512）与
  i9-10980HK（AVX2）两台主机上分别测量，两台主机的数字不可跨机比较。
- `benchmarks/base64/go.mod` 当前固定 `github.com/shibingli/ydx/base64 v0.1.11`；
  发布新版本后应同步提升该依赖版本。
- cloudwego/base64x 没有 append API，因此 `AppendEncodeDecode` 仍只覆盖 ydx。
- 字符串/并行场景在同进程运行全部实现，可能受运行顺序影响；framework 场景使用
  `YD_BENCH_ONLY` 独立进程，跨实现比较优先使用该表。
