# benchmarks/base64 — 自适应 Base64 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/base64` 在所有架构上默认使用自研后端：amd64 在运行时按指令集完整性与优先级自动选择
手写 AVX-512 VBMI2/VBMI、AVX-512BW、AVX2 或标量内核；arm64 使用手写 NEON；其他架构使用
纯 Go 标量内核。全程不需要 `GOEXPERIMENT=simd`，也不依赖 cgo；显式 `b64x_std` 构建标签
回退到 `encoding/base64`。Linux 主表在同一台机器、同一轮采样中比较默认自研后端、标准库
与 cristalhq；cloudwego/base64x 的同机对照单独列在 Windows 开发机上。

## 对比对象

| 实现 | 版本/构建 | 说明 |
|---|---|---|
| ydx/base64 | v0.1.11（当前）；Linux 主表采集于 v0.1.9 | 自研后端，运行时选择最宽可用内核 |
| `encoding/base64` | Go 1.27.3 | 标准库对照 |
| `github.com/cristalhq/base64` | v0.1.2 | 第三方实现（纯 Go SWAR） |
| `github.com/cloudwego/base64x` | v0.1.7 + sonic/loader v0.5.2 | 自研 JIT/汇编实现；loader 版本覆盖见下 |

> v0.1.8 把短输入 SIMD 阈值提高到 64；v0.1.9 为恰好 32 字节新增两个 12 字节 XMM
> 头部加一个 8 字节向量尾部的全向量编码内核（一次写满 44 个字符、不调用标量尾部），
> 并让 32–63 字符解码先走 128 位块内核。本表的 16 B、1 KiB 与 64 KiB 路径不变；
> 32 B 的对比见下方「32 字节短内核」与 [`../yd-vs-ydx-analysis.md`](../yd-vs-ydx-analysis.md)。
>
> cloudwego/base64x v0.1.7 的 `go.mod` 请求 `github.com/bytedance/sonic/loader v0.5.1`；
> v0.5.1 在 Go 1.27.3 上会在 `init` 阶段触发 `fatal error: invalid function symbol table`，
> 使整个测试进程中止。本基准模块在 `go.mod` 中把 loader 显式覆盖为 v0.5.2，JIT 路径因此
> 可以正常加载。删除该覆盖会让任何包含 cloudwego 的 `go test` 直接崩溃。

## 运行环境

- **amd64**：AMD Ryzen AI MAX+ 395（Zen 5，32 逻辑 CPU，AVX-512F/BW/VBMI/VBMI2），
  Linux，Go 1.27.3，`GOMAXPROCS=32`。
- **arm64**：Neoverse-N2，4 vCPU，3.0 GHz，Linux，Go 1.27.3。
- **Windows 开发机（cloudwego 同机对照）**：Intel Core i9-10980HK，16 逻辑 CPU（AVX2），
  Windows 11，Go 1.27.3，`GOMAXPROCS=16`。
- 实测日期：Linux 主表 2026-10-24；Windows cloudwego 对照 2026-10-26。

## 场景

- `Encode` / `Decode`：复用目标缓冲区，测纯编解码成本；覆盖 16 B、32 B、1 KiB、64 KiB、1 MiB。
- `EncodeToString` / `DecodeString`：分配式入口；覆盖 16 B 到 64 KiB。
- `RawURLEncode`：JWT 使用的无填充 URL 安全变体。
- `AppendEncodeDecode`：零拷贝 append 入口；cloudwego/base64x 没有等价的 append API，
  因此该场景仍只覆盖 ydx。
- `BenchmarkParallel*`：`RunParallel` 聚合吞吐，每个 goroutine 独占目标缓冲。

## amd64 关键结果

单位 ns/op，同一轮 3 次采样中位数；越小越好。

| 场景 | ydx/base64 | stdlib | cristalhq |
|---|---:|---:|---:|
| `Encode` 16 B | **5.61** | 7.42 | 6.10 |
| `Encode` 1 KiB | **23.4** | 470 | 200 |
| `Encode` 64 KiB | **1.03 µs** | 29.9 µs | 12.8 µs |
| `EncodeToString` 16 B | **13.1** | 17.5 | 13.2 |
| `EncodeToString` 1 KiB | **112** | 639 | 284 |
| `RawURLEncode` 16 B | **5.42** | 7.26 | 6.02 |
| `RawURLEncode` 1 KiB | **23.1** | 471 | 200 |
| `RawURLEncode` 64 KiB | **1.04 µs** | 29.9 µs | 12.9 µs |
| `Decode` 16 B | **7.15** | 12.1 | 7.58 |
| `Decode` 1 KiB | **42.1** | 455 | 274 |
| `Decode` 64 KiB | **2.34 µs** | 28.6 µs | 17.4 µs |
| `DecodeString` 16 B | **14.6** | 19.9 | 16.9 |
| `DecodeString` 256 B | **44.1** | 147.5 | 97.6 |
| `DecodeString` 1 KiB | **127.9** | 542 | 372 |
| `DecodeString` 64 KiB | **6.00 µs** | 31.3 µs | 21.1 µs |
| `AppendEncodeDecode` 1 KiB encode | 25.8 | — | — |
| `AppendEncodeDecode` 1 KiB decode | 45.7 | — | — |

所有场景均领先标准库与 cristalhq：

- 块路径（1 KiB / 64 KiB）领先 cristalhq 约 **6.5–12.5 倍**，领先标准库约 **11–29 倍**；
- 16 B 短路径领先 cristalhq 约 **1%–14%**，其中 `EncodeToString` 16 B 仅约 1%，属于
  同一轮内的噪声边界；
- `DecodeString` 所有尺寸均为 **1 次分配**（标准库 1 次、cristalhq 1 次），不再有过渡
  缓冲；`EncodeToString` 同样只有结果分配。

## arm64 关键结果

单位 ns/op，同一轮 3 次采样中位数。

| 场景 | ydx/base64 | stdlib | cristalhq |
|---|---:|---:|---:|
| `Encode` 16 B | **10.7** | 15.9 | 13.1 |
| `Encode` 1 KiB | **134** | 787 | 382 |
| `EncodeToString` 16 B | **34.4** | 36.2 | 38.2 |
| `EncodeToString` 1 KiB | **436** | 1.42 µs | 693 |
| `Decode` 16 B | **17.25** | 25.2 | 17.68 |
| `Decode` 1 KiB | **279** | 781 | 566 |
| `DecodeString` 16 B | **37.4** | 46.5 | 44.2 |
| `DecodeString` 1 KiB | **526** | 1.04 µs | 890 |

arm64 上 NEON 块内核与同一套标量快速路径在所有场景领先两个对照实现；短输入由标量
SWAR 路径承担，未额外引入 NEON 短块开销。

## 32 字节与 1 MiB

本目录的 `BenchmarkFrameworkEncode/Decode` 在同一轮、同一台主机上对比 32 B 载荷
（解码输入为 44 字符）：

| 操作 | ydx/base64 | cristalhq/base64 | stdlib |
|---|---:|---:|---:|
| `Encode` 32 B | **5.58 ns** | 9.57 ns | 14.38 ns |
| `Decode` 32 B | **10.47 ns** | 12.93 ns | 19.92 ns |

1 MiB 块：

| 操作 | ydx/base64 | cristalhq/base64 | stdlib |
|---|---:|---:|---:|
| `Encode` 1 MiB | **55.5 GB/s** | 5.05 GB/s | 2.39 GB/s |
| `Decode` 1 MiB | **27.1 GB/s** | 3.73 GB/s | 2.28 GB/s |

32 B 的提升来自全向量编码内核（两个 12 字节 XMM 头部 + 8 字节向量尾部）与 32–63 字符
的 128 位解码块路径。cloudwego/base64x 的对比见下一节；上方 Linux 主表未在同一台
Zen 5 主机上重跑 cloudwego，不能与下一节的 Windows 数字直接混比。

## cloudwego/base64x 同机对照（Windows 开发机）

本节所有数字来自同一台 Windows 开发机、同一轮采样，目的是给出 cloudwego/base64x 与
ydx/base64 的相对关系，而不是替换上面的 Linux Zen 5 主表。

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
| `Encode` 32 B | **17.29** | 19.21 | 22.82 | 34.16 |
| `Encode` 1 KiB | 114.7 | 110.7 | 457.4 | 955.0 |
| `Encode` 64 KiB | 6.33 µs | **5.86 µs** | 27.54 µs | 58.58 µs |
| `Encode` 1 MiB | 110.24 µs | **103.91 µs** | 457.68 µs | 934.89 µs |
| `Decode` 32 B | **27.95** | 35.34 | 28.80 | 46.12 |
| `Decode` 1 KiB | 167.9 | 169.7 | 603.3 | 1.02 µs |
| `Decode` 64 KiB | 9.35 µs | **8.78 µs** | 37.08 µs | 63.66 µs |
| `Decode` 1 MiB | 161.09 µs | **151.58 µs** | 622.80 µs | 1135.44 µs |

### 分配式入口与 URL 变体

单位 ns/op。

| 场景 | ydx/base64 | cloudwego/base64x |
|---|---:|---:|
| `EncodeToString` 16 B | **32.50** | 37.94 |
| `EncodeToString` 1 KiB | 529.5 | **391.7** |
| `RawURLEncode` 16 B | **13.87** | 18.69 |
| `RawURLEncode` 1 KiB | 108.4 | **98.63** |
| `RawURLEncode` 64 KiB | 6.14 µs | **5.54 µs** |
| `DecodeString` 16 B | **41.34** | 46.41 |
| `DecodeString` 256 B | **128.2** | 149.4 |
| `DecodeString` 1 KiB | **405.9** | 448.1 |
| `DecodeString` 64 KiB | 21.89 µs | 20.86 µs |

### 并行聚合（`-cpu 16`）

单位 ns/op，聚合摊薄值。

| 场景 | ydx/base64 | cloudwego/base64x |
|---|---:|---:|
| `Encode` 16 B | **3.00** | 3.68 |
| `Encode` 1 KiB | 20.68 | **17.45** |
| `Encode` 64 KiB | 1.05 µs | **970.8 ns** |
| `Decode` 16 B | **9.60** | 13.18 |
| `Decode` 1 KiB | 25.78 | 25.43 |
| `Decode` 64 KiB | 1.35 µs | 1.38 µs |

### 结论

- **短输入**：32 B `Encode` / `Decode` 由 ydx 领先约 11% / 21%；16 B 的
  `EncodeToString`、`RawURLEncode`、`DecodeString` 也由 ydx 领先约 11%–26%。
- **块路径**：1 KiB 的 `Encode` / `Decode` 基本持平（差异在 5% 噪声内）；64 KiB 与
  1 MiB 由 cloudwego 领先约 5%–10%，两套实现在这个尺寸区间都接近内存带宽上限。
- **分配式入口**：`EncodeToString` 1 KiB 的 cloudwego 优势约 26%，来自其分配式入口
  优化；对应的非分配 `Encode` 1 KiB 差距只有约 3.5%。
- **并行聚合**：16 B 短输入 ydx 领先约 19%–27%；1 KiB / 64 KiB 编码 cloudwego
  领先约 8%–16%；1 KiB / 64 KiB 解码基本持平（差异在 5% 噪声内）。
- 这些数字来自 AVX2 的 i9-10980HK；Linux Zen 5 主表上 ydx 的 1 MiB 编码为
  55.5 GB/s，但未在该主机上运行 cloudwego，不能把两者直接比较。

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

> 下方完整采样对应 Linux Zen 5 主表（ydx/stdlib/cristalhq），不包含 cloudwego；
> cloudwego 的原始采样可用上一节命令复现。

<details>
<summary>amd64 完整采样（3 次，ns/op）</summary>

| Benchmark | ns/op |
|---|---:|
| `Encode/b64x/16` | 5.60–5.62 |
| `Encode/stdlib/16` | 7.42 |
| `Encode/cristalhq/16` | 6.10 |
| `Encode/b64x/1024` | 23.4 |
| `Encode/stdlib/1024` | 470–472 |
| `Encode/cristalhq/1024` | 200 |
| `Encode/b64x/65536` | 1.027–1.028 µs |
| `Encode/stdlib/65536` | 29.85 µs |
| `Encode/cristalhq/65536` | 12.83–12.85 µs |
| `EncodeToString/b64x/16` | 12.96–13.06 |
| `EncodeToString/stdlib/16` | 17.44–17.61 |
| `EncodeToString/cristalhq/16` | 13.15–13.20 |
| `EncodeToString/b64x/1024` | 109.4–117.1 |
| `EncodeToString/stdlib/1024` | 639–643 |
| `EncodeToString/cristalhq/1024` | 284–286 |
| `Decode/b64x/16` | 7.14–7.19 |
| `Decode/stdlib/16` | 12.07–12.08 |
| `Decode/cristalhq/16` | 7.57–7.58 |
| `Decode/b64x/1024` | 42.1–42.2 |
| `Decode/stdlib/1024` | 455–457 |
| `Decode/cristalhq/1024` | 274–281 |
| `Decode/b64x/65536` | 2.339–2.348 µs |
| `Decode/stdlib/65536` | 28.63 µs |
| `Decode/cristalhq/65536` | 17.45–17.46 µs |
| `DecodeString/b64x/16` | 14.57–14.90 |
| `DecodeString/stdlib/16` | 19.81–20.13 |
| `DecodeString/cristalhq/16` | 16.75–16.96 |
| `DecodeString/b64x/256` | 43.90–44.15 |
| `DecodeString/stdlib/256` | 147.4–147.5 |
| `DecodeString/cristalhq/256` | 97.60–97.93 |
| `DecodeString/b64x/1024` | 127.8–128.4 |
| `DecodeString/stdlib/1024` | 542–551 |
| `DecodeString/cristalhq/1024` | 372.4 |
| `DecodeString/b64x/65536` | 6.00–6.30 µs |
| `DecodeString/stdlib/65536` | 31.3–31.4 µs |
| `DecodeString/cristalhq/65536` | 21.05–21.52 µs |
</details>

## 复现

```bash
cd benchmarks/base64
GOWORK=off go test -run '^$' -bench . -benchmem -count=3 -benchtime=500ms
GOWORK=off go test -run '^$' -bench 'BenchmarkParallel' -cpu 1,16,32 -count=3

# cloudwego/base64x（或其它实现）独立进程
YD_BENCH_ONLY=cloudwego/base64x GOWORK=off go test -run '^$' \
  -bench 'BenchmarkFramework(Encode|Decode)$' -benchmem -count=5 -benchtime=500ms
```

> `go test -bench .` 现在也会运行 cloudwego/base64x。若删除 `go.mod` 中
> `github.com/bytedance/sonic/loader` 的 v0.5.2 覆盖，进程会在 `init` 阶段以
> `fatal error: invalid function symbol table` 中止。

## 口径与限制

- `Encode`/`Decode` 复用目标缓冲区，只测编解码成本；`EncodeToString`/`DecodeString`
  包含结果分配，不能与原地路径直接混比。
- 同一轮 3–5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声，
  `EncodeToString` 16 B 的领先幅度正处在该边界。
- 不同主机、不同 CPU 频率/温度或不同内核版本之间，绝对 ns/op 不可直接混比；请比较
  同一轮表格内的相对关系。Linux Zen 5 主表与 Windows cloudwego 对照来自不同主机，
  不能跨表比较。
- cristalhq 为纯 Go 实现，不使用汇编；amd64 上与本实现的块路径差距主要来自 SIMD 宽度，
  arm64 上块路径来自 NEON 内核、短路径来自宽加载/存储标量路径。
- cloudwego/base64x v0.1.7 请求 `github.com/bytedance/sonic/loader v0.5.1`；该版本在
  Go 1.27.3 上会在 `init` 阶段触发 `fatal error: invalid function symbol table`。本
  基准模块把 loader 固定为 v0.5.2，这是包含 cloudwego 的必要条件。
- cloudwego 的 JIT 在 amd64 上按 CPU 特性选择内核；本机为 AVX2，未覆盖 AVX-512。
  AVX-512 主机上的 cloudwego 数字需要单独测量。
- cloudwego/base64x 没有 append API，因此 `AppendEncodeDecode` 仍只覆盖 ydx。
- 字符串/并行场景在同进程运行全部实现，可能受运行顺序影响；framework 场景使用
  `YD_BENCH_ONLY` 独立进程，跨实现比较优先使用该表。
