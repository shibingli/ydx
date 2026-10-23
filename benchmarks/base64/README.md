# benchmarks/base64 — 自适应 Base64 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/base64` 在所有架构上默认使用自研后端：amd64 在运行时按指令集完整性与优先级自动选择
手写 AVX-512 VBMI2/VBMI、AVX-512BW、AVX2 或标量内核；arm64 使用手写 NEON；其他架构使用
纯 Go 标量内核。全程不需要 `GOEXPERIMENT=simd`，也不依赖 cgo；显式 `b64x_std` 构建标签
回退到 `encoding/base64`。本基准在同一台机器、同一轮采样中比较默认自研后端、标准库与
cristalhq。

## 对比对象

| 实现 | 版本/构建 | 说明 |
|---|---|---|
| ydx/base64 | v0.1.8，默认构建 | 自研后端，运行时选择最宽可用内核 |
| `encoding/base64` | Go 1.27.2 | 标准库对照 |
| `github.com/cristalhq/base64` | v0.1.2 | 第三方实现（纯 Go SWAR） |

## 运行环境

- **amd64**：AMD Ryzen AI MAX+ 395（Zen 5，32 逻辑 CPU，AVX-512F/BW/VBMI/VBMI2），
  Linux，Go 1.27.2，`GOMAXPROCS=32`。
- **arm64**：Neoverse-N2，4 vCPU，3.0 GHz，Linux，Go 1.27.2。
- 实测日期：2026-10-23。

## 场景

- `Encode` / `Decode`：复用目标缓冲区，测纯编解码成本；覆盖 16 B、1 KiB、64 KiB。
- `EncodeToString` / `DecodeString`：分配式入口；覆盖 16 B 到 64 KiB。
- `RawURLEncode`：JWT 使用的无填充 URL 安全变体。
- `AppendEncodeDecode`：零拷贝 append 入口。
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

## 并行吞吐

`RunParallel` 聚合 ns/op，Ryzen 主机，同一二进制按 `-cpu 1,16,32` 运行：

| 场景 | 1 P | 16 P | 32 P | 16 P 加速比 |
|---|---:|---:|---:|---:|
| `Encode` 16 B | 6.41 ns | 0.48 ns | 0.47 ns | 13.4× |
| `Decode` 16 B | 8.18 ns | 0.59 ns | 0.585 ns | 13.9× |
| `Encode` 64 KiB | 1.06 µs | 84.0 ns | 83.9 ns | 12.6× |
| `Decode` 64 KiB | 2.37 µs | 171 ns | 160 ns | 13.8× |

编解码在 `init` 之后完全无共享可变状态：常量表与内核指针只读，目标缓冲由调用方持有，
因此扩展性只受内存带宽限制。16 B 在 16 线程仍有约 13–14 倍聚合吞吐；64 KiB 在 32 线程
进入写带宽瓶颈，继续增加并发不再线性增长。没有需要额外优化的锁或全局池竞争。

## 指令集内核

| 级别 | amd64 内核 | 覆盖 |
|---|---|---|
| 4 | AVX-512 VBMI2 解码 | 64 字符 → 48 字节，`VPERMB` + `VPMADDUBSW` + `VPCOMPRESSB` |
| 3 | AVX-512 VBMI 编码 | 48 字节 → 64 字符，`VPERMB` 查表 |
| 2 | AVX-512BW 编码/解码 | 按 128 位通道局部 `VPSHUFB`，解码用于 ≥4 KiB 输入 |
| 1 | AVX2 编码/解码 | 24 字节 ↔ 32 字符，全部输入的基线向量路径 |
| 0 | 标量 | 8 字符 SWAR 解码（24 位预移位表 + 64 位存储）、32 位分组加载 + 64 位存储编码 |

- 内核按指令集级别安装，与 `init` 顺序无关；同一级别内后安装者覆盖前者，高优先级内核
  始终胜出。URL 变体在 VBMI2 解码上继续使用 AVX2（其融合内核在该场景更快）。
- 标量路径不是兜底摆设：16 B 等短输入走 8 字符 SWAR 与宽加载/存储，避免 SIMD 分派和
  常量装载成本；raw 尾部 2/3 字符与 padded 尾部在快路径内直接解码，不再进入逐字符状态机。
- arm64 使用手写 NEON：48 字节 → 64 字符编码、64 字符 → 48 字节解码，标量路径负责尾部。

## 完整数据

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
```

## 口径与限制

- `Encode`/`Decode` 复用目标缓冲区，只测编解码成本；`EncodeToString`/`DecodeString`
  包含结果分配，不能与原地路径直接混比。
- 同一轮 3–5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声，
  `EncodeToString` 16 B 的领先幅度正处在该边界。
- 不同主机、不同 CPU 频率/温度或不同内核版本之间，绝对 ns/op 不可直接混比；请比较
  同一轮表格内的相对关系。
- cristalhq 为纯 Go 实现，不使用汇编；amd64 上与本实现的块路径差距主要来自 SIMD 宽度，
  arm64 上块路径来自 NEON 内核、短路径来自宽加载/存储标量路径。
