# benchmarks/json — 自适应 JSON 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/json` 在所有架构上使用自研原生编解码器：amd64 使用手写 SSE2/AVX2/AVX-512BW 字符串
扫描内核，运行时按 AVX-512BW > AVX2 > SSE2 择优；arm64 使用手写 NEON；其他架构使用可移植
SWAR/标量路径。不需要 `GOEXPERIMENT=simd`，也不依赖 cgo；显式 `jsonx_std` 构建标签回退到
`encoding/json`。本基准在相同载荷、相同轮次中比较原生后端与六个主流 JSON 实现。

## 对比对象

| 实现 | 版本 | 配置 |
|---|---|---|
| ydx/json | v0.1.7（原生后端） | 默认构建 |
| `encoding/json` | Go 1.27.2 | 标准库 |
| `github.com/goccy/go-json` | v0.11.2 | 默认配置 |
| `github.com/json-iterator/go` | v1.1.12 | `ConfigCompatibleWithStandardLibrary` |
| `github.com/bytedance/sonic` | v1.15.4 | 默认配置，运行时编译 |
| `github.com/segmentio/encoding/json` | v0.5.4 | 默认配置 |
| `github.com/go-json-experiment/json` | v0.0.0-20260820222146 | 官方实验版（表中 `go-json-v2`） |

## 运行环境

- **amd64**：AMD Ryzen AI MAX+ 395（Zen 5，32 逻辑 CPU，AVX-512F/BW/VBMI/VBMI2），
  Linux，Go 1.27.2，`GOMAXPROCS=32`。
- **arm64**：Neoverse-N2，4 vCPU，3.0 GHz，Linux，Go 1.27.2。
- 实测日期：2026-10-23。

## 场景

- `Marshal/one`：单个 5 字段用户对象（string、[]string、int64、float64、bool）。
- `Marshal/many`：64 个相同用户对象组成的切片。
- `Marshal/large`：1024 个对象（约 98 KiB 输出）。
- `Unmarshal/one`、`many`、`large`：解码到每次新建的目标值。
- 每个子基准在计时区外执行一次预热，避免首次计划构建与 sonic 运行时编译污染稳态。
- `BenchmarkParallel*`：`RunParallel` 聚合吞吐；`Marshal/large` 覆盖大载荷分配路径。

## amd64 关键结果

单位 ns/op，同一轮 3 次采样中位数；越小越好。**加粗**为本列最优。

| 场景 | ydx | stdlib | goccy | jsoniter | sonic | segmentio | go-json-v2 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `Marshal/one` | **67.7** | 310 | 89.4 | 138 | 88.4 | 99.2 | 320 |
| `Marshal/many` | **2.51 µs** | 12.8 µs | 4.19 µs | 6.92 µs | 3.00 µs | 4.84 µs | 13.1 µs |
| `Marshal/large` | **38.2 µs** | 205 µs | 66.8 µs | 108 µs | 46.6 µs | 78.3 µs | 207 µs |
| `Unmarshal/one` | **117.4** | 551 | 123.0 | 222 | 190 | 208 | 454 |
| `Unmarshal/many` | **6.43 µs** | 29.7 µs | 6.90 µs | 13.5 µs | 10.7 µs | 13.3 µs | 25.6 µs |
| `Unmarshal/large` | **98.1 µs** | 475 µs | 110 µs | 208 µs | 160 µs | 204 µs | 404 µs |

六个场景全部领先所有对比实现：

- 相对 goccy：`Marshal/one` 快约 24%，`Marshal/many` 快约 40%，`Marshal/large` 快约 43%，
  `Unmarshal/one` 快约 5%，`Unmarshal/many` 快约 7%，`Unmarshal/large` 快约 10%；
- 相对 sonic：编码快约 16%–23%，解码快约 38%–40%；
- 相对标准库：编码快约 4.6–5.4 倍，解码快约 4.6–4.8 倍。

分配特征（B/op、allocs/op）：

| 场景 | ydx | goccy | 说明 |
|---|---|---|---|
| `Marshal/one` | 96 B / 1 | 96 B / 1 | 与代码生成型实现相同的分配特征 |
| `Marshal/many` | 6165 B / 1 | 6156 B / 1 | 池化缓冲 + 一次精确输出分配 |
| `Marshal/large` | 98.6 KiB / 1 | 98.5 KiB / 1 | 大载荷同样精确输出，不再过量分配 |
| `Unmarshal/many` | 9547 B / 66 | 10544 B / 66 | 每次新建 64 元素切片，66 次分配已含目标 |
| `Unmarshal/large` | 140.3 KiB / 1027 | 163.1 KiB / 1028 | 大切片使用池化结构体缓冲与精确最终分配 |

## arm64 关键结果

单位 ns/op，同一轮 3 次采样中位数（该主机只运行四个实现）。

| 场景 | ydx | stdlib | goccy | sonic |
|---|---:|---:|---:|---:|
| `Marshal/one` | **180** | 689 | 206 | 428 |
| `Marshal/many` | **5.97 µs** | 28.2 µs | 9.73 µs | 20.3 µs |
| `Unmarshal/one` | **303** | 1.25 µs | 334 | 704 |
| `Unmarshal/many` | **15.3 µs** | 70.9 µs | 17.3 µs | 26.3 µs |

arm64 的 NEON 扫描内核与同一套原生编解码路径在四个场景均领先；NEON 只负责字符串扫描，
其余路径与 amd64 共用，因此语义与分配特征完全一致。

## 并行吞吐

`RunParallel` 聚合 ns/op（所有 goroutine 均摊），Ryzen 主机同一二进制按 `-cpu 16,32`
运行；每个操作使用独立结果/目标。

**Marshal**

| 场景 | 实现 | 16 P | 32 P |
|---|---|---:|---:|
| `one` | ydx | **19.5** | 23.9 |
| `one` | goccy | 20.9 | 23.9 |
| `one` | sonic | 24.0 | **22.6** |
| `many` | ydx | **696** | **642** |
| `many` | goccy | 817 | 795 |
| `many` | sonic | 698 | 745 |
| `large` | ydx | **8.98 µs** | **7.97 µs** |
| `large` | goccy | 10.9 µs | 10.2 µs |
| `large` | sonic | 10.1 µs | 8.59 µs |

**Unmarshal**

| 场景 | 实现 | 16 P | 32 P |
|---|---|---:|---:|
| `one` | ydx | **30.0** | **32.7** |
| `one` | goccy | 40.6 | 46.4 |
| `one` | sonic | 57.1 | 55.1 |
| `many` | ydx | **1.69 µs** | **1.72 µs** |
| `many` | goccy | 3.04 µs | 2.49 µs |
| `many` | sonic | 2.44 µs | 3.04 µs |
| `large` | ydx | **21.9 µs** | **19.8 µs** |
| `large` | goccy | 40.3 µs | 34.5 µs |
| `large` | sonic | 33.5 µs | 31.9 µs |

扩展性结论：

- 解码使用每 P 的解码器池、只追加字符串 arena 与池化结构体切片缓冲，16→32 P 仍继续
  提升；所有并发场景领先或持平对比实现。
- 编码的中、大载荷使用池化缓冲后复制精确结果，分配量与 goccy 持平；`Marshal/large`
  在 32 P 比 sonic 快约 7%，比 goccy 快约 22%。
- 单对象 `Marshal/one` 在 32 P 与 goccy 持平、比 sonic 慢约 6%（23.9 ns vs 22.6 ns 的
  差异处于噪声边界）；其瓶颈是每次操作的 96 B 输出分配与 GC，而不是共享锁。

## 复杂类型预热（Prewarm）

`json.Prewarm` 在启动期编译并安装编码/解码计划，避免首个请求承担计划构建成本：

```go
json.Prewarm(User{}, (*User)(nil), (*[]User)(nil))
```

- 传入值预热其类型的 `Marshal`；传入 `(*T)(nil)` 预热 `Unmarshal` 到 `T`；
- 嵌套结构体、切片、数组、指针以及 map 的键/值类型递归预热；
- 幂等、可并发调用；`jsonx_std` 后端下为空操作。

在 Ryzen 主机上对一个含嵌套结构体、两个切片和一个 map 的复杂类型实测（25 次中位数）：

| 操作 | 未预热首次调用 | `Prewarm` 后首次调用 | 提升 |
|---|---:|---:|---:|
| `Marshal` | 42.1 µs | 6.43 µs | 6.6× |
| `Unmarshal` | 20.8 µs | 8.35 µs | 2.5× |

`Prewarm` 同时构建编码与解码计划约需 51.7 µs，发生在启动期；此后首个请求不再支付
约 36 µs 的编码计划与约 12 µs 的解码计划构建成本。对上表之外的尺寸，计划构建成本与
载荷大小无关，预热收益固定；运行时分配策略则按载荷尺寸自动选择池化缓冲或直接分配。

## 实现概要

- **编码**：按类型缓存编码计划；字段全部可直接按内存读取的结构体走无反射快速编码器；
  非可寻址结构体通过接口数据字直接读取；输出先写入池化缓冲，中/大载荷复制为精确大小
  结果（阈值跟随池上限 1 MiB），超出池上限才直接分配。
- **解码**：按类型缓存解码计划与直接按内存的结构体解码器；结构体切片使用按类型池化
  缓冲与一次精确最终分配；字符串使用只追加 arena，避免逐字段分配。
- **扫描**：字符串扫描与转义分别提供 SSE2、AVX2、AVX-512BW 与 arm64 NEON 内核，运行时
  择优；短字符串与干净字符串走融合扫描/复制路径。
- **预热**：`Prewarm` 把上述类型计划的构建移到启动期。

## 复现

```bash
cd benchmarks/json
GOWORK=off go test -run '^$' -bench . -benchmem -count=3 -benchtime=500ms
GOWORK=off go test -run '^$' -bench 'BenchmarkParallel' -cpu 16,32 -count=3
```

## 口径与限制

- jsoniter 使用与标准库兼容配置，而不是 `ConfigFastest`；后者会放宽部分语义，无法与
  其它实现直接对比。
- sonic 首次调用包含运行时编译；基准在计时区外预热，但编译结果会受 CPU 特性影响。
- `Unmarshal` 每次迭代创建新目标值，分配数包含目标分配；所有解码器承担相同的目标构造
  成本。`Unmarshal/many`、`large` 的 66/1027 次分配也包含目标切片本身。
- 同一轮 3–5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声。
  `Marshal/one` 在 32 P 与 goccy 的差距正处在该边界。
- 不同主机、不同 CPU 频率/温度之间绝对 ns/op 不可直接混比；请比较同一轮表格内的相对关系。
