# benchmarks/json — 自适应 JSON 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/json` 在所有架构上使用自研原生编解码器：amd64 使用手写 SSE2/AVX2/AVX-512BW 字符串
扫描内核，运行时按 AVX-512BW > AVX2 > SSE2 择优；arm64 使用手写 NEON；其他架构使用可移植
SWAR/标量路径。不需要 `GOEXPERIMENT=simd`，也不依赖 cgo；显式 `jsonx_std` 构建标签回退到
`encoding/json`。本基准在相同载荷、相同轮次中比较原生后端与六个主流 JSON 实现。

## 对比对象

| 实现 | 版本 | 配置 |
|---|---|---|
| ydx/json | v0.1.15（原生后端） | 默认构建 |
| `encoding/json` | Go 1.27.3 | 标准库 |
| `github.com/goccy/go-json` | v0.11.2 | 默认配置 |
| `github.com/json-iterator/go` | v1.1.12 | `ConfigCompatibleWithStandardLibrary` |
| `github.com/bytedance/sonic` | v1.15.4 | 默认配置，运行时编译 |
| `github.com/segmentio/encoding/json` | v0.5.4 | 默认配置 |
| `github.com/go-json-experiment/json` | v0.0.0-20260820222146 | 官方实验版（表中 `go-json-v2`） |

> 表中数值于 2026-11-01 在 v0.1.15 上重测（5 次中位数）；`FrameworkUnmarshal/n=1`
> 另用 10 次独立重测确认（见下文）。长小数与 `time.Time` 载荷的对照见
> [`../yd-vs-ydx-analysis.md`](../yd-vs-ydx-analysis.md)。

> 2026-10-24：yd 仓的 7 字段 `record` 载荷（`time.Time`、长小数、n=1/100/1000、并行）
> 已并入本模块，对应 `BenchmarkFrameworkMarshal/Unmarshal*`；主表同时保留 5 字段
> `benchUser` 载荷（`BenchmarkMarshal/Unmarshal*`）。两套载荷的结果都在同一台主机、
> 同一轮采样中给出。

## API 兼容性测试

`api_compat_test.go` 覆盖本模块新增（v0.1.15）的 `encoding/json` 完整 API 面，并与标准库
逐项对拍：

- `TestFormattingAPIMatchesStdlib`：`Compact`、`Indent`、`HTMLEscape` 的输出与语法错误
  类型/偏移；
- `TestTokenAPIMatchesStdlib`：`Token` 序列、`More`、`Buffered`、`InputOffset`；
- `TestEncoderOptionsMatchStdlib`：`Encoder.SetIndent`、`Encoder.SetEscapeHTML`、
  `Decoder.DisallowUnknownFields`；
- `TestErrorTypesMatchStdlib`：`SyntaxError`、`UnmarshalTypeError`、
  `InvalidUnmarshalError`、`UnsupportedTypeError` 的 `errors.As` 兼容性；
- `TestUnicodeAPIMatchesStdlib`：CJK、表情符号、组合附加符、元字符、控制字符与
  U+2028/U+2029 在字符串、对象键与字段名别名中的编码/解码，包含 `SetEscapeHTML`
  对字段名的转义；`unicodeTagTarget` 覆盖含 CJK、emoji、空格和保留字符的标签别名；
- `TestEncodersAgree` / `TestDecodersAgree`：所有对比实现输出合法 JSON 且往返值一致。

## 运行环境

- **amd64**：AMD Ryzen AI MAX+ 395（Zen 5，32 逻辑 CPU，AVX-512F/BW/VBMI/VBMI2），
  Linux，Go 1.27.3，`GOMAXPROCS=32`。
- **arm64**：Neoverse-N2，4 vCPU，3.0 GHz，Linux，Go 1.27.3。
- 实测日期：2026-10-24 首次采样；2026-11-01 在 v0.1.15 上复测。

## 场景

- `Marshal/one`：单个 5 字段用户对象（string、[]string、int64、float64、bool）。
- `Marshal/many`：64 个相同用户对象组成的切片。
- `Marshal/large`：1024 个对象（约 98 KiB 输出）。
- `Unmarshal/one`、`many`、`large`：解码到每次新建的目标值。
- 每个子基准在计时区外执行一次预热，避免首次计划构建与 sonic 运行时编译污染稳态。
- `BenchmarkParallel*`：`RunParallel` 聚合吞吐；`Marshal/large` 覆盖大载荷分配路径。

## amd64 关键结果

单位 ns/op，同一轮 5 次采样中位数；越小越好。**加粗**为本列最优。

| 场景 | ydx | stdlib | goccy | jsoniter | sonic | segmentio | go-json-v2 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `Marshal/one` | **61.88** | 318.5 | 99.23 | 158.9 | 94.86 | 105.9 | 315.9 |
| `Marshal/many` | **2.799 µs** | 12.93 µs | 4.503 µs | 7.241 µs | 3.357 µs | 5.174 µs | 13.03 µs |
| `Marshal/large` | **43.07 µs** | 208.4 µs | 71.58 µs | 115.8 µs | 50.01 µs | 79.47 µs | 203.7 µs |
| `Unmarshal/one` | **120.7** | 559.2 | 137.2 | 254.3 | 193.0 | 232.6 | 458.6 |
| `Unmarshal/many` | **7.233 µs** | 30.15 µs | 7.697 µs | 15.45 µs | 12.28 µs | 13.37 µs | 26.27 µs |
| `Unmarshal/large` | **110.1 µs** | 458.4 µs | 121.1 µs | 232.6 µs | 160.2 µs | 226.9 µs | 407.7 µs |

六个场景全部领先所有对比实现：

- 相对 goccy：`Marshal/one` 快约 38%，`Marshal/many` 快约 38%，`Marshal/large` 快约 40%，
  `Unmarshal/one` 快约 12%，`Unmarshal/many` 快约 6.0%，`Unmarshal/large` 快约 9.1%；
- 相对 sonic：编码快约 14%–35%，解码快约 31%–41%；
- 相对标准库：编码快约 4.6–5.1 倍，解码快约 4.2–4.6 倍。

分配特征（B/op、allocs/op）：

| 场景 | ydx | goccy | 说明 |
|---|---|---|---|
| `Marshal/one` | 96 B / 1 | 96 B / 1 | 与代码生成型实现相同的分配特征 |
| `Marshal/many` | 6.02 KiB / 1 | 6.01 KiB / 1 | 池化缓冲 + 一次精确输出分配 |
| `Marshal/large` | 96.3 KiB / 1 | 96.1 KiB / 1 | 大载荷同样精确输出，不再过量分配 |
| `Unmarshal/many` | 9.31 KiB / 66 | 10.29 KiB / 66 | 每次新建 64 元素切片，66 次分配已含目标 |
| `Unmarshal/large` | 136.8 KiB / 1027 | 159.3 KiB / 1028 | 大切片使用池化结构体缓冲与精确最终分配 |

### 7 字段 record 载荷（合并自 yd，2026-10-24）

该载荷含 `time.Time`、长小数 `Score=float64(i)/3`，并覆盖 n=1/100/1000 与并行场景；
对应 `BenchmarkFrameworkMarshal/Unmarshal*`。同一轮 5 次中位数：

| 场景 | ydx | go-json | sonic-std | stdlib |
|---|---:|---:|---:|---:|
| `Marshal/n=1` | **97.43 ns** | 118.3 ns | 305.8 ns | 409.6 ns |
| `Marshal/n=100` | **8.729 µs** | 12.06 µs | 16.48 µs | 30.31 µs |
| `Marshal/n=1000` | **87.91 µs** | 110.4 µs | 157.1 µs | 295.1 µs |
| `Unmarshal/n=1` | **219.3 ns** | 256.3 ns | 365.5 ns | 797.6 ns |
| `Unmarshal/n=100` | **16.28 µs** | 20.04 µs | 30.43 µs | 69.37 µs |
| `Unmarshal/n=1000` | **162.1 µs** | 180.9 µs | 286.9 µs | 691.1 µs |

- n=1 的 Unmarshal 领先 go-json 约 14.4%（219.3 vs 256.3 ns），保持 3 allocs、
  221 B/op（go-json 为 3 allocs、543 B/op）；n=100/1000 的 Unmarshal 领先约
  18.8%/10.4%，长小数与 `time.Time` 载荷不再构成弱项。独立 10 次复测为
  224.5 ns vs 252.0 ns，结论一致。
- n=1 的优化：载荷不超过 512 字节时直接把元素解码进紧凑目标切片，跳过池化暂存缓冲的
  Get/解码/复制/清零往返；大载荷仍走池化路径，以保持「结果容量精确、分配次数与真实
  大小一致」。同进程 A/B 显示该路径从约 538 ns 降到约 470 ns（本地开发机），分配次数
  与字节数不变；Zen 5 上 n=1 从 250.9 ns 降到 214.2 ns。

## arm64 关键结果

单位 ns/op，同一轮 3 次采样中位数（该主机只运行四个实现）。

| 场景 | ydx | stdlib | goccy | sonic |
|---|---:|---:|---:|---:|
| `Marshal/one` | **162** | 689 | 206 | 428 |
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
| `one` | ydx | **17.4** | **21.2** |
| `one` | goccy | 23.3 | 24.3 |
| `one` | sonic | 23.7 | 23.8 |
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
- 单对象 `Marshal/one` 在 32 P 比 sonic 快约 11%、比 goccy 快约 13%，16 P 领先约 26%；
  此前的瓶颈是逐字段回写堆上 `e.buf` 引发的写屏障，现已改为局部缓冲单次回写，并给
  快速结构体计划加了最近类型原子缓存。剩余成本主要是每次操作 96 B 输出分配与 GC。

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
  非可寻址结构体通过接口数据字直接读取，单结构体与结构体切片都用局部缓冲编码、每个值
  只回写一次 `e.buf`，消除逐字段写屏障；输出先写入池化缓冲，中/大载荷复制为精确大小
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
- 不同主机、不同 CPU 频率/温度之间绝对 ns/op 不可直接混比；请比较同一轮表格内的相对关系。
