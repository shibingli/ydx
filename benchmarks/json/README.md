# benchmarks/json — 自适应 JSON 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/json` 在所有架构上使用自研原生编解码器：amd64 使用手写 SSE2/AVX2/AVX-512BW 字符串
扫描内核，运行时按 AVX-512BW > AVX2 > SSE2 择优；arm64 使用手写 NEON；其他架构使用可移植
SWAR/标量路径。不需要 `GOEXPERIMENT=simd`，也不依赖 cgo；显式 `jsonx_std` 构建标签回退到
`encoding/json`。本基准在相同载荷、相同轮次中比较原生后端与六个主流 JSON 实现。

## 对比对象

| 实现 | 版本 | 配置 |
|---|---|---|
| ydx/json | 本地工作区（原生后端） | 默认构建，v1 语义 |
| ydx/json v2 | 本地工作区（原生后端） | `DefaultOptionsV2()`，表中 `jsonx-v2` |
| `encoding/json` | Go 1.27.3 | 标准库 v1 |
| `encoding/json/v2` | Go 1.27.3 | 标准库 v2，表中 `stdlib-v2` |
| `github.com/goccy/go-json` | v0.11.2 | 默认配置 |
| `github.com/json-iterator/go` | v1.1.12 | `ConfigCompatibleWithStandardLibrary` |
| `github.com/bytedance/sonic` | v1.15.4 | 默认配置，运行时编译 |
| `github.com/segmentio/encoding/json` | v0.5.4 | 默认配置 |
| `github.com/go-json-experiment/json` | v0.0.0-20260820222146 | 官方实验版（表中 `go-json-v2`） |

> 基准模块通过仓库外临时 `go.work` 使用本地工作区的 `ydx/json`，不提交任何本地 `replace`。

> 表中数值于 2026-11-01 在 v0.1.15 上重测（5 次中位数）；`FrameworkUnmarshal/n=1`
> 另用 10 次独立重测确认（见下文）。长小数与 `time.Time` 载荷的对照见
> [`../yd-vs-ydx-analysis.md`](../yd-vs-ydx-analysis.md)。

> 2026-10-24：yd 仓的 7 字段 `record` 载荷（`time.Time`、长小数、n=1/100/1000、并行）
> 已并入本模块，对应 `BenchmarkFrameworkMarshal/Unmarshal*`；主表同时保留 5 字段
> `benchUser` 载荷（`BenchmarkMarshal/Unmarshal*`）。两套载荷的结果都在同一台主机、
> 同一轮采样中给出。

## v2 API 对比

v2 条目由 `jsonx_v2_bench` 构建标签启用（默认构建仍兼容 `go.mod` 固定的已发布 `ydx/json` 版本）。在仓库外临时 `go.work` 指向本地工作区后运行：

```bash
GOWORK=/path/outside/repo/go.work go test -tags jsonx_v2_bench -run '^$' -bench . -benchmem
```

`bench_test.go` 的编码器/解码器集合新增两个条目：

- `jsonx-v2`：`ydx/json.Marshal(v, ydxjson.DefaultOptionsV2())` 与对应 `Unmarshal`；
- `stdlib-v2`：`encoding/json/v2` 的 `Marshal` / `Unmarshal`。

同一轮内对比默认 v2 语义（不转义 HTML、nil 容器、大小写敏感、拒绝重复键等）。v2 入口与
v1 共用原生计划、SIMD 扫描与池化缓冲；`json` 模块内的 `json_v2_*_test.go` 另行覆盖
选项、标签、嵌入回退、自定义 Marshalers、流式入口与错误类型对拍。

远程 Zen5（AMD Ryzen AI MAX+ 395，32 逻辑 CPU，Go 1.27.3，`-count=5` 中位数）结果：

| 场景 | jsonx-v2 | stdlib-v2 | go-json-v2 | 相对 stdlib-v2 |
|---|---:|---:|---:|---:|
| `Marshal/one` | **71.1 ns** | 314.3 ns | 316.4 ns | 4.4× |
| `Marshal/many`（64） | **2.796 µs** | 12.84 µs | 12.77 µs | 4.6× |
| `Marshal/large`（1024） | **43.81 µs** | 203.4 µs | 202.5 µs | 4.6× |
| `Unmarshal/one` | 128.9 ns | 436.5 ns | 432.5 ns | 3.4× |
| `Unmarshal/many`（64） | 6.830 µs | 24.58 µs | 25.94 µs | 3.6× |
| `Unmarshal/large`（1024） | 105.9 µs | 393.7 µs | 387.2 µs | 3.7× |

分配特征与 v1 相同：`Marshal/one` 96 B / 1 alloc，`Unmarshal/one` 136 B / 2 alloc。
`Unmarshal/one` 与 `Unmarshal/many` 分别受 v2 重复键/UTF-8 校验影响，比 v1 慢约 5% 和
2%，但仍比 `stdlib-v2` 快 3.3 倍和 3.6 倍；其余四个场景 v2 与 v1 持平或更快。

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
- 实测日期：2026-10-24 首次采样；2026-11-01 在 v0.1.15 上复测；2026-11-07 在远程
  Zen5/Neoverse-N2/Xeon 三台主机上加入 v2 入口并完成兼容性、串行与并行复测。

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
| `Marshal/one` | **73.8** | 312.9 | 88.0 | 138.7 | 88.5 | 98.1 | 316.4 |
| `Marshal/many` | **3.010 µs** | 12.61 µs | 4.173 µs | 6.862 µs | 3.011 µs | 4.759 µs | 12.77 µs |
| `Marshal/large` | 47.91 µs | 200.5 µs | 66.02 µs | 106.5 µs | **46.98 µs** | 77.03 µs | 202.5 µs |
| `Unmarshal/one` | 126.3 | 539.5 | **121.1** | 224.7 | 190.3 | 226.0 | 432.5 |
| `Unmarshal/many` | **6.718 µs** | 28.71 µs | 6.767 µs | 13.46 µs | 10.59 µs | 14.08 µs | 25.94 µs |
| `Unmarshal/large` | **103.3 µs** | 445.4 µs | 109.0 µs | 210.6 µs | 162.0 µs | 220.8 µs | 387.2 µs |

v1 路径在 4/6 场景最优；`Marshal/large` 与 sonic 相差约 2%，`Unmarshal/one` 与 goccy
相差约 4%（136 B/2 allocs 对 152 B/2 allocs）。相对标准库：编码快约 4.2–4.3 倍，
解码快约 4.3 倍。

v2 入口（`jsonx-v2`）在同一轮中进一步领先：详见下节，六个场景相对 `stdlib-v2` 快
3.3–4.6 倍，其中 `Marshal/one`、`Marshal/many`、`Marshal/large` 为全场最优。

分配特征（B/op、allocs/op）：

| 场景 | ydx | goccy | 说明 |
|---|---|---|---|
| `Marshal/one` | 96 B / 1 | 96 B / 1 | 与代码生成型实现相同的分配特征 |
| `Marshal/many` | 6.16 KiB / 1 | 6.16 KiB / 1 | 池化缓冲 + 一次精确输出分配 |
| `Marshal/large` | 98.6 KiB / 1 | 98.5 KiB / 1 | 大载荷同样精确输出，不再过量分配 |
| `Unmarshal/many` | 9.55 KiB / 66 | 10.54 KiB / 66 | 每次新建 64 元素切片，66 次分配已含目标 |
| `Unmarshal/large` | 140.4 KiB / 1027 | 163.7 KiB / 1028 | 大切片使用池化结构体缓冲与精确最终分配 |

### 7 字段 record 载荷（合并自 yd，2026-10-24）

该载荷含 `time.Time`、长小数 `Score=float64(i)/3`，并覆盖 n=1/100/1000 与并行场景；
对应 `BenchmarkFrameworkMarshal/Unmarshal*`。远程 Zen5，`-count=3`（n=1 为 `-count=10`）
中位数：

| 场景 | ydx | ydx-v2 | go-json | sonic-std | stdlib |
|---|---:|---:|---:|---:|---:|
| `Marshal/n=1` | 111.0 ns | **109.2 ns** | 124.7 ns | 278.1 ns | 433.9 ns |
| `Marshal/n=100` | 9.60 µs | **9.29 µs** | 11.37 µs | 16.96 µs | 31.85 µs |
| `Marshal/n=1000` | 92.20 µs | **89.60 µs** | 112.6 µs | 175.2 µs | 310.2 µs |
| `Unmarshal/n=1` | **223.8 ns** | 224.5 ns | 246.6 ns | 413.3 ns | 889.7 ns |
| `Unmarshal/n=100` | **16.61 µs** | 16.95 µs | 18.70 µs | 31.11 µs | 78.46 µs |
| `Unmarshal/n=1000` | **163.1 µs** | 168.8 µs | 180.9 µs | 308.3 µs | 765.8 µs |

- 该载荷下 v2 入口在三个编码场景均为全场最优；解码场景与 v1 相差约 0–3.5%，仍领先
  go-json 与 sonic-std。
- n=1 的 Unmarshal 保持 2 allocs、168 B/op（go-json 为 2 allocs、168 B/op），长小数与
  `time.Time` 不构成弱项。

## arm64 关键结果

单位 ns/op，同一轮 3 次采样中位数（Neoverse-N2，4 vCPU）。

| 场景 | ydx | ydx-v2 | stdlib | goccy | sonic |
|---|---:|---:|---:|---:|---:|
| `Marshal/one` | **174.5** | 177.5 | 696.6 | 207.1 | 431.7 |
| `Marshal/many` | 7.170 µs | **6.968 µs** | 28.90 µs | 9.678 µs | 20.65 µs |
| `Marshal/large` | 113.9 µs | **110.3 µs** | 459.1 µs | 155.7 µs | 331.2 µs |
| `Unmarshal/one` | **324.7** | 340.7 | 1246 | 339.5 | 700.0 |
| `Unmarshal/many` | **16.58 µs** | 16.85 µs | 71.58 µs | 17.59 µs | 26.75 µs |
| `Unmarshal/large` | **260.8 µs** | 266.1 µs | 1139 µs | 303.7 µs | 413.9 µs |

arm64 的 NEON 扫描内核与同一套原生编解码路径在六个场景均领先 stdlib-v2（约 2–4 倍）；
v2 与 v1 的差距在解码场景约 2–5%，与 amd64 的重复键/UTF-8 校验成本一致。NEON 只负责
字符串扫描，其余路径与 amd64 共用，因此语义与分配特征完全一致。

## 并行吞吐

`RunParallel` 聚合 ns/op（所有 goroutine 均摊），Ryzen 主机同一二进制按 `-cpu 16,32`
运行；每个操作使用独立结果/目标。

**Marshal**

| 场景 | 实现 | 16 P | 32 P |
|---|---|---:|---:|
| `one` | ydx | 22.6 | 21.8 |
| `one` | ydx-v2 | **20.4** | 22.0 |
| `one` | goccy | 23.0 | 24.0 |
| `one` | sonic | 23.8 | 22.0 |
| `many` | ydx | 759.4 | 705.5 |
| `many` | ydx-v2 | 737.2 | **690.9** |
| `many` | goccy | 847.8 | 826.2 |
| `many` | sonic | **675.7** | 739.4 |
| `large` | ydx | 9.908 µs | 8.752 µs |
| `large` | ydx-v2 | **9.744 µs** | **8.583 µs** |
| `large` | goccy | 10.83 µs | 10.33 µs |
| `large` | sonic | 9.892 µs | 8.700 µs |

**Unmarshal**

| 场景 | 实现 | 16 P | 32 P |
|---|---|---:|---:|
| `one` | ydx | 31.2 | **33.5** |
| `one` | ydx-v2 | **29.2** | **33.5** |
| `one` | goccy | 61.7 | 57.0 |
| `one` | sonic | 49.9 | 54.2 |
| `many` | ydx | 1.950 µs | **1.745 µs** |
| `many` | ydx-v2 | **1.914 µs** | 1.755 µs |
| `many` | goccy | 3.003 µs | 2.603 µs |
| `many` | sonic | 3.136 µs | 3.140 µs |
| `large` | ydx | 25.62 µs | **22.13 µs** |
| `large` | ydx-v2 | **25.52 µs** | 22.23 µs |
| `large` | goccy | 39.29 µs | 34.78 µs |
| `large` | sonic | 37.46 µs | 33.07 µs |

扩展性结论：

- 解码使用每 P 的解码器池、只追加字符串 arena 与池化结构体切片缓冲，16→32 P 仍继续
  提升；v2 入口在 16 P 的三个解码场景均为最优，32 P 与 v1 相差不超过 1%。
- 编码的中、大载荷使用池化缓冲后复制精确结果，分配量与 goccy 持平；`Marshal/large`
  在 16/32 P 均为 v2 最优（9.744/8.583 µs），比 sonic 快约 2%/1%，比 goccy 快约
  10%/17%。
- 单对象 `Marshal/one` 在 16 P 为 v2 最优（20.4 ns），32 P 与 sonic 持平（22.0 ns）；
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
# v2 对比需要本地工作区与构建标签。
GOWORK=/path/outside/repo/go.work go test -tags jsonx_v2_bench -run '^$' -bench . -benchmem -count=3 -benchtime=500ms
```

## 口径与限制

- jsoniter 使用与标准库兼容配置，而不是 `ConfigFastest`；后者会放宽部分语义，无法与
  其它实现直接对比。
- sonic 首次调用包含运行时编译；基准在计时区外预热，但编译结果会受 CPU 特性影响。
- `Unmarshal` 每次迭代创建新目标值，分配数包含目标分配；所有解码器承担相同的目标构造
  成本。`Unmarshal/many`、`large` 的 66/1027 次分配也包含目标切片本身。
- 同一轮 3–5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声。
- 不同主机、不同 CPU 频率/温度之间绝对 ns/op 不可直接混比；请比较同一轮表格内的相对关系。
