# regexpx 基准

对比自研 `github.com/shibingli/ydx/regexpx` 与 Go 主流正则实现的延迟、吞吐与分配。

> 最新指标：`regexpx v0.1.13` 的兼容 API、本机 AVX2 与并行结果；Zen 5、AVX-512、arm64 表为历史远端数据。

## 对比对象

| 标签 | 实现 | 说明 |
|---|---|---|
| `ydx` | 本仓 `regexpx` | 自研解析器、Pike VM、回溯 VM、惰性 ASCII 搜索 DFA、运行/定长/线性/邮件/字面量快速路径与 SIMD 预过滤 |
| `stdlib` | 标准库 `regexp` | RE2 语法，one-pass / bitstate / NFA |
| `grafana` | `github.com/grafana/regexp` | 标准库分支，接口与语义相同 |
| `regexp2` | `github.com/dlclark/regexp2` | .NET 回溯引擎，使用 `regexp2.RE2` 模式 |
| `go-re2` | `github.com/wasilibs/go-re2` | RE2 C++ 经 wazero 运行（WASM） |

## 环境与方法

- **本机最新（2026-10-31）**：Windows 11，Intel i9-10980HK（AVX2），Go 1.27.3，regexpx v0.1.13。
- **历史远端（2026-10-24）**：AMD Ryzen AI MAX+ 395（Zen 5，32 线程，AVX-512F/BW/VBMI/VBMI2），Ubuntu 26.04，Go 1.27.3，`GOMAXPROCS=32`；AVX-512 主机；Skylake 代 AVX-512 主机；aarch64 NEON 主机。远端表保留作架构横向参考，尚未在 v0.1.13 上复测。
- 语料：256 KiB 的英文/数字/日期/邮箱/URL 混合文本；128 KiB 中英希混合文本；128 KiB 含 emoji（ZWJ、肤色、旗帜、变体选择符）、简繁中文与中英文混排的混合文本。
- 计时：本机主表与并行 `-benchtime=300ms -count=5`，兼容 API `-benchtime=1s -count=6`；历史远端 `-benchtime=80ms -count=3`；均 `-benchmem`，所有模式在计时外编译。
- 绝对值受 CPU、负载与调度影响；跨实现比较请优先看同一行的相对值。

## 兼容 API 指标（regexpx v0.1.13，2026-10-31）

`api_bench_test.go` 覆盖 `Copy`、`Expand`、流式替换、`Longest` 快路径、Reader 提前返回与
回溯最长匹配，与标准库同场对比。完整表格、内存/分配、分析、复现命令与原始样本见
[`../../regexpx/PERFORMANCE.md`](../../regexpx/PERFORMANCE.md)。

| 项目 | regexpx | 标准库 | 结论 |
|---|---:|---:|---|
| `Copy` | ~37.7 ns，160 B，1 alloc | ~37.7 ns，160 B，1 alloc | 基本持平 |
| `ReplaceAllString` | ~263 µs，3 allocs | ~695 µs，18 allocs | 约 2.6x 快 |
| `ReplaceAllLiteralString` | ~172 µs，5 allocs | ~568 µs，21 allocs | 约 3.3x 快 |
| `Longest` 通配字面量 | ~121 ns，0 alloc | ~128 µs，0 alloc | 约 1050x 快 |
| `Longest` 定长线性 | ~181 ns，0 alloc | ~50.3 µs，0 alloc | 约 278x 快 |
| `MatchReader` 早期匹配 | ~43 ns | ~85 ns | 约 2.0x 快 |
| `FindReaderIndex` 早期匹配 | ~77 ns | ~125 ns | 约 1.6x 快 |
| `LiteralPrefix` | ~1.8 ns | ~0.67 ns | 纳秒级，非热路径 |

原始样本与 `benchstat` 输出见
[`results/regexpx-v0.1.13-api-windows-i9-10980hk.txt`](results/regexpx-v0.1.13-api-windows-i9-10980hk.txt)
与 [`results/regexpx-v0.1.13-api-windows-benchstat.txt`](results/regexpx-v0.1.13-api-windows-benchstat.txt)。

## 历史远端主机：Zen 5 主表（2026-10-24）

| 场景 | ydx | stdlib | grafana | regexp2 | go-re2 |
|---|---:|---:|---:|---:|---:|
| MatchString/literal | **10.70 ns** | 226.9 ns | 225.3 ns | 176.4 µs | 2.216 µs |
| MatchString/email | **36.73 ns** | 527.1 ns | 535.0 ns | 170.1 µs | 2.001 µs |
| MatchString/date | **38.53 ns** | 492.7 ns | 501.1 ns | 170.6 µs | 2.032 µs |
| MatchString/anchored_id | **11.30 ns** | 120.3 ns | 122.5 ns | 113.4 ns | 89.67 ns |
| FindAll/email | **94.98 µs** | 5.679 ms | 5.66 ms | 21.1 ms | 732.3 µs |
| FindAll/date | **110.8 µs** | 3.872 ms | 4.01 ms | 3.54 ms | 705.5 µs |

所有匹配/查找/批量扫描场景领先；简单模式（如 `\d+`）的 `BenchmarkCompile` 仍慢于
标准库（约 780 vs 253 ns），属于启动期一次性解析/编译成本，不影响请求热路径。

## 本机 AVX2 结果（regexpx v0.1.13，2026-10-31）

| 场景 | ydx | stdlib | grafana | regexp2 | go-re2 |
|---|---:|---:|---:|---:|---:|
| MatchString/literal | **34.7 ns** | 503 ns | 488 ns | 360 µs | 10.7 µs |
| MatchString/literal_ci | **99.8 µs** | 6.17 ms | 5.97 ms | 644 µs | 273 µs |
| MatchString/word | **54.0 ns** | 123 ns | 121 ns | 367 µs | 10.4 µs |
| MatchString/email | **77.5 ns** | 1.16 µs | 1.15 µs | 365 µs | 10.6 µs |
| MatchString/uri | **194 ns** | 415 ns | 404 ns | 370 µs | 10.3 µs |
| MatchString/date | **86.8 ns** | 1.03 µs | 1.00 µs | 366 µs | 10.9 µs |
| MatchString/anchored_id | **24.5 ns** | 277 ns | 266 ns | 247 ns | 193 ns |
| MatchString/unicode | **72.8 ns** | 149 ns | 155 ns | 285 µs | 3.19 µs |
| MatchString/han | **80.6 ns** | 137 ns | 142 ns | 249 µs | 3.08 µs |
| MatchString/emoji | **107 ns** | 184 ns | 182 ns | 254 µs | 3.66 µs |
| FindStringIndex/word | **62.6 ns** | 413 ns | 412 ns | 1.34 ms | 10.8 µs |
| FindStringIndex/literal | **44.6 ns** | 559 ns | 559 ns | 1.38 ms | 11.2 µs |
| FindStringIndex/literal_ci | **100.5 µs** | 6.76 ms | 6.46 ms | 724 µs | 269 µs |
| FindStringIndex/email | **91.8 ns** | 1.37 µs | 1.35 µs | 1.55 ms | 10.7 µs |
| FindStringIndex/uri | **212 ns** | 1.20 µs | 1.17 µs | 1.48 ms | 10.9 µs |
| FindStringIndex/date | **99.5 ns** | 1.17 µs | 1.17 µs | 1.48 ms | 10.9 µs |
| FindStringIndex/anchored_id | **47.5 ns** | 311 ns | 308 ns | 504 ns | 270 ns |
| FindStringIndex/captures | **889 ns** | 1.25 µs | 1.22 µs | 1.57 ms | 10.8 µs |
| FindAll/word | **5.40 ms** | 17.1 ms | 18.2 ms | 20.9 ms | 19.6 ms |
| FindAll/email | **254 µs** | 11.9 ms | 11.7 ms | 41.7 ms | 1.52 ms |
| FindAll/date | **291 µs** | 8.06 ms | 8.04 ms | 6.42 ms | 1.48 ms |
| FindAll/unicode | **2.38 ms** | 5.87 ms | 6.10 ms | 8.65 ms | 5.63 ms |
| FindAll/han | **1.23 ms** | 2.70 ms | 2.63 ms | 3.62 ms | 1.69 ms |
| FindAll/emoji | **1.95 ms** | 4.10 ms | 4.03 ms | 5.83 ms | 3.75 ms |

表中 24 个场景全部最快；完整 32 个场景也全部最快。四个重点场景：

- `(?i)` 字面量：2 字节折叠 SIMD 扫描后为 99.8 µs，约为 go-re2 的 1/2.7、标准库的 1/62。
- URI `MatchString`：可选段 + 尾运行的线性匹配器后为 194 ns，约为标准库的 1/2.1。
- 邮箱 `FindAll`：围绕 `@` 定位并反向扫描局部部分后为 254 µs，约为标准库的 1/47、go-re2 的 1/6.0。
- 日期 `FindAll`：以固定偏移的 `-` 为锚点后为 291 µs，约为 go-re2 的 1/5.1、标准库的 1/28。

`BenchmarkCompile` 是启动期一次性成本：简单模式 `\d+` 约 1.9 µs（标准库 0.61 µs），
锚定 ID 约 5.6 µs（标准库 32 µs），邮箱形态约 4.6 µs（标准库 2.8 µs），不影响请求热路径。

## 历史远端主机：AVX-512（2026-10-24）

| 场景 | ydx | stdlib | grafana | regexp2 | go-re2 |
|---|---:|---:|---:|---:|---:|
| MatchString/literal | 10.8 ns | 222 ns | 226 ns | 169 µs | 2.23 µs |
| MatchString/literal_ci | 50.6 µs | 3.15 ms | 3.16 ms | 345 µs | 93.8 µs |
| MatchString/word | 23.8 ns | 53 ns | 52 ns | 172 µs | 1.81 µs |
| MatchString/email | 35.7 ns | 528 ns | 536 ns | 174 µs | 2 µs |
| MatchString/uri | 96.8 ns | 180 ns | 184 ns | 172 µs | 2 µs |
| MatchString/date | 38 ns | 492 ns | 488 ns | 173 µs | 2.04 µs |
| MatchString/anchored_id | 11.6 ns | 126 ns | 130 ns | 114 ns | 89.8 ns |
| MatchString/unicode | 31.4 ns | 65.2 ns | 64.5 ns | 150 µs | 1.26 µs |
| FindStringIndex/word | 36 ns | 176 ns | 179 ns | 483 µs | 2.08 µs |
| FindStringIndex/literal_ci | 50.4 µs | 3.36 ms | 3.35 ms | 346 µs | 94 µs |
| FindStringIndex/email | 48.4 ns | 579 ns | 581 ns | 369 µs | 1.93 µs |
| FindStringIndex/uri | 109 ns | 531 ns | 528 ns | 474 µs | 2.34 µs |
| FindStringIndex/date | 50.9 ns | 541 ns | 537 ns | 473 µs | 2.12 µs |
| FindStringIndex/anchored_id | 24.9 ns | 133 ns | 134 ns | 213 ns | 132 ns |
| FindAll/word | 2.8 ms | 8.69 ms | 9.05 ms | 10.5 ms | 9.19 ms |
| FindAll/email | 93.4 µs | 5.71 ms | 5.68 ms | 20.8 ms | 736 µs |
| FindAll/date | 112 µs | 3.88 ms | 3.88 ms | 3.4 ms | 704 µs |

表中 17 个场景全部最快，完整 32 个场景也全部最快；AVX-512BW 折叠字节对（`VPORQ` + `VPCMPEQB` + `KANDQ`）与字节集合内核通过逐字节对照测试。

AVX-512 内核只要求 `AVX512F + AVX512BW` 与操作系统对 opmask/ZMM 的 `XCR0` 支持，**不依赖 VBMI/VBMI2**，因此新老两代都走同一套 64 字节内核：

- 新指令集主机（Ice Lake 代，含 VBMI/VBMI2）与旧指令集主机（Skylake 代，F/BW/CD/DQ/VL）均通过 `TestAMD64SIMDSelection`，即 `indexByte/indexByteSet/indexFoldPair` 的块大小均为 64。
- 旧指令集主机上 SIMD 内核的逐字节对照测试全部通过；32 个基准场景全部最快，`FindAll/date` 为 359 µs、go-re2 为 1.94 ms（约 5.4 倍）。
- 只有 F 而没有 BW 的早期 AVX-512 处理器（如 Knights Landing）会自动落到 AVX2 内核，不会执行不支持的指令。

没有 AVX2 时按 **SSE4.2 → SSE4.1 → 标量** 的顺序回退，SSE 内核一次处理 16 字节。SSE4.2 的 `PCMPESTRI` 实测比 `PCMPEQB` 慢（256 KiB 无匹配扫描 22.8 µs vs 9.9 µs，提前匹配 3.0 ns vs 2.4 ns），因此 SSE4.2 入口使用相同的 16 字节字节比较循环，集合与折叠字节对复用 SSE4.1 内核；两套 SSE 内核在强制安装后通过逐字节对照测试。

## 历史远端主机：arm64（2026-10-24）

| 场景 | ydx | stdlib | grafana | regexp2 | go-re2 |
|---|---:|---:|---:|---:|---:|
| MatchString/literal | 29.4 ns | 498 ns | 497 ns | 440 µs | 8.14 µs |
| MatchString/literal_ci | 119 µs | 6.93 ms | 6.93 ms | 735 µs | 224 µs |
| MatchString/word | 46.9 ns | 120 ns | 118 ns | 449 µs | 7.96 µs |
| MatchString/email | 84 ns | 1.18 µs | 1.18 µs | 468 µs | 8.12 µs |
| MatchString/uri | 185 ns | 432 ns | 427 ns | 463 µs | 8.11 µs |
| MatchString/date | 84.9 ns | 1.09 µs | 1.1 µs | 467 µs | 8.19 µs |
| MatchString/anchored_id | 26.1 ns | 288 ns | 278 ns | 282 ns | 205 ns |
| MatchString/unicode | 70.2 ns | 142 ns | 141 ns | 327 µs | 3.52 µs |
| FindStringIndex/word | 85.6 ns | 395 ns | 393 ns | 1.04 ms | 8.46 µs |
| FindStringIndex/literal_ci | 128 µs | 7.84 ms | 7.77 ms | 725 µs | 224 µs |
| FindStringIndex/email | 129 ns | 1.33 µs | 1.32 µs | 1.04 ms | 8.18 µs |
| FindStringIndex/uri | 220 ns | 1.21 µs | 1.21 µs | 1.08 ms | 8.29 µs |
| FindStringIndex/date | 118 ns | 1.23 µs | 1.23 µs | 1.14 ms | 8.21 µs |
| FindStringIndex/anchored_id | 60.9 ns | 311 ns | 306 ns | 658 ns | 285 ns |
| FindAll/word | 6.24 ms | 18.9 ms | 19.7 ms | 31.4 ms | 21.6 ms |
| FindAll/email | 265 µs | 12.1 ms | 12.1 ms | 43.7 ms | 1.63 ms |
| FindAll/date | 290 µs | 8.33 ms | 8.32 ms | 7.15 ms | 1.57 ms |

表中 17 个场景全部最快，完整 32 个场景也全部最快；NEON 的 `VTBL`/`VUMAXV` 与折叠字节对内核通过逐字节对照测试。

## 并行（regexpx v0.1.13，2026-10-31）

`FindAllStringIndexParallel` 在存在可靠且具有选择性的起点过滤器时按块并行；密集无界运行（如
`\w+`）、锚定、整模式字面量、通配字面量与可空模式自动回退顺序执行。

本机（AVX2，4 MiB 文本，`-benchtime=300ms -count=5`）：

| 场景 | 顺序 | 并行 |
|---|---:|---:|
| `\d{4}-\d{2}-\d{2}` | 4.50 ms | **2.54 ms** |
| 邮箱 | 4.00 ms | **2.41 ms** |
| `\w+` | 92.5 ms | 94.5 ms（回退，差异为噪声） |
| `[a-z]+` | 65.7 ms | 65.5 ms（回退） |
| `\p{Han}+` | 40.9 ms | 44.1 ms（回退） |
| `\p{So}+` | 61.4 ms | 64.4 ms（回退） |

快速路径把定长与邮箱扫描降到内存带宽附近，并行分别为 1.77x 与 1.66x；分块在小语料上没有收益，
4 MiB 时才摊薄协作与合并开销。密集通用 NFA 扫描（如 `\p{Han}+`、`\p{So}+`）顺序更快，建议使用
顺序 API。并行结果与顺序结果逐项一致，测试覆盖跨块匹配、结果上限、并发调用与非法 UTF-8 回退。

## 复现

```bash
# 发布后（go.mod 指向已发布版本）
cd benchmarks/regexpx
GOWORK=off go test -run '^$' -bench . -benchmem

# 开发期：把本模块与 ../../regexpx 加入临时 go.work 后
cd benchmarks/regexpx
go test -run '^$' -bench . -benchmem

# 兼容 API / Longest / Reader 基准（最新样本 v0.1.13）
GOWORK=off go test -run '^$' -bench 'Benchmark(Copy|StdCopy|ExpandString|StdExpandString|ReplaceAllString|StdReplaceAllString|ReplaceAllLiteralString|StdReplaceAllLiteralString|LongestExact|StdLongestExact|LongestRun|StdLongestRun|LongestWild|StdLongestWild|LongestLinear|StdLongestLinear|LongestDFA|StdLongestDFA|MatchReaderEarly|StdMatchReaderEarly|FindReaderIndexEarly|StdFindReaderIndexEarly|LongestLookahead|LiteralPrefix|StdLiteralPrefix)$' -benchmem -count=6 -benchtime=1s

# 并行基准（v0.1.13 起并行 API 已包含在发布版本中）
GOWORK=off go test -run '^$' -bench BenchmarkParallelFindAll -benchmem

# 交叉编译到远端主机
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/regexbench_amd64.test .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/regexbench_arm64.test .
```

`benchmarks/regexpx/go.mod` 在发布前指向当前已发布版本；开发期请使用工作区或临时 `go.work`，不要提交本地 `replace`。

## 预过滤回归基准

`required_bench_test.go` 固定了 CRS 4.29 的 942420（标点重复 8 次）与 932240（宽首字节
字符类分支）形态、最小长度短路，以及一个可触发惰性 ASCII 搜索 DFA 的大型命令名交替模式。
它们使用公开 API；基准模块已引用 `regexpx v0.1.13`，可直接复现 AST 必需字节/字面量预过滤、
最小长度短路、搜索 DFA、`Warm()` 启动预热以及 v0.1.13 折叠字面量预过滤优化：

```bash
cd benchmarks/regexpx
GOWORK=off go test -run '^$' \
  -bench 'Benchmark(CRSRequiredByteRepetition|CRSRequiredByteAlternation|MinimumLengthShort|DFALargeAlternation)$' \
  -benchmem -count=5
```

缓冲区 API 的零分配验证位于 `regexpx/find_buffer_test.go`；`Warm()` 的行为验证位于
`regexpx/dfa_search_test.go`；折叠字面量预过滤验证位于 `regexpx/literal_prefilter_test.go`。
基准模块可直接引用这些符号。

## 最新结果文件

- [`results/regexpx-v0.1.13-windows-i9-10980hk.txt`](results/regexpx-v0.1.13-windows-i9-10980hk.txt)
- [`results/regexpx-v0.1.13-windows-benchstat.txt`](results/regexpx-v0.1.13-windows-benchstat.txt)
- [`results/regexpx-v0.1.13-api-windows-i9-10980hk.txt`](results/regexpx-v0.1.13-api-windows-i9-10980hk.txt)
- [`results/regexpx-v0.1.13-api-windows-benchstat.txt`](results/regexpx-v0.1.13-api-windows-benchstat.txt)
- [`results/regexpx-v0.1.13-parallel-windows-i9-10980hk.txt`](results/regexpx-v0.1.13-parallel-windows-i9-10980hk.txt)
- [`results/regexpx-v0.1.13-parallel-windows-benchstat.txt`](results/regexpx-v0.1.13-parallel-windows-benchstat.txt)

历史 v0.1.9 样本保留在 [`results/regexpx-v0.1.9-windows-i9-10980hk.txt`](results/regexpx-v0.1.9-windows-i9-10980hk.txt)。
