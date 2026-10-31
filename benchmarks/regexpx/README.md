# regexpx 基准

对比自研 `github.com/shibingli/ydx/regexpx` 与 Go 主流正则实现的延迟、吞吐与分配。

## 对比对象

| 标签 | 实现 | 说明 |
|---|---|---|
| `ydx` | 本仓 `regexpx` | 自研解析器、Pike VM、回溯 VM、惰性 ASCII 搜索 DFA、运行/定长/线性/邮件/字面量快速路径与 SIMD 预过滤 |
| `stdlib` | 标准库 `regexp` | RE2 语法，one-pass / bitstate / NFA |
| `grafana` | `github.com/grafana/regexp` | 标准库分支，接口与语义相同 |
| `regexp2` | `github.com/dlclark/regexp2` | .NET 回溯引擎，使用 `regexp2.RE2` 模式 |
| `go-re2` | `github.com/wasilibs/go-re2` | RE2 C++ 经 wazero 运行（WASM） |

## 环境与方法

- **主表（2026-10-24）**：AMD Ryzen AI MAX+ 395（Zen 5，32 线程，AVX-512F/BW/VBMI/VBMI2），Ubuntu 26.04，Go 1.27.3，`GOMAXPROCS=32`。
- 本机：Windows 11，Intel i9-10980HK，AVX2，Go 1.27.3。
- AVX-512 主机：Ubuntu，x86_64，AVX-512F/BW/VL/VBMI，Go 1.27.3（本地交叉编译测试二进制）。
- 旧指令集 AVX-512 主机：Skylake 代 Xeon，仅 AVX-512F/BW/CD/DQ/VL（无 VBMI/VBMI2），Go 1.27.3（同样使用交叉编译测试二进制）。
- arm64 主机：aarch64 云主机，NEON，Go 1.27.3（本地交叉编译测试二进制）。
- 语料：256 KiB 的英文/数字/日期/邮箱/URL 混合文本；128 KiB 中英希混合文本；128 KiB 含 emoji（ZWJ、肤色、旗帜、变体选择符）、简繁中文与中英文混排的混合文本。
- 所有模式在计时外编译；每项跑 3 次取中位数（本机 `-benchtime=300ms`，远端 80ms），`-benchmem`。
- 绝对值受 CPU、负载与调度影响；跨实现比较请优先看同一行的相对值。

## 新增兼容 API 指标（regexpx v0.1.9）

`api_bench_test.go` 覆盖 `Copy`、`Expand`、流式替换、`Longest` 快路径、Reader 提前返回与
回溯最长匹配，与标准库同场对比。完整表格、内存/分配、分析、复现命令与原始样本见
[`../../regexpx/PERFORMANCE.md`](../../regexpx/PERFORMANCE.md)。

摘录（Windows 11 / i9-10980HK / Go 1.27.3）：

| 项目 | regexpx | 标准库 | 结论 |
|---|---:|---:|---|
| `Copy` | ~70 ns，160 B，1 alloc | ~67 ns，160 B，1 alloc | 结构对齐，基本持平 |
| `ReplaceAllString` | ~321 µs，3 allocs | ~892 µs，18 allocs | 约 2.8x 快 |
| `ReplaceAllLiteralString` | ~225 µs，5 allocs | ~0.73–1.31 ms，21 allocs | 约 3–6x 快 |
| `Longest` 通配字面量 | ~159 ns，0 alloc | ~161 µs，0 alloc | 约 1000x 快 |
| `Longest` 定长线性 | ~235 ns，0 alloc | ~64 µs，0 alloc | 约 270x 快 |
| `MatchReader` 早期匹配 | ~66 ns | ~109 ns | 约 1.7x 快 |
| `FindReaderIndex` 早期匹配 | ~111 ns | ~163 ns | 约 1.5x 快 |
| `LiteralPrefix` | ~2.2 ns | ~0.83 ns | 绝对值纳秒级，非热路径 |

原始样本与 `benchstat` 输出保存在 `results/`。

## Zen 5 主表结果（2026-10-24）

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

## 本机 AVX2 结果

| 场景 | ydx | stdlib | grafana | regexp2 | go-re2 |
|---|---:|---:|---:|---:|---:|
| MatchString/literal | 33.1 ns | 466 ns | 460 ns | 434 µs | 10.8 µs |
| MatchString/literal_ci | 102 µs | 6.58 ms | 6.17 ms | 659 µs | 277 µs |
| MatchString/word | 48.5 ns | 120 ns | 120 ns | 408 µs | 10.8 µs |
| MatchString/email | 77.6 ns | 1.17 µs | 1.16 µs | 411 µs | 10.8 µs |
| MatchString/uri | 186 ns | 412 ns | 412 ns | 399 µs | 10.5 µs |
| MatchString/date | 84.1 ns | 1.01 µs | 994 ns | 416 µs | 11.8 µs |
| MatchString/anchored_id | 22.2 ns | 278 ns | 278 ns | 269 ns | 198 ns |
| MatchString/unicode | 63.6 ns | 146 ns | 150 ns | 298 µs | 3.2 µs |
| MatchString/han | 73 ns | 139 ns | 150 ns | 259 µs | 3.16 µs |
| MatchString/emoji | 105 ns | 182 ns | 181 ns | 260 µs | 3.21 µs |
| FindStringIndex/word | 75.8 ns | 417 ns | 422 ns | 1.13 ms | 10.9 µs |
| FindStringIndex/literal | 54.7 ns | 564 ns | 553 ns | 1.11 ms | 11.5 µs |
| FindStringIndex/literal_ci | 101 µs | 6.97 ms | 6.68 ms | 660 µs | 271 µs |
| FindStringIndex/email | 105 ns | 1.33 µs | 1.32 µs | 1.17 ms | 10.9 µs |
| FindStringIndex/uri | 224 ns | 1.2 µs | 1.21 µs | 1.21 ms | 10.9 µs |
| FindStringIndex/date | 115 ns | 1.2 µs | 1.21 µs | 1.12 ms | 11.1 µs |
| FindStringIndex/anchored_id | 54.9 ns | 305 ns | 310 ns | 616 ns | 279 ns |
| FindStringIndex/captures | 792 ns | 1.3 µs | 1.24 µs | 1.16 ms | 11.3 µs |
| FindAll/word | 10.7 ms | 20.3 ms | 20.8 ms | 28.8 ms | 21.7 ms |
| FindAll/email | 311 µs | 12.4 ms | 12.9 ms | 43.3 ms | 1.66 ms |
| FindAll/date | 350 µs | 8.52 ms | 8.41 ms | 7.59 ms | 1.56 ms |
| FindAll/unicode | 3.14 ms | 6.77 ms | 6.98 ms | 12.5 ms | 6.68 ms |
| FindAll/han | 1.23 ms | 2.81 ms | 3 ms | 4.69 ms | 1.83 ms |
| FindAll/emoji | 2.03 ms | 4.38 ms | 4.5 ms | 8.65 ms | 4.2 ms |

表中 24 个场景全部最快；完整 32 个场景也全部最快。四个重点场景的优化结果：

- `(?i)` 字面量：2 字节折叠 SIMD 扫描后为 102 µs，约为 go-re2 的 1/2.7、标准库的 1/65。
- URI `MatchString`：可选段 + 尾运行的线性匹配器后为 186 ns，约为标准库的 1/2.2。
- 邮箱 `FindAll`：围绕 `@` 定位并反向扫描局部部分后为 311 µs，约为标准库的 1/40、go-re2 的 1/5.3。
- 日期 `FindAll`：以固定偏移的 `-` 为锚点后为 350 µs，约为 go-re2 的 1/4.5、标准库的 1/24。

不同 CPU 与负载会改变绝对值；跨实现请用 `benchstat` 复核。

## AVX-512 主机

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

## arm64 主机

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

## 并行

`FindAllStringIndexParallel` 在存在可靠且具有选择性的起点过滤器时按块并行；密集无界运行（如 `\w+`）、锚定、整模式字面量、通配字面量与可空模式自动回退顺序执行。

本机（AVX2，4 MiB 文本，取中位数）：

| 场景 | 顺序 | 并行 |
|---|---:|---:|
| `\d{4}-\d{2}-\d{2}` | 4.11 ms | 2.94 ms |
| 邮箱 | 3.47 ms | 2.65 ms |
| `\w+` | 83.6 ms | 91.8 ms（回退，差异为噪声） |

快速路径把定长与邮箱扫描降到内存带宽附近；分块在小语料上没有收益，4 MiB 时才摊薄协作与合并开销。密集的通用 NFA 扫描（如 `\p{Han}+`）在同样语料上顺序更快，建议使用顺序 API。并行结果与顺序结果逐项一致，测试覆盖跨块匹配、结果上限、并发调用与非法 UTF-8 回退。

## 复现

```bash
# 发布后（go.mod 指向已发布版本）
cd benchmarks/regexpx
GOWORK=off go test -run '^$' -bench . -benchmem

# 开发期：把本模块与 ../../regexpx 加入临时 go.work 后
cd benchmarks/regexpx
go test -run '^$' -bench . -benchmem

# 新增兼容 API / Longest / Reader 基准（v0.1.9+）
GOWORK=off go test -run '^$' -bench 'Benchmark(Copy|StdCopy|ExpandString|StdExpandString|ReplaceAllString|StdReplaceAllString|ReplaceAllLiteralString|StdReplaceAllLiteralString|LongestExact|StdLongestExact|LongestRun|StdLongestRun|LongestWild|StdLongestWild|LongestLinear|StdLongestLinear|LongestDFA|StdLongestDFA|MatchReaderEarly|StdMatchReaderEarly|FindReaderIndexEarly|StdFindReaderIndexEarly|LongestLookahead|LiteralPrefix|StdLiteralPrefix)$' -benchmem -count=6 -benchtime=1s

# 并行基准使用 regexpx_dev 构建标签（并行 API 尚未包含在已发布版本中）
go test -run '^$' -bench BenchmarkParallelFindAll -tags regexpx_dev

# 交叉编译到远端主机
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/regexbench_amd64.test .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/regexbench_arm64.test .
```

`benchmarks/regexpx/go.mod` 在发布前指向当前已发布版本；开发期请使用工作区或临时 `go.work`，不要提交本地 `replace`。

## 预过滤回归基准

`required_bench_test.go` 固定了 CRS 4.29 的 942420（标点重复 8 次）与 932240（宽首字节
字符类分支）形态、最小长度短路，以及一个可触发惰性 ASCII 搜索 DFA 的大型命令名交替模式。
它们使用公开 API；基准模块已引用 `regexpx v0.1.11`，可直接复现 AST 必需字节/字面量预过滤、
最小长度短路与搜索 DFA 相对旧版本的差异：

```bash
cd benchmarks/regexpx
GOWORK=off go test -run '^$' \
  -bench 'Benchmark(CRSRequiredByteRepetition|CRSRequiredByteAlternation|MinimumLengthShort|DFALargeAlternation)$' \
  -benchmem -count=5
```

缓冲区 API 的零分配验证位于 `regexpx/find_buffer_test.go`；基准模块升级到 v0.1.11 后也可直接
引用这些符号。
