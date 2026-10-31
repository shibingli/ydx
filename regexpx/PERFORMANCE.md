# regexpx 性能测试数据

本文记录 `regexpx` 兼容 API、`Longest` 快路径与 Reader 优化的对比数据。通用匹配/查找、
SIMD 与并行数据见 [`benchmarks/regexpx/README.md`](../benchmarks/regexpx/README.md)。

## 1. 范围与版本

- 被测版本：`github.com/shibingli/ydx/regexpx v0.1.9`
- 基准源码：[`benchmarks/regexpx/api_bench_test.go`](../benchmarks/regexpx/api_bench_test.go)
- 原始样本：[`benchmarks/regexpx/results/regexpx-v0.1.9-windows-i9-10980hk.txt`](../benchmarks/regexpx/results/regexpx-v0.1.9-windows-i9-10980hk.txt)
- `benchstat` 输出：[`benchmarks/regexpx/results/regexpx-v0.1.9-benchstat.txt`](../benchmarks/regexpx/results/regexpx-v0.1.9-benchstat.txt)

## 2. 环境与方法

| 项 | 值 |
|---|---|
| CPU | Intel Core i9-10980HK，16 逻辑线程，AVX2 |
| 操作系统 | Windows 11 Pro for Workstations |
| Go | 1.27.3 |
| 模式编译 | 计时外完成 |
| 时间单位 | `benchtime=1s`，`count=6`，取 benchstat 中位数 |
| Copy / LiteralPrefix | 单独 `benchtime=2s`、`count=10` 取中位数，降低高方差影响 |
| 内存 | `-benchmem` |
| 对照 | Go 标准库 `regexp` |

环境存在并行构建/测试负载，部分项目（`ReplaceAllString`、`ReplaceAllLiteralString`、
`LongestLinear`）的样本波动较大；跨实现比较优先看同一行的相对值，绝对值请以原始样本为准。

## 3. 耗时对比

`ydx/std` 小于 1 表示 regexpx 更快。

| 项目 | regexpx | 标准库 | ydx/std | 结论 |
|---|---:|---:|---:|---|
| `Copy` | 69.9 ns | 66.7 ns | 1.05x | 基本持平；结构体均为 160 B、1 alloc |
| `ExpandString` | 133.2 ns | 132.3 ns | 1.01x | 持平 |
| `ReplaceAllString` | 320.5 µs | 892.1 µs | 0.36x | 快约 2.8x |
| `ReplaceAllLiteralString` | 224.5 µs | 1307.2 µs | 0.17x | 本机样本快约 5.8x；标准库波动范围约 0.73–1.31 ms |
| `Longest` 整字面量 | 157.3 ns | 208.8 ns | 0.75x | 快约 1.3x（本次 p=0.065，处于噪声边界） |
| `Longest` 单运行 | 38.6 ns | 214.9 ns | 0.18x | 快约 5.6x |
| `Longest` 通配字面量 | 158.8 ns | 160.8 µs | ~0.001x | 快约 1000x |
| `Longest` 定长线性 | 234.5 ns | 63.8 µs | ~0.004x | 快约 270x |
| `Longest` 锚定 DFA | 19.6 µs | 54.2 µs | 0.36x | 快约 2.8x |
| `MatchReader` 早期匹配 | 65.7 ns | 109.1 ns | 0.60x | 快约 1.7x |
| `FindReaderIndex` 早期匹配 | 111.3 ns | 162.6 ns | 0.68x | 快约 1.5x |
| `LiteralPrefix` | 2.21 ns | 0.83 ns | 2.68x | 慢约 2.7x，绝对值仅 2.2 ns |

### 无标准库对照

| 项目 | 结果 |
|---|---:|
| `Longest` + 回溯环视 | 3.9–5.2 µs/op，2818 B/op，36 allocs/op |
| 优化前同项 | 约 1.3 ms/op，819 KB/op，10236 allocs/op |

## 4. 内存与分配

| 项目 | regexpx | 标准库 |
|---|---:|---:|
| `Copy` | 160 B / 1 alloc | 160 B / 1 alloc |
| `ExpandString` | 8 B / 1 alloc | 8 B / 1 alloc |
| `ReplaceAllString` | 28.02 KiB / 3 allocs | 58.21 KiB / 18 allocs |
| `ReplaceAllLiteralString` | 89.27 KiB / 5 allocs | 135.91 KiB / 21 allocs |
| `Longest` 整字面量 | 0 B / 0 alloc | 0 B / 0 alloc |
| `Longest` 单运行 | 0 B / 0 alloc | 0 B / 0 alloc |
| `Longest` 通配字面量 | 0 B / 0 alloc | 0–71 B / 0 alloc |
| `Longest` 定长线性 | 0 B / 0 alloc | 0–2 B / 0 alloc |
| `Longest` 锚定 DFA | 0 B / 0 alloc | 0 B / 0 alloc |
| `MatchReader` 早期匹配 | 32 B / 2 allocs | 24 B / 1 alloc |
| `FindReaderIndex` 早期匹配 | 44 B / 3 allocs | 40 B / 2 allocs |
| `LiteralPrefix` | 0 B / 0 alloc | 0 B / 0 alloc |

## 5. 本轮优化结论

1. **`Copy` 已完成结构对齐**：`Regexp` 从 176 B 降到 160 B，`Copy` 的 B/op 从 192 B 降到
   160 B，与标准库一致；耗时为同量级。
2. **`ReplaceAll*` 分配显著更低**：模板替换 3 allocs（标准库 18），字面量替换 5 allocs
   （标准库 21），同时耗时约为标准库的 1/3–1/6。
3. **`Longest` 快路径优势明显**：整字面量、单运行、通配字面量、定长线性、锚定 DFA 均不
   分配；通配/线性场景比标准库快 2–3 个数量级。
4. **Reader 提前返回生效**：`MatchReader`/`FindReaderIndex` 对可提前判定的模式无需读完
   整个流，耗时约为标准库的 0.6–0.7x；代价是固定的小额分配。
5. **`LiteralPrefix` 的剩余差距**：2.2 ns vs 0.8 ns，来自惰性缓存快路径的函数调用与原子
   读取；绝对值极小，不在请求热路径。把标准库 oracle 前移到编译期可进一步接近标准库，但会
   让所有模式编译成本翻倍，不划算。

## 6. 复现

```bash
cd benchmarks/regexpx
GOWORK=off go test -run '^$' \
  -bench 'Benchmark(Copy|StdCopy|ExpandString|StdExpandString|ReplaceAllString|StdReplaceAllString|ReplaceAllLiteralString|StdReplaceAllLiteralString|LongestExact|StdLongestExact|LongestRun|StdLongestRun|LongestWild|StdLongestWild|LongestLinear|StdLongestLinear|LongestDFA|StdLongestDFA|MatchReaderEarly|StdMatchReaderEarly|FindReaderIndexEarly|StdFindReaderIndexEarly|LongestLookahead|LiteralPrefix|StdLiteralPrefix)$' \
  -benchmem -count=6 -benchtime=1s
```

`benchmarks/regexpx` 中的 `Benchmark*` 是 regexpx，`BenchmarkStd*` 是标准库。需要
`benchstat` 对比时，把 `BenchmarkStd` 前缀改为 `Benchmark` 后分别作为 baseline/new 输入。

> 绝对值受 CPU 频率、并行负载与 Windows 调度影响。跨机器比较请优先看同一行的相对值，
> 并在目标平台重新运行基准。
