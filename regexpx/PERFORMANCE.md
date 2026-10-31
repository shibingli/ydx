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

## 7. v0.1.11 热路径优化

在不改变既有导出 API 的匹配语义或超时策略的前提下，v0.1.11 增加了六项优化：

1. **最小匹配长度短路**：`prog.info.minLen` 在进入专用快路径和 Pike VM 之前检查剩余字节数；
   剩余字节少于最小符文数时直接返回未命中。该检查对 ASCII 精确，对多字节输入也是安全下界。
2. **无捕获 Pike VM 快路径**：`addSimple` 将指令表、代际标记与线程列表放入局部变量；
   `step` 在 `capLen <= 2` 时走 `stepSimple`，内联指令分派、rune/class/any 消费检查，避免
   每线程 `consumes`/`addThread` 调用。捕获路径与回溯路径保持不变。
3. **AST 必需字节集/计数预过滤**：从 AST 推导“匹配至少包含 N 个来自集合的字节”的可靠必要条件，
   支持 ASCII 字符类、`\d`/`\s`/`\w`、字面量、分支、重复（计数按最小重复次数放大）、捕获与
   原子组；Unicode/折叠/否定类保守处理。它只作用于通用引擎，专用 exact/run/wild/email/linear/DFA
   路径已在前面返回，不会为 SIMD 扫描增加第二遍开销。
4. **AST 必需字面量预过滤**：单字面量使用 `Contains`，多字面量使用 1–4 字节 gram 布隆过滤；
   含单字母分支或无法证明的折叠构造会直接放弃。与字节集过滤互补，主要帮助带长必需片段、但
   字符类特征不明显的模式。
5. **惰性 ASCII 搜索 DFA**：对无回溯、无字面量前缀、首字节足够宽且指令数不少于 128 的通用
   模式，在首次匹配时构建按需填充的确定性自动机。DFA 只处理 ASCII 输入；遇到非 ASCII 字节、
   行锚点等不支持构造或超过 1024 个状态时立即回退到 Pike VM。状态转移按字母表分组缓存，
   已完成的单元以原子方式读取，稳态搜索无锁竞争。无捕获搜索直接采用 DFA 结果；带捕获搜索
   只用它提前拒绝不可能命中的输入。
6. **调用方缓冲区 API**：新增 `FindStringSubmatchIndexInto`、`FindStringSubmatchInto`、
   `FindSubmatchIndexInto` 与 `FindSubmatchInto`。调用方提供 `[]int` / `[]string` / `[][]byte`
   后，预热路径可复用缓冲区；8 组以内的字符串 API 还使用栈上索引缓冲。基准测试确认
   `FindStringSubmatchIndexInto` / `FindStringSubmatchInto` 在缓冲区充足时 0 allocs/op。

同一机器、同一组模式（`benchtime=1s`，`count=3`，取中位数；临时外部基准，非正式发布门禁）：

| 场景 | 优化前 | v0.1.11 | 变化 |
|---|---:|---:|---:|
| 短于最小长度输入（`abcdef` vs `abc`） | 179.9 ns | 4.0 ns | 约 45x |
| 大型交替模式善意值 | 18.58 µs | 17.18 µs | -7.5% |
| 方法名交替 | 657 ns | 595 ns | -9.4% |
| 捕获子匹配 | 823 ns | 770 ns | -6.5% |
| 200 条命令名交替 | 61.1 ns | 55.0 ns | -10.0% |
| CRS 942420 善意值（标点重复 8 次） | 2.22 µs | 26 ns | 约 85x |
| CRS 932240 善意值（宽首字节字符类分支） | 24.2 µs | 26 ns | 约 930x |
| CRS 932236 善意值（巨型命令名分支，20 B） | 约 6.8 µs | 约 0.10 µs | 约 65x |
| CRS 932260 善意值（20 B） | 约 6.6 µs | 约 0.13–0.17 µs | 约 40–50x |
| CRS 932236 / 932260 较长善意值（50 B） | 约 19 µs | 约 0.25–0.27 µs | 约 70x |
| 缓冲区 API 子匹配（预热） | — | 0 allocs/op | 消除切片分配 |

DFA 首次构建成本（含字母表与起始状态）在 932236/932260 上约 0.5 ms/模式，之后状态按需
增长；在 OWASP CRS 4.29.0 全量规则下，首次请求额外约 1.1–1.4 ms，冷内存约 300 KB。稳态
WAF 基准（regexpx v0.1.11，CRS 善意请求）约 124–141 µs / 2.5 KB / 111 allocs，并发约
21–23 µs/op；50 个唯一参数约 670 µs / 58 KB / 2945 allocs。绝对值受 CPU 频率与后台负载影响。

验证：`GOWORK=off CGO_ENABLED=1 CC=clang go test ./... -race` 通过；新增
`TestMinimumLengthShortCircuit`、`TestRequiredBytes*`、`TestRequiredLiterals*`、
`TestRequiredByteConditions*`、`TestSearchDFA*`、`TestFind*Into*` 固定行为与并发安全。
预过滤基准位于 [`benchmarks/regexpx/required_bench_test.go`](../benchmarks/regexpx/required_bench_test.go)；
基准模块在本次依赖同步后引用 v0.1.11，可直接复现上述数值。`waf/go.mod` 已同步到 v0.1.11，
WAF 可使用 DFA 与缓冲区 API；WAF 侧的请求行缓存、`RequestURI` 复用与参数总大小缓存独立生效。
