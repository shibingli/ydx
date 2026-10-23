# benchmarks/log — 结构化日志对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/log` 是零拷贝结构化日志器：字段直接追加进池化缓冲，稳态零分配；可选异步批量
写入与免锁并发模式。本基准比较它与 zap、zerolog、标准库 slog、logrus 的 JSON 热点
路径，并保留 ydx 的异步/慢写入器场景。

## 对比对象

| 实现 | 版本 | 配置 |
|---|---|---|
| ydx/log | v0.1.8 | JSON，`io.Discard`，Info 级 |
| `go.uber.org/zap` | v1.28.0 | 生产风格 JSON encoder，`io.Discard` |
| `github.com/rs/zerolog` | v1.35.1 | JSON，带时间戳，`io.Discard` |
| `log/slog` | Go 1.27.2 | `NewJSONHandler(io.Discard)` |
| `github.com/sirupsen/logrus` | v1.10.2 | `JSONFormatter`，`io.Discard` |

## 场景

- `InfoFieldsCompare`：5 字段请求日志（method/path/status/request_id/took）。
- `Info8FieldsCompare`：8 字段宽记录（增加 bytes/cached/latency_ms/at）。
- `DisabledCompare`：Error 级日志器上调用 Info，测禁用路径。
- `ParallelCompare`：`RunParallel` 持续并发写入。
- 既有 ydx 基准：console 格式、文件/缓冲文件写入、异步批量、慢写入器、`SlowQuery`。

## 关键结果

| 场景 | ydx | zap | zerolog | slog | logrus |
|---|---:|---:|---:|---:|---:|
| 5 字段 Info | **136.3 ns** | 441.8 ns | 157.5 ns | 562.4 ns | 2.559 µs |
| 8 字段 Info | **206.0 ns** | 605.3 ns | 215.6 ns | 1.099 µs | 3.603 µs |
| 禁用 Info 调用 | 10.32 ns | 61.0 ns | **7.16 ns** | 28.67 ns | 305.3 ns |
| 并发 5 字段 | **133.5 ns** | 440.0 ns | 159.1 ns | 577.5 ns | 2.553 µs |

- v0.1.8 的纯 ASCII 快速转义、64 字节 Field 与毫秒时间戳缓存把 5 字段 Info 从
  394.4 ns 降到 136.3 ns：现在快于 zerolog 约 13%，约为 zap 的 31%、slog 的 24%，
  稳态仍为 0 B/op、0 allocs/op。
- 8 字段 JSON：ydx 206.0 ns，快于 zerolog（215.6 ns）约 4.5%，并明显快于 zap、
  slog、logrus；宽记录下零分配优势保持。
- 禁用路径：zerolog 的 7.16 ns 仍最快；ydx 10.32 ns 较 v0.1.7 的 31.36 ns 明显
  收窄，且 0 alloc。
- 并发：ydx 133.5 ns 快于 zerolog 159.1 ns；`ConcurrentWrites` 免锁模式见完整数据，
  但要求 Writer 自身串行化并发写。

**异步与 I/O 场景（仅 ydx 内部对照）**

| 场景 | 耗时 |
|---|---:|
| 同步写入 500 µs 慢写入器 | 905.8 µs/op |
| 异步批量 4 KiB | 26.57 µs/op |
| 异步批量 64 KiB | 1.727 µs/op |
| 无缓冲文件写入 | 3.717 µs/op |
| 缓冲文件写入 | 501.7 ns/op |
| 异步文件写入 | 659.7 ns/op |

慢目的地是最能体现异步价值的场景：请求路径不再承担每次 Write 的 500 µs 阻塞，
而是按批合并后交给写协程。`writes/op` 指标直接显示批处理效果：同步路径为
1.000 次/记录，异步 4 KiB 批为 0.04774 次/记录，异步 64 KiB 批为 0.002967 次/记录。

## 完整数据

<details>
<summary>3 次中位数（v0.1.8，2026-10-23）</summary>


**github.com/shibingli/ydx/benchmarks/log**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `AsyncInfoFieldsSerial` | 200.5 ns | 7 | 0 |  |
| `AsyncInfoFieldsParallel` | 198.4 ns | 7 | 0 |  |
| `AsyncWriterFile` | 222.8 ns | 8 | 0 |  |
| `SlowWriterSync` | 1.052 ms | 0 | 0 |  |
| `AsyncSlowWriterBatch4K` | 34.95 µs | 913 | 1 |  |
| `AsyncSlowWriterBatch64K` | 3.256 µs | 92 | 0 |  |
| `InfoNoFields` | 61.9 ns | 0 | 0 |  |
| `Info8Fields` | 203.6 ns | 0 | 0 |  |
| `Console8Fields` | 270.3 ns | 0 | 0 |  |
| `InfoFieldsParallel` | 137.2 ns | 0 | 0 |  |
| `ConsoleFieldsParallel` | 189.8 ns | 0 | 0 |  |
| `WriterDiscard` | 136.0 ns | 0 | 0 |  |
| `WriterBuffer` | 139.5 ns | 0 | 0 |  |
| `WriterFile` | 365.3 ns | 0 | 0 |  |
| `WriterBufferedFile` | 162.9 ns | 0 | 0 |  |
| `InfoFieldsParallelConcurrent` | 135.5 ns | 0 | 0 |  |
| `InfoFieldsConcurrent` | 136.5 ns | 0 | 0 |  |
| `InfoFields` | 135.1 ns | 0 | 0 |  |
| `ConsoleFields` | 164.8 ns | 0 | 0 |  |
| `SlowQuery` | 123.5 ns | 0 | 0 |  |
| `DisabledLevel` | 5.29 ns | 0 | 0 |  |
| `InfoFieldsCompare/ydx` | 136.3 ns | 0 | 0 |  |
| `InfoFieldsCompare/zap` | 441.8 ns | 320 | 1 |  |
| `InfoFieldsCompare/zerolog` | 157.5 ns | 0 | 0 |  |
| `InfoFieldsCompare/slog` | 562.4 ns | 32 | 2 |  |
| `InfoFieldsCompare/logrus` | 2.559 µs | 1.653 KiB | 36 |  |
| `Info8FieldsCompare/ydx` | 206.0 ns | 0 | 0 |  |
| `Info8FieldsCompare/zap` | 605.3 ns | 512 | 1 |  |
| `Info8FieldsCompare/zerolog` | 215.6 ns | 0 | 0 |  |
| `Info8FieldsCompare/slog` | 1.099 µs | 200 | 6 |  |
| `Info8FieldsCompare/logrus` | 3.603 µs | 2.108 KiB | 47 |  |
| `DisabledCompare/ydx` | 10.32 ns | 0 | 0 |  |
| `DisabledCompare/zap` | 61.0 ns | 320 | 1 |  |
| `DisabledCompare/zerolog` | 7.16 ns | 0 | 0 |  |
| `DisabledCompare/slog` | 28.67 ns | 32 | 2 |  |
| `DisabledCompare/logrus` | 305.3 ns | 528 | 6 |  |
| `ParallelCompare/ydx` | 133.5 ns | 0 | 0 |  |
| `ParallelCompare/zap` | 440.0 ns | 320 | 1 |  |
| `ParallelCompare/zerolog` | 159.1 ns | 0 | 0 |  |
| `ParallelCompare/slog` | 577.5 ns | 32 | 2 |  |
| `ParallelCompare/logrus` | 2.553 µs | 1.688 KiB | 36 |  |

</details>

## 复现

```bash
cd benchmarks/log
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 各库的时间戳格式不同：ydx 为毫秒 RFC3339，zap 为 RFC3339Nano，zerolog 为 Unix
  秒，slog/logrus 为各自默认格式；这部分差异计入 ns/op。
- logrus 使用 `WithFields(map)` 逐条构造字段，这是其常见用法；它的字段 map 分配已
  计入结果。
- 禁用路径的语义不同：zerolog 在 `Info()` 阶段就短路，ydx/zap/slog/logrus 的检查点
  各异；该表只反映各库的默认行为。
- 异步/慢写入器/文件写入是 ydx 内部能力对照，没有与其它库做跨库异步比较。
- 并发基准的 ns/op 是所有 goroutine 的墙钟均摊值，不能与串行 ns/op 直接相加比较。
- 笔记本 CPU 的频率/温度与后台负载会让**同一份代码在不同轮次**的绝对 ns/op 相差
  数十个百分点；本模块重跑时部分基准观察到 20%–50% 的漂移。请只比较同一轮表格内的
  相对关系，不要把这里的绝对值与其它模块/其它时间的数字混比。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声。
