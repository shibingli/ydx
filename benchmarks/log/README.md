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
| `log/slog` | Go 1.27.3 | `NewJSONHandler(io.Discard)` |
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
| 5 字段 Info | **134.1 ns** | 395.2 ns | 168.6 ns | 529.9 ns | 2.324 µs |
| 8 字段 Info | **206.1 ns** | 534.9 ns | 228.0 ns | 1.012 µs | 3.015 µs |
| 禁用 Info 调用 | 9.87 ns | 76.46 ns | **7.33 ns** | 24.79 ns | 282.1 ns |
| prebound Info | **86.6 ns** | 157.8 ns | 96.2 ns | 274.4 ns | 1.551 µs |
| 并发 5 字段 | **8.08 ns** | 140.9 ns | 10.53 ns | 155.4 ns | 883.9 ns |

- 5 字段 Info 134.1 ns，快于 zerolog（168.6 ns）约 20%，约为 zap 的 37%、slog 的
  25%；稳态 0 B/op、0 allocs/op。
- 8 字段 JSON：ydx 206.1 ns，快于 zerolog（228.0 ns）约 10%，并明显快于 zap、slog、
  logrus；宽记录下零分配优势保持。
- 禁用路径：zerolog 的 7.33 ns 仍最快；ydx 9.87 ns，0 alloc。两者字段构造方式不同：
  ydx 的 variadic 字段由调用方构造，zerolog 的字段链在禁用时不构造参数。
- 并发：基准使用 `ConcurrentWrites`（`io.Discard` 无状态且并发安全），ydx 8.08 ns，
  领先 zerolog（10.53 ns）约 23%；该模式要求 Writer 自身串行化并发写。

**异步与 I/O 场景（仅 ydx 内部对照）**

| 场景 | 耗时 |
|---|---:|
| 同步写入 500 µs 慢写入器 | 1.052 ms/op |
| 异步批量 4 KiB | 43.77 µs/op |
| 异步批量 64 KiB | 3.203 µs/op |
| 无缓冲文件写入 | 383.4 ns/op |
| 缓冲文件写入 | 162.5 ns/op |
| 异步文件写入 | 244.6 ns/op |

慢目的地是最能体现异步价值的场景：请求路径不再承担每次 Write 的 500 µs 阻塞，
而是按批合并后交给写协程。`writes/op` 指标直接显示批处理效果：同步路径为
1.000 次/记录，异步 64 KiB 批约为 0.003 次/记录。

## 完整数据

<details>
<summary>5 轮中位数（2026-10-24，Zen 5 + Go 1.27.3）</summary>


**github.com/shibingli/ydx/benchmarks/log**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `AsyncInfoFieldsSerial` | 256.40 ns | 0 | 0 |  |
| `AsyncInfoFieldsParallel` | 115.70 ns | 3 | 0 |  |
| `AsyncWriterFile` | 244.60 ns | 0 | 0 |  |
| `SlowWriterSync` | 1.052 ms |  |  |  |
| `AsyncSlowWriterBatch4K` | 43.768 µs |  |  |  |
| `AsyncSlowWriterBatch64K` | 3.203 µs |  |  |  |
| `InfoNoFields` | 62.13 ns | 0 | 0 |  |
| `Info8Fields` | 202.30 ns | 0 | 0 |  |
| `Console8Fields` | 263.40 ns | 0 | 0 |  |
| `InfoFieldsParallel` | 74.91 ns | 0 | 0 |  |
| `ConsoleFieldsParallel` | 77.88 ns | 0 | 0 |  |
| `WriterDiscard` | 136.30 ns | 0 | 0 |  |
| `WriterBuffer` | 138.00 ns | 0 | 0 |  |
| `WriterFile` | 383.40 ns | 0 | 0 |  |
| `WriterBufferedFile` | 162.50 ns | 0 | 0 |  |
| `InfoFieldsParallelConcurrent` | 8.08 ns | 0 | 0 |  |
| `InfoFieldsConcurrent` | 131.80 ns | 0 | 0 |  |
| `Info/yd-logx` | 90.93 ns | 0 | 0 |  |
| `Info/zap` | 266.30 ns | 193 | 1 |  |
| `Info/zerolog` | 117.00 ns | 0 | 0 |  |
| `Info/slog` | 410.10 ns | 0 | 0 |  |
| `Info/logrus` | 1.941 µs | 1.561 KiB | 29 |  |
| `InfoPrebound/yd-logx` | 86.62 ns | 0 | 0 |  |
| `InfoPrebound/zap` | 157.80 ns | 0 | 0 |  |
| `InfoPrebound/zerolog` | 96.24 ns | 0 | 0 |  |
| `InfoPrebound/slog` | 274.40 ns | 0 | 0 |  |
| `InfoPrebound/logrus` | 1.551 µs | 1.069 KiB | 25 |  |
| `Disabled/yd-logx` | 5.89 ns | 0 | 0 |  |
| `Disabled/zap` | 52.18 ns | 192 | 1 |  |
| `Disabled/zerolog` | 119.80 ns | 0 | 0 |  |
| `Disabled/slog` | 5.05 ns | 0 | 0 |  |
| `Disabled/logrus` | 204.80 ns | 497 | 4 |  |
| `DisabledPrebound/yd-logx` | 1.01 ns | 0 | 0 |  |
| `DisabledPrebound/zap` | 3.53 ns | 0 | 0 |  |
| `DisabledPrebound/zerolog` | 97.03 ns | 0 | 0 |  |
| `DisabledPrebound/slog` | 4.32 ns | 0 | 0 |  |
| `DisabledPrebound/logrus` | 1.80 ns | 0 | 0 |  |
| `InfoFields` | 135.80 ns | 0 | 0 |  |
| `ConsoleFields` | 167.40 ns | 0 | 0 |  |
| `SlowQuery` | 121.70 ns | 0 | 0 |  |
| `DisabledLevel` | 4.52 ns | 0 | 0 |  |
| `InfoFieldsCompare/ydx` | 134.10 ns | 0 | 0 |  |
| `InfoFieldsCompare/zap` | 395.20 ns | 322 | 1 |  |
| `InfoFieldsCompare/zerolog` | 168.60 ns | 0 | 0 |  |
| `InfoFieldsCompare/slog` | 529.90 ns | 32 | 2 |  |
| `InfoFieldsCompare/logrus` | 2.324 µs | 1.663 KiB | 36 |  |
| `Info8FieldsCompare/ydx` | 206.10 ns | 0 | 0 |  |
| `Info8FieldsCompare/zap` | 534.90 ns | 515 | 1 |  |
| `Info8FieldsCompare/zerolog` | 228.00 ns | 0 | 0 |  |
| `Info8FieldsCompare/slog` | 1.012 µs | 201 | 6 |  |
| `Info8FieldsCompare/logrus` | 3.015 µs | 2.120 KiB | 47 |  |
| `DisabledCompare/ydx` | 9.87 ns | 0 | 0 |  |
| `DisabledCompare/zap` | 76.46 ns | 320 | 1 |  |
| `DisabledCompare/zerolog` | 7.33 ns | 0 | 0 |  |
| `DisabledCompare/slog` | 24.79 ns | 32 | 2 |  |
| `DisabledCompare/logrus` | 282.10 ns | 529 | 6 |  |
| `ParallelCompare/ydx` | 8.08 ns | 0 | 0 |  |
| `ParallelCompare/zap` | 140.90 ns | 324 | 1 |  |
| `ParallelCompare/zerolog` | 10.53 ns | 0 | 0 |  |
| `ParallelCompare/slog` | 155.40 ns | 32 | 2 |  |
| `ParallelCompare/logrus` | 883.90 ns | 1.676 KiB | 36 |  |

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
