# log — 零拷贝结构化日志

`github.com/shibingli/ydx/log` 是 ydx 的统一日志器：编码直接追加到池化字节缓冲，字段以
联合表示承载，热路径不装箱、不反射、不产生中间字符串；可选异步批量写入与免锁并发模式。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/log` |
| 包名 | `log` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- 两种格式：`json`（默认）与 `console`；时间一律按 UTC 输出。
- 级别：Debug / Info / Warn / Error / Fatal；`ParseLevel` 解析字符串。
- 字段构造：`Str`、`Strs`、`Int`、`Int64`、`Uint64`、`Float64`、`Bool`、`Dur`、`Time`、
  `Bytes`、`Err`、`Any`、`Raw`、`RawField`。
- `With` / `Named` 派生带持久字段或名称的子日志器。
- `Enabled` 把级别判断前置，禁用路径零分配。
- `Async` 可选异步批量写入；`Sync` / `Close` 控制持久性。
- `SlowQuery` 记录慢查询；`OpenFile` 以 `O_APPEND` 打开日志文件。
- `SetDefault` / `Default` 管理包级默认日志器。

## 特性

- **一次性 Write**：每条记录只调用一次 `io.Writer.Write`，并发写入不会产生交错行。
- **池化缓冲**：初始 1 KB，超过 64 KB 的缓冲不回池，避免常驻内存被单条大日志撑大。
- **无反射**：字段以 `Field` 联合表示承载，热路径不反射、不装箱。
- **级别前置**：`Enabled` 避免在禁用级别上构造字段。
- **预编码元数据**：进程号、主机名、service 名在 `New` 时取一次并预编码，记录写出时
  不再重复转义。
- **缓存行分离**：级别阈值与写锁分处不同缓存行，减少多核级别读取的缓存失效。
- **异步有界背压**：专用写协程合并整条记录为批量写；队列满时阻塞生产者，记录不丢弃。
- **顺序语义明确**：异步模式保证完整性与不丢失，但不保证跨环调用顺序；需要严格顺序
  时保持同步模式。

## 快速开始

```go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/shibingli/ydx/log"
)

func main() {
	f, err := log.OpenFile("logs/api.log") // O_APPEND，多个进程可安全追加
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer func() { _ = f.Close() }()

	logger := log.New(log.Options{
		Service: "api",
		Level:   log.InfoLevel,
		Format:  "json",
		Writer:  f,
	})
	defer func() { _ = logger.Close() }()

	logger.Info("server started | 服务器已启动",
		log.Str("addr", ":8080"),
		log.Dur("boot", 12*time.Millisecond),
	)

	reqLog := logger.With(log.Str("request_id", "req-1"))
	reqLog.Warn("slow request | 请求较慢", log.Int("status", 200))
}
```

异步写入：

```go
logger := log.New(log.Options{
	Service:    "api",
	Async:      true,
	QueueSize:  8192,
	BatchBytes: 64 << 10,
})
defer func() { _ = logger.Close() }()

if logger.Enabled(log.DebugLevel) {
	logger.Debug("debug detail | 调试细节", log.Str("k", "v"))
}
```

## 应用场景

- **高吞吐 API**：逐请求结构化日志，稳态零分配。
- **访问日志**：与 `middleware/accesslog` 配合记录状态码、字节数与耗时。
- **慢查询**：`SlowQuery` 记录 SQL、行数与耗时，并配合 `ParamsFilter` 脱敏。
- **异步落盘**：慢磁盘或远端日志目的地，避免请求路径承担 Write 延迟。
- **审计与追踪**：`request_id`、`trace_id` 等持久字段通过 `With` 继承。

## 性能指标

基准模块：[`benchmarks/log`](../benchmarks/log/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数，输出到
`io.Discard`。

| 场景 | ydx/log | zap | zerolog | slog | logrus |
|---|---:|---:|---:|---:|---:|
| 5 字段 Info | **134.1 ns** | 395.2 ns | 168.6 ns | 529.9 ns | 2.324 µs |
| 8 字段 Info | **206.1 ns** | 534.9 ns | 228.0 ns | 1.012 µs | 3.015 µs |
| 禁用 Info 调用 | 9.87 ns | 76.46 ns | **7.33 ns** | 24.79 ns | 282.1 ns |
| prebound Info | **86.6 ns** | 157.8 ns | 96.2 ns | 274.4 ns | 1.551 µs |
| 并发 5 字段 | **8.08 ns** | 140.9 ns | 10.53 ns | 155.4 ns | 883.9 ns |

- 5 字段 Info 为 134.1 ns，快于 zerolog 约 20%，约为 zap 的 37%、slog 的 25%；
  稳态 0 B/op、0 allocs/op。
- 8 字段宽记录仍保持零分配，快于 zerolog 约 10%。
- 禁用路径 zerolog 最快（7.33 ns），ydx 为 9.87 ns 且零分配；两者字段构造方式不同。
- 异步慢写入器场景：同步 1.052 ms/op，异步批 4 KiB 43.77 µs/op、64 KiB 3.203 µs/op；
  请求路径不再承担每次 Write 的 500 µs 阻塞。
- 异步 64 KiB 批的 `writes/op` 约为 0.003 次/记录，同步路径为 1.000 次/记录。

> 异步模式以固定队列/交接成本换取慢目的地下的延迟隔离；目的地为 `io.Discard` 时异步
> 反而比同步多约 0.77 µs。完整表格与口径见基准 README。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只依赖 Go 标准库与 ydx 内部模块（`base64`、`errs`、
`json`、`sysinfo`）。

基准对比对象：`go.uber.org/zap`、`rs/zerolog`、标准库 `log/slog`、`sirupsen/logrus`，
仅出现在 `benchmarks/log`，不进入产品模块依赖。

## 相关模块

- [`middleware/accesslog`](../middleware/accesslog/README.md)、
  [`middleware/asyncafter`](../middleware/asyncafter/README.md)：访问日志与响应后异步管线。
- [`gorm`](../gorm/README.md)：慢查询与参数脱敏。
- [`asynq`](../asynq/README.md)：任务处理日志。
- [`gc`](../gc/README.md)：调度器生命周期日志。
- [`middleware/recovery`](../middleware/recovery/README.md)：panic 记录。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
