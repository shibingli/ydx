# benchmarks/sse — SSE 事件编码与广播对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/sse` 提供严格按 W3C 事件流格式组装的 `Writer`，以及进程内主题广播 `Broker`。
本基准比较事件编码路径与 gin-contrib/sse、手写 `fmt.Fprintf` 基线，并保留 Broker
扇出与既有写入用例。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/sse | 本仓源码（工作区） | 逐字段组装，复用帧缓冲，零分配稳态 |
| `github.com/gin-contrib/sse` | v1.1.2 | Gin 生态常用 SSE 编码器 |
| 手写 `fmt.Fprintf` | Go 1.27.3 | 不使用库的常见基线 |

## 场景

- `WriteDataCompare/small_32B`：32 B 纯 data 事件。
- `WriteDataCompare/large_4KiB`：4 KiB 纯 data 事件。
- `WriteEventCompare`：带 comment/id/event/retry/data 的完整事件。
- 既有 ydx：`WriteData` 三种载荷（含多行）、`WriteEvent`、`Publish` 1/64 订阅者。

## 关键结果

| 场景 | ydx | gin-contrib | 手写 |
|---|---:|---:|---:|
| 32 B data | **14.07 ns** | 47.51 ns | 33.61 ns |
| 4 KiB data | **63.69 ns** | 1.453 µs | 52.27 ns |
| 完整事件 | **152.0 ns** | 190.2 ns | 127.7 ns |

- 小事件：ydx 比 gin-contrib 快约 3.4 倍，比手写快约 2.4 倍。
- 4 KiB：ydx 比 gin-contrib 快约 23 倍。手写基线（52.27 ns）把字符串直接交给丢弃
  写入器，不做 CR/LF 规整、字段顺序组装或帧缓冲；ydx 的 63.69 ns 包含两次向量化
  换行扫描与三段直接写（约 64 GB/s 的有效载荷吞吐）。真实网络写入会把固定成本摊薄。
- 完整事件：ydx 152.0 ns，比 gin-contrib（190.2 ns）快约 25%；手写基线 127.7 ns
  不规整多行数据（其输出不是合法 SSE 帧），不能作为等价口径。
- 分配：ydx 三个编码用例均为 0 B/op、0 allocs/op；gin-contrib 为 1–2 allocs/op。
- Broker：1 个订阅者 53.41 ns，64 个订阅者 1.962 µs（约 31 ns/订阅者），投递非阻塞。

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/sse**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `WriteData/small_32B` | 14.16 ns | 0 | 0 | 2261 |
| `WriteData/large_4KiB` | 63.62 ns | 0 | 0 | 64.02 GiB/s |
| `WriteData/multiline_1KiB` | 473.6 ns | 0 | 0 | 2176 |
| `WriteEvent` | 150.1 ns | 0 | 0 | 1391 |
| `Publish/subscribers=1` | 53.41 ns | 0 | 0 |  |
| `Publish/subscribers=64` | 1.962 µs | 0 | 0 |  |
| `WriteDataCompare/small_32B/ydx` | 14.07 ns | 0 | 0 | 2274 |
| `WriteDataCompare/small_32B/gin-contrib` | 47.51 ns | 32 | 1 | 694.5 |
| `WriteDataCompare/small_32B/manual` | 33.61 ns | 16 | 1 | 944.8 |
| `WriteDataCompare/large_4KiB/ydx` | 63.69 ns | 0 | 0 | 64.23 GiB/s |
| `WriteDataCompare/large_4KiB/gin-contrib` | 1.453 µs | 4.009 KiB | 1 | 2819 |
| `WriteDataCompare/large_4KiB/manual` | 52.27 ns | 16 | 1 | 79.32 GiB/s |
| `WriteEventCompare/ydx` | 152.0 ns | 0 | 0 | 1371 |
| `WriteEventCompare/gin-contrib` | 190.2 ns | 212 | 2 | 1132 |
| `WriteEventCompare/manual` | 127.7 ns | 72 | 5 | 1622 |
</details>

## 复现

```bash
cd benchmarks/sse
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 手写基线不做多行 `data:` 拆分、CR/LF 规整、字段转义或错误处理；它是“最小写入”
  下界，不是生产等价实现。
- gin-contrib/sse 没有 comment 字段；`WriteEventCompare` 的 gin 用例省略 comment，
  手写与 ydx 用例包含 comment。事件内容因此并非逐字节相同。
- 写入器是只统计字节数的丢弃 `ResponseWriter`；基准不包含真实网络 flush、TLS 或
  客户端消费成本。
- Broker 对比只覆盖 ydx 内部扇出；r3labs/sse 等实现是完整 HTTP 服务端/订阅模型，
  与本进程内 `chan Event` 广播不是同一 API，未强行对比。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
