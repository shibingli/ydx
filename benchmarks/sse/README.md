# benchmarks/sse — SSE 事件编码与广播对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/sse` 提供严格按 W3C 事件流格式组装的 `Writer`，以及进程内主题广播 `Broker`。
本基准比较事件编码路径与 gin-contrib/sse、手写 `fmt.Fprintf` 基线，并保留 Broker
扇出与既有写入用例。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/sse | v0.1.6 | 逐字段组装，复用帧缓冲，零分配稳态 |
| `github.com/gin-contrib/sse` | v1.1.2 | Gin 生态常用 SSE 编码器 |
| 手写 `fmt.Fprintf` | Go 1.27.2 | 不使用库的常见基线 |

## 场景

- `WriteDataCompare/small_32B`：32 B 纯 data 事件。
- `WriteDataCompare/large_4KiB`：4 KiB 纯 data 事件。
- `WriteEventCompare`：带 comment/id/event/retry/data 的完整事件。
- 既有 ydx：`WriteData` 三种载荷（含多行）、`WriteEvent`、`Publish` 1/64 订阅者。

## 关键结果

| 场景 | ydx | gin-contrib | 手写 |
|---|---:|---:|---:|
| 32 B data | 42.86 ns | 100.2 ns | 70.27 ns |
| 4 KiB data | 2.558 µs | 3.387 µs | 108.3 ns |
| 完整事件 | 307.0 ns | 403.3 ns | 306.5 ns |

- 小事件：ydx 比 gin-contrib 快约 2.3 倍，比手写快约 1.6 倍；三者都只做一次
  `Write` 调用。
- 4 KiB：ydx 比 gin-contrib 快约 25%，但比手写慢约 24 倍。手写基线把字符串直接交给
  丢弃写入器，不做 CR/LF 规整、字段顺序组装或帧缓冲拷贝；ydx 的 2.558 µs 包含把
  4 KiB 复制进可复用帧缓冲的成本。真实网络写入会把这段固定成本摊薄。
- 完整事件：ydx 与手写几乎持平（307.0 ns vs 306.5 ns），比 gin-contrib 快约 24%；
  ydx 额外支持 comment 字段与严格的字段顺序。
- 分配：ydx 三个编码用例均为 0 B/op、0 allocs/op；gin-contrib 为 1–2 allocs/op。
- Broker：1 个订阅者 113.4 ns，64 个订阅者 3.893 µs（约 61 ns/订阅者），投递非阻塞。

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/sse**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `WriteData/small_32B` | 42.11 ns | 0 | 0 | 724.7 MiB/s |
| `WriteData/large_4KiB` | 2.469 µs | 0 | 0 | 1.545 GiB/s |
| `WriteData/multiline_1KiB` | 929.0 ns | 0 | 0 | 1.043 GiB/s |
| `WriteEvent` | 296.8 ns | 0 | 0 | 668.4 MiB/s |
| `Publish/subscribers=1` | 113.4 ns | 0 | 0 |  |
| `Publish/subscribers=64` | 3.893 µs | 0 | 0 |  |
| `WriteDataCompare/small_32B/ydx` | 42.86 ns | 0 | 0 | 712.0 MiB/s |
| `WriteDataCompare/small_32B/gin-contrib` | 100.2 ns | 32 | 1 | 304.5 MiB/s |
| `WriteDataCompare/small_32B/manual` | 70.27 ns | 16 | 1 | 434.3 MiB/s |
| `WriteDataCompare/large_4KiB/ydx` | 2.558 µs | 0 | 0 | 1.491 GiB/s |
| `WriteDataCompare/large_4KiB/gin-contrib` | 3.387 µs | 4.006 KiB | 1 | 1.126 GiB/s |
| `WriteDataCompare/large_4KiB/manual` | 108.3 ns | 16 | 1 | 35.23 GiB/s |
| `WriteEventCompare/ydx` | 307.0 ns | 0 | 0 | 646.2 MiB/s |
| `WriteEventCompare/gin-contrib` | 403.3 ns | 212 | 2 | 491.9 MiB/s |
| `WriteEventCompare/manual` | 306.5 ns | 72 | 5 | 647.2 MiB/s |
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
