# benchmarks/websocket — WebSocket 往返与批量写对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/websocket` 覆盖 RFC 6455/7692/8441/9220，公开 `Upgrade`/`Dial`/`WriteBatch`
等 API。本基准在真实回环连接上比较它与 gorilla/websocket、coder/websocket 的
消息往返与客户端写吞吐。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/websocket | v0.1.0 | 原生批量写 `WriteBatch`，可选 permessage-deflate |
| `github.com/gorilla/websocket` | v1.5.3 | 最广泛使用的 WebSocket 库 |
| `github.com/coder/websocket` | v1.8.15 | 前 nhooyr.io/websocket，context 优先 API |

## 场景

- `MessageRoundTripCompare`：32 B 文本消息，客户端写入后读取服务端回显。
- `WriteBatchCompare`：向只读丢弃的服务端写 1/4/16/64 条 1 KiB 二进制消息。
  ydx 使用 `WriteBatch`；gorilla/coder 没有批量 API，逐条 `WriteMessage`。
- 既有 ydx 基准：`MessageRoundTrip`、`WriteBatch`、`CompressedRoundTrip`、`Upgrade`。

## 关键结果

| 场景 | ydx | gorilla | coder |
|---|---:|---:|---:|
| 32 B 回显往返 | 65.85 µs | 63.61 µs | 69.62 µs |
| 批量 1×1 KiB | 26.59 µs | 27.74 µs | 29.39 µs |
| 批量 4×1 KiB | 29.66 µs | 107.6 µs | 110.9 µs |
| 批量 16×1 KiB | 90.96 µs | 429.8 µs | 460.0 µs |
| 批量 64×1 KiB | 305.6 µs | 1.699 ms | 1.780 ms |

- 单条往返：三者都在 64–70 µs，差异约 9%，主要是回环 syscall 与调度成本；
  ydx 为 0 B/op、0 allocs/op，gorilla 为 5 allocs/op（约 1.06 KiB），coder 为
  2 allocs/op（约 1 KiB）。
- 批量写：ydx 的 `WriteBatch` 把多条消息合并到一次写路径，64 条时比逐条写快约
  5.5 倍；gorilla/coder 的逐条 API 随批量线性增长，吞吐稳定在约 33–37 MiB/s。
- ydx 既有基准：`MessageRoundTrip` 68.14 µs，`WriteBatch` 25.33/28.82/85.56/292.3 µs，
  `CompressedRoundTrip` 122.6 µs，`Upgrade` 8.067 µs（9 allocs、17.13 KiB）。

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/websocket**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `MessageRoundTrip` | 68.14 µs | 0 | 0 | 459.0 KiB/s |
| `WriteBatch/batch=1` | 25.33 µs | 0 | 0 | 38.56 MiB/s |
| `WriteBatch/batch=4` | 28.82 µs | 0 | 0 | 135.6 MiB/s |
| `WriteBatch/batch=16` | 85.56 µs | 0 | 0 | 182.6 MiB/s |
| `WriteBatch/batch=64` | 292.3 µs | 1 | 0 | 213.8 MiB/s |
| `CompressedRoundTrip` | 122.6 µs | 525 | 0 | 31.87 MiB/s |
| `MessageRoundTripCompare/ydx` | 65.85 µs | 0 | 0 | 478.5 KiB/s |
| `MessageRoundTripCompare/gorilla` | 63.61 µs | 1.062 KiB | 5 | 488.3 KiB/s |
| `MessageRoundTripCompare/coder` | 69.62 µs | 1.000 KiB | 2 | 449.2 KiB/s |
| `WriteBatchCompare/batch=1/ydx` | 26.59 µs | 0 | 0 | 36.74 MiB/s |
| `WriteBatchCompare/batch=1/gorilla` | 27.74 µs | 2.181 KiB | 6 | 35.20 MiB/s |
| `WriteBatchCompare/batch=1/coder` | 29.39 µs | 2.126 KiB | 4 | 33.23 MiB/s |
| `WriteBatchCompare/batch=4/ydx` | 29.66 µs | 0 | 0 | 131.7 MiB/s |
| `WriteBatchCompare/batch=4/gorilla` | 107.6 µs | 8.725 KiB | 24 | 36.31 MiB/s |
| `WriteBatchCompare/batch=4/coder` | 110.9 µs | 8.506 KiB | 16 | 35.21 MiB/s |
| `WriteBatchCompare/batch=16/ydx` | 90.96 µs | 0 | 0 | 171.8 MiB/s |
| `WriteBatchCompare/batch=16/gorilla` | 429.8 µs | 34.90 KiB | 96 | 36.35 MiB/s |
| `WriteBatchCompare/batch=16/coder` | 460.0 µs | 34.02 KiB | 64 | 33.97 MiB/s |
| `WriteBatchCompare/batch=64/ydx` | 305.6 µs | 0 | 0 | 204.5 MiB/s |
| `WriteBatchCompare/batch=64/gorilla` | 1.699 ms | 139.6 KiB | 384 | 36.79 MiB/s |
| `WriteBatchCompare/batch=64/coder` | 1.780 ms | 136.1 KiB | 256 | 35.10 MiB/s |
| `Upgrade` | 8.067 µs | 17.13 KiB | 9 |  |
</details>

## 复现

```bash
cd benchmarks/websocket
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 所有连接都是本机回环；Windows 回环栈、TCP_NODELAY 默认值、调度抖动会主导微秒级
  差异。不要把绝对数字外推到公网或其它操作系统。
- gorilla/coder 没有批量 API，批量用例逐条调用其公开写方法；这正是“库能力差异”的
  一部分，而不是不公平的测量。
- 压缩往返只测 ydx；gorilla/coder 也支持 permessage-deflate，但协商参数与阈值不同，
  同表比较会引入额外变量。
- `Upgrade` 使用可复用 hijack 缓冲与最小 `net.Conn`，隔离握手分配与 CPU；它不包含
  真实 TCP 建连。
- 并发连接未纳入本次对比；当前基准是单连接串行路径。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
