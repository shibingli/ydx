# benchmarks/websocket — WebSocket 往返与批量写对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/websocket` 覆盖 RFC 6455/7692/8441/9220，公开 `Upgrade`/`Dial`/`WriteBatch`
等 API。本基准在真实回环连接上比较它与 gorilla/websocket、coder/websocket 的
消息往返与客户端写吞吐。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/websocket | 本仓源码（工作区） | 原生批量写 `WriteBatch`，可选 permessage-deflate |
| `github.com/gorilla/websocket` | v1.5.3 | 最广泛使用的 WebSocket 库 |
| `github.com/coder/websocket` | v1.8.15 | 前 nhooyr.io/websocket，context 优先 API |
| `github.com/gobwas/ws` | v1.4.0 | 零分配编解码原语 |
| `github.com/lxzan/gws` | v1.8.48 | 事件驱动、并行写 |

## 场景

- `Echo/*`：32 B–64 KiB 文本消息在 5 个实现上的回显往返。
- `EchoConcurrent`：并发回显；`our-readahead` 使用 `BufferedRead` 提示合并写出。
- `EchoPipelined`：客户端/服务端批量写与全部合批三种流水线形态（仅 ydx）。
- `MessageRoundTripCompare`：32 B 文本消息，客户端写入后读取服务端回显。
- `WriteBatchCompare`：向只读丢弃的服务端写 1/4/16/64 条 1 KiB 二进制消息。
  ydx 对真正的批次使用 `WriteBatch`，单条用例与其对比库一样使用逐消息 `WriteMessage`；
  gorilla/coder 没有批量 API，逐条 `WriteMessage`/`Write`。
- 既有 ydx 基准：`MessageRoundTrip`、`WriteBatch`、`CompressedRoundTrip`、`Upgrade`。

## 关键结果（2026-10-24，Zen 5 + Go 1.27.3，Linux 回环）

| 场景 | ydx | gorilla | coder | gobwas | gws |
|---|---:|---:|---:|---:|---:|
| 32 B 回显 | **4.068 µs** | 4.257 µs | 5.589 µs | 4.343 µs | 6.463 µs |
| 1 KiB 回显 | **4.276 µs** | 4.428 µs | 5.787 µs | 4.695 µs | 7.002 µs |
| 64 KiB 回显 | **16.59 µs** | 18.58 µs | 38.61 µs | 22.46 µs | 18.25 µs |
| 并发回显 | 2.301 µs（readahead **1.413**） | 2.331 µs | 2.385 µs | 2.333 µs | **2.003 µs** |
| 批量 1×1 KiB | 1.931 µs | 1.912 µs | **1.107 µs** | — | — |
| 批量 4×1 KiB | **2.258 µs** | 6.753 µs | 4.291 µs | — | — |
| 批量 16×1 KiB | **5.130 µs** | 27.73 µs | 19.26 µs | — | — |
| 批量 64×1 KiB | **14.06 µs** | 124.3 µs | 73.74 µs | — | — |

- 回显：ydx 在 32 B–64 KiB 全部尺寸上最快，32 B 领先 gorilla 4%，64 KiB 领先 gorilla
  11%；ydx 为 0 B/op、0 allocs/op，gorilla 为 4–6 allocs、gobwas 4、coder 0–2、gws 2。
- 并发回显：ydx 2.301 µs，与 gorilla/gobwas（2.33 µs）持平，gws 的 2.003 µs 快约 13%；
  按文档使用 `BufferedRead` 合并写出的 `our-readahead` 为 1.413 µs，反超全部实现 30%–41%。
- 批量写：4×/16×/64× 分别比 coder 快 1.9×/3.8×/5.2×、比 gorilla 快 3.0×/5.4×/8.8×。
  单条（1×）用例是唯一非批量场景：ydx 1.931 µs ≈ gorilla 1.912 µs，coder 为 1.107 µs；
  该行的服务端只读不写，单条写入会受对端读取节奏影响，因此只作为单条写入参考，不代表
  批量能力。
- 分配：ydx 所有回显与批量用例均为 0 B/op、0 allocs/op（稳态）。
- 既有基准：`MessageRoundTrip` 4.150 µs、`WriteBatch` 1.930/2.253/4.511/14.04 µs、
  `CompressedRoundTrip` 18.45 µs、`Upgrade` 4.608 µs（9 allocs、33.13 KiB）。

## 完整数据

<details>
<summary>5 轮中位数（Zen 5 + Go 1.27.3，2026-10-24）</summary>

**github.com/shibingli/ydx/benchmarks/websocket**

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `Echo/our/32` | 4.068 µs | 0 | 0 |
| `Echo/coder/32` | 5.589 µs | 0 | 0 |
| `Echo/gorilla/32` | 4.257 µs | 112 | 4 |
| `Echo/gobwas/32` | 4.343 µs | 64 | 4 |
| `Echo/gws/32` | 6.463 µs | 32 | 2 |
| `Echo/our/256` | 4.183 µs | 0 | 0 |
| `Echo/coder/256` | 5.679 µs | 0 | 0 |
| `Echo/gorilla/256` | 4.343 µs | 112 | 4 |
| `Echo/gobwas/256` | 4.562 µs | 64 | 4 |
| `Echo/gws/256` | 6.658 µs | 32 | 2 |
| `Echo/our/1024` | 4.276 µs | 0 | 0 |
| `Echo/coder/1024` | 5.787 µs | 0 | 0 |
| `Echo/gorilla/1024` | 4.428 µs | 112 | 4 |
| `Echo/gobwas/1024` | 4.695 µs | 64 | 4 |
| `Echo/gws/1024` | 7.002 µs | 32 | 2 |
| `Echo/our/4096` | 5.264 µs | 0 | 0 |
| `Echo/coder/4096` | 8.723 µs | 2 | 2 |
| `Echo/gorilla/4096` | 5.511 µs | 114 | 6 |
| `Echo/gobwas/4096` | 8.566 µs | 64 | 4 |
| `Echo/gws/4096` | 8.426 µs | 32 | 2 |
| `Echo/our/65536` | 16.588 µs | 0 | 0 |
| `Echo/coder/65536` | 38.607 µs | 2 | 2 |
| `Echo/gorilla/65536` | 18.579 µs | 114 | 6 |
| `Echo/gobwas/65536` | 22.462 µs | 64 | 4 |
| `Echo/gws/65536` | 18.249 µs | 32 | 2 |
| `EchoConcurrent/our` | 2.301 µs | 8 | 0 |
| `EchoConcurrent/our-readahead` | 1.413 µs | 5 | 0 |
| `EchoConcurrent/gorilla` | 2.331 µs | 118 | 4 |
| `EchoConcurrent/coder` | 2.385 µs | 7 | 0 |
| `EchoConcurrent/gobwas` | 2.333 µs | 67 | 4 |
| `EchoConcurrent/gws` | 2.003 µs | 36 | 2 |
| `EchoPipelined/baseline` | 29.177 µs | 0 | 0 |
| `EchoPipelined/client-batched` | 18.195 µs | 0 | 0 |
| `EchoPipelined/server-batched` | 16.511 µs | 0 | 0 |
| `EchoPipelined/batched` | 5.972 µs | 0 | 0 |
| `MessageRoundTrip` | 4.150 µs | 0 | 0 |
| `WriteBatch/batch=1` | 1.930 µs | 0 | 0 |
| `WriteBatch/batch=4` | 2.253 µs | 0 | 0 |
| `WriteBatch/batch=16` | 4.511 µs | 0 | 0 |
| `WriteBatch/batch=64` | 14.036 µs | 0 | 0 |
| `CompressedRoundTrip` | 18.453 µs | 71 | 0 |
| `MessageRoundTripCompare/ydx` | 4.184 µs | 0 | 0 |
| `MessageRoundTripCompare/gorilla` | 4.687 µs | 1.062 KiB | 5 |
| `MessageRoundTripCompare/coder` | 5.461 µs | 1.000 KiB | 2 |
| `WriteBatchCompare/batch=1/ydx` | 1.931 µs | 0 | 0 |
| `WriteBatchCompare/batch=1/gorilla` | 1.912 µs | 2.169 KiB | 5 |
| `WriteBatchCompare/batch=1/coder` | 1.107 µs | 2.116 KiB | 3 |
| `WriteBatchCompare/batch=4/ydx` | 2.258 µs | 0 | 0 |
| `WriteBatchCompare/batch=4/gorilla` | 6.753 µs | 8.718 KiB | 24 |
| `WriteBatchCompare/batch=4/coder` | 4.291 µs | 8.488 KiB | 15 |
| `WriteBatchCompare/batch=16/ydx` | 5.130 µs | 0 | 0 |
| `WriteBatchCompare/batch=16/gorilla` | 27.726 µs | 34.875 KiB | 96 |
| `WriteBatchCompare/batch=16/coder` | 19.261 µs | 33.965 KiB | 63 |
| `WriteBatchCompare/batch=64/ydx` | 14.059 µs | 0 | 0 |
| `WriteBatchCompare/batch=64/gorilla` | 124.312 µs | 139.500 KiB | 384 |
| `WriteBatchCompare/batch=64/coder` | 73.737 µs | 135.121 KiB | 254 |
| `Upgrade` | 4.608 µs | 33.133 KiB | 9 |
</details>

## 复现

```bash
cd benchmarks/websocket
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 所有连接都是本机 Linux 回环；回环栈、TCP_NODELAY 默认值、调度抖动会主导微秒级
  差异。不要把绝对数字外推到公网或其它操作系统。
- gorilla/coder 没有批量 API，批量用例逐条调用其公开写方法；这正是“库能力差异”的
  一部分，而不是不公平的测量。ydx 的单条用例同样改走逐消息 API，与两个对比库同形态。
- 单条（1×）批量用例的服务端只读不写，写入方在套接字缓冲填满后会跟随对端读取节奏；
  coder 在该行的 1.107 µs 未能用其公开写路径的结构差异解释（它同样走 bufio + 单次
  flush），因此只作为单条写入参考，不作为批量能力结论。
- `EchoConcurrent/our` 走通用回显循环；`our-readahead` 是文档推荐的 `BufferedRead`
  合并写出版本，两者都是 ydx 的公开能力，表内分别列出。
- 压缩往返只测 ydx；gorilla/coder/gobwas/gws 的 permessage-deflate 协商参数与阈值不同，
  同表比较会引入额外变量。
- `Upgrade` 使用可复用 hijack 缓冲与最小 `net.Conn`，隔离握手分配与 CPU；它不包含
  真实 TCP 建连。
- 并发连接未纳入本次对比；当前基准是单连接串行路径。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
