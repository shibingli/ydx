# buffpool — 按尺寸分级的字节缓冲池

`github.com/shibingli/ydx/buffpool` 提供按固定尺寸分级的 `[]byte` 复用池。每个尺寸一个
`sync.Pool`，几百字节的请求不会占用 256 KiB 的大块，大响应也不会迫使小分配跟随迁移。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/buffpool` |
| 包名 | `buffpool` |
| Go 版本 | 1.27.4 |
| 许可证 | Apache-2.0 |
| 最大缓冲 | 256 KiB（`MaxSize`） |

## 功能

- `Get(n int) []byte`：返回长度为 0、容量不小于 `n` 的切片。
- `Put(p []byte)`：归还缓冲；只接纳容量恰好等于某一分级且不超过 `MaxSize` 的切片。
- 九个尺寸分级：1、2、4、8、16、32、64、128、256 KiB（2× 间隔，最坏容量浪费 ≤2×）。
- 每级独立 `sync.Pool`，池内存放指向块首的 `*byte`，避免把切片头装箱进接口。
- 2× 分级同时简化查找：`classForSize` 只需 `bits.Len(n-1)-10`，
  `classForCapacity` 只需 `bits.TrailingZeros(cap)-10`。

## 特性

- **容量即契约**：`Get` 返回的切片在 `cap(buf)` 内 `append` 不会重新分配。
- **尺寸隔离**：小请求不会长期占住大块，大响应也不会污染小尺寸池。
- **拒绝超大归还**：`Put` 丢弃超过 `MaxSize` 或容量非分级的缓冲，避免单次超大请求
  把池的常驻内存撑大。
- **非零值语义**：返回缓冲内容不保证为零；处理敏感数据或依赖零值的调用方必须自行清零。
- **所有权转移**：传给 `Put` 后不得继续使用，同一块内存可能被交给其它协程。
- **零分配热路径**：预热后 `Get`/`Put` 均为 0 B/op、0 allocs/op。

## 快速开始

```go
package main

import (
	"bytes"
	"fmt"

	"github.com/shibingli/ydx/buffpool"
)

func main() {
	buf := buffpool.Get(4096)
	defer buffpool.Put(buf)

	buf = append(buf, "hello "...)
	buf = append(buf, "buffpool"...)
	fmt.Println(bytes.ToUpper(buf))
}
```

需要零值缓冲时：

```go
buf := buffpool.Get(4096)
clear(buf[:cap(buf)])
defer buffpool.Put(buf)
```

## 应用场景

- **HTTP 请求/响应缓冲**：读取 body、组装响应、压缩前后的临时字节。
- **压缩中间件**：`middleware/compress` 复用编码器与待压缩正文缓冲。
- **日志编码**：日志器在池化缓冲上追加记录，减少 GC 压力。
- **SSE / WebSocket 帧**：复用帧缓冲，降低高频消息的分配。
- **模板渲染**：渲染输出先写入池化缓冲，再一次性写出。

## 性能指标

基准模块：[`benchmarks/buffpool`](../benchmarks/buffpool/README.md)。测试环境为远程
host-01，AMD Ryzen AI MAX+ 395（Zen 5，16 核 32 线程，`GOMAXPROCS=32`）、Go 1.27.3、
Linux，`-count=5 -benchtime=1s` 中位数。

| 场景 | ydx/buffpool | `sync.Pool` | `bytebufferpool` |
|---|---:|---:|---:|
| 1 KiB Get/Put | 9.37 ns | 7.04 ns | 9.39 ns |
| 2 KiB Get/Put | 9.79 ns | 7.12 ns | 9.38 ns |
| 4 KiB Get/Put | 9.96 ns | 7.38 ns | 9.78 ns |
| 8 KiB Get/Put | 9.96 ns | 7.19 ns | 9.54 ns |
| 16 KiB Get/Put | 9.66 ns | 7.22 ns | 9.38 ns |
| 32 KiB Get/Put | 9.96 ns | 7.62 ns | 9.77 ns |
| 64 KiB Get/Put | 9.96 ns | 7.49 ns | 9.81 ns |
| 128 KiB Get/Put | 10.15 ns | 7.51 ns | 9.39 ns |
| 256 KiB Get/Put | 9.74 ns | 7.17 ns | 9.49 ns |
| 4 KiB 并发 Get/Put | 0.58 ns | 0.43 ns | 29.58 ns |
| 混合九级并发 | 0.65 ns | 0.45 ns | 27.05 ns |

- **公平基线**：`sync.Pool` 基线也存放 `*byte` 并用 `unsafe.Slice` 重建切片，与 ydx
  的存储方式一致；因此两者差值就是尺寸分级选择、边界检查与 `*byte` 转换的成本。
- 串行路径比裸 `sync.Pool` 多约 **2.3–2.6 ns**；与 `bytebufferpool` 在 9.4–10.2 ns
  区间基本持平。分级查找是缓冲池提供的真正增值：调用方无需自己维护每个尺寸的池。
- 并发路径把竞争分散到九个池：4 KiB 并发 0.58 ns，混合九级并发 0.65 ns，仅比裸
  `sync.Pool` 多约 0.2 ns；单一全局池的 `bytebufferpool` 为 27–30 ns。
- 所有 Get/Put 路径预热后均为 **0 B/op、0 allocs/op**。
- **2× 分级**把最坏容量浪费从接近 4× 降到 ≤2×；`middleware/reqlog` 的 32 KiB 请求
  从 64 KiB 类降到 32 KiB 类，单请求缓冲减半。
- 曾尝试为九个池槽做缓存行隔离；混合分级并行 A/B 无收益（中位数约 3.93 ns vs
  3.60 ns，在噪声范围内），因此最终版本不引入 padding，减少常驻内存与缓存占用。

> `sync.Pool` 基线没有尺寸分级与“只回收恰好分级容量”的约束，其数字是无策略上限；
> 同一轮内小于约 5% 的差异视为噪声，跨轮次绝对值会随 CPU 频率/温度漂移。
>
> **v0.1.5 行为变更**：`Get(n)` 的 cap 可能与 v0.1.4 不同（例如 1 KiB+1 从 4 KiB 变为
> 2 KiB），但始终满足 `cap >= n`；升级下游时需复核是否依赖具体 cap。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只使用 Go 标准库（`sync`、`unsafe`）。

基准对比使用 [`valyala/bytebufferpool`](https://github.com/valyala/bytebufferpool)
（MIT）与标准库 `sync.Pool`；它们只出现在基准模块，不进入本产品模块的依赖。

## 相关模块

- [`middleware/compress`](../middleware/compress/README.md)：压缩缓冲复用。
- [`log`](../log/README.md)：日志编码缓冲。
- [`sse`](../sse/README.md)、[`websocket`](../websocket/README.md)：帧与消息缓冲。
- [`middleware/reqlog`](../middleware/reqlog/README.md)：请求捕获复用。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
