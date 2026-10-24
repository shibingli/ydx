# benchmarks/buffpool — 分级缓冲池对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/buffpool` 是带尺寸分级的 `[]byte` 池：1 KiB、4 KiB、16 KiB、64 KiB、256 KiB
五个等级，每级一个 `sync.Pool`，池内存放指向块首的 `*byte`，避免把切片头装箱进
接口。本基准比较它与直接使用 `sync.Pool`、`valyala/bytebufferpool` 的 Get/Put 成本。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/buffpool | v0.1.4 | 五个尺寸分级，`*byte` 存放 |
| `sync.Pool` | Go 1.27.3 | 每个尺寸一个独立池，存放 `*[]byte` |
| `github.com/valyala/bytebufferpool` | v1.0.0 | 单一全局池，存放 `*ByteBuffer` |

## 场景

- `GetPut`：每个尺寸分级各做一次 Get/Put，计时前预热一个缓冲。
- `GetPutParallel`：4 KiB 分级下多 goroutine 并发 Get/Put。

## 关键结果（2026-10-24，Zen 5 + Go 1.27.3）

| 场景 | ydx | `sync.Pool` | bytebufferpool |
|---|---:|---:|---:|
| 1 KiB Get/Put | **9.27 ns** | 7.09 ns | 9.40 ns |
| 4 KiB Get/Put | 9.94 ns | 7.23 ns | 9.49 ns |
| 16 KiB Get/Put | 9.78 ns | 7.26 ns | 9.50 ns |
| 64 KiB Get/Put | 9.79 ns | 7.24 ns | 9.53 ns |
| 256 KiB Get/Put | 9.96 ns | 7.15 ns | 9.57 ns |
| 4 KiB 并发 Get/Put | 0.58 ns | 0.42 ns | 30.36 ns |

- 串行路径：ydx 比裸 `sync.Pool` 多约 2.2–2.7 ns，这部分是尺寸分级查找、边界检查与
  `*byte` 到 `[]byte` 的转换成本；与 bytebufferpool 在 9.3–10.0 ns 区间互有胜负
  （1 KiB 领先 1.4%，4–256 KiB 落后 2.7%–4.7%），全部落在同一轮 5% 噪声阈值内，
  记为持平。
- 并发路径：ydx 的每分级独立 `sync.Pool` 把竞争分散到 5 个池，0.58 ns；bytebufferpool
  的单一全局池竞争明显（30.36 ns）。
- 所有 Get/Put 路径均为 0 B/op、0 allocs/op（预热后）。
- `Put` 用 `unsafe.SliceData` 取得块首指针、`Get` 用 `unsafe.Slice` 重建视图，两者都不
  产生装箱或边界检查以外的额外工作。

## 完整数据

<details>
<summary>5 轮中位数（Zen 5 + Go 1.27.3）</summary>

**github.com/shibingli/ydx/benchmarks/buffpool**

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `GetPut/1KiB/ydx` | 9.27 ns | 0 | 0 |
| `GetPut/1KiB/syncpool` | 7.09 ns | 0 | 0 |
| `GetPut/1KiB/bytebufferpool` | 9.40 ns | 0 | 0 |
| `GetPut/4KiB/ydx` | 9.94 ns | 0 | 0 |
| `GetPut/4KiB/syncpool` | 7.23 ns | 0 | 0 |
| `GetPut/4KiB/bytebufferpool` | 9.49 ns | 0 | 0 |
| `GetPut/16KiB/ydx` | 9.78 ns | 0 | 0 |
| `GetPut/16KiB/syncpool` | 7.26 ns | 0 | 0 |
| `GetPut/16KiB/bytebufferpool` | 9.50 ns | 0 | 0 |
| `GetPut/64KiB/ydx` | 9.79 ns | 0 | 0 |
| `GetPut/64KiB/syncpool` | 7.24 ns | 0 | 0 |
| `GetPut/64KiB/bytebufferpool` | 9.53 ns | 0 | 0 |
| `GetPut/256KiB/ydx` | 9.96 ns | 0 | 0 |
| `GetPut/256KiB/syncpool` | 7.15 ns | 0 | 0 |
| `GetPut/256KiB/bytebufferpool` | 9.57 ns | 0 | 0 |
| `GetPutParallel/ydx` | 0.58 ns | 0 | 0 |
| `GetPutParallel/syncpool` | 0.42 ns | 0 | 0 |
| `GetPutParallel/bytebufferpool` | 30.36 ns | 0 | 0 |
</details>

## 复现

```bash
cd benchmarks/buffpool
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- `sync.Pool` 基准的 `New` 只分配目标尺寸的 `[]byte`；它没有尺寸分级、边界检查或
  “只回收恰好分级容量”的约束，因此它的数字是**无策略上限**。
- ydx 只回收容量恰好等于某一分级的缓冲；`sync.Pool` 与 bytebufferpool 没有这个限制。
- bytebufferpool 的 `Get` 返回带 `B []byte` 字段的结构体，基准在 Put 前调用
  `Reset`；ydx 与 `sync.Pool` 的基准不重置内容（两者都不保证零值）。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
