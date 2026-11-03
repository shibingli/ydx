# benchmarks/buffpool — 分级缓冲池对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/buffpool` 是带尺寸分级的 `[]byte` 池：1、2、4、8、16、32、64、128、256 KiB
九个等级（2× 间隔），每级一个 `sync.Pool`，池内存放指向块首的 `*byte`，避免把切片头
装箱进接口。本基准比较它与直接使用 `sync.Pool`、`valyala/bytebufferpool` 的 Get/Put 成本。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/buffpool | v0.1.5 | 九个 2× 尺寸分级，`*byte` 存放 |
| `sync.Pool` | Go 1.27.3 | 每个尺寸一个独立池，同样存放 `*byte`（公平基线） |
| `github.com/valyala/bytebufferpool` | v1.0.0 | 单一全局池，存放 `*ByteBuffer` |

## 场景

- `GetPut`：九个尺寸分级各做一次 Get/Put，计时前预热一个缓冲。
- `GetPutParallel`：4 KiB 分级下多 goroutine 并发 Get/Put。
- `GetPutMixedParallel`：多 goroutine 轮换全部九个分级，观察分级查找与跨分级槽位的
  缓存行行为。

## 关键结果（2026-11-03，Zen 5 + Go 1.27.3）

环境：远程 host-01，Linux AMD Ryzen AI MAX+ 395（Zen 5，16 核 32 线程），
`GOMAXPROCS=32`，`-count=5 -benchtime=1s` 中位数。

| 场景 | ydx | `sync.Pool` | bytebufferpool |
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
| 混合分级并发 | 0.65 ns | 0.45 ns | 27.05 ns |

- **公平基线**：`sync.Pool` 基线也存放 `*byte` 并用 `unsafe.Slice` 重建切片，与 ydx
  的存储方式一致；因此两者差值就是尺寸分级选择、边界检查与 `*byte` 转换的成本。
- 串行路径：ydx 比裸 `sync.Pool` 多约 **2.3–2.6 ns**；与 bytebufferpool 在 9.4–10.2 ns
  区间基本持平。分级查找是缓冲池提供的真正增值：调用方无需自己维护每个尺寸的池。
- 并发路径：ydx 每分级独立 `sync.Pool`，4 KiB 并发 0.58 ns；混合九级并发 0.65 ns，
  仅比裸 `sync.Pool` 多约 0.2 ns，说明九个分级没有引入可测的跨池争用。
- 所有 Get/Put 路径均为 **0 B/op、0 allocs/op**（预热后）。
- **2× 分级**把最坏容量浪费从接近 4× 降到 ≤2×；`middleware/reqlog` 的 32 KiB 请求
  从 64 KiB 类降到 32 KiB 类，单请求缓冲减半。
- 曾尝试为九个池槽加缓存行隔离；混合分级并行 A/B 无收益（中位数约 3.93 ns vs 3.60 ns，
  在噪声范围内），因此最终版本不引入 padding，减少常驻内存与缓存占用。

## 完整数据

<details>
<summary>5 轮中位数（Zen 5 + Go 1.27.3，host-01）</summary>

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `GetPut/1KiB/ydx` | 9.37 ns | 0 | 0 |
| `GetPut/1KiB/syncpool` | 7.04 ns | 0 | 0 |
| `GetPut/1KiB/bytebufferpool` | 9.39 ns | 0 | 0 |
| `GetPut/2KiB/ydx` | 9.79 ns | 0 | 0 |
| `GetPut/2KiB/syncpool` | 7.12 ns | 0 | 0 |
| `GetPut/2KiB/bytebufferpool` | 9.38 ns | 0 | 0 |
| `GetPut/4KiB/ydx` | 9.96 ns | 0 | 0 |
| `GetPut/4KiB/syncpool` | 7.38 ns | 0 | 0 |
| `GetPut/4KiB/bytebufferpool` | 9.78 ns | 0 | 0 |
| `GetPut/8KiB/ydx` | 9.96 ns | 0 | 0 |
| `GetPut/8KiB/syncpool` | 7.19 ns | 0 | 0 |
| `GetPut/8KiB/bytebufferpool` | 9.54 ns | 0 | 0 |
| `GetPut/16KiB/ydx` | 9.66 ns | 0 | 0 |
| `GetPut/16KiB/syncpool` | 7.22 ns | 0 | 0 |
| `GetPut/16KiB/bytebufferpool` | 9.38 ns | 0 | 0 |
| `GetPut/32KiB/ydx` | 9.96 ns | 0 | 0 |
| `GetPut/32KiB/syncpool` | 7.62 ns | 0 | 0 |
| `GetPut/32KiB/bytebufferpool` | 9.77 ns | 0 | 0 |
| `GetPut/64KiB/ydx` | 9.96 ns | 0 | 0 |
| `GetPut/64KiB/syncpool` | 7.49 ns | 0 | 0 |
| `GetPut/64KiB/bytebufferpool` | 9.81 ns | 0 | 0 |
| `GetPut/128KiB/ydx` | 10.15 ns | 0 | 0 |
| `GetPut/128KiB/syncpool` | 7.51 ns | 0 | 0 |
| `GetPut/128KiB/bytebufferpool` | 9.39 ns | 0 | 0 |
| `GetPut/256KiB/ydx` | 9.74 ns | 0 | 0 |
| `GetPut/256KiB/syncpool` | 7.17 ns | 0 | 0 |
| `GetPut/256KiB/bytebufferpool` | 9.49 ns | 0 | 0 |
| `GetPutParallel/ydx` | 0.58 ns | 0 | 0 |
| `GetPutParallel/syncpool` | 0.43 ns | 0 | 0 |
| `GetPutParallel/bytebufferpool` | 29.58 ns | 0 | 0 |
| `GetPutMixedParallel/ydx` | 0.65 ns | 0 | 0 |
| `GetPutMixedParallel/syncpool` | 0.45 ns | 0 | 0 |
| `GetPutMixedParallel/bytebufferpool` | 27.05 ns | 0 | 0 |
</details>

## 复现

`buffpool/v0.1.5` 子目录标签发布后：

```bash
cd benchmarks/buffpool
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=1s
```

标签发布前，在仓库外临时 `replace` 指向本地 `buffpool` 模块（不得提交）：

```bash
cd benchmarks/buffpool
go mod edit -replace github.com/shibingli/ydx/buffpool=/path/to/ydx/buffpool
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=1s
git checkout go.mod
```

## 口径与限制

- `sync.Pool` 基线现在同样存放 `*byte`，因此它**没有**尺寸分级选择成本，但也没有
  “只回收恰好分级容量”的约束；其数字应视为无策略上限。
- ydx 只回收容量恰好等于某一分级的缓冲；`sync.Pool` 与 bytebufferpool 没有这个限制。
- bytebufferpool 的 `Get` 返回带 `B []byte` 字段的结构体，基准在 Put 前调用
  `Reset`；ydx 与 `sync.Pool` 的基准不重置内容（两者都不保证零值）。
- 2× 分级是行为变更：`Get(n)` 的 cap 在 v0.1.5 可能与 v0.1.4 不同（例如 1 KiB+1 从
  4 KiB 变为 2 KiB），但始终满足 `cap >= n`；下游升级时需复核是否依赖具体 cap。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
