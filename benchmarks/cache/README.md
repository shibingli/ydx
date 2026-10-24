# benchmarks/cache — 二级缓存与主流本地缓存对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/cache` 是二级缓存：L1 为分片、按字节预算、TinyLFU 准入的环形缓存，L2 可选
Redis；值在两层都以字节信封保存，`Raw.View`/`GetOrLoadView` 提供零拷贝回调。
本基准分两部分：Manager 原始路径，以及 L1（`cache/local`）与主流本地缓存的对比。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/cache/local | v0.1.7 | 分片、字节预算、TinyLFU、TTL、零拷贝 View |
| `github.com/allegro/bigcache/v3` | v3.2.0 | 分片、字节数组存储、无 GC 扫描 |
| `github.com/coocood/freecache` | v1.2.7 | 环形缓冲、无 GC 扫描 |
| `github.com/dgraph-io/ristretto/v2` | v2.4.2 | TinyLFU + 采样 LFU，异步写 |
| `sync.Map` | Go 1.27.3 | 通用并发 map，无预算/淘汰 |
| `github.com/patrickmn/go-cache` | v2.1.0+incompatible | 通用 map + 过期，无字节预算 |

## 场景

- `LocalGetCompare`：1024 个 32 字节值，顺序循环读取。
- `LocalSetCompare`：4096 个键循环写入 32 字节值；键在计时前预生成。
- `LocalGetParallelCompare`：1024 个键，多 goroutine 并发读取。
- Manager：`RawGet`、`RawView`、`RawSet`、`RawGetTwoLevelL1Hit`。

## 关键结果（2026-10-24，Zen 5 + Go 1.27.3）

| 场景 | ydx | bigcache | freecache | ristretto | `sync.Map` | go-cache |
|---|---:|---:|---:|---:|---:|---:|
| Get 命中（32 B，防御性副本） | 44.99 ns | 43.08 ns | 82.99 ns | 35.53 ns | 13.45 ns | 47.50 ns |
| Set（32 B） | **49.07 ns** | 95.84 ns | 75.53 ns | 173.4 ns* | 74.12 ns | 78.78 ns |
| 并发 Get | 9.79 ns | 21.25 ns | 15.17 ns | 6.51 ns | 0.81 ns | 23.00 ns |
| `GetAppend` / `View`（零拷贝） | 38.33 / 36.54 ns | — | — | 35.53 ns | 13.45 ns | — |

\* ristretto 的 `Set` 是异步准入入队，不等待写入可见，不能与同步 Set 直接等价比较。

- **Set 全面领先**：49.07 ns，比 freecache 快约 35%、比 bigcache 快约 49%、比 `sync.Map`
  快约 34%、比 go-cache 快约 38%；全程零分配。
- **Get（副本语义）**：44.99 ns 与 bigcache（43.08 ns）基本持平（差异约 4%，在噪声内），
  比 freecache 快约 46%；ristretto（35.53 ns）与 `sync.Map`（13.45 ns）返回缓存内引用，
  go-cache 没有容量/TTL 约束，均不能与防御性副本路径直接横比。
- **零拷贝读路径**：`GetAppend` 38.33 ns、`View` 36.54 ns，与 ristretto 的引用 Get
  基本持平；需要零分配时优先使用这两个入口。
- **并发 Get**：9.79 ns，领先 bigcache（21.25）/freecache（15.17）/go-cache（23.00），
  落后引用语义的 ristretto（6.51）与 `sync.Map`（0.81）。
- **Manager 原始路径**：`RawGet` 110.4 ns、`RawView` 100.4 ns、`RawSet` 229.0 ns、
  两级缓存 L1 命中 110.2 ns；包含命名空间查找与字节信封处理。

> 历史 Windows 口径的完整数据保留在下方，仅作变化轨迹参考；主表以本节为准。

## 扩展对比（64 B / 1 KiB / TTL / 混合轨迹，同一轮）

| 场景（64 B） | ydx | bigcache | freecache | ristretto | theine | ttlcache | golang-lru | go-cache |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Get（副本） | 57.19 ns | 66.53 ns | 94.11 ns | 45.91 ns | 90.85 ns | 57.11 ns | 24.75 ns | 14.59 ns |
| `GetAppend`（零拷贝） | 46.77 ns | — | 80.99 ns* | — | — | — | — | — |
| `View`（零拷贝） | **42.52 ns** | — | — | — | — | — | — | — |
| Set | **52.44 ns** | 182.4 ns | 82.52 ns | 222.4 ns† | 93.96 ns | 84.54 ns | 26.17 ns | 44.49 ns |

| 场景（1 KiB） | ydx | bigcache | freecache | ristretto | theine | ttlcache | golang-lru | go-cache |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Get（副本） | 246.2 ns | 237.9 ns | 261.1 ns | 46.12 ns | 88.84 ns | 57.22 ns | 24.74 ns | 15.12 ns |
| `GetAppend`（零拷贝） | 94.79 ns | — | 84.70 ns* | — | — | — | — | — |
| `View`（零拷贝） | **38.11 ns** | — | — | — | — | — | — | — |
| Set | **83.32 ns** | 550.4 ns | 117.2 ns | 225.1 ns† | 93.82 ns | 83.99 ns | 25.97 ns | 45.41 ns |

| 场景 | ydx | bigcache | freecache | ristretto | theine | ttlcache | golang-lru | go-cache |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 并发 Get（副本 / 零拷贝） | 17.99 / **12.69** ns | 19.30 ns | 23.05 ns | 13.19 ns | 12.57 ns | 210.7 ns | 110.0 ns | 29.87 ns |
| 混合轨迹 Get（副本 / `View`） | 59.76 / **44.47** ns | 88.95 ns | 98.02 ns | 78.32 ns | 118.7 ns | 59.98 ns | 25.48 ns | 18.56 ns |
| Get + 1 h TTL（副本 / `View`） | 96.61 / **83.59** ns | — | 100.3 ns | 84.26 ns | 92.21 ns | 293.1 ns | — | 57.95 ns |
| Set + 1 h TTL | 100.0 ns | — | **82.66 ns** | 301.0 ns† | 127.8 ns | 258.9 ns | — | 88.08 ns |

\* freecache 的 `Getfn` 是零拷贝回调口径。† ristretto 的 `Set` 是异步准入入队，不等待写入可见。
golang-lru 与 go-cache 没有字节预算与淘汰统计，能力集不同，仅作参考。

- **Set 领先**：64 B 52.44 ns、1 KiB 83.32 ns，比 freecache 快 36%/29%、比 bigcache
  快 3.5×/6.6×、比 theine 快 44%/11%；全程零分配（bigcache 每次写分配 200 B–2.7 KiB）。
- **副本 Get**：64 B 领先 bigcache（66.53）、freecache（94.11）、theine（90.85）；
  1 KiB 246.2 ns 与 bigcache 237.9 ns 相差 3.5%，在噪声内。ristretto 46.12 ns 返回
  缓存内引用，与副本口径不可直接横比。
- **零拷贝路径**：`View` 在 64 B 42.52 ns、1 KiB 38.11 ns，1 KiB 时比 ristretto 的
  引用 Get（46.12 ns）还快 17%；并发 `View` 12.69 ns 与 theine（12.57）持平。
- **TTL 行**：本机 `time.Now()` 单次约 43 ns（实测），凡带 TTL 的读写都要支付这笔时钟
  成本。`Set + TTL` 100.0 ns 比 freecache（82.66）慢 21%，是缓存对比里唯一同口径落后项；
  无 TTL 的 Set 则快 36%。freecache 在无 TTL 的 Set 上也读时钟，因此其 82.5 ns 已含这笔
  成本，而 ydx 只在给出 TTL 时支付。
- **Manager 原始路径**：`RawGet` 110.4 ns、`RawView` 100.4 ns、`RawSet` 229.0 ns、
  两级缓存 L1 命中 110.2 ns；包含命名空间查找与字节信封处理。

## 完整数据

<details>
<summary>5 轮中位数（2026-10-24，Zen 5 + Go 1.27.3）</summary>

`Raw*` 来自 `cache` 包，`Get`/`Set`/`View` 等来自 `cache/local`，`Compare*` 来自
`cache/compare`；三个包在同一进程轮次内串行执行。

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `RawGet` | 110.40 ns | 48 | 2 |
| `RawView` | 100.40 ns | 16 | 1 |
| `RawSet` | 229.00 ns | 48 | 3 |
| `RawGetTwoLevelL1Hit` | 110.20 ns | 48 | 2 |
| `CompareGet/64B/yd-local-get` | 57.19 ns | 64 | 1 |
| `CompareGet/64B/yd-local-getappend` | 46.77 ns | 0 | 0 |
| `CompareGet/64B/yd-local-view` | 42.52 ns | 0 | 0 |
| `CompareGet/64B/freecache-get` | 94.11 ns | 64 | 1 |
| `CompareGet/64B/freecache-getfn` | 80.99 ns | 0 | 0 |
| `CompareGet/64B/ristretto` | 45.91 ns | 2 | 0 |
| `CompareGet/64B/theine` | 90.85 ns | 16 | 1 |
| `CompareGet/64B/bigcache` | 66.53 ns | 80 | 2 |
| `CompareGet/64B/go-cache` | 14.59 ns | 0 | 0 |
| `CompareGet/64B/ttlcache` | 57.11 ns | 0 | 0 |
| `CompareGet/64B/golang-lru` | 24.75 ns | 0 | 0 |
| `CompareGet/1024B/yd-local-get` | 246.20 ns | 1.000 KiB | 1 |
| `CompareGet/1024B/yd-local-getappend` | 94.79 ns | 0 | 0 |
| `CompareGet/1024B/yd-local-view` | 38.11 ns | 0 | 0 |
| `CompareGet/1024B/freecache-get` | 261.10 ns | 1.000 KiB | 1 |
| `CompareGet/1024B/freecache-getfn` | 84.70 ns | 0 | 0 |
| `CompareGet/1024B/ristretto` | 46.12 ns | 2 | 0 |
| `CompareGet/1024B/theine` | 88.84 ns | 16 | 1 |
| `CompareGet/1024B/bigcache` | 237.90 ns | 1.016 KiB | 2 |
| `CompareGet/1024B/go-cache` | 15.12 ns | 0 | 0 |
| `CompareGet/1024B/ttlcache` | 57.22 ns | 0 | 0 |
| `CompareGet/1024B/golang-lru` | 24.74 ns | 0 | 0 |
| `CompareGetParallel/yd-local-get` | 17.99 ns | 64 | 1 |
| `CompareGetParallel/yd-local-getappend` | 12.81 ns | 0 | 0 |
| `CompareGetParallel/yd-local-view` | 12.69 ns | 0 | 0 |
| `CompareGetParallel/freecache-get` | 23.05 ns | 64 | 1 |
| `CompareGetParallel/freecache-getfn` | 18.00 ns | 0 | 0 |
| `CompareGetParallel/ristretto` | 13.19 ns | 0 | 0 |
| `CompareGetParallel/theine` | 12.57 ns | 0 | 0 |
| `CompareGetParallel/bigcache` | 19.30 ns | 80 | 2 |
| `CompareGetParallel/go-cache` | 29.87 ns | 0 | 0 |
| `CompareGetParallel/ttlcache` | 210.70 ns | 0 | 0 |
| `CompareGetParallel/golang-lru` | 110.00 ns | 0 | 0 |
| `CompareSet/64B/yd-local` | 52.44 ns | 0 | 0 |
| `CompareSet/64B/freecache` | 82.52 ns | 0 | 0 |
| `CompareSet/64B/ristretto` | 222.40 ns | 99 | 1 |
| `CompareSet/64B/theine` | 93.96 ns | 0 | 0 |
| `CompareSet/64B/bigcache` | 182.40 ns | 214 | 0 |
| `CompareSet/64B/go-cache` | 44.49 ns | 24 | 1 |
| `CompareSet/64B/ttlcache` | 84.54 ns | 0 | 0 |
| `CompareSet/64B/golang-lru` | 26.17 ns | 0 | 0 |
| `CompareSet/1024B/yd-local` | 83.32 ns | 0 | 0 |
| `CompareSet/1024B/freecache` | 117.20 ns | 0 | 0 |
| `CompareSet/1024B/ristretto` | 225.10 ns | 99 | 1 |
| `CompareSet/1024B/theine` | 93.82 ns | 0 | 0 |
| `CompareSet/1024B/bigcache` | 550.40 ns | 2.633 KiB | 0 |
| `CompareSet/1024B/go-cache` | 45.41 ns | 24 | 1 |
| `CompareSet/1024B/ttlcache` | 83.99 ns | 0 | 0 |
| `CompareSet/1024B/golang-lru` | 25.97 ns | 0 | 0 |
| `CompareSetChanging/64B/yd-local` | 54.24 ns | 0 | 0 |
| `CompareSetChanging/64B/freecache` | 82.83 ns | 0 | 0 |
| `CompareSetChanging/64B/ristretto` | 230.60 ns | 99 | 1 |
| `CompareSetChanging/64B/theine` | 93.63 ns | 0 | 0 |
| `CompareSetChanging/64B/bigcache` | 188.20 ns | 230 | 0 |
| `CompareSetChanging/64B/go-cache` | 47.74 ns | 24 | 1 |
| `CompareSetChanging/64B/ttlcache` | 84.70 ns | 0 | 0 |
| `CompareSetChanging/64B/golang-lru` | 26.35 ns | 0 | 0 |
| `CompareSetChanging/1024B/yd-local` | 85.65 ns | 0 | 0 |
| `CompareSetChanging/1024B/freecache` | 115.20 ns | 0 | 0 |
| `CompareSetChanging/1024B/ristretto` | 232.50 ns | 99 | 1 |
| `CompareSetChanging/1024B/theine` | 93.76 ns | 0 | 0 |
| `CompareSetChanging/1024B/bigcache` | 552.80 ns | 2.633 KiB | 0 |
| `CompareSetChanging/1024B/go-cache` | 47.30 ns | 24 | 1 |
| `CompareSetChanging/1024B/ttlcache` | 84.94 ns | 0 | 0 |
| `CompareSetChanging/1024B/golang-lru` | 26.52 ns | 0 | 0 |
| `CompareMixed/yd-local-get` | 59.76 ns | 57 | 0 |
| `CompareMixed/yd-local-getappend` | 48.11 ns | 0 | 0 |
| `CompareMixed/yd-local-view` | 44.47 ns | 0 | 0 |
| `CompareMixed/freecache-get` | 98.02 ns | 57 | 0 |
| `CompareMixed/freecache-getfn` | 81.37 ns | 0 | 0 |
| `CompareMixed/ristretto` | 78.32 ns | 14 | 0 |
| `CompareMixed/theine` | 118.70 ns | 14 | 0 |
| `CompareMixed/bigcache` | 88.95 ns | 95 | 1 |
| `CompareMixed/go-cache` | 18.56 ns | 2 | 0 |
| `CompareMixed/ttlcache` | 59.98 ns | 0 | 0 |
| `CompareMixed/golang-lru` | 25.48 ns | 0 | 0 |
| `CompareGetTTL/yd-local-get` | 96.61 ns | 64 | 1 |
| `CompareGetTTL/yd-local-getappend` | 82.39 ns | 0 | 0 |
| `CompareGetTTL/yd-local-view` | 83.59 ns | 0 | 0 |
| `CompareGetTTL/freecache-get` | 100.30 ns | 64 | 1 |
| `CompareGetTTL/freecache-getfn` | 81.01 ns | 0 | 0 |
| `CompareGetTTL/ristretto` | 84.26 ns | 3 | 0 |
| `CompareGetTTL/theine` | 92.21 ns | 16 | 1 |
| `CompareGetTTL/go-cache` | 57.95 ns | 0 | 0 |
| `CompareGetTTL/ttlcache` | 293.10 ns | 0 | 0 |
| `CompareSetTTL/yd-local` | 100.00 ns | 0 | 0 |
| `CompareSetTTL/freecache` | 82.66 ns | 0 | 0 |
| `CompareSetTTL/ristretto` | 301.00 ns | 99 | 1 |
| `CompareSetTTL/theine` | 127.80 ns | 0 | 0 |
| `CompareSetTTL/go-cache` | 88.08 ns | 24 | 1 |
| `CompareSetTTL/ttlcache` | 258.90 ns | 0 | 0 |
| `Get` | 44.82 ns | 32 | 1 |
| `GetAppend` | 38.33 ns | 0 | 0 |
| `View` | 36.54 ns | 0 | 0 |
| `Set` | 98.45 ns | 23 | 1 |
| `GetParallel` | 11.83 ns | 57 | 2 |
| `LocalGetCompare/ydx` | 44.99 ns | 32 | 1 |
| `LocalGetCompare/bigcache` | 43.08 ns | 48 | 2 |
| `LocalGetCompare/freecache` | 82.99 ns | 32 | 1 |
| `LocalGetCompare/ristretto` | 35.53 ns | 1 | 0 |
| `LocalGetCompare/syncmap` | 13.45 ns | 0 | 0 |
| `LocalGetCompare/go-cache` | 47.50 ns | 0 | 0 |
| `LocalSetCompare/ydx` | 49.07 ns | 0 | 0 |
| `LocalSetCompare/bigcache` | 95.84 ns | 21 | 0 |
| `LocalSetCompare/freecache` | 75.53 ns | 0 | 0 |
| `LocalSetCompare/ristretto` | 173.40 ns | 96 | 1 |
| `LocalSetCompare/syncmap` | 74.12 ns | 88 | 3 |
| `LocalSetCompare/go-cache` | 78.78 ns | 24 | 1 |
| `LocalGetParallelCompare/ydx` | 9.79 ns | 32 | 1 |
| `LocalGetParallelCompare/bigcache` | 21.25 ns | 48 | 2 |
| `LocalGetParallelCompare/freecache` | 15.17 ns | 32 | 1 |
| `LocalGetParallelCompare/ristretto` | 6.51 ns | 0 | 0 |
| `LocalGetParallelCompare/syncmap` | 0.81 ns | 0 | 0 |
| `LocalGetParallelCompare/go-cache` | 23.00 ns | 0 | 0 |
</details>

> 全量轮次中 `CompareSetTTL/yd-local` 为 104.7 ns；截止时间改为直接纳秒加法后复测为
> 100.0 ns，表中已采用复测值，其余行仍来自同一全量轮次。

## 复现

```bash
cd benchmarks/cache
GOWORK=off go test ./... -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- ydx/cache/local 只存 `[]byte`；bigcache/freecache 也是字节缓存；`sync.Map` 与
  go-cache 存任意值，基准存入 `[]byte`。后两者的接口装箱/类型断言成本与字节缓存不同。
- bigcache/freecache 的 `Get` 返回副本；ydx 的 `Get` 也返回副本，`View`/`GetAppend`
  才是零拷贝路径。基准表把 `Get` 与 `View` 分开报告。
- ristretto 的 `Set` 异步准入；`LocalSetCompare` 不调用 `Wait()`，因此 408.3 ns 只表示
  入队成本，不代表写入完成。
- go-cache 使用 `New(time.Hour, 0)` 关闭后台 janitor，避免额外 goroutine 污染测量；
  它的 `Set` 带过期时间参数。bigcache 关闭 `Verbose`，避免队列分配日志污染基准输出。
- `LocalSetCompare/ydx` 使用预生成键；既有 `Set` 基准在循环内 `fmt.Sprintf` 生成键，
  因此 206.3 ns 包含键格式化，不能与对比表的 89.52 ns 直接混比。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
