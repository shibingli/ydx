# benchmarks/cache — 二级缓存与主流本地缓存对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/cache` 是二级缓存：L1 为分片、按字节预算、TinyLFU 准入的环形缓存，L2 可选
Redis；值在两层都以字节信封保存，`Raw.View`/`GetOrLoadView` 提供零拷贝回调。
本基准分两部分：Manager 原始路径，以及 L1（`cache/local`）与主流本地缓存的对比。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/cache/local | v0.1.5 | 分片、字节预算、TinyLFU、TTL、零拷贝 View |
| `github.com/allegro/bigcache/v3` | v3.2.0 | 分片、字节数组存储、无 GC 扫描 |
| `github.com/coocood/freecache` | v1.2.7 | 环形缓冲、无 GC 扫描 |
| `github.com/dgraph-io/ristretto/v2` | v2.4.2 | TinyLFU + 采样 LFU，异步写 |
| `sync.Map` | Go 1.27.2 | 通用并发 map，无预算/淘汰 |
| `github.com/patrickmn/go-cache` | v2.1.0+incompatible | 通用 map + 过期，无字节预算 |

## 场景

- `LocalGetCompare`：1024 个 32 字节值，顺序循环读取。
- `LocalSetCompare`：4096 个键循环写入 32 字节值；键在计时前预生成。
- `LocalGetParallelCompare`：1024 个键，多 goroutine 并发读取。
- Manager：`RawGet`、`RawView`、`RawSet`、`RawGetTwoLevelL1Hit`。

## 关键结果

| 场景 | ydx | bigcache | freecache | ristretto | `sync.Map` | go-cache |
|---|---:|---:|---:|---:|---:|---:|
| Get 命中 | 83.02 ns | 125.7 ns | 106.9 ns | 98.97 ns | 24.49 ns | 28.28 ns |
| Set | 89.52 ns | 124.3 ns | 75.80 ns | 408.3 ns* | 172.5 ns | 81.71 ns |
| 并发 Get | 20.88 ns | 41.06 ns | 32.43 ns | 17.04 ns | 4.151 ns | 42.82 ns |

\* ristretto 的 `Set` 是异步准入入队，不等待写入可见，不能与同步 Set 直接等价比较。

- Get：ydx 比 bigcache 快约 34%、比 freecache 快约 22%、比 ristretto 快约 16%；
  `sync.Map` 与 go-cache 更快，但它们没有字节预算、淘汰策略或 TTL 语义，且值类型是
  任意接口。
- Set：ydx 比 bigcache 快约 28%，比 freecache 慢约 18%，比 go-cache 慢约 9%；
  freecache 与 go-cache 的同步写入路径更轻。
- 并发 Get：ydx 20.88 ns，仅次于 ristretto 17.04 ns 与 `sync.Map` 4.151 ns；
  bigcache/freecache/go-cache 在 32–43 ns。
- Manager 原始路径：`RawGet` 204.8 ns、`RawView` 201.6 ns、`RawSet` 515.9 ns、
  两级缓存 L1 命中 157.6 ns；这些数字包含命名空间查找与字节信封处理。

## 完整数据

<details>
<summary>5 轮均值（含 Manager 与 L1）</summary>

**github.com/shibingli/ydx/benchmarks/cache**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `RawGet` | 204.8 ns | 48 | 2 |  |
| `RawView` | 201.6 ns | 16 | 1 |  |
| `RawSet` | 515.9 ns | 48 | 3 |  |
| `RawGetTwoLevelL1Hit` | 157.6 ns | 48 | 2 |  |

**github.com/shibingli/ydx/benchmarks/cache/local**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `Get` | 82.21 ns | 32 | 1 |  |
| `GetAppend` | 79.46 ns | 0 | 0 |  |
| `View` | 69.66 ns | 0 | 0 |  |
| `Set` | 206.3 ns | 23 | 1 |  |
| `GetParallel` | 42.70 ns | 61 | 2 |  |
| `LocalGetCompare/ydx` | 83.02 ns | 32 | 1 |  |
| `LocalGetCompare/bigcache` | 125.7 ns | 48 | 2 |  |
| `LocalGetCompare/freecache` | 106.9 ns | 32 | 1 |  |
| `LocalGetCompare/ristretto` | 98.97 ns | 7 | 0 |  |
| `LocalGetCompare/syncmap` | 24.49 ns | 0 | 0 |  |
| `LocalGetCompare/go-cache` | 28.28 ns | 0 | 0 |  |
| `LocalSetCompare/ydx` | 89.52 ns | 0 | 0 |  |
| `LocalSetCompare/bigcache` | 124.3 ns | 27 | 0 |  |
| `LocalSetCompare/freecache` | 75.80 ns | 0 | 0 |  |
| `LocalSetCompare/ristretto` | 408.3 ns | 96 | 1 |  |
| `LocalSetCompare/syncmap` | 172.5 ns | 88 | 3 |  |
| `LocalSetCompare/go-cache` | 81.71 ns | 24 | 1 |  |
| `LocalGetParallelCompare/ydx` | 20.88 ns | 32 | 1 |  |
| `LocalGetParallelCompare/bigcache` | 41.06 ns | 48 | 2 |  |
| `LocalGetParallelCompare/freecache` | 32.43 ns | 32 | 1 |  |
| `LocalGetParallelCompare/ristretto` | 17.04 ns | 0 | 0 |  |
| `LocalGetParallelCompare/syncmap` | 4.151 ns | 0 | 0 |  |
| `LocalGetParallelCompare/go-cache` | 42.82 ns | 0 | 0 |  |
</details>

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
