# cache — 二级缓存（L1 环形缓存 + Redis）

`github.com/shibingli/ydx/cache` 是框架的二级缓存。`Manager` 拥有一个由所有命名空间共享的
一级缓存，以及可选的远端存储（Redis）。值在 L1 与 L2 中都保存为字节信封，使两层字节
完全一致，也让长生命周期的 Go 对象图远离堆。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/cache` |
| 包名 | `cache` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认前缀 | `yd:cache:` |

## 功能

- `NewManager(...)`：构造二级缓存管理器。
- `Manager.Raw(namespace)`：取得原始字节命名空间。
- `New[T](m, namespace, opts...)` / `NewWithCodec[T]`：类型化缓存。
- `Raw.View` / `Raw.GetOrLoadView`：零拷贝回调读取。
- `Codec[T]`：`Bool`、`Bytes`、`Float64`、`Int`、`Int64`、`JSON[T]`、`String`、`Time`、
  `Uint64`。
- 缓存选项：`WithTTL`、`WithJitter`、`WithNegativeTTL`、`WithNamespaceLease`。
- 管理器选项：`WithRemote`、`WithLocalOptions`、`WithFailOpen`、`WithLease`、
  `WithLoadTimeout`、`WithNodeID`、`WithTombstoneTTL`、`WithEventBuffer`、`WithLogger`。
- `OptionsFromConfig` / `RedisOptionsFromConfig`：配置驱动。
- `WithBypass` / `Bypass`、`WithDeferredInvalidation` / `DeferredInvalidation`：请求级
  缓存旁路与延迟失效。
- `WireEncode` / `WireAppend` / `WireDecode`：字节信封编解码。
- 子包：`cache/local`（L1 实现）、`cache/gormcache`（GORM 查询缓存）。

## 特性

- **两层字节一致**：L1 与 L2 都存字节信封，避免两层序列化语义不同。
- **减少 GC 扫描**：缓存值不保留长生命周期 Go 对象图；数百 MiB 缓存只增加少量可扫描对象。
- **一致性模型**：
  - 写入先到 L2，再更新 L1 并发布失效事件；每个节点收到事件后删除自己的 L1 条目。
  - 每个 L2 条目带单调递增版本号；读透加载用 CAS 回填，慢加载不会覆盖更新的写入。
  - L1 条目最长存活 `Lease`；丢失的 Pub/Sub 消息把陈旧窗口限制在 `Lease` 内，重连会
    整体清空 L1。
- **零拷贝读取**：`Raw.View` / `Raw.GetOrLoadView` 把已存字节直接交给回调，不再从环形
  缓冲区复制；类型化缓存就在回调内解码。
- **防击穿/雪崩**：`WithJitter` 打散 TTL，读透加载合并并发请求。
- **失败策略可控**：`WithFailOpen` 决定 L2 读失败时是否回退加载；写失败不被静默隐藏。
- **L1 实现**：分片、按字节预算、TinyLFU 准入、TTL 与零拷贝 `View`。

## 快速开始

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/shibingli/ydx/cache"
)

type User struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

func main() {
	mgr, err := cache.NewManager(
		cache.WithOptions(cache.Options{
			Lease: 30 * time.Second, // L1 条目最长存活时间
		}),
	)
	if err != nil {
		return
	}
	defer func() { _ = mgr.Close() }()

	users, err := cache.New[User](mgr, "users", cache.WithTTL(time.Minute))
	if err != nil {
		return
	}

	ctx := context.Background()
	u, err := users.GetOrLoad(ctx, "42", func(ctx context.Context) (User, error) {
		return User{ID: 42, Name: "Ada"}, nil
	})
	if err != nil {
		return
	}
	fmt.Println(u.Name)
}
```

零拷贝读取：

```go
raw, err := mgr.Raw("users")
if err != nil {
	return err
}
_, err = raw.View(ctx, "42", func(b []byte) error {
	// b 只在回调期间有效，不要保存引用。
	return nil
})
```

请求级旁路：

```go
ctx = cache.WithBypass(ctx) // 本次请求跳过缓存读写
```

子包 `cache/gormcache` 提供 GORM 查询结果缓存；`cache/local` 可单独作为进程内缓存使用。

## 应用场景

- **读多写少的 API**：用户资料、商品详情、配置。
- **多机一致性**：Redis Pub/Sub 失效事件 + L1 Lease 限制陈旧窗口。
- **大容量本地缓存**：字节预算与 TinyLFU 控制内存，避免 GC 扫描大对象图。
- **GORM 查询缓存**：`cache/gormcache` 缓存查询结果。
- **防击穿**：并发读透合并 + 抖动 TTL。
- **请求级旁路**：写后读一致性要求高的请求跳过缓存。

## 性能指标

基准模块：[`benchmarks/cache`](../benchmarks/cache/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | ydx/cache/local | bigcache | freecache | ristretto | `sync.Map` |
|---|---:|---:|---:|---:|---:|
| Get 命中（32 B，防御性副本） | 44.99 ns | 43.08 ns | 82.99 ns | 35.53 ns* | 13.45 ns* |
| Set（32 B） | **49.07 ns** | 95.84 ns | 75.53 ns | 173.4 ns† | 74.12 ns |
| 并发 Get | 9.79 ns | 21.25 ns | 15.17 ns | 6.51 ns* | 0.81 ns* |
| `GetAppend` / `View`（零拷贝） | 38.33 / 36.54 ns | — | — | 35.53 ns* | 13.45 ns* |

\* 返回缓存内引用，与防御性副本口径不可直接横比。† ristretto 的 `Set` 是异步准入入队。

- Set 全面领先：比 freecache 快约 35%、比 bigcache 快约 49%、比 `sync.Map` 快约 34%，
  全程零分配。
- 副本 Get 与 bigcache 基本持平（差异约 4%，在噪声内），比 freecache 快约 46%。
- 零拷贝 `View` 36.54 ns、`GetAppend` 38.33 ns，与 ristretto 的引用 Get 基本持平。
- Manager 原始路径：`RawGet` 110.4 ns、`RawView` 100.4 ns、`RawSet` 229.0 ns、
  两级缓存 L1 命中 110.2 ns（含命名空间查找与字节信封处理）。
- 64 B / 1 KiB / TTL / 混合轨迹的扩展结果见基准 README；带 TTL 的读写需支付本机约
  43 ns 的 `time.Now()` 成本。

> 同一轮内小于约 5% 的差异视为噪声；完整表格与语义差异见基准 README。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`redis/go-redis/v9`](https://github.com/redis/go-redis) | v9.23.0 | BSD-2-Clause | L2 Redis 存储与 Pub/Sub |
| [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync) | v0.24.0 | BSD-3-Clause | 并发加载合并 |
| [`gorm.io/gorm`](https://gorm.io) | v1.31.2 | MIT | `cache/gormcache` 查询缓存 |
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 配置来源文件系统 |

测试使用 [`alicebob/miniredis/v2`](https://github.com/alicebob/miniredis)（MIT）与
[`glebarez/sqlite`](https://github.com/glebarez/sqlite)（MIT）。

基准对比对象：bigcache、freecache、ristretto、`sync.Map`、go-cache、theine、ttlcache、
golang-lru，仅出现在 `benchmarks/cache`。

仓库内依赖：`afs`、`config`、`errs`、`json`、`log`、`nodeid`、`sysinfo`。

## 相关模块

- [`redis`](../redis/README.md)：Redis 客户端与读透缓存。
- [`gorm`](../gorm/README.md)：数据库装配；`cache/gormcache` 查询缓存。
- [`nodeid`](../nodeid/README.md)：多机失效事件中的节点身份。
- [`middleware`](../middleware/README.md)：请求级缓存旁路中间件。
- [`json`](../json/README.md)：类型化缓存载荷序列化。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
