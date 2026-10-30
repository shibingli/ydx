# middleware/ratelimit — 按键令牌桶限流

`github.com/shibingli/ydx/middleware/ratelimit` 执行按键的令牌桶限流。超限请求返回 429
并带上 `Retry-After` 与 `X-RateLimit-Limit`、`X-RateLimit-Remaining`、`X-RateLimit-Reset`；
被放行的响应同样携带这三个头。存储故障遵循 `FailClosed`：默认放行并记录告警，开启后返回
503。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/middleware/ratelimit` |
| 包名 | `ratelimit` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `RateLimit(RateLimitOptions)`：YD 路由中间件。
- `Middleware(RateLimitOptions)`：原生 `net/http` 包装器。
- `MemoryStore`：单机内存令牌桶，带惰性清理。
- `RedisStore`：多机令牌桶，Lua 脚本以 Redis 服务器时钟原子完成读取/补充/判定/写回。
- `KeyFunc`：`KeyRemoteIP`、`KeyHeader`、`KeyQuery`、`KeyPath`、`KeyBasicAuthUser`、
  `KeyFingerprint`。
- `Decision`：剩余令牌与重置时间。
- `RateLimitOptions`：`Store`、`KeyFunc`、`KeyPrefix`、`TrustedProxies`、`Rate`、`Burst`、
  `CleanupInterval`、`FailClosed`、`Logger`。

## 特性

- **原子 Redis 限流**：Lua 脚本在 Redis 内完成整个令牌桶周期，避免多实例竞态。
- **内存快路径**：内存存储的中间件在装配期归一化选项，热路径跳过每请求归一化与取消检查。
- **标准响应头**：所有结果（放行/限流）都写 `X-RateLimit-*`；超限额外写 `Retry-After`。
- **失败策略可选**：默认 fail-open，避免 Redis 故障拖垮服务；保护稀缺资源时用
  `FailClosed`。
- **可信代理**：`KeyRemoteIP` 只信任 `TrustedProxies` 提供的 `X-Forwarded-For`。
- **键前缀隔离**：共享同一 Store 的多条规则用 `KeyPrefix` 隔离。
- **组合键**：`KeyFingerprint` 把多个 KeyFunc 组合成一个键。
- **双入口共享实现**：YD 与原生路径语义一致。

## 快速开始

### YD 路由（内存）

```go
r.Use(ratelimit.RateLimit(ratelimit.RateLimitOptions{
	Rate:  10,  // 每秒补充 10 个令牌
	Burst: 20,  // 桶容量 20
	KeyFunc: ratelimit.KeyRemoteIP([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}),
}))
```

### 多机（Redis）

```go
store, err := ratelimit.NewRedisStore(ratelimit.RedisStoreOptions{
	Client: rdb,
	Prefix: "rl:",
})
if err != nil {
	return err
}

r.Use(ratelimit.RateLimit(ratelimit.RateLimitOptions{
	Store:      store,
	Rate:       100,
	Burst:      200,
	KeyPrefix:  "api:",
	FailClosed: true,
	KeyFunc:    ratelimit.KeyHeader("X-API-Key"),
}))
```

### 原生 net/http

```go
handler := ratelimit.Middleware(o)(mux)
```

## 多实例与命名空间

- `Store` 为 nil 时每个中间件持有私有 `MemoryStore`，同进程多实例互不影响。
- 共享 Redis 时，`RedisStoreOptions.Prefix` 前缀化存储键，默认 `yd:rl:`；不同应用必须使用
  不同前缀或不同 Redis DB。
- 同一个 Store 上挂多条限流规则时，必须给每条规则不同的 `RateLimitOptions.KeyPrefix`；
  否则不同规则的桶会互相覆盖。
- 多机要共享同一限额，所有节点必须使用相同的 Store Prefix + 规则 KeyPrefix；要隔离环境则
  相反。前缀不是安全边界。

## 应用场景

- **API 配额**：按 API Key、用户或 IP 限流。
- **登录/验证码**：限制尝试频率。
- **防刷/防爬**：按指纹组合限流。
- **多机一致**：RedisStore 在所有实例间共享桶。
- **稀缺资源保护**：`FailClosed` 在存储故障时拒绝而不是超卖。

## 性能指标

基准模块：[`benchmarks/middleware`](../../benchmarks/middleware/README.md)。参考环境为
AMD Ryzen AI MAX+ 395、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms` 中位数。

| 场景 | 耗时 | 能力 |
|---|---:|---|
| ydx 放行（默认按 IP + 3 头） | 136.5 ns | 分布式 Store、标准头、按 IP 分桶 |
| `x/time/rate` 全局、不写头 | 59.92 ns | 单进程、固定头 |
| `x/time/rate` + 三个头 | 127.8 ns | 固定头值 |
| `x/time/rate` + 按 IP + 头 | 139.0 ns | 与 ydx 能力对齐 |
| YD 路由 RateLimit（含路由/Ctx） | 539.8 ns | 1.120 KiB、12 allocs |

- 与同能力变体（按 IP + 写头）相比，ydx 领先约 1.8%，在噪声内记为持平。
- ydx 每请求实时计算剩余令牌与重置时间，并保留可替换的 `LimitStore` 抽象；
  `x/time/rate` 的 59.92 ns 是单进程、不写头的更窄能力。
- RedisStore 的每次判定是一次 Redis Lua 往返，成本由网络 RTT 决定。

> 完整表格与口径见基准 README。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`redis/go-redis/v9`](https://github.com/redis/go-redis) | v9.23.0 | BSD-2-Clause | RedisStore 多机限流 |

测试使用 [`alicebob/miniredis/v2`](https://github.com/alicebob/miniredis)（MIT）。

基准对比对象：`golang.org/x/time/rate`，仅出现在 `benchmarks/middleware`。

仓库内依赖：`errs`、`log`、`router`。

## 相关模块

- [`middleware`](../README.md)：聚合门面。
- [`redis`](../../redis/README.md)：Redis 客户端装配。
- [`captcha`](../../captcha/README.md)：使用本模块的限流存储接口。
- [`middleware/requestid`](../requestid/README.md)：请求 ID。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../../LICENSE)。
