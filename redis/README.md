# redis — Redis 装配与读透缓存

`github.com/shibingli/ydx/redis` 是 YunDev 的 Redis 装配层。`Open` 把一个 `Options` 收敛为
支持单机、哨兵与集群模式的 go-redis 通用客户端；`Health` 提供探活；`Cache[T]` 是带单飞、
抖动 TTL 与可选负缓存的泛型读透装饰器。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/redis` |
| 包名 | `redis` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 部署模式 | `single`、`sentinel`、`cluster` |

## 功能

- `Open(Options)`：构造 `goredis.UniversalClient`，统一单机/哨兵/集群。
- `Health(ctx, cli)`：执行 liveness 探活。
- `Close(cli)`：关闭客户端。
- `NewCache[T](cli, CacheOptions)`：泛型读透缓存。
- `Cache.GetOrLoad(ctx, key, load)`：缓存命中直接返回，未命中调用 loader 并回填。
- `OptionsFromConfig`：读取 `redis.*` 配置段。
- `ErrNotFound`：缓存未命中的哨兵错误。

## 特性

- **部署形态透明**：调用方无需按单机/哨兵/集群分支。
- **无网络往返的 Open**：`Open` 只构造客户端，不做网络往返，因此可以在服务端就绪之前
  构造客户端。
- **单飞加载**：并发未命中同一 key 时只执行一次 loader，其余请求等待结果，避免击穿。
- **抖动 TTL**：在基础 TTL 上加入随机抖动，避免大量 key 同时过期。
- **可选负缓存**：短时间内缓存“未找到”，降低无效查询对后端的压力。
- **载荷经 ydx/json**：缓存值统一走 `github.com/shibingli/ydx/json`，与全仓序列化语义
  一致。
- **错误如实上报**：不静默降级、不封装分布式锁/发布订阅/重试；缓存错误由调用方决定。
- **配置驱动**：`OptionsFromConfig` 映射 `redis.*` 配置段。

## 快速开始

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/shibingli/ydx/redis"
)

type User struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

func main() {
	cli, err := redis.Open(redis.Options{
		Mode: redis.ModeSingle,
		Addr: "127.0.0.1:6379",
	})
	if err != nil {
		return
	}
	defer func() { _ = redis.Close(cli) }()

	ctx := context.Background()
	if err := redis.Health(ctx, cli); err != nil {
		return
	}

	cache := redis.NewCache[User](cli, redis.CacheOptions{
		TTL:    time.Minute,
		Prefix: "app:",
	})
	user, err := cache.GetOrLoad(ctx, "user:42", func(ctx context.Context) (User, error) {
		return User{ID: 42, Name: "Ada"}, nil
	})
	if err != nil {
		return
	}
	fmt.Println(user.Name)
}
```

配置驱动：

```go
cli, err := redis.Open(redis.OptionsFromConfig(cfg))
```

## 多实例与命名空间

- `Options.KeyPrefix` 是框架写入的所有键共享的命名空间；构造 `redis.Cache` 时传给
  `CacheOptions.Prefix`。装饰器实际写入的键是 `Prefix + key`。
- 同一个 Redis 上运行多个应用时，每个应用必须使用不同前缀或不同 Redis DB；否则缓存键会
  互相覆盖。
- 客户端由调用方所有，多个 `Cache`/实例可以共享同一个 `UniversalClient`；`Close` 由调用方
  统一负责。前缀不是安全边界。

## 应用场景

- **读多写少的 API**：用户资料、配置、权限等读透缓存。
- **会话与令牌**：共享登录态、刷新令牌、验证码状态。
- **分布式计数/限流**：作为 `middleware/ratelimit` 的 RedisStore 后端。
- **实时消息**：`realtime` 的 Redis 后端。
- **多机验证码状态**：`captcha/store/redisstore`。
- **任务队列**：`asynq` 使用 Redis 作为 broker。

## 性能指标

本模块没有独立基准；性能主要由网络 RTT 与 Redis 服务器决定：

- 每次 Redis 操作是一次网络往返（或 pipeline/批处理时的摊薄往返）。
- `Cache.GetOrLoad` 命中时只有一次 GET；未命中时执行 loader 并回填；并发未命中由单飞
  合并为一次 loader。
- 抖动 TTL 不增加操作次数，只在写入时计算过期时间。
- 负缓存把“不存在”也写入一次，减少重复穿透查询。
- 载荷序列化经 `ydx/json`；大对象应评估序列化成本与网络带宽。
- `Open` 不做网络往返；`Health` 才建立连接并探活。

> 需要吞吐数字时，应在目标 Redis 拓扑与网络下压测；本模块不隐藏或重试 Redis 错误。

## 第三方依赖与鸣谢

| 依赖 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| [`redis/go-redis/v9`](https://github.com/redis/go-redis) | v9.23.0 | BSD-2-Clause | Redis 客户端、单机/哨兵/集群 |
| [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync) | v0.24.0 | BSD-3-Clause | `singleflight` 并发加载合并 |
| [`spf13/afero`](https://github.com/spf13/afero) | v1.15.0 | Apache-2.0 | 配置来源文件系统（经 config） |

测试使用 [`alicebob/miniredis/v2`](https://github.com/alicebob/miniredis)（MIT）作为
内存 Redis。

仓库内依赖：`afs`、`config`、`errs`、`json`。

## 相关模块

- [`cache`](../cache/README.md)：L1 + Redis 二级缓存。
- [`realtime`](../realtime/README.md)：Redis 多机广播后端。
- [`middleware/ratelimit`](../middleware/ratelimit/README.md)：Redis 令牌桶存储。
- [`asynq`](../asynq/README.md)：Redis 任务队列。
- [`captcha`](../captcha/README.md)：Redis 多机验证码状态。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
