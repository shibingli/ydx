// Package redis is the YunDev Redis assembly layer. | Package redis 是 YunDev 的 Redis 装配层。
//
// Open turns one Options value into a go-redis universal client supporting single-node, sentinel
// and cluster modes, so callers never branch on the deployment shape; Health performs the liveness
// probe on top of it. Cache is a generic read-through decorator with single-flight, jittered TTL
// and optional negative caching; its payloads are serialized through github.com/shibingli/ydx/json.
// OptionsFromConfig reads the redis.* section of a github.com/shibingli/ydx/config instance. |
// Open 把一个 Options 收敛为支持单机、哨兵与集群模式的 go-redis 通用客户端，调用方无需按部署形态
// 分支；Health 在其上提供探活。Cache 是带单飞、抖动 TTL 与可选负缓存的泛型读透装饰器，载荷经
// github.com/shibingli/ydx/json 序列化。OptionsFromConfig 读取 github.com/shibingli/ydx/config
// 实例的 redis.* 配置段。
//
// The package intentionally does not design business key layouts, wrap distributed locks or
// pub/sub, retry, or degrade silently: cache errors are reported as-is. Open performs no network
// round trip, so a client can be constructed before the server is reachable. |
// 本包刻意不替业务设计键布局、不封装分布式锁与发布订阅、不做重试与静默降级：缓存错误一律如实上报。
// Open 不做任何网络往返，因此可以在服务端就绪之前构造客户端。
//
// Native Go usage | 原生 Go 用法：
//
//	cli, err := redis.Open(redis.Options{Mode: redis.ModeSingle, Addr: "127.0.0.1:6379"})
//	if err != nil { return err }
//	defer func() { _ = cli.Close() }()
//	if err := redis.Health(ctx, cli); err != nil { return err }
//	cache := redis.NewCache[User](cli, redis.CacheOptions{TTL: time.Minute, Prefix: "app:"})
//	user, err := cache.GetOrLoad(ctx, "user:42", loadUser)
//
// YD routing and HTTP are not involved; this module is infrastructure-only. |
// 本模块与 YD 路由、HTTP 无关，属于纯基础设施组件。
package redis
