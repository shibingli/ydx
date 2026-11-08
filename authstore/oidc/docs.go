// Package oidc implements the auth/protocol/oidc logout replay store on Redis.
// | Package oidc 在 Redis 上实现 auth/protocol/oidc 的登出重放存储。
//
// Store implements oidc.LogoutReplayStore. Assign it to ProviderConfig.LogoutReplay so every
// provider instance sharing the Redis deployment rejects the same replayed logout-token jti, even
// when the instances run in different processes or on different hosts. The in-memory
// MemoryLogoutReplayStore is suitable only for a single process. | Store 实现
// oidc.LogoutReplayStore。把它赋给 ProviderConfig.LogoutReplay 后，共享该 Redis 部署的所有提供方
// 实例都会拒绝相同的重放登出令牌 jti，即使实例运行在不同进程或不同主机。内存
// MemoryLogoutReplayStore 仅适用于单进程。
//
// # Multi-instance semantics | 多实例语义
//
// Accept performs the read, deadline comparison and write in one Lua script. Redis executes scripts
// atomically, so among concurrent Accept calls for one jti exactly one returns true and every other
// call returns false. The record is stored as an absolute millisecond deadline and the Redis key also
// receives a matching PEXPIREAT, so a key cannot outlive its deadline even if an operator removes the
// TTL. A zero or already elapsed expiresAt is replaced by five minutes from the current time,
// matching the in-memory store; if that deadline has already elapsed at the Redis clock, the script
// substitutes five minutes from the Redis clock instead, so application clock skew cannot create an
// immediately vanished replay record. Accept returns only a boolean, so no caller-owned map, slice or
// pointer can alias stored state. All non-zero times are normalized to UTC. | Accept 在单个 Lua
// 脚本内完成读取、期限比较与写入。Redis 原子执行脚本，因此同一 jti 的并发 Accept 调用中恰好一个
// 返回 true，其余全部返回 false。记录保存为绝对毫秒期限，同时 Redis 键也设置匹配的
// PEXPIREAT，因此即使运维移除 TTL，键也不会超过期限。零值或已经过去的 expiresAt 会被替换为
// 当前时间起五分钟，与内存存储一致；若该期限在 Redis 时钟下也已经过去，脚本会改用 Redis 时钟加
// 五分钟，因此应用时钟偏差不会产生立即消失的重放记录。Accept 只返回布尔值，调用方拥有的映射、
// 切片或指针不可能与存储状态共享。所有非零时间统一规范化为 UTC。
//
// Backend failures are reported as ErrStoreUnavailable with a fixed bilingual detail; the underlying
// go-redis error text is deliberately not attached because it can contain addresses or credentials.
// Context cancellation and deadline errors are returned unchanged. An empty jti or a nil Store
// reports oidc.ErrInvalidToken. | 后端故障以 ErrStoreUnavailable 加固定中英双语细节返回；底层
// go-redis 错误文本会被有意丢弃，因为它可能包含地址或凭据。上下文取消与超时错误原样返回。空 jti
// 或 nil Store 返回 oidc.ErrInvalidToken。
//
// # Redis key layout | Redis 键布局
//
// The key carries a hash tag so a cluster deployment routes it deterministically. The configurable
// prefix comes first and must not contain '{' or '}'. With the default prefix
// "ydx:authstore:oidc:" the layout is: | 键携带哈希标签，使集群部署确定性地路由它。可配置前缀位于
// 最前，且不得包含 '{' 或 '}'。默认前缀 "ydx:authstore:oidc:" 下的布局为：
//
//	ydx:authstore:oidc:{authstore:oidc}:replay:<len>:<jti>
//	                                                       string: absolute deadline in Unix milliseconds
//
// The length-prefixed segment keeps arbitrary jti values, including values containing ':' or '{',
// unambiguous. | 长度前缀段保证任意 jti 值（包括含 ':' 或 '{' 的值）无歧义。
//
// # Usage | 用法
//
// The caller owns the go-redis client passed to New and must close it. | 传给 New 的 go-redis
// 客户端归调用方所有，调用方必须关闭它。
//
//	store, err := oidcstore.New(client, oidcstore.Options{}) // caller closes client
//	if err != nil { ... }
//	provider, err := oidc.NewProvider(oidc.ProviderConfig{
//		// ... required issuer, keys and endpoint configuration ...
//		LogoutReplay: store,
//	})
//	if err != nil { ... }
//
//	// YD router | YD 路由
//	provider.Register(r)
//
//	// Native net/http | 原生 net/http
//	mux.Handle("/oidc/", provider.HTTPHandler())
package oidc
