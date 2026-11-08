// Package federation implements the auth/protocol/federation state store on Redis.
// | Package federation 在 Redis 上实现 auth/protocol/federation 的 state 存储。
//
// Store implements federation.StateStore. Assign it to BrokerConfig.StateStore or
// Broker.StateStore so every broker instance sharing the Redis deployment saves and consumes the
// same short-lived authorization state. The default MemoryStateStore is suitable only for a single
// process. | Store 实现 federation.StateStore。把它赋给 BrokerConfig.StateStore 或
// Broker.StateStore，共享该 Redis 部署的所有代理实例即可保存与消费同一批短时授权 state。默认的
// MemoryStateStore 仅适用于单进程。
//
// # Multi-instance semantics | 多实例语义
//
// Save and Consume each run one Lua script. Redis executes a script atomically, so two application
// instances cannot both consume the same state: exactly one Consume call succeeds and every other
// caller receives federation.ErrStateMismatch. Save rejects a duplicate while the existing record is
// live, but may replace one whose logical deadline passed. The script reads the current time from
// Redis, not from the application host, so instances with different clocks agree on expiry and Save
// uses the same time source as Consume. The physical key receives an absolute PEXPIREAT at the
// logical deadline plus a five-minute classification window; Consume still enforces the logical
// deadline and reports federation.ErrStateExpired inside that window, which keeps the distinction
// between an expired record and a forged or unknown state available to callers. | Save 与 Consume
// 各运行一个 Lua 脚本。Redis 原子执行脚本，因此两个应用实例不可能同时消费同一 state：恰有一次
// Consume 成功，其余调用方收到 federation.ErrStateMismatch。只要既有记录仍然有效，Save 就拒绝
// 重复；但可以替换逻辑期限已过的记录。脚本从 Redis 而非应用主机读取当前时间，因此时钟不同的实例
// 对过期判断一致，Save 与 Consume 也使用同一时间源。物理键在逻辑期限加五分钟分类窗口处设置绝对
// PEXPIREAT；Consume 仍强制执行逻辑期限，并在该窗口内返回 federation.ErrStateExpired，从而保留
// 过期记录与伪造或未知 state 之间的区别。
//
// Every record is serialized with ydx/json at the store boundary and every returned record is a
// fresh deep copy. All non-zero times are normalized to UTC. | 每条记录都在存储边界用 ydx/json
// 序列化，每次返回的记录都是全新的深拷贝。所有非零时间统一规范化为 UTC。
//
// Backend failures are reported as ErrStoreUnavailable with a fixed bilingual detail; the underlying
// go-redis error text is deliberately not attached because it can contain addresses or credentials.
// Context cancellation and deadline errors are returned unchanged. | 后端故障以 ErrStoreUnavailable
// 加固定中英双语细节返回；底层 go-redis 错误文本会被有意丢弃，因为它可能包含地址或凭据。上下文
// 取消与超时错误原样返回。
//
// # Redis key layout | Redis 键布局
//
// The key carries a hash tag so a cluster deployment routes it deterministically. The configurable
// prefix comes first and must not contain '{' or '}'. With the default prefix
// "ydx:authstore:federation:" the layout is: | 键携带哈希标签，使集群部署确定性地路由它。可配置
// 前缀位于最前，且不得包含 '{' 或 '}'。默认前缀 "ydx:authstore:federation:" 下的布局为：
//
//	ydx:authstore:federation:{authstore:federation}:state:<len>:<state>
//	                                                       hash: data/expSec/expNsec
//
// The length-prefixed segment keeps arbitrary state values, including values containing ':' or '{',
// unambiguous. | 长度前缀段保证任意 state 值（包括含 ':' 或 '{' 的值）无歧义。
//
// # Usage | 用法
//
// The caller owns the go-redis client passed to New and must close it. | 传给 New 的 go-redis
// 客户端归调用方所有，调用方必须关闭它。
//
//	store, err := federationstore.New(client, federationstore.Options{}) // caller closes client
//	if err != nil { ... }
//	broker, err := federation.NewBroker(federation.BrokerConfig{
//		Service:    service,
//		StateStore: store,
//		Providers:  providers,
//	})
//	if err != nil { ... }
//
//	// YD router | YD 路由
//	broker.Register(r, "/auth")
//
//	// Native net/http | 原生 net/http
//	mux.Handle("/auth/", broker.HTTPHandler("/auth"))
package federation
