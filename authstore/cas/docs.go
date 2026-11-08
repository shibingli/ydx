// Package cas implements the auth/protocol/cas storage ports on Redis.
// | Package cas 在 Redis 上实现 auth/protocol/cas 的存储端口。
//
// New accepts a go-redis universal client and returns a Stores value whose Tickets field implements
// cas.TicketStore and whose Sessions field implements cas.ServiceSessionRegistry. Both stores are
// safe for concurrent use by several goroutines and by several application instances that share one
// Redis deployment. Pass the two fields to cas.ServerConfig so a multi-node CAS server keeps tickets
// and Single Logout sessions in shared state instead of process memory. | New 接受 go-redis 通用
// 客户端并返回 Stores，其 Tickets 字段实现 cas.TicketStore，Sessions 字段实现
// cas.ServiceSessionRegistry。两个存储都可供多个 goroutine 与多个共享同一 Redis 部署的应用实例并发
// 使用。把这两个字段传给 cas.ServerConfig，多节点 CAS 服务端即可把票据与单点登出会话保存在共享状态
// 而不是进程内存中。
//
// The caller owns a client passed to New and must close it. | 传给 New 的客户端由调用方拥有并负责关闭。
//
// # Multi-instance semantics | 多实例语义
//
// Every write that maintains an index or a single-use guarantee is a Redis Lua script. Redis
// executes a script atomically, so two application instances cannot both consume the same ST or PT:
// exactly one Consume call succeeds and every other caller receives cas.ErrTicketUsed. Save and
// Register reconcile the previous service, ticket-family and user indexes with the new record inside
// the same script, using the previous record as a compare-and-set guard, so an interleaved writer
// forces a retry instead of leaving a stale index; exhausting the bounded retry budget reports
// ErrConflict. Deletions are idempotent, and every read returns a fresh deep copy, so callers never
// share maps, slices or pointers with the store or with another instance. All non-zero times are
// normalized to UTC. | 所有维护索引或单次使用保证的写入都是 Redis Lua 脚本。Redis 原子执行脚本，
// 因此两个应用实例不可能同时消费同一 ST 或 PT：恰有一次 Consume 成功，其余调用方收到
// cas.ErrTicketUsed。Save 与 Register 在同一脚本内以旧记录作比较并交换守卫，协调旧的服务、
// 票据族与用户索引和新记录，交错写入会触发重试而不是留下陈旧索引；重试预算耗尽时返回
// ErrConflict。删除是幂等的，每次读取都返回全新的深拷贝，调用方不会与存储或其它实例共享映射、
// 切片或指针。所有非零时间统一规范化为 UTC。
//
// Backend failures are reported as ErrStoreUnavailable with a fixed bilingual detail; the
// underlying go-redis error text is deliberately not attached because it can contain addresses or
// credentials. Context cancellation and deadline errors are returned unchanged. | 后端故障以
// ErrStoreUnavailable 加固定中英双语细节返回；底层 go-redis 错误文本会被有意丢弃，因为它可能包含
// 地址或凭据。上下文取消与超时错误原样返回。
//
// # Redis key layout | Redis 键布局
//
// Every key carries the same hash tag, so a cluster deployment routes every key touched by one script
// to a single slot. The configurable prefix comes first and must not contain '{' or '}'. With the
// default prefix "ydx:authstore:cas:" and <n> standing for that prefix without its trailing colon,
// the layout is: | 每个键携带相同的哈希标签，因此集群部署把单个脚本访问的所有键路由到同一槽位。
// 可配置前缀位于最前，且不得包含 '{' 或 '}'。默认前缀 "ydx:authstore:cas:" 下（<n> 表示去掉末尾
// 冒号的前缀），布局为：
//
//	<n>:{authstore:cas}:ticket:<len>:<id>              hash: ticket JSON and index fields
//	<n>:{authstore:cas}:tickets                        set of ticket keys | 票据键集合
//	<n>:{authstore:cas}:tickets:type:<TGT|ST|PGT|PT>   set of ticket keys by type | 按类型的票据键集合
//	<n>:{authstore:cas}:tickets:idx:service:<len>:<s>  set of ticket keys by service | 按服务的票据键集合
//	<n>:{authstore:cas}:tickets:idx:root:<len>:<tgt>   set of ticket keys by root TGT | 按根 TGT 的票据键集合
//	<n>:{authstore:cas}:tickets:idx:user:<len>:<u>     set of ticket keys by user | 按用户的票据键集合
//	<n>:{authstore:cas}:tickets:expiry                 sorted set keyed by deadline | 按期限评分的票据有序集合
//
//	<n>:{authstore:cas}:session:<len>:<index>          hash: session JSON and index fields
//	<n>:{authstore:cas}:sessions                       set of session keys | 会话键集合
//	<n>:{authstore:cas}:sessions:idx:tgt:<len>:<tgt>   set of session keys by TGT | 按 TGT 的会话键集合
//	<n>:{authstore:cas}:sessions:idx:user:<len>:<u>    set of session keys by user | 按用户的会话键集合
//	<n>:{authstore:cas}:sessions:expiry                sorted set keyed by deadline | 按期限评分的会话有序集合
//
// Length-prefixed segments keep arbitrary ticket identifiers, service URLs, user identifiers and
// session indexes unambiguous. Index sets store full keys, so a delete script can remove every
// membership without rebuilding key names. | 长度前缀段保证任意票据标识、服务 URL、用户标识与会话
// 索引无歧义。索引集合保存完整键，因此删除脚本无需重建键名即可移除全部成员关系。
//
// # Usage | 用法
//
// The following assembly works for both entry points; only the mounting differs. | 下面的装配对两种
// 入口都适用，只有挂载方式不同。
//
//	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
//	stores, err := casstore.New(client, casstore.Options{}) // caller closes client
//	if err != nil { ... }
//	server, err := cas.NewServer(cas.ServerConfig{
//		Issuer:          "https://cas.example.com",
//		Authenticator:   cas.NewServiceAuthenticator(svc),
//		ServiceRegistry: cas.NewStaticServiceRegistry("https://app.example.com/*"),
//		TicketStore:     stores.Tickets,
//		SessionRegistry: stores.Sessions,
//	})
//	if err != nil { ... }
//
//	// YD router | YD 路由
//	server.Register(router, "/cas")
//
//	// Native net/http | 原生 net/http
//	mux := http.NewServeMux()
//	mux.Handle("/cas/", server.HTTPHandler())
//
// Stores also exposes Stats, ListTickets and ListSessions for operational inspection. These methods
// page through the same indexes the interfaces maintain; they are extensions, not part of the CAS
// storage contracts, and the CAS server itself never calls them. | Stores 还提供 Stats、ListTickets
// 与 ListSessions 供运维检查。这些方法分页遍历接口维护的同一批索引；它们是扩展而不是 CAS 存储
// 契约的一部分，CAS 服务端本身不会调用它们。
package cas
