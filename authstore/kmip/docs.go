// Package kmip implements the auth/keymgmt/kmip Store persistence port on Redis.
// | Package kmip 在 Redis 上实现 auth/keymgmt/kmip 的 Store 持久化端口。
//
// New accepts a go-redis universal client and returns a *Store that satisfies kmip.Store, so it
// can be assigned directly to kmip.ServerConfig.Store. The store is safe for concurrent use by
// several goroutines and by several application instances that share one Redis deployment; it
// replaces the package MemoryStore when KMIP objects must outlive one process or be visible to
// every node of a KMIP cluster. The client passed to New belongs to the caller and is never closed
// by the store. New performs no network round trip, so a caller that needs a liveness check should
// probe the client itself. | New 接受 go-redis 通用客户端并返回满足 kmip.Store 的 *Store，可直接
// 赋给 kmip.ServerConfig.Store。该存储可供多个 goroutine 以及共享同一 Redis 部署的多个应用实例
// 并发使用；当 KMIP 对象必须跨进程存活或被 KMIP 集群的每个节点看到时，它替代包内 MemoryStore。
// 传给 New 的客户端归调用方所有，存储从不关闭它。New 不进行网络往返，因此需要探活的调用方应自行
// 探测客户端。
//
// # Multi-instance semantics | 多实例语义
//
// Every mutation is a Redis Lua script. Redis executes a script atomically, so two instances cannot
// both create the same unique identifier: Create succeeds for exactly one caller and every other
// caller receives kmip.ErrObjectExists. Update uses a per-record revision as a compare-and-set
// guard; a concurrent writer forces a bounded retry instead of writing over a state the caller has
// never observed, and a record deleted in the meantime yields kmip.ErrItemNotFound. Delete removes
// the record and its index membership in one script. | 所有变更都是 Redis Lua 脚本。Redis 原子
// 执行脚本，因此两个实例不可能同时创建同一唯一标识符：恰有一个 Create 调用成功，其余调用方收到
// kmip.ErrObjectExists。Update 使用每条记录的修订号作为比较并交换守卫；并发写入会触发有界重试，
// 而不会覆盖调用方从未观测到的状态；期间被删除的记录返回 kmip.ErrItemNotFound。Delete 在同一
// 脚本中删除记录及其索引成员关系。
//
// Records survive the process that wrote them and the exact lifecycle state round-trips. A
// destroyed object is stored as a tombstone: Object is nil, State is Destroyed or
// Destroyed Compromised, DestroyDate is set, and the object is removed only by Delete. Every Get
// and List decodes fresh slices, attribute trees and key material, so callers never share mutable
// state with the store or with another instance. These properties give Batch Undo the snapshot it
// needs: Get returns an independent copy of the pre-mutation record, and replaying Update, Create
// or Delete against that copy restores material, attributes, dates and tombstone state exactly.
// All non-zero times are normalized to UTC. | 记录在其写入进程结束后仍然存在，且生命周期状态
// 精确保留。被销毁的对象以墓碑形式保存：Object 为 nil、State 为 Destroyed 或 Destroyed
// Compromised、DestroyDate 已设置，对象仅由 Delete 移除。每次 Get 与 List 都解码出全新的切片、
// 属性树与密钥材料，调用方绝不与存储或其它实例共享可变状态。这些性质为 Batch Undo 提供了所需
// 快照：Get 返回变更前记录的独立副本，对副本重放 Update、Create 或 Delete 可精确恢复材料、属性、
// 日期与墓碑状态。所有非零时间统一规范化为 UTC。
//
// # Redis key layout | Redis 键布局
//
// Every key carries the same hash tag, so a cluster deployment routes every key touched by one
// script to a single slot. The configurable prefix comes first and must not contain '{' or '}'.
// With the default prefix "ydx:authstore:kmip:" the layout is: | 每个键携带相同的哈希标签，因此
// 集群部署把单个脚本访问的所有键路由到同一槽位。可配置前缀位于最前，且不得包含 '{' 或 '}'。默认
// 前缀 "ydx:authstore:kmip:" 下的布局为：
//
//	ydx:authstore:kmip:{authstore:kmip}:all                  set of full object keys | 全部对象键集合
//	ydx:authstore:kmip:{authstore:kmip}:object:<len>:<uid>   hash: data (record JSON), rev (CAS revision token)
//
// The unique identifier is length-prefixed so the object key is unambiguous for every identifier.
// Compact key names and value contents. Key material is never placed in a key name, and error
// texts never include record data. | 唯一标识符带长度前缀，因此对象键对任意标识符都无歧义。键名
// 保持紧凑，值保存记录内容。密钥材料绝不放入键名，错误文案也绝不包含记录数据。
//
// # Errors | 错误
//
// Domain failures use the kmip sentinels: kmip.ErrInvalidRequest for a nil client, a prefix with
// braces, or an empty unique identifier; kmip.ErrItemNotFound for a missing object;
// kmip.ErrObjectExists for a duplicate identifier. Backend failures and corrupt stored records use
// ErrStoreUnavailable with a fixed bilingual detail; the underlying go-redis error text is
// deliberately not attached because it can contain addresses or credentials. ErrConflict reports
// that Update exhausted its compare-and-set retries. Context cancellation and deadline errors are
// returned unchanged. | 领域失败使用 kmip 哨兵：nil 客户端、含花括号的前缀或空唯一标识符返回
// kmip.ErrInvalidRequest；对象不存在返回 kmip.ErrItemNotFound；标识符重复返回
// kmip.ErrObjectExists。后端故障与损坏的已存记录使用 ErrStoreUnavailable 加固定中英双语细节；
// 底层 go-redis 错误文本会被有意丢弃，因为它可能包含地址或凭据。ErrConflict 表示 Update 用尽
// 比较并交换重试次数。上下文取消与超时错误原样返回。
//
// # Usage | 用法
//
// The store is passed to a KMIP server instead of MemoryStore. The same assembly works for both
// deployment styles the server supports: ListenAndServe owns the listener, while ServeListener
// accepts an existing net.Listener. | 该存储传给 KMIP 服务器以替代 MemoryStore。下面的装配适用于
// 服务器支持的两种部署方式：ListenAndServe 自行创建监听器，ServeListener 接受既有 net.Listener。
//
//	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
//	defer client.Close() // the caller owns the client | 调用方拥有客户端
//
//	store, err := kmipstore.New(client, kmipstore.Options{KeyPrefix: "myapp:kmip:"})
//	if err != nil { ... }
//	server, err := kmip.NewServer(kmip.ServerConfig{
//		Store:   store,
//		Address: ":5696",
//	})
//	if err != nil { ... }
//	defer server.Close()
//	if err := server.ListenAndServe(); err != nil { ... }
//
// KMIP is a full-duplex TCP protocol, not an HTTP protocol, so this package is not mounted on a
// ydx/router route or a net/http handler. Applications that also expose HTTP health or admin
// endpoints mount those separately with router.HandleRaw or http.ServeMux; the KMIP store is
// independent of those entry points. | KMIP 是全双工 TCP 协议而非 HTTP 协议，因此本包不挂载到
// ydx/router 路由或 net/http 处理器。同时提供 HTTP 健康或管理端点的应用可用 router.HandleRaw
// 或 http.ServeMux 单独挂载这些端点；KMIP 存储与这些入口相互独立。
//
// # Operational reset | 运维重置
//
// Store.Reset removes every record below the configured prefix. It is an extension used by tests
// and operational tooling, not part of kmip.Store. Writers should be quiesced first, because a
// write that completes after Reset may survive it. | Store.Reset 删除配置前缀下的全部记录。它是
// 测试与运维工具使用的扩展，不属于 kmip.Store。调用前应停止写入，因为 Reset 之后完成的写入可能
// 继续存在。
package kmip
