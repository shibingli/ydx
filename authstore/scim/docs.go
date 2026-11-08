// Package scim implements the SCIM 2.0 store port of
// github.com/shibingli/ydx/auth/directory/scim on Redis. | Package scim 在 Redis 上实现
// github.com/shibingli/ydx/auth/directory/scim 的 SCIM 2.0 存储端口。
//
// The Store type implements scim.Store and scim.UserVersionReplacer. It persists Users and Groups
// for any number of application instances that share one Redis deployment. Uniqueness checks,
// index maintenance and record writes run as Lua scripts, so Redis's single-threaded script
// execution provides the atomicity the in-memory store obtains from a mutex. Every read
// deserializes a fresh value, so callers never share slices, maps or pointers with the backend or
// with another instance. | Store 类型实现 scim.Store 与 scim.UserVersionReplacer。它为任意多个共享同一
// Redis 部署的应用实例持久化 User 与 Group。唯一性检查、索引维护与记录写入都以 Lua 脚本执行，因此
// 内存存储用互斥锁获得的原子性由 Redis 的脚本单线程执行提供。每次读取都反序列化新值，调用方不会与
// 后端或其它实例共享切片、映射或指针。
//
// # Multi-instance semantics | 多实例语义
//
// A User has a unique case-insensitive userName, and a Group has a unique case-insensitive
// displayName, exactly like scim.MemoryStore. externalId and a User displayName are secondary,
// non-unique indexes: lookups return the oldest match and ListUsers with a filter returns every
// match. Creation order is preserved with a sorted set, replacement keeps the position, and delete
// followed by create appends a new position. Versions are weak entity tags derived from the
// resource type, identifier and a Redis-global revision counter, so every mutation produces a new
// tag on every instance. ReplaceUserIfVersion compares and writes atomically, which is what the
// SCIM server's password compensation and atomic bulk rollback rely on. | User 拥有大小写不敏感的
// 唯一 userName，Group 拥有大小写不敏感的唯一 displayName，与 scim.MemoryStore 完全一致。externalId
// 与 User 的 displayName 是次要的非唯一索引：单条查询返回最早匹配，带过滤器的 ListUsers 返回全部匹配。
// 创建顺序用有序集合保留，替换保持位置，删除后重建则追加新位置。版本是由资源类型、标识与 Redis 全局
// 修订计数器派生的弱实体标签，因此每次变更在任何实例上都会产生新标签。ReplaceUserIfVersion 原子地
// 比较并写入，这正是 SCIM 服务端口令补偿与批量原子回滚所依赖的语义。
//
// # Bulk atomic undo | 批量原子撤销
//
// The SCIM server implements transactional bulk requests with a request-scoped undo log; this
// store provides the semantics that log depends on: CreateUser and CreateGroup preserve a
// caller-supplied identifier so a deleted resource can be recreated with its original ID,
// ReplaceUser and ReplaceGroup restore a prior snapshot, DeleteUser and DeleteGroup report
// scim.ErrNotFound when a resource is already gone, and every record exposes a stable entity tag
// so a concurrent change is reported as scim.ErrBulkRollbackConflict instead of being
// overwritten. Each individual compensation step is atomic across instances. The whole bulk
// request is not a single Redis transaction: a request-scoped undo log cannot isolate other
// instances that write between operations, which the entity-tag checks detect. | SCIM 服务端用请求
// 内的撤销日志实现事务性批量请求；本存储提供该日志依赖的语义：CreateUser 与 CreateGroup 保留调用方
// 提供的标识，使已删除资源可用原标识重建；ReplaceUser 与 ReplaceGroup 恢复先前快照；资源已不存在时
// DeleteUser 与 DeleteGroup 返回 scim.ErrNotFound；每条记录都暴露稳定的实体标签，使并发修改变成
// scim.ErrBulkRollbackConflict 而不是被覆盖。每个补偿步骤在跨实例范围内原子。整个批量请求不是单个
// Redis 事务：请求内撤销日志无法隔离在操作之间写入的其它实例，实体标签检查会发现这类并发变更。
//
// # Redis key layout | Redis 键布局
//
// Every key starts with the configurable prefix and then a cluster hash tag, so all keys touched by
// one script share one Redis Cluster slot. The prefix must not contain '{' or '}'. With the default
// prefix "ydx:authstore:scim:" the layout is: | 每个键以可配置前缀开头，随后是集群哈希标签，因此单个
// 脚本访问的所有键共享同一 Redis Cluster 槽位。前缀不得包含 '{' 或 '}'。默认前缀
// "ydx:authstore:scim:" 下的布局为：
//
//	ydx:authstore:scim:{authstore:scim}:users:order          zset: user ID scored by creation seq
//	ydx:authstore:scim:{authstore:scim}:users:seq            user creation sequence | 用户创建序号
//	ydx:authstore:scim:{authstore:scim}:user:<len>:<id>      hash: data/version/versionTag/...
//	ydx:authstore:scim:{authstore:scim}:uidx:name:<len>:<name>      unique userName index
//	ydx:authstore:scim:{authstore:scim}:uidx:external:<len>:<id>    zset: externalId -> user IDs
//	ydx:authstore:scim:{authstore:scim}:uidx:display:<len>:<name>   zset: displayName -> user IDs
//
//	ydx:authstore:scim:{authstore:scim}:groups:order         zset: group ID scored by creation seq
//	ydx:authstore:scim:{authstore:scim}:groups:seq           group creation sequence | 组创建序号
//	ydx:authstore:scim:{authstore:scim}:group:<len>:<id>     hash: data/version/versionTag/...
//	ydx:authstore:scim:{authstore:scim}:gidx:display:<len>:<name>   unique displayName index
//	ydx:authstore:scim:{authstore:scim}:gidx:external:<len>:<id>    zset: externalId -> group IDs
//
//	ydx:authstore:scim:{authstore:scim}:revision            global entity tag revision
//
// Length-prefixed segments ("<len>:<value>") make identifiers, user names and external IDs that
// contain ':' or any other byte unambiguous. | 长度前缀段（"<len>:<value>"）使包含 ':' 或任意其它字节
// 的标识、用户名与外部标识无歧义。
//
// # Usage | 用法
//
// The caller owns the go-redis client and must close it.
// | 调用方拥有 go-redis 客户端并负责关闭。
//
//	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
//	store, err := authstorescim.New(client, authstorescim.Options{})
//	if err != nil {
//		return err
//	}
//	srv, err := scim.New(scim.Options{Store: store})
//	if err != nil {
//		return err
//	}
//
//	// Plain net/http | 原生 net/http
//	http.Handle("/scim/v2/", http.StripPrefix("/scim/v2", srv.HTTPHandler("")))
//
//	// YD router | YD 路由
//	engine := router.New()
//	srv.Register(engine, "/scim/v2")
package scim
