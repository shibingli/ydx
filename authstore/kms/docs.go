// Package kms implements the auth/keymgmt/kms persistence port on Redis.
// | Package kms 在 Redis 上实现 auth/keymgmt/kms 持久化端口。
//
// New accepts a go-redis universal client and returns a *Store that implements kms.Store. The
// store is safe for concurrent use by several goroutines and by several application instances that
// share one Redis deployment, so keys, versions, aliases and audit records stay consistent across
// a horizontally scaled KMS service. The caller owns the client passed to New and must close it.
// | New 接受 go-redis 通用客户端并返回实现 kms.Store 的 *Store。该存储可供多个 goroutine 与多个
// 共享同一 Redis 部署的应用实例并发使用，因此密钥、版本、别名与审计记录在横向扩展的 KMS 服务中
// 保持一致。传给 New 的客户端由调用方拥有并负责关闭。
//
// # Multi-instance semantics | 多实例语义
//
// Every write that maintains a uniqueness guarantee or an index runs as a Redis Lua script, so
// Redis's single-threaded script execution supplies the atomicity the in-memory store obtains from
// a mutex. CreateKey checks the identifier and the primary alias in one script; UpdateKey compares
// the stored revision and primary alias before replacing the record and its versions, so a stale
// caller receives kms.ErrConflict instead of overwriting newer data; SetAlias refuses an alias
// already bound to another key; SaveVersion checks and appends the version atomically; DeleteKey
// removes the record, every version and every alias bound to it in one script; AppendAudit
// allocates a sequence number, writes the event and updates the time index atomically.
// | 所有维护唯一性保证或索引的写入都以 Redis Lua 脚本执行，因此内存存储用互斥锁获得的原子性由
// Redis 的脚本单线程执行提供。CreateKey 在一个脚本内检查标识与主别名；UpdateKey 在替换记录及其
// 版本前比较已存修订号与主别名，因此过期的调用方会收到 kms.ErrConflict 而不会覆盖更新的数据；
// SetAlias 拒绝已绑定到其它密钥的别名；SaveVersion 原子检查并追加版本；DeleteKey 在一个脚本内
// 删除记录、全部版本与绑定到它的全部别名；AppendAudit 原子分配序号、写入事件并更新时间索引。
//
// Every value is serialized at the store boundary and every read returns a freshly allocated deep
// copy, so callers never share maps, slices or pointers with the store or with another instance.
// All non-zero times are normalized to UTC. Key material is carried inside the serialized record
// (encoded through ydx/json) and never appears in error text or logs; local material buffers are
// zeroed after use. | 所有值都在存储边界序列化，每次读取都返回全新分配的深拷贝，调用方不会与
// 存储或其它实例共享映射、切片或指针。所有非零时间统一规范化为 UTC。密钥材料保存在序列化记录
// 内部（经 ydx/json 编码），绝不出现于错误文案或日志；本地材料缓冲区在用完后清零。
//
// Backend failures are reported as kms.ErrStoreUnavailable with a fixed bilingual detail; the
// underlying go-redis error text is deliberately not attached because it can contain addresses or
// credentials. Context cancellation and deadline errors are returned unchanged. | 后端故障以
// kms.ErrStoreUnavailable 加固定中英双语细节返回；底层 go-redis 错误文本会被有意丢弃，因为它
// 可能包含地址或凭据。上下文取消与超时错误原样返回。
//
// # Redis key layout | Redis 键布局
//
// Every key carries the same hash tag, so a cluster deployment routes every key touched by one
// script to a single slot. The configurable prefix comes first and must not contain '{' or '}'.
// With the default prefix "ydx:authstore:kms:" the layout is: | 每个键携带相同的哈希标签，因此
// 集群部署把单个脚本访问的所有键路由到同一槽位。可配置前缀位于最前，且不得包含 '{' 或 '}'。
// 默认前缀 "ydx:authstore:kms:" 下的布局为：
//
//	<n>:{authstore:kms}:keys                        sorted set: key ID by creation time
//	<n>:{authstore:kms}:key:<len>:<id>              hash: data/revision/alias/createdAt
//	<n>:{authstore:kms}:versions:<len>:<id>         hash: version number -> version JSON
//	<n>:{authstore:kms}:aliases:<len>:<id>          set of aliases bound to the key | 密钥别名集合
//	<n>:{authstore:kms}:alias:<len>:<alias>         string: alias -> key ID | 别名到密钥标识
//	<n>:{authstore:kms}:audit:seq                   append sequence | 追加序号
//	<n>:{authstore:kms}:audit:events                hash: sequence -> event JSON
//	<n>:{authstore:kms}:audit:index                 sorted set: sequence scored by event time
//
// Length-prefixed segments keep arbitrary key identifiers and aliases unambiguous. The alias
// reverse set stores alias strings, so DeleteKey can remove every binding without rebuilding key
// names. | 长度前缀段保证任意密钥标识与别名无歧义。别名反向集合保存别名字符串，因此 DeleteKey
// 无需重建键名即可移除全部绑定。
//
// # Usage | 用法
//
// Native Go assembly with an existing go-redis client: | 使用已有 go-redis 客户端的原生 Go 装配：
//
//	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
//	store, err := kmsstore.New(client, kmsstore.Options{KeyPrefix: "myapp:kms:"})
//	if err != nil { ... }
//	defer client.Close() // the caller owns the client | 客户端由调用方拥有
//
//	service, err := authkms.New(authkms.Config{Store: store})
//	if err != nil { ... }
//
// The service constructed above is transport-independent and can be mounted through either entry
// point. | 上面构造的服务与传输无关，可通过任一种入口挂载。
//
//	// YD router | YD 路由
//	r.HandleRaw(http.MethodPost, "/kms/encrypt", func(w http.ResponseWriter, req *http.Request) {
//		ciphertext, err := service.Encrypt(req.Context(), "k1", nil, nil)
//		...
//	})
//
//	// Native net/http | 原生 net/http
//	mux := http.NewServeMux()
//	mux.HandleFunc("POST /kms/encrypt", func(w http.ResponseWriter, req *http.Request) {
//		ciphertext, err := service.Encrypt(req.Context(), "k1", nil, nil)
//		...
//	})
package kms
