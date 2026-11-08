// Package webauthn implements the auth/mfa/webauthn ChallengeStore and CredentialStore on Redis.
// | Package webauthn 在 Redis 上实现 auth/mfa/webauthn 的 ChallengeStore 与 CredentialStore。
//
// New returns one Store that can be assigned to both webauthn.Config.ChallengeStore and
// webauthn.Config.CredentialStore. It also implements webauthn.BackupStateUpdater, so a
// successful assertion persists the current BS flag. Every application instance that shares the
// same Redis deployment then sees the same in-flight ceremonies and registered credentials, so a
// registration begun on one instance can be finished on another. The go-redis universal client
// passed to New stays owned by the caller and must be closed by the caller. New performs no
// network round trip. | New 返回一个 Store，可同时赋给 webauthn.Config.ChallengeStore 与
// webauthn.Config.CredentialStore。它还实现 webauthn.BackupStateUpdater，因此成功断言会持久化当前
// BS 标志。共享同一 Redis 部署的所有应用实例随后看到相同的进行中流程与已注册凭据，因此在一个实例
// 开始的注册可以在另一个实例完成。传给 New 的 go-redis 通用客户端始终归调用方所有，调用方必须
// 关闭它。New 不进行网络往返。
//
// # Multi-instance semantics | 多实例语义
//
// Challenge consumption and credential creation are single Redis Lua scripts. Redis executes a
// script atomically, so two instances cannot consume the same challenge and cannot both create
// the same credential ID; a user index entry never exists without its credential record.
// Signature-counter and BS-flag updates are single atomic scripts that touch only the authoritative
// hash fields, so concurrent assertions cannot overwrite each other with a stale serialized
// snapshot. Every read returns a fresh deep copy and all times are normalized to UTC. | 挑战消费与
// 凭据创建都是单个 Redis Lua 脚本。Redis 原子执行脚本，因此两个实例不可能消费同一个挑战，也不可能
// 同时创建相同的凭据 ID；用户索引条目绝不会脱离凭据记录存在。签名计数器与 BS 标志更新是只修改权威
// 哈希字段的单个原子脚本，因此并发断言不会用过期序列化快照互相覆盖。每次读取返回全新深拷贝，所有
// 时间统一为 UTC。
//
// # Redis key layout | Redis 键布局
//
// Keys carry the shared hash tag so a cluster routes every key touched by one script to one slot.
// The configurable prefix comes first and must not contain '{' or '}'. Arbitrary values use a
// length-prefixed segment, so concatenation stays unambiguous. With the default prefix
// "ydx:authstore:webauthn:" the layout is: | 键携带共享哈希标签，使集群把单个脚本访问的所有键路由
// 到单一槽位。可配置前缀位于最前，且不得包含 '{' 或 '}'。任意值使用长度前缀段，因此拼接始终无
// 歧义。默认前缀 "ydx:authstore:webauthn:" 下的布局为：
//
//	ydx:authstore:webauthn:{authstore:webauthn}:challenge:<len>:<challenge>
//	                                                       string: ceremony JSON; the Redis expiry
//	                                                       outlives ExpiresAt by a retention window
//	                                                       | 字符串：流程 JSON；Redis 期限比
//	                                                       ExpiresAt 多保留一个窗口
//	ydx:authstore:webauthn:{authstore:webauthn}:credential:<len>:<base64url credential ID>
//	                                                       hash: data/signCount/backupState
//	                                                       | 哈希：data/signCount/backupState
//	ydx:authstore:webauthn:{authstore:webauthn}:idx:user:<len>:<userID>
//	                                                       set of credential hash keys
//	                                                       | 凭据哈希键集合
//
// # YD router | YD 路由
//
// Assign the store to the service configuration and mount the ceremony endpoints: |
// 把存储赋给服务配置并挂载流程端点：
//
//	stores, err := webauthnstore.New(client, webauthnstore.Options{})
//	if err != nil {
//		return err
//	}
//	service, err := webauthn.New(webauthn.Config{
//		RPDisplayName:   "Example",
//		RPID:            "example.com",
//		RPOrigins:       []string{"https://example.com"},
//		ChallengeStore:  stores,
//		CredentialStore: stores,
//	})
//	if err != nil {
//		return err
//	}
//	r.HandleRaw(http.MethodPost, "/webauthn/register/begin", func(w http.ResponseWriter, req *http.Request) {
//		options, ceremony, err := service.BeginRegistration(req.Context(), user, webauthn.RegistrationOptions{})
//		if err != nil {
//			http.Error(w, "registration rejected", http.StatusBadRequest)
//			return
//		}
//		writeJSON(w, map[string]any{"options": options, "ceremony": ceremony})
//	})
//
// # Native net/http | 原生 net/http
//
// The same store works without the YD router, because it depends only on context and native Go
// values: | 同一个存储无需 YD 路由即可工作，因为它只依赖上下文与原生 Go 值：
//
//	stores, err := webauthnstore.New(client, webauthnstore.Options{})
//	if err != nil {
//		return err
//	}
//	service, err := webauthn.New(webauthn.Config{
//		RPDisplayName:   "Example",
//		RPID:            "example.com",
//		RPOrigins:       []string{"https://example.com"},
//		ChallengeStore:  stores,
//		CredentialStore: stores,
//	})
//	if err != nil {
//		return err
//	}
//	mux := http.NewServeMux()
//	mux.HandleFunc("POST /webauthn/register/begin", func(w http.ResponseWriter, req *http.Request) {
//		options, ceremony, err := service.BeginRegistration(req.Context(), user, webauthn.RegistrationOptions{})
//		if err != nil {
//			http.Error(w, "registration rejected", http.StatusBadRequest)
//			return
//		}
//		writeJSON(w, map[string]any{"options": options, "ceremony": ceremony})
//	})
//
// Deployments with a single process may keep webauthn.NewMemoryChallengeStore and
// webauthn.NewMemoryCredentialStore; select this package only when several instances must share
// ceremonies and credentials. | 单进程部署可以继续使用 webauthn.NewMemoryChallengeStore 与
// webauthn.NewMemoryCredentialStore；仅在多个实例必须共享流程与凭据时选用本包。
package webauthn
