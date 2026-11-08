// Package oauth2 implements the auth/protocol/oauth2 persistence ports on Redis.
// | Package oauth2 在 Redis 上实现 auth/protocol/oauth2 的持久化端口。
//
// New returns one Stores value whose Store, Clients, DPoPNonces, DPoPReplay and Scopes fields can
// be handed to an OAuth authorization server. Every field is safe for concurrent use by several
// goroutines and by several application instances that share one Redis deployment. The go-redis
// universal client passed to New stays owned by the caller and must be closed by the caller. New
// performs no network round trip; the scope snapshot is loaded on the first registry read or by an
// explicit Reload. | New 返回一个 Stores，其 Store、Clients、DPoPNonces、DPoPReplay 与 Scopes 字段
// 可直接交给 OAuth 授权服务器。每个字段都可供多个 goroutine 与多个共享同一 Redis 部署的应用实例
// 并发使用。传给 New 的 go-redis 通用客户端始终归调用方所有，调用方必须关闭它。New 不进行网络
// 往返；作用域快照在第一次读取注册表时或显式调用 Reload 时加载。
//
// # Multi-instance semantics | 多实例语义
//
// Every state transition that must be atomic is one Redis Lua script: single-use authorization
// codes and pushed authorization requests, refresh-token rotation and family revocation, RFC 8628
// device polling, DPoP nonce issuance and replay detection, and client uniqueness. Redis executes
// a script atomically, so two instances cannot consume the same code, rotate the same refresh
// token twice, exchange the same approved device grant twice, or accept the same DPoP proof
// identifier twice. All values are serialized at the store boundary, every read returns a fresh
// deep copy, and all times are normalized to UTC. | 所有必须原子完成的状态转换都是单个 Redis Lua
// 脚本：一次性授权码与推送授权请求、刷新令牌轮换与家族撤销、RFC 8628 设备轮询、DPoP nonce 签发
// 与重放检测，以及客户端唯一性。Redis 原子执行脚本，因此两个实例不可能消费同一个授权码、两次
// 轮换同一个刷新令牌、两次兑换同一个已批准设备许可，或两次接受同一个 DPoP 证明标识。所有值都在
// 存储边界序列化，每次读取返回全新深拷贝，所有时间统一为 UTC。
//
// # Redis key layout | Redis 键布局
//
// Keys are grouped by a hash tag so that a cluster routes every key touched by one script to the
// same slot. The configurable prefix comes first and must not contain '{' or '}'. Arbitrary
// values use a length-prefixed segment, so concatenation stays unambiguous. With the default
// prefix "ydx:authstore:oauth2:" the layout is: | 键按哈希标签分组，使集群把单个脚本访问的所有键
// 路由到同一槽位。可配置前缀位于最前，且不得包含 '{' 或 '}'。任意值使用长度前缀段，因此拼接
// 始终无歧义。默认前缀 "ydx:authstore:oauth2:" 下的布局为：
//
//	ydx:authstore:oauth2:{authstore:oauth2:codes}:all       set of authorization-code keys
//	ydx:authstore:oauth2:{authstore:oauth2:codes}:code:<len>:<hash>
//	                                                           hash: data/used/expiry fields
//
//	ydx:authstore:oauth2:{authstore:oauth2:refresh}:all      set of refresh-token keys
//	ydx:authstore:oauth2:{authstore:oauth2:refresh}:token:<len>:<hash>
//	                                                           hash: data/used/revoked/family/subject
//	ydx:authstore:oauth2:{authstore:oauth2:refresh}:family:<len>:<familyID>
//	                                                           set of token keys | 令牌键集合
//	ydx:authstore:oauth2:{authstore:oauth2:refresh}:subject:<len>:<clientID>:<len>:<subject>
//	                                                           set of token keys | 令牌键集合
//
//	ydx:authstore:oauth2:{authstore:oauth2:access}:all       set of access-token keys
//	ydx:authstore:oauth2:{authstore:oauth2:access}:token:<len>:<hash>
//	                                                           hash: data/revoked/expiry fields
//
//	ydx:authstore:oauth2:{authstore:oauth2:devices}:all      set of device-code keys
//	ydx:authstore:oauth2:{authstore:oauth2:devices}:code:<len>:<hash>
//	                                                           hash: data/state/expiry/principal fields
//	ydx:authstore:oauth2:{authstore:oauth2:devices}:user:<len>:<userCode>
//	                                                           string: device-code key | 设备码键
//
//	ydx:authstore:oauth2:{authstore:oauth2:par}:all          set of pushed-request keys
//	ydx:authstore:oauth2:{authstore:oauth2:par}:request:<len>:<requestURI>
//	                                                           hash: data/used/expiry fields
//
//	ydx:authstore:oauth2:{authstore:oauth2:clients}:all      set of client IDs | 客户端 ID 集合
//	ydx:authstore:oauth2:{authstore:oauth2:clients}:client:<len>:<id>
//	                                                           hash: data
//
//	ydx:authstore:oauth2:{authstore:oauth2:nonces}:expiry    hash: nonce -> exact expiry
//	ydx:authstore:oauth2:{authstore:oauth2:nonces}:index     sorted set scored by expiry second
//	ydx:authstore:oauth2:{authstore:oauth2:replay}:jti:<len>:<jti>
//	                                                           string: exact proof expiry
//
//	ydx:authstore:oauth2:{authstore:oauth2:scopes}:defs      hash: scope name -> definition JSON
//	ydx:authstore:oauth2:{authstore:oauth2:scopes}:order     list preserving registration order
//
// # YD router | YD 路由
//
// The stores are infrastructure rather than a route, so a YD handler reads a bearer token from
// the request and asks the shared store to classify it: | 存储属于基础设施而非路由，因此 YD 处理器
// 从请求读取承载令牌并让共享存储对其分类：
//
//	stores, err := oauth2.New(client, oauth2.Options{})
//	if err != nil {
//		return err
//	}
//	r.HandleRaw(http.MethodGet, "/userinfo", func(w http.ResponseWriter, req *http.Request) {
//		hash := auth.HashToken(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
//		token, err := stores.Store.GetAccessToken(req.Context(), hash)
//		if err != nil || token.Revoked {
//			http.Error(w, "unauthorized", http.StatusUnauthorized)
//			return
//		}
//		writeUserInfo(w, token.Subject)
//	})
//
// # Native net/http | 原生 net/http
//
// The same handler works without the YD router, because the store depends only on context and
// native Go values: | 同一个处理器无需 YD 路由即可工作，因为存储只依赖上下文与原生 Go 值：
//
//	stores, err := oauth2.New(client, oauth2.Options{})
//	if err != nil {
//		return err
//	}
//	mux := http.NewServeMux()
//	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, req *http.Request) {
//		hash := auth.HashToken(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
//		token, err := stores.Store.GetAccessToken(req.Context(), hash)
//		if err != nil || token.Revoked {
//			http.Error(w, "unauthorized", http.StatusUnauthorized)
//			return
//		}
//		writeUserInfo(w, token.Subject)
//	})
//
// Server implementations should keep using the in-memory stores for single-process tests and
// select this package only when several instances must share grants, tokens, device codes,
// clients, DPoP nonces or the scope registry. | 服务器实现应在单进程测试中继续使用内存存储，仅在
// 多个实例必须共享许可、令牌、设备码、客户端、DPoP nonce 或作用域注册表时选用本包。
package oauth2
