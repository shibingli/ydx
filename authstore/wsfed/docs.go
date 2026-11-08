// Package wsfed implements the auth/protocol/wsfed RequestStore on Redis.
// | Package wsfed 在 Redis 上实现 auth/protocol/wsfed 的 RequestStore。
//
// New returns a Store that can be assigned to wsfed.RelyingPartyConfig.RequestStore. Every
// application instance that shares the same Redis deployment then sees the same outstanding
// sign-in requests, so a response received by one instance can be correlated with a request
// started on another. The go-redis universal client passed to New stays owned by the caller and
// must be closed by the caller. New performs no network round trip. | New 返回可赋给
// wsfed.RelyingPartyConfig.RequestStore 的 Store。共享同一 Redis 部署的所有应用实例随后看到相同
// 的未完成登录请求，因此一个实例收到的响应可以与另一个实例发起的请求关联。传给 New 的 go-redis
// 通用客户端始终归调用方所有，调用方必须关闭它。New 不进行网络往返。
//
// # Multi-instance semantics | 多实例语义
//
// TakeRequest is one Redis Lua script that reads and deletes the record in a single atomic step,
// so two application instances cannot both consume the same request. Saved values are serialized
// at the store boundary; reads return fresh values; every time is normalized to UTC. The Redis
// key expiry follows the record ExpiresAt so abandoned requests are reclaimed automatically. |
// TakeRequest 是单个 Redis Lua 脚本，在一步原子操作中读取并删除记录，因此两个应用实例不可能同时
// 消费同一个请求。保存的值在存储边界序列化；读取返回全新值；所有时间统一为 UTC。Redis 键期限跟随
// 记录的 ExpiresAt，因此被放弃的请求会被自动回收。
//
// # Redis key layout | Redis 键布局
//
// Keys carry the shared hash tag so a cluster routes the whole script to one slot. The
// configurable prefix comes first and must not contain '{' or '}'. Arbitrary values use a
// length-prefixed segment, so concatenation stays unambiguous. With the default prefix
// "ydx:authstore:wsfed:" the layout is: | 键携带共享哈希标签，使集群把整个脚本路由到单一槽位。
// 可配置前缀位于最前，且不得包含 '{' 或 '}'。任意值使用长度前缀段，因此拼接始终无歧义。默认前缀
// "ydx:authstore:wsfed:" 下的布局为：
//
//	ydx:authstore:wsfed:{authstore:wsfed}:request:<len>:<wctx>
//	                                                       string: request state JSON | 请求状态 JSON
//
// # YD router | YD 路由
//
// Assign the store to the relying party configuration and mount the reply endpoint: |
// 把存储赋给依赖方配置并挂载回复端点：
//
//	requests, err := wsfedstore.New(client, wsfedstore.Options{})
//	if err != nil {
//		return err
//	}
//	rp, err := wsfed.NewRelyingParty(wsfed.RelyingPartyConfig{
//		Realm:        "https://app.example.com",
//		ReplyURL:     "https://app.example.com/wsfed/reply",
//		IDPURL:       "https://idp.example.com/wsfed",
//		Issuer:       "https://idp.example.com/wsfed",
//		RequestStore: requests,
//	})
//	if err != nil {
//		return err
//	}
//	rp.Register(routerInstance, "/wsfed")
//
// # Native net/http | 原生 net/http
//
// The same store works without the YD router, because it depends only on context and native Go
// values: | 同一个存储无需 YD 路由即可工作，因为它只依赖上下文与原生 Go 值：
//
//	requests, err := wsfedstore.New(client, wsfedstore.Options{})
//	if err != nil {
//		return err
//	}
//	rp, err := wsfed.NewRelyingParty(wsfed.RelyingPartyConfig{
//		Realm:        "https://app.example.com",
//		ReplyURL:     "https://app.example.com/wsfed/reply",
//		IDPURL:       "https://idp.example.com/wsfed",
//		Issuer:       "https://idp.example.com/wsfed",
//		RequestStore: requests,
//	})
//	if err != nil {
//		return err
//	}
//	mux := http.NewServeMux()
//	mux.Handle("/wsfed/", rp.HTTPHandler("/wsfed"))
//
// Deployments with a single process may keep wsfed.NewMemoryRequestStore; select this package
// only when several instances must share outstanding requests. | 单进程部署可以继续使用
// wsfed.NewMemoryRequestStore；仅在多个实例必须共享未完成请求时选用本包。
package wsfed
