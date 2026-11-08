// Package saml implements the SAML persistence ports of
// github.com/shibingli/ydx/auth/protocol/saml on Redis. | Package saml 在 Redis 上实现
// github.com/shibingli/ydx/auth/protocol/saml 的 SAML 持久化端口。
//
// One Stores value implements saml.Store, saml.ArtifactStore and saml.AssertionReplayStore, so an
// identity provider or service provider can use it directly as its Store: providers discover the
// optional artifact and replay extensions by type assertion. Stores also exposes
// CleanupAssertions with the signature of saml.AssertionReplayCleaner, so replay records can be
// reclaimed explicitly. | 单个 Stores 值实现 saml.Store、saml.ArtifactStore 与
// saml.AssertionReplayStore，因此身份提供方或服务提供方可以直接把它用作 Store：提供方通过类型
// 断言发现可选的工件与重放扩展。Stores 还提供与 saml.AssertionReplayCleaner 签名一致的
// CleanupAssertions，可显式回收重放记录。
//
// # Multi-instance semantics | 多实例语义
//
// Every operation that must be atomic (request creation, request consumption, artifact save and
// single-use resolution, assertion replay recording, session save and delete, and cleanup) is a
// Lua script. Redis executes a script atomically, so several application instances that share one
// Redis deployment cannot both consume the same request or artifact and cannot both accept the
// same assertion identifier. All values cross the store boundary as JSON, and every read returns
// a fresh deep copy, so callers never share maps, slices or pointers with the store or with
// another instance. All non-zero times are normalized to UTC. | 所有必须原子执行的操作（请求创建、
// 请求消费、工件保存与一次性解析、断言重放记录、会话保存与删除、清理）都是 Lua 脚本。Redis 原子
// 执行脚本，因此共享同一 Redis 部署的多个应用实例不可能同时消费同一请求或工件，也不可能同时接受
// 相同断言标识。所有值以 JSON 跨越存储边界，每次读取都返回全新的深拷贝，调用方不会与存储或其它
// 实例共享映射、切片或指针。所有非零时间统一规范化为 UTC。
//
// # Key layout | 键布局
//
// Each category has its own hash tag, so Redis Cluster routes every key touched by one script to a
// single slot. The configurable prefix comes first and must not contain '{' or '}'. With the
// default prefix "ydx:authstore:saml:" the layout is: | 每个类别拥有独立的哈希标签，因此 Redis
// Cluster 把单个脚本访问的所有键路由到同一槽位。可配置前缀位于最前，且不得包含 '{' 或 '}'。默认
// 前缀 "ydx:authstore:saml:" 下的布局为：
//
//	ydx:authstore:saml:{authstore:saml:requests}:request:<len>:<id>
//	    hash: data/used/hasExpiry/expireSec/expireNsec
//	ydx:authstore:saml:{authstore:saml:requests}:expiry
//	    sorted set: request key scored by expiry second | 请求键按到期秒评分
//
//	ydx:authstore:saml:{authstore:saml:assertions}:assertion:<len>:<id>
//	    hash: hasExpiry/expireSec/expireNsec
//	ydx:authstore:saml:{authstore:saml:assertions}:expiry
//	    sorted set: assertion key scored by expiry second | 断言键按到期秒评分
//
//	ydx:authstore:saml:{authstore:saml:sessions}:session:<len>:<id>
//	    hash: data/nameID/hasExpiry/expireSec/expireNsec
//	ydx:authstore:saml:{authstore:saml:sessions}:subject:<len>:<nameID>
//	    set of full session keys | 完整会话键集合
//	ydx:authstore:saml:{authstore:saml:sessions}:expiry
//	    sorted set: session key scored by expiry second | 会话键按到期秒评分
//
//	ydx:authstore:saml:{authstore:saml:artifacts}:artifact:<len>:<key>
//	    hash: data/used/hasExpiry/expireSec/expireNsec
//	ydx:authstore:saml:{authstore:saml:artifacts}:expiry
//	    sorted set: artifact key scored by expiry second | 工件键按到期秒评分
//
// <len>: is the byte length of the following segment. Length prefixes keep arbitrary request
// IDs, NameIDs and 42-byte artifact keys unambiguous. The artifact segment covers the artifact
// type, source identifier and message handle, exactly like the unexported Artifact.storeKey used by
// the in-memory store; the endpoint index is not part of the key. | <len>: 是后续段的字节长度。
// 长度前缀使任意请求标识、NameID 与 42 字节工件键都无歧义。工件段覆盖工件类型、源标识与消息句柄，
// 与内存存储使用的未导出 Artifact.storeKey 完全一致；端点索引不属于键的一部分。
//
// # YD router usage | YD 路由用法
//
// The stores value is passed to a service provider or identity provider as its Store. The provider
// mounts itself on a ydx/router Router: | 存储值作为 Store 传给服务提供方或身份提供方。提供方把
// 自身挂载到 ydx/router Router 上：
//
//	stores, err := authsaml.New(client, authsaml.Options{KeyPrefix: "myapp:saml:"})
//	if err != nil {
//		return err
//	}
//	sp, err := saml.NewServiceProvider(saml.ServiceProviderConfig{
//		EntityID: "https://sp.example.com/saml/metadata",
//		ACSURL:   "https://sp.example.com/saml/acs",
//		Store:    stores,
//	})
//	if err != nil {
//		return err
//	}
//	sp.Register(router, "/saml")
//
// # Native net/http usage | 原生 net/http 用法
//
// ServiceProvider.HTTPHandler returns a net/http handler that serves the ACS, SLO and metadata
// endpoints, and identity-provider handlers can be mounted directly because their method values
// have the http.HandlerFunc shape: | ServiceProvider.HTTPHandler 返回服务 ACS、SLO 与元数据端点的
// net/http 处理器；身份提供方处理器可直接挂载，因为其方法值与 http.HandlerFunc 形状相同：
//
//	mux.Handle("/saml/", sp.HTTPHandler("/saml"))
//	mux.HandleFunc("/saml/sso", idp.HandleSSO)
//	mux.HandleFunc("/saml/artifact", idp.HandleArtifactResolution)
//
// The caller owns the goredis client passed to New; the package never closes it. | 传给 New 的
// goredis 客户端归调用方所有；本包从不关闭它。
package saml
