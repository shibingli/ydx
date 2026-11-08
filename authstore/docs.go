// Package authstore provides shared, multi-instance persistence for the ydx auth toolkit.
// | Package authstore 为 ydx auth 工具集提供多实例共享持久化。
//
// The module itself only carries documentation. Implementations live in subpackages: authstore/redis
// implements the auth root store ports, and authstore/{oauth2,oidc,saml,cas,scim,rbac,kms,kmip,
// wsfed,otp,webauthn} implement the store, registry, replay, challenge and state ports of the
// corresponding auth package. Every subpackage uses Redis Lua scripts for atomic transitions,
// length-prefixed keys, and a configurable namespace. | 本模块只承载文档，具体实现位于子包：
// authstore/redis 实现 auth 根包存储端口，authstore/{oauth2,oidc,saml,cas,scim,rbac,kms,kmip,
// wsfed,otp,webauthn} 实现对应 auth 包的存储、注册表、重放、挑战与状态端口。每个子包都使用 Redis
// Lua 脚本完成原子状态转换、长度前缀键与可配置命名空间。
//
// # Dependency direction | 依赖方向
//
// authstore depends on github.com/shibingli/ydx/auth; auth never imports authstore or Redis. An
// application assembles the stores from this module and passes them to the corresponding auth
// server or service, so a deployment can choose in-memory stores for tests or Redis stores for
// multiple application instances without changing auth itself. | authstore 依赖
// github.com/shibingli/ydx/auth，auth 绝不反向导入 authstore 或 Redis。应用从本模块组装存储并交给
// 对应的 auth 服务器或服务，因此部署可以在测试用内存存储、多实例用 Redis 存储之间切换，而无需改动
// auth 本身。
//
// # Multi-instance semantics | 多实例语义
//
// Every write that maintains a uniqueness index or a single-use guarantee is a Redis Lua script.
// Redis executes a script atomically, so two application instances cannot both create the same
// username, email, phone, provider/subject pair, credential ID, or consume the same one-time
// token. All values are serialized at the store boundary and every read returns a fresh deep
// copy, so callers never share maps or slices with the store or with another instance. All times
// are normalized to UTC. | 所有维护唯一索引或单次使用保证的写入都是 Redis Lua 脚本。Redis 原子
// 执行脚本，因此两个应用实例不可能同时创建相同的用户名、邮箱、手机号、provider/subject、
// 凭据 ID，也不可能同时消费同一个一次性令牌。所有值都在存储边界序列化，每次读取都返回全新的
// 深拷贝，调用方不会与存储或其它实例共享映射或切片。所有时间统一为 UTC。
//
// # Redis key layout | Redis 键布局
//
// Keys are grouped by a hash tag so that cluster deployments route every key touched by one
// script to the same slot. The configurable prefix comes first; it must not contain '{' or '}'.
// With the default prefix "ydx:authstore:" the layout is: | 键按哈希标签分组，使集群部署把单个
// 脚本访问的所有键路由到同一槽位。可配置前缀位于最前，且不得包含 '{' 或 '}'。默认前缀
// "ydx:authstore:" 下的布局为：
//
//	ydx:authstore:{authstore:users}:all                    set of user IDs | 用户 ID 集合
//	ydx:authstore:{authstore:users}:user:<id>              hash: data/username/email/phone
//	ydx:authstore:{authstore:users}:idx:username:<name>    unique username index | 用户名唯一索引
//	ydx:authstore:{authstore:users}:idx:email:<mail>       unique email index | 邮箱唯一索引
//	ydx:authstore:{authstore:users}:idx:phone:<number>     unique phone index | 手机号唯一索引
//
//	ydx:authstore:{authstore:sessions}:all                 set of session IDs | 会话 ID 集合
//	ydx:authstore:{authstore:sessions}:session:<id>        hash: data/user/expiry fields
//	ydx:authstore:{authstore:sessions}:user:<userID>       set of session IDs | 用户会话集合
//
//	ydx:authstore:{authstore:identities}:identity:<len>:<provider><subject>
//	                                                       hash: data/user
//	ydx:authstore:{authstore:identities}:user:<userID>     set of identity keys | 身份键集合
//
//	ydx:authstore:{authstore:credentials}:credential:<id>  hash: data/user
//	ydx:authstore:{authstore:credentials}:user:<userID>    set of credential IDs | 凭据 ID 集合
//
//	ydx:authstore:{authstore:audits}:seq                   append sequence | 追加序号
//	ydx:authstore:{authstore:audits}:events                hash: sequence -> event JSON
//	ydx:authstore:{authstore:audits}:index                 sorted set: sequence scored by time
//
//	ydx:authstore:{authstore:tokens}:token:<len>:<purpose><hash>
//	                                                       hash: data/user/used/expiry fields
//	ydx:authstore:{authstore:tokens}:user:<len>:<purpose><userID>
//	                                                       set of token keys | 令牌键集合
//
// Length-prefixed segments keep arbitrary provider, subject, purpose and hash values
// unambiguous. Sequence numbers, not event IDs, identify audit records, so appending the same
// event ID twice still retains both records. | 长度前缀段保证任意 provider、subject、purpose 与
// hash 值无歧义。审计记录以序号而不是事件 ID 标识，因此相同事件 ID 追加两次仍会保留两条记录。
package authstore
