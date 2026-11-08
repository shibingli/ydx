// Package rbac implements the github.com/shibingli/ydx/auth/authz/rbac Store port on Redis.
// | Package rbac 在 Redis 上实现 github.com/shibingli/ydx/auth/authz/rbac 的 Store 端口。
//
// One Store value satisfies authrbac.Store and can be passed to Engine through WithStore, so a
// multi-instance deployment keeps roles, assignments and policies in shared state instead of
// process memory. The client passed to New belongs to the caller and is never closed by the
// store. | 单个 Store 值满足 authrbac.Store，可经 WithStore 传给 Engine，因此多实例部署把角色、
// 分配与策略保存在共享状态而不是进程内存中。传给 New 的客户端归调用方所有，存储从不关闭它。
//
// # Multi-instance semantics | 多实例语义
//
// Every write that enforces a uniqueness rule, detects an inheritance cycle, replaces an expired
// assignment, cascades a role removal or resets the store is a Redis Lua script. Redis executes a
// script atomically, so two application instances cannot both create the same role, policy or
// active subject-role-scope assignment. Role name uniqueness and cycle detection happen inside the
// same script as the role write. Assignment writes compare the stored deadline from whole seconds
// and nanoseconds, so the replacement rule matches the in-memory store exactly. Every read returns
// a fresh deep copy and all non-zero times are normalized to UTC. | 所有执行唯一性规则、检测继承环、
// 替换过期分配、级联删除角色或重置存储的写入都是 Redis Lua 脚本。Redis 原子执行脚本，因此两个
// 应用实例不可能同时创建相同的角色、策略或有效的主体、角色与作用域分配。角色名唯一性与环检测与角色
// 写入在同一脚本内完成。分配写入以整秒与纳秒比较已存期限，因此替换规则与内存存储完全一致。每次读取
// 都返回全新的深拷贝，所有非零时间统一规范化为 UTC。
//
// Failures that the in-memory store reports with a package sentinel keep that sentinel here, so
// errors.Is works unchanged: role, assignment and policy conflicts, unknown records, invalid
// definitions, inheritance cycles and canceled contexts. A canceled or expired context is reported
// as authrbac.ErrCanceled. Redis backend failures are reported as ErrStoreUnavailable with a fixed
// bilingual detail; the underlying go-redis error text is deliberately not attached because it can
// contain addresses or credentials. | 内存存储用包哨兵报告的错误在这里保留同一哨兵，因此 errors.Is
// 无需改动即可使用：角色、分配与策略冲突，未知记录，非法定义，继承环与已取消上下文。已取消或超时的
// 上下文报告为 authrbac.ErrCanceled。Redis 后端故障以 ErrStoreUnavailable 加固定中英双语细节返回；
// 底层 go-redis 错误文本会被有意丢弃，因为它可能包含地址或凭据。
//
// # Redis key layout | Redis 键布局
//
// Every key carries the same hash tag, so a cluster deployment routes every key touched by one
// script to a single slot. The configurable prefix comes first and must not contain '{' or '}'.
// With the default prefix "ydx:authstore:rbac:" the layout is: | 每个键携带相同的哈希标签，因此
// 集群部署把单个脚本访问的所有键路由到同一槽位。可配置前缀位于最前，且不得包含 '{' 或 '}'。默认
// 前缀 "ydx:authstore:rbac:" 下的布局为：
//
//	ydx:authstore:rbac:{authstore:rbac}:roles
//	    hash: role name -> Role JSON | 角色名称 -> 角色 JSON
//	ydx:authstore:rbac:{authstore:rbac}:roles:parents
//	    hash: role name -> length-prefixed parent list | 长度前缀父角色列表
//	ydx:authstore:rbac:{authstore:rbac}:assignments
//	    hash: assignment identifier -> Assignment JSON | 分配标识 -> 分配 JSON
//	ydx:authstore:rbac:{authstore:rbac}:assignments:expiry
//	    hash: assignment identifier -> hasExpiry:seconds:nanoseconds
//	ydx:authstore:rbac:{authstore:rbac}:assignments:subjects
//	    set: every subject owning at least one assignment | 拥有分配的全部主体
//	ydx:authstore:rbac:{authstore:rbac}:assignments:subject:<len>:<subject>
//	    set: assignment identifiers owned by one subject | 单个主体拥有的分配标识
//	ydx:authstore:rbac:{authstore:rbac}:policies
//	    hash: policy identifier -> Policy JSON | 策略标识 -> 策略 JSON
//
// The assignment identifier is the length-prefixed concatenation of subject, role and scope, so
// arbitrary identifiers cannot collide. <len>: is the byte length of the following segment.
// | 分配标识是主体、角色与作用域的长度前缀拼接，因此任意标识都不会碰撞。<len>: 是后续段的字节长度。
//
// # Usage | 用法
//
// The same store serves both HTTP entry styles; only the mounting differs. | 同一个存储服务两种
// HTTP 入口，只有挂载方式不同。
//
//	store, err := rbacstore.New(client, rbacstore.Options{KeyPrefix: "myapp:rbac:"})
//	if err != nil {
//		return err
//	}
//	engine := authrbac.New(authrbac.WithStore(store))
//	if err := engine.AddRole(ctx, authrbac.Role{Name: "editor", Permissions: []string{"post:read"}}); err != nil {
//		return err
//	}
//
//	// YD router | YD 路由
//	r := router.New()
//	r.GET("/posts", postsHandler, authrbac.Require(engine, "post:read", nil))
//
//	// Native net/http | 原生 net/http
//	mux := http.NewServeMux()
//	mux.Handle("/posts", authrbac.RequireHTTP(engine, "post:read", nil)(postsHTTPHandler))
//
// Both adapters require an earlier authentication middleware, such as
// auth.SessionManager.Middleware or auth.SessionManager.HTTPMiddleware, to attach the principal.
// | 两种适配器都需要更早的认证中间件（例如 auth.SessionManager.Middleware 或
// auth.SessionManager.HTTPMiddleware）附加主体。
//
// # Boundaries | 边界
//
// ListRoles, ListAssignments and ListPolicies read every record of their category and sort in the
// caller; the Store interface offers no pagination. Redis guarantees atomicity per script, not
// snapshot isolation across several calls, so a list started during concurrent writes may observe
// a mixture of states from before and after those writes. GetRole and ListRoles read the role hash
// and the parent-list hash separately, so a concurrent role addition can briefly appear without its
// parent list; move such reads under one Lua script if a stronger guarantee is required. RemoveRole
// scans every assignment to cascade the deletion and Reset iterates the subject index sets inside
// one script; a very large number of assignments or subjects lengthens that single script. | ListRoles、
// ListAssignments 与 ListPolicies 读取其类别的全部记录并在调用方排序；Store 接口不提供分页。Redis
// 只保证单个脚本的原子性，不提供跨多次调用的快照隔离，因此并发写入期间开始的列表操作可能观察到写入
// 前后的混合状态。GetRole 与 ListRoles 分别读取角色哈希与父角色列表哈希，因此并发新增角色可能短暂
// 出现没有父角色列表的状态；需要更强保证时应把这些读取移入同一个 Lua 脚本。RemoveRole 为级联删除
// 扫描全部分配，Reset 在单个脚本内遍历按主体索引集合；分配或主体数量极大时会延长该脚本的执行时间。
package rbac
