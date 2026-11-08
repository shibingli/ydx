// Package scim implements a SCIM 2.0 (RFC 7643 / RFC 7644) server and client for user and
// group lifecycle provisioning. | Package scim 实现 SCIM 2.0（RFC 7643 / RFC 7644）的用户与组
// 生命周期预配服务端与客户端。
//
// The resource model follows RFC 7643 exactly: User, Group, EnterpriseUser, ListResponse,
// Error, ServiceProviderConfig, ResourceType and Schema, including the multi-valued attribute
// shape (value / display / type / primary / $ref). | 资源模型严格遵循 RFC 7643：User、Group、
// EnterpriseUser、ListResponse、Error、ServiceProviderConfig、ResourceType 与 Schema，包括多值
// 属性的 value / display / type / primary / $ref 结构。
//
// The filter parser implements the RFC 7644 section 3.4.2.2 grammar: eq, ne, co, sw, ew, gt, ge,
// lt, le and pr, combined with and, or, not and parentheses, attribute paths with sub-attributes,
// and value filters such as emails[type eq "work"].value. Attribute names, operators and keywords
// are matched case-insensitively. | 过滤器解析器实现 RFC 7644 第 3.4.2.2 节的语法：eq、ne、co、
// sw、ew、gt、ge、lt、le 与 pr，可用 and、or、not 和括号组合，支持带子属性的属性路径，以及
// emails[type eq "work"].value 这类值过滤器。属性名、运算符与关键字均大小写不敏感。
//
// PATCH implements RFC 7644 section 3.5.2 add / replace / remove operations, including
// path-less object merges, value filters and multivalued attribute edits. | PATCH 实现 RFC 7644
// 第 3.5.2 节的 add / replace / remove 操作，包括无路径对象合并、值过滤器与多值属性编辑。
//
// # Bulk | 批量
//
// By default bulk operations run sequentially and are not transactional: a failed operation is
// reported in place and does not undo earlier results. A "bulkId:<id>" reference is resolved only
// when it is the whole string value in operation data or a whole path segment; substrings inside
// larger strings are left untouched. References to a bulkId that has not been created successfully
// by an earlier operation fail with ErrBulkIDUnresolved, and duplicate definitions fail with
// ErrBulkIDDuplicate before any operation runs. | 默认情况下批量操作按顺序执行且不具备事务性：失败
// 的操作就地报告，不会撤销先前结果。只有当 "bulkId:<id>" 是操作数据中的完整字符串值或完整路径段时
// 才会解析；更长字符串内的子串保持原样。引用尚未由先前操作成功创建的 bulkId 会返回
// ErrBulkIDUnresolved，重复定义会在任何操作执行前返回 ErrBulkIDDuplicate。
//
// Options.BulkAtomic enables an optional transactional mode. Each User and Group mutation records a
// compensating undo entry (create records a delete, update and patch record the prior resource,
// delete records the prior resource for recreation). The first failure stops processing, rolls the
// applied entries back in reverse order and removes the bulkId mappings created by rolled-back
// operations. The response is then one RFC 7644 Error object whose status reflects the original
// operation failure; FailOnErrors is ignored because processing always stops at the first failure.
// Rollback never calls PasswordSetter, PasswordProvisioner or any other hook, so external credential
// provisioning performed before a failure is not undone. Rollback refuses to overwrite a resource
// whose entity tag changed concurrently and reports ErrBulkRollbackConflict; an incomplete rollback
// reports ErrBulkRollbackFailed with a generic client detail, while the joined original and rollback
// errors remain available through errors.Is. Options.BulkMaxUndoBytes bounds the estimated undo log
// memory and violations fail with ErrBulkUndoLimit before the overflowing mutation is applied. |
// Options.BulkAtomic 启用可选的事务模式。每个 User 与 Group 变更都会记录补偿撤销条目（创建记录删除，
// 更新与补丁记录先前资源，删除记录先前资源用于重建）。首次失败会停止处理、按逆序回滚已应用条目，并
// 移除已回滚操作创建的 bulkId 映射。响应随后是单个 RFC 7644 Error 对象，其状态反映原始操作失败；
// FailOnErrors 被忽略，因为处理总是在首次失败时停止。回滚绝不会调用 PasswordSetter、
// PasswordProvisioner 或其他钩子，因此失败前已执行的外部口令预配不会被撤销。回滚拒绝覆盖实体标签
// 已被并发修改的资源，并报告 ErrBulkRollbackConflict；回滚不完整会报告 ErrBulkRollbackFailed 且
// 客户端明细为通用文案，而合并后的原始错误与回滚错误仍可通过 errors.Is 判定。
// Options.BulkMaxUndoBytes 限制撤销日志的估算内存，超限会在应用会溢出的变更前以 ErrBulkUndoLimit
// 失败。
//
// # Password provisioning | 口令预配
//
// Options.PasswordPrecheck runs before every password write and rejects the request before any
// profile or external change. Options.PasswordProvisioner then performs a two-phase external write:
// BeginPassword runs before the profile is stored, Commit runs after it succeeds, and Rollback runs
// when either step fails. A provisioner takes precedence over Options.PasswordSetter; the legacy
// setter remains available for single-phase hooks. Begin failure leaves the profile untouched.
// Commit failure restores the prior profile and rolls the external transaction back. A rollback
// failure is never ignored: it is reported as ErrPasswordRollbackFailed together with the original
// cause, and a concurrent profile change during compensation is reported as
// ErrPasswordRollbackConflict. On create, a failed delete of the newly created profile is likewise
// joined into ErrPasswordRollbackFailed. | Options.PasswordPrecheck 在每次口令写入前运行，并在任何
// 资料或外部变更前拒绝请求。Options.PasswordProvisioner 随后执行两阶段外部写入：BeginPassword 在
// 存储资料前运行，Commit 在资料存储成功后运行，任一步失败时运行 Rollback。预配器优先于
// Options.PasswordSetter；旧版 setter 仍可用于单阶段钩子。Begin 失败不会改动资料。Commit 失败会恢复
// 先前资料并回滚外部事务。回滚失败绝不会被忽略：它与原始原因一并报告为
// ErrPasswordRollbackFailed；补偿期间资料被并发修改则报告 ErrPasswordRollbackConflict。创建时若
// 删除新建资料失败，也会合并进 ErrPasswordRollbackFailed。
//
// # Server | 服务端
//
// The Server exposes /Users, /Groups, /Me, /Bulk, the discovery endpoints and the .search
// endpoints. It is usable through ydx/router or plain net/http; both entries share one dispatch
// path, so behavior never diverges. | Server 提供 /Users、/Groups、/Me、/Bulk、发现端点与 .search
// 端点。它既可通过 ydx/router 使用，也可用于原生 net/http；两个入口共享同一条分发路径，因此行为
// 不会分叉。
//
//	store := scim.NewMemoryStore()
//	srv, _ := scim.New(scim.Options{Store: store})
//
//	// ydx/router | YD 路由
//	r := router.New()
//	srv.Register(r, "/scim/v2")
//
//	// plain net/http | 原生 net/http
//	http.Handle("/scim/v2/", http.StripPrefix("/scim/v2", srv.HTTPHandler("")))
//
// # Client | 客户端
//
// Client talks to any RFC 7644 server, with bearer or basic authentication, typed errors and a
// pagination iterator. | Client 可访问任何 RFC 7644 服务端，支持承载或基本认证、类型化错误与
// 分页迭代器。
//
//	client, _ := scim.NewClient("https://example.com/scim/v2", scim.WithBearerToken("..."))
//	page, _ := client.ListUsers(ctx, scim.ListOptions{Filter: `userName sw "a"`})
//	for _, user := range page.Resources { ... }
//
// # Authorization | 授权
//
// Server calls an optional Authorizer before every operation. PrincipalFromRequest and
// PrincipalFromContext (from the parent auth package) provide the authenticated subject; the
// default authorizer allows every request, so the caller can mount its own authentication
// middleware. | Server 在每次操作前调用可选的 Authorizer。父 auth 包的 PrincipalFromRequest 与
// PrincipalFromContext 提供已认证主体；默认授权器放行所有请求，因此调用方可以自行挂载认证中间件。
package scim
