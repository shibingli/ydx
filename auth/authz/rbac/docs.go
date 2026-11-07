// Package rbac implements role-based and attribute-based access control on top of the ydx auth
// toolkit. | Package rbac 在 ydx 认证工具集之上实现基于角色与基于属性的访问控制。
//
// The package combines three declarations. A Role grants permission strings and may inherit other
// roles. An Assignment binds a subject to a role inside an optional scope, with optional equality
// conditions and an optional expiry. A Policy is an attribute-based permit or deny rule whose
// subject, resource, action and scope patterns accept "*" and "prefix:*" globs and whose conditions
// are evaluated against the request attributes and environment. | 本包组合三类声明。Role 授予权限
// 字符串并可继承其它角色。Assignment 在可选作用域内把主体绑定到角色，可附带等值条件与过期时间。
// Policy 是基于属性的许可或拒绝规则，其主体、资源、动作与作用域模式支持 "*" 与 "prefix:*" 通配，
// 条件则针对请求属性与环境求值。
//
// # Combining | 合并
//
// New defaults to DenyOverrides: any applicable deny wins, otherwise any permit (a matching policy
// or a role permission) allows, and no match denies. WithCombiningAlgorithm selects
// PermitOverrides, FirstApplicable or OnlyOneApplicable instead. OnlyOneApplicable returns
// ErrMultiplePolicies when more than one policy applies. | New 默认使用 DenyOverrides：任一适用的
// 拒绝获胜；否则任一许可（匹配的策略或角色权限）允许；无匹配则拒绝。WithCombiningAlgorithm 可改用
// PermitOverrides、FirstApplicable 或 OnlyOneApplicable。OnlyOneApplicable 在多条策略适用时返回
// ErrMultiplePolicies。
//
// # Conditions | 条件
//
// Condition operands resolve from Request fields and maps. The built-in keys are subject, action,
// resource and scope. An exact Attributes entry is checked first, then prefixes: "env.<name>" and
// "environment.<name>" read Environment, while "subject.<name>" and "resource.<name>" read
// Attributes with the prefix stripped. The operators are eq, ne, in, not_in, contains,
// starts_with, ends_with, gt, ge, lt, le, present and absent; in / not_in use a comma-separated
// Value list and ordering operators compare numbers. | 条件操作数从 Request 字段与映射解析。内建键为
// subject、action、resource 与 scope。先检查 Attributes 的精确条目，再处理前缀："env.<name>" 与
// "environment.<name>" 读取 Environment，"subject.<name>" 与 "resource.<name>" 读取去掉前缀的
// Attributes。运算符包括 eq、ne、in、not_in、contains、starts_with、ends_with、gt、ge、lt、le、
// present 与 absent；in / not_in 使用逗号分隔的 Value 列表，排序运算符比较数值。
//
// # Snapshots | 快照
//
// Snapshot and LoadSnapshot move the complete engine state, while MarshalSnapshot,
// UnmarshalSnapshot and the Snapshot type encode it with github.com/shibingli/ydx/json. Every
// snapshot carries a version field checked on load. | Snapshot 与 LoadSnapshot 迁移完整引擎状态，
// MarshalSnapshot、UnmarshalSnapshot 与 Snapshot 类型使用 github.com/shibingli/ydx/json 编解码。
// 每个快照都带版本字段并在加载时校验。
//
// # HTTP entries | HTTP 入口
//
// ydx/router is the primary entry: Require, RequireAny and RequireAll read the principal with
// auth.PrincipalFromCtx and return router.Middleware. RequireHTTP, RequireAnyHTTP and
// RequireAllHTTP are the net/http equivalents and read the principal with
// auth.PrincipalFromRequest. A missing principal yields 401, a denied decision yields 403 and an
// unexpected engine error yields 500; WithErrorHandler and WithHTTPErrorHandler replace the default
// renderers. | ydx/router 是主入口：Require、RequireAny 与 RequireAll 使用 auth.PrincipalFromCtx
// 读取主体并返回 router.Middleware。RequireHTTP、RequireAnyHTTP 与 RequireAllHTTP 是 net/http
// 等价物，使用 auth.PrincipalFromRequest 读取主体。缺少主体返回 401，拒绝决策返回 403，引擎意外
// 错误返回 500；WithErrorHandler 与 WithHTTPErrorHandler 可替换默认渲染器。
//
// # Example | 示例
//
//	engine := rbac.New()
//	_ = engine.AddRole(ctx, rbac.Role{Name: "editor", Permissions: []string{"post:read", "post:write"}})
//	_ = engine.Assign(ctx, rbac.Assignment{Subject: "alice", Role: "editor", Scope: "tenant:1"})
//
//	// ydx/router
//	r := router.New()
//	r.GET("/posts", func(c *router.Ctx) { _ = c.String(200, "ok") },
//		rbac.Require(engine, "post:read", func(c *router.Ctx) string { return "/api/posts" }))
//
//	// net/http
//	mux := http.NewServeMux()
//	mux.HandleFunc("/posts", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
//	handler := rbac.RequireHTTP(engine, "post:read", nil)(mux)
//
// Both adapters require an earlier authentication middleware, such as auth.SessionManager.Middleware
// or auth.SessionManager.HTTPMiddleware, to attach the principal. | 两种适配器都需要更早的认证中间件
// （例如 auth.SessionManager.Middleware 或 auth.SessionManager.HTTPMiddleware）附加主体。
package rbac
