// Package auth is the identity, credential, session and account-lifecycle foundation of the ydx
// authentication toolkit. | Package auth 是 ydx 认证工具集的身份、凭据、会话与账号生命周期基础。
//
// Subpackages are grouped by domain and must not be added flat under auth/:
//
//	auth/token/      jwt, jose
//	auth/protocol/   oauth2, oidc, saml, cas, wsfed, federation, radius
//	auth/directory/  ldap, scim, ntlm
//	auth/mfa/        otp, webauthn
//	auth/authz/      rbac
//	auth/keymgmt/    kms, kmip
//	auth/crypto/     xmlsig
//	auth/identity/   cn
//
// They all build on the types, stores and session manager declared here, so a deployment can mix
// them without translating principals, sessions or audit records. | 子包按领域分组，不得在 auth/
// 下新增平铺子包：token/、protocol/、directory/、mfa/、authz/、keymgmt/、crypto/、identity/。
// 它们都建立在这里声明的类型、存储与会话管理器之上，因此同一部署可以混用它们而无需转换主体、
// 会话或审计记录。
//
// All timestamps are UTC and all identifiers are opaque strings. Stores never mutate the values they
// receive; they store deep copies so callers can keep using the value they passed in. | 所有时间戳均为
// UTC，所有标识符均为不透明字符串。存储实现从不修改收到的值，而是保存深拷贝，因此调用方可以继续
// 使用传入的值。
//
// # HTTP entries | HTTP 入口
//
// The packages under auth use ydx/router as their native HTTP surface: SessionManager.Middleware
// returns a router.Middleware and the protocol servers expose Register methods that mount their
// endpoints on a *router.Router. Every server also offers an http.Handler or a standard middleware
// adapter, so the same implementation runs on net/http without a second code path. | auth 下的包以
// ydx/router 作为原生 HTTP 入口：SessionManager.Middleware 返回 router.Middleware，协议服务器的
// Register 方法把端点挂载到 *router.Router。每个服务器同时提供 http.Handler 或标准中间件适配器，
// 因此同一实现可以在 net/http 上运行而无需第二条代码路径。
//
// # Start here | 从这里开始
//
//	stores := auth.NewMemoryStores()
//	hasher, _ := auth.NewArgon2idHasher(auth.DefaultArgon2idConfig())
//	svc, _ := auth.New(auth.Config{Stores: stores, Passwords: hasher})
//	user, _ := svc.Register(ctx, auth.RegisterInput{Username: "alice", Password: "..."})
//	result, _ := svc.Authenticate(ctx, auth.AuthenticateInput{Login: "alice", Password: "..."})
//
// The same service is the authentication delegate for the oauth2, oidc, saml and cas servers. | 同一个
// 服务同时是 oauth2、oidc、saml 与 cas 服务器的认证委托。
package auth
