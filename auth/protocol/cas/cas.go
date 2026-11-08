// Package cas implements the Apereo CAS 1.0, 2.0 and 3.0 server and client protocols on top of the
// ydx auth foundation. | Package cas 在 ydx auth 基础之上实现 Apereo CAS 1.0、2.0 与 3.0 的
// 服务端与客户端协议。
//
// The server side issues Ticket Granting Tickets (TGT), Service Tickets (ST), Proxy Granting
// Tickets (PGT) and Proxy Tickets (PT), and serves the login, logout, validate, serviceValidate,
// proxyValidate, proxy and samlValidate endpoints. Every handler has the router.HandlerFuncRaw
// signature, so it mounts directly on ydx/router: | 服务端签发票据授予票据（TGT）、服务票据（ST）、
// 代理授予票据（PGT）与代理票据（PT），并提供 login、logout、validate、serviceValidate、
// proxyValidate、proxy 与 samlValidate 端点。每个处理器都具有 router.HandlerFuncRaw 签名，因此
// 可直接挂载到 ydx/router：
//
//	srv, err := cas.NewServer(cas.ServerConfig{
//		Issuer:          "https://cas.example.com",
//		Authenticator:   cas.NewServiceAuthenticator(svc),
//		ServiceRegistry: cas.NewStaticServiceRegistry("https://app.example.com/*"),
//	})
//	if err != nil { ... }
//	srv.Register(r, "/cas")
//
// The same methods are valid net/http handlers, and HTTPHandler returns a complete multiplexer. |
// 同样的方法也是合法的 net/http 处理器，HTTPHandler 返回完整的多路复用器。
//
// # Login | 登录
//
// GET /login renders the login form (or redirects with a fresh ST when a TGC cookie is present);
// POST /login verifies the credentials through the Authenticator, sets the TGC cookie and redirects
// to the service with a ticket parameter. gateway=true returns to the service without a ticket when
// no valid TGT exists, and renew=true forces re-authentication. | GET /login 渲染登录表单（存在 TGC
// Cookie 时直接携带新 ST 重定向）；POST /login 经 Authenticator 校验凭据、设置 TGC Cookie，并携带
// ticket 参数重定向到服务。gateway=true 在没有有效 TGT 时返回服务而不带票据，renew=true 强制
// 重新认证。
//
// # Validation | 校验
//
// GET /serviceValidate and /p3/serviceValidate validate an ST; /proxyValidate and
// /p3/proxyValidate also accept a PT; /validate implements the CAS 1.0 yes/no text protocol; and
// /samlValidate implements the SAML 1.1 POST profile (unsigned by default; configure
// ServerConfig.SAMLResponseBuilder to sign). | GET /serviceValidate 与 /p3/serviceValidate 校验
// ST；/proxyValidate 与 /p3/proxyValidate 还接受 PT；/validate 实现 CAS 1.0 的 yes/no 文本协议；
// /samlValidate 实现 SAML 1.1 POST 配置（默认不签名；配置 ServerConfig.SAMLResponseBuilder 以签名）。
//
// # JSON views | JSON 视图
//
// The CAS 2.0/3.0 validation endpoints emit the CAS 3.0 JSON schema when the request carries
// format=json or, without that parameter, when its Accept header prefers application/json. XML
// stays the default and format=xml forces it. JSON responses use "application/json; charset=utf-8"
// with HTTP 200 for both success and protocol failure, and contain either authenticationSuccess
// (user, attributes, proxyGrantingTicket, proxies) or authenticationFailure (code, description).
// /validate honors an explicit format=json and otherwise keeps its CAS 1.0 yes/no body, ignoring
// Accept so legacy clients are unaffected. | CAS 2.0/3.0 校验端点在请求携带 format=json，或未携带该
// 参数但 Accept 头更偏好 application/json 时输出 CAS 3.0 JSON 模式。XML 仍是默认值，format=xml 强制
// 使用它。JSON 响应使用 "application/json; charset=utf-8"，成功与协议失败都返回 HTTP 200，正文为
// authenticationSuccess（user、attributes、proxyGrantingTicket、proxies）或
// authenticationFailure（code、description）。/validate 尊重显式的 format=json，否则保持 CAS 1.0
// yes/no 正文并忽略 Accept，以免影响旧客户端。
//
// # Single logout | 单点登出
//
// Validating an ST or PT records a ServiceSession keyed by the ticket identifier for the lifetime of
// its TGT/PGT. POST /logout with a SAML 1.1 LogoutRequest in the logoutRequest form parameter (raw
// XML or base64 XML, on GET or POST) revokes the named TGT family and sends a back-channel
// logoutRequest POST to every other recorded service in parallel, each bounded by
// LogoutCallbackTimeout. Browser logout destroys the TGC family, expires the cookie, and performs
// the same delivery. Failures are recorded in LogoutDeliveryResult and reported through
// LogoutObserver; they never fail the local logout. Replaying a request whose session is gone is an
// idempotent no-op, and only a request without SessionIndex falls back to NameIdentifier. When the
// service registry registers front-channel logout URLs (or ServerConfig.FrontChannelLogoutResolver is
// set), browser logout answers with a page that loads one hidden frame per distinct registered URL,
// capped by MaxFrontChannelLogoutServices; otherwise it redirects straight to the registered service
// parameter. Inbound LogoutRequest XML signatures are checked by an optional
// LogoutRequestSignatureVerifier; RequireSignedLogoutRequest rejects unsigned requests, and the
// built-in verifier binds the signature to the request ID so wrapped signatures fail. Configure a
// shared ServiceSessionRegistry for multi-node deployments. | 校验 ST 或 PT 时按票据标识记录一个在其
// TGT/PGT 生命周期内存活的 ServiceSession。POST /logout 携带 logoutRequest 表单参数中的 SAML 1.1
// LogoutRequest（原始 XML 或 base64 XML，GET 或 POST）时，撤销指定 TGT 族，并并行地向其它每个已记录
// 服务发送后端 logoutRequest POST，每次受 LogoutCallbackTimeout 限制。浏览器登出销毁 TGC 族、过期
// Cookie，并执行同样的投递。失败记录在 LogoutDeliveryResult 中并通过 LogoutObserver 报告，绝不会使
// 本地登出失败。重放会话已不存在的请求是幂等空操作，只有不带 SessionIndex 的请求才回退到
// NameIdentifier。当服务注册表登记了前端登出 URL（或设置了
// ServerConfig.FrontChannelLogoutResolver）时，浏览器登出返回一个为每个不同已注册 URL 加载一个隐藏
// 框架的页面，数量受 MaxFrontChannelLogoutServices 限制；否则直接重定向到已注册的 service 参数。
// 入站 LogoutRequest 的 XML 签名由可选的 LogoutRequestSignatureVerifier 校验；
// RequireSignedLogoutRequest 拒绝未签名请求，内置校验器把签名绑定到请求 ID，使包裹签名失败。多节点
// 部署应配置共享的 ServiceSessionRegistry。
//
// # Client | 客户端
//
// Client speaks the same protocol against a remote CAS server and parses CAS 1.0, 2.0 and 3.0
// responses. ClientConfig.ValidationFormat selects a JSON request, and the response parser detects
// XML or JSON from the body. SendLogoutRequest sends the back-channel form POST; BuildLogoutRequest
// and ParseLogoutRequest let services create or inspect SAML logout requests. | Client 以相同协议
// 访问远程 CAS 服务器，并解析 CAS 1.0、2.0 与 3.0 响应。ClientConfig.ValidationFormat 选择 JSON
// 请求，响应解析器按正文检测 XML 或 JSON。SendLogoutRequest 发送后端表单 POST；BuildLogoutRequest
// 与 ParseLogoutRequest 供服务创建或检查 SAML 登出请求。
//
// # Security | 安全
//
// Tickets are opaque random identifiers and are never written to logs. STs and PTs are single-use
// and consumed atomically; the service binding is checked on every validation. PGT callbacks
// require HTTPS unless AllowInsecurePGTCallback is explicitly enabled, and the TGC cookie is always
// HttpOnly with SameSite=Lax by default. Configure a ServiceRegistry in production so login and
// logout redirects cannot target arbitrary URLs. | 票据是不透明随机标识，绝不写入日志。ST 与 PT
// 一次性使用并原子消费；每次校验都检查服务绑定。除非显式启用 AllowInsecurePGTCallback，否则 PGT
// 回调必须使用 HTTPS；TGC Cookie 始终为 HttpOnly，并默认 SameSite=Lax。生产环境应配置
// ServiceRegistry，避免登录与登出重定向指向任意 URL。
package cas

import (
	"crypto/subtle"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
)

// Protocol version identifiers. | 协议版本标识。
const (
	// ProtocolVersion10 is the CAS 1.0 protocol. | ProtocolVersion10 是 CAS 1.0 协议。
	ProtocolVersion10 = "1.0"
	// ProtocolVersion20 is the CAS 2.0 protocol. | ProtocolVersion20 是 CAS 2.0 协议。
	ProtocolVersion20 = "2.0"
	// ProtocolVersion30 is the CAS 3.0 protocol. | ProtocolVersion30 是 CAS 3.0 协议。
	ProtocolVersion30 = "3.0"
)

// Ticket identifier prefixes defined by the CAS protocol. | CAS 协议定义的票据标识前缀。
const (
	// TicketPrefixTGT is the Ticket Granting Ticket prefix. | TicketPrefixTGT 是票据授予票据前缀。
	TicketPrefixTGT = "TGT-"
	// TicketPrefixST is the Service Ticket prefix. | TicketPrefixST 是服务票据前缀。
	TicketPrefixST = "ST-"
	// TicketPrefixPGT is the Proxy Granting Ticket prefix. | TicketPrefixPGT 是代理授予票据前缀。
	TicketPrefixPGT = "PGT-"
	// TicketPrefixPT is the Proxy Ticket prefix. | TicketPrefixPT 是代理票据前缀。
	TicketPrefixPT = "PT-"
	// TicketPrefixPGTIOU is the Proxy Granting Ticket IOU prefix sent to a pgtUrl callback. |
	// TicketPrefixPGTIOU 是发送给 pgtUrl 回调的代理授予票据 IOU 前缀。
	TicketPrefixPGTIOU = "PGTIOU-"
)

// CookieNameTGC is the standard Ticket Granting Ticket cookie name. | CookieNameTGC 是标准的票据授予票据 Cookie 名。
const CookieNameTGC = "TGC"

// CAS error codes returned in validation responses. | 校验响应中返回的 CAS 错误码。
const (
	// ErrorCodeInvalidRequest reports a missing or malformed protocol parameter. | ErrorCodeInvalidRequest 表示协议参数缺失或格式非法。
	ErrorCodeInvalidRequest = "INVALID_REQUEST"
	// ErrorCodeInvalidTicket reports an unknown, expired, consumed or wrong-type ticket. | ErrorCodeInvalidTicket 表示票据未知、过期、已消费或类型错误。
	ErrorCodeInvalidTicket = "INVALID_TICKET"
	// ErrorCodeInvalidService reports a service that does not match the ticket binding. | ErrorCodeInvalidService 表示服务与票据绑定不匹配。
	ErrorCodeInvalidService = "INVALID_SERVICE"
	// ErrorCodeInvalidProxyCallback reports a failed PGT callback. | ErrorCodeInvalidProxyCallback 表示 PGT 回调失败。
	ErrorCodeInvalidProxyCallback = "INVALID_PROXY_CALLBACK"
	// ErrorCodeInternalError reports an unexpected server failure. | ErrorCodeInternalError 表示意外的服务端故障。
	ErrorCodeInternalError = "INTERNAL_ERROR"
)

// Default protocol timeouts. | 默认协议超时。
const (
	// DefaultTGTTimeout is the default TGT lifetime. | DefaultTGTTimeout 是默认 TGT 寿命。
	DefaultTGTTimeout = 2 * time.Hour
	// DefaultServiceTicketTimeout is the default ST lifetime. | DefaultServiceTicketTimeout 是默认 ST 寿命。
	DefaultServiceTicketTimeout = 10 * time.Second
	// DefaultProxyGrantingTicketTimeout is the default PGT lifetime. | DefaultProxyGrantingTicketTimeout 是默认 PGT 寿命。
	DefaultProxyGrantingTicketTimeout = 2 * time.Hour
	// DefaultProxyTicketTimeout is the default PT lifetime. | DefaultProxyTicketTimeout 是默认 PT 寿命。
	DefaultProxyTicketTimeout = 10 * time.Second
	// DefaultTicketStoreGCInterval is the default memory-store cleanup interval. |
	// DefaultTicketStoreGCInterval 是内存存储的默认清理间隔。
	DefaultTicketStoreGCInterval = time.Minute
)

// maxProtocolBody limits the response body read by Client and the SAML request body read by
// Server. | maxProtocolBody 限制 Client 读取的响应体大小与 Server 读取的 SAML 请求体大小。
const maxProtocolBody = 1 << 20

// casNamespace is the XML namespace used by every CAS response. | casNamespace 是每个 CAS 响应使用的 XML 命名空间。
const casNamespace = "http://www.yale.edu/tp/cas"

// normalizePrefix canonicalizes a mount prefix: empty stays empty, otherwise it starts with "/" and
// has no trailing "/". | normalizePrefix 规范化挂载前缀：空值保持为空，否则以 "/" 开头且不含结尾 "/"。
func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return ""
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return strings.TrimRight(prefix, "/")
}

// parseBoolParam interprets the loose boolean forms used by CAS query parameters. | parseBoolParam
// 解析 CAS 查询参数使用的宽松布尔形式。
func parseBoolParam(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// secureCompare reports whether a and b are equal in constant time. | secureCompare 以常量时间报告 a 与 b 是否相等。
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// cloneStrings returns a copy of m. | cloneStrings 返回 m 的副本。
func cloneStrings(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// attributeValues converts scalar attributes into the multi-valued protocol form. | attributeValues
// 把标量属性转换为多值协议形式。
func attributeValues(in map[string]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = []string{v}
	}
	return out
}

// userIdentifier returns the protocol user identifier of p, preferring the login name. |
// userIdentifier 返回 p 的协议用户标识，优先使用登录名。
func userIdentifier(p *auth.Principal) string {
	if p == nil {
		return ""
	}
	if p.Username != "" {
		return p.Username
	}
	return p.Subject
}
