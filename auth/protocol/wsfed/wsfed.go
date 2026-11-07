// Package wsfed implements the WS-Federation 1.2 Passive Requestor Profile for relying parties and
// security token services, using WS-Trust 1.3 token issuance over the HTTP-POST and HTTP-Redirect
// passive bindings. | Package wsfed 实现 WS-Federation 1.2 被动请求者配置文件的依赖方与安全令牌
// 服务，基于 HTTP-POST 与 HTTP-Redirect 被动绑定使用 WS-Trust 1.3 令牌签发。
//
// The package covers sign-in requests (wa=wsignin1.0), sign-out requests (wa=wsignout1.0), sign-out
// cleanup (wa=wsignoutcleanup1.0), the WS-Trust RequestSecurityTokenResponseCollection carried in
// wresult, SAML 1.1 and SAML 2.0 assertions, optional JWT tokens, replay protection, audience,
// recipient, lifetime and signature validation, and a minimal federation metadata document. | 本包
// 覆盖登录请求（wa=wsignin1.0）、登出请求（wa=wsignout1.0）、登出清理（wa=wsignoutcleanup1.0）、
// wresult 中携带的 WS-Trust RequestSecurityTokenResponseCollection、SAML 1.1 与 SAML 2.0 断言、
// 可选 JWT 令牌、重放保护、受众、接收方、生命周期与签名校验，以及最小化的联合元数据文档。
//
// # YD router usage | YD 路由用法
//
//	sts, _ := wsfed.NewSecurityTokenService(wsfed.STSConfig{
//		Issuer:        "https://sts.example.com/",
//		Authenticator: myAuthenticator,
//		AllowedRealms: []string{"https://app.example.com/"},
//	})
//	r := router.New()
//	sts.Register(r, "/adfs")
//
// # Native net/http usage | 原生 net/http 用法
//
//	mux := http.NewServeMux()
//	mux.Handle("/adfs/", sts.HTTPHandler("/adfs"))
//	http.ListenAndServe(":8080", mux)
//
// Relying parties follow the same shape with RelyingParty.Register and RelyingParty.HTTPHandler. |
// 依赖方使用相同形式，通过 RelyingParty.Register 与 RelyingParty.HTTPHandler 挂载。
package wsfed

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Action values carried by the wa parameter. | wa 参数携带的动作取值。
const (
	// ActionSignIn is the sign-in action value. | ActionSignIn 是登录动作取值。
	ActionSignIn = "wsignin1.0"
	// ActionSignOut is the sign-out action value. | ActionSignOut 是登出动作取值。
	ActionSignOut = "wsignout1.0"
	// ActionSignOutCleanup is the sign-out cleanup action value. | ActionSignOutCleanup 是登出清理动作取值。
	ActionSignOutCleanup = "wsignoutcleanup1.0"
)

// WS-Federation parameter names. | WS-Federation 参数名。
const (
	// ParamWA is the wa parameter. | ParamWA 是 wa 参数。
	ParamWA = "wa"
	// ParamWtrealm is the wtrealm parameter. | ParamWtrealm 是 wtrealm 参数。
	ParamWtrealm = "wtrealm"
	// ParamWreply is the wreply parameter. | ParamWreply 是 wreply 参数。
	ParamWreply = "wreply"
	// ParamWctx is the wctx parameter. | ParamWctx 是 wctx 参数。
	ParamWctx = "wctx"
	// ParamWct is the wct parameter. | ParamWct 是 wct 参数。
	ParamWct = "wct"
	// ParamWhr is the whr parameter. | ParamWhr 是 whr 参数。
	ParamWhr = "whr"
	// ParamWfresh is the wfresh parameter. | ParamWfresh 是 wfresh 参数。
	ParamWfresh = "wfresh"
	// ParamWauth is the wauth parameter. | ParamWauth 是 wauth 参数。
	ParamWauth = "wauth"
	// ParamWP is the wp parameter. | ParamWP 是 wp 参数。
	ParamWP = "wp"
	// ParamWresult is the wresult parameter carrying the WS-Trust response XML. | ParamWresult 是携带
	// WS-Trust 响应 XML 的 wresult 参数。
	ParamWresult = "wresult"
)

// Security token types. | 安全令牌类型。
const (
	// TokenTypeSAML11 is the SAML 1.1 assertion token type. | TokenTypeSAML11 是 SAML 1.1 断言令牌类型。
	TokenTypeSAML11 = "urn:oasis:names:tc:SAML:1.0:assertion"
	// TokenTypeSAML20 is the SAML 2.0 assertion token type. | TokenTypeSAML20 是 SAML 2.0 断言令牌类型。
	TokenTypeSAML20 = "urn:oasis:names:tc:SAML:2.0:assertion"
	// TokenTypeJWT is the JWT token type. | TokenTypeJWT 是 JWT 令牌类型。
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
)

// XML namespaces used by WS-Federation and WS-Trust. | WS-Federation 与 WS-Trust 使用的 XML 命名空间。
const (
	// NamespaceWSTrust is the WS-Trust 1.3 namespace. | NamespaceWSTrust 是 WS-Trust 1.3 命名空间。
	NamespaceWSTrust = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	// NamespaceWSTrust2005 is the WS-Trust 2005 namespace used by ADFS 1.x. | NamespaceWSTrust2005 是
	// ADFS 1.x 使用的 WS-Trust 2005 命名空间。
	NamespaceWSTrust2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	// NamespaceWSFed is the WS-Federation 1.2 namespace. | NamespaceWSFed 是 WS-Federation 1.2 命名空间。
	NamespaceWSFed = "http://docs.oasis-open.org/wsfed/federation/200706"
	// NamespaceWSAddressing is the WS-Addressing 1.0 namespace. | NamespaceWSAddressing 是
	// WS-Addressing 1.0 命名空间。
	NamespaceWSAddressing = "http://www.w3.org/2005/08/addressing"
	// NamespaceWSSecurity is the WS-Security 1.0 security-token namespace. | NamespaceWSSecurity 是
	// WS-Security 1.0 安全令牌命名空间。
	NamespaceWSSecurity = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	// NamespaceWSU is the WS-Security utility namespace. | NamespaceWSU 是 WS-Security 工具命名空间。
	NamespaceWSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	// NamespaceSAML11 is the SAML 1.1 assertion namespace. | NamespaceSAML11 是 SAML 1.1 断言命名空间。
	NamespaceSAML11 = "urn:oasis:names:tc:SAML:1.0:assertion"
	// NamespaceSAML20 is the SAML 2.0 assertion namespace. | NamespaceSAML20 是 SAML 2.0 断言命名空间。
	NamespaceSAML20 = "urn:oasis:names:tc:SAML:2.0:assertion"
	// NamespaceXMLSchemaInstance is the XML Schema instance namespace. | NamespaceXMLSchemaInstance 是
	// XML Schema 实例命名空间。
	NamespaceXMLSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance"
)

// WS-Trust request types, status values and token reference value types. | WS-Trust 请求类型、状态值与
// 令牌引用的值类型。
const (
	// RequestTypeIssue is the WS-Trust Issue request type. | RequestTypeIssue 是 WS-Trust Issue 请求类型。
	RequestTypeIssue = NamespaceWSTrust + "/Issue"
	// RequestTypeCancel is the WS-Trust Cancel request type. | RequestTypeCancel 是 WS-Trust Cancel 请求类型。
	RequestTypeCancel = NamespaceWSTrust + "/Cancel"
	// StatusSuccess is the WS-Trust success status code. | StatusSuccess 是 WS-Trust 成功状态码。
	StatusSuccess = NamespaceWSTrust + "/status/success"
	// StatusFailure is the WS-Trust failure status code. | StatusFailure 是 WS-Trust 失败状态码。
	StatusFailure = NamespaceWSTrust + "/status/failure"
	// ValueTypeSAMLV20 is the SAML 2.0 token reference value type. | ValueTypeSAMLV20 是 SAML 2.0
	// 令牌引用值类型。
	ValueTypeSAMLV20 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
	// ValueTypeSAMLV11 is the SAML 1.1 token reference value type. | ValueTypeSAMLV11 是 SAML 1.1
	// 令牌引用值类型。
	ValueTypeSAMLV11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
)

// Fault codes used by this package. | 本包使用的故障码。
const (
	// FaultCodeInvalidRequest reports a malformed request. | FaultCodeInvalidRequest 表示请求非法。
	FaultCodeInvalidRequest = "InvalidRequest"
	// FaultCodeAuthenticationFailed reports a failed authentication. | FaultCodeAuthenticationFailed
	// 表示认证失败。
	FaultCodeAuthenticationFailed = "AuthenticationFailed"
	// FaultCodeAccessDenied reports a denied relying party. | FaultCodeAccessDenied 表示依赖方被拒绝。
	FaultCodeAccessDenied = "AccessDenied"
	// FaultCodeServerError reports a server-side failure. | FaultCodeServerError 表示服务端失败。
	FaultCodeServerError = "ServerError"
)

// MaxRequestBytes is the maximum accepted request body size. | MaxRequestBytes 是接受的最大请求正文大小。
const MaxRequestBytes = 1 << 20

// The declared sentinels of this package. | 本包的哨兵错误声明。
var (
	// ErrInvalidConfig reports a missing or contradictory configuration. | ErrInvalidConfig 表示配置缺失或矛盾。
	ErrInvalidConfig = errs.New("wsfed: invalid configuration | wsfed：配置非法")
	// ErrInvalidRequest reports a malformed WS-Federation request. | ErrInvalidRequest 表示 WS-Federation 请求非法。
	ErrInvalidRequest = errs.New("wsfed: invalid request | wsfed：请求非法")
	// ErrInvalidResponse reports a malformed WS-Federation response. | ErrInvalidResponse 表示 WS-Federation 响应非法。
	ErrInvalidResponse = errs.New("wsfed: invalid response | wsfed：响应非法")
	// ErrInvalidSignature reports a missing or invalid XML signature. | ErrInvalidSignature 表示缺失或无效的 XML 签名。
	ErrInvalidSignature = errs.New("wsfed: invalid signature | wsfed：签名无效")
	// ErrInvalidIssuer reports an issuer mismatch. | ErrInvalidIssuer 表示签发方不匹配。
	ErrInvalidIssuer = errs.New("wsfed: issuer mismatch | wsfed：签发方不匹配")
	// ErrInvalidAudience reports an audience mismatch. | ErrInvalidAudience 表示受众不匹配。
	ErrInvalidAudience = errs.New("wsfed: audience mismatch | wsfed：受众不匹配")
	// ErrInvalidRecipient reports a recipient or reply URL mismatch. | ErrInvalidRecipient 表示接收方或回复 URL 不匹配。
	ErrInvalidRecipient = errs.New("wsfed: recipient mismatch | wsfed：接收方不匹配")
	// ErrInvalidRealm reports a relying party realm that the STS does not trust. | ErrInvalidRealm 表示
	// STS 不信任的依赖方领域。
	ErrInvalidRealm = errs.New("wsfed: realm is not allowed | wsfed：领域不被允许")
	// ErrResponseExpired reports an assertion past its expiry. | ErrResponseExpired 表示断言超过过期时间。
	ErrResponseExpired = errs.New("wsfed: response expired | wsfed：响应已过期")
	// ErrResponseNotYetValid reports an assertion before its NotBefore time. | ErrResponseNotYetValid
	// 表示断言早于 NotBefore 时间。
	ErrResponseNotYetValid = errs.New("wsfed: response not yet valid | wsfed：响应尚未生效")
	// ErrReplay reports a replayed assertion or request. | ErrReplay 表示断言或请求重放。
	ErrReplay = errs.New("wsfed: replay detected | wsfed：检测到重放")
	// ErrStatusFailure reports a non-success WS-Trust status or fault. | ErrStatusFailure 表示
	// WS-Trust 状态非成功或出现故障。
	ErrStatusFailure = errs.New("wsfed: status failure | wsfed：状态失败")
	// ErrUnsolicited reports a response without a matching outstanding request. | ErrUnsolicited 表示
	// 响应没有匹配的未完成请求。
	ErrUnsolicited = errs.New("wsfed: unsolicited response | wsfed：未请求的响应")
	// ErrNoToken reports a response without a security token. | ErrNoToken 表示响应没有安全令牌。
	ErrNoToken = errs.New("wsfed: no security token | wsfed：没有安全令牌")
	// ErrRequestTooLarge reports a request body over MaxRequestBytes. | ErrRequestTooLarge 表示请求正文
	// 超过 MaxRequestBytes。
	ErrRequestTooLarge = errs.New("wsfed: request body too large | wsfed：请求正文过大")
	// ErrUnsupported reports a feature this build or configuration does not implement. | ErrUnsupported
	// 表示本构建或配置未实现该特性。
	ErrUnsupported = errs.New("wsfed: unsupported | wsfed：不支持")
	// ErrLoginRequired reports that the STS needs an authenticated user. | ErrLoginRequired 表示 STS
	// 需要已认证用户。
	ErrLoginRequired = errs.New("wsfed: login required | wsfed：需要登录")
)

// SignInRequest is a WS-Federation passive sign-in request. | SignInRequest 是 WS-Federation 被动登录请求。
type SignInRequest struct {
	// WA is the action value. | WA 是动作取值。
	WA string
	// Wtrealm is the relying party realm. | Wtrealm 是依赖方领域。
	Wtrealm string
	// Wreply is the reply URL that receives the result. | Wreply 是接收结果的回复 URL。
	Wreply string
	// Wctx is the opaque context returned to the relying party. | Wctx 是返回给依赖方的不透明上下文。
	Wctx string
	// Wct is the client time hint. | Wct 是客户端时间提示。
	Wct string
	// Whr is the home realm hint. | Whr 是主领域提示。
	Whr string
	// Wfresh requests a maximum authentication age in minutes, or "0" for forced re-authentication. |
	// Wfresh 请求最大认证时长（分钟），或为 "0" 表示强制重新认证。
	Wfresh string
	// Wauth requests an authentication method. | Wauth 请求认证方法。
	Wauth string
	// WP is the request policy. | WP 是请求策略。
	WP string
}

// SignOutRequest is a WS-Federation passive sign-out or sign-out cleanup request. | SignOutRequest 是
// WS-Federation 被动登出或登出清理请求。
type SignOutRequest struct {
	// WA is the action value. | WA 是动作取值。
	WA string
	// Wtrealm is the relying party realm. | Wtrealm 是依赖方领域。
	Wtrealm string
	// Wreply is the URL that receives the sign-out result. | Wreply 是接收登出结果的 URL。
	Wreply string
	// Wctx is the opaque context returned to the relying party. | Wctx 是返回给依赖方的不透明上下文。
	Wctx string
}

// ParseSignInRequest parses a sign-in request from the query string or a form body. | ParseSignInRequest
// 从查询串或表单正文解析登录请求。
func ParseSignInRequest(r *http.Request) (*SignInRequest, error) {
	values, err := requestValues(r)
	if err != nil {
		return nil, err
	}
	return signInRequestFromValues(values)
}

// signInRequestFromValues builds a sign-in request from parsed values. | signInRequestFromValues 从
// 已解析的值构建登录请求。
func signInRequestFromValues(values url.Values) (*SignInRequest, error) {
	request := &SignInRequest{
		WA:      strings.TrimSpace(values.Get(ParamWA)),
		Wtrealm: strings.TrimSpace(values.Get(ParamWtrealm)),
		Wreply:  strings.TrimSpace(values.Get(ParamWreply)),
		Wctx:    values.Get(ParamWctx),
		Wct:     strings.TrimSpace(values.Get(ParamWct)),
		Whr:     strings.TrimSpace(values.Get(ParamWhr)),
		Wfresh:  strings.TrimSpace(values.Get(ParamWfresh)),
		Wauth:   strings.TrimSpace(values.Get(ParamWauth)),
		WP:      strings.TrimSpace(values.Get(ParamWP)),
	}
	if request.WA == "" {
		request.WA = ActionSignIn
	}
	if request.WA != ActionSignIn {
		return nil, errs.Detail(ErrInvalidRequest, "wa %[1]q is not %[2]q | wa %[1]q 不是 %[2]q", request.WA, ActionSignIn)
	}
	if request.Wtrealm == "" {
		return nil, errs.Detail(ErrInvalidRequest, "wtrealm is missing | 缺少 wtrealm")
	}
	return request, nil
}

// ParseSignOutRequest parses a sign-out or sign-out cleanup request from the query string or a form
// body. | ParseSignOutRequest 从查询串或表单正文解析登出或登出清理请求。
func ParseSignOutRequest(r *http.Request) (*SignOutRequest, error) {
	values, err := requestValues(r)
	if err != nil {
		return nil, err
	}
	return signOutRequestFromValues(values)
}

// signOutRequestFromValues builds a sign-out request from parsed values. | signOutRequestFromValues
// 从已解析的值构建登出请求。
func signOutRequestFromValues(values url.Values) (*SignOutRequest, error) {
	request := &SignOutRequest{
		WA:      strings.TrimSpace(values.Get(ParamWA)),
		Wtrealm: strings.TrimSpace(values.Get(ParamWtrealm)),
		Wreply:  strings.TrimSpace(values.Get(ParamWreply)),
		Wctx:    values.Get(ParamWctx),
	}
	if request.WA == "" {
		request.WA = ActionSignOut
	}
	if request.WA != ActionSignOut && request.WA != ActionSignOutCleanup {
		return nil, errs.Detail(ErrInvalidRequest, "wa %[1]q is not a sign-out action | wa %[1]q 不是登出动作", request.WA)
	}
	return request, nil
}

// URL builds the sign-in request URL on base. | URL 在 base 上构建登录请求 URL。
func (req SignInRequest) URL(base string) (string, error) {
	wa := req.WA
	if wa == "" {
		wa = ActionSignIn
	}
	if wa != ActionSignIn {
		return "", errs.Detail(ErrInvalidRequest, "wa %[1]q is not %[2]q | wa %[1]q 不是 %[2]q", wa, ActionSignIn)
	}
	if req.Wtrealm == "" {
		return "", errs.Detail(ErrInvalidRequest, "wtrealm is missing | 缺少 wtrealm")
	}
	values := url.Values{ParamWA: {wa}, ParamWtrealm: {req.Wtrealm}}
	setIfNotEmpty(values, ParamWreply, req.Wreply)
	setIfNotEmpty(values, ParamWctx, req.Wctx)
	setIfNotEmpty(values, ParamWct, req.Wct)
	setIfNotEmpty(values, ParamWhr, req.Whr)
	setIfNotEmpty(values, ParamWfresh, req.Wfresh)
	setIfNotEmpty(values, ParamWauth, req.Wauth)
	setIfNotEmpty(values, ParamWP, req.WP)
	return appendQuery(base, values)
}

// URL builds the sign-out request URL on base. | URL 在 base 上构建登出请求 URL。
func (req SignOutRequest) URL(base string) (string, error) {
	wa := req.WA
	if wa == "" {
		wa = ActionSignOut
	}
	if wa != ActionSignOut && wa != ActionSignOutCleanup {
		return "", errs.Detail(ErrInvalidRequest, "wa %[1]q is not a sign-out action | wa %[1]q 不是登出动作", wa)
	}
	values := url.Values{ParamWA: {wa}}
	setIfNotEmpty(values, ParamWtrealm, req.Wtrealm)
	setIfNotEmpty(values, ParamWreply, req.Wreply)
	setIfNotEmpty(values, ParamWctx, req.Wctx)
	return appendQuery(base, values)
}

// setIfNotEmpty sets key to value when value is non-empty. | setIfNotEmpty 在 value 非空时设置 key。
func setIfNotEmpty(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

// appendQuery merges values into the query string of base. | appendQuery 把 values 合并到 base 的查询串。
func appendQuery(base string, values url.Values) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", errs.Detail(ErrInvalidConfig, "base URL is empty | 基础 URL 为空")
	}
	location, err := url.Parse(base)
	if err != nil {
		return "", errs.WrapDetail(err, ErrInvalidConfig, "base URL %[1]q | 基础 URL %[1]q", base)
	}
	query := location.Query()
	for key, val := range values {
		query.Set(key, val[0])
	}
	location.RawQuery = query.Encode()
	return location.String(), nil
}

// requestValues reads the query string and a form body, preferring body values. | requestValues 读取
// 查询串与表单正文，正文值优先。
func requestValues(r *http.Request) (url.Values, error) {
	if r == nil {
		return nil, errs.Detail(ErrInvalidRequest, "request is nil | 请求为空")
	}
	values := make(url.Values)
	for key, list := range r.URL.Query() {
		values[key] = append(values[key], list...)
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return values, nil
	}
	if r.ContentLength > MaxRequestBytes {
		return nil, errs.Detail(ErrRequestTooLarge, "content length %[1]d | 正文长度 %[1]d", r.ContentLength)
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(nil, r.Body, MaxRequestBytes)
	}
	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, errs.Detail(ErrRequestTooLarge, "body exceeds %[1]d bytes | 正文超过 %[1]d 字节", MaxRequestBytes)
		}
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	for key, list := range r.PostForm {
		values[key] = append([]string(nil), list...)
	}
	return values, nil
}

// postForm writes an auto-submitting HTML form carrying fields to action. | postForm 写入携带 fields
// 并自动提交到 action 的 HTML 表单。
func postForm(w http.ResponseWriter, action string, fields [][2]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(postFormHTML(action, fields)))
}

// postFormHTML returns the auto-submitting form markup. | postFormHTML 返回自动提交表单标记。
func postFormHTML(action string, fields [][2]string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue</title></head><body>")
	b.WriteString("<form id=\"wsfed\" method=\"post\" action=\"")
	b.WriteString(escapeHTML(action))
	b.WriteString("\">")
	for _, field := range fields {
		b.WriteString("<input type=\"hidden\" name=\"")
		b.WriteString(escapeHTML(field[0]))
		b.WriteString("\" value=\"")
		b.WriteString(escapeHTML(field[1]))
		b.WriteString("\">")
	}
	b.WriteString("</form><script>document.getElementById('wsfed').submit()</script></body></html>")
	return b.String()
}

// escapeHTML escapes value for HTML text and attribute context. | escapeHTML 为 HTML 文本与属性上下文转义 value。
func escapeHTML(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&#34;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// joinPath joins a mount prefix and an endpoint path. | joinPath 连接挂载前缀与端点路径。
func joinPath(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if prefix == "/" {
		if strings.HasPrefix(path, "/") {
			return path
		}
		return "/" + path
	}
	prefix = strings.TrimRight(prefix, "/")
	if path == "" {
		return prefix
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return prefix + path
}
