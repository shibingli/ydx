package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// ParseAuthorizationRequest normalizes an authorization-endpoint request. | ParseAuthorizationRequest
// 规范化授权端点请求。
//
// It reads GET query parameters or an application/x-www-form-urlencoded POST body, resolves the
// client, and validates the response type, redirect URI, scope syntax, PKCE pair, response mode,
// prompt list, max_age, resource indicators and request-object parameters. Policy decisions such as
// "PKCE is mandatory" remain in Server. | 它读取 GET 查询参数或
// application/x-www-form-urlencoded POST 正文，解析客户端，并校验响应类型、重定向 URI、作用域
// 语法、PKCE 组合、响应模式、prompt 列表、max_age、资源指示器与请求对象参数。“PKCE 是否强制”
// 等策略判断仍由 Server 完成。
func ParseAuthorizationRequest(r *http.Request, clients ClientStore, scopes ScopeRegistry) (*AuthorizationRequest, error) {
	if r == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil request | 请求为空")
	}
	return ParseAuthorizationRequestContext(r.Context(), r, clients, scopes)
}

// ParseAuthorizationRequestContext is ParseAuthorizationRequest with an explicit context. | ParseAuthorizationRequestContext
// 是带显式上下文的 ParseAuthorizationRequest。
func ParseAuthorizationRequestContext(ctx context.Context, r *http.Request, clients ClientStore, scopes ScopeRegistry) (*AuthorizationRequest, error) {
	if r == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil request | 请求为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var raw url.Values
	switch r.Method {
	case http.MethodGet:
		raw = r.URL.Query()
	case http.MethodPost:
		contentType := r.Header.Get("Content-Type")
		if !strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
			return nil, errs.Detail(ErrInvalidRequest, "authorization POST requires application/x-www-form-urlencoded | 授权 POST 需要 application/x-www-form-urlencoded")
		}
		if err := r.ParseForm(); err != nil {
			return nil, errs.Wrap(err, ErrInvalidRequest)
		}
		raw = r.PostForm
	default:
		return nil, errs.Detail(ErrInvalidRequest, "method %[1]s is not allowed | 不允许方法 %[1]s", r.Method)
	}
	return parseAuthorizationValues(ctx, raw, clients, scopes)
}

// parseAuthorizationValues validates already parsed authorization parameters. | parseAuthorizationValues
// 校验已解析的授权参数。
func parseAuthorizationValues(ctx context.Context, raw url.Values, clients ClientStore, scopes ScopeRegistry) (*AuthorizationRequest, error) {
	if len(raw) == 0 {
		return nil, errs.Detail(ErrInvalidRequest, "no authorization parameters | 缺少授权参数")
	}
	clientID := strings.TrimSpace(raw.Get("client_id"))
	if clientID == "" {
		return nil, errs.Detail(ErrInvalidRequest, "client_id is required | client_id 必填")
	}
	if clients == nil {
		return nil, errs.Detail(ErrInvalidConfig, "client store is nil | 客户端存储为空")
	}
	client, err := clients.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	redirectURI := strings.TrimSpace(raw.Get("redirect_uri"))
	if redirectURI == "" {
		if len(client.RedirectURIs) != 1 {
			return nil, errs.Detail(ErrInvalidRequest, "redirect_uri is required | redirect_uri 必填")
		}
		redirectURI = client.RedirectURIs[0]
	}
	if !client.AllowsRedirect(redirectURI) {
		return nil, errs.Detail(ErrInvalidRequest, "redirect_uri is not registered | redirect_uri 未注册")
	}
	responseType, err := canonicalResponseType(raw.Get("response_type"))
	if err != nil {
		return nil, err
	}
	if len(client.ResponseTypes) > 0 && !client.AllowsResponseType(responseType) {
		return nil, errs.Detail(ErrUnsupportedResponseType, "response_type %[1]q is not registered | response_type %[1]q 未注册", responseType)
	}
	requestedScopes := ParseScope(raw.Get("scope"))
	if len(requestedScopes) == 0 && len(client.Scopes) > 0 {
		requestedScopes = append([]string(nil), client.Scopes...)
	}
	if scopes != nil {
		requestedScopes, err = scopes.Validate(requestedScopes, client)
		if err != nil {
			return nil, err
		}
	} else {
		for _, scope := range requestedScopes {
			if !client.AllowsScope(scope) {
				return nil, errs.Detail(ErrInvalidScope, "scope %[1]q is not allowed | 不允许作用域 %[1]q", scope)
			}
		}
	}
	challenge := strings.TrimSpace(raw.Get("code_challenge"))
	method := strings.TrimSpace(raw.Get("code_challenge_method"))
	if challenge == "" && method != "" {
		return nil, errs.Detail(ErrInvalidRequest, "code_challenge_method without code_challenge | 有 code_challenge_method 但无 code_challenge")
	}
	if challenge != "" {
		if err := ValidCodeChallenge(challenge, method); err != nil {
			return nil, err
		}
		method = NormalizePKCEMethod(method)
	}
	responseMode := strings.TrimSpace(raw.Get("response_mode"))
	if responseMode == "" {
		responseMode = defaultResponseMode(responseType)
	}
	if !validResponseMode(responseMode, responseType) {
		return nil, errs.Detail(ErrInvalidRequest, "response_mode %[1]q is not allowed | 不允许 response_mode %[1]q", responseMode)
	}
	prompt, err := parsePrompt(raw.Get("prompt"))
	if err != nil {
		return nil, err
	}
	var maxAge *int
	if value := raw.Get("max_age"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return nil, errs.Detail(ErrInvalidRequest, "max_age must be a non-negative integer | max_age 必须是非负整数")
		}
		maxAge = &n
	}
	resources, err := parseResources(raw["resource"])
	if err != nil {
		return nil, err
	}
	requestObject := raw.Get("request")
	requestURI := raw.Get("request_uri")
	if requestObject != "" {
		// This standalone parser has no issuer, replay store or verification policy, so it cannot
		// validate a signed request object. Server.Authorize resolves and verifies RFC 9101
		// objects before calling this parser; rejecting here keeps a direct caller from acting on
		// unverified signed parameters. | 该独立解析器没有签发方、重放存储与校验策略，无法校验
		// 已签名请求对象。Server.Authorize 在调用本解析器前已解析并校验 RFC 9101 对象；此处拒绝
		// 可避免直接调用方按未校验的已签名参数执行。
		return nil, NewError(ErrorRequestNotSupported, "request objects require Server.Authorize | 请求对象需经 Server.Authorize 校验")
	}
	if len(requestURI) > 64<<10 {
		return nil, errs.Detail(ErrInvalidRequest, "request_uri is too large | request_uri 过大")
	}
	return &AuthorizationRequest{
		ClientID:            clientID,
		ResponseType:        responseType,
		RedirectURI:         redirectURI,
		Scopes:              requestedScopes,
		State:               raw.Get("state"),
		Nonce:               raw.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ResponseMode:        responseMode,
		Prompt:              prompt,
		MaxAge:              maxAge,
		LoginHint:           raw.Get("login_hint"),
		IDTokenHint:         raw.Get("id_token_hint"),
		ACRValues:           strings.Fields(raw.Get("acr_values")),
		UILocales:           strings.Fields(raw.Get("ui_locales")),
		Claims:              raw.Get("claims"),
		Resource:            resources,
		Request:             requestObject,
		RequestURI:          requestURI,
		Raw:                 cloneValues(raw),
		Client:              client,
	}, nil
}

// canonicalResponseType normalizes and validates a response_type value. | canonicalResponseType
// 规范化并校验 response_type 取值。
func canonicalResponseType(raw string) (string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		// RFC 6749 section 4.1.1 makes response_type REQUIRED; guessing "code" would make the
		// server act on a parameter the client never sent. | RFC 6749 第 4.1.1 节规定
		// response_type 必填；猜测为 "code" 会让服务器按客户端从未发送的参数执行。
		return "", errs.Detail(ErrInvalidRequest, "response_type is required | response_type 必填")
	}
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		switch field {
		case ResponseCode, ResponseToken, ResponseIDToken, ResponseNone:
		default:
			return "", errs.Detail(ErrUnsupportedResponseType, "unknown response_type %[1]q | 未知 response_type %[1]q", field)
		}
		if seen[field] {
			return "", errs.Detail(ErrInvalidRequest, "duplicate response_type %[1]q | 重复的 response_type %[1]q", field)
		}
		seen[field] = true
		out = append(out, field)
	}
	if seen[ResponseNone] && len(seen) > 1 {
		return "", errs.Detail(ErrInvalidRequest, "response_type none cannot be combined | response_type none 不能组合")
	}
	sort.Strings(out)
	return strings.Join(out, " "), nil
}

// responseTypeHas reports whether a canonical response type contains token. | responseTypeHas 报告规范响应类型是否包含 token。
func responseTypeHas(responseType, token string) bool {
	for _, field := range strings.Fields(responseType) {
		if field == token {
			return true
		}
	}
	return false
}

// defaultResponseMode returns the RFC 6749 default for a response type. | defaultResponseMode 返回 RFC 6749 默认响应模式。
func defaultResponseMode(responseType string) string {
	if responseTypeHas(responseType, ResponseCode) && !responseTypeHas(responseType, ResponseToken) && !responseTypeHas(responseType, ResponseIDToken) {
		return ResponseModeQuery
	}
	if responseType == ResponseNone {
		return ResponseModeQuery
	}
	return ResponseModeFragment
}

// validResponseMode reports whether mode is legal for responseType. | validResponseMode 报告 mode 对 responseType 是否合法。
func validResponseMode(mode, responseType string) bool {
	switch mode {
	case ResponseModeQuery:
		// OAuth 2.0 Multiple Response Type Encoding Practices forbids query responses that carry
		// tokens. Only a bare code or none response may use the query encoding. | OAuth 2.0 多响应
		// 类型编码实践禁止通过 query 返回任何令牌；只有纯 code 或 none 响应可用 query。
		return responseType == ResponseCode || responseType == ResponseNone
	case ResponseModeFragment:
		return responseTypeHas(responseType, ResponseToken) || responseTypeHas(responseType, ResponseIDToken)
	case ResponseModeFormPost:
		return true
	case ResponseModeQueryJWT:
		// JARM mirrors the query encoding restrictions. | JARM 沿用 query 编码限制。
		return responseType == ResponseCode || responseType == ResponseNone
	case ResponseModeFragmentJWT:
		// JARM places no response-type restriction on fragment.jwt. | JARM 不限制 fragment.jwt
		// 的响应类型。
		return true
	case ResponseModeFormPostJWT:
		return true
	case ResponseModeJWT:
		// The jwt mode selects query.jwt for a bare code or none response and fragment.jwt for the
		// implicit and hybrid responses. | jwt 模式为纯 code 或 none 响应选择 query.jwt，为隐式与混合
		// 响应选择 fragment.jwt。
		if responseType == ResponseCode || responseType == ResponseNone {
			return true
		}
		return responseTypeHas(responseType, ResponseToken) || responseTypeHas(responseType, ResponseIDToken)
	default:
		return false
	}
}

// jarmBaseMode maps a JARM response mode to the delivery encoding it uses. | jarmBaseMode 把 JARM
// 响应模式映射为其使用的投递编码。
func jarmBaseMode(mode, responseType string) (string, bool) {
	switch mode {
	case ResponseModeQueryJWT:
		return ResponseModeQuery, true
	case ResponseModeFragmentJWT:
		return ResponseModeFragment, true
	case ResponseModeFormPostJWT:
		return ResponseModeFormPost, true
	case ResponseModeJWT:
		if responseType == ResponseCode || responseType == ResponseNone {
			return ResponseModeQuery, true
		}
		return ResponseModeFragment, true
	default:
		return mode, false
	}
}

// parsePrompt validates and deduplicates the prompt parameter. | parsePrompt 校验并去重 prompt 参数。
func parsePrompt(raw string) ([]string, error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		switch field {
		case "none", "login", "consent", "select_account":
		default:
			return nil, errs.Detail(ErrInvalidRequest, "unknown prompt %[1]q | 未知 prompt %[1]q", field)
		}
		if seen[field] {
			continue
		}
		seen[field] = true
		out = append(out, field)
	}
	if seen["none"] && len(out) > 1 {
		return nil, errs.Detail(ErrInvalidRequest, "prompt none cannot be combined | prompt none 不能组合")
	}
	return out, nil
}

// parseResources validates RFC 8707 resource indicators. | parseResources 校验 RFC 8707 资源指示器。
func parseResources(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment != "" {
			return nil, errs.Detail(ErrInvalidTarget, "invalid resource %[1]q | 非法资源 %[1]q", value)
		}
		seen[value] = true
		out = append(out, value)
	}
	return out, nil
}
