package federation

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

const (
	// maxProviderResponse limits provider bodies to one mebibyte. | maxProviderResponse 把提供方响应限制为 1 MiB。
	maxProviderResponse = 1 << 20
	// defaultUserAgent identifies federation requests. | defaultUserAgent 标识联合登录请求。
	defaultUserAgent = "ydx-auth-federation/1.0"
)

// errInvalidJSON reports a malformed provider JSON body. | errInvalidJSON 表示提供方 JSON 体格式非法。
var errInvalidJSON = errs.New("federation: invalid JSON body | federation：JSON 体非法")

// defaultHTTPClient returns the package HTTP client used when none is configured.
// defaultHTTPClient 返回未配置时使用的包级 HTTP 客户端。
func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

// clientFor returns the provider client, then the broker fallback, then the default.
// clientFor 依次返回提供方客户端、代理回退客户端与默认客户端。
func clientFor(p *Provider, fallback *http.Client) *http.Client {
	if p != nil && p.HTTPClient != nil {
		return p.HTTPClient
	}
	if fallback != nil {
		return fallback
	}
	return defaultHTTPClient()
}

// doRequest sends one provider request without exposing the URL in transport errors.
// doRequest 发送单个提供方请求，且不在传输错误中暴露 URL。
func doRequest(ctx context.Context, client *http.Client, method, endpoint string, body []byte, contentType string, headers map[string]string) (int, []byte, error) {
	if client == nil {
		client = defaultHTTPClient()
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, nil, errs.Detail(ErrTransport, "cannot build provider request | 无法构建提供方请求")
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		// The raw url.Error carries the endpoint, so it is never exposed. The
		// context cause is safe to keep and lets callers detect cancellation. |
		// 原始 url.Error 含有端点，因此绝不暴露；上下文原因可安全保留，使调用方能
		// 识别取消。
		if cause := ctx.Err(); cause != nil {
			return 0, nil, errs.WrapDetail(cause, ErrTransport, "provider request failed | 提供方请求失败")
		}
		return 0, nil, errs.Detail(ErrTransport, "provider request failed | 提供方请求失败")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse+1))
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return 0, nil, errs.WrapDetail(cause, ErrTransport, "cannot read provider response | 无法读取提供方响应")
		}
		return 0, nil, errs.Detail(ErrTransport, "cannot read provider response | 无法读取提供方响应")
	}
	if len(data) > maxProviderResponse {
		return 0, nil, errs.Detail(ErrTransport, "provider response is too large | 提供方响应过大")
	}
	return resp.StatusCode, data, nil
}

// getProvider sends a GET request. | getProvider 发送 GET 请求。
func getProvider(ctx context.Context, client *http.Client, endpoint string, headers map[string]string) (int, []byte, error) {
	return doRequest(ctx, client, http.MethodGet, endpoint, nil, "", headers)
}

// postForm sends an application/x-www-form-urlencoded request. | postForm 发送 application/x-www-form-urlencoded 请求。
func postForm(ctx context.Context, client *http.Client, endpoint string, values url.Values, headers map[string]string) (int, []byte, error) {
	return doRequest(ctx, client, http.MethodPost, endpoint, []byte(values.Encode()), "application/x-www-form-urlencoded", headers)
}

// postJSON sends an application/json request. | postJSON 发送 application/json 请求。
func postJSON(ctx context.Context, client *http.Client, endpoint string, payload any, headers map[string]string) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, errs.Detail(ErrTransport, "cannot encode provider request | 无法编码提供方请求")
	}
	return doRequest(ctx, client, http.MethodPost, endpoint, body, "application/json", headers)
}

// parseJSONObject decodes a JSON object while preserving number text. | parseJSONObject
// 在保留数字文本的前提下解码 JSON 对象。
func parseJSONObject(body []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errInvalidJSON
	}
	// Some QQ endpoints wrap JSON in a JavaScript callback even with fmt=json.
	// QQ 部分端点即使指定 fmt=json 也可能把 JSON 包在 JavaScript 回调中。
	if trimmed[0] != '{' {
		start := bytes.IndexByte(trimmed, '{')
		end := bytes.LastIndexByte(trimmed, '}')
		if start >= 0 && end > start {
			trimmed = trimmed[start : end+1]
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil || raw == nil {
		return nil, errInvalidJSON
	}
	return raw, nil
}

// parseFormObject parses a form-encoded body into scalar values. | parseFormObject
// 把表单编码响应解析为标量取值。
func parseFormObject(body []byte) (map[string]any, error) {
	values, err := url.ParseQuery(strings.TrimSpace(string(body)))
	if err != nil || len(values) == 0 {
		return nil, errInvalidJSON
	}
	raw := make(map[string]any, len(values))
	for key, items := range values {
		if len(items) > 0 {
			raw[key] = items[0]
		}
	}
	return raw, nil
}

// tokenFromBody parses a JSON or form token response and normalizes common fields.
// tokenFromBody 解析 JSON 或表单令牌响应并规范化常见字段。
func tokenFromBody(body []byte, now time.Time) (*Token, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errs.Detail(ErrTokenExchange, "empty token response | 令牌响应为空")
	}
	var raw map[string]any
	var err error
	if trimmed[0] == '{' || bytes.IndexByte(trimmed, '{') >= 0 {
		raw, err = parseJSONObject(trimmed)
	} else {
		raw, err = parseFormObject(trimmed)
	}
	if err != nil {
		return nil, errs.Detail(ErrTokenExchange, "invalid token response | 令牌响应非法")
	}
	return tokenFromMap(raw, now)
}

// tokenFromMap normalizes a token response map. | tokenFromMap 规范化令牌响应映射。
func tokenFromMap(raw map[string]any, now time.Time) (*Token, error) {
	if raw == nil {
		return nil, errs.Detail(ErrTokenExchange, "empty token response | 令牌响应为空")
	}
	if code := providerErrorCode(raw); code != "" {
		return nil, errs.Detail(ErrTokenExchange, "provider returned %s | 提供方返回 %s", code, code)
	}
	if _, ok := raw["access_token"]; !ok {
		if _, camel := raw["accessToken"]; !camel {
			if nested, ok := raw["data"].(map[string]any); ok {
				raw = nested
				if code := providerErrorCode(raw); code != "" {
					return nil, errs.Detail(ErrTokenExchange, "provider returned %s | 提供方返回 %s", code, code)
				}
			}
		}
	}
	token := &Token{
		AccessToken:  firstStringValue(raw, "access_token", "accessToken"),
		TokenType:    firstStringValue(raw, "token_type", "tokenType"),
		RefreshToken: firstStringValue(raw, "refresh_token", "refreshToken"),
		Scope:        firstStringValue(raw, "scope"),
		IDToken:      firstStringValue(raw, "id_token", "idToken"),
		OpenID:       firstStringValue(raw, "openid", "openId"),
		UnionID:      firstStringValue(raw, "unionid", "unionId"),
		Raw:          stringMap(raw),
	}
	token.ExpiresIn = firstIntValue(raw, "expires_in", "expiresIn", "expire_in", "expireIn")
	if token.TokenType == "" {
		token.TokenType = "Bearer"
	}
	token.SetExpiry(now)
	if token.AccessToken == "" {
		return nil, errs.Detail(ErrTokenExchange, "token response has no access token | 令牌响应缺少访问令牌")
	}
	return token, nil
}

// providerErrorCode extracts a safe provider error code without descriptions. | providerErrorCode
// 提取安全的提供方错误码，不包含描述文本。
func providerErrorCode(raw map[string]any) string {
	if raw == nil {
		return ""
	}
	if value := stringValue(raw["error"]); value != "" && value != "0" {
		return sanitizeProviderCode(value)
	}
	if value := stringValue(raw["error_code"]); value != "" && value != "0" {
		return sanitizeProviderCode(value)
	}
	if value, ok := raw["errcode"]; ok {
		if code := int64Value(value); code != 0 {
			return strconv.FormatInt(code, 10)
		}
	}
	if value, ok := raw["errno"]; ok {
		if code := int64Value(value); code != 0 {
			return strconv.FormatInt(code, 10)
		}
	}
	return ""
}

// providerCodeZeroAware returns a top-level provider code except the success value "0".
// providerCodeZeroAware 返回顶层提供方错误码，"0" 视为成功而不返回。
func providerCodeZeroAware(value any) string {
	code := stringValue(value)
	if code == "" || code == "0" {
		return ""
	}
	return code
}

// sanitizeProviderCode limits provider error codes to a safe character set. | sanitizeProviderCode
// 把提供方错误码限制在安全字符集内。
func sanitizeProviderCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "error"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			return "error"
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "error"
	}
	return b.String()
}

// firstStringValue returns the first non-empty scalar among keys. | firstStringValue
// 返回 keys 中第一个非空标量。
func firstStringValue(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(raw[key]); value != "" {
			return value
		}
	}
	return ""
}

// firstIntValue returns the first non-zero integer among keys. | firstIntValue 返回 keys 中第一个非零整数。
func firstIntValue(raw map[string]any, keys ...string) int64 {
	for _, key := range keys {
		if value := int64Value(raw[key]); value != 0 {
			return value
		}
	}
	return 0
}

// firstNonEmpty returns the first non-empty string. | firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// stringValue converts a scalar JSON value to text without losing integer precision.
// stringValue 把标量 JSON 值转换为文本，并尽量保留整数精度。
func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(typed), 'f', -1, 32)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case uint:
		return strconv.FormatUint(uint64(typed), 10)
	case interface{ String() string }:
		return typed.String()
	case []string:
		return strings.Join(typed, " ")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := stringValue(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, " ")
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}

// int64Value converts a scalar JSON value to an integer. | int64Value 把标量 JSON 值转换为整数。
func int64Value(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case uint64:
		if typed <= uint64(^uint64(0)>>1) {
			return int64(typed)
		}
	case float64:
		return int64(typed)
	case interface{ String() string }:
		number, _ := strconv.ParseInt(strings.TrimSpace(typed.String()), 10, 64)
		return number
	case string:
		number, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return number
	}
	return 0
}

// boolValue converts common JSON representations of booleans. | boolValue 转换 JSON 中常见的布尔表示。
func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes", "y":
			return true
		}
	case interface{ String() string }:
		return typed.String() == "1"
	case float64:
		return typed == 1
	case int64:
		return typed == 1
	case int:
		return typed == 1
	}
	return false
}

// stringMap converts all top-level values to scalar strings. | stringMap 把所有顶层取值转换为标量字符串。
func stringMap(raw map[string]any) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		if text := stringValue(value); text != "" {
			out[key] = text
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// nestedMap returns a nested object by key. | nestedMap 按键返回嵌套对象。
func nestedMap(raw map[string]any, key string) map[string]any {
	if nested, ok := raw[key].(map[string]any); ok {
		return nested
	}
	return nil
}

// mergeIdentity fills empty identity fields from fallback. | mergeIdentity 用 fallback 填充空身份字段。
func mergeIdentity(identity, fallback *Identity) *Identity {
	if identity == nil {
		return fallback
	}
	if fallback == nil {
		return identity
	}
	if identity.Provider == "" {
		identity.Provider = fallback.Provider
	}
	if identity.Subject == "" {
		identity.Subject = fallback.Subject
	}
	if identity.Email == "" {
		identity.Email = fallback.Email
		identity.EmailVerified = fallback.EmailVerified
	}
	if identity.Username == "" {
		identity.Username = fallback.Username
	}
	if identity.Name == "" {
		identity.Name = fallback.Name
	}
	if identity.AvatarURL == "" {
		identity.AvatarURL = fallback.AvatarURL
	}
	if identity.Raw == nil {
		identity.Raw = make(map[string]string, len(fallback.Raw))
	}
	for key, value := range fallback.Raw {
		if _, exists := identity.Raw[key]; !exists {
			identity.Raw[key] = value
		}
	}
	return identity
}

// identityFromMap maps standard OAuth/OIDC user fields into an Identity. | identityFromMap
// 把标准 OAuth/OIDC 用户字段映射为 Identity。
func identityFromMap(providerName string, raw map[string]any) *Identity {
	identity := &Identity{
		Provider:  providerName,
		Subject:   firstStringValue(raw, "sub", "unionid", "union_id", "unionId", "id", "user_id", "userId", "uid", "openid", "open_id", "openId"),
		Email:     firstStringValue(raw, "email", "mail", "enterprise_email"),
		Username:  firstStringValue(raw, "preferred_username", "login", "username", "user_name"),
		Name:      firstStringValue(raw, "name", "display_name", "displayName", "nickname", "nick", "screen_name", "realname", "user_name", "userName"),
		AvatarURL: firstStringValue(raw, "picture", "avatar_url", "avatarUrl", "avatar", "headimgurl", "portrait", "figureurl_qq_2", "figureurl_2", "profile_image_url", "avatar_large"),
		Raw:       stringMap(raw),
	}
	identity.EmailVerified = boolValue(raw["email_verified"]) || boolValue(raw["emailVerified"]) || boolValue(raw["verified_email"])
	identity.EmailVerified = identity.EmailVerified && identity.Email != ""
	return identity
}

// scopeValue joins scopes with the provider separator. | scopeValue 使用提供方分隔符连接作用域。
func scopeValue(p *Provider) string {
	if p == nil || len(p.Scopes) == 0 {
		return ""
	}
	separator := p.ScopeSeparator
	if separator == "" {
		separator = " "
	}
	return strings.Join(p.Scopes, separator)
}

// setQueryParams sets or deletes query parameters on an endpoint. | setQueryParams
// 在端点上设置或删除查询参数。
func setQueryParams(endpoint string, params map[string]string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errs.Detail(ErrProviderConfig, "invalid provider endpoint | 提供方端点非法")
	}
	query := parsed.Query()
	for key, value := range params {
		if value == "" {
			query.Del(key)
		} else {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// appendQuery appends non-empty query values to an endpoint. | appendQuery 把非空查询值追加到端点。
func appendQuery(endpoint string, params map[string]string) (string, error) {
	return setQueryParams(endpoint, params)
}

// replaceURLPath replaces an endpoint path while preserving scheme and host. | replaceURLPath
// 在保留 scheme 与 host 的前提下替换端点路径。
func replaceURLPath(endpoint, path string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return endpoint
	}
	parsed.Path = path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// setURLFragment replaces an endpoint fragment. | setURLFragment 替换端点片段。
func setURLFragment(endpoint, fragment string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errs.Detail(ErrProviderConfig, "invalid provider endpoint | 提供方端点非法")
	}
	parsed.Fragment = fragment
	return parsed.String(), nil
}

// providerStatusError returns a safe status error for a provider endpoint. | providerStatusError
// 返回提供方端点的安全状态错误。
func providerStatusError(sentinel error, providerName, endpoint string, status int) error {
	return errs.Detail(sentinel, "provider %s %s returned HTTP %d | 提供方 %s %s 返回 HTTP %d", providerName, endpoint, status, providerName, endpoint, status)
}

// mergeRawMaps merges scalar maps, with later values winning. | mergeRawMaps 合并标量映射，后者优先。
func mergeRawMaps(values ...map[string]string) map[string]string {
	var out map[string]string
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(value))
		}
		for key, item := range value {
			if item != "" {
				out[key] = item
			}
		}
	}
	return out
}
