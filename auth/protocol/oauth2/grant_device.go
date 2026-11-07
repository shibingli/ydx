package oauth2

import (
	"context"
	"crypto/rand"
	htmlstd "html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// userCodeAlphabet excludes visually ambiguous characters. | userCodeAlphabet 排除易混淆字符。
const userCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// DeviceAuthorization is the RFC 8628 device authorization endpoint. | DeviceAuthorization 是 RFC 8628 设备授权端点。
func (s *Server) DeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if s.config.DisableDeviceFlow {
		s.writeOAuthError(w, r, errs.Detail(ErrUnsupportedGrantType, "device flow is disabled | 设备流程已禁用"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeOAuthError(w, r, errs.Detail(ErrInvalidRequest, "method %[1]s not allowed | 不允许方法 %[1]s", r.Method))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, r, errs.Wrap(err, ErrInvalidRequest))
		return
	}
	form := r.PostForm
	client, err := s.authenticateClient(r.Context(), r, form)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantDeviceCode) {
		s.writeOAuthError(w, r, errs.Detail(ErrUnauthorizedClient, "client is not registered for the device grant | 客户端未注册设备授权"))
		return
	}
	scopes, err := s.grantScopes(client, ParseScope(form.Get("scope")))
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	if len(scopes) == 0 {
		scopes = append([]string(nil), client.Scopes...)
	}
	audience, err := s.grantAudience(form["resource"], s.config.DefaultAudience)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	rawDeviceCode, err := auth.RandomToken(40)
	if err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	var userCode string
	for attempt := 0; attempt < 8; attempt++ {
		candidate, err := generateUserCode()
		if err != nil {
			s.writeOAuthError(w, r, err)
			return
		}
		if _, err := s.config.Store.GetDeviceCodeByUserCode(r.Context(), candidate); err != nil {
			userCode = candidate
			break
		}
	}
	if userCode == "" {
		s.writeOAuthError(w, r, errs.Detail(ErrServerError, "could not allocate a user code | 无法分配用户码"))
		return
	}
	now := s.Now()
	code := &DeviceCode{
		DeviceCodeHash: auth.HashToken(rawDeviceCode),
		UserCode:       userCode,
		ClientID:       client.ID,
		Scopes:         scopes,
		Audience:       audience,
		Status:         DevicePending,
		Interval:       s.config.DeviceInterval,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.config.DeviceCodeTTL),
	}
	if err := s.config.Store.SaveDeviceCode(r.Context(), code); err != nil {
		s.writeOAuthError(w, r, err)
		return
	}
	verificationURI := s.Endpoint(s.config.DeviceVerificationPath)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               rawDeviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(userCode),
		"expires_in":                int64(s.config.DeviceCodeTTL / time.Second),
		"interval":                  int64(s.config.DeviceInterval / time.Second),
	})
}

// generateUserCode returns an eight-character user code in XXXX-XXXX form. | generateUserCode 返回 XXXX-XXXX 形式的八字符用户码。
func generateUserCode() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errs.Wrap(err, ErrServerError)
	}
	out := make([]byte, 0, 9)
	for i, value := range raw {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, userCodeAlphabet[int(value)%len(userCodeAlphabet)])
	}
	return string(out), nil
}

// normalizeUserCode normalizes user input to XXXX-XXXX form. | normalizeUserCode 把用户输入规范化为 XXXX-XXXX 形式。
func normalizeUserCode(raw string) string {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, "-", "")
	if len(raw) != 8 {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		if !strings.ContainsRune(userCodeAlphabet, rune(raw[i])) {
			return ""
		}
	}
	return raw[:4] + "-" + raw[4:]
}

// DeviceVerification renders and processes the user approval page. | DeviceVerification 渲染并处理用户批准页。
func (s *Server) DeviceVerification(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromRequest(r)
	if !ok || principal == nil {
		if s.config.LoginURL != "" {
			location := s.config.LoginURL + "?return_to=" + url.QueryEscape(s.Endpoint(s.Path(s.config.DeviceVerificationPath))+"?"+r.URL.RawQuery)
			http.Redirect(w, r, location, http.StatusFound)
			return
		}
		writeHTTPJSONError(w, http.StatusUnauthorized, "login_required", "login is required | 需要登录")
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			writeHTTPJSONError(w, http.StatusBadRequest, "invalid_request", "invalid form | 表单非法")
			return
		}
		userCode := normalizeUserCode(r.PostForm.Get("user_code"))
		if userCode == "" {
			writeHTTPJSONError(w, http.StatusBadRequest, "invalid_request", "invalid user_code | 用户码非法")
			return
		}
		if strings.EqualFold(r.PostForm.Get("action"), "deny") {
			if err := s.DenyDevice(r.Context(), userCode); err != nil {
				writeHTTPJSONError(w, http.StatusBadRequest, "invalid_grant", "device code is invalid or expired | 设备码无效或已过期")
				return
			}
			writeDevicePage(w, "Request denied | 请求已拒绝", "The device request was denied. | 设备请求已被拒绝。")
			return
		}
		if err := s.ApproveDevice(r.Context(), userCode, principal); err != nil {
			writeHTTPJSONError(w, http.StatusBadRequest, "invalid_grant", "device code is invalid or expired | 设备码无效或已过期")
			return
		}
		writeDevicePage(w, "Device approved | 设备已批准", "You can return to your device. | 可以返回设备继续。")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		writeHTTPJSONError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed | 方法不允许")
		return
	}
	userCode := normalizeUserCode(r.URL.Query().Get("user_code"))
	writeDeviceForm(w, userCode)
}

// ApproveDevice marks a device grant approved by principal. | ApproveDevice 把设备许可标记为由 principal 批准。
func (s *Server) ApproveDevice(ctx context.Context, userCode string, principal *auth.Principal) error {
	if principal == nil {
		return ErrAccessDenied
	}
	_, err := s.config.Store.SetDeviceCodeStatus(ctx, normalizeUserCode(userCode), DeviceApproved, s.Now(), principal)
	return err
}

// DenyDevice marks a device grant denied. | DenyDevice 把设备许可标记为拒绝。
func (s *Server) DenyDevice(ctx context.Context, userCode string) error {
	_, err := s.config.Store.SetDeviceCodeStatus(ctx, normalizeUserCode(userCode), DeviceDenied, s.Now(), nil)
	return err
}

// grantDeviceCode exchanges an approved device code. | grantDeviceCode 兑换已批准的设备码。
func (s *Server) grantDeviceCode(r *http.Request, client *Client, form url.Values) (*TokenResponse, error) {
	if s.config.DisableDeviceFlow {
		return nil, errs.Detail(ErrUnsupportedGrantType, "device flow is disabled | 设备流程已禁用")
	}
	raw := form.Get("device_code")
	if raw == "" {
		return nil, errs.Detail(ErrInvalidRequest, "device_code is required | device_code 必填")
	}
	if len(client.GrantTypes) > 0 && !client.AllowsGrant(GrantDeviceCode) {
		return nil, errs.Detail(ErrUnauthorizedClient, "client is not registered for the device grant | 客户端未注册设备授权")
	}
	now := s.Now()
	// Polling is atomic: an approved grant is consumed exactly once and a too-frequent poll grows
	// the stored interval, so concurrent pollers cannot issue two token sets. | 轮询是原子操作：
	// 已批准的许可只会被消费一次，过频轮询会增加存储的间隔，因此并发轮询不会签发两套令牌。
	code, polled, err := s.config.Store.PollDeviceCode(r.Context(), auth.HashToken(raw), client.ID, now)
	if err != nil {
		return nil, err
	}
	switch code.Status {
	case DevicePending:
		if !polled {
			return nil, NewError(ErrorSlowDown, "polling too frequently | 轮询过于频繁")
		}
		return nil, NewError(ErrorAuthorizationPending, "authorization is pending | 授权等待中")
	case DeviceApproved:
		// The store has already moved the grant to DeviceUsed; continue to issue tokens. | 存储
		// 已把许可转为 DeviceUsed，继续签发令牌。
	case DeviceDenied:
		return nil, NewError(ErrorAccessDenied, "user denied the request | 用户拒绝了请求")
	case DeviceUsed:
		return nil, errs.Detail(ErrInvalidGrant, "device code already used | 设备码已被使用")
	case DeviceExpired:
		return nil, NewError(ErrorExpiredToken, "device code expired | 设备码已过期")
	default:
		return nil, errs.Detail(ErrInvalidGrant, "device code is not usable | 设备码不可用")
	}
	jkt, err := s.dpopForTokenRequest(r.Context(), r, code.DPoPJKT, "")
	if err != nil {
		return nil, err
	}
	scopes := append([]string(nil), code.Scopes...)
	if requested := ParseScope(form.Get("scope")); len(requested) > 0 {
		validated, err := s.grantScopes(client, requested)
		if err != nil {
			return nil, err
		}
		if !isSubset(validated, code.Scopes) {
			return nil, errs.Detail(ErrInvalidScope, "scope is broader than the device grant | 作用域超出设备许可")
		}
		scopes = validated
	}
	principal := code.Principal.Clone()
	if principal == nil {
		principal = &auth.Principal{Subject: code.Subject, AuthTime: now}
	}
	grant := &Grant{
		Client:         client,
		Principal:      principal,
		UserID:         code.UserID,
		Subject:        code.Subject,
		Scopes:         scopes,
		Audience:       append([]string(nil), code.Audience...),
		AuthTime:       now,
		DPoPJKT:        jkt,
		CertThumbprint: certThumbprint(r),
		GrantID:        auth.NewID("grant"),
		IssuedAt:       now,
	}
	return s.issueTokens(r.Context(), grant, s.shouldIssueRefresh(grant))
}

// writeDevicePage writes a minimal result page. | writeDevicePage 写入最小结果页。
func writeDevicePage(w http.ResponseWriter, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>" +
		htmlstd.EscapeString(title) + "</title></head><body><h1>" + htmlstd.EscapeString(title) +
		"</h1><p>" + htmlstd.EscapeString(message) + "</p></body></html>"))
}

// writeDeviceForm writes the user-code approval form. | writeDeviceForm 写入用户码批准表单。
func writeDeviceForm(w http.ResponseWriter, userCode string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Device authorization</title></head><body>" +
		"<h1>Device authorization | 设备授权</h1><form method=\"post\">" +
		"<label>Code | 用户码 <input name=\"user_code\" value=\"" + htmlstd.EscapeString(userCode) + "\" autofocus></label>" +
		"<button name=\"action\" value=\"approve\">Approve | 批准</button>" +
		"<button name=\"action\" value=\"deny\">Deny | 拒绝</button></form></body></html>"))
}

// writeHTTPJSONError writes a small JSON error. | writeHTTPJSONError 写入小型 JSON 错误。
func writeHTTPJSONError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
