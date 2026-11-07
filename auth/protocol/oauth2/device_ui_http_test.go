package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// deviceHTTPRequest performs one request with an optional form body and principal. |
// deviceHTTPRequest 执行一次请求，可选表单正文与主体。
func deviceHTTPRequest(t *testing.T, handler http.Handler, method, target string, form url.Values, principal *auth.Principal) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	request := httptest.NewRequest(method, target, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if principal != nil {
		request = request.WithContext(auth.ContextWithPrincipal(request.Context(), principal))
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// issueDeviceCode starts a device authorization and returns both codes. | issueDeviceCode 发起设备
// 授权并返回两种码。
func issueDeviceCode(t *testing.T, server *Server, clientID string) (string, string) {
	t.Helper()
	recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceAuthorization), http.MethodPost, "/device_authorization",
		url.Values{"client_id": {clientID}, "scope": {"openid"}}, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("device authorization status = %d body=%s | 设备授权状态 = %d，正文 = %s", recorder.Code, recorder.Body.String(), recorder.Code, recorder.Body.String())
	}
	body := decodeMap(t, recorder)
	deviceCode, _ := body["device_code"].(string)
	userCode, _ := body["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device response = %v | 设备响应 = %v", body, body)
	}
	return deviceCode, userCode
}

// pollDeviceToken polls the token endpoint for a device code. | pollDeviceToken 为设备码轮询令牌端点。
func pollDeviceToken(t *testing.T, server *Server, deviceCode, clientID string) *httptest.ResponseRecorder {
	t.Helper()
	return deviceHTTPRequest(t, http.HandlerFunc(server.Token), http.MethodPost, "/token", url.Values{
		"grant_type":  {GrantDeviceCode},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	}, nil)
}

// deviceUser returns a fixed principal for approval tests. | deviceUser 返回批准测试使用的固定主体。
func deviceUser() *auth.Principal {
	return &auth.Principal{Subject: "device-user", AuthTime: time.Now().UTC()}
}

// TestDeviceVerificationFormAndActions covers the approval page, method handling, deny/approve
// outcomes and the normalization accepted from user input. | TestDeviceVerificationFormAndActions
// 覆盖批准页、方法处理、拒绝/批准结果以及用户输入规范化。
func TestDeviceVerificationFormAndActions(t *testing.T) {
	server, _, public := testServer(t)
	deviceCode, userCode := issueDeviceCode(t, server, public.ID)

	if recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodGet, "/device", nil, nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET status = %d, want 401 | 匿名 GET 状态 = %d，期望 401", recorder.Code, recorder.Code)
	} else if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("anonymous GET content type = %q | 匿名 GET 内容类型 = %q", contentType, contentType)
	} else if body := decodeMap(t, recorder); body["error"] != "login_required" {
		t.Fatalf("anonymous GET body = %v | 匿名 GET 正文 = %v", body, body)
	}

	formRecorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodGet, "/device?user_code="+url.QueryEscape(strings.ToLower(userCode)), nil, deviceUser())
	if formRecorder.Code != http.StatusOK {
		t.Fatalf("GET form status = %d body=%s | GET 表单状态 = %d，正文 = %s", formRecorder.Code, formRecorder.Body.String(), formRecorder.Code, formRecorder.Body.String())
	}
	if contentType := formRecorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("GET form content type = %q | GET 表单内容类型 = %q", contentType, contentType)
	}
	if cacheControl := formRecorder.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("GET form Cache-Control = %q | GET 表单 Cache-Control = %q", cacheControl, cacheControl)
	}
	page := formRecorder.Body.String()
	if !strings.Contains(page, `name="user_code"`) || !strings.Contains(page, `value="`+userCode+`"`) {
		t.Fatalf("GET form does not contain the normalized user code: %s | GET 表单未包含规范化用户码：%s", page, page)
	}
	if !strings.Contains(page, `name="action" value="approve"`) || !strings.Contains(page, `name="action" value="deny"`) {
		t.Fatalf("GET form is missing actions: %s | GET 表单缺少操作按钮：%s", page, page)
	}

	if recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodGet, "/device?user_code=%3Cscript%3E", nil, deviceUser()); recorder.Code != http.StatusOK {
		t.Fatalf("invalid code GET status = %d | 非法用户码 GET 状态 = %d", recorder.Code, recorder.Code)
	} else if strings.Contains(recorder.Body.String(), "<script>") {
		t.Fatalf("form reflected an unescaped code: %s | 表单回显了未转义的用户码：%s", recorder.Body.String(), recorder.Body.String())
	}

	if recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodPost, "/device",
		url.Values{"user_code": {""}, "action": {"approve"}}, deviceUser()); recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing code status = %d, want 400 | 缺少用户码状态 = %d，期望 400", recorder.Code, recorder.Code)
	} else if body := decodeMap(t, recorder); body["error"] != "invalid_request" {
		t.Fatalf("missing code body = %v | 缺少用户码正文 = %v", body, body)
	}

	if recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodPut, "/device", nil, deviceUser()); recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT status = %d, want 405 | PUT 状态 = %d，期望 405", recorder.Code, recorder.Code)
	} else if allow := recorder.Header().Get("Allow"); allow != "GET, POST" {
		t.Fatalf("PUT Allow = %q | PUT Allow = %q", allow, allow)
	}

	spacedCode := strings.ToLower(userCode[:4]) + " - " + strings.ToLower(userCode[5:])
	approve := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodPost, "/device",
		url.Values{"user_code": {spacedCode}, "action": {"approve"}}, deviceUser())
	if approve.Code != http.StatusOK || !strings.Contains(approve.Body.String(), "Device approved") {
		t.Fatalf("approve status = %d body=%s | 批准状态 = %d，正文 = %s", approve.Code, approve.Body.String(), approve.Code, approve.Body.String())
	}
	issued := pollDeviceToken(t, server, deviceCode, public.ID)
	if issued.Code != http.StatusOK {
		t.Fatalf("approved poll status = %d body=%s | 已批准轮询状态 = %d，正文 = %s", issued.Code, issued.Body.String(), issued.Code, issued.Body.String())
	}
}

// TestDeviceDenyAndInvalidCodes covers DenyDevice, its token outcome and invalid grants. |
// TestDeviceDenyAndInvalidCodes 覆盖 DenyDevice、其令牌结果与非法授权。
func TestDeviceDenyAndInvalidCodes(t *testing.T) {
	server, _, public := testServer(t)
	deviceCode, userCode := issueDeviceCode(t, server, public.ID)
	denied := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodPost, "/device",
		url.Values{"user_code": {strings.ToLower(userCode)}, "action": {"deny"}}, deviceUser())
	if denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), "Request denied") {
		t.Fatalf("deny status = %d body=%s | 拒绝状态 = %d，正文 = %s", denied.Code, denied.Body.String(), denied.Code, denied.Body.String())
	}
	poll := pollDeviceToken(t, server, deviceCode, public.ID)
	requireErrorCode(t, poll, http.StatusBadRequest, "access_denied")

	unknownDeny := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodPost, "/device",
		url.Values{"user_code": {"ZZZZ-ZZZZ"}, "action": {"deny"}}, deviceUser())
	requireErrorCode(t, unknownDeny, http.StatusBadRequest, "invalid_grant")
	unknownApprove := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodPost, "/device",
		url.Values{"user_code": {"ZZZZ-ZZZZ"}, "action": {"approve"}}, deviceUser())
	requireErrorCode(t, unknownApprove, http.StatusBadRequest, "invalid_grant")

	if err := server.DenyDevice(context.Background(), "ZZZZ-ZZZZ"); err == nil {
		t.Fatal("DenyDevice accepted an unknown user code | DenyDevice 接受了未知用户码")
	}
	if err := server.ApproveDevice(context.Background(), userCode, nil); err == nil {
		t.Fatal("ApproveDevice accepted a nil principal | ApproveDevice 接受了空主体")
	}
}

// TestNormalizeUserCode verifies accepted and rejected user-code spellings. |
// TestNormalizeUserCode 校验接受与拒绝的用户码写法。
func TestNormalizeUserCode(t *testing.T) {
	valid := "ABCD-EFGH"
	for _, input := range []string{"ABCD-EFGH", "abcd-efgh", " abcd efgh ", "ABCDEFGH"} {
		if got := normalizeUserCode(input); got != valid {
			t.Fatalf("normalizeUserCode(%q) = %q, want %q | normalizeUserCode(%q) = %q，期望 %q", input, got, valid, input, got, valid)
		}
	}
	for _, input := range []string{"", "ABCD-EFG", "ABCD-EFGHI", "ABCD-EFG1", "ABCD_EFGH"} {
		if got := normalizeUserCode(input); got != "" {
			t.Fatalf("normalizeUserCode(%q) = %q, want empty | normalizeUserCode(%q) = %q，期望空", input, got, input, got)
		}
	}
}

// TestDeviceLoginRedirect verifies that a configured LoginURL receives the return target. |
// TestDeviceLoginRedirect 校验已配置的 LoginURL 会收到返回目标。
func TestDeviceLoginRedirect(t *testing.T) {
	server, _, _ := testServer(t)
	server.config.LoginURL = "https://login.example/signin"
	recorder := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceVerification), http.MethodGet, "/device?user_code=ABCD-EFGH", nil, nil)
	if recorder.Code != http.StatusFound {
		t.Fatalf("redirect status = %d, want 302 | 重定向状态 = %d，期望 302", recorder.Code, recorder.Code)
	}
	location := recorder.Header().Get("Location")
	if !strings.HasPrefix(location, "https://login.example/signin?return_to=") || !strings.Contains(location, url.QueryEscape(server.Endpoint(server.Path(server.config.DeviceVerificationPath))+"?")) {
		t.Fatalf("redirect Location = %q | 重定向 Location = %q", location, location)
	}
}

// TestHTTPServerHandlerRoutes verifies the native mux mounts endpoints and omits device routes when
// disabled. | TestHTTPServerHandlerRoutes 校验原生多路复用器挂载端点，并在禁用设备流程时省略设备路由。
func TestHTTPServerHandlerRoutes(t *testing.T) {
	server, confidential, public := testServer(t)
	handler := server.HTTPHandler()

	metadata := deviceHTTPRequest(t, handler, http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil)
	if metadata.Code != http.StatusOK || !strings.HasPrefix(metadata.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("metadata status = %d content type = %q | 元数据状态 = %d，内容类型 = %q", metadata.Code, metadata.Header().Get("Content-Type"), metadata.Code, metadata.Header().Get("Content-Type"))
	}

	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type": {GrantClientCredentials},
		"scope":      {"api:read"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(url.QueryEscape(confidential.ID), url.QueryEscape("super-secret"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("mux token status = %d body=%s | 多路复用令牌状态 = %d，正文 = %s", recorder.Code, recorder.Body.String(), recorder.Code, recorder.Body.String())
	}

	device := deviceHTTPRequest(t, handler, http.MethodPost, "/device_authorization", url.Values{"client_id": {public.ID}}, nil)
	if device.Code != http.StatusOK {
		t.Fatalf("mux device authorization status = %d body=%s | 多路复用设备授权状态 = %d，正文 = %s", device.Code, device.Body.String(), device.Code, device.Body.String())
	}
	userCode, _ := decodeMap(t, device)["user_code"].(string)
	verification := deviceHTTPRequest(t, handler, http.MethodGet, "/device?user_code="+url.QueryEscape(userCode), nil, deviceUser())
	if verification.Code != http.StatusOK {
		t.Fatalf("mux device verification status = %d | 多路复用设备校验状态 = %d", verification.Code, verification.Code)
	}

	disabled, err := NewServer(ServerConfig{
		Issuer:            "https://auth.example",
		Clients:           server.config.Clients,
		Store:             NewMemoryStore(),
		Scopes:            server.config.Scopes,
		DisableDeviceFlow: true,
	})
	if err != nil {
		t.Fatalf("NewServer disabled: %v | 禁用设备流程的 NewServer：%v", err, err)
	}
	disabledHandler := disabled.HTTPHandler()
	if recorder := deviceHTTPRequest(t, disabledHandler, http.MethodPost, "/device_authorization", url.Values{"client_id": {public.ID}}, nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("disabled device authorization status = %d, want 404 | 禁用设备授权状态 = %d，期望 404", recorder.Code, recorder.Code)
	}
	if recorder := deviceHTTPRequest(t, disabledHandler, http.MethodGet, "/device", nil, deviceUser()); recorder.Code != http.StatusNotFound {
		t.Fatalf("disabled device verification status = %d, want 404 | 禁用设备校验状态 = %d，期望 404", recorder.Code, recorder.Code)
	}
	if recorder := deviceHTTPRequest(t, disabledHandler, http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil); recorder.Code != http.StatusOK {
		t.Fatalf("disabled metadata status = %d, want 200 | 禁用元数据状态 = %d，期望 200", recorder.Code, recorder.Code)
	}
}

// TestDeviceAuthorizationErrors covers disabled flow, method and client validation responses. |
// TestDeviceAuthorizationErrors 覆盖禁用流程、方法与客户端校验响应。
func TestDeviceAuthorizationErrors(t *testing.T) {
	server, _, public := testServer(t)

	get := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceAuthorization), http.MethodGet, "/device_authorization", nil, nil)
	if get.Code >= 200 && get.Code < 300 {
		t.Fatalf("GET device authorization succeeded | GET 设备授权意外成功")
	}
	if allow := get.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("GET Allow = %q | GET Allow = %q", allow, allow)
	}

	missingClient := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceAuthorization), http.MethodPost, "/device_authorization", url.Values{}, nil)
	if missingClient.Code != http.StatusUnauthorized {
		t.Fatalf("missing client status = %d, want 401 | 缺少客户端状态 = %d，期望 401", missingClient.Code, missingClient.Code)
	}

	server.config.DisableDeviceFlow = true
	disabled := deviceHTTPRequest(t, http.HandlerFunc(server.DeviceAuthorization), http.MethodPost, "/device_authorization", url.Values{"client_id": {public.ID}}, nil)
	requireErrorCode(t, disabled, http.StatusBadRequest, "unsupported_grant_type")
}
