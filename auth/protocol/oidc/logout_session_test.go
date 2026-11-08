package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// frontchannelSessionClock is the deterministic session clock. | frontchannelSessionClock 是确定性
// 会话时钟。
var frontchannelSessionClock = time.Unix(1_700_000_000, 0).UTC()

// newFrontchannelSessionManager builds a session manager over memory stores. |
// newFrontchannelSessionManager 在内存存储之上构建会话管理器。
func newFrontchannelSessionManager(t *testing.T) *auth.SessionManager {
	t.Helper()
	manager, err := auth.NewSessionManager(auth.NewMemorySessionStore(), auth.NewMemoryUserStore(), auth.SessionConfig{})
	if err != nil {
		t.Fatalf("new session manager: %v", err)
	}
	manager.SetClock(func() time.Time { return frontchannelSessionClock })
	return manager
}

// createFrontchannelSession creates a session for userID. | createFrontchannelSession 为 userID
// 创建会话。
func createFrontchannelSession(t *testing.T, manager *auth.SessionManager, userID string) *auth.Session {
	t.Helper()
	session, err := manager.Create(context.Background(), userID, "web", httptest.NewRequest(http.MethodGet, "https://rp.example/", nil), []string{"pwd"}, "")
	if err != nil {
		t.Fatalf("create session for %s: %v", userID, err)
	}
	return session
}

// callFrontchannelLogout delivers a front-channel logout request. | callFrontchannelLogout 投递前端
// 登出请求。
func callFrontchannelLogout(provider *Provider, method string, values url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/frontchannel?"+values.Encode(), nil)
	recorder := httptest.NewRecorder()
	provider.FrontchannelLogout(recorder, req)
	return recorder
}

// TestFrontchannelLogoutHandlerRevokesSessions verifies the optional handler receives validated
// parameters and can revoke sessions by sid or sub. | TestFrontchannelLogoutHandlerRevokesSessions
// 校验可选处理器收到已校验参数，并能按 sid 或 sub 撤销会话。
func TestFrontchannelLogoutHandlerRevokesSessions(t *testing.T) {
	ctx := context.Background()
	manager := newFrontchannelSessionManager(t)
	first := createFrontchannelSession(t, manager, "user-1")
	second := createFrontchannelSession(t, manager, "user-1")
	other := createFrontchannelSession(t, manager, "user-2")

	type call struct {
		request FrontchannelLogoutRequest
	}
	var mu sync.Mutex
	var calls []call
	fixture := newOIDCFixture(t, false, func(config *ProviderConfig) {
		config.FrontchannelLogoutHandler = FrontchannelLogoutFunc(func(ctx context.Context, request FrontchannelLogoutRequest) error {
			mu.Lock()
			calls = append(calls, call{request: request})
			mu.Unlock()
			if request.SID != "" {
				return manager.Revoke(ctx, request.SID, "frontchannel_logout")
			}
			_, err := manager.RevokeUser(ctx, request.Subject, "frontchannel_logout")
			return err
		})
	})
	provider := fixture.provider
	issuer := fixture.server.URL

	// A sid revokes exactly that session. | sid 只撤销对应会话。
	w := callFrontchannelLogout(provider, http.MethodGet, url.Values{"iss": {issuer}, "sid": {first.ID}})
	if w.Code != http.StatusOK {
		t.Fatalf("sid logout = %d body=%s | sid 登出 = %d，正文 = %s", w.Code, w.Body.String(), w.Code, w.Body.String())
	}
	mu.Lock()
	if len(calls) != 1 {
		mu.Unlock()
		t.Fatalf("handler calls = %d | 处理器调用次数 = %d", len(calls), len(calls))
	}
	got := calls[0].request
	mu.Unlock()
	if got.Issuer != issuer || got.ClientID != "web" || got.SID != first.ID || got.Subject != "" {
		t.Fatalf("handler request = %+v | 处理器请求 = %+v", got, got)
	}
	if _, err := manager.Validate(ctx, first.ID); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("sid session error = %v | sid 会话错误 = %v", err, err)
	}
	if _, err := manager.Validate(ctx, second.ID); err != nil {
		t.Fatalf("unrelated session revoked: %v | 无关会话被撤销：%v", err, err)
	}

	// A sub revokes every session of that subject and leaves others alone. | sub 撤销该主体的全部
	// 会话，且不影响其他主体。
	w = callFrontchannelLogout(provider, http.MethodGet, url.Values{"iss": {issuer}, "sub": {"user-1"}})
	if w.Code != http.StatusOK {
		t.Fatalf("sub logout = %d body=%s | sub 登出 = %d，正文 = %s", w.Code, w.Body.String(), w.Code, w.Body.String())
	}
	mu.Lock()
	if len(calls) != 2 || calls[1].request.Subject != "user-1" || calls[1].request.SID != "" {
		mu.Unlock()
		t.Fatalf("sub handler calls = %+v | sub 处理器调用 = %+v", calls, calls)
	}
	mu.Unlock()
	if _, err := manager.Validate(ctx, second.ID); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("sub session error = %v | sub 会话错误 = %v", err, err)
	}
	if _, err := manager.Validate(ctx, other.ID); err != nil {
		t.Fatalf("other user session revoked: %v | 其他用户会话被撤销：%v", err, err)
	}

	// Rejected requests never reach the handler. | 被拒绝的请求绝不会到达处理器。
	before := len(calls)
	for _, tc := range []struct {
		name   string
		method string
		values url.Values
	}{
		{name: "wrong issuer", method: http.MethodGet, values: url.Values{"iss": {"https://other.example"}, "sid": {second.ID}}},
		{name: "missing sid and sub", method: http.MethodGet, values: url.Values{"iss": {issuer}}},
		{name: "other client", method: http.MethodGet, values: url.Values{"iss": {issuer}, "client_id": {"other"}, "sid": {second.ID}}},
		{name: "other audience", method: http.MethodGet, values: url.Values{"iss": {issuer}, "aud": {"other"}, "sid": {second.ID}}},
		{name: "method", method: http.MethodPost, values: url.Values{"iss": {issuer}, "sid": {second.ID}}},
	} {
		w := callFrontchannelLogout(provider, tc.method, tc.values)
		if w.Code < http.StatusBadRequest {
			t.Fatalf("%s status = %d | %s 状态 = %d", tc.name, w.Code, tc.name, w.Code)
		}
	}
	mu.Lock()
	after := len(calls)
	mu.Unlock()
	if after != before {
		t.Fatalf("handler calls after rejected requests = %d, want %d | 拒绝请求后的处理器调用 = %d，期望 %d", after, before, after, before)
	}
}

// TestFrontchannelLogoutHandlerFailure verifies a handler error produces HTTP 500 and does not
// report success. | TestFrontchannelLogoutHandlerFailure 校验处理器错误产生 HTTP 500，且不会报告
// 成功。
func TestFrontchannelLogoutHandlerFailure(t *testing.T) {
	manager := newFrontchannelSessionManager(t)
	session := createFrontchannelSession(t, manager, "user-1")
	handlerErr := errors.New("session store unavailable")
	fixture := newOIDCFixture(t, false, func(config *ProviderConfig) {
		config.FrontchannelLogoutHandler = FrontchannelLogoutFunc(func(context.Context, FrontchannelLogoutRequest) error {
			return handlerErr
		})
	})
	w := callFrontchannelLogout(fixture.provider, http.MethodGet, url.Values{"iss": {fixture.server.URL}, "sid": {session.ID}})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("handler failure status = %d | 处理器失败状态 = %d", w.Code, w.Code)
	}
	if _, err := manager.Validate(context.Background(), session.ID); err != nil {
		t.Fatalf("handler failure revoked the session: %v | 处理器失败撤销了会话：%v", err, err)
	}

	// A nil function adapter is a valid no-op handler. | nil 函数适配器是合法的无操作处理器。
	if err := (FrontchannelLogoutFunc(nil)).FrontchannelLogout(context.Background(), FrontchannelLogoutRequest{}); err != nil {
		t.Fatalf("nil FrontchannelLogoutFunc = %v | nil FrontchannelLogoutFunc = %v", err, err)
	}
}

// TestFrontchannelLogoutWithoutHandlerKeepsPage verifies the historical page-only behaviour when
// no handler is configured. | TestFrontchannelLogoutWithoutHandlerKeepsPage 校验未配置处理器时的
// 历史纯页面行为。
func TestFrontchannelLogoutWithoutHandlerKeepsPage(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	if provider.config.FrontchannelLogoutHandler != nil {
		t.Fatal("fixture unexpectedly configured a handler | fixture 意外配置了处理器")
	}
	w := callFrontchannelLogout(provider, http.MethodGet, url.Values{"iss": {fixture.server.URL}, "sid": {"sid-1"}})
	if w.Code != http.StatusOK {
		t.Fatalf("page-only status = %d | 纯页面状态 = %d", w.Code, w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "sid=sid-1") || !strings.Contains(body, "Logged out") {
		t.Fatalf("page body = %s | 页面正文 = %s", body, body)
	}
}
