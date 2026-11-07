package cas

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// TestValidationCodeAndMessage covers every error-to-protocol mapping branch. |
// TestValidationCodeAndMessage 覆盖全部错误到协议码的映射分支。
func TestValidationCodeAndMessage(t *testing.T) {
	cases := []struct {
		err     error
		code    string
		message string
	}{
		{nil, "", "The ticket could not be validated | 票据无法校验"},
		{ErrTicketNotFound, ErrorCodeInvalidTicket, "The ticket is not valid | 票据无效"},
		{ErrTicketUsed, ErrorCodeInvalidTicket, "The ticket is not valid | 票据无效"},
		{ErrTicketExpired, ErrorCodeInvalidTicket, "The ticket is not valid | 票据无效"},
		{ErrTicketTypeMismatch, ErrorCodeInvalidTicket, "The ticket is not valid | 票据无效"},
		{errs.Wrap(ErrTicketUsed, ErrTicketNotFound), ErrorCodeInvalidTicket, "The ticket is not valid | 票据无效"},
		{ErrInvalidService, ErrorCodeInvalidService, "The service is not valid | 服务无效"},
		{ErrServiceNotRegistered, ErrorCodeInvalidService, "The service is not valid | 服务无效"},
		{ErrInvalidProxyCallback, ErrorCodeInvalidProxyCallback, "The proxy callback could not be verified | 代理回调无法校验"},
		{ErrInsecureProxyCallback, ErrorCodeInvalidProxyCallback, "The proxy callback could not be verified | 代理回调无法校验"},
		{ErrInvalidRequest, ErrorCodeInvalidRequest, "The validation request is invalid | 校验请求非法"},
		{ErrInvalidConfig, ErrorCodeInvalidRequest, "The validation request is invalid | 校验请求非法"},
		{errs.New("cas: unexpected | cas：意外"), ErrorCodeInternalError, "The ticket could not be validated | 票据无法校验"},
	}
	for _, tc := range cases {
		if got := validationCode(tc.err); got != tc.code {
			t.Fatalf("validationCode(%v) = %q, want %q", tc.err, got, tc.code)
		}
		if got := validationMessage(tc.err); got != tc.message {
			t.Fatalf("validationMessage(%v) = %q, want %q", tc.err, got, tc.message)
		}
	}
}

// TestServerAccessorsAndMatching covers the accessors and service binding helpers. |
// TestServerAccessorsAndMatching 覆盖访问器与服务绑定辅助函数。
func TestServerAccessorsAndMatching(t *testing.T) {
	server, store, _ := newTestServer(t)
	if got := server.Config(); got.Issuer != testIssuer || got.TicketStore != store {
		t.Fatalf("Config() = %#v", got)
	}
	if server.Store() != store {
		t.Fatal("Store() did not return the configured store")
	}
	if !server.servicesMatch(testAppService, testAppService) {
		t.Fatal("identical service did not match")
	}
	if server.servicesMatch(testAppService, testOtherService) {
		t.Fatal("different service matched")
	}
	if server.servicesMatch("", testAppService) || server.servicesMatch(testAppService, "") {
		t.Fatal("empty service matched")
	}
	plain := &Server{config: ServerConfig{}}
	if !plain.servicesMatch("https://app.example.com/callback", "https://app.example.com/callback") {
		t.Fatal("exact match without registry failed")
	}
	if plain.servicesMatch("https://app.example.com/callback", "https://other.example.com/home") {
		t.Fatal("mismatch without registry succeeded")
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodHead, "/cas/serviceValidate", nil)
	if !server.methodAllowed(recorder, request, http.MethodGet) {
		t.Fatal("HEAD was not allowed for a GET endpoint")
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/cas/serviceValidate", nil)
	if server.methodAllowed(recorder, request, http.MethodGet) {
		t.Fatal("POST was allowed for a GET endpoint")
	}
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
	if allow := recorder.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", allow)
	}
}

// TestCloneStringsAndUserIdentifier covers attribute copies and user naming. |
// TestCloneStringsAndUserIdentifier 覆盖属性复制与用户标识。
func TestCloneStringsAndUserIdentifier(t *testing.T) {
	if cloneStrings(nil) != nil || cloneStrings(map[string]string{}) != nil {
		t.Fatal("empty map was not cloned to nil")
	}
	source := map[string]string{"role": "admin"}
	copy := cloneStrings(source)
	if copy["role"] != "admin" {
		t.Fatalf("clone = %#v", copy)
	}
	source["role"] = "user"
	if copy["role"] != "admin" {
		t.Fatal("clone aliases the source map")
	}
	if userIdentifier(nil) != "" {
		t.Fatal("nil principal has a user identifier")
	}
	if got := userIdentifier(&auth.Principal{Subject: "user-1"}); got != "user-1" {
		t.Fatalf("subject identifier = %q", got)
	}
	if got := userIdentifier(&auth.Principal{Subject: "user-1", Username: "alice"}); got != "alice" {
		t.Fatalf("username identifier = %q", got)
	}
}

// TestP3ProxyValidate covers the CAS 3.0 proxy validation endpoint. |
// TestP3ProxyValidate 覆盖 CAS 3.0 代理校验端点。
func TestP3ProxyValidate(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := newTestRouter(t, server)
	_, st := issueTestTickets(t, server, testAppService)
	recorder := serve(t, handler, http.MethodGet, validateURL("p3/proxyValidate", st.ID, testAppService, nil), nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}
	if user := elementText(t, recorder.Body.String(), "user"); user != "alice" {
		t.Fatalf("user = %q, want alice", user)
	}
	replay := serve(t, handler, http.MethodGet, validateURL("p3/proxyValidate", st.ID, testAppService, nil), nil)
	if body := replay.Body.String(); !strings.Contains(body, ErrorCodeInvalidTicket) || !strings.Contains(body, "The ticket is not valid") {
		t.Fatalf("replay body = %s", body)
	}
	missing := serve(t, handler, http.MethodGet, "/cas/p3/proxyValidate?service="+testAppService, nil)
	if body := missing.Body.String(); !strings.Contains(body, ErrorCodeInvalidRequest) {
		t.Fatalf("missing ticket body = %s", body)
	}
}

// TestClientProxyValidateV3AndConfig covers the CAS 3.0 client entry point. |
// TestClientProxyValidateV3AndConfig 覆盖 CAS 3.0 客户端入口。
func TestClientProxyValidateV3AndConfig(t *testing.T) {
	server, client, _ := newClientFixture(t)
	if config := client.Config(); config.ServerURL == "" || config.ServiceURL != testAppService {
		t.Fatalf("Config() = %#v", config)
	}
	_, st := issueTestTickets(t, server, testAppService)
	response, err := client.ProxyValidateV3(context.Background(), st.ID, testAppService)
	if err != nil {
		t.Fatalf("ProxyValidateV3: %v", err)
	}
	if !response.Success || response.User != "alice" {
		t.Fatalf("ProxyValidateV3 = %#v", response)
	}
}

// TestServiceAuthenticatorNilConfiguration covers nil-safe adapter branches. |
// TestServiceAuthenticatorNilConfiguration 覆盖适配器的空值安全分支。
func TestServiceAuthenticatorNilConfiguration(t *testing.T) {
	authenticator := NewServiceAuthenticator(nil)
	if _, err := authenticator.Authenticate(context.Background(), &LoginRequest{Username: "alice"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil service err = %v", err)
	}
	authenticator.SetClientID("custom")
	if authenticator.clientID != "custom" {
		t.Fatalf("clientID = %q", authenticator.clientID)
	}
	var nilAuthenticator *ServiceAuthenticator
	nilAuthenticator.SetClientID("ignored")
	if _, err := nilAuthenticator.Authenticate(context.Background(), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil authenticator err = %v", err)
	}
	withService := &ServiceAuthenticator{service: &auth.Service{}}
	if _, err := withService.Authenticate(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil request err = %v", err)
	}

	var nilFunc PrincipalProviderFunc
	if _, err := nilFunc.Principal(context.Background(), "user-1"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil provider func err = %v", err)
	}
	provider := NewServicePrincipalProvider(nil)
	if _, err := provider.Principal(context.Background(), "user-1"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil service provider err = %v", err)
	}
	var nilProvider *ServicePrincipalProvider
	if _, err := nilProvider.Principal(context.Background(), "user-1"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil provider err = %v", err)
	}
}

// TestMemoryTicketStoreDefaults covers constructor defaults and nil clock handling. |
// TestMemoryTicketStoreDefaults 覆盖构造默认值与空时钟处理。
func TestMemoryTicketStoreDefaults(t *testing.T) {
	store := NewMemoryTicketStore()
	if store.tickets == nil || store.bySvc == nil || store.byRoot == nil || store.byUser == nil {
		t.Fatal("constructor left an index nil")
	}
	if store.clock == nil {
		t.Fatal("constructor left the clock nil")
	}
	store.SetClock(nil)
	if store.clock == nil {
		t.Fatal("SetClock(nil) cleared the clock")
	}
	fixed := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return fixed })
	if got := store.clock(); !got.Equal(fixed) {
		t.Fatalf("clock = %v, want %v", got, fixed)
	}
}
