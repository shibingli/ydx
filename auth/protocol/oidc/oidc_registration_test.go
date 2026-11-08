package oidc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/json"
)

// registrationCall performs one dynamic-registration HTTP request. | registrationCall 执行一次动态注册
// HTTP 请求。
func registrationCall(t *testing.T, method, target, body, bearer string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := make(map[string]any)
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatalf("decode %q: %v", data, err)
		}
	}
	return resp, out
}

// TestRegistrationRejectsClientSecretJWT verifies that RFC 7591 registration refuses the
// unsupported client_secret_jwt method with an error that names it. |
// TestRegistrationRejectsClientSecretJWT 校验 RFC 7591 注册会拒绝不支持的 client_secret_jwt，
// 并在错误中指明该方法。
func TestRegistrationRejectsClientSecretJWT(t *testing.T) {
	fixture := newOIDCFixture(t, true)
	endpoint := fixture.server.URL + RegistrationPath
	body := `{"redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"client_secret_jwt"}`
	resp, out := registrationCall(t, http.MethodPost, endpoint, body, "")
	if resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
		t.Fatalf("register = %d body=%v | 注册 = %d 正文 = %v", resp.StatusCode, out, resp.StatusCode, out)
	}
	description, _ := out["error_description"].(string)
	if !strings.Contains(description, "client_secret_jwt") {
		t.Fatalf("error_description = %q | error_description = %q", description, description)
	}
}

func TestDynamicRegistrationLifecycle(t *testing.T) {
	fixture := newOIDCFixture(t, true)
	endpoint := fixture.server.URL + RegistrationPath

	// The router answers the unmatched method first, so exercise the handler branch directly. |
	// 路由器会先处理未匹配的方法，因此直接覆盖处理器分支。
	get := httptest.NewRequest(http.MethodGet, RegistrationPath, nil)
	getRecorder := httptest.NewRecorder()
	fixture.provider.RegisterClient(getRecorder, get)
	if getRecorder.Code != http.StatusMethodNotAllowed || !strings.Contains(getRecorder.Header().Get("Allow"), "POST") {
		t.Fatalf("GET registration = %d allow=%q", getRecorder.Code, getRecorder.Header().Get("Allow"))
	}
	if resp, body := registrationCall(t, http.MethodPost, endpoint, "not json", ""); resp.StatusCode != http.StatusBadRequest ||
		body["error"] != "invalid_client_metadata" {
		t.Fatalf("invalid JSON = %d body=%v", resp.StatusCode, body)
	}
	if resp, body := registrationCall(t, http.MethodPost, endpoint, `{"grant_types":["password"]}`, ""); resp.StatusCode != http.StatusBadRequest ||
		body["error"] != "invalid_client_metadata" {
		t.Fatalf("invalid metadata = %d body=%v", resp.StatusCode, body)
	}

	metadata := `{
		"redirect_uris":["https://client.example/cb"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"scope":"openid profile",
		"client_name":"Before",
		"token_endpoint_auth_method":"client_secret_basic",
		"post_logout_redirect_uris":["https://client.example/logout"]
	}`
	resp, registered := registrationCall(t, http.MethodPost, endpoint, metadata, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d body=%v", resp.StatusCode, registered)
	}
	clientID, _ := registered["client_id"].(string)
	secret, _ := registered["client_secret"].(string)
	registrationToken, _ := registered["registration_access_token"].(string)
	clientURI, _ := registered["registration_client_uri"].(string)
	if clientID == "" || secret == "" || registrationToken == "" ||
		clientURI != endpoint+"/"+clientID || registered["client_name"] != "Before" {
		t.Fatalf("registration response = %v", registered)
	}

	if resp, body := registrationCall(t, http.MethodGet, clientURI, "", ""); resp.StatusCode != http.StatusUnauthorized ||
		body["error"] != "invalid_token" || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthenticated read = %d body=%v", resp.StatusCode, body)
	}
	if resp, _ := registrationCall(t, http.MethodGet, endpoint+"/unknown", "", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown client = %d", resp.StatusCode)
	}
	if resp, _ := registrationCall(t, http.MethodGet, clientURI, "", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong registration token = %d", resp.StatusCode)
	}
	resp, current := registrationCall(t, http.MethodGet, clientURI, "", registrationToken)
	if resp.StatusCode != http.StatusOK || current["client_id"] != clientID || current["client_name"] != "Before" ||
		current["client_secret"] != nil {
		t.Fatalf("read = %d body=%v", resp.StatusCode, current)
	}

	if resp, body := registrationCall(t, http.MethodPut, clientURI, `{"client_name":"NoID"}`, registrationToken); resp.StatusCode != http.StatusBadRequest ||
		body["error"] != "invalid_client_metadata" {
		t.Fatalf("PUT without client_id = %d body=%v", resp.StatusCode, body)
	}
	mismatch := `{"client_id":"other","redirect_uris":["https://client.example/cb"]}`
	if resp, body := registrationCall(t, http.MethodPut, clientURI, mismatch, registrationToken); resp.StatusCode != http.StatusBadRequest ||
		body["error"] != "invalid_client_metadata" {
		t.Fatalf("PUT client_id mismatch = %d body=%v", resp.StatusCode, body)
	}
	badRedirect := `{"client_id":"` + clientID + `","redirect_uris":["javascript:alert(1)"]}`
	if resp, body := registrationCall(t, http.MethodPut, clientURI, badRedirect, registrationToken); resp.StatusCode != http.StatusBadRequest ||
		body["error"] != "invalid_client_metadata" {
		t.Fatalf("PUT bad redirect = %d body=%v", resp.StatusCode, body)
	}
	update := `{
		"client_id":"` + clientID + `",
		"redirect_uris":["https://client.example/cb"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"scope":"openid profile",
		"client_name":"After",
		"token_endpoint_auth_method":"client_secret_basic",
		"post_logout_redirect_uris":["https://client.example/logout"]
	}`
	resp, updated := registrationCall(t, http.MethodPut, clientURI, update, registrationToken)
	if resp.StatusCode != http.StatusOK || updated["client_name"] != "After" || updated["client_secret"] != nil ||
		updated["client_id"] != clientID {
		t.Fatalf("PUT = %d body=%v", resp.StatusCode, updated)
	}
	// The update must preserve the original registration access token. | 更新必须保留原注册访问令牌。
	if resp, after := registrationCall(t, http.MethodGet, clientURI, "", registrationToken); resp.StatusCode != http.StatusOK ||
		after["client_name"] != "After" {
		t.Fatalf("read after update = %d body=%v", resp.StatusCode, after)
	}
	if resp, _ := registrationCall(t, http.MethodDelete, clientURI, "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated delete = %d", resp.StatusCode)
	}
	if resp, _ := registrationCall(t, http.MethodDelete, clientURI, "", registrationToken); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if resp, _ := registrationCall(t, http.MethodGet, clientURI, "", registrationToken); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("read after delete = %d", resp.StatusCode)
	}
}

func TestDynamicRegistrationInitialAccessToken(t *testing.T) {
	fixture := newOIDCFixture(t, true)
	config := fixture.provider.Config()
	config.RegistrationInitialAccessToken = "initial-secret"
	provider, err := NewProvider(config)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	body := `{"redirect_uris":["https://native.example/cb"],"token_endpoint_auth_method":"none"}`
	call := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, RegistrationPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		provider.RegisterClient(w, req)
		return w
	}
	if w := call(""); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("missing initial token = %d", w.Code)
	}
	if w := call("wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong initial token = %d", w.Code)
	}
	w := call("initial-secret")
	if w.Code != http.StatusCreated {
		t.Fatalf("initial token = %d body=%s", w.Code, w.Body.String())
	}
	var registered RegistrationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &registered); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if registered.ClientID == "" || registered.ClientSecret != "" || registered.RegistrationAccessToken == "" {
		t.Fatalf("public registration = %+v", registered)
	}

	// Disabled registration answers 404 before any method or token check. | 关闭注册时在方法或令牌
	// 校验之前直接返回 404。
	disabled := fixture.provider.Config()
	disabled.EnableRegistration = false
	disabledProvider, err := NewProvider(disabled)
	if err != nil {
		t.Fatalf("disabled provider: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, RegistrationPath, strings.NewReader(body))
	w = httptest.NewRecorder()
	disabledProvider.RegisterClient(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled register = %d", w.Code)
	}
	w = httptest.NewRecorder()
	disabledProvider.ClientConfiguration(w, httptest.NewRequest(http.MethodGet, RegistrationPath+"/client-1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled management = %d", w.Code)
	}
}

func TestCloneOIDCClient(t *testing.T) {
	if cloneOIDCClient(nil) != nil {
		t.Fatal("nil clone")
	}
	original := &oauth2.Client{
		ID:                     "client-1",
		RedirectURIs:           []string{"https://rp.example/cb"},
		GrantTypes:             []string{oauth2.GrantAuthorizationCode},
		ResponseTypes:          []string{oauth2.ResponseCode},
		Scopes:                 []string{ScopeOpenID},
		PostLogoutRedirectURIs: []string{"https://rp.example/logout"},
		Contacts:               []string{"admin@rp.example"},
		TLSClientAuthSANs:      []string{"rp.example"},
		JWKS:                   []byte(`{"keys":[]}`),
		Metadata:               map[string]string{"owner": "team"},
	}
	clone := cloneOIDCClient(original)
	if clone == original || clone.ID != original.ID {
		t.Fatalf("clone = %+v", clone)
	}
	clone.RedirectURIs[0] = "https://evil.example/cb"
	clone.GrantTypes[0] = "password"
	clone.ResponseTypes[0] = "token"
	clone.Scopes[0] = "admin"
	clone.PostLogoutRedirectURIs[0] = "https://evil.example/logout"
	clone.Contacts[0] = "evil@example.com"
	clone.TLSClientAuthSANs[0] = "evil.example"
	clone.JWKS[0] = 'x'
	clone.Metadata["owner"] = "evil"
	if original.RedirectURIs[0] != "https://rp.example/cb" || original.GrantTypes[0] != oauth2.GrantAuthorizationCode ||
		original.ResponseTypes[0] != oauth2.ResponseCode || original.Scopes[0] != ScopeOpenID ||
		original.PostLogoutRedirectURIs[0] != "https://rp.example/logout" ||
		original.Contacts[0] != "admin@rp.example" || original.TLSClientAuthSANs[0] != "rp.example" ||
		original.JWKS[0] != '{' || original.Metadata["owner"] != "team" {
		t.Fatalf("original mutated: %+v", original)
	}
}
