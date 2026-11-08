package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestClientSecretJWTIsRejected verifies that a client registered for client_secret_jwt receives a
// clear unsupported error both with and without an assertion, instead of appearing configurable
// while never being able to authenticate. |
// TestClientSecretJWTIsRejected 校验注册为 client_secret_jwt 的客户端在带与不带断言时都会收到明确
// 的不支持错误，而不是呈现为可配置但永远无法认证。
func TestClientSecretJWTIsRejected(t *testing.T) {
	client := &Client{
		ID:                      "hmac-client",
		GrantTypes:              []string{GrantClientCredentials},
		Scopes:                  []string{"api:read"},
		TokenEndpointAuthMethod: ClientSecretJWT,
	}
	verifier := &fakeClientAssertionVerifier{}
	server := issuerPathServer(t, func(config *ServerConfig) {
		config.ClientAssertionVerifier = verifier
	}, client)
	cases := []struct {
		name string
		form url.Values
	}{
		{
			name: "assertion",
			form: url.Values{
				"grant_type":            {GrantClientCredentials},
				"client_id":             {client.ID},
				"client_assertion":      {"assertion-1"},
				"client_assertion_type": {ClientAssertionTypeJWTBearer},
			},
		},
		{
			name: "no assertion",
			form: url.Values{
				"grant_type": {GrantClientCredentials},
				"client_id":  {client.ID},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tc.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := request.ParseForm(); err != nil {
				t.Fatalf("parse form: %v | 解析表单：%v", err, err)
			}
			_, err := server.authenticateClient(context.Background(), request, request.PostForm, server.config.TokenPath)
			if !errors.Is(err, ErrInvalidClient) || !strings.Contains(err.Error(), ClientSecretJWT) {
				t.Fatalf("error = %v, want ErrInvalidClient naming %s | 错误 = %v，期望指明 %s 的 ErrInvalidClient", err, ClientSecretJWT, err, ClientSecretJWT)
			}

			// The token endpoint still answers with the generic invalid_client body so it does
			// not reveal authentication internals. | 令牌端点仍返回通用 invalid_client 正文，避免
			// 泄露认证内部细节。
			recorder := httptest.NewRecorder()
			server.Token(recorder, request)
			body := decodeMap(t, recorder)
			if recorder.Code != http.StatusUnauthorized || body["error"] != ErrorInvalidClient {
				t.Fatalf("token response = %d %v | 令牌响应 = %d %v", recorder.Code, body, recorder.Code, body)
			}
		})
	}
	if verifier.Calls != 0 {
		t.Fatalf("client_secret_jwt reached the private_key_jwt verifier | client_secret_jwt 到达了 private_key_jwt 校验器")
	}
}
