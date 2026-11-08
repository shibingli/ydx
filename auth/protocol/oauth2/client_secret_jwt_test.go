package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// testClientSecretJWTSecret is an obvious fixed test secret with enough bytes for HS512. |
// testClientSecretJWTSecret 是明显的固定测试密钥，字节数足以支持 HS512。
const testClientSecretJWTSecret = "test-client-secret-jwt-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// memoryClientSecretResolver is a concurrency-safe in-memory resolver used by tests. |
// memoryClientSecretResolver 是测试使用的并发安全内存解析器。
type memoryClientSecretResolver struct {
	mu      sync.Mutex
	secrets map[string]string
	err     error
	calls   int
}

// ClientSecret implements ClientSecretResolver. | ClientSecret 实现 ClientSecretResolver。
func (r *memoryClientSecretResolver) ClientSecret(_ context.Context, client *Client) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	return r.secrets[client.ID], nil
}

// callsCount returns the number of resolver calls. | callsCount 返回解析器调用次数。
func (r *memoryClientSecretResolver) callsCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// memoryClientSecretRegistrar stores issued secrets for resolver lookups. |
// memoryClientSecretRegistrar 保存签发的密钥，供解析器查询。
type memoryClientSecretRegistrar struct {
	mu      sync.Mutex
	secrets map[string]string
	err     error
}

// RegisterClientSecret implements ClientSecretRegistrar. | RegisterClientSecret 实现 ClientSecretRegistrar。
func (r *memoryClientSecretRegistrar) RegisterClientSecret(_ context.Context, clientID, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if r.secrets == nil {
		r.secrets = make(map[string]string)
	}
	r.secrets[clientID] = secret
	return nil
}

// secret returns the stored secret for clientID. | secret 返回 clientID 的已保存密钥。
func (r *memoryClientSecretRegistrar) secret(clientID string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.secrets[clientID]
}

// hsJWTClient returns a client registered for client_secret_jwt. | hsJWTClient 返回注册为
// client_secret_jwt 的客户端。
func hsJWTClient(id string) *Client {
	return &Client{
		ID:                      id,
		RedirectURIs:            []string{"https://client.example/callback"},
		GrantTypes:              []string{GrantAuthorizationCode, GrantClientCredentials, GrantDeviceCode},
		ResponseTypes:           []string{ResponseCode},
		Scopes:                  []string{"api:read"},
		TokenEndpointAuthMethod: ClientSecretJWT,
	}
}

// newHSJWTServer builds a server with client_secret_jwt enabled and a resolver primed with the
// fixed test secret for every supplied client. | newHSJWTServer 构建启用 client_secret_jwt 的服务器，
// 解析器为每个客户端预置固定测试密钥。
func newHSJWTServer(t *testing.T, mutate func(*ServerConfig), clients ...*Client) (*Server, *memoryClientSecretResolver) {
	t.Helper()
	resolver := &memoryClientSecretResolver{secrets: make(map[string]string, len(clients))}
	for _, client := range clients {
		resolver.secrets[client.ID] = testClientSecretJWTSecret
	}
	server := issuerPathServer(t, func(config *ServerConfig) {
		config.ClientSecretJWT = &ClientSecretJWTConfig{Resolver: resolver}
		if mutate != nil {
			mutate(config)
		}
	}, clients...)
	return server, resolver
}

// signHSClientAssertion signs an RFC 7523 client assertion with an HMAC algorithm. |
// signHSClientAssertion 使用 HMAC 算法签发 RFC 7523 客户端断言。
func signHSClientAssertion(t *testing.T, secret, alg, clientID, audience string, mutate func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"exp": flowNow.Add(2 * time.Minute).Unix(),
		"iat": flowNow.Unix(),
		"jti": auth.NewID("jti"),
	}
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal assertion: %v | 编码断言：%v", err, err)
	}
	key, err := jose.FromHMAC("", []byte(secret))
	if err != nil {
		t.Fatalf("hmac key: %v | HMAC 密钥：%v", err, err)
	}
	assertion, err := jose.Sign(payload, key, jose.SignOptions{Alg: alg})
	if err != nil {
		t.Fatalf("sign assertion: %v | 签发断言：%v", err, err)
	}
	return assertion
}

// clientAssertionTokenForm returns a client_credentials token request carrying an assertion. |
// clientAssertionTokenForm 返回携带断言的 client_credentials 令牌请求。
func clientAssertionTokenForm(clientID, assertion string) url.Values {
	return url.Values{
		"grant_type":            {GrantClientCredentials},
		"client_id":             {clientID},
		"client_assertion":      {assertion},
		"client_assertion_type": {ClientAssertionTypeJWTBearer},
	}
}

// TestClientSecretJWTAcceptsHSAlgorithms verifies HS256, HS384 and HS512 assertions authenticate
// a client at the token endpoint. | TestClientSecretJWTAcceptsHSAlgorithms 校验 HS256、HS384 与
// HS512 断言都能在令牌端点认证客户端。
func TestClientSecretJWTAcceptsHSAlgorithms(t *testing.T) {
	client := hsJWTClient("hs-client")
	server, _ := newHSJWTServer(t, nil, client)
	audience := server.Endpoint(server.config.TokenPath)
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		t.Run(alg, func(t *testing.T) {
			assertion := signHSClientAssertion(t, testClientSecretJWTSecret, alg, client.ID, audience, nil)
			w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, assertion), nil)
			if w.Code != http.StatusOK {
				t.Fatalf("token status = %d body=%s | 令牌状态 = %d 正文 = %s", w.Code, w.Body.String(), w.Code, w.Body.String())
			}
			body := decodeMap(t, w)
			if body["access_token"] == "" || body["access_token"] == nil {
				t.Fatalf("access_token missing: %v | 缺少 access_token：%v", body, body)
			}
		})
	}
}

// TestClientSecretJWTRejectsInvalidAssertions verifies every claim and signature failure is
// classified as invalid_client. | TestClientSecretJWTRejectsInvalidAssertions 校验每个声明与签名
// 失败都被归类为 invalid_client。
func TestClientSecretJWTRejectsInvalidAssertions(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		alg    string
		mutate func(map[string]any)
	}{
		{
			name: "wrong audience",
			mutate: func(claims map[string]any) {
				claims["aud"] = "https://auth.example/introspect"
			},
		},
		{
			name: "wrong issuer",
			mutate: func(claims map[string]any) {
				claims["iss"] = "other-client"
			},
		},
		{
			name: "wrong subject",
			mutate: func(claims map[string]any) {
				claims["sub"] = "other-client"
			},
		},
		{
			name: "expired",
			mutate: func(claims map[string]any) {
				claims["exp"] = flowNow.Add(-time.Minute).Unix()
			},
		},
		{
			name: "not before in the future",
			mutate: func(claims map[string]any) {
				claims["nbf"] = flowNow.Add(time.Minute).Unix()
			},
		},
		{
			name: "issued at in the future",
			mutate: func(claims map[string]any) {
				claims["iat"] = flowNow.Add(time.Minute).Unix()
			},
		},
		{
			name: "missing exp",
			mutate: func(claims map[string]any) {
				delete(claims, "exp")
			},
		},
		{
			name: "missing jti",
			mutate: func(claims map[string]any) {
				delete(claims, "jti")
			},
		},
		{
			name: "lifetime too long",
			mutate: func(claims map[string]any) {
				claims["exp"] = flowNow.Add(10 * time.Minute).Unix()
			},
		},
		{
			name:   "wrong secret",
			secret: testClientSecretJWTSecret + "-wrong",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := hsJWTClient("hs-client")
			server, _ := newHSJWTServer(t, nil, client)
			secret := tc.secret
			if secret == "" {
				secret = testClientSecretJWTSecret
			}
			assertion := signHSClientAssertion(t, secret, "HS256", client.ID, server.Endpoint(server.config.TokenPath), tc.mutate)
			w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, assertion), nil)
			requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
		})
	}
}

// TestClientSecretJWTRejectsAsymmetricAssertion verifies an RS256 assertion cannot authenticate a
// client_secret_jwt client even when the signature itself would verify with the wrong key type. |
// TestClientSecretJWTRejectsAsymmetricAssertion 校验即使签名本身可用错误密钥类型验证，RS256 断言
// 也不能认证 client_secret_jwt 客户端。
func TestClientSecretJWTRejectsAsymmetricAssertion(t *testing.T) {
	client := hsJWTClient("hs-client")
	server, _ := newHSJWTServer(t, nil, client)
	key, err := jose.GenerateKey("RS256", 2048)
	if err != nil {
		t.Fatalf("generate key: %v | 生成密钥：%v", err, err)
	}
	claims := map[string]any{
		"iss": client.ID,
		"sub": client.ID,
		"aud": server.Endpoint(server.config.TokenPath),
		"exp": flowNow.Add(2 * time.Minute).Unix(),
		"iat": flowNow.Unix(),
		"jti": auth.NewID("jti"),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal assertion: %v | 编码断言：%v", err, err)
	}
	assertion, err := jose.Sign(payload, key, jose.SignOptions{Alg: "RS256"})
	if err != nil {
		t.Fatalf("sign assertion: %v | 签发断言：%v", err, err)
	}
	w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, assertion), nil)
	requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
}

// TestClientSecretJWTRegisteredAlgorithmIsEnforced verifies the registered
// token_endpoint_auth_signing_alg confines the accepted HMAC algorithm. |
// TestClientSecretJWTRegisteredAlgorithmIsEnforced 校验注册的 token_endpoint_auth_signing_alg
// 限定可接受的 HMAC 算法。
func TestClientSecretJWTRegisteredAlgorithmIsEnforced(t *testing.T) {
	client := hsJWTClient("hs-client")
	client.TokenEndpointAuthSigningAlg = "HS256"
	server, _ := newHSJWTServer(t, nil, client)
	audience := server.Endpoint(server.config.TokenPath)

	valid := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, audience, nil)
	w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, valid), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("HS256 status = %d body=%s | HS256 状态 = %d 正文 = %s", w.Code, w.Body.String(), w.Code, w.Body.String())
	}
	wrongAlg := signHSClientAssertion(t, testClientSecretJWTSecret, "HS512", client.ID, audience, nil)
	w = doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, wrongAlg), nil)
	requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)

	// A registered asymmetric algorithm can never be satisfied by an HMAC assertion. | 注册的非对称
	// 算法永远无法由 HMAC 断言满足。
	asymmetric := hsJWTClient("asymmetric-client")
	asymmetric.TokenEndpointAuthSigningAlg = "RS256"
	server, _ = newHSJWTServer(t, nil, asymmetric)
	assertion := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", asymmetric.ID, server.Endpoint(server.config.TokenPath), nil)
	w = doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(asymmetric.ID, assertion), nil)
	requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
}

// TestClientSecretJWTReplayIsRejected verifies a reused jti fails after the first success. |
// TestClientSecretJWTReplayIsRejected 校验重复的 jti 在首次成功后失败。
func TestClientSecretJWTReplayIsRejected(t *testing.T) {
	client := hsJWTClient("hs-client")
	server, _ := newHSJWTServer(t, nil, client)
	assertion := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, server.Endpoint(server.config.TokenPath), nil)
	form := clientAssertionTokenForm(client.ID, assertion)
	w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, form, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("first status = %d body=%s | 首次状态 = %d 正文 = %s", w.Code, w.Body.String(), w.Code, w.Body.String())
	}
	w = doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, form, nil)
	requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
}

// TestClientSecretJWTResolverFailures verifies a missing or failing resolver secret is rejected. |
// TestClientSecretJWTResolverFailures 校验缺失或失败的解析器密钥会被拒绝。
func TestClientSecretJWTResolverFailures(t *testing.T) {
	t.Run("missing secret", func(t *testing.T) {
		client := hsJWTClient("hs-client")
		server, resolver := newHSJWTServer(t, nil, client)
		resolver.mu.Lock()
		delete(resolver.secrets, client.ID)
		resolver.mu.Unlock()
		assertion := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, server.Endpoint(server.config.TokenPath), nil)
		w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, assertion), nil)
		requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
	})
	t.Run("resolver error", func(t *testing.T) {
		client := hsJWTClient("hs-client")
		server, resolver := newHSJWTServer(t, nil, client)
		resolver.mu.Lock()
		resolver.err = errTest
		resolver.mu.Unlock()
		assertion := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, server.Endpoint(server.config.TokenPath), nil)
		w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, assertion), nil)
		requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
	})
	t.Run("hash mismatch", func(t *testing.T) {
		client := hsJWTClient("hs-client")
		client.SetSecret("a-different-registered-secret")
		server, _ := newHSJWTServer(t, nil, client)
		assertion := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, server.Endpoint(server.config.TokenPath), nil)
		w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, assertion), nil)
		requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
	})
}

// TestClientSecretJWTRequiresResolver verifies construction fails without a resolver. |
// TestClientSecretJWTRequiresResolver 校验缺少解析器时构造失败。
func TestClientSecretJWTRequiresResolver(t *testing.T) {
	_, err := NewServer(ServerConfig{
		Issuer:          "https://auth.example",
		Clients:         NewMemoryClientStore(),
		Store:           NewMemoryStore(),
		ClientSecretJWT: &ClientSecretJWTConfig{},
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig | 错误 = %v，期望 ErrInvalidConfig", err, err)
	}
	if _, err := NewClientSecretJWTVerifier(ClientSecretJWTConfig{ValidAlgs: []string{"RS256"}, Resolver: &memoryClientSecretResolver{}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("non-HMAC alg error = %v | 非 HMAC 算法错误 = %v", err, err)
	}
	verifier, err := NewClientSecretJWTVerifier(ClientSecretJWTConfig{
		Resolver:    &memoryClientSecretResolver{},
		ValidAlgs:   []string{"HS256", "HS256"},
		MaxLifetime: 0,
	})
	if err != nil {
		t.Fatalf("verifier: %v | 校验器：%v", err, err)
	}
	if got := verifier.SigningAlgs(); len(got) != 1 || got[0] != "HS256" {
		t.Fatalf("SigningAlgs = %v | SigningAlgs = %v", got, got)
	}
}

// TestClientSecretJWTVerifierClassification verifies specific sentinels remain reachable while
// every failure also matches ErrInvalidClient. | TestClientSecretJWTVerifierClassification 校验特定
// 哨兵仍可判定，同时每个失败也匹配 ErrInvalidClient。
func TestClientSecretJWTVerifierClassification(t *testing.T) {
	client := hsJWTClient("hs-client")
	server, _ := newHSJWTServer(t, nil, client)
	verifier := server.clientSecretJWT
	if verifier == nil {
		t.Fatal("client_secret_jwt verifier missing | 缺少 client_secret_jwt 校验器")
	}
	audience := server.Endpoint(server.config.TokenPath)

	missingJTI := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, audience, func(claims map[string]any) {
		delete(claims, "jti")
	})
	err := verifier.VerifyClientAssertion(context.Background(), client, missingJTI, audience)
	if !errors.Is(err, ErrInvalidClient) || !errors.Is(err, ErrInvalidClientAssertion) {
		t.Fatalf("missing jti error = %v | 缺少 jti 错误 = %v", err, err)
	}

	assertion := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, audience, nil)
	if err := verifier.VerifyClientAssertion(context.Background(), client, assertion, audience); err != nil {
		t.Fatalf("first verification: %v | 首次校验：%v", err, err)
	}
	err = verifier.VerifyClientAssertion(context.Background(), client, assertion, audience)
	if !errors.Is(err, ErrInvalidClient) || !errors.Is(err, ErrClientAssertionReplay) {
		t.Fatalf("replay error = %v | 重放错误 = %v", err, err)
	}
}

// TestClientSecretJWTMetadataAdvertising verifies the method and HS algorithms appear only when
// enabled. | TestClientSecretJWTMetadataAdvertising 校验方法与 HS 算法仅在启用时公布。
func TestClientSecretJWTMetadataAdvertising(t *testing.T) {
	client := hsJWTClient("hs-client")
	server, _ := newHSJWTServer(t, nil, client)
	document := server.MetadataDocument()
	for _, methods := range [][]string{
		document.TokenEndpointAuthMethodsSupported,
		document.RevocationEndpointAuthMethodsSupported,
		document.IntrospectionEndpointAuthMethodsSupported,
	} {
		if !containsValue(methods, ClientSecretJWT) {
			t.Fatalf("client_secret_jwt missing from %v | client_secret_jwt 缺失于 %v", methods, methods)
		}
	}
	signingAlgs := document.TokenEndpointAuthSigningAlgValuesSupported
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		if !containsValue(signingAlgs, alg) {
			t.Fatalf("%s missing from %v | %s 缺失于 %v", alg, signingAlgs, alg, signingAlgs)
		}
	}

	disabled := issuerPathServer(t, func(config *ServerConfig) {
		config.ClientAssertionVerifier = &fakeClientAssertionVerifier{}
	}, client)
	document = disabled.MetadataDocument()
	if containsValue(document.TokenEndpointAuthMethodsSupported, ClientSecretJWT) {
		t.Fatalf("disabled metadata advertises client_secret_jwt: %v", document.TokenEndpointAuthMethodsSupported)
	}
	want := []string{"RS256", "PS256", "ES256", "EdDSA"}
	if len(document.TokenEndpointAuthSigningAlgValuesSupported) != len(want) {
		t.Fatalf("asymmetric signing algs = %v | 非对称签名算法 = %v", document.TokenEndpointAuthSigningAlgValuesSupported, document.TokenEndpointAuthSigningAlgValuesSupported)
	}
	for index, alg := range want {
		if document.TokenEndpointAuthSigningAlgValuesSupported[index] != alg {
			t.Fatalf("asymmetric signing algs = %v | 非对称签名算法 = %v", document.TokenEndpointAuthSigningAlgValuesSupported, document.TokenEndpointAuthSigningAlgValuesSupported)
		}
	}
}

// TestClientSecretJWTAuthenticatesEndpoints verifies PAR, device authorization, introspection and
// revocation authenticate client_secret_jwt with their own audience. |
// TestClientSecretJWTAuthenticatesEndpoints 校验 PAR、设备授权、自省与撤销都使用各自受众认证
// client_secret_jwt。
func TestClientSecretJWTAuthenticatesEndpoints(t *testing.T) {
	client := hsJWTClient("hs-client")
	_, challenge := pkcePair(t)
	base := url.Values{
		"client_id":             {client.ID},
		"client_assertion_type": {ClientAssertionTypeJWTBearer},
	}
	cases := []struct {
		name     string
		path     string
		handler  http.HandlerFunc
		params   url.Values
		wantCode int
	}{
		{
			name:    "PAR",
			path:    "/par",
			handler: nil,
			params: url.Values{
				"response_type":         {ResponseCode},
				"redirect_uri":          {client.RedirectURIs[0]},
				"scope":                 {"api:read"},
				"code_challenge":        {challenge},
				"code_challenge_method": {PKCES256},
			},
			wantCode: http.StatusCreated,
		},
		{
			name:     "device authorization",
			path:     "/device_authorization",
			params:   url.Values{"scope": {"api:read"}},
			wantCode: http.StatusOK,
		},
		{
			name:     "introspection",
			path:     "/introspect",
			params:   url.Values{"token": {"unknown-token"}},
			wantCode: http.StatusOK,
		},
		{
			name:     "revocation",
			path:     "/revoke",
			params:   url.Values{"token": {"unknown-token"}},
			wantCode: http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newHSJWTServer(t, nil, client)
			handler := tc.handler
			switch tc.path {
			case "/par":
				handler = server.PAR
			case "/device_authorization":
				handler = server.DeviceAuthorization
			case "/introspect":
				handler = server.Introspect
			case "/revoke":
				handler = server.Revoke
			}
			audience := server.Endpoint(tc.path)
			form := cloneValues(base)
			for key, values := range tc.params {
				form[key] = values
			}
			form.Set("client_assertion", signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, audience, nil))
			w := doRequest(t, handler, http.MethodPost, tc.path, form, nil)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d want %d body=%s | 状态 = %d 期望 %d 正文 = %s", w.Code, tc.wantCode, w.Body.String(), w.Code, tc.wantCode, w.Body.String())
			}

			// The same assertion addressed to the token endpoint must not authenticate another
			// endpoint. | 同一断言若指向令牌端点，不得认证其它端点。
			form.Set("client_assertion", signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, server.Endpoint(server.config.TokenPath), nil))
			w = doRequest(t, handler, http.MethodPost, tc.path, form, nil)
			requireErrorCode(t, w, http.StatusUnauthorized, ErrorInvalidClient)
		})
	}
}

// TestClientSecretJWTConcurrent verifies concurrent verification is race-free and that a single
// assertion is accepted exactly once. | TestClientSecretJWTConcurrent 校验并发校验无数据竞争，
// 且同一断言只被接受一次。
func TestClientSecretJWTConcurrent(t *testing.T) {
	client := hsJWTClient("hs-client")
	server, _ := newHSJWTServer(t, nil, client)
	audience := server.Endpoint(server.config.TokenPath)

	const workers = 16
	var wg sync.WaitGroup
	codes := make(chan int, workers)
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assertion := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, audience, nil)
			w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, assertion), nil)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("concurrent status = %d | 并发状态 = %d", code, code)
		}
	}

	shared := signHSClientAssertion(t, testClientSecretJWTSecret, "HS256", client.ID, audience, nil)
	codes = make(chan int, workers)
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doRequest(t, server.Token, http.MethodPost, server.config.TokenPath, clientAssertionTokenForm(client.ID, shared), nil)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	accepted := 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			accepted++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("replay status = %d | 重放状态 = %d", code, code)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d times, want 1 | 接受 %d 次，期望 1 次", accepted, accepted)
	}
}

// TestClientSecretJWTServerRegistrationHelpers verifies the exported server helpers expose the
// resolver and registrar state. | TestClientSecretJWTServerRegistrationHelpers 校验导出的服务器
// 辅助方法暴露解析器与注册器状态。
func TestClientSecretJWTServerRegistrationHelpers(t *testing.T) {
	client := hsJWTClient("hs-client")
	resolver := &memoryClientSecretResolver{secrets: map[string]string{client.ID: testClientSecretJWTSecret}}
	registrar := &memoryClientSecretRegistrar{}
	server, err := NewServer(ServerConfig{
		Issuer:  "https://auth.example",
		Clients: NewMemoryClientStore(client),
		Store:   NewMemoryStore(),
		ClientSecretJWT: &ClientSecretJWTConfig{
			Resolver:  resolver,
			Registrar: registrar,
		},
	})
	if err != nil {
		t.Fatalf("new server: %v | 新服务器：%v", err, err)
	}
	if !server.ClientSecretJWTEnabled() || !server.ClientSecretJWTRegistrarEnabled() {
		t.Fatal("client_secret_jwt helpers report disabled | client_secret_jwt 辅助方法报告为禁用")
	}
	if got := server.ClientSecretJWTSigningAlgs(); len(got) != 3 {
		t.Fatalf("signing algs = %v | 签名算法 = %v", got, got)
	}
	if err := server.RegisterClientSecret(context.Background(), client.ID, "issued-secret"); err != nil {
		t.Fatalf("register secret: %v | 注册密钥：%v", err, err)
	}
	if got := registrar.secret(client.ID); got != "issued-secret" {
		t.Fatalf("registered secret = %q | 已注册密钥 = %q", got, got)
	}

	disabled := issuerPathServer(t, nil, client)
	if disabled.ClientSecretJWTEnabled() {
		t.Fatal("default server enables client_secret_jwt | 默认服务器启用了 client_secret_jwt")
	}
	if err := disabled.RegisterClientSecret(context.Background(), client.ID, "x"); !errors.Is(err, ErrClientSecretJWTDisabled) {
		t.Fatalf("disabled error = %v | 禁用错误 = %v", err, err)
	}

	noRegistrar, err := NewServer(ServerConfig{
		Issuer:          "https://auth.example",
		Clients:         NewMemoryClientStore(client),
		Store:           NewMemoryStore(),
		ClientSecretJWT: &ClientSecretJWTConfig{Resolver: resolver},
	})
	if err != nil {
		t.Fatalf("new server: %v | 新服务器：%v", err, err)
	}
	if noRegistrar.ClientSecretJWTRegistrarEnabled() {
		t.Fatal("registrar reported without one | 未配置注册器却报告存在")
	}
	if err := noRegistrar.RegisterClientSecret(context.Background(), client.ID, "x"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing registrar error = %v | 缺少注册器错误 = %v", err, err)
	}
}

// containsValue reports whether values contains want. | containsValue 报告 values 是否包含 want。
func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
