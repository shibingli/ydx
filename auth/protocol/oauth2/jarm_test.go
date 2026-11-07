package oauth2

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// jarmFlowServer builds a flow server whose client can be adjusted before validation. |
// jarmFlowServer 构建可在校验前调整客户端的流程服务器。
func jarmFlowServer(t *testing.T, signer AuthorizationResponseSigner, mutate func(*ServerConfig, *Client)) (*Server, *Client) {
	t.Helper()
	client := flowClient()
	config := ServerConfig{
		Issuer:                      "https://auth.example",
		Store:                       NewMemoryStore(),
		Scopes:                      flowScopes(),
		AccessTokenTTL:              time.Minute,
		AuthorizationResponseSigner: signer,
		Clock:                       func() time.Time { return flowNow },
		Authenticator: AuthenticatorFunc(func(context.Context, http.ResponseWriter, *http.Request, *AuthorizationRequest) (*auth.Principal, error) {
			return &auth.Principal{Subject: "user-1", AuthTime: flowNow, AMR: []string{"pwd"}}, nil
		}),
	}
	if mutate != nil {
		mutate(&config, client)
	}
	config.Clients = NewMemoryClientStore(client)
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server, client
}

// fakeAuthorizationSigner records JARM calls and optionally fails. | fakeAuthorizationSigner 记录 JARM
// 调用并可选择失败。
type fakeAuthorizationSigner struct {
	key        *jose.Key
	set        *jose.KeySet
	err        error
	empty      bool
	calls      int
	lastParams url.Values
	lastClient *Client
	lastIssuer string
}

// SignAuthorizationResponse implements AuthorizationResponseSigner with a real ES256 JWS. |
// SignAuthorizationResponse 用真实 ES256 JWS 实现 AuthorizationResponseSigner。
func (f *fakeAuthorizationSigner) SignAuthorizationResponse(_ context.Context, issuer string, client *Client, params url.Values) (string, error) {
	f.calls++
	f.lastClient = client
	f.lastIssuer = issuer
	f.lastParams = cloneValues(params)
	if f.err != nil {
		return "", f.err
	}
	if f.empty {
		return "", nil
	}
	claims := make(map[string]any, len(params)+4)
	for name, values := range params {
		if len(values) > 0 {
			claims[name] = values[0]
		}
	}
	claims["iss"] = issuer
	claims["aud"] = client.ID
	claims["exp"] = flowNow.Add(5 * time.Minute).Unix()
	claims["iat"] = flowNow.Unix()
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, f.key, jose.SignOptions{Alg: "ES256", Kid: f.key.Kid, Typ: "JWT"})
}

// AuthorizationSigningAlgValuesSupported implements AuthorizationSigningAlgProvider. |
// AuthorizationSigningAlgValuesSupported 实现 AuthorizationSigningAlgProvider。
func (f *fakeAuthorizationSigner) AuthorizationSigningAlgValuesSupported() []string {
	return []string{"ES256"}
}

// newFakeAuthorizationSigner returns a signer holding a fresh ES256 key. | newFakeAuthorizationSigner
// 返回持有新 ES256 密钥的签名器。
func newFakeAuthorizationSigner(t *testing.T) *fakeAuthorizationSigner {
	t.Helper()
	key, set := newTestJWTKey(t)
	return &fakeAuthorizationSigner{key: key, set: set}
}

// verifyJARMToken verifies the signature and decodes the JARM claim set. | verifyJARMToken 校验签名并
// 解码 JARM 声明集。
func verifyJARMToken(t *testing.T, signer *fakeAuthorizationSigner, token string) map[string]any {
	t.Helper()
	verified, err := jose.VerifyContext(context.Background(), token, signer.set.Resolver(), jose.VerifyOptions{
		ValidAlgs: []string{"ES256"},
	})
	if err != nil {
		t.Fatalf("verify JARM token: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(verified.Claims, &claims); err != nil {
		t.Fatalf("decode JARM claims: %v", err)
	}
	return claims
}

// jarmValues extracts the outer JARM parameters for mode. | jarmValues 提取 mode 的外层 JARM 参数。
func jarmValues(t *testing.T, resp *http.Response, mode string) url.Values {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if mode == ResponseModeFormPost {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if strings.Count(text, "<input") != 1 {
			t.Fatalf("form_post body has unexpected inputs: %s", text)
		}
		const marker = `name="response" value="`
		index := strings.Index(text, marker)
		if index < 0 {
			t.Fatalf("form_post body has no response input: %s", text)
		}
		rest := text[index+len(marker):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			t.Fatalf("unterminated response input: %s", text)
		}
		return url.Values{"response": {rest[:end]}}
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	switch mode {
	case ResponseModeFragment:
		if location.RawQuery != "" {
			t.Fatalf("fragment response has query parameters: %s", location.RawQuery)
		}
		values, err := url.ParseQuery(location.Fragment)
		if err != nil {
			t.Fatal(err)
		}
		return values
	default:
		if location.Fragment != "" {
			t.Fatalf("query response has fragment parameters: %s", location.Fragment)
		}
		return location.Query()
	}
}

func TestJARMAuthorizationResponseModes(t *testing.T) {
	cases := []struct {
		name         string
		responseType string
		mode         string
		delivery     string
		mutate       func(*ServerConfig, *Client)
	}{
		{name: "query.jwt code", responseType: ResponseCode, mode: ResponseModeQueryJWT, delivery: ResponseModeQuery},
		{name: "fragment.jwt code", responseType: ResponseCode, mode: ResponseModeFragmentJWT, delivery: ResponseModeFragment},
		{name: "form_post.jwt code", responseType: ResponseCode, mode: ResponseModeFormPostJWT, delivery: ResponseModeFormPost},
		{name: "jwt code", responseType: ResponseCode, mode: ResponseModeJWT, delivery: ResponseModeQuery},
		{
			name:         "jwt token",
			responseType: ResponseToken,
			mode:         ResponseModeJWT,
			delivery:     ResponseModeFragment,
			mutate: func(config *ServerConfig, client *Client) {
				config.AllowImplicit = true
				client.ResponseTypes = []string{ResponseCode, ResponseToken}
			},
		},
		{
			name:         "fragment.jwt token",
			responseType: ResponseToken,
			mode:         ResponseModeFragmentJWT,
			delivery:     ResponseModeFragment,
			mutate: func(config *ServerConfig, client *Client) {
				config.AllowImplicit = true
				client.ResponseTypes = []string{ResponseCode, ResponseToken}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := newFakeAuthorizationSigner(t)
			server, client := jarmFlowServer(t, signer, func(config *ServerConfig, client *Client) {
				if tc.mutate != nil {
					tc.mutate(config, client)
				}
			})
			verifier, _ := pkcePair(t)
			values := codeAuthorizationValues(client, verifier)
			values.Set("response_mode", tc.mode)
			if tc.responseType == ResponseToken {
				values = url.Values{
					"response_type": {ResponseToken},
					"client_id":     {client.ID},
					"redirect_uri":  {client.RedirectURIs[0]},
					"scope":         {ScopeOpenID},
					"state":         {"state-1"},
					"response_mode": {tc.mode},
				}
			}
			resp := authorize(t, server, values)
			if tc.delivery == ResponseModeFormPost {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d", resp.StatusCode)
				}
			} else if resp.StatusCode != http.StatusFound {
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
			outer := jarmValues(t, resp, tc.delivery)
			if len(outer) != 1 || outer.Get("response") == "" {
				t.Fatalf("outer parameters = %v", outer)
			}
			claims := verifyJARMToken(t, signer, outer.Get("response"))
			if claims["iss"] != server.Issuer() || claims["aud"] != client.ID {
				t.Fatalf("iss/aud = %v/%v", claims["iss"], claims["aud"])
			}
			if claims["state"] != "state-1" {
				t.Fatalf("state = %v", claims["state"])
			}
			if _, ok := claims["exp"]; !ok {
				t.Fatal("JARM token has no exp")
			}
			if _, ok := claims["iat"]; !ok {
				t.Fatal("JARM token has no iat")
			}
			if signer.calls != 1 {
				t.Fatalf("signer calls = %d", signer.calls)
			}
			if signer.lastClient == nil || signer.lastClient.ID != client.ID || signer.lastIssuer != server.Issuer() {
				t.Fatalf("signer arguments = %+v/%s", signer.lastClient, signer.lastIssuer)
			}
			if signer.lastParams.Get("state") != "state-1" {
				t.Fatalf("signed parameters = %v", signer.lastParams)
			}
			switch tc.responseType {
			case ResponseCode:
				code, _ := claims["code"].(string)
				if code == "" {
					t.Fatalf("claims have no code: %v", claims)
				}
				token, status := tokenRequest(t, server, url.Values{
					"grant_type":    {GrantAuthorizationCode},
					"code":          {code},
					"redirect_uri":  {client.RedirectURIs[0]},
					"code_verifier": {verifier},
				}, client.ID, "super-secret")
				if status != http.StatusOK || token.AccessToken == "" {
					t.Fatalf("token exchange status = %d", status)
				}
			case ResponseToken:
				if claims["access_token"] == "" || claims["token_type"] == "" {
					t.Fatalf("implicit claims = %v", claims)
				}
			}
		})
	}
}

func TestJARMSignedErrorResponse(t *testing.T) {
	signer := newFakeAuthorizationSigner(t)
	server, client := jarmFlowServer(t, signer, nil)
	values := codeAuthorizationValues(client, "verifier")
	values.Del("code_challenge")
	values.Del("code_challenge_method")
	values.Set("response_mode", ResponseModeQueryJWT)
	resp := authorize(t, server, values)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	outer := jarmValues(t, resp, ResponseModeQuery)
	if len(outer) != 1 || outer.Get("response") == "" {
		t.Fatalf("outer parameters = %v", outer)
	}
	claims := verifyJARMToken(t, signer, outer.Get("response"))
	if claims["error"] != ErrorInvalidRequest {
		t.Fatalf("error claim = %v", claims["error"])
	}
	if claims["state"] != "state-1" {
		t.Fatalf("state = %v", claims["state"])
	}
	if claims["iss"] != server.Issuer() || claims["aud"] != client.ID {
		t.Fatalf("iss/aud = %v/%v", claims["iss"], claims["aud"])
	}
}

func TestJARMWithoutSignerIsUnsupported(t *testing.T) {
	server, client := jarmFlowServer(t, nil, nil)
	verifier, _ := pkcePair(t)
	values := codeAuthorizationValues(client, verifier)
	values.Set("response_mode", ResponseModeQueryJWT)
	w := doRequest(t, server.Authorize, http.MethodGet, "/authorize?"+values.Encode(), nil, nil)
	requireErrorCode(t, w, http.StatusBadRequest, ErrorUnsupportedResponseType)
}

func TestJARMSignerFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeAuthorizationSigner)
	}{
		{name: "signer error", mutate: func(signer *fakeAuthorizationSigner) { signer.err = errTest }},
		{name: "empty token", mutate: func(signer *fakeAuthorizationSigner) { signer.empty = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := newFakeAuthorizationSigner(t)
			tc.mutate(signer)
			server, client := jarmFlowServer(t, signer, nil)
			verifier, _ := pkcePair(t)
			values := codeAuthorizationValues(client, verifier)
			values.Set("response_mode", ResponseModeQueryJWT)
			w := doRequest(t, server.Authorize, http.MethodGet, "/authorize?"+values.Encode(), nil, nil)
			requireErrorCode(t, w, http.StatusInternalServerError, ErrorServerError)
		})
	}
}

func TestJARMMetadata(t *testing.T) {
	signer := newFakeAuthorizationSigner(t)
	server, _ := jarmFlowServer(t, signer, func(config *ServerConfig, _ *Client) {
		config.RequestObjects = RequestObjectConfig{Enabled: true, SigningAlgs: []string{"ES256"}}
		config.RequestURIs = RequestURIConfig{Enabled: true, RequireRegistration: true}
	})
	metadata := server.MetadataDocument()
	for _, mode := range []string{
		ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT,
	} {
		if !containsString(metadata.ResponseModesSupported, mode) {
			t.Fatalf("response modes = %v missing %q", metadata.ResponseModesSupported, mode)
		}
	}
	if len(metadata.AuthorizationSigningAlgValuesSupported) != 1 || metadata.AuthorizationSigningAlgValuesSupported[0] != "ES256" {
		t.Fatalf("JARM algorithms = %v", metadata.AuthorizationSigningAlgValuesSupported)
	}
	if !metadata.RequestParameterSupported || !metadata.RequestURIParameterSupported || !metadata.RequireRequestURIRegistration {
		t.Fatalf("request metadata = %+v", metadata)
	}
	if len(metadata.RequestObjectSigningAlgValuesSupported) != 1 || metadata.RequestObjectSigningAlgValuesSupported[0] != "ES256" {
		t.Fatalf("request object algorithms = %v", metadata.RequestObjectSigningAlgValuesSupported)
	}

	plain, _ := jarmFlowServer(t, nil, nil)
	doc := plain.MetadataDocument()
	for _, mode := range []string{ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT} {
		if containsString(doc.ResponseModesSupported, mode) {
			t.Fatalf("plain server advertises %q", mode)
		}
	}
	if len(doc.AuthorizationSigningAlgValuesSupported) != 0 || doc.RequestParameterSupported {
		t.Fatalf("plain metadata = %+v", doc)
	}
}
