package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// flowReplayStore is a deterministic request-object replay store driven by flowNow. |
// flowReplayStore 是由 flowNow 驱动的确定性请求对象重放存储。
type flowReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// newFlowReplayStore returns an empty deterministic replay store. | newFlowReplayStore 返回空的
// 确定性重放存储。
func newFlowReplayStore() *flowReplayStore {
	return &flowReplayStore{seen: make(map[string]time.Time)}
}

// Accept records jti until expiresAt relative to flowNow. | Accept 依据 flowNow 记录 jti 至 expiresAt。
func (s *flowReplayStore) Accept(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expiry := range s.seen {
		if !flowNow.Before(expiry) {
			delete(s.seen, key)
		}
	}
	if _, exists := s.seen[jti]; exists {
		return false, nil
	}
	s.seen[jti] = expiresAt
	return true, nil
}

// requestObjectClaims builds a valid RFC 9101 claim set from authorization values. |
// requestObjectClaims 从授权参数构建合法的 RFC 9101 声明集。
func requestObjectClaims(clientID string, values url.Values, now time.Time) map[string]any {
	claims := map[string]any{
		"client_id": clientID,
		"iss":       clientID,
		"aud":       "https://auth.example",
		"iat":       now.Unix(),
		"exp":       now.Add(2 * time.Minute).Unix(),
		"jti":       "request-" + values.Get("state"),
	}
	for name, items := range values {
		if len(items) > 0 {
			claims[name] = items[0]
		}
	}
	return claims
}

// signRequestObject serializes and signs request-object claims. | signRequestObject 序列化并签名
// 请求对象声明。
func signRequestObject(t *testing.T, key *jose.Key, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal request object: %v", err)
	}
	signed, err := jose.Sign(payload, key, jose.SignOptions{Alg: "ES256", Kid: key.Kid})
	if err != nil {
		t.Fatalf("sign request object: %v", err)
	}
	return signed
}

// requestObjectServer builds a flow server with RFC 9101 request objects enabled. |
// requestObjectServer 构建启用 RFC 9101 请求对象的流程服务器。
func requestObjectServer(t *testing.T, mutate func(*ServerConfig, *Client)) (*Server, *Client, *jose.Key) {
	t.Helper()
	key, _ := newTestJWTKey(t)
	client := flowClient()
	client.JWKS = publicJWKS(t, key)
	client.RequestObjectSigningAlg = "ES256"
	server, _ := flowServer(t, func(config *ServerConfig) {
		config.RequestObjects = RequestObjectConfig{
			Enabled:     true,
			SigningAlgs: []string{"ES256"},
			Replay:      newFlowReplayStore(),
			RequireJTI:  true,
		}
		if mutate != nil {
			mutate(config, client)
		}
		config.Clients = NewMemoryClientStore(client)
	})
	return server, client, key
}

// authorizeRequestObject performs a GET authorization request with request. | authorizeRequestObject
// 使用 request 执行 GET 授权请求。
func authorizeRequestObject(t *testing.T, server *Server, clientID, requestObject string) *http.Response {
	t.Helper()
	return authorize(t, server, url.Values{"client_id": {clientID}, "request": {requestObject}})
}

func TestRequestObjectAuthorizationSuccess(t *testing.T) {
	server, client, key := requestObjectServer(t, nil)
	verifier, _ := pkcePair(t)
	values := codeAuthorizationValues(client, verifier)
	object := signRequestObject(t, key, requestObjectClaims(client.ID, values, flowNow))
	// Outer parameters conflict on purpose: RFC 9101 says only the signed object counts. | 外层
	// 参数故意冲突：RFC 9101 规定只采用已签名对象内容。
	outer := url.Values{
		"client_id":     {client.ID},
		"request":       {object},
		"response_type": {ResponseToken},
		"redirect_uri":  {"https://evil.example/cb"},
		"state":         {"outer-state"},
	}
	resp := authorize(t, server, outer)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Scheme != "https" || location.Host != "client.example" {
		t.Fatalf("redirect = %s", location)
	}
	query := location.Query()
	code := query.Get("code")
	if code == "" || query.Get("state") != "state-1" || query.Get("iss") != server.Issuer() {
		t.Fatalf("response = %v", query)
	}
	token, status := tokenRequest(t, server, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {client.RedirectURIs[0]},
		"code_verifier": {verifier},
	}, client.ID, "super-secret")
	if status != http.StatusOK || token.AccessToken == "" {
		t.Fatalf("token = %+v status=%d", token, status)
	}
	// The same jti is rejected on replay. | 相同 jti 重放被拒绝。
	requireErrorCode(t, doRequest(t, server.Authorize, http.MethodGet, "/authorize?"+outer.Encode(), nil, nil),
		http.StatusBadRequest, ErrorInvalidRequestObject)
}

func TestRequestObjectValidationErrors(t *testing.T) {
	verifier, _ := pkcePair(t)
	cases := []struct {
		name       string
		mutate     func(*ServerConfig, *Client)
		claims     func(map[string]any)
		signer     func(*testing.T, *jose.Key) string
		want       string
		wantStatus int
	}{
		{
			name:   "request disabled",
			mutate: func(config *ServerConfig, _ *Client) { config.RequestObjects.Enabled = false },
			want:   ErrorRequestNotSupported,
		},
		{
			name:       "missing client_id",
			want:       ErrorInvalidRequest,
			wantStatus: http.StatusBadRequest,
			claims:     func(claims map[string]any) { delete(claims, "client_id") },
		},
		{
			name:       "unknown client",
			want:       ErrorInvalidClient,
			wantStatus: http.StatusUnauthorized,
			claims:     func(claims map[string]any) {},
		},
		{
			name:   "client_id claim mismatch",
			want:   ErrorInvalidRequest,
			claims: func(claims map[string]any) { claims["client_id"] = "other" },
		},
		{
			name:   "iss mismatch",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["iss"] = "other" },
		},
		{
			name:   "aud mismatch",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["aud"] = "https://other.example" },
		},
		{
			name:   "aud wrong type",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["aud"] = 42 },
		},
		{
			name:   "missing exp",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { delete(claims, "exp") },
		},
		{
			name:   "expired",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["exp"] = flowNow.Add(-time.Minute).Unix() },
		},
		{
			name:   "lifetime too long",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["exp"] = flowNow.Add(time.Hour).Unix() },
		},
		{
			name:   "iat in future",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["iat"] = flowNow.Add(10 * time.Minute).Unix() },
		},
		{
			name:   "nbf in future",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["nbf"] = flowNow.Add(10 * time.Minute).Unix() },
		},
		{
			name:   "nested request",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["request"] = "nested" },
		},
		{
			name:   "nested request_uri",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["request_uri"] = "https://client.example/obj" },
		},
		{
			name:   "client restricts algorithm",
			mutate: func(_ *ServerConfig, client *Client) { client.RequestObjectSigningAlg = "RS256" },
			want:   ErrorInvalidRequestObject,
		},
		{
			name:   "missing jti",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { delete(claims, "jti") },
		},
		{
			name:   "boolean parameter",
			want:   ErrorInvalidRequestObject,
			claims: func(claims map[string]any) { claims["prompt"] = true },
		},
		{
			name: "bad signature",
			signer: func(t *testing.T, _ *jose.Key) string {
				other, _ := newTestJWTKey(t)
				return signRequestObject(t, other, requestObjectClaims("web", codeAuthorizationValues(flowClient(), verifier), flowNow))
			},
			want: ErrorInvalidRequestObject,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client, key := requestObjectServer(t, tc.mutate)
			values := codeAuthorizationValues(client, verifier)
			claims := requestObjectClaims(client.ID, values, flowNow)
			clientID := client.ID
			if tc.name == "unknown client" {
				clientID = "ghost"
			}
			if tc.claims != nil {
				claims["client_id"] = clientID
				tc.claims(claims)
			}
			var object string
			if tc.signer != nil {
				object = tc.signer(t, key)
			} else {
				object = signRequestObject(t, key, claims)
			}
			w := doRequest(t, server.Authorize, http.MethodGet,
				"/authorize?"+url.Values{"client_id": {clientID}, "request": {object}}.Encode(), nil, nil)
			status := tc.wantStatus
			if status == 0 {
				status = http.StatusBadRequest
			}
			requireErrorCode(t, w, status, tc.want)
		})
	}
}

func TestRequestObjectDuplicateParametersRejected(t *testing.T) {
	server, client, key := requestObjectServer(t, nil)
	object := signRequestObject(t, key, requestObjectClaims(client.ID, codeAuthorizationValues(client, "verifier"), flowNow))
	w := doRequest(t, server.Authorize, http.MethodGet, "/authorize?"+url.Values{
		"client_id":   {client.ID},
		"request":     {object},
		"request_uri": {"https://client.example/object"},
	}.Encode(), nil, nil)
	requireErrorCode(t, w, http.StatusBadRequest, ErrorInvalidRequest)
}

func TestRequestObjectViaPAR(t *testing.T) {
	server, client, key := requestObjectServer(t, nil)
	verifier, _ := pkcePair(t)
	object := signRequestObject(t, key, requestObjectClaims(client.ID, codeAuthorizationValues(client, verifier), flowNow))
	form := url.Values{"client_id": {client.ID}, "request": {object}}
	req := doRequest(t, server.PAR, http.MethodPost, "/par", form, func(r *http.Request) {
		r.SetBasicAuth(url.QueryEscape(client.ID), url.QueryEscape("super-secret"))
	})
	if req.Code != http.StatusCreated {
		t.Fatalf("PAR status = %d body=%s", req.Code, req.Body.String())
	}
	var pushed struct {
		RequestURI string `json:"request_uri"`
	}
	if err := json.Unmarshal(req.Body.Bytes(), &pushed); err != nil {
		t.Fatal(err)
	}
	resp := authorize(t, server, url.Values{"client_id": {client.ID}, "request_uri": {pushed.RequestURI}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	location, _ := url.Parse(resp.Header.Get("Location"))
	if location.Query().Get("code") == "" || location.Query().Get("state") != "state-1" {
		t.Fatalf("redirect = %s", location)
	}
	// A second consumption is rejected by the PAR store. | PAR 存储拒绝第二次消费。
	resp = authorize(t, server, url.Values{"client_id": {client.ID}, "request_uri": {pushed.RequestURI}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused request_uri status = %d", resp.StatusCode)
	}
}

func TestRequestObjectParameterShapes(t *testing.T) {
	server, client, key := requestObjectServer(t, nil)
	verifier, _ := pkcePair(t)
	claims := requestObjectClaims(client.ID, codeAuthorizationValues(client, verifier), flowNow)
	claims["max_age"] = float64(60)
	claims["claims"] = map[string]any{"id_token": map[string]any{"email": nil}}
	object := signRequestObject(t, key, claims)
	resp := authorizeRequestObject(t, server, client.ID, object)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
}

func TestRequestObjectHelpers(t *testing.T) {
	if _, ok := requestObjectTime(json.Number("123")); !ok {
		t.Fatal("json.Number time rejected")
	}
	if _, ok := requestObjectTime(int64(1)); !ok {
		t.Fatal("int64 time rejected")
	}
	if _, ok := requestObjectTime(int(1)); !ok {
		t.Fatal("int time rejected")
	}
	if _, ok := requestObjectTime("1"); ok {
		t.Fatal("string time accepted")
	}
	if _, ok := requestObjectTime(1.5); ok {
		t.Fatal("fractional time accepted")
	}
	if audience, err := requestObjectAudience([]string{"a"}); err != nil || !audience.Contains("a") {
		t.Fatalf("audience []string = %v err=%v", audience, err)
	}
	if _, err := requestObjectAudience(1); err == nil {
		t.Fatal("numeric audience accepted")
	}
	if _, err := requestObjectAudience([]any{"a", 2}); err == nil {
		t.Fatal("mixed audience accepted")
	}
	values, err := requestObjectParamValues(json.Number("7"))
	if err != nil || len(values) != 1 || values[0] != "7" {
		t.Fatalf("json number = %v err=%v", values, err)
	}
	if _, err := requestObjectParamValues(map[string]any{"a": "b"}); err != nil {
		t.Fatalf("object parameter: %v", err)
	}
	if _, err := requestObjectParamValues([]any{"a", "b"}); err != nil {
		t.Fatalf("array parameter: %v", err)
	}
	if _, err := requestObjectParamValues(struct{}{}); err == nil {
		t.Fatal("unsupported parameter accepted")
	}
	params, err := requestObjectValues(map[string]any{
		"client_id": "web", "iss": "web", "aud": []any{"https://auth.example"}, "exp": float64(1),
		"scope": "openid", "resource": []any{"https://api.example"},
	}, "web")
	if err != nil || params.Get("client_id") != "web" || params.Get("scope") != "openid" ||
		len(params["resource"]) != 1 || params.Get("iss") != "" {
		t.Fatalf("values = %v err=%v", params, err)
	}
	if !requestObjectAlgAllowed([]string{"ES256"}, "ES256") || requestObjectAlgAllowed(nil, "ES256") {
		t.Fatal("algorithm allow list")
	}
	if got := strings.Join(defaultRequestObjectSigningAlgs, ","); !strings.Contains(got, "RS256") {
		t.Fatalf("default algorithms = %s", got)
	}
}
