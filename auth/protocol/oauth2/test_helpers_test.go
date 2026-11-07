package oauth2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// fakeTokenEnricher records token enrichment and optionally fails. | fakeTokenEnricher 记录令牌增强并
// 可选择失败。
type fakeTokenEnricher struct {
	IDToken string
	Extra   map[string]any
	Err     error
	Calls   int
	Grant   *Grant
}

// EnrichToken implements TokenEnricher. | EnrichToken 实现 TokenEnricher。
func (f *fakeTokenEnricher) EnrichToken(_ context.Context, grant *Grant, response *TokenResponse) error {
	f.Calls++
	f.Grant = grant
	if f.Err != nil {
		return f.Err
	}
	if f.IDToken != "" {
		response.IDToken = f.IDToken
	}
	if len(f.Extra) > 0 {
		if response.Extra == nil {
			response.Extra = make(map[string]any, len(f.Extra))
		}
		for key, value := range f.Extra {
			response.Extra[key] = value
		}
	}
	return nil
}

// fakeAuthorizationEnricher records authorization enrichment. | fakeAuthorizationEnricher 记录授权增强。
type fakeAuthorizationEnricher struct {
	IDToken string
	Params  url.Values
	Err     error
	Grant   *Grant
}

// EnrichAuthorization implements AuthorizationEnricher. | EnrichAuthorization 实现 AuthorizationEnricher。
func (f *fakeAuthorizationEnricher) EnrichAuthorization(_ context.Context, grant *Grant, params url.Values) error {
	f.Grant = grant
	if f.Params != nil {
		for key, values := range f.Params {
			for _, value := range values {
				params.Set(key, value)
			}
		}
	}
	if f.Err != nil {
		return f.Err
	}
	if f.IDToken != "" {
		params.Set("id_token", f.IDToken)
	}
	return nil
}

// fakeDPoPVerifier returns a configured thumbprint. | fakeDPoPVerifier 返回配置的指纹。
type fakeDPoPVerifier struct {
	JKT           string
	Err           error
	Calls         int
	LastProof     string
	LastMethod    string
	LastTarget    string
	LastAccessTok string
}

// VerifyProof implements DPoPVerifier. | VerifyProof 实现 DPoPVerifier。
func (f *fakeDPoPVerifier) VerifyProof(_ context.Context, proof, method, target, accessToken string) (string, error) {
	f.Calls++
	f.LastProof = proof
	f.LastMethod = method
	f.LastTarget = target
	f.LastAccessTok = accessToken
	if f.Err != nil {
		return "", f.Err
	}
	return f.JKT, nil
}

// fakeClientAssertionVerifier records assertion verification. | fakeClientAssertionVerifier 记录断言校验。
type fakeClientAssertionVerifier struct {
	Err           error
	Calls         int
	LastClient    *Client
	LastAssertion string
	LastAudience  string
}

// VerifyClientAssertion implements ClientAssertionVerifier. | VerifyClientAssertion 实现
// ClientAssertionVerifier。
func (f *fakeClientAssertionVerifier) VerifyClientAssertion(_ context.Context, client *Client, assertion, audience string) error {
	f.Calls++
	f.LastClient = client
	f.LastAssertion = assertion
	f.LastAudience = audience
	return f.Err
}

// fakePasswordAuthenticator authenticates a fixed principal. | fakePasswordAuthenticator 认证固定主体。
type fakePasswordAuthenticator struct {
	Principal *auth.Principal
	Err       error
	Username  string
	Password  string
}

// AuthenticatePassword implements PasswordAuthenticator. | AuthenticatePassword 实现 PasswordAuthenticator。
func (f *fakePasswordAuthenticator) AuthenticatePassword(_ context.Context, username, password string) (*auth.Principal, error) {
	f.Username = username
	f.Password = password
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Principal, nil
}

// fakeSubjectTokenValidator validates RFC 8693 tokens. | fakeSubjectTokenValidator 校验 RFC 8693 令牌。
type fakeSubjectTokenValidator struct {
	Principal *auth.Principal
	Err       error
	Calls     int
	LastType  string
	LastToken string
}

// ValidateSubjectToken implements SubjectTokenValidator. | ValidateSubjectToken 实现 SubjectTokenValidator。
func (f *fakeSubjectTokenValidator) ValidateSubjectToken(_ context.Context, tokenType, token string) (*auth.Principal, error) {
	f.Calls++
	f.LastType = tokenType
	f.LastToken = token
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Principal, nil
}

// fakeJWTBearerValidator validates RFC 7523 bearer assertions. | fakeJWTBearerValidator 校验 RFC 7523
// 承载断言。
type fakeJWTBearerValidator struct {
	Principal *auth.Principal
	Err       error
	Calls     int
	Last      string
}

// ValidateJWTBearer implements JWTBearerValidator. | ValidateJWTBearer 实现 JWTBearerValidator。
func (f *fakeJWTBearerValidator) ValidateJWTBearer(_ context.Context, assertion string) (*auth.Principal, error) {
	f.Calls++
	f.Last = assertion
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Principal, nil
}

// fakeJWTIssuer signs tokens with a fixed value. | fakeJWTIssuer 用固定值签发令牌。
type fakeJWTIssuer struct {
	Token string
	Err   error
	Last  *AccessTokenClaims
}

// SignAccessToken implements JWTIssuer. | SignAccessToken 实现 JWTIssuer。
func (f *fakeJWTIssuer) SignAccessToken(_ context.Context, claims *AccessTokenClaims) (string, error) {
	f.Last = claims
	if f.Err != nil {
		return "", f.Err
	}
	return f.Token, nil
}

// fakeJWTVerifier verifies tokens with fixed claims. | fakeJWTVerifier 用固定声明校验令牌。
type fakeJWTVerifier struct {
	Claims *AccessTokenClaims
	Err    error
	Last   string
}

// VerifyAccessToken implements AccessTokenVerifier. | VerifyAccessToken 实现 AccessTokenVerifier。
func (f *fakeJWTVerifier) VerifyAccessToken(_ context.Context, token string) (*AccessTokenClaims, error) {
	f.Last = token
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Claims, nil
}

// newTestJWTKey returns a fresh ES256 signing key and its public key set. | newTestJWTKey 返回新的
// ES256 签名密钥及其公钥集。
func newTestJWTKey(t *testing.T) (*jose.Key, *jose.KeySet) {
	t.Helper()
	key, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatalf("generate jwt key: %v", err)
	}
	key.Kid = "test-key"
	key.Alg = "ES256"
	key.Use = "sig"
	set := &jose.KeySet{}
	if err := set.Add(key.Public()); err != nil {
		t.Fatalf("add public key: %v", err)
	}
	return key, set
}

// newTestJWTIssuerVerifier returns a JWT access-token issuer and verifier pair. | newTestJWTIssuerVerifier
// 返回 JWT 访问令牌签发器与校验器对。
func newTestJWTIssuerVerifier(t *testing.T, key *jose.Key) (*JWTAccessTokenIssuer, *JWTAccessTokenVerifier) {
	t.Helper()
	issuer, err := NewJWTAccessTokenIssuer(key, "ES256")
	if err != nil {
		t.Fatalf("jwt issuer: %v", err)
	}
	set := &jose.KeySet{}
	if err := set.Add(key.Public()); err != nil {
		t.Fatalf("add public key: %v", err)
	}
	verifier, err := NewJWTAccessTokenVerifier(set, "https://auth.example", "api")
	if err != nil {
		t.Fatalf("jwt verifier: %v", err)
	}
	return issuer, verifier
}

// doRequest invokes handler with an optionally encoded form body. | doRequest 用可选的表单正文调用
// handler。
func doRequest(t *testing.T, handler http.HandlerFunc, method, target string, form url.Values, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if mutate != nil {
		mutate(req)
	}
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// decodeMap decodes a JSON response body. | decodeMap 解码 JSON 响应正文。
func decodeMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	return out
}

// requireErrorCode asserts an OAuth error response code. | requireErrorCode 断言 OAuth 错误响应码。
func requireErrorCode(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d want %d body=%s", w.Code, status, w.Body.String())
	}
	body := decodeMap(t, w)
	if body["error"] != code {
		t.Fatalf("error = %v want %q body=%s", body["error"], code, w.Body.String())
	}
}

// errTest is a generic test failure. | errTest 是通用测试失败。
var errTest = errors.New("test failure")
