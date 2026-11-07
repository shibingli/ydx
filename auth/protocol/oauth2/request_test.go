package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth"
)

// requestTestClients returns a client store for request-parsing tests. | requestTestClients 返回请求解析
// 测试用的客户端存储。
func requestTestClients() *MemoryClientStore {
	return NewMemoryClientStore(
		&Client{
			ID:            "web",
			RedirectURIs:  []string{"https://rp.example/cb", "https://rp.example/cb2"},
			GrantTypes:    []string{GrantAuthorizationCode, GrantRefreshToken},
			ResponseTypes: []string{ResponseCode, "code id_token"},
			Scopes:        []string{"openid", "profile", "api:read"},
		},
		&Client{
			ID:           "single",
			RedirectURIs: []string{"https://single.example/cb"},
		},
	)
}

// requestTestScopes returns the scope registry used by request tests. | requestTestScopes 返回请求测试
// 使用的作用域注册表。
func requestTestScopes() *StaticScopes {
	return NewStaticScopes(
		Scope{Name: "openid"},
		Scope{Name: "profile"},
		Scope{Name: "api:read"},
	)
}

func TestParseAuthorizationRequestMethods(t *testing.T) {
	clients := requestTestClients()
	scopes := requestTestScopes()

	if _, err := ParseAuthorizationRequest(nil, clients, scopes); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil request = %v", err)
	}
	nilRequest := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	if _, err := ParseAuthorizationRequestContext(nil, nilRequest, clients, scopes); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil context request = %v", err)
	}

	bad := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader("client_id=web"))
	bad.Header.Set("Content-Type", "application/json")
	if _, err := ParseAuthorizationRequestContext(context.Background(), bad, clients, scopes); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("json POST = %v", err)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/authorize", nil)
	if _, err := ParseAuthorizationRequest(deleteReq, clients, scopes); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("delete method = %v", err)
	}

	valid := url.Values{
		"client_id":     {"web"},
		"redirect_uri":  {"https://rp.example/cb"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"state-1"},
		"nonce":         {"nonce-1"},
		"login_hint":    {"alice"},
		"id_token_hint": {"hint"},
		"acr_values":    {"urn:acr:1 urn:acr:2"},
		"ui_locales":    {"en zh"},
		"claims":        {`{"id_token":{"email":null}}`},
		"resource":      {"https://api.example", "https://api.example", "https://api2.example"},
		"max_age":       {"300"},
		"prompt":        {"login consent login"},
		"response_mode": {ResponseModeQuery},
		"request_uri":   {"urn:ietf:params:oauth:request_uri:abc"},
	}
	getReq := httptest.NewRequest(http.MethodGet, "/authorize?"+valid.Encode(), nil)
	parsed, err := ParseAuthorizationRequest(getReq, clients, scopes)
	if err != nil {
		t.Fatalf("GET parse: %v", err)
	}
	if parsed.ClientID != "web" || parsed.ResponseType != ResponseCode ||
		parsed.RedirectURI != "https://rp.example/cb" ||
		!reflect.DeepEqual(parsed.Scopes, []string{"openid", "profile"}) ||
		parsed.State != "state-1" || parsed.Nonce != "nonce-1" ||
		parsed.LoginHint != "alice" || parsed.IDTokenHint != "hint" ||
		!reflect.DeepEqual(parsed.ACRValues, []string{"urn:acr:1", "urn:acr:2"}) ||
		!reflect.DeepEqual(parsed.UILocales, []string{"en", "zh"}) ||
		parsed.Claims == "" || !reflect.DeepEqual(parsed.Prompt, []string{"login", "consent"}) ||
		parsed.MaxAge == nil || *parsed.MaxAge != 300 ||
		!reflect.DeepEqual(parsed.Resource, []string{"https://api.example", "https://api2.example"}) ||
		parsed.ResponseMode != ResponseModeQuery || parsed.RequestURI == "" ||
		parsed.Client == nil || parsed.Raw.Get("state") != "state-1" {
		t.Fatalf("parsed = %+v", parsed)
	}
	if parsed.ScopeString() != "openid profile" {
		t.Fatalf("scope string = %q", parsed.ScopeString())
	}

	postReq := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(valid.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	parsed, err = ParseAuthorizationRequest(postReq, clients, scopes)
	if err != nil || parsed.State != "state-1" {
		t.Fatalf("POST parse = %+v err=%v", parsed, err)
	}
}

func TestParseAuthorizationRequestValidation(t *testing.T) {
	clients := requestTestClients()
	scopes := requestTestScopes()
	parse := func(values url.Values) (*AuthorizationRequest, error) {
		req := httptest.NewRequest(http.MethodGet, "/authorize?"+values.Encode(), nil)
		return ParseAuthorizationRequest(req, clients, scopes)
	}
	base := func() url.Values {
		return url.Values{
			"client_id":     {"web"},
			"redirect_uri":  {"https://rp.example/cb"},
			"response_type": {ResponseCode},
		}
	}

	if _, err := parse(url.Values{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty values = %v", err)
	}
	noClient := base()
	delete(noClient, "client_id")
	if _, err := parse(noClient); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing client = %v", err)
	}
	unknownClient := base()
	unknownClient.Set("client_id", "unknown")
	if _, err := parse(unknownClient); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("unknown client = %v", err)
	}
	noRedirect := base()
	delete(noRedirect, "redirect_uri")
	if _, err := parse(noRedirect); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("multi redirect without redirect_uri = %v", err)
	}
	// A client with exactly one redirect may omit the parameter. | 只有一个重定向的客户端可省略参数。
	single := url.Values{"client_id": {"single"}, "response_type": {ResponseCode}}
	parsed, err := parse(single)
	if err != nil || parsed.RedirectURI != "https://single.example/cb" {
		t.Fatalf("single redirect = %+v err=%v", parsed, err)
	}
	badRedirect := base()
	badRedirect.Set("redirect_uri", "https://evil.example/cb")
	if _, err := parse(badRedirect); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unregistered redirect = %v", err)
	}

	noResponseType := base()
	delete(noResponseType, "response_type")
	if _, err := parse(noResponseType); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing response_type = %v", err)
	}
	unknownResponseType := base()
	unknownResponseType.Set("response_type", "device")
	if _, err := parse(unknownResponseType); !errors.Is(err, ErrUnsupportedResponseType) {
		t.Fatalf("unknown response_type = %v", err)
	}
	duplicate := base()
	duplicate.Set("response_type", "code code")
	if _, err := parse(duplicate); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("duplicate response_type = %v", err)
	}
	noneCombo := base()
	noneCombo.Set("response_type", "none code")
	if _, err := parse(noneCombo); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("none combination = %v", err)
	}
	unregisteredType := base()
	unregisteredType.Set("response_type", "token")
	if _, err := parse(unregisteredType); !errors.Is(err, ErrUnsupportedResponseType) {
		t.Fatalf("unregistered response_type = %v", err)
	}
	// Canonical ordering accepts reversed response types. | 规范排序接受逆序的响应类型。
	hybrid := base()
	hybrid.Set("response_type", "id_token code")
	parsed, err = parse(hybrid)
	if err != nil || parsed.ResponseType != "code id_token" || parsed.ResponseMode != ResponseModeFragment {
		t.Fatalf("hybrid = %+v err=%v", parsed, err)
	}

	unknownScope := base()
	unknownScope.Set("scope", "unknown")
	if _, err := parse(unknownScope); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("unknown scope = %v", err)
	}
	clientScope := base()
	clientScope.Set("scope", "other")
	if _, err := parse(clientScope); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("client scope = %v", err)
	}
	defaulted := base()
	parsed, err = parse(defaulted)
	if err != nil || !reflect.DeepEqual(parsed.Scopes, []string{"openid", "profile", "api:read"}) {
		t.Fatalf("default scopes = %v err=%v", parsed.Scopes, err)
	}

	methodOnly := base()
	methodOnly.Set("code_challenge_method", PKCES256)
	if _, err := parse(methodOnly); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("challenge method without challenge = %v", err)
	}
	badChallenge := base()
	badChallenge.Set("code_challenge", "short")
	if _, err := parse(badChallenge); !errors.Is(err, ErrPKCE) {
		t.Fatalf("short challenge = %v", err)
	}
	badMethod := base()
	badMethod.Set("code_challenge", strings.Repeat("a", 43))
	badMethod.Set("code_challenge_method", "S512")
	if _, err := parse(badMethod); !errors.Is(err, ErrPKCE) {
		t.Fatalf("bad method = %v", err)
	}
	verifier, _ := pkcePair(t)
	challenge := CodeChallengeS256(verifier)
	defaultMethod := base()
	defaultMethod.Set("code_challenge", challenge)
	parsed, err = parse(defaultMethod)
	if err != nil || parsed.CodeChallengeMethod != PKCEPlain {
		t.Fatalf("default PKCE method = %+v err=%v", parsed, err)
	}
	lowerMethod := base()
	lowerMethod.Set("code_challenge", challenge)
	lowerMethod.Set("code_challenge_method", "s256")
	parsed, err = parse(lowerMethod)
	if err != nil || parsed.CodeChallengeMethod != PKCES256 {
		t.Fatalf("lowercase PKCE method = %+v err=%v", parsed, err)
	}

	badMode := base()
	badMode.Set("response_mode", "web_message")
	if _, err := parse(badMode); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad response mode = %v", err)
	}
	queryWithToken := base()
	queryWithToken.Set("response_type", "code token")
	queryWithToken.Set("response_mode", ResponseModeQuery)
	// The client does not register "code token", so response-type validation wins. | 客户端未注册
	// "code token"，因此响应类型校验先失败。
	if _, err := parse(queryWithToken); !errors.Is(err, ErrUnsupportedResponseType) {
		t.Fatalf("code token = %v", err)
	}
	// A response type registered by the client but illegal for the mode. | 客户端已注册但对模式非法的
	// 响应类型。
	client := &Client{ID: "mode", RedirectURIs: []string{"https://mode.example/cb"}, ResponseTypes: []string{"code token"}}
	modeClients := NewMemoryClientStore(client)
	modeValues := url.Values{
		"client_id":     {"mode"},
		"redirect_uri":  {"https://mode.example/cb"},
		"response_type": {"code token"},
		"response_mode": {ResponseModeQuery},
	}
	modeReq := httptest.NewRequest(http.MethodGet, "/authorize?"+modeValues.Encode(), nil)
	if _, err := ParseAuthorizationRequest(modeReq, modeClients, scopes); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mode mismatch = %v", err)
	}

	badPrompt := base()
	badPrompt.Set("prompt", "login magic")
	if _, err := parse(badPrompt); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad prompt = %v", err)
	}
	nonePrompt := base()
	nonePrompt.Set("prompt", "none login")
	if _, err := parse(nonePrompt); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("none prompt combination = %v", err)
	}
	badMaxAge := base()
	badMaxAge.Set("max_age", "-1")
	if _, err := parse(badMaxAge); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("negative max_age = %v", err)
	}
	nonNumericMaxAge := base()
	nonNumericMaxAge.Set("max_age", "soon")
	if _, err := parse(nonNumericMaxAge); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("non-numeric max_age = %v", err)
	}
	badResource := base()
	badResource.Set("resource", "not-a-url")
	if _, err := parse(badResource); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("bad resource = %v", err)
	}
	fragmentResource := base()
	fragmentResource.Set("resource", "https://api.example/#frag")
	if _, err := parse(fragmentResource); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("fragment resource = %v", err)
	}
	requestObject := base()
	requestObject.Set("request", "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ4In0.")
	var oauthErr *Error
	if _, err := parse(requestObject); !errors.As(err, &oauthErr) || oauthErr.Code != ErrorRequestNotSupported {
		t.Fatalf("request object = %v", err)
	}
	oversizedURI := base()
	oversizedURI.Set("request_uri", strings.Repeat("a", (64<<10)+1))
	if _, err := parse(oversizedURI); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized request_uri = %v", err)
	}

	// Nil clients and nil scope registry. | 空客户端存储与空作用域注册表。
	if _, err := ParseAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/authorize?client_id=web", nil), nil, scopes); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil clients = %v", err)
	}
	noRegistry := base()
	noRegistry.Set("scope", "anything")
	parsed, err = ParseAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/authorize?"+noRegistry.Encode(), nil), NewMemoryClientStore(&Client{
		ID:           "any",
		RedirectURIs: []string{"https://any.example/cb"},
	}), nil)
	_ = parsed
	_ = err
	anyScope := base()
	anyScope.Set("client_id", "web")
	anyScope.Set("scope", "openid")
	parsed, err = ParseAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/authorize?"+anyScope.Encode(), nil), clients, nil)
	if err != nil || !reflect.DeepEqual(parsed.Scopes, []string{"openid"}) {
		t.Fatalf("nil registry = %+v err=%v", parsed, err)
	}
	clientScopeWithNilRegistry := base()
	clientScopeWithNilRegistry.Set("scope", "admin")
	if _, err := ParseAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/authorize?"+clientScopeWithNilRegistry.Encode(), nil), clients, nil); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("nil registry client scope = %v", err)
	}
}

func TestAuthorizationRequestParserHelpers(t *testing.T) {
	if got, err := canonicalResponseType("none"); err != nil || got != ResponseNone {
		t.Fatalf("none = %q err=%v", got, err)
	}
	if got, err := canonicalResponseType("token id_token code"); err != nil || got != "code id_token token" {
		t.Fatalf("sorted = %q err=%v", got, err)
	}
	if _, err := canonicalResponseType(""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty response type = %v", err)
	}
	if _, err := canonicalResponseType("code code"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("duplicate response type = %v", err)
	}
	if _, err := canonicalResponseType("magic"); !errors.Is(err, ErrUnsupportedResponseType) {
		t.Fatalf("unknown response type = %v", err)
	}
	if responseTypeHas("code id_token", ResponseIDToken) != true || responseTypeHas("code", ResponseToken) {
		t.Fatal("responseTypeHas")
	}
	if defaultResponseMode(ResponseCode) != ResponseModeQuery ||
		defaultResponseMode(ResponseNone) != ResponseModeQuery ||
		defaultResponseMode("code id_token") != ResponseModeFragment ||
		defaultResponseMode(ResponseToken) != ResponseModeFragment {
		t.Fatal("default response mode")
	}
	if !validResponseMode(ResponseModeQuery, ResponseCode) ||
		!validResponseMode(ResponseModeQuery, ResponseNone) ||
		validResponseMode(ResponseModeQuery, ResponseToken) ||
		validResponseMode(ResponseModeQuery, "code token") ||
		validResponseMode(ResponseModeQuery, "code id_token") ||
		!validResponseMode(ResponseModeFragment, ResponseToken) ||
		!validResponseMode(ResponseModeFragment, ResponseIDToken) ||
		validResponseMode(ResponseModeFragment, ResponseCode) ||
		!validResponseMode(ResponseModeFormPost, ResponseCode) ||
		validResponseMode("magic", ResponseCode) {
		t.Fatal("valid response mode")
	}
	if prompt, err := parsePrompt(" login  login consent "); err != nil || !reflect.DeepEqual(prompt, []string{"login", "consent"}) {
		t.Fatalf("prompt = %v err=%v", prompt, err)
	}
	if prompt, err := parsePrompt(""); err != nil || prompt != nil {
		t.Fatalf("empty prompt = %v err=%v", prompt, err)
	}
	if _, err := parsePrompt("select_account magic"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown prompt = %v", err)
	}
	if resources, err := parseResources(nil); err != nil || resources != nil {
		t.Fatalf("nil resources = %v err=%v", resources, err)
	}
	if resources, err := parseResources([]string{" https://a.example ", "", "https://a.example", "https://b.example"}); err != nil ||
		!reflect.DeepEqual(resources, []string{"https://a.example", "https://b.example"}) {
		t.Fatalf("resources = %v err=%v", resources, err)
	}
	if _, err := parseResources([]string{"relative"}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("relative resource = %v", err)
	}
}

// Ensure auth stays referenced by request tests. | 确保请求测试仍引用 auth。
var _ = auth.Principal{}
