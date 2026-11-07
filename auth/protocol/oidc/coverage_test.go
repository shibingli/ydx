package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

func TestValidateClientMetadataRules(t *testing.T) {
	valid := func() *ClientMetadata {
		return &ClientMetadata{
			RedirectURIs:            []string{"https://rp.example/callback"},
			GrantTypes:              []string{oauth2.GrantAuthorizationCode},
			ResponseTypes:           []string{oauth2.ResponseCode},
			TokenEndpointAuthMethod: oauth2.ClientSecretBasic,
		}
	}
	cases := []struct {
		name     string
		metadata *ClientMetadata
		wantErr  bool
	}{
		{name: "nil", metadata: nil, wantErr: true},
		{name: "valid", metadata: valid()},
		{
			name: "refresh token only",
			metadata: &ClientMetadata{
				GrantTypes: []string{oauth2.GrantRefreshToken},
			},
		},
		{
			name: "client credentials",
			metadata: &ClientMetadata{
				GrantTypes:              []string{oauth2.GrantClientCredentials},
				TokenEndpointAuthMethod: oauth2.PrivateKeyJWT,
			},
		},
		{
			name: "unsupported grant",
			metadata: &ClientMetadata{
				GrantTypes: []string{"password"},
			},
			wantErr: true,
		},
		{
			name:     "missing redirect URIs",
			metadata: &ClientMetadata{GrantTypes: []string{oauth2.GrantAuthorizationCode}},
			wantErr:  true,
		},
		{
			name: "invalid redirect URI",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.RedirectURIs = []string{"javascript:alert(1)"}
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "invalid post logout redirect URI",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.PostLogoutRedirectURIs = []string{"https://rp.example/logout#fragment"}
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "empty response type",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.ResponseTypes = []string{""}
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "unknown response type",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.ResponseTypes = []string{"magic"}
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "duplicate response type",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.ResponseTypes = []string{"code code"}
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "none combined",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.ResponseTypes = []string{"none code"}
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "none alone",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.ResponseTypes = []string{"none"}
				return metadata
			}(),
		},
		{
			name: "unsupported auth method",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.TokenEndpointAuthMethod = "magic"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "unsupported subject type",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.SubjectType = "magic"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "pairwise subject",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.SubjectType = SubjectTypePairwise
				metadata.SectorIdentifierURI = "https://rp.example/sector"
				return metadata
			}(),
		},
		{
			name: "unsupported application type",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.ApplicationType = "desktop"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "jwks and jwks_uri",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.JWKS = map[string]any{"keys": []any{}}
				metadata.JWKSURI = "https://rp.example/jwks"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "insecure jwks_uri",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.JWKSURI = "http://rp.example/jwks"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "insecure request_uri",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.RequestURIs = []string{"http://rp.example/request"}
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "secured request_uri",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.RequestURIs = []string{"https://rp.example/request"}
				return metadata
			}(),
		},
		{
			name: "unsigned authorization response",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.AuthorizationSignedResponseAlg = "none"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "signed authorization response",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.AuthorizationSignedResponseAlg = "ES256"
				return metadata
			}(),
		},
		{
			name: "sector identifier host mismatch",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.SectorIdentifierURI = "https://other.example/sector"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "sector identifier not https",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.SectorIdentifierURI = "http://rp.example/sector"
				return metadata
			}(),
			wantErr: true,
		},
		{
			name: "malformed redirect URI",
			metadata: func() *ClientMetadata {
				metadata := valid()
				metadata.RedirectURIs = []string{"https://[::1"}
				return metadata
			}(),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClientMetadata(tc.metadata)
			if tc.wantErr {
				if err == nil {
					t.Fatal("metadata accepted")
				}
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("metadata rejected: %v", err)
			}
		})
	}
}

func TestValidateRedirectURIRules(t *testing.T) {
	cases := []struct {
		name          string
		raw           string
		allowFragment bool
		wantErr       bool
	}{
		{name: "https", raw: "https://rp.example/callback"},
		{name: "relative", raw: "/callback", wantErr: true},
		{name: "fragment", raw: "https://rp.example/callback#frag", wantErr: true},
		{name: "fragment allowed", raw: "https://rp.example/callback#frag", allowFragment: true},
		{name: "userinfo", raw: "https://user:pass@rp.example/callback", wantErr: true},
		{name: "javascript", raw: "javascript:alert(1)", wantErr: true},
		{name: "data", raw: "data:text/html,hello", wantErr: true},
		{name: "vbscript", raw: "vbscript:msgbox(1)", wantErr: true},
		{name: "file", raw: "file:///etc/passwd", wantErr: true},
		{name: "blob", raw: "blob:https://rp.example/id", wantErr: true},
		{name: "about", raw: "about:blank", wantErr: true},
		{name: "https without host", raw: "https:/callback", wantErr: true},
		{name: "http public", raw: "http://rp.example/callback", wantErr: true},
		{name: "http localhost", raw: "http://localhost/callback"},
		{name: "http loopback", raw: "http://127.0.0.1/callback"},
		{name: "http ipv6 loopback", raw: "http://[::1]/callback"},
		{name: "native path", raw: "com.example.app:/callback"},
		{name: "native opaque", raw: "com.example.app:callback"},
		{name: "native empty", raw: "com.example.app:", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRedirectURI(tc.raw, tc.allowFragment)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("redirect rejected: %v", err)
			}
		})
	}
}

func TestAudienceAndHalfHash(t *testing.T) {
	var single Audience
	if err := json.Unmarshal([]byte(`"web"`), &single); err != nil || len(single) != 1 || single[0] != "web" {
		t.Fatalf("single audience = %v err=%v", single, err)
	}
	var many Audience
	if err := json.Unmarshal([]byte(`["web","api"]`), &many); err != nil || len(many) != 2 || !many.Contains("api") {
		t.Fatalf("array audience = %v err=%v", many, err)
	}
	var invalid Audience
	if err := json.Unmarshal([]byte(`42`), &invalid); err == nil {
		t.Fatal("numeric audience accepted")
	}
	if (Audience{"web"}).Contains("other") {
		t.Fatal("unexpected audience match")
	}
	for _, alg := range []string{"RS256", "PS256", "ES256", "HS256", "EdDSA", "RS384", "PS384", "ES384", "HS384", "RS512", "PS512", "ES512", "HS512"} {
		hash, err := halfHash(alg, "value")
		if err != nil || hash == "" {
			t.Fatalf("halfHash(%q) = %q err=%v", alg, hash, err)
		}
	}
	if _, err := halfHash("magic", "value"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unsupported alg = %v", err)
	}
	var nilToken *IDToken
	if err := nilToken.ValidateAccessTokenHash("token"); !errors.Is(err, ErrInvalidAtHash) {
		t.Fatalf("nil token = %v", err)
	}
	hash, err := halfHash("RS256", "token")
	if err != nil {
		t.Fatal(err)
	}
	token := &IDToken{Header: map[string]any{"alg": "RS256"}, Claims: Claims{AccessTokenHash: hash}}
	if err := token.ValidateAccessTokenHash("token"); err != nil {
		t.Fatalf("at_hash: %v", err)
	}
	token.Header["alg"] = "magic"
	if err := token.ValidateAccessTokenHash("token"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unsupported at_hash alg = %v", err)
	}
}

func TestQuoteJSAndJSONHelpers(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "ab", want: `"ab"`},
		{name: "backslash", in: `\`, want: `"\\"`},
		{name: "quote", in: `"`, want: `"\""`},
		{name: "newline", in: "\n", want: `"\n"`},
		{name: "carriage return", in: "\r", want: `"\r"`},
		{name: "less than", in: "<", want: `"\<"`},
		{name: "greater than", in: ">", want: `"\>"`},
		{name: "ampersand", in: "&", want: `"\&"`},
		{name: "line separator", in: " ", want: "\"\\ \""},
		{name: "paragraph separator", in: " ", want: "\"\\ \""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := quoteJS(tc.in); got != tc.want {
				t.Fatalf("quoteJS(%q) = %q want %q", tc.in, got, tc.want)
			}
		})
	}
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusOK, make(chan int))
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "server_error") {
		t.Fatalf("marshal failure = %d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	invalidConfig(recorder, errors.New("config"))
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "server_error") {
		t.Fatalf("invalid config = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

// saveOpenIDAccessToken stores an opaque access token for the fixture client. | saveOpenIDAccessToken
// 为 fixture 客户端保存不透明访问令牌。
func saveOpenIDAccessToken(t *testing.T, fixture *oidcFixture, raw string) {
	t.Helper()
	now := time.Now().UTC()
	err := fixture.oauth.Config().Store.SaveAccessToken(context.Background(), &oauth2.AccessToken{
		TokenHash: auth.HashToken(raw),
		ClientID:  "web",
		UserID:    "user-1",
		Subject:   "user-1",
		Principal: &auth.Principal{Subject: "user-1", Email: "alice@example.com", EmailVerified: true},
		Scopes:    []string{ScopeOpenID, ScopeEmail},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("save access token: %v", err)
	}
}

func TestUserInfoSignedAndEncryptedResponses(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	ctx := context.Background()
	saveOpenIDAccessToken(t, fixture, "openid-token")
	clients := fixture.oauth.Config().Clients
	updateClient := func(mutate func(*oauth2.Client)) {
		t.Helper()
		client, err := clients.GetClient(ctx, "web")
		if err != nil {
			t.Fatal(err)
		}
		mutate(client)
		if err := clients.UpdateClient(ctx, client); err != nil {
			t.Fatal(err)
		}
	}
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Authorization", "Bearer openid-token")
		recorder := httptest.NewRecorder()
		provider.UserInfo(recorder, req)
		return recorder
	}
	verify := func(raw string) map[string]any {
		t.Helper()
		verified, err := jose.VerifyContext(ctx, raw, provider.Keys().Resolver(), jose.VerifyOptions{})
		if err != nil {
			t.Fatalf("verify userinfo JWT: %v", err)
		}
		var claims map[string]any
		if err := json.Unmarshal(verified.Claims, &claims); err != nil {
			t.Fatal(err)
		}
		return claims
	}

	recorder := call()
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("JSON userinfo = %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	var plain map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &plain); err != nil || plain["sub"] != "user-1" {
		t.Fatalf("JSON claims = %v err=%v", plain, err)
	}

	updateClient(func(client *oauth2.Client) { client.UserInfoSignedResponseAlg = "RS256" })
	recorder = call()
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Type"), "application/jwt") {
		t.Fatalf("signed userinfo = %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	if claims := verify(recorder.Body.String()); claims["sub"] != "user-1" || claims["email"] != "alice@example.com" {
		t.Fatalf("signed claims = %v", claims)
	}

	encKey := newEncryptionKey(t)
	updateClient(func(client *oauth2.Client) {
		client.UserInfoEncryptedResponseAlg = "RSA-OAEP-256"
		client.UserInfoEncryptedResponseEnc = "A256GCM"
		client.JWKS = publicJWKS(t, encKey)
	})
	recorder = call()
	if recorder.Code != http.StatusOK {
		t.Fatalf("encrypted userinfo = %d body=%s", recorder.Code, recorder.Body.String())
	}
	decrypted, err := jose.Decrypt(recorder.Body.String(), encKey, jose.DecryptOptions{})
	if err != nil {
		t.Fatalf("decrypt userinfo: %v", err)
	}
	if claims := verify(string(decrypted)); claims["sub"] != "user-1" {
		t.Fatalf("encrypted claims = %v", claims)
	}

	updateClient(func(client *oauth2.Client) { client.UserInfoSignedResponseAlg = "ES256" })
	if recorder = call(); recorder.Code != http.StatusInternalServerError {
		t.Fatalf("missing signing key = %d body=%s", recorder.Code, recorder.Body.String())
	}

	updateClient(func(client *oauth2.Client) {
		client.UserInfoSignedResponseAlg = "RS256"
		client.JWKS = nil
		client.JWKSURI = ""
	})
	if recorder = call(); recorder.Code != http.StatusInternalServerError {
		t.Fatalf("missing encryption key = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestProviderEnricherBranches(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	ctx := context.Background()
	principal := &auth.Principal{Subject: "user-1", AuthTime: time.Now().UTC()}
	if err := provider.EnrichToken(ctx, nil, nil); err != nil {
		t.Fatalf("nil token grant = %v", err)
	}
	if err := provider.EnrichToken(ctx, &oauth2.Grant{Client: fixture.client, Scopes: []string{ScopeProfile}}, &oauth2.TokenResponse{}); err != nil {
		t.Fatalf("non-openid token grant = %v", err)
	}
	response := &oauth2.TokenResponse{}
	grant := &oauth2.Grant{Client: fixture.client, Principal: principal, Scopes: []string{ScopeOpenID}}
	if err := provider.EnrichToken(ctx, grant, response); err != nil || response.IDToken == "" {
		t.Fatalf("openid token grant = %q err=%v", response.IDToken, err)
	}

	if err := provider.EnrichAuthorization(ctx, nil, nil); err != nil {
		t.Fatalf("nil authorization grant = %v", err)
	}
	params := url.Values{}
	if err := provider.EnrichAuthorization(ctx, &oauth2.Grant{Client: fixture.client, Scopes: []string{ScopeProfile}}, params); err != nil || len(params) != 0 {
		t.Fatalf("non-openid authorization = %v err=%v", params, err)
	}
	codeGrant := &oauth2.Grant{Client: fixture.client, Principal: principal, Scopes: []string{ScopeOpenID}, ResponseType: oauth2.ResponseCode}
	if err := provider.EnrichAuthorization(ctx, codeGrant, params); err != nil || params.Get("id_token") != "" {
		t.Fatalf("code authorization = %v err=%v", params, err)
	}
	implicit := &oauth2.Grant{
		Client: fixture.client, Principal: principal, Scopes: []string{ScopeOpenID},
		ResponseType: "id_token token", SessionID: "sid-1",
	}
	params = url.Values{"state": {"state-1"}}
	if err := provider.EnrichAuthorization(ctx, implicit, params); err != nil {
		t.Fatalf("implicit authorization = %v", err)
	}
	if params.Get("id_token") == "" || params.Get("session_state") == "" {
		t.Fatalf("implicit params = %v", params)
	}
	existing := url.Values{"id_token": {"existing"}}
	if err := provider.EnrichAuthorization(ctx, implicit, existing); err != nil || existing.Get("id_token") != "existing" {
		t.Fatalf("existing id_token = %v err=%v", existing, err)
	}

	claims, err := (DefaultClaimsProvider{}).UserInfoClaims(ctx, nil, nil)
	if err != nil || len(claims) != 0 {
		t.Fatalf("nil principal claims = %v err=%v", claims, err)
	}
}

func TestProviderHelperBranches(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	provider := fixture.provider
	if _, err := NewProvider(ProviderConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil oauth = %v", err)
	}
	if _, err := NewProvider(ProviderConfig{OAuth: fixture.oauth, Issuer: "https://other.example"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("issuer mismatch = %v", err)
	}
	if _, err := NewProvider(ProviderConfig{OAuth: fixture.oauth, SubjectType: "magic"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("subject type = %v", err)
	}
	if _, err := NewProvider(ProviderConfig{OAuth: fixture.oauth, SubjectType: SubjectTypePairwise}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("pairwise salt = %v", err)
	}

	rp := newTestRelyingParty(t, fixture)
	if rp.Discovery() == nil || rp.Client() == nil {
		t.Fatal("relying party getters returned nil")
	}
	if metadata := metadataFromClient(nil); len(metadata.RedirectURIs) != 0 {
		t.Fatalf("nil metadata = %+v", metadata)
	}
	pathCases := []struct {
		path   string
		prefix string
		want   string
	}{
		{path: "/register/client-1", prefix: "/register", want: "client-1"},
		{path: "/register/", prefix: "/register", want: ""},
		{path: "/register/client-1/extra", prefix: "/register", want: "client-1"},
		{path: "/other/client-1", prefix: "/register", want: "other"},
		{path: "/register/a%2Fb", prefix: "/register", want: "a/b"},
	}
	for _, tc := range pathCases {
		if got := clientIDFromPath(tc.path, tc.prefix); got != tc.want {
			t.Fatalf("clientIDFromPath(%q) = %q want %q", tc.path, got, tc.want)
		}
	}

	if key, err := provider.signingKeyFor(""); err != nil || key != provider.signingKey {
		t.Fatalf("default signing key = %v err=%v", key, err)
	}
	if key, err := provider.signingKeyFor("RS256"); err != nil || key != provider.signingKey {
		t.Fatalf("RS256 signing key = %v err=%v", key, err)
	}
	if _, err := provider.signingKeyFor("ES256"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing ES256 key = %v", err)
	}
	ecKey, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatal(err)
	}
	ecKey.Alg = ""
	ecKey.Kid = "ec-1"
	ecKey.Use = "sig"
	if err := provider.Keys().Add(ecKey); err != nil {
		t.Fatal(err)
	}
	if key, err := provider.signingKeyFor("ES256"); err != nil || key.Kid != "ec-1" {
		t.Fatalf("ES256 key = %v err=%v", key, err)
	}
	edKey, err := jose.GenerateKey("EdDSA", 0)
	if err != nil {
		t.Fatal(err)
	}
	edKey.Alg = ""
	edKey.Kid = "ed-1"
	edKey.Use = "sig"
	if err := provider.Keys().Add(edKey); err != nil {
		t.Fatal(err)
	}
	if key, err := provider.signingKeyFor("EdDSA"); err != nil || key.Kid != "ed-1" {
		t.Fatalf("EdDSA key = %v err=%v", key, err)
	}
	if err := provider.Keys().Add(&jose.Key{Kty: jose.KeyTypeRSA, Kid: "enc-1", Alg: "RS256", Use: "enc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.signingKeyFor("PS256"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("encryption key used for signing = %v", err)
	}
	if !keyMatchesAlg(provider.signingKey, "PS256") || keyMatchesAlg(provider.signingKey, "ES256") ||
		keyMatchesAlg(provider.signingKey, "EdDSA") || keyMatchesAlg(provider.signingKey, "magic") {
		t.Fatal("keyMatchesAlg mismatch")
	}

	registrationFixture := newOIDCFixture(t, true)
	recorder := httptest.NewRecorder()
	registrationFixture.provider.ClientConfiguration(recorder, httptest.NewRequest(http.MethodGet, "/register/", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing client id = %d", recorder.Code)
	}
}
