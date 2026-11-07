package oidc

import (
	"net/http"
	"testing"

	"github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/json"
)

// containsValue reports whether values contains want. | containsValue 报告 values 是否包含 want。
func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestOIDCDiscoveryRequestObjectMetadata(t *testing.T) {
	fixture := newOIDCFixture(t, false)
	oauthServer, err := oauth2.NewServer(oauth2.ServerConfig{
		Issuer:  "https://op.example",
		Clients: oauth2.NewMemoryClientStore(),
		Store:   oauth2.NewMemoryStore(),
		Scopes:  oauth2.DefaultScopes(),
		RequestObjects: oauth2.RequestObjectConfig{
			Enabled:     true,
			SigningAlgs: []string{"ES256"},
		},
		RequestURIs: oauth2.RequestURIConfig{Enabled: true, RequireRegistration: true},
	})
	if err != nil {
		t.Fatalf("oauth server: %v", err)
	}
	provider, err := NewProvider(ProviderConfig{
		OAuth:      oauthServer,
		Keys:       fixture.provider.Keys(),
		SigningKey: fixture.provider.signingKey,
		SigningAlg: "RS256",
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	document := provider.DiscoveryDocument()
	if !document.RequestParameterSupported || !document.RequestURIParameterSupported ||
		!document.RequireRequestURIRegistration {
		t.Fatalf("request metadata = %+v", document.ServerMetadata)
	}
	if len(document.RequestObjectSigningAlgValuesSupported) != 1 ||
		document.RequestObjectSigningAlgValuesSupported[0] != "ES256" {
		t.Fatalf("request object algorithms = %v", document.RequestObjectSigningAlgValuesSupported)
	}
	if !containsValue(document.AuthorizationSigningAlgValuesSupported, "RS256") ||
		!containsValue(document.ResponseModesSupported, oauth2.ResponseModeQueryJWT) {
		t.Fatalf("JARM metadata = %+v", document.ServerMetadata)
	}

	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["request_parameter_supported"] != true || raw["request_uri_parameter_supported"] != true ||
		raw["require_request_uri_registration"] != true {
		t.Fatalf("request JSON metadata = %v", raw)
	}
	if algs, _ := raw["request_object_signing_alg_values_supported"].([]any); len(algs) != 1 || algs[0] != "ES256" {
		t.Fatalf("request object JSON algorithms = %v", raw["request_object_signing_alg_values_supported"])
	}
}

func TestDynamicRegistrationRequestObjectMetadata(t *testing.T) {
	fixture := newOIDCFixture(t, true)
	endpoint := fixture.server.URL + RegistrationPath
	const metadata = `{
		"redirect_uris":["https://rp.example/callback"],
		"grant_types":["authorization_code"],
		"response_types":["code"],
		"scope":"openid profile",
		"token_endpoint_auth_method":"client_secret_basic",
		"request_uris":["https://rp.example/request"],
		"request_object_signing_alg":"ES256",
		"authorization_signed_response_alg":"RS256"
	}`
	resp, registered := registrationCall(t, http.MethodPost, endpoint, metadata, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d body=%v", resp.StatusCode, registered)
	}
	clientID, _ := registered["client_id"].(string)
	registrationToken, _ := registered["registration_access_token"].(string)
	clientURI, _ := registered["registration_client_uri"].(string)
	if clientID == "" || registrationToken == "" || clientURI == "" {
		t.Fatalf("registration response = %v", registered)
	}
	uris, _ := registered["request_uris"].([]any)
	if len(uris) != 1 || uris[0] != "https://rp.example/request" ||
		registered["request_object_signing_alg"] != "ES256" ||
		registered["authorization_signed_response_alg"] != "RS256" {
		t.Fatalf("registered metadata = %v", registered)
	}

	resp, current := registrationCall(t, http.MethodGet, clientURI, "", registrationToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read = %d body=%v", resp.StatusCode, current)
	}
	uris, _ = current["request_uris"].([]any)
	if len(uris) != 1 || current["request_object_signing_alg"] != "ES256" ||
		current["authorization_signed_response_alg"] != "RS256" {
		t.Fatalf("stored metadata = %v", current)
	}

	update := `{
		"client_id":"` + clientID + `",
		"redirect_uris":["https://rp.example/callback"],
		"grant_types":["authorization_code"],
		"response_types":["code"],
		"scope":"openid profile",
		"token_endpoint_auth_method":"client_secret_basic",
		"request_uris":["https://rp.example/request"],
		"request_object_signing_alg":"ES256",
		"authorization_signed_response_alg":"RS256"
	}`
	resp, updated := registrationCall(t, http.MethodPut, clientURI, update, registrationToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update = %d body=%v", resp.StatusCode, updated)
	}
	uris, _ = updated["request_uris"].([]any)
	if len(uris) != 1 || updated["authorization_signed_response_alg"] != "RS256" {
		t.Fatalf("updated metadata = %v", updated)
	}

	invalidURIs := `{
		"redirect_uris":["https://rp.example/callback"],
		"request_uris":["http://rp.example/request"]
	}`
	if resp, body := registrationCall(t, http.MethodPost, endpoint, invalidURIs, ""); resp.StatusCode != http.StatusBadRequest ||
		body["error"] != "invalid_client_metadata" {
		t.Fatalf("insecure request_uri = %d body=%v", resp.StatusCode, body)
	}
	unsigned := `{
		"redirect_uris":["https://rp.example/callback"],
		"authorization_signed_response_alg":"none"
	}`
	if resp, body := registrationCall(t, http.MethodPost, endpoint, unsigned, ""); resp.StatusCode != http.StatusBadRequest ||
		body["error"] != "invalid_client_metadata" {
		t.Fatalf("alg none = %d body=%v", resp.StatusCode, body)
	}
}
